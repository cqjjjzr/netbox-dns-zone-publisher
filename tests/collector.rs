mod support;

use netbox_dns_zone_publisher::netbox::Source;
use serde_json::{Value, json};
use std::{io::Read, net::TcpListener, time::Duration};
use support::*;

fn collect_pages(pages: Vec<Value>) -> anyhow::Result<netbox_dns_zone_publisher::dns::Records> {
    let server = HttpServer::scripted(pages.into_iter().map(Response::json).collect());
    let fixture = Sandbox::new(server.url.clone(), &["example.com"]);
    Source::new(&fixture.config.netbox)?.collect(&fixture.config)
}

fn scoped_pages(records: Value) -> Vec<Value> {
    vec![
        page(vec![view()]),
        page(vec![zone(1, "example.com")]),
        records,
    ]
}

#[test]
fn https_collection_sends_a_tls_client_hello() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("https://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let mut fixture = Sandbox::new(url, &["example.com"]);
    fixture.config.netbox.timeout_secs = 1;

    // Leave the handshake unanswered. The request times out, but its queued
    // ClientHello proves HTTPS reached TLS rather than rejecting the scheme
    // or sending the API token over plaintext HTTP. No certificate fixture or
    // external server is needed to exercise the production client setup.
    let result = Source::new(&fixture.config.netbox)
        .unwrap()
        .collect(&fixture.config);
    assert!(result.is_err());
    let (mut stream, _) = listener
        .accept()
        .unwrap_or_else(|error| panic!("HTTPS made no connection: {error}; {result:?}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut header = [0; 6];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[0], 22, "expected a TLS handshake record");
    assert_eq!(header[1], 3, "expected TLS record version 3.x");
    assert_eq!(header[5], 1, "expected a ClientHello handshake");
}

#[test]
fn paginated_collection_authenticates_and_uses_effective_ttls_and_absolute_values() {
    let mut rows = zone_records(1, "example.com");
    rows[3]["ttl"] = json!(0);
    rows.push(record(5, 1, "alias.example.com.", "CNAME", "wrong"));
    rows[4]["absolute_value"] = json!("www.example.com.");
    let mut inactive = record(6, 1, "inactive.example.com.", "A", "invalid address");
    inactive["active"] = json!(false);
    rows.push(inactive);
    let second = rows.split_off(3);
    let mut pages =
        scoped_pages(json!({"count": 6, "next": "?zone_id=1&offset=3", "results": rows}));
    pages.push(json!({"count": 6, "next": null, "results": second}));
    let server = HttpServer::scripted(pages.into_iter().map(Response::json).collect());
    let fixture = Sandbox::new(server.url.clone(), &["EXAMPLE.COM."]);
    let records = Source::new(&fixture.config.netbox)
        .unwrap()
        .collect(&fixture.config)
        .unwrap();
    let zone = &records["example.com"];
    assert_eq!(zone.records.len(), 5);
    let text = zone.comparison_text();
    assert!(text.contains("www.example.com. 0 IN A 192.0.2.10\n"));
    assert!(text.contains("example.com. 300 IN NS ns.example.com.\n"));
    assert!(text.contains("alias.example.com. 300 IN CNAME www.example.com.\n"));
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[1].target.contains("name=example.com&view_id=1"));
    assert!(requests[3].target.ends_with("?zone_id=1&offset=3"));
    assert!(requests.iter().all(|r| {
        r.headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("authorization: Token test-token"))
    }));
}

#[test]
fn scope_resolution_requires_one_matching_active_view_and_zone() {
    for invalid in [
        page(vec![]),
        page(vec![view(), view()]),
        page(vec![json!({"id": 2, "name": "other"})]),
    ] {
        assert!(collect_pages(vec![invalid]).is_err());
    }
    for (field, value) in [
        ("active", json!(false)),
        ("view", json!({"id": 2})),
        ("name", json!("other.example")),
        ("id", json!(0)),
    ] {
        let mut wrong = zone(1, "example.com");
        wrong[field] = value;
        assert_error(
            collect_pages(vec![page(vec![view()]), page(vec![wrong])]),
            "scope/identity/active mismatch",
        );
    }
    assert_error(
        collect_pages(vec![page(vec![view()]), page(vec![])]),
        "zone must resolve uniquely",
    );
}

#[test]
fn pagination_rejects_missing_duplicate_wrong_scope_and_excess_records() {
    let row = record(1, 1, "www.example.com.", "A", "192.0.2.1");
    for (response, expected) in [
        (
            json!({"count": 2, "next": null, "results": [row.clone()]}),
            "incomplete pagination",
        ),
        (page(vec![row.clone(), row.clone()]), "duplicate ID"),
        (
            page(vec![record(1, 2, "www.example.com.", "A", "192.0.2.1")]),
            "record scope mismatch",
        ),
        (
            json!({"count": 101, "next": null, "results": [row.clone()]}),
            "record count exceeds limit",
        ),
        (
            json!({"count": 2, "next": "?offset=1", "results": []}),
            "empty non-final page",
        ),
    ] {
        assert_error(collect_pages(scoped_pages(response)), expected);
    }
}

#[test]
fn pagination_rejects_cycles_changed_counts_and_unsafe_next_urls() {
    let row = record(1, 1, "www.example.com.", "A", "192.0.2.1");
    for (next, expected) in [
        ("?zone_id=1&limit=1000", "pagination cycle"),
        (
            "https://elsewhere.invalid/api/plugins/netbox-dns/records/",
            "unsafe pagination URL",
        ),
        ("/api/plugins/netbox-dns/zones/", "unsafe pagination URL"),
        (
            "http://user:secret@127.0.0.1/api/plugins/netbox-dns/records/",
            "unsafe pagination URL",
        ),
    ] {
        assert_error(
            collect_pages(scoped_pages(
                json!({"count": 2, "next": next, "results": [row.clone()]}),
            )),
            expected,
        );
    }
    let mut pages = scoped_pages(json!({"count": 2, "next": "?offset=1", "results": [row]}));
    pages.push(json!({"count": 3, "next": null, "results": []}));
    assert_error(collect_pages(pages), "pagination count changed");
}

#[test]
fn active_records_need_an_effective_ttl() {
    let mut no_ttl = zone(1, "example.com");
    no_ttl["default_ttl"] = Value::Null;
    assert_error(
        collect_pages(vec![
            page(vec![view()]),
            page(vec![no_ttl]),
            page(vec![record(1, 1, "www.example.com.", "A", "192.0.2.1")]),
        ]),
        "both lack an effective TTL",
    );
}

#[test]
fn stable_reads_ignore_order_and_source_serial_but_reject_content_changes() {
    for change in ["none", "address", "ttl"] {
        let first = zone_records(1, "example.com");
        let mut second = first.clone();
        second[0]["value"] =
            json!("ns.example.com. hostmaster.example.com. 999 3600 600 86400 300");
        match change {
            "address" => second[3]["value"] = json!("192.0.2.99"),
            "ttl" => second[3]["ttl"] = json!(301),
            _ => {}
        }
        second.reverse();
        let mut pages = scoped_pages(page(first));
        pages.extend(scoped_pages(page(second)));
        let server = HttpServer::scripted(pages.into_iter().map(Response::json).collect());
        let fixture = Sandbox::new(server.url.clone(), &["example.com"]);
        let result = Source::new(&fixture.config.netbox)
            .unwrap()
            .stable(&fixture.config);
        if change != "none" {
            assert_error(result, "source records changed between collections");
        } else {
            assert!(result.is_ok());
        }
        assert_eq!(server.requests.lock().unwrap().len(), 6);
    }
}

#[test]
fn http_and_schema_errors_keep_actionable_context() {
    for (response, expected) in [
        (Response::unavailable(), "HTTP 503"),
        (
            Response {
                status: 302,
                body: String::new(),
            },
            "HTTP 302",
        ),
        (
            Response {
                status: 200,
                body: "not json".into(),
            },
            "invalid NetBox JSON/schema",
        ),
        (
            Response::json(json!({"results": []})),
            "invalid NetBox JSON/schema",
        ),
    ] {
        let server = HttpServer::scripted(vec![response]);
        let fixture = Sandbox::new(server.url.clone(), &["example.com"]);
        assert_error(
            Source::new(&fixture.config.netbox)
                .unwrap()
                .collect(&fixture.config),
            expected,
        );
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
}
