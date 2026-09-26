use domain::zonefile::inplace::ScannedRecord;
use netbox_dns_zone_publisher::dns::{self, Zone};

fn record(name: &str, ttl: u32, kind: &str, value: &str) -> ScannedRecord {
    dns::parse_record("example.com", name, ttl, kind, value).unwrap()
}

#[test]
fn normalization_ignores_source_serial_order_and_duplicate_records() {
    let soa = record(
        "@",
        300,
        "SOA",
        "ns.example.com. hostmaster.example.com. 123 3600 600 86400 300",
    );
    let address = record("WWW.Example.COM.", 0, "A", "192.0.2.1");
    let before = Zone::new(
        "EXAMPLE.COM",
        vec![soa.clone(), address.clone(), address.clone()],
    )
    .unwrap();
    let bumped = record(
        "@",
        300,
        "SOA",
        "ns.example.com. hostmaster.example.com. 999 3600 600 86400 300",
    );
    let after = Zone::new("example.com.", vec![address, bumped]).unwrap();
    assert_eq!(before, after);
    assert_eq!(before.name, "example.com.");
    assert!(
        before
            .comparison_text()
            .contains("www.example.com. 0 IN A 192.0.2.1\n")
    );
    let rendered = before.render_with_serial(2026092601);
    let reloaded = Zone::new(&before.name, dns::parse(&before.name, &rendered).unwrap()).unwrap();
    assert_eq!(reloaded.records.len(), 2);
    assert_eq!(
        dns::soa_serial(&before.name, &reloaded.records).unwrap(),
        2026092601
    );
    assert_eq!(before, reloaded);
    assert_eq!(dns::soa_serial(&before.name, &before.records).unwrap(), 123);
    assert_eq!(dns::soa_serial(&after.name, &after.records).unwrap(), 999);
}

#[test]
fn txt_binary_octets_and_generic_rdata_survive_rendering() {
    let records = vec![
        record("txt", 0, "TXT", r#""MiXeD\000\255" "quote\"slash\\" """#),
        record("opaque", 300, "TYPE65280", r"\# 4 00ffabcd"),
        record("@", 300, "MX", "10 mail"),
        record(r"a\032b", 300, "A", "192.0.2.1"),
    ];
    let zone = Zone::new("example.com", records).unwrap();
    let rendered = zone.render_with_serial(1);
    assert!(dns::final_matches_unsigned("example.com", &rendered, &rendered).unwrap());
    assert!(rendered.contains("10 mail.example.com."));
    assert!(rendered.contains(r"MiXeD\000\255"));
    assert!(rendered.contains(r"a\ b.example.com."));
    let again = Zone::new("example.com", dns::parse("example.com", &rendered).unwrap()).unwrap();
    assert_eq!(again, zone);
    assert_eq!(again.render_with_serial(1), rendered);
}

#[test]
fn source_policy_rejects_out_of_zone_dnssec_and_inconsistent_rrset_ttls() {
    let cases = [
        (
            vec![record("outside.net.", 300, "A", "192.0.2.1")],
            "record outside zone",
        ),
        (
            vec![record("@", 300, "DNSKEY", "257 3 13 AQID")],
            "generated DNSSEC data",
        ),
        (
            vec![
                record("www", 300, "A", "192.0.2.1"),
                record("www", 301, "A", "192.0.2.2"),
            ],
            "inconsistent TTL",
        ),
    ];
    for (records, expected) in cases {
        let error = Zone::new("example.com", records).unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn delegation_accepts_supplied_glue_but_rejects_occluded_records() {
    let mut records = vec![
        record("child", 300, "NS", "ns.child.example.com."),
        record("ns.child", 300, "A", "192.0.2.1"),
        record(
            "child",
            300,
            "DS",
            "12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
    ];
    Zone::new("example.com", records.clone()).unwrap();
    records.push(record("www.child", 300, "A", "192.0.2.2"));
    assert!(
        Zone::new("example.com", records)
            .unwrap_err()
            .to_string()
            .contains("non-glue data below delegation")
    );
}

#[test]
fn untrusted_rows_cannot_inject_records_or_include_files() {
    let cases = [
        ("www\nother", 300, "A", "192.0.2.1"),
        ("www", 300, "A IN", "192.0.2.1"),
        ("www", 300, "A", "192.0.2.1\nother 300 IN A 192.0.2.2"),
        ("www", 300, "A", "192.0.2.1\n$INCLUDE /does/not/exist"),
        ("@", 300, "AXFR", ""),
        ("www 301 CH A 192.0.2.1 ;", 300, "A", "192.0.2.2"),
    ];
    for (name, ttl, kind, value) in cases {
        assert!(
            dns::parse_record("example.com", name, ttl, kind, value).is_err(),
            "accepted {name} {ttl} {kind} {value}"
        );
    }
    assert!(
        dns::parse("example.com", "$INCLUDE /does/not/exist\n")
            .unwrap_err()
            .to_string()
            .contains("includes are not allowed")
    );
}

#[test]
fn final_zone_may_add_signatures_but_must_preserve_records_ttls_class_and_serial() {
    let unsigned = "@ 300 IN SOA ns hostmaster 123 3600 600 86400 300\nwww 300 IN A 192.0.2.1\n";
    let signed = format!("{unsigned}@ 300 IN DNSKEY 257 3 13 AQID\n");
    assert!(dns::final_matches_unsigned("example.com", unsigned, &signed).unwrap());
    for changed in [
        signed.replace("192.0.2.1", "192.0.2.2"),
        signed.replace("www 300", "www 301"),
        signed.replace("123", "124"),
        signed.replace(" IN ", " CH "),
        signed.replace("www 300 IN A 192.0.2.1\n", ""),
    ] {
        assert!(
            !dns::final_matches_unsigned("example.com", unsigned, &changed).unwrap(),
            "accepted {changed}"
        );
    }
}

#[test]
fn zone_filenames_are_canonical_safe_and_collision_resistant() {
    assert_eq!(
        dns::sanitize_zone_id_for_filename("Example.COM.").unwrap(),
        "example.com"
    );
    for name in [
        "con.example",
        "LPT1.example",
        r"a/b.example",
        r"a\092b.example",
    ] {
        let id = dns::sanitize_zone_id_for_filename(name).unwrap();
        assert!(!id.contains(['/', '\\']));
        assert!(id.contains('%'), "{id}");
    }
    let prefix = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(60));
    let first = dns::sanitize_zone_id_for_filename(&format!("{prefix}.com")).unwrap();
    let second = dns::sanitize_zone_id_for_filename(&format!("{prefix}.net")).unwrap();
    assert!(first.len() <= 180);
    assert_ne!(first, second);
    assert!(dns::sanitize_zone_id_for_filename(".").is_err());
    assert!(dns::canonicalize_name("bad name").is_err());
}
