use domain::{
    base::{name::ToName, rdata::ComposeRecordData},
    zonefile::inplace::ScannedRecord,
};
use netbox_dns_zone_publisher::dns::{self, Zone};

fn record(name: &str, ttl: u32, kind: &str, value: &str) -> ScannedRecord {
    dns::parse_record("example.com", name, ttl, kind, value).unwrap()
}

fn rdata_bytes(record: &ScannedRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    record.data().compose_rdata(&mut bytes).unwrap();
    bytes
}

#[test]
fn every_label_octet_survives_owner_and_cname_rendering() {
    for byte in 0..=255 {
        let owner = format!(r"a\{byte:03}b.example.com.");
        let target = format!(r"t\{byte:03}z.example.com.");
        let original = record(&owner, 0, "CNAME", &target);
        let zone = Zone::new("example.com", vec![original.clone()]).unwrap();
        let rendered = zone.render_with_serial(1);
        let parsed = dns::parse("example.com", &rendered)
            .unwrap_or_else(|error| panic!("byte {byte}: {error}; {rendered}"));
        assert_eq!(parsed.len(), 1, "byte {byte}: {rendered}");
        let actual = &parsed[0];
        assert_eq!(
            actual.owner().to_canonical_name::<Vec<u8>>(),
            original.owner().to_canonical_name::<Vec<u8>>()
        );
        assert_eq!(actual.ttl(), original.ttl());
        assert_eq!(actual.class(), original.class());
        assert_eq!(actual.rtype(), original.rtype());
        assert_eq!(
            rdata_bytes(actual),
            rdata_bytes(&original),
            "byte {byte}: {rendered}"
        );
    }
}

#[test]
fn punctuation_uses_generic_rdata_only_when_readable_output_loses_bytes() {
    let original = record("alias", 300, "CNAME", r"a\;b.example.com.");
    let zone = Zone::new("example.com", vec![original]).unwrap();
    let rendered = zone.render_with_serial(1);
    assert!(rendered.contains(r"CNAME \# 17 "));
    let reloaded = Zone::new("example.com", dns::parse("example.com", &rendered).unwrap()).unwrap();
    assert_eq!(zone.comparison_text(), reloaded.comparison_text());
    assert!(
        !dns::final_matches_unsigned(
            "example.com",
            &rendered,
            "alias 300 IN CNAME a.example.com.\n"
        )
        .unwrap()
    );

    let normal = Zone::new(
        "example.com",
        vec![
            record("www", 300, "A", "192.0.2.1"),
            record("alias", 300, "CNAME", "MiXeD.example.com."),
            record("text", 300, "TXT", r#""semi; (paren) quote\" slash\\""#),
        ],
    )
    .unwrap();
    let rendered = normal.render_with_serial(1);
    assert!(!rendered.contains(r"\#"), "{rendered}");
    let parsed = dns::parse("example.com", &rendered).unwrap();
    for original in &normal.records {
        let actual = parsed
            .iter()
            .find(|r| r.owner().name_eq(original.owner()))
            .unwrap();
        assert_eq!(rdata_bytes(actual), rdata_bytes(original));
    }
}

#[test]
fn escaping_zonefile_names_preserves_zone_identity_and_filenames() {
    for name in [
        r"a\;b.example.com.",
        r"a\059b.example.com.",
        "a;b.example.com.",
    ] {
        assert_eq!(dns::canonicalize_name(name).unwrap(), "a;b.example.com.");
        assert_eq!(
            dns::sanitize_zone_id_for_filename(name).unwrap(),
            "a%3bb.example.com"
        );
        let zone = Zone::new(
            name,
            vec![dns::parse_record(name, "@", 300, "A", "192.0.2.1").unwrap()],
        )
        .unwrap();
        let rendered = zone.render_with_serial(1);
        assert!(
            rendered.starts_with("$ORIGIN a\\059b.example.com.\n"),
            "{rendered}"
        );
        let parsed = dns::parse(name, &rendered).unwrap();
        assert!(parsed[0].owner().name_eq(zone.records[0].owner()));
        assert_eq!(zone.name, "a;b.example.com.");
        assert_eq!(
            dns::sanitize_zone_id_for_filename(&zone.name).unwrap(),
            "a%3bb.example.com"
        );
    }
}

#[test]
fn escaped_soa_and_ns_names_retain_serial_and_delegation_behavior_after_reload() {
    let original = Zone::new(
        "example.com",
        vec![
            record(
                "@",
                300,
                "SOA",
                r#"ns\;x.example.com. host\"master.example.com. 1 3600 600 86400 300"#,
            ),
            record("child", 300, "NS", r"ns\(x.child.example.com."),
        ],
    )
    .unwrap();
    let rendered = original.render_with_serial(2);
    assert!(!rendered.contains(r"\#"), "{rendered}");
    let mut reloaded =
        Zone::new("example.com", dns::parse("example.com", &rendered).unwrap()).unwrap();
    assert_eq!(
        dns::soa_serial("example.com", &reloaded.records).unwrap(),
        2
    );
    assert_eq!(original.comparison_text(), reloaded.comparison_text());
    reloaded
        .records
        .push(record("www.child", 300, "TXT", r#""occluded""#));
    assert!(
        Zone::new("example.com", reloaded.records)
            .unwrap_err()
            .to_string()
            .contains("non-glue data")
    );
}

#[test]
fn leading_name_syntax_and_root_rdata_survive_rendering() {
    for owner in [r"\036INCLUDE", r"\064"] {
        let original = record(owner, 300, "CNAME", ".");
        let zone = Zone::new("example.com", vec![original.clone()]).unwrap();
        let rendered = zone.render_with_serial(1);
        let parsed = dns::parse("example.com", &rendered).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].owner().name_eq(original.owner()));
        assert_eq!(rdata_bytes(&parsed[0]), rdata_bytes(&original));
    }
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
