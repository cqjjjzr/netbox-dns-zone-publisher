use netbox_dns_zone_publisher::dns::{self, InternalRecord};

fn record(name: &str, ttl: u32, kind: &str, value: &str) -> InternalRecord {
    InternalRecord {
        name: name.into(),
        ttl,
        rr_type: kind.into(),
        value: value.into(),
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
    let before = dns::canonicalize(
        "EXAMPLE.COM",
        vec![soa.clone(), address.clone(), address.clone()],
    )
    .unwrap();
    let mut bumped = soa;
    bumped.value = bumped.value.replace("123", "999");
    let after = dns::canonicalize("example.com.", vec![address, bumped]).unwrap();
    assert_eq!(before, after);
    assert_eq!(before.records.len(), 2);
    assert_eq!(before.name, "example.com.");
    assert!(
        before
            .records
            .iter()
            .any(|r| r.name == "www.example.com." && r.ttl == 0)
    );
    let scanned = dns::internal_to_scanned_records(&before.name, &before.records).unwrap();
    assert_eq!(dns::soa_serial(&before.name, &scanned).unwrap(), 0);
    let rendered = dns::render_with_serial(&before.name, scanned, 2026092601).unwrap();
    assert_eq!(
        dns::soa_serial(&before.name, &dns::parse(&before.name, &rendered).unwrap()).unwrap(),
        2026092601
    );
}

#[test]
fn txt_binary_octets_and_generic_rdata_survive_rendering() {
    let records = vec![
        record("txt", 0, "TXT", r#""a\000\255" "quote\"slash\\" """#),
        record("opaque", 300, "TYPE65280", r"\# 4 00ffabcd"),
        record("@", 300, "MX", "10 mail"),
    ];
    let normalized = dns::canonicalize("example.com", records).unwrap();
    let rendered = dns::render_with_serial(
        "example.com",
        dns::internal_to_scanned_records("example.com", &normalized.records).unwrap(),
        1,
    )
    .unwrap();
    assert!(dns::final_matches_unsigned("example.com", &rendered, &rendered).unwrap());
    assert!(
        normalized
            .records
            .iter()
            .any(|r| r.value == "10 mail.example.com.")
    );
    let text = normalized
        .records
        .iter()
        .find(|r| r.rr_type == "TXT")
        .unwrap();
    assert!(text.value.contains(r"\000"));
    assert!(text.value.contains(r"\255"));
    let again = dns::canonicalize("example.com", normalized.records.clone()).unwrap();
    assert_eq!(again, normalized);
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
        let error = dns::canonicalize("example.com", records)
            .unwrap_err()
            .to_string();
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
    dns::canonicalize("example.com", records.clone()).unwrap();
    records.push(record("www.child", 300, "A", "192.0.2.2"));
    assert!(
        dns::canonicalize("example.com", records)
            .unwrap_err()
            .to_string()
            .contains("non-glue data below delegation")
    );
}

#[test]
fn untrusted_rows_cannot_inject_records_or_include_files() {
    let cases = [
        record("www\nother", 300, "A", "192.0.2.1"),
        record("www", 300, "A IN", "192.0.2.1"),
        record("www", 300, "A", "192.0.2.1\nother 300 IN A 192.0.2.2"),
        record("www", 300, "A", "192.0.2.1\n$INCLUDE /does/not/exist"),
        record("@", 300, "AXFR", ""),
    ];
    for row in cases {
        assert!(
            dns::canonicalize("example.com", vec![row.clone()]).is_err(),
            "accepted {row:?}"
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
fn final_zone_may_add_signatures_but_must_preserve_records_ttls_and_serial() {
    let unsigned = "@ 300 IN SOA ns hostmaster 123 3600 600 86400 300\nwww 300 IN A 192.0.2.1\n";
    let signed = format!("{unsigned}@ 300 IN DNSKEY 257 3 13 AQID\n");
    assert!(dns::final_matches_unsigned("example.com", unsigned, &signed).unwrap());
    for changed in [
        signed.replace("192.0.2.1", "192.0.2.2"),
        signed.replace("www 300", "www 301"),
        signed.replace("123", "124"),
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
