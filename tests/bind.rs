mod support;

use domain::base::{iana::Rtype, name::ToName, rdata::ComposeRecordData};
use netbox_dns_zone_publisher::{config::Signer, dns, publisher, util};
use std::{fs, time::Duration};
use support::*;

#[test]
#[ignore = "requires named-checkzone, dnssec-keygen, dnssec-signzone and dnssec-verify on PATH"]
fn real_bind_signs_verifies_publishes_and_refreshes_during_a_source_outage() {
    signing_lifecycle(false);
}

#[test]
#[ignore = "requires named-checkzone, dnssec-keygen, dnssec-signzone and dnssec-verify on PATH"]
fn real_bind_nsec3_signs_verifies_publishes_and_refreshes_during_a_source_outage() {
    signing_lifecycle(true);
}

fn assert_denial_records(signed: &str, nsec3: bool) {
    let records = dns::parse("example.com", signed).unwrap();
    for (rtype, expected) in [
        (Rtype::NSEC, !nsec3),
        (Rtype::NSEC3, nsec3),
        (Rtype::NSEC3PARAM, nsec3),
    ] {
        assert_eq!(records.iter().any(|r| r.rtype() == rtype), expected);
    }
    for record in records
        .iter()
        .filter(|r| matches!(r.rtype(), Rtype::NSEC3 | Rtype::NSEC3PARAM))
    {
        let mut bytes = Vec::new();
        record.data().compose_rdata(&mut bytes).unwrap();
        // SHA-1, no Opt-Out, zero extra iterations, empty salt.
        assert_eq!(&bytes[..5], &[1, 0, 0, 0, 0]);
    }
}

fn signing_lifecycle(nsec3: bool) {
    let api = Api::new(&["example.com", "example.net"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com", "example.net"]);
    let generated = util::command(
        &duct::cmd(
            "dnssec-keygen",
            ["-q", "-a", "ECDSAP256SHA256", "-f", "KSK", "example.com"],
        )
        .dir(fixture.root.path()),
        &[],
        Duration::from_secs(30),
    )
    .expect("generate disposable BIND CSK");
    let key = String::from_utf8(generated).unwrap();
    fixture.config.checker = "named-checkzone".into();
    fixture.config.signer = Some(Signer {
        program: "dnssec-signzone".into(),
        verifier: "dnssec-verify".into(),
        validity_secs: 1_209_600,
        refresh_secs: 86_400,
    });
    fixture.config.zones[0].sign = true;
    fixture.config.zones[0].nsec3 = nsec3;
    fixture.config.zones[0].keys = vec![fixture.root.path().join(key.trim())];
    fixture.config.validate().unwrap();

    let unusual = [
        ("alias.example.com.", "CNAME", r"a\;b.example.com."),
        (r"o\;wner.example.com.", "TXT", r#""semi; (paren)""#),
    ];
    api.state
        .lock()
        .unwrap()
        .records
        .get_mut("example.com")
        .unwrap()
        .extend(
            unusual
                .iter()
                .enumerate()
                .map(|(i, (owner, kind, value))| record(i as u64 + 10, 1, owner, kind, value)),
        );
    publisher::collect(&fixture.config).unwrap();
    let first_serial = fixture.manifest()["serial"].as_u64().unwrap();
    let signed = fs::read_to_string(fixture.package().join("example.com.zone")).unwrap();
    assert!(signed.contains("RRSIG"));
    assert!(signed.contains("DNSKEY"));
    assert_denial_records(&signed, nsec3);
    assert_eq!(
        fs::read(fixture.package().join("example.net.zone")).unwrap(),
        fs::read(fixture.package().join("example.net.unsigned.zone")).unwrap(),
        "the other zone must remain unsigned"
    );
    let unsigned = fs::read_to_string(fixture.package().join("example.com.unsigned.zone")).unwrap();
    assert!(
        dns::final_matches_unsigned("example.com", &unsigned, &signed).unwrap(),
        "unsigned:\n{unsigned}\nsigned:\n{signed}"
    );
    let pointer = fixture.pointer();
    publisher::collect(&fixture.config).unwrap();
    assert_eq!(
        fixture.pointer(),
        pointer,
        "generic snapshots must remain a no-op"
    );
    let published = fixture.cli("publish");
    assert!(published.status.success());
    assert!(
        published.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
    let records = dns::parse("example.com", &signed).unwrap();
    for (owner, kind, value) in unusual {
        let expected = dns::parse_record("example.com", owner, 300, kind, value).unwrap();
        assert!(
            records
                .iter()
                .any(|r| { r.owner().name_eq(expected.owner()) && r.data() == expected.data() }),
            "signed output changed {owner} {kind} {value}"
        );
    }

    // Keep authoritative data and the DNSKEY intact, but remove all signatures.
    // This reaches the real verifier after the record comparison and zone checker.
    let public_key =
        fs::read_to_string(format!("{}.key", fixture.config.zones[0].keys[0].display())).unwrap();
    fs::write(
        fixture.package().join("example.com.zone"),
        format!("{unsigned}\n{public_key}"),
    )
    .unwrap();
    let rejected = fixture.cli("publish");
    assert!(rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("verify signed zone"));
    assert_eq!(
        fs::read_to_string(fixture.config.targets[0].directory.join("example.com.zone")).unwrap(),
        signed
    );

    fixture.make_refresh_due();
    api.state.lock().unwrap().unavailable = true;
    publisher::collect(&fixture.config).unwrap();
    assert!(fixture.manifest()["serial"].as_u64().unwrap() > first_serial);
    publisher::publish(&fixture.config).unwrap();
    for name in ["example.com", "example.net"] {
        let expected = fs::read(fixture.package().join(format!("{name}.zone"))).unwrap();
        for target in &fixture.config.targets {
            assert_eq!(
                fs::read(target.directory.join(format!("{name}.zone"))).unwrap(),
                expected
            );
        }
    }
    assert_ne!(
        fs::read_to_string(fixture.package().join("example.com.zone")).unwrap(),
        signed
    );
    assert_denial_records(
        &fs::read_to_string(fixture.package().join("example.com.zone")).unwrap(),
        nsec3,
    );

    // Changing only the denial mode must rebuild, even with unchanged API records.
    api.state.lock().unwrap().unavailable = false;
    let pointer = fixture.pointer();
    fixture.config.zones[0].nsec3 = !nsec3;
    publisher::collect(&fixture.config).unwrap();
    assert_ne!(fixture.pointer(), pointer);
    assert!(
        fixture.manifest()["reasons"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("configuration changed"))
    );
    assert_denial_records(
        &fs::read_to_string(fixture.package().join("example.com.zone")).unwrap(),
        !nsec3,
    );
    let published = fixture.cli("publish");
    assert!(published.status.success());
    assert!(
        published.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );
}

#[test]
#[ignore = "requires named-checkzone on PATH"]
fn real_bind_rejects_a_zone_without_soa_before_reserving_a_serial() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    fixture.config.checker = "named-checkzone".into();
    api.state
        .lock()
        .unwrap()
        .records
        .get_mut("example.com")
        .unwrap()
        .retain(|row| row["type"] != "SOA");
    assert_error(
        publisher::collect(&fixture.config),
        "check zone example.com.",
    );
    assert!(!fixture.config.state_dir.join("current.json").exists());
    assert!(!fixture.config.state_dir.join("collected").exists());
}
