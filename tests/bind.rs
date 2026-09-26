mod support;

use netbox_dns_zone_publisher::{config::Signer, publisher, util};
use std::{fs, time::Duration};
use support::*;

#[test]
#[ignore = "requires named-checkzone, dnssec-keygen, dnssec-signzone and dnssec-verify on PATH"]
fn real_bind_signs_verifies_publishes_and_refreshes_during_a_source_outage() {
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
    fixture.config.zones[0].keys = vec![fixture.root.path().join(key.trim())];
    fixture.config.validate().unwrap();

    publisher::collect(&fixture.config).unwrap();
    let first_serial = fixture.manifest()["serial"].as_u64().unwrap();
    let signed = fs::read_to_string(fixture.package().join("example.com.zone")).unwrap();
    assert!(signed.contains("RRSIG"));
    assert!(signed.contains("DNSKEY"));
    publisher::publish(&fixture.config).unwrap();

    // Keep authoritative data and the DNSKEY intact, but remove all signatures.
    // This reaches the real verifier after the record comparison and zone checker.
    let unsigned = fs::read_to_string(fixture.package().join("example.com.unsigned.zone")).unwrap();
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
