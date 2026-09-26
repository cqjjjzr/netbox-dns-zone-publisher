mod support;

use netbox_dns_zone_publisher::{dns, publisher, util::StateLock};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};
use support::*;

fn assert_published(fixture: &Sandbox, name: &str) {
    let expected = fs::read(fixture.package().join(format!("{name}.zone"))).unwrap();
    for target in &fixture.config.targets {
        let path = target.directory.join(format!("{name}.zone"));
        assert_eq!(fs::read(&path).unwrap(), expected, "target {}", target.name);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

#[test]
fn collect_publish_noop_change_and_repair_preserve_release_history() {
    let api = Api::new(&["example.com", "example.net"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com", "example.net"]);

    publisher::collect(&fixture.config).unwrap();
    let initial_pointer = fixture.pointer();
    let initial_package = fixture.package();
    let initial_zone = fs::read(initial_package.join("example.com.zone")).unwrap();
    let initial_manifest = fixture.manifest();
    let mut files: Vec<_> = fs::read_dir(&initial_package)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            "collection.json",
            "example.com.unsigned.zone",
            "example.com.zone",
            "example.net.unsigned.zone",
            "example.net.zone",
        ]
    );
    for name in ["example.com", "example.net"] {
        assert_eq!(
            fs::read(initial_package.join(format!("{name}.unsigned.zone"))).unwrap(),
            fs::read(initial_package.join(format!("{name}.zone"))).unwrap(),
        );
    }
    assert_eq!(
        initial_manifest["zones"],
        json!(["example.com.", "example.net."])
    );
    assert_eq!(initial_manifest["reasons"].as_array().unwrap().len(), 2);
    assert!(
        !fixture.config.targets[0].directory.exists(),
        "collect must not deploy"
    );
    publisher::publish(&fixture.config).unwrap();
    assert_published(&fixture, "example.com");
    assert_published(&fixture, "example.net");

    let active = fixture.config.targets[0].directory.join("example.com.zone");
    let inode = fs::metadata(&active).unwrap().ino();
    publisher::collect(&fixture.config).unwrap();
    publisher::publish(&fixture.config).unwrap();
    assert_eq!(
        fixture.pointer(),
        initial_pointer,
        "no-op must not consume a serial"
    );
    assert_eq!(
        fs::read_dir(fixture.config.state_dir.join("collected"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        fs::metadata(&active).unwrap().ino(),
        inode,
        "no-op must not replace live file"
    );

    api.state
        .lock()
        .unwrap()
        .records
        .get_mut("example.com")
        .unwrap()[3]["value"] = json!("192.0.2.20");
    publisher::collect(&fixture.config).unwrap();
    let manifest = fixture.manifest();
    assert!(manifest["serial"].as_u64().unwrap() > initial_manifest["serial"].as_u64().unwrap());
    let reasons = manifest["reasons"].to_string();
    assert!(
        reasons.contains("-www.example.com. 300 IN A 192.0.2.10"),
        "{reasons}"
    );
    assert!(
        reasons.contains("+www.example.com. 300 IN A 192.0.2.20"),
        "{reasons}"
    );
    for name in ["example.com", "example.net"] {
        let text = fs::read_to_string(fixture.package().join(format!("{name}.zone"))).unwrap();
        assert_eq!(
            u64::from(dns::soa_serial(name, &dns::parse(name, &text).unwrap()).unwrap()),
            manifest["serial"].as_u64().unwrap()
        );
    }
    assert_eq!(
        fs::read(initial_package.join("example.com.zone")).unwrap(),
        initial_zone
    );
    publisher::publish(&fixture.config).unwrap();
    assert_published(&fixture, "example.com");

    fs::write(&active, "corrupt live file").unwrap();
    fs::remove_file(fixture.config.targets[1].directory.join("example.net.zone")).unwrap();
    api.state.lock().unwrap().unavailable = true;
    let requests_before = api.server.requests.lock().unwrap().len();
    publisher::publish(&fixture.config).unwrap();
    assert_published(&fixture, "example.com");
    assert_published(&fixture, "example.net");
    assert_eq!(
        api.server.requests.lock().unwrap().len(),
        requests_before,
        "publish must be offline"
    );
}

#[test]
fn source_or_checker_failure_keeps_the_selected_release_and_serial() {
    let api = Api::new(&["example.com"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    publisher::collect(&fixture.config).unwrap();
    let pointer = fixture.pointer();
    api.state.lock().unwrap().unavailable = true;
    assert_error(publisher::collect(&fixture.config), "HTTP 503");
    assert_eq!(fixture.pointer(), pointer);

    api.state.lock().unwrap().unavailable = false;
    api.state
        .lock()
        .unwrap()
        .records
        .get_mut("example.com")
        .unwrap()[3]["value"] = json!("192.0.2.20");
    fs::write(fixture.root.path().join("checker.fail"), "").unwrap();
    assert_error(
        publisher::collect(&fixture.config),
        "check zone example.com.",
    );
    assert_eq!(fixture.pointer(), pointer);
    assert_eq!(
        fs::read_dir(fixture.config.state_dir.join("collected"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn configuration_change_requires_a_new_collection_before_publishing() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    publisher::collect(&fixture.config).unwrap();
    fixture.config.targets[0].directory = fixture.root.path().join("replacement");
    assert_error(
        publisher::publish(&fixture.config),
        "configuration changed; collect a new release",
    );
    assert!(!fixture.config.targets[0].directory.exists());
    publisher::collect(&fixture.config).unwrap();
    assert_eq!(
        fixture.manifest()["reasons"],
        json!(["configuration changed"])
    );
    publisher::publish(&fixture.config).unwrap();
    assert_published(&fixture, "example.com");
}

#[test]
fn damaged_package_rebuilds_after_the_last_reserved_serial() {
    let api = Api::new(&["example.com"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    publisher::collect(&fixture.config).unwrap();
    let old_package = fixture.package();
    let mut pointer = fixture.pointer();
    // Model a crash after serial reservation but before selecting a new package.
    let reserved = pointer["last_serial"].as_u64().unwrap() + 1;
    pointer["last_serial"] = json!(reserved);
    fs::write(
        fixture.config.state_dir.join("current.json"),
        serde_json::to_vec(&pointer).unwrap(),
    )
    .unwrap();
    fs::remove_file(old_package.join("example.com.zone")).unwrap();
    assert_error(publisher::publish(&fixture.config), "no current collection");
    publisher::collect(&fixture.config).unwrap();
    assert!(fixture.manifest()["serial"].as_u64().unwrap() > reserved);
    assert_ne!(fixture.package(), old_package);
    assert!(old_package.exists(), "keep historical package for recovery");
}

#[test]
fn failed_package_save_retains_selection_but_consumes_serial_before_retry() {
    let api = Api::new(&["example.com"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    publisher::collect(&fixture.config).unwrap();
    let previous = fixture.pointer();
    let checker = fs::read(&fixture.config.checker).unwrap();
    let collected = fixture.config.state_dir.join("collected");
    // Force a known next ID, then make its staging directory appear during
    // validation, after ID allocation but before the package save. This models
    // a storage conflict without timing races, permissions assumptions or hooks
    // in production code.
    fs::create_dir(collected.join("9000000000000")).unwrap();
    let conflict = collected.join(".9000000000001.tmp");
    script(
        &fixture.config.checker,
        &format!("mkdir -p '{}'\ncat >/dev/null", conflict.display()),
    );
    api.state
        .lock()
        .unwrap()
        .records
        .get_mut("example.com")
        .unwrap()[3]["value"] = json!("192.0.2.20");
    assert!(publisher::collect(&fixture.config).is_err());
    let reserved = fixture.pointer();
    assert_eq!(reserved["collection_id"], previous["collection_id"]);
    assert!(reserved["last_serial"].as_u64().unwrap() > previous["last_serial"].as_u64().unwrap());
    assert!(!collected.join("9000000000001").exists());
    fs::write(&fixture.config.checker, checker).unwrap();
    publisher::collect(&fixture.config).unwrap();
    assert!(
        fixture.manifest()["serial"].as_u64().unwrap() > reserved["last_serial"].as_u64().unwrap()
    );
    assert_eq!(fixture.pointer()["collection_id"], json!(9000000000002_u64));
}

#[test]
fn missing_or_malformed_serial_ledger_cannot_be_silently_reinitialized() {
    let api = Api::new(&["example.com"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    assert_error(publisher::publish(&fixture.config), "no current collection");
    publisher::collect(&fixture.config).unwrap();
    let current = fixture.config.state_dir.join("current.json");
    fs::remove_file(&current).unwrap();
    assert_error(publisher::collect(&fixture.config), "recover serial ledger");
    fs::write(current, "broken json").unwrap();
    assert_error(
        publisher::collect(&fixture.config),
        "invalid current pointer",
    );
}

#[test]
fn rejected_zone_and_failed_target_do_not_block_healthy_publications() {
    let api = Api::new(&["example.com", "example.net"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com", "example.net"]);
    publisher::collect(&fixture.config).unwrap();
    publisher::publish(&fixture.config).unwrap();
    let live = fixture.config.targets[1].directory.join("example.com.zone");
    let previous = fs::read(&live).unwrap();

    api.state
        .lock()
        .unwrap()
        .records
        .get_mut("example.com")
        .unwrap()[3]["value"] = json!("192.0.2.20");
    api.state
        .lock()
        .unwrap()
        .records
        .get_mut("example.net")
        .unwrap()[3]["value"] = json!("192.0.2.30");
    publisher::collect(&fixture.config).unwrap();
    let path = fixture.package().join("example.com.zone");
    let tampered = fs::read_to_string(&path)
        .unwrap()
        .replace("192.0.2.20", "192.0.2.99");
    fs::write(path, tampered).unwrap();
    // Block one target with a regular file; this works even when tests run as root.
    fs::remove_dir_all(&fixture.config.targets[0].directory).unwrap();
    fs::write(&fixture.config.targets[0].directory, "blocked target").unwrap();
    let output = fixture.cli("publish");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Rejecting example.com"), "{stderr}");
    assert!(
        stderr.contains("does not match authoritative unsigned"),
        "{stderr}"
    );
    assert!(stderr.contains("example.net to ns1"), "{stderr}");
    assert_eq!(
        fs::read(live).unwrap(),
        previous,
        "rejected zone must stay live at its old release"
    );
    assert_eq!(
        fs::read(fixture.config.targets[1].directory.join("example.net.zone")).unwrap(),
        fs::read(fixture.package().join("example.net.zone")).unwrap()
    );
}

#[test]
fn signed_refresh_uses_fresh_records_online_and_retained_unsigned_files_offline() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    fixture.enable_signing();
    publisher::collect(&fixture.config).unwrap();
    let initial = fixture.pointer();
    let calls = fixture.root.path().join("signer.calls");
    let signed_once = fs::read(&calls).unwrap();
    publisher::collect(&fixture.config).unwrap();
    publisher::publish(&fixture.config).unwrap();
    assert_eq!(fixture.pointer(), initial);
    assert_eq!(
        fs::read(&calls).unwrap(),
        signed_once,
        "unchanged collect and publish must not sign"
    );

    fixture.make_refresh_due();
    // Corrupt retained unsigned content: successful API reads remain authoritative.
    fs::write(
        fixture.package().join("example.com.unsigned.zone"),
        "invalid retained zone",
    )
    .unwrap();
    publisher::collect(&fixture.config).unwrap();
    assert_eq!(
        fixture.manifest()["reasons"],
        json!(["initial publication for example.com"])
    );
    assert_ne!(fs::read(&calls).unwrap(), signed_once);

    fixture.make_refresh_due();
    let online_serial = fixture.manifest()["serial"].as_u64().unwrap();
    // The offline path must not reuse a corrupted signed final file.
    fs::write(
        fixture.package().join("example.com.zone"),
        "invalid old signature",
    )
    .unwrap();
    api.state.lock().unwrap().unavailable = true;
    publisher::collect(&fixture.config).unwrap();
    assert!(fixture.manifest()["serial"].as_u64().unwrap() > online_serial);
    assert_eq!(
        fixture.manifest()["reasons"],
        json!(["signature refresh from previous package after NetBox failure"])
    );
    publisher::publish(&fixture.config).unwrap();
    assert_published(&fixture, "example.com");
}

#[test]
fn offline_refresh_requires_due_signatures_and_matching_configuration() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    fixture.enable_signing();
    publisher::collect(&fixture.config).unwrap();
    let pointer = fixture.pointer();
    api.state.lock().unwrap().unavailable = true;
    assert_error(publisher::collect(&fixture.config), "HTTP 503");
    fixture.make_refresh_due();
    fixture.config.targets[0].name = "changed target".into();
    assert_error(publisher::collect(&fixture.config), "HTTP 503");
    assert_eq!(fixture.pointer(), pointer);
}

#[test]
fn signer_and_verifier_failures_do_not_select_or_deploy_a_bad_release() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    fixture.enable_signing();
    publisher::collect(&fixture.config).unwrap();
    let pointer = fixture.pointer();
    fixture.make_refresh_due();
    for (tool, context) in [("signer", "sign zone"), ("verifier", "verify signed zone")] {
        let failure = fixture.root.path().join(format!("{tool}.fail"));
        fs::write(&failure, "").unwrap();
        assert_error(publisher::collect(&fixture.config), context);
        assert_eq!(fixture.pointer(), pointer);
        fs::remove_file(failure).unwrap();
    }
    fs::write(fixture.root.path().join("verifier.fail"), "").unwrap();
    let output = fixture.cli("publish");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("verify signed zone"));
    assert!(!fixture.config.targets[0].directory.exists());
}

#[test]
fn cli_reports_failures_on_stderr_and_fences_concurrent_writers() {
    let api = Api::new(&["example.com"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    let lock = StateLock::try_lock(&fixture.config.state_dir).unwrap();
    let output = fixture.cli("collect");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("another writer holds the state lock")
    );
    assert!(api.server.requests.lock().unwrap().is_empty());
    drop(lock);
    let output = fixture.cli("collect");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Collected"));
    api.state.lock().unwrap().unavailable = true;
    let output = fixture.cli("collect");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("HTTP 503"));
}

#[test]
fn default_bind_program_names_are_resolved_from_path() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    fixture.enable_signing();
    let bin = fixture.root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    for (stub, default) in [
        ("checker", "named-checkzone"),
        ("signer", "dnssec-signzone"),
        ("verifier", "dnssec-verify"),
    ] {
        fs::rename(fixture.root.path().join(stub), bin.join(default)).unwrap();
    }
    fixture.config.checker = "named-checkzone".into();
    let signer = fixture.config.signer.as_mut().unwrap();
    signer.program = "dnssec-signzone".into();
    signer.verifier = "dnssec-verify".into();
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(paths).unwrap();
    for command in ["collect", "publish"] {
        let output = fixture
            .cli_command(command)
            .env("PATH", &path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_published(&fixture, "example.com");
}

#[test]
fn ttl_only_change_creates_a_release_and_diff_after_reloading_unsigned_records() {
    let api = Api::new(&["example.com"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    publisher::collect(&fixture.config).unwrap();
    let previous = fixture.pointer();
    api.state
        .lock()
        .unwrap()
        .records
        .get_mut("example.com")
        .unwrap()[3]["ttl"] = json!(301);
    publisher::collect(&fixture.config).unwrap();
    assert!(
        fixture.pointer()["last_serial"].as_u64().unwrap()
            > previous["last_serial"].as_u64().unwrap()
    );
    let reasons = fixture.manifest()["reasons"].to_string();
    assert!(
        reasons.contains("-www.example.com. 300 IN A 192.0.2.10"),
        "{reasons}"
    );
    assert!(
        reasons.contains("+www.example.com. 301 IN A 192.0.2.10"),
        "{reasons}"
    );
    let changed = fixture.pointer();
    publisher::collect(&fixture.config).unwrap();
    assert_eq!(fixture.pointer(), changed);
}

#[test]
fn invalid_unsigned_snapshot_cannot_refresh_offline_but_rebuilds_from_netbox() {
    for invalid in ["invalid retained zone", "outside.net. 300 IN A 192.0.2.1\n"] {
        let api = Api::new(&["example.com"]);
        let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
        fixture.enable_signing();
        publisher::collect(&fixture.config).unwrap();
        fixture.make_refresh_due();
        let previous = fixture.pointer();
        let old_package = fixture.package();
        fs::write(old_package.join("example.com.unsigned.zone"), invalid).unwrap();
        api.state.lock().unwrap().unavailable = true;
        assert_error(publisher::collect(&fixture.config), "HTTP 503");
        assert_eq!(fixture.pointer(), previous);
        api.state.lock().unwrap().unavailable = false;
        publisher::collect(&fixture.config).unwrap();
        assert_eq!(
            fixture.manifest()["reasons"],
            json!(["initial publication for example.com"])
        );
        assert!(
            fixture.pointer()["last_serial"].as_u64().unwrap()
                > previous["last_serial"].as_u64().unwrap()
        );
        assert_eq!(
            fs::read_to_string(old_package.join("example.com.unsigned.zone")).unwrap(),
            invalid
        );
    }
}

#[test]
fn offline_refresh_rejects_a_retained_serial_above_the_next_allocation() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    fixture.enable_signing();
    publisher::collect(&fixture.config).unwrap();
    fixture.make_refresh_due();
    let previous = fixture.pointer();
    let path = fixture.package().join("example.com.unsigned.zone");
    let text = fs::read_to_string(&path).unwrap();
    let zone = dns::Zone::new("example.com", dns::parse("example.com", &text).unwrap()).unwrap();
    fs::write(&path, zone.render_with_serial(u32::MAX)).unwrap();
    api.state.lock().unwrap().unavailable = true;
    assert_error(
        publisher::collect(&fixture.config),
        "source SOA serial is not older",
    );
    assert_eq!(fixture.pointer(), previous);
    assert_eq!(
        fs::read_dir(fixture.config.state_dir.join("collected"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn offline_edits_become_the_snapshot_and_are_replaced_when_netbox_returns() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    fixture.enable_signing();
    publisher::collect(&fixture.config).unwrap();
    fixture.make_refresh_due();
    let old_package = fixture.package();
    let path = old_package.join("example.com.unsigned.zone");
    let edited = fs::read_to_string(&path)
        .unwrap()
        .replace("192.0.2.10", "192.0.2.77");
    fs::write(&path, &edited).unwrap();
    api.state.lock().unwrap().unavailable = true;
    publisher::collect(&fixture.config).unwrap();
    assert_ne!(fixture.package(), old_package);
    assert_eq!(fs::read_to_string(path).unwrap(), edited);
    assert!(
        fs::read_to_string(fixture.package().join("example.com.unsigned.zone"))
            .unwrap()
            .contains("192.0.2.77")
    );
    publisher::publish(&fixture.config).unwrap();
    assert_published(&fixture, "example.com");

    api.state.lock().unwrap().unavailable = false;
    publisher::collect(&fixture.config).unwrap();
    let reasons = fixture.manifest()["reasons"].to_string();
    assert!(
        reasons.contains("-www.example.com. 300 IN A 192.0.2.77"),
        "{reasons}"
    );
    assert!(
        reasons.contains("+www.example.com. 300 IN A 192.0.2.10"),
        "{reasons}"
    );
    publisher::publish(&fixture.config).unwrap();
    assert_published(&fixture, "example.com");
}

#[test]
fn malformed_unsigned_zone_does_not_block_other_zones_during_publication() {
    let api = Api::new(&["example.com", "example.net"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com", "example.net"]);
    publisher::collect(&fixture.config).unwrap();
    fs::write(
        fixture.package().join("example.com.unsigned.zone"),
        "invalid retained zone",
    )
    .unwrap();
    let output = fixture.cli("publish");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Rejecting example.com"));
    assert!(
        !fixture.config.targets[0]
            .directory
            .join("example.com.zone")
            .exists()
    );
    assert_published(&fixture, "example.net");
}
