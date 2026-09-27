mod support;

use netbox_dns_zone_publisher::{config::Config, util};
use std::{fs, time::Duration};
use support::*;

#[test]
fn missing_signing_keys_report_zone_and_exact_path_after_validation() {
    for extension in ["private", "key"] {
        let api = Api::new(&["example.com"]);
        let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
        fixture.enable_signing();
        let missing = format!(
            "{}.{}",
            fixture.config.zones[0].keys[0].display(),
            extension
        );
        fs::remove_file(&missing).unwrap();
        let output = fixture.cli("collect");
        assert!(!output.status.success());
        let logs = String::from_utf8(output.stderr).unwrap();
        assert!(logs.contains("prepare signed zone example.com"), "{logs}");
        let operation = if extension == "private" {
            "inspect private signing key"
        } else {
            "read public signing key"
        };
        assert!(logs.contains(&format!("{operation} {missing}")), "{logs}");
        assert!(logs.contains("No such file or directory"), "{logs}");
        assert!(!fixture.config.state_dir.join("current.json").exists());
    }
}

#[test]
fn configuration_and_write_errors_identify_the_path_and_operation() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("missing.toml");
    assert_error(
        Config::read(&config),
        &format!("read configuration {}", config.display()),
    );
    fs::write(&config, "not valid toml").unwrap();
    assert_error(
        Config::read(&config),
        &format!("parse configuration {}", config.display()),
    );

    let target = root.path().join("directory");
    fs::create_dir(&target).unwrap();
    let error = util::atomic_write(&target, b"data").unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains(&format!("atomically write {}", target.display())));
    assert!(message.contains("persist temporary file"));
}

#[test]
fn cli_reports_lock_path_before_collection_starts() {
    let fixture = Sandbox::new("http://127.0.0.1/".parse().unwrap(), &["example.com"]);
    let lock = fixture.config.state_dir.join("lock");
    fs::create_dir_all(&lock).unwrap();
    let output = fixture.cli("collect");
    assert!(!output.status.success());
    let logs = String::from_utf8(output.stderr).unwrap();
    assert!(logs.contains(&format!("open state lock {} for writing", lock.display())));
    assert!(!logs.contains("Collecting"));
}

#[test]
fn cli_reports_token_path_and_collection_stage() {
    let fixture = Sandbox::new("http://127.0.0.1/".parse().unwrap(), &["example.com"]);
    fs::remove_file(&fixture.config.netbox.token_file).unwrap();
    let output = fixture.cli("collect");
    assert!(!output.status.success());
    let logs = String::from_utf8(output.stderr).unwrap();
    assert!(logs.contains("collect failed"));
    assert!(logs.contains(&format!(
        "read NetBox token file {}",
        fixture.config.netbox.token_file.display()
    )));
}

#[test]
fn command_start_error_identifies_the_executable() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("missing-checker");
    let error = util::command(
        &duct::cmd(&executable, ["--check"]),
        &[],
        Duration::from_secs(1),
    )
    .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("start subprocess"));
    assert!(message.contains(executable.to_str().unwrap()));
}
