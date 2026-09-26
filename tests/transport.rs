mod support;

use netbox_dns_zone_publisher::{config::Ssh, publisher};
use serde_json::json;
use std::{fs, process::Output};
use support::*;

fn install_transport_stubs(fixture: &mut Sandbox) {
    let bin = fixture.root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    script(
        &bin.join("ssh"),
        r#"
printf '%s\n' "$@" >> "$0.calls"
test ! -f "$0.fail"
exec sh -s
"#,
    );
    script(
        &bin.join("scp"),
        r#"
printf '%s\n' "$@" >> "$0.calls"
while test "$#" -gt 2; do shift; done
destination="${2#*:}"
cp -- "$1" "$destination"
if test -f "$0.corrupt"; then printf corrupt >> "$destination"; fi
test ! -f "$0.fail"
"#,
    );
    fixture.config.targets[0].ssh = Some(Ssh {
        host: "publisher@ns1".into(),
        port: Some(2222),
        extra_args: vec!["-oIdentityFile=/test/key".into()],
    });
}

fn publish_with_transport_stubs(fixture: &Sandbox) -> Output {
    let mut paths = vec![fixture.root.path().join("bin")];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    fixture
        .cli_command("publish")
        .env("PATH", std::env::join_paths(paths).unwrap())
        .output()
        .unwrap()
}

#[test]
fn remote_publication_passes_noninteractive_transport_options_and_is_idempotent() {
    let api = Api::new(&["example.com"]);
    let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    install_transport_stubs(&mut fixture);
    publisher::collect(&fixture.config).unwrap();
    let output = publish_with_transport_stubs(&fixture);
    assert!(output.status.success());
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = fs::read(fixture.package().join("example.com.zone")).unwrap();
    assert_eq!(
        fs::read(fixture.config.targets[0].directory.join("example.com.zone")).unwrap(),
        expected
    );
    let ssh = fs::read_to_string(fixture.root.path().join("bin/ssh.calls")).unwrap();
    let scp = fs::read_to_string(fixture.root.path().join("bin/scp.calls")).unwrap();
    for option in [
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=10",
        "-oForwardAgent=no",
        "-oClearAllForwardings=yes",
        "-oIdentityFile=/test/key",
    ] {
        assert!(
            ssh.lines().any(|line| line == option),
            "ssh missing {option}"
        );
        assert!(
            scp.lines().any(|line| line == option),
            "scp missing {option}"
        );
    }
    assert!(ssh.contains("-T\n"));
    assert!(ssh.contains("-p\n2222\n"));
    assert!(ssh.contains("publisher@ns1\nsh -s\n"));
    assert!(scp.starts_with("-B\n"));
    assert!(scp.contains("-P\n2222\n"));
    assert!(scp.contains("\n--\n"));
    assert!(scp.contains("publisher@ns1:"));
    assert!(scp.contains(".example.com.zone.dns-publish-"));
    assert!(publish_with_transport_stubs(&fixture).status.success());
    assert_eq!(
        fs::read_to_string(fixture.root.path().join("bin/scp.calls")).unwrap(),
        scp,
        "no-op must not upload"
    );
}

#[test]
fn upload_failure_or_checksum_mismatch_preserves_live_file_cleans_staging_and_allows_retry() {
    for failure in ["ssh.fail", "scp.fail", "scp.corrupt"] {
        let api = Api::new(&["example.com"]);
        let mut fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
        install_transport_stubs(&mut fixture);
        publisher::collect(&fixture.config).unwrap();
        assert!(publish_with_transport_stubs(&fixture).status.success());
        let live = fixture.config.targets[0].directory.join("example.com.zone");
        let previous = fs::read(&live).unwrap();
        api.state
            .lock()
            .unwrap()
            .records
            .get_mut("example.com")
            .unwrap()[3]["value"] = json!("192.0.2.20");
        publisher::collect(&fixture.config).unwrap();
        let marker = fixture.root.path().join("bin").join(failure);
        fs::write(&marker, "").unwrap();

        let output = publish_with_transport_stubs(&fixture);
        assert!(
            output.status.success(),
            "target failures are logged, not fatal"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("example.com to ns1"),
            "{failure}"
        );
        assert_eq!(fs::read(&live).unwrap(), previous, "{failure}");
        assert_eq!(
            fs::read_dir(&fixture.config.targets[0].directory)
                .unwrap()
                .count(),
            1,
            "staged file leaked after {failure}"
        );
        let expected = fs::read(fixture.package().join("example.com.zone")).unwrap();
        assert_eq!(
            fs::read(fixture.config.targets[1].directory.join("example.com.zone")).unwrap(),
            expected,
            "healthy target must continue after {failure}"
        );

        fs::remove_file(marker).unwrap();
        assert!(publish_with_transport_stubs(&fixture).status.success());
        assert_eq!(fs::read(live).unwrap(), expected);
    }
}
