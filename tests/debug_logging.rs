mod support;

use support::*;

#[test]
fn debug_logs_http_error_details_without_authentication_token() {
    let server = HttpServer::start(|_| Response {
        status: 400,
        body: r#"{"view_id":["Invalid filter value"]}"#.into(),
    });
    let fixture = Sandbox::new(server.url.clone(), &["example.com"]);
    for level in ["info", "netbox_dns_zone_publisher=debug"] {
        let output = fixture
            .cli_command("collect")
            .env("RUST_LOG", level)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let logs = String::from_utf8(output.stderr).unwrap();
        assert!(logs.contains("NetBox returned HTTP 400"));
        assert!(!logs.contains("test-token"));
        if level == "info" {
            assert!(!logs.contains("HTTP request:"));
            assert!(!logs.contains("Invalid filter value"));
        } else {
            assert!(logs.contains("HTTP request: GET"));
            assert!(logs.contains("api/plugins/netbox-dns/views/?name=public"));
            assert!(logs.contains("authorization"));
            assert!(logs.contains("<redacted>"));
            assert!(logs.contains("HTTP response:"));
            assert!(logs.contains("Invalid filter value"));
        }
    }
}

#[test]
fn debug_logs_successful_and_failed_commands_and_stdin() {
    let api = Api::new(&["example.com"]);
    let fixture = Sandbox::new(api.server.url.clone(), &["example.com"]);
    for exit in [0, 1] {
        script(
            &fixture.config.checker,
            &format!("printf 'checker stdout'\nprintf 'checker stderr' >&2\nexit {exit}"),
        );
        let output = fixture
            .cli_command("collect")
            .env("RUST_LOG", "netbox_dns_zone_publisher=debug")
            .output()
            .unwrap();
        assert_eq!(output.status.success(), exit == 0);
        let logs = String::from_utf8(output.stderr).unwrap();
        assert!(logs.contains("HTTP response body:"));
        assert!(logs.contains("Executing command:"));
        assert!(logs.contains("Command stdin:"));
        assert!(logs.contains("Command completed:"));
        assert!(logs.contains("stdout:\nchecker stdout"));
        assert!(logs.contains("stderr:\nchecker stderr"));
        assert!(logs.contains("timed out: false"));
        // Force the next collection to run validation again.
        if exit == 0 {
            let publish = fixture
                .cli_command("publish")
                .env("RUST_LOG", "netbox_dns_zone_publisher=debug")
                .output()
                .unwrap();
            assert!(publish.status.success());
            let logs = String::from_utf8(publish.stderr).unwrap();
            assert!(logs.contains("Command stdin:\nset -eu"));
            std::fs::remove_file(fixture.package().join("example.com.zone")).unwrap();
        }
    }
}
