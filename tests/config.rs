mod support;

use netbox_dns_zone_publisher::{
    config::{Config, Signer, Ssh},
    netbox::Source,
};
use support::{Sandbox, assert_error};

#[test]
fn example_configuration_is_valid_and_unknown_fields_are_rejected() {
    let example = include_str!("../examples/publisher.toml");
    let config: Config = toml::from_str(example).unwrap();
    config.validate().unwrap();
    assert!(toml::from_str::<Config>(&format!("typo = true\n{example}")).is_err());
    assert!(toml::from_str::<Config>(&example.replace("view =", "veiw =")).is_err());
}

#[test]
fn omitted_optional_settings_use_documented_defaults() {
    let config: Config = toml::from_str(
        r#"
state_dir = "/tmp/state"
zones = [{name = "example.com"}]
targets = []
[netbox]
url = "https://netbox.example/"
view = "public"
token_file = "/tmp/token"
[signer]
"#,
    )
    .unwrap();
    config.validate().unwrap();
    assert_eq!(config.checker.to_str().unwrap(), "named-checkzone");
    assert_eq!(config.netbox.timeout_secs, 15);
    assert_eq!(config.netbox.max_records, 100_000);
    assert!(!config.zones[0].sign);
    assert!(!config.zones[0].nsec3);
    let signer = config.signer.unwrap();
    assert_eq!(signer.program.to_str().unwrap(), "dnssec-signzone");
    assert_eq!(signer.verifier.to_str().unwrap(), "dnssec-verify");
    assert_eq!(signer.validity_secs, 1_209_600);
    assert_eq!(signer.refresh_secs, 86_400);
}

#[test]
fn nsec3_is_per_zone_and_default_serialization_preserves_existing_config_hashes() {
    let example = include_str!("../examples/publisher.toml");
    let old: Config = toml::from_str(example).unwrap();
    let explicit_default: Config =
        toml::from_str(&example.replace("# nsec3 = true", "nsec3 = false")).unwrap();
    let old_json = serde_json::to_value(&old).unwrap();
    assert!(old_json["zones"][0].get("nsec3").is_none());
    assert_eq!(
        serde_json::to_vec(&old).unwrap(),
        serde_json::to_vec(&explicit_default).unwrap()
    );

    let enabled: Config =
        toml::from_str(&example.replace("# nsec3 = true", "nsec3 = true")).unwrap();
    enabled.validate().unwrap();
    assert!(enabled.zones[0].nsec3);
    assert!(!enabled.zones[1].nsec3);
    let json = serde_json::to_vec(&enabled).unwrap();
    assert_ne!(json, serde_json::to_vec(&old).unwrap());
    let reloaded: Config = serde_json::from_slice(&json).unwrap();
    assert_eq!(reloaded.zones, enabled.zones);
}

#[test]
fn configuration_rejects_ambiguous_identities_and_unsafe_destinations() {
    type Case = (&'static str, fn(&mut Config));
    let cases: &[Case] = &[
        ("state_dir must be absolute", |c| {
            c.state_dir = "relative".into()
        }),
        ("NetBox view is required", |c| c.netbox.view = "  ".into()),
        ("duplicate zone", |c| {
            let mut zone = c.zones[0].clone();
            zone.name = "EXAMPLE.COM.".into();
            c.zones.push(zone);
        }),
        ("key paths must be absolute", |c| {
            c.zones[0].keys.push("relative".into())
        }),
        ("signed zone requires signer", |c| c.zones[0].sign = true),
        ("NSEC3 requires sign = true", |c| c.zones[0].nsec3 = true),
        ("target name must not be blank", |c| {
            c.targets[0].name = " ".into()
        }),
        ("duplicate target", |c| c.targets.push(c.targets[0].clone())),
        ("absolute non-root path", |c| {
            c.targets[0].directory = "/".into()
        }),
        ("absolute non-root path", |c| {
            c.targets[0].directory = "relative".into()
        }),
        ("unsafe target directory", |c| {
            c.targets[0].directory = "/zones/../escape".into()
        }),
        ("unsafe target directory", |c| {
            c.targets[0].directory = "/zones\ncommand".into()
        }),
        ("invalid SSH destination", |c| {
            c.targets[0].ssh = Some(Ssh {
                host: "-oProxyCommand=bad".into(),
                port: None,
                extra_args: vec![],
            })
        }),
    ];
    let fixture = Sandbox::new("http://127.0.0.1/".parse().unwrap(), &["example.com"]);
    for (expected, mutate) in cases {
        let mut config = fixture.config.clone();
        mutate(&mut config);
        assert_error(config.validate(), expected);
    }
}

#[test]
fn signing_windows_leave_time_to_refresh_before_expiry() {
    let fixture = Sandbox::new("http://127.0.0.1/".parse().unwrap(), &["example.com"]);
    for (refresh, validity, valid) in [
        (0, 100, false),
        (49, 100, true),
        (50, 100, false),
        (1, 2_592_000, true),
        (1, 2_592_001, false),
    ] {
        let mut config = fixture.config.clone();
        config.signer = Some(Signer {
            program: "sign".into(),
            verifier: "verify".into(),
            refresh_secs: refresh,
            validity_secs: validity,
        });
        assert_eq!(
            config.validate().is_ok(),
            valid,
            "refresh={refresh}, validity={validity}"
        );
    }
}

#[test]
fn source_rejects_unsafe_base_urls_and_zero_bounds_before_requests() {
    let fixture = Sandbox::new("http://127.0.0.1/".parse().unwrap(), &["example.com"]);
    for (url, expected) in [
        ("https://netbox.example/prefix", "must end with /"),
        ("https://netbox.example/?q=1", "query or fragment"),
        ("https://netbox.example/#fragment", "query or fragment"),
        (
            "https://user:password@netbox.example/",
            "credentials are not allowed",
        ),
    ] {
        let mut netbox = fixture.config.netbox.clone();
        netbox.url = url.parse().unwrap();
        assert_error(Source::new(&netbox).map(|_| ()), expected);
    }
    for (timeout, max_records) in [(0, 100), (1, 0)] {
        let mut netbox = fixture.config.netbox.clone();
        netbox.timeout_secs = timeout;
        netbox.max_records = max_records;
        assert_error(
            Source::new(&netbox).map(|_| ()),
            "invalid collection bounds",
        );
    }
}
