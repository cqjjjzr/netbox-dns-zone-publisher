use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use url::Url;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    #[serde(default = "check_program")]
    pub checker: PathBuf,
    pub netbox: NetBox,
    pub zones: Vec<ZoneConfig>,
    pub targets: Vec<Target>,
    pub signer: Option<Signer>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetBox {
    pub view: String,
    pub url: Url,
    pub token_file: PathBuf,
    #[serde(default = "timeout")]
    pub timeout_secs: u64,
    #[serde(default = "max_records")]
    pub max_records: usize,
}
fn timeout() -> u64 {
    15
}
fn max_records() -> usize {
    100_000
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    pub name: String,
    #[serde(default)]
    pub sign: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub nsec3: bool,
    #[serde(default)]
    pub keys: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub name: String,
    pub directory: PathBuf,
    pub ssh: Option<Ssh>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    pub host: String,
    #[serde(default)]
    pub extra_args: Vec<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    #[serde(default = "sign_program")]
    pub program: PathBuf,
    #[serde(default = "verify_program")]
    pub verifier: PathBuf,
    #[serde(default = "validity")]
    pub validity_secs: u64,
    #[serde(default = "refresh")]
    pub refresh_secs: u64,
}
fn sign_program() -> PathBuf {
    "dnssec-signzone".into()
}
fn verify_program() -> PathBuf {
    "dnssec-verify".into()
}
fn validity() -> u64 {
    1_209_600
}
fn refresh() -> u64 {
    86_400
}
fn check_program() -> PathBuf {
    "named-checkzone".into()
}

impl Config {
    pub fn read(path: &Path) -> Result<Config> {
        let r: Config = toml::from_str(&std::fs::read_to_string(path)?)?;
        r.validate()?;
        Ok(r)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.state_dir.is_absolute(), "state_dir must be absolute");
        ensure!(
            !self.netbox.view.trim().is_empty(),
            "NetBox view is required"
        );
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for z in &self.zones {
            let id = crate::dns::sanitize_zone_id_for_filename(&z.name)?;
            let name = crate::dns::canonicalize_name(&z.name)?;
            ensure!(
                ids.insert(id) && names.insert(name),
                "duplicate zone identity/name"
            );
            ensure!(
                z.keys.iter().all(|k| k.is_absolute()),
                "key paths must be absolute"
            );
            ensure!(
                !z.sign || (self.signer.is_some() && !z.keys.is_empty()),
                "signed zone requires signer and key paths"
            );
            ensure!(!z.nsec3 || z.sign, "NSEC3 requires sign = true");
        }
        let mut targets = BTreeSet::new();
        for t in &self.targets {
            ensure!(!t.name.trim().is_empty(), "target name must not be blank");
            ensure!(targets.insert(&t.name), "duplicate target name");
            ensure!(
                t.directory.is_absolute() && t.directory != Path::new("/"),
                "target directory must be an absolute non-root path"
            );
            let path = t
                .directory
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 target path"))?;
            ensure!(
                !path.chars().any(char::is_control) && !path.contains("/../"),
                "unsafe target directory"
            );
            if let Some(ssh) = &t.ssh {
                ensure!(
                    !ssh.host.is_empty()
                        && !ssh.host.starts_with('-')
                        && ssh
                            .host
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"@.:-_[]".contains(&b)),
                    "invalid SSH destination"
                );
            }
        }
        if let Some(s) = &self.signer {
            ensure!(
                s.refresh_secs > 0
                    && s.refresh_secs < s.validity_secs / 2
                    && s.validity_secs <= 2_592_000,
                "invalid signing windows: require 0 < refresh_secs < validity_secs / 2 and validity_secs <= 2592000 (30 days)"
            );
        }
        Ok(())
    }
}
