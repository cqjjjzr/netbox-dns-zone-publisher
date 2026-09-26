//! Small fixtures shared by integration tests. No global environment changes or services.
#![allow(dead_code)] // Each integration-test binary uses a different subset.

use netbox_dns_zone_publisher::config::{Config, NetBox, Signer, Target, ZoneConfig};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tempfile::TempDir;

pub fn assert_error<T: std::fmt::Debug>(result: anyhow::Result<T>, expected: &str) {
    let error = format!("{:#}", result.expect_err(expected));
    assert!(
        error.contains(expected),
        "expected {expected:?}, got {error:?}"
    );
}

pub fn page(rows: Vec<Value>) -> Value {
    json!({"count": rows.len(), "next": null, "results": rows})
}

pub fn view() -> Value {
    json!({"id": 1, "name": "public"})
}
pub fn zone(id: u64, name: &str) -> Value {
    json!({"id": id, "name": name, "view": {"id": 1}, "active": true, "default_ttl": 300})
}
pub fn record(id: u64, zone: u64, name: &str, kind: &str, value: &str) -> Value {
    json!({"id": id, "zone": {"id": zone}, "fqdn": name, "ttl": null,
        "type": kind, "value": value, "absolute_value": null, "active": true})
}
pub fn zone_records(id: u64, name: &str) -> Vec<Value> {
    vec![
        record(
            1,
            id,
            &format!("{name}."),
            "SOA",
            &format!("ns.{name}. hostmaster.{name}. 42 3600 600 86400 300"),
        ),
        record(2, id, &format!("{name}."), "NS", &format!("ns.{name}.")),
        record(3, id, &format!("ns.{name}."), "A", "192.0.2.1"),
        record(4, id, &format!("www.{name}."), "A", "192.0.2.10"),
    ]
}

#[derive(Clone, Debug)]
pub struct Request {
    pub target: String,
    pub headers: Vec<String>,
}
pub struct Response {
    pub status: u16,
    pub body: String,
}
impl Response {
    pub fn json(value: Value) -> Self {
        Self {
            status: 200,
            body: value.to_string(),
        }
    }
    pub fn unavailable() -> Self {
        Self {
            status: 503,
            body: "maintenance".into(),
        }
    }
}

pub struct HttpServer {
    pub url: url::Url,
    pub requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl HttpServer {
    pub fn start(mut respond: impl FnMut(&Request) -> Response + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            for connection in listener.incoming() {
                let mut stream = connection.expect("accept test request");
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let target = line
                    .split_whitespace()
                    .nth(1)
                    .expect("HTTP request target")
                    .to_owned();
                let mut headers = Vec::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    headers.push(line.trim().to_owned());
                }
                let request = Request { target, headers };
                captured.lock().unwrap().push(request.clone());
                let response = respond(&request);
                // A client rejecting a response may close before the body is sent.
                let _ = write!(
                    stream,
                    "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.body
                );
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }
    pub fn scripted(responses: Vec<Response>) -> Self {
        let mut responses = responses.into_iter();
        Self::start(move |_| responses.next().expect("unexpected extra HTTP request"))
    }
}
impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.url.socket_addrs(|| None).unwrap()[0]);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.expect("HTTP fixture thread panicked");
        }
    }
}

pub struct ApiState {
    pub unavailable: bool,
    pub records: BTreeMap<String, Vec<Value>>,
}
pub struct Api {
    pub server: HttpServer,
    pub state: Arc<Mutex<ApiState>>,
}
impl Api {
    pub fn new(names: &[&str]) -> Self {
        let zones: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(i, name)| zone(i as u64 + 1, name))
            .collect();
        let state = Arc::new(Mutex::new(ApiState {
            unavailable: false,
            records: names
                .iter()
                .enumerate()
                .map(|(i, name)| (name.to_string(), zone_records(i as u64 + 1, name)))
                .collect(),
        }));
        let shared = state.clone();
        let server = HttpServer::start(move |request| {
            let state = shared.lock().unwrap();
            if state.unavailable {
                return Response::unavailable();
            }
            let url = url::Url::parse(&format!("http://fixture{}", request.target)).unwrap();
            let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            let rows = match url.path() {
                "/api/plugins/netbox-dns/views/" => {
                    assert_eq!(query["name"], "public");
                    vec![view()]
                }
                "/api/plugins/netbox-dns/zones/" => {
                    assert_eq!(query["view_id"], "1");
                    zones
                        .iter()
                        .filter(|z| z["name"] == query["name"])
                        .cloned()
                        .collect()
                }
                "/api/plugins/netbox-dns/records/" => {
                    let id: u64 = query["zone_id"].parse().unwrap();
                    let zone = zones.iter().find(|z| z["id"] == id).unwrap();
                    state.records[zone["name"].as_str().unwrap()].clone()
                }
                other => panic!("unexpected API path: {other}"),
            };
            Response::json(page(rows))
        });
        Self { server, state }
    }
}

pub fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

pub struct Sandbox {
    pub root: TempDir,
    pub config: Config,
}
impl Sandbox {
    pub fn new(url: url::Url, names: &[&str]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path();
        fs::write(path.join("token"), "test-token\n").unwrap();
        script(
            &path.join("checker"),
            "test \"$1 $2 $3\" = '-q -i local'\ntest \"$5\" = '-'\ncat >/dev/null\ntest ! -f \"$0.fail\"",
        );
        let config = Config {
            state_dir: path.join("state"),
            checker: path.join("checker"),
            netbox: NetBox {
                view: "public".into(),
                url,
                token_file: path.join("token"),
                timeout_secs: 2,
                max_records: 100,
            },
            zones: names
                .iter()
                .map(|name| ZoneConfig {
                    name: name.to_string(),
                    sign: false,
                    nsec3: false,
                    keys: vec![],
                })
                .collect(),
            targets: ["ns1", "ns2"]
                .iter()
                .map(|name| Target {
                    name: name.to_string(),
                    directory: path.join(name),
                    ssh: None,
                })
                .collect(),
            signer: None,
        };
        config.validate().unwrap();
        Self { root, config }
    }
    pub fn enable_signing(&mut self) {
        let path = self.root.path();
        // These stubs test orchestration only; real cryptography is covered separately.
        script(
            &path.join("signer"),
            r#"
test ! -f "$0.fail"
printf '%s\n' "$@" >> "$0.calls"
while test "$1" != '-f'; do shift; done
cp "$3" "$2"
"#,
        );
        script(
            &path.join("verifier"),
            "test \"$1 $2\" = '-z -o'\ntest -s \"$4\"\ntest ! -f \"$0.fail\"",
        );
        self.config.signer = Some(Signer {
            program: path.join("signer"),
            verifier: path.join("verifier"),
            validity_secs: 1209600,
            refresh_secs: 86400,
        });
        for zone in &mut self.config.zones {
            let key = path.join(format!("K{}", zone.name));
            fs::write(format!("{}.private", key.display()), "fixture private key").unwrap();
            fs::write(
                format!("{}.key", key.display()),
                format!("{}. 300 IN DNSKEY 257 3 13 AQID\n", zone.name),
            )
            .unwrap();
            zone.sign = true;
            zone.keys = vec![key];
        }
    }
    pub fn pointer(&self) -> Value {
        read_json(&self.config.state_dir.join("current.json"))
    }
    pub fn package(&self) -> PathBuf {
        self.config
            .state_dir
            .join("collected")
            .join(self.pointer()["collection_id"].to_string())
    }
    pub fn manifest(&self) -> Value {
        read_json(&self.package().join("collection.json"))
    }
    pub fn make_refresh_due(&self) {
        let path = self.package().join("collection.json");
        let mut manifest = read_json(&path);
        manifest["collected_at"] = json!(1);
        fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }
    pub fn cli_command(&self, command: &str) -> Command {
        let path = self.root.path().join("publisher.toml");
        fs::write(&path, toml::to_string(&self.config).unwrap()).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_netbox-dns-zone-publisher"));
        cmd.args(["--config"])
            .arg(path)
            .arg(command)
            .env_remove("JOURNAL_STREAM")
            .env("RUST_LOG", "info");
        cmd
    }
    pub fn cli(&self, command: &str) -> Output {
        self.cli_command(command).output().unwrap()
    }
}
pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
