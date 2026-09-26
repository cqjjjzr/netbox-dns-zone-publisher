# netbox-dns-zone-publisher

A publisher for NetBox DNS and local/remote DNS servers. It reads the NetBox DNS REST API, retains historical normalized collections, optionally signs conventional NSEC zones, and installs verified zone files locally and using SCP/SSH.

The publisher runs external of NetBox or DNS server in a separate process.

The publisher keep all produced zone and manifest files and deploys the latest collection results. The collection and deployment should be run periodically.

## Build and check

```sh
cargo build --release
cargo test --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## Usage

Debian 13 is used as the example.


```sh
sudo apt install bind9-utils openssh-client util-linux coreutils
```

Install the release binary on the publisher host (may on any host with access to all destination servers). Targets may be local or SSH, in any order. On remote nodes, set up the SSH server and DNS server, and provision the publication account and zone directory as described in [operations](docs/operations.md). Adapt [the example configuration](examples/publisher.toml) with NetBox view/zone names, paths and signing keys.

```sh
netbox-dns-zone-publisher --config /etc/netbox-dns-zone-publisher/publisher.toml collect
netbox-dns-zone-publisher --config /etc/netbox-dns-zone-publisher/publisher.toml publish
```

Commands log to stderr, with journald priority prefixes when `JOURNAL_STREAM` is set. 

The operation has 2 stages, collect (NetBox → zone file) and publish (zone file → DNS server). The example [systemd timer](packaging/netbox-dns-zone-publisher.timer) schedules both stages.

See [operations and recovery](docs/operations.md).
