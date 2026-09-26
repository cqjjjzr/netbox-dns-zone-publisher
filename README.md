# netbox-dns-zone-publisher

A publisher for NetBox DNS and local/remote DNS servers. It reads the NetBox DNS REST API, retains historical normalized collections, optionally signs NSEC or NSEC3 zones, and installs verified zone files locally and using SCP/SSH.

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

## Set up an SSH receiving user

On the publisher, generate a key for the `dns-zone-publisher` service account:

```sh
sudo install -d -o dns-zone-publisher -g dns-zone-publisher -m 0700 \
  /var/lib/netbox-dns-zone-publisher/.ssh
sudo -u dns-zone-publisher ssh-keygen -t ed25519 -N '' \
  -f /var/lib/netbox-dns-zone-publisher/.ssh/id_ed25519
sudo cat /var/lib/netbox-dns-zone-publisher/.ssh/id_ed25519.pub
```

Copy the generated public key to `/path/to/id_ed25519.pub` on each target, then
run the following there. Replace `coredns` with your DNS server's existing group.

```sh
sudo apt install openssh-server coreutils
sudo adduser --system --group --disabled-password --shell /bin/sh \
  --home /var/lib/dns-publish dns-publish
sudo install -d -o dns-publish -g dns-publish -m 0700 /var/lib/dns-publish/.ssh
sudo install -o dns-publish -g dns-publish -m 0600 \
  /path/to/id_ed25519.pub /var/lib/dns-publish/.ssh/authorized_keys
sudo install -d -o dns-publish -g coredns -m 2750 /var/lib/coredns/zones
sudo systemctl enable --now ssh
```

Set `targets.ssh.host = "dns-publish@ns2.example.com"` and
`targets.directory = "/var/lib/coredns/zones"` in the publisher configuration.

## Build Debian package

### On Debian

Prerequisites: Debian 13 with `trixie-backports` enabled; Rust/Cargo ≥ 1.89.

```sh
sudo apt update
sudo apt install build-essential debhelper pkg-config clang cmake python3 bind9-utils
sudo apt install -t trixie-backports cargo rustc
cargo fetch --locked
dpkg-buildpackage -us -uc -b
```

### On other hosts

Prerequisites: Docker or Podman running Linux containers; network access.
Run either command from the repository root; packages go to `target/debian/`.

```sh
# Podman
./packaging/build-deb.sh

# Docker
CONTAINER_ENGINE=docker ./packaging/build-deb.sh
```
