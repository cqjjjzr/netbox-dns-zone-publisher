# netbox-dns-zone-publisher

A Rust publisher for NetBox DNS and two independent CoreDNS servers. It reads the NetBox DNS REST API, retains historical normalized collections, optionally signs conventional NSEC zones, and installs verified zone files locally and using SCP/SSH. CoreDNS serves local files and does not depend on NetBox to answer or restart.

The publisher is a separate process on ns1. It is **not** a NetBox custom script or a CoreDNS plugin. NetBox/Django/PostgreSQL do not need to be installed on either DNS VM.

## Implemented

- Explicit NetBox zone/view scope; bounded authenticated API collection, complete pagination, duplicate/count checks, and two matching normalized reads.
- Generated and manual active DNS records, including external addresses, DS, explicit zero TTL and multi-string/binary TXT. Record parsing and rendering enforce byte-preserving RDATA round trips. Complex types can be emitted using standard RFC 3597 generic notation.
- Two explicit stages: `collect` generates, signs, and validates a complete release; `publish` validates and installs its final zone files. Content changes are reported in the collection result as a unified record diff.
- Durable collection packages and an atomic pointer/serial ledger. Record or configuration changes create a new collection for all configured zones with one shared `YYYYMMDDNN` serial; unchanged collections write no package and consume no serial.
- Standard BIND signing utilities, without a BIND daemon. Collection signs once, preserves the allocated serial, and stores verified final files. The selected collection binds publication to its NetBox source scope and complete configuration.
- Unique temporary files beside live zones, SCP upload, transfer checks and atomic per-file rename. DNS validation and signature verification run globally on the publisher before target installation.
- Every local or SSH target reconciles from the selected final files. Signature refresh creates a new collection and can reuse retained unsigned files during a NetBox outage.

## Build and check

Tested with Rust 1.94.1 on Linux. Dependencies are pinned in `Cargo.lock`.

```sh
cargo build --release --locked
cargo test --all-targets --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
```

## Operator workflow

Install runtime dependencies on Debian 13:

```sh
sudo apt install bind9-utils openssh-client coreutils util-linux
```

Install the release binary on the publisher host. Targets may be local or SSH, in any order. On remote nodes, install `openssh-server`, `coreutils` and `util-linux`, and provision the publication account and zone directory as described in [operations](docs/operations.md). Adapt [the example configuration](examples/publisher.toml) with NetBox view/zone names, paths and signing keys. Use a dedicated read-only NetBox identity and store its token in a protected file.

```sh
netbox-dns-zone-publisher --config /etc/netbox-dns-zone-publisher/publisher.toml collect
netbox-dns-zone-publisher --config /etc/netbox-dns-zone-publisher/publisher.toml publish
```

Commands log to stderr, with journald priority prefixes when `JOURNAL_STREAM` is set. They produce no routine stdout or JSON output. An unchanged collection emits two INFO entries; a no-op publication is quiet. The [systemd timer](packaging/netbox-dns-zone-publisher.timer) schedules both stages. Exit 1 indicates an execution error; otherwise commands exit 0. Per-zone rejection and individual target failures are logged without changing the exit status.

Zone files use canonical names such as `example.com.zone`. Unsafe filename characters and Windows device names are escaped; long stems receive a hash suffix.

`collect` creates a new release when a signed collection reaches `refresh_secs`. It tries NetBox first and may reuse the selected unsigned files when NetBox is unavailable and the configuration is unchanged. `publish` never signs or creates collections; it accepts signed files according to their actual `dnssec-verify` result, not collection age.

See [operations and recovery](docs/operations.md) and [design](docs/design.md).

## Scope boundaries

ACME challenge TXT values remain in acme-dns. Only stable enrollment CNAMEs and delegation/DS records belong in NetBox. The publisher does not participate in each challenge update.

This implementation does not provide a DKIM HTTP registry, automatic DNSSEC key rollover/DS changes, automatic writer failover, an RFC 2136 update service, or an externally mastered secondary-zone collector. Those remain separate explicit requirements, rather than implied exporter features. Two matching HTTP exports reduce inconsistent-read risk but do not establish a database transaction snapshot. DNSSEC service during signer failure remains bounded by signature expiration.
