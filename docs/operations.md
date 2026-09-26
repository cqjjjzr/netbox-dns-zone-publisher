# Operations

Run the publisher on one Linux host with access to NetBox and the target zone directories. The document uses CoreDNS as an example (any other server implementations with file watch or periodical reload should also do).

## Install and configure

Build the binary with the repository's locked dependencies:

```sh
cargo build --release
sudo install -m 0755 target/release/netbox-dns-zone-publisher /usr/local/bin/
```

On a Debian publisher host, install the runtime tools:

```sh
sudo apt install bind9-utils openssh-client coreutils
```

Create a `dns-zone-publisher` account and a `coredns` group for the supplied service unit. Give the publisher write access to its state directory and local zone directory. For remote targets, create a dedicated publication account, such as `dns-publish`, and install an SSH server with SFTP support and GNU coreutils. The publisher runs `sh` commands on both local and remote targets.

Use mode 0750 for zone directories and ownership that lets the publication account write and CoreDNS read. The publisher installs zone files with mode 0644 and writes package files with mode 0600. Keep executables, Corefiles and deployment configuration under administrator control.

Copy [publisher.toml](../examples/publisher.toml) to `/etc/netbox-dns-zone-publisher/publisher.toml` and set it up.

Adapt [Corefile](../examples/Corefile) to load the target files. Ordinary names map to files such as `example.com.zone`. Configure CoreDNS listeners and zones yourself.

Before the first publication, compare the planned `YYYYMMDD01` UTC serial with the SOA serials that your servers and secondaries serve. The publisher does not read target serials, and a fresh state directory starts its own ledger.

## Collect and publish

Run both commands as the publication account with access to the same configuration and state:

```sh
netbox-dns-zone-publisher --config /etc/netbox-dns-zone-publisher/publisher.toml collect
netbox-dns-zone-publisher --config /etc/netbox-dns-zone-publisher/publisher.toml publish
```

During `collect`, the publisher reads the source twice, prepares zone files, signs configured zones and checks the results. Changed records, changed configuration or a due signature refresh create a new package. All zones in that package share one serial. Unchanged records and configuration leave the selected package in place unless a refresh is due.

If you really want to manually change the collected file beforer publish, you need to ensure the unsigned one matches the signed one. Still, this will be overwritten on next collection, so you have to either fix the root cause or disable the timer. 

During `publish`, the publisher checks the selected package and installs accepted zone files on the configured targets. You can repeat this command to repair missing files, changed bytes or incorrect modes. It uses the stored final files without contacting NetBox or signing again.

Run `collect` after changing configuration, including target settings. Publication refuses a package whose configuration hash differs.

## Schedule and monitor

Install the supplied [service](../packaging/netbox-dns-zone-publisher.service) and [timer](../packaging/netbox-dns-zone-publisher.timer) under `/etc/systemd/system/`. Adapt the service account, writable paths and timeout to your deployment, then enable the timer:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now netbox-dns-zone-publisher.timer
journalctl -u netbox-dns-zone-publisher.service
```

## State

A state directory contains the following files:

```text
state_dir/
├── current.json
├── lock
└── collected/
    └── <collection-id>/
        ├── collection.json
        ├── example.com.unsigned.zone
        └── example.com.zone
```

`current.json` holds the selected collection ID and `last_serial`, the last reserved serial. An interrupted write can leave `last_serial` above the selected package's serial. Preserve that value to avoid reusing a reservation. The publisher permits 99 reservations per UTC day, including reservations consumed by failed writes.
