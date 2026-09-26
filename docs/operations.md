# Operations

Run the publisher on one Linux host with access to NetBox and the target zone directories. Keep its state directory across upgrades and restarts. CoreDNS serves the installed files from each target's disk.

## Install and configure

Build the binary with the repository's locked dependencies:

```sh
cargo build --release --locked
sudo install -m 0755 target/release/netbox-dns-zone-publisher /usr/local/bin/
```

On a Debian publisher host, install the runtime tools:

```sh
sudo apt install bind9-utils openssh-client coreutils
```

Create a `dns-zone-publisher` account and a `coredns` group for the supplied service unit. Give the publisher write access to its state directory and local zone directory. For remote targets, create a dedicated publication account, such as `dns-publish`, and install an SSH server with SFTP support and GNU coreutils. The publisher runs `sh` commands on both local and remote targets.

Use mode 0750 for zone directories and ownership that lets the publication account write and CoreDNS read. The publisher installs zone files with mode 0644 and writes package files with mode 0600. Keep executables, Corefiles and deployment configuration under administrator control.

Copy [publisher.toml](../examples/publisher.toml) to `/etc/netbox-dns-zone-publisher/publisher.toml` and set these values:

| Setting | Operator action |
| --- | --- |
| `state_dir` | Choose an absolute path on persistent storage. |
| `netbox.url` | Set the HTTPS base URL with a trailing slash and no query or fragment. |
| `netbox.view`, `zones[].name` | Use the exact view name and the DNS zone names from NetBox. |
| `netbox.token_file` | Store a read-only NetBox API token in a file readable by the publisher account. |
| `targets[].directory` | Use an absolute zone directory on each target. |
| `targets[].ssh` | Set the SSH destination, optional port and authentication options for a remote target. |
| `zones[].sign`, `zones[].keys` | Enable signing and supply absolute BIND key basenames for signed zones. |

Pin verified SSH host keys for the publisher account and configure authentication without prompts. SSH and SCP run with batch mode and strict host-key checking. The supplied systemd service uses `ProtectHome=yes`; place credentials outside home directories and pass explicit paths through `ssh.extra_args`, such as `-i` and `-oUserKnownHostsFile=...`.

Adapt [Corefile](../examples/Corefile) to load the target files. Ordinary names map to files such as `example.com.zone`; unusual names use the filename encoding described in [design](design.md). Configure CoreDNS listeners and zones yourself. Removing a zone from the publisher configuration leaves its old target file in place, so remove the corresponding server configuration and file as part of decommissioning.

Before the first publication, compare the planned `YYYYMMDD01` UTC serial with the SOA serials that your servers and secondaries serve. The publisher does not read target serials, and a fresh state directory starts its own ledger.

## Collect and publish

Run both commands as the publication account with access to the same configuration and state:

```sh
netbox-dns-zone-publisher --config /etc/netbox-dns-zone-publisher/publisher.toml collect
netbox-dns-zone-publisher --config /etc/netbox-dns-zone-publisher/publisher.toml publish
```

During `collect`, the publisher reads the source twice, prepares zone files, signs configured zones and checks the results. Changed records, changed configuration or a due signature refresh create a new package. All zones in that package share one serial. Unchanged records and configuration leave the selected package in place unless a refresh is due.

During `publish`, the publisher checks the selected package and installs accepted zone files on the configured targets. You can repeat this command to repair missing files, changed bytes or incorrect modes. It uses the stored final files without contacting NetBox or signing again.

Run `collect` after changing configuration, including target settings. Publication refuses a package whose configuration hash differs. Replacing key file contents at the same path does not change the hash or trigger collection; coordinate key changes with signing refresh and the parent DS lifecycle.

Read the error logs after publication and query each server for the expected SOA and records. Exit status zero does not prove that all zones reached all targets: the publisher logs zone rejection and installation failures, then continues. Top-level errors, such as invalid configuration or a missing usable collection, exit with status 1.

## Schedule and monitor

Install the supplied [service](../packaging/netbox-dns-zone-publisher.service) and [timer](../packaging/netbox-dns-zone-publisher.timer) under `/etc/systemd/system/`. Adapt the service account, writable paths and timeout to your deployment, then enable the timer:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now netbox-dns-zone-publisher.timer
journalctl -u netbox-dns-zone-publisher.service
```

The timer starts 30 seconds after boot and waits 60 seconds after the previous service run ends. The service runs collection followed by publication, including after collection fails. It returns a publication error if one occurs; otherwise it returns the collection status. This permits retries from retained files during a source outage.

Both commands log to stderr. Set `RUST_LOG` to change the default `info` filter. An unchanged collection emits two INFO messages; a publication with no changes emits none at INFO. Under journald, the logger adds priority prefixes. Alert on error messages and signature expiration as well as failed service runs.

The supplied unit allows 300 seconds per run. Size that limit for your zone and target count: external checks, signing and transport operations have their own 120-second limits. API requests default to 15 seconds, with four times that allowance for each complete source read.

## Signing and source outages

For publisher signing, provision both `.key` and `.private` files for each BIND key basename. Set `sign = true`, configure `[signer]`, and keep the private keys on the publisher host. The default signature validity is 14 days and the refresh interval is one day. Configuration requires `0 < refresh_secs < validity_secs / 2`, with validity at most 30 days.

A due refresh first attempts NetBox collection. If fetching fails and the selected package has the same configuration hash, the publisher reuses its unsigned zone files, assigns a new serial and signs a new package. It can refresh after the previous signatures expire because the unsigned files supply the records. An unreadable token file or another API client setup error prevents this fallback.

Before refresh is due, a NetBox failure makes collection fail. You can continue publishing retained files that pass validation. Publication rejects expired or invalid signatures; it does not create replacement signatures. Keep the publisher running often enough to refresh before expiration.

For an emergency record change during a source outage, stop scheduled runs and back up the selected package before editing its `.unsigned.zone` file. Preserve its SOA serial below the next allocated serial. A due offline refresh can consume that edit, but a successful NetBox read supplies the source records instead. Editing the unsigned file alone makes its existing final file disagree, so publication rejects that zone until you produce a matching release. Apply the change in NetBox before normal collection resumes.

The example Corefile includes online signing for separate child zones. Provision those CoreDNS keys on the serving nodes and manage their parent delegations and DS records outside the publisher. Keep ACME challenge values in the ACME backend; use NetBox for stable CNAMEs and delegation data.

## State, backup and recovery

A state directory contains the following files for a single-zone release:

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

Stop scheduled runs and wait for active commands to finish before backing up the whole state directory, configuration, credentials and signing keys. Keep one active writer. The state lock covers commands using that directory; it provides no fencing across separate publisher hosts.

Use the recovery action that matches the failure:

| Failure | Recovery |
| --- | --- |
| Collection interrupted during storage | Retry `collect`. It retains the previous selection until the replacement is complete and skips consumed serials. |
| Selected package missing or malformed, ledger intact | Run `collect` with NetBox available to build a replacement. `publish` cannot use the damaged package. Damage confined to per-zone JSON blocks collection reuse but does not block publication, which reads the zone files. |
| Target unavailable or out of date | Repair access and retry `publish` with the selected package. Check the logs and served records. |
| Zone rejected during publication | Fix the source, configuration or signing problem, then collect and publish. Other accepted zones can proceed. |
| Pointer malformed, or missing beside `collected/` | Stop and fence publishers. Restore or reconstruct the serial ledger before collecting. |
| Daily serial counter exhausted or clock behind the ledger's day | Correct the clock if needed, or wait for the next UTC day. Preserve the ledger. |

For ledger recovery, inspect surviving packages and the serials served by primaries and secondaries. Preserve `last_serial` at or above known reservations and served serials, and ensure that the next date-based serial can advance them. Restoring target files alone does not restore this state. Selecting an old package can deploy an older SOA serial; restore desired records through a new collection instead.

The publisher retains historical packages and abandoned temporary directories without a retention policy. With commands stopped, prune unneeded packages and `.tmp` directories while preserving `current.json` and its selected package. It does not select an unreferenced directory during recovery.
