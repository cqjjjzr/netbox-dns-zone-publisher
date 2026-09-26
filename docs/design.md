# Design

Run one publisher to copy NetBox DNS records into zone files for your DNS servers. CoreDNS reads those files from its own disk, so serving DNS does not require a connection to NetBox or the publisher. You can install the files on local or SSH targets in any order.

Use `collect` to prepare a release and `publish` to install it. This split lets you retry deployment during a NetBox outage without fetching records or using signing keys.

```text
NetBox DNS REST API
        |
        | two matching normalized reads
        v
collect: render -> check -> sign if configured -> verify
        |
        v
state_dir/collected/<id>/  <-- state_dir/current.json
        |
        v
publish: check unsigned/final agreement -> check zone and signatures
        |
        +--> local zone directory
        +--> SCP upload and SSH activation
```

## Source records

In the configuration, name one NetBox view and an explicit set of zones. During collection, the publisher resolves the view and each zone to a unique API object. It checks zone membership and active status, then reads the zone's records through the NetBox DNS REST endpoints.

The collector includes active manual and generated records. For a missing record TTL, it uses the zone default; it preserves an explicit zero. It prefers `absolute_value` over `value` for RDATA and resolves relative names against the zone origin.

Collection checks cover record IDs, zone IDs, page counts, pagination cycles and complete results. A pagination URL must retain the original origin and endpoint path. The HTTP client refuses redirects. Configure HTTPS to protect the token: the code accepts HTTP URLs too.

`max_records` bounds the count per zone, including inactive records. The default is 100,000. Each request has a `timeout_secs` deadline, and each full read has a deadline of four times that value. The publisher requires two complete reads with equal normalized records. This detects changes between reads but provides no database transaction snapshot.

## DNS representation and checks

The publisher uses the `domain` crate to parse and format zone records. It retains typed records in memory and uses unsigned zone files as snapshots. Rendering sorts and deduplicates records. Supported RFC 3597 data and TXT byte escapes pass through the same parser and formatter.

Comparison renders the SOA serial as zero without changing the retained records. A NetBox serial change alone therefore leaves the normalized collection unchanged. The publisher assigns the output serial from its own ledger.

Source checks reject out-of-zone owners, inconsistent TTLs within an RRset, generated DNSSEC records and non-glue data below a delegation. At a delegation, the publisher accepts NS and DS records, plus A/AAAA glue for the named servers. It does not require missing glue. `named-checkzone -q -i local` checks the rendered zone before storage, including its SOA and NS structure.

Zone filenames derive from canonical DNS names. For example, `Example.COM.` becomes `example.com.zone`. The filename encoder escapes unsafe characters and Windows device names and adds a hash suffix to long stems.

Zone-file escaping is separate from filename encoding. Owners and `$ORIGIN` escape syntax characters without changing zone identities or filenames. Readable RDATA is reparsed and checked against the original wire bytes; if it cannot round-trip exactly, the publisher emits RFC 3597 generic RDATA. This preserves unusual DNS names while keeping ordinary records readable.

## Release contents

A collection covers the configured zone set with one shared serial. For each zone, it contains:

| File                   | Purpose                                                                                                              |
|------------------------|----------------------------------------------------------------------------------------------------------------------|
| `<zone>.unsigned.zone` | Authoritative snapshot with the release serial; source for comparisons, record diffs and offline refresh.            |
| `<zone>.zone`          | Final bytes for deployment, including signatures for a signed zone.                                                  |
| `collection.json`      | One manifest per collection, with its ID, serial, timestamp, source URL/view, zones, reasons and configuration hash. |

The configuration hash covers the parsed configuration, including targets, paths and signer settings. TOML comments and formatting do not affect it. Changes to the contents of a token or key file do not affect it either.

Collection creates a release after a record or configuration change, or once a signed release reaches `refresh_secs`. A release includes all configured zones. An unchanged collection with no refresh due consumes no serial and writes no package. The manifest and logs include unified record diffs for content changes.

For a signed zone, the publisher appends the configured public keys to the unsigned input and runs `dnssec-signzone -z -N keep`. It uses NSEC, preserves the assigned serial and sets signature inception five minutes in the past. It then runs `dnssec-verify -z` and checks the final zone. Targets receive the same final bytes and need no signing keys or BIND utilities.

During a due refresh, a successful NetBox read supplies the new records. After a fetch failure, the publisher can use the selected package's unsigned files if the configuration hash matches. It assigns a new serial and signs those records into a new package. The unsigned source serial must be less than the next serial. Client setup errors, including an unreadable token file, fail before this fallback. An offline refresh leaves the old package unchanged.

## Serial allocation and crash recovery

Both CLI commands hold an advisory lock on `state_dir/lock`. Keep one publisher with one state directory; the lock does not coordinate separate hosts or state directories.

`current.json` stores the selected `collection_id` and the last reserved serial, `last_serial`. Serials use `YYYYMMDDNN` in UTC, with `NN` from 01 through 99. Allocation rejects an earlier calendar day, an exhausted day's counter and numeric overflow. The publisher does not consult target SOA serials.

Collection prepares, checks and serializes the package before reserving its serial. It then:

1. Replaces `current.json` with the new `last_serial`, retaining the previous collection selection.
2. Writes and syncs the package in `collected/.<id>.tmp/`.
3. Renames the directory to `collected/<id>/` and syncs its parent.
4. Replaces `current.json` to select the complete package.

Each file replacement uses a temporary file and rename. Collection IDs start from the current millisecond timestamp and exceed existing numeric package and temporary-directory IDs. A failed write after reservation consumes the serial. Retrying collection skips that reservation; it does not promote abandoned directories.

A damaged selected package causes a warning. With a valid ledger and a successful NetBox read, `collect` can build a replacement. `publish` requires a readable selected package. A malformed pointer, or a missing pointer alongside an existing `collected/` directory, requires ledger recovery before either command can proceed.

## Publication and failure boundaries

Before deployment, `publish` requires a matching configuration hash. It checks each unsigned zone, compares its records with the final file after excluding generated DNSSEC data, and checks the final zone. Signed zones must pass `dnssec-verify`. A rejected zone remains untouched on the targets; other accepted zones can proceed.

For each accepted zone and target, the publisher compares the installed bytes and mode. Matching content with mode 0644 needs no write. Matching content with another mode needs a permission repair. For changed content, the publisher stages a file beside the live file, checks its SHA-256 digest, sets mode 0644, flushes it, renames it over the live file and flushes the directory. Remote staging uses SCP; activation uses SSH with pinned host keys and batch authentication.

A rename replaces one complete file. Zones and targets can serve different releases after a partial failure. Retry `publish` to reconcile them. Deployment has no target lock or distributed ordering, so fence competing publishers and other writers to the zone directories.

Per-zone rejection and per-target installation failures produce error logs without a failing command exit status. Monitor those logs and query the servers to confirm deployment. Collection age schedules signing refresh; publication checks the signatures themselves.

Manage DNSSEC rollover and parent DS updates outside this program. Keep ACME challenge updates in their serving backend, with stable enrollment CNAMEs and delegation records in NetBox. Use a persistent secondary DNS implementation for externally mastered zones so that refresh and expiration remain part of their operation.
