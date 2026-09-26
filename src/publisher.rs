use crate::{
    config::{Config, ZoneConfig},
    deployment,
    dns::{self, Records, Zone},
    netbox::Source,
    util,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use similar::TextDiff;
use std::{collections::BTreeMap, ffi::OsString, fs, time::Duration};

/// A prepared release: NetBox scope, shared serial, and reported reasons.
///
/// The manifest records reasons instead of addition/removal counters; a plain
/// content change records the exact record diff in `reasons`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub id: u64,
    pub serial: u32,
    pub url: String,
    pub view: String,
    pub zones: Vec<String>,
    pub reasons: Vec<String>,
    pub collected_at: u64,
}

/// The `current.json` pointer and the serial reservation ledger.
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentCollection {
    collection_id: Option<u64>,
    last_serial: u32,
}

/// Zone file text per canonical zone ID.
type ZoneFiles = BTreeMap<String, String>;

/// A collection manifest with the normalized records and final files it selects.
#[derive(Serialize, Deserialize)]
struct CollectionPackage {
    #[serde(flatten)]
    collection: Collection,
    config_sha256: String,
    #[serde(skip)]
    records: Records,
    #[serde(skip)]
    unsigneds: ZoneFiles,
    #[serde(skip)]
    finals: ZoneFiles,
}

/// Read collection pointed by current.json
fn read_current_collection(
    c: &Config,
    load_records: bool,
) -> Result<(CurrentCollection, Option<CollectionPackage>)> {
    // Read current.json
    let current_path = c.state_dir.join("current.json");
    let current: CurrentCollection = match fs::read(&current_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("invalid current pointer")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                !c.state_dir.join("collected").exists(),
                "current pointer missing; recover serial ledger before collecting"
            );
            CurrentCollection::default()
        }
        Err(error) => return Err(error.into()),
    };
    let Some(id) = current.collection_id else {
        return Ok((current, None));
    };

    // A damaged package can be rebuilt, but the serial reservation ledger must
    // survive so that the replacement never reuses an already reserved serial.
    let package = match read_collection(c, &current, id, load_records) {
        Ok(package) => Some(package),
        Err(error) => {
            log::warn!("Ignoring invalid current collection {id}: {error:#}");
            None
        }
    };
    Ok((current, package))
}

/// Read a collection's data
fn read_collection(
    c: &Config,
    current: &CurrentCollection,
    id: u64,
    load_records: bool,
) -> Result<CollectionPackage> {
    // Read collection.json pointed by current.json
    let directory = c.state_dir.join("collected").join(id.to_string());
    let mut package: CollectionPackage = serde_json::from_slice(
        &fs::read(directory.join("collection.json"))
            .context("incomplete collection: missing manifest")?,
    )
    .context("invalid collection manifest")?;
    ensure!(
        package.collection.id == id
            && package.collection.serial > 0
            && package.collection.serial <= current.last_serial,
        "collection identity/serial does not match current pointer"
    );

    // Read final files and (optionally) normalized records
    let mut records = Records::new();
    let mut unsigneds = ZoneFiles::new();
    let mut finals = ZoneFiles::new();
    for name in &package.collection.zones {
        let zone_id = dns::sanitize_zone_id_for_filename(name)?;
        if load_records {
            let bytes =
                util::bounded_read(fs::File::open(directory.join(format!("{zone_id}.json")))?)?;
            let zone: Zone = serde_json::from_slice(&bytes)?;
            ensure!(
                zone.name == dns::canonicalize_name(name)?,
                "collection zone identity mismatch"
            );
            ensure!(
                records.insert(zone_id.clone(), zone).is_none(),
                "duplicate collection zone"
            );
        }
        let unsigned = util::bounded_read(fs::File::open(
            directory.join(format!("{zone_id}.unsigned.zone")),
        )?)?;
        ensure!(
            unsigneds
                .insert(zone_id.clone(), String::from_utf8(unsigned)?)
                .is_none(),
            "duplicate collection zone"
        );
        let contents =
            util::bounded_read(fs::File::open(directory.join(format!("{zone_id}.zone")))?)?;
        ensure!(
            finals
                .insert(zone_id, String::from_utf8(contents)?)
                .is_none(),
            "duplicate collection zone"
        );
    }
    package.records = records;
    package.unsigneds = unsigneds;
    package.finals = finals;
    Ok(package)
}

fn validate_with_bind(c: &Config, name: &str, contents: &str) -> Result<()> {
    let name = dns::canonicalize_name(name)?;
    util::command(
        &duct::cmd(
            c.checker.as_os_str(), // default binary: named-checkzone; bare names search PATH; explicit paths stay paths
            ["-q", "-i", "local", &name, "-"], // quiet, local integrity checks, stdin
        ),
        contents.as_bytes(),      // candidate zone text fed on stdin
        Duration::from_secs(120), // cap the external checker
    )
    .with_context(|| format!("check zone {name}"))?;
    Ok(())
}

fn verify_signed_zone(c: &Config, zone_config: &ZoneConfig, contents: &str) -> Result<()> {
    let signer = c.signer.as_ref().context("signer missing")?;
    let directory = tempfile::tempdir_in(&c.state_dir)?;
    let path = directory.path().join("signed.zone");
    fs::write(&path, contents)?;
    util::command(
        &duct::cmd(
            signer.verifier.as_os_str(), // default binary: dnssec-verify
            [
                OsString::from("-z"), // ignore the KSK flag, as during signing
                "-o".into(),          // zone origin follows
                zone_config.name.clone().into(),
                path.as_os_str().to_owned(), // signed zone file to verify
            ],
        ),
        &[],                      // no stdin: the zone is the file argument
        Duration::from_secs(120), // cap signature verification
    )
    .with_context(|| format!("verify signed zone {}", zone_config.name))?;
    Ok(())
}

fn sign_zone_file(c: &Config, zone_config: &ZoneConfig, unsigned: &str) -> Result<String> {
    let signer = c.signer.as_ref().context("signer missing")?;
    let directory = tempfile::tempdir_in(&c.state_dir)?;
    let input = directory.path().join("unsigned.zone");
    let output = directory.path().join("signed.zone");
    let mut source = unsigned.to_owned();
    for key in &zone_config.keys {
        ensure!(
            fs::metadata(format!("{}.private", key.display()))?.is_file(),
            "private signing key is not a file"
        );
        source.push_str(
            &fs::read_to_string(format!("{}.key", key.display()))
                .context("read public signing key")?,
        );
        source.push('\n');
    }
    fs::write(&input, source)?;

    let mut args: Vec<OsString> = [
        "-q",   // quiet
        "-n",   // thread count
        "1",    // one thread
        "-z",   // ignore the KSK flag
        "-N",   // SOA serial format
        "keep", // preserve the serial set by render_with_serial
        "-o",   // zone origin
        &zone_config.name,
        "-s",                                     // signature inception
        "now-300",                                // five minutes back for clock skew
        "-e",                                     // signature expiry
        &format!("now+{}", signer.validity_secs), // after the configured validity
        "-f",                                     // output file
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.push(output.as_os_str().to_owned()); // signed output written here
    args.push(input.as_os_str().to_owned()); // unsigned zone to sign
    args.extend(
        zone_config
            .keys
            .iter()
            .map(|key| key.as_os_str().to_owned()),
    ); // signing keys
    util::command(
        &duct::cmd(
            signer.program.as_os_str(), // default binary: dnssec-signzone
            args,                       // flags, output file, unsigned zone, then keys
        )
        .dir(directory.path()),
        &[],                      // no stdin: the input file argument carries the zone and keys
        Duration::from_secs(120), // cap signing
    )
    .with_context(|| format!("sign zone {}", zone_config.name))?;
    let signed = fs::read_to_string(&output)?;
    verify_signed_zone(c, zone_config, &signed)?;
    Ok(signed)
}

fn next_serial(last: u32, date: time::Date) -> Result<u32> {
    let day = u32::try_from(date.year())?
        .checked_mul(10_000)
        .and_then(|value| {
            value.checked_add(u32::from(u8::from(date.month())) * 100 + u32::from(date.day()))
        })
        .context("serial date overflow")?;
    let base = day.checked_mul(100).context("serial date exceeds u32")?;
    ensure!(
        last / 100 <= day,
        "clock moved behind the last allocated serial day"
    );
    if last < base {
        Ok(base + 1)
    } else {
        ensure!(last % 100 < 99, "99 releases per UTC day exhausted");
        last.checked_add(1).context("serial exhausted")
    }
}

fn next_collection_id(root: &std::path::Path) -> Result<u64> {
    let mut id = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)?;
    if root.exists() {
        for entry in fs::read_dir(root)? {
            let filename = entry?.file_name();
            let filename = filename.to_string_lossy();
            if let Ok(previous) = filename
                .trim_start_matches('.')
                .trim_end_matches(".tmp")
                .parse::<u64>()
            {
                id = id.max(previous.checked_add(1).context("collection ID exhausted")?);
            }
        }
    }
    Ok(id)
}

fn prepare_zone_files(
    c: &Config,
    records: &Records,
    previous_unsigneds: Option<&ZoneFiles>,
    serial: u32,
) -> Result<(ZoneFiles, ZoneFiles)> {
    let mut unsigneds = ZoneFiles::new();
    let mut finals = ZoneFiles::new();
    for zone in &c.zones {
        let id = dns::sanitize_zone_id_for_filename(&zone.name)?;
        let scanned_records = if let Some(previous_unsigneds) = previous_unsigneds {
            let previous = previous_unsigneds
                .get(&id)
                .context("missing previous unsigned zone")?;
            let parsed_records = dns::parse(&zone.name, previous)?;
            let previous_serial = dns::soa_serial(&zone.name, &parsed_records)?;
            ensure!(
                previous_serial < serial,
                "source SOA serial is not older than the next collection serial"
            );
            parsed_records
        } else {
            let zone_data = records.get(&id).context("missing configured zone")?;
            dns::internal_to_scanned_records(&zone_data.name, &zone_data.records)?
        };
        let unsigned = dns::render_with_serial(&zone.name, scanned_records, serial)?;
        validate_with_bind(c, &zone.name, &unsigned)?;
        let final_zone = if zone.sign {
            sign_zone_file(c, zone, &unsigned)?
        } else {
            unsigned.clone()
        };
        validate_with_bind(c, &zone.name, &final_zone)?;
        ensure!(
            final_zone.len() as u64 <= util::MAX_FILE,
            "collection zone exceeds size limit"
        );
        unsigneds.insert(id.clone(), unsigned);
        finals.insert(id, final_zone);
    }
    Ok((unsigneds, finals))
}

fn prepare_collection(
    c: &Config,
    last_serial: u32,
    reasons: Vec<String>,
    records: Records,
    previous_unsigneds: Option<&ZoneFiles>,
    config_sha256: String,
) -> Result<CollectionPackage> {
    let serial = next_serial(last_serial, time::OffsetDateTime::now_utc().date())?;
    let root = c.state_dir.join("collected");
    let id = next_collection_id(&root)?;

    let mut zones: Vec<_> = records.values().map(|zone| zone.name.clone()).collect();
    zones.sort();
    let collection = Collection {
        id,
        serial,
        url: c.netbox.url.to_string(),
        view: c.netbox.view.clone(),
        zones,
        reasons,
        collected_at: util::now(),
    };
    let (unsigneds, finals) = prepare_zone_files(c, &records, previous_unsigneds, serial)?;

    Ok(CollectionPackage {
        collection,
        config_sha256,
        records,
        unsigneds,
        finals,
    })
}

/// Validate and serialize every file before reserving the collection's serial.
fn serialize_collection(package: &CollectionPackage) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    for (zone_id, zone) in &package.records {
        ensure!(
            *zone_id == dns::sanitize_zone_id_for_filename(&zone.name)?,
            "invalid snapshot zone ID"
        );
        let json = serde_json::to_vec_pretty(zone)?;
        ensure!(
            json.len() as u64 <= util::MAX_FILE,
            "collection zone exceeds size limit"
        );
        files.insert(format!("{zone_id}.json"), json);
        files.insert(
            format!("{zone_id}.unsigned.zone"),
            package.unsigneds[zone_id].as_bytes().to_vec(),
        );
        files.insert(
            format!("{zone_id}.zone"),
            package.finals[zone_id].as_bytes().to_vec(),
        );
    }
    files.insert(
        "collection.json".into(),
        serde_json::to_vec_pretty(package)?,
    );
    Ok(files)
}

/// Persist an immutable package; the caller owns serial reservation and selection.
fn save_collection(c: &Config, id: u64, files: BTreeMap<String, Vec<u8>>) -> Result<()> {
    let root = c.state_dir.join("collected");
    fs::create_dir_all(&root)?;
    fs::File::open(&c.state_dir)?.sync_all()?;
    let temporary = root.join(format!(".{id}.tmp"));
    fs::create_dir(&temporary)?;
    for (name, bytes) in files {
        util::atomic_write(&temporary.join(name), &bytes)?;
    }
    fs::File::open(&temporary)?.sync_all()?;
    fs::rename(&temporary, root.join(id.to_string()))?;
    fs::File::open(&root)?.sync_all()?;
    Ok(())
}

fn is_refresh_due(c: &Config, package: &CollectionPackage, config_sha256: &str) -> bool {
    if package.config_sha256 != config_sha256 || !c.zones.iter().any(|zone| zone.sign) {
        return false;
    }
    let now = util::now();
    let refresh = c.signer.as_ref().unwrap().refresh_secs;
    now < package.collection.collected_at || now - package.collection.collected_at >= refresh
}

/// Render a unified, git-style diff between two zone record sets.
fn unified_record_diff(
    zone_name: &str,
    before: &[dns::InternalRecord],
    after: &[dns::InternalRecord],
) -> String {
    let render = |records: &[dns::InternalRecord]| {
        records
            .iter()
            .map(|record| format!("{record}\n"))
            .collect::<String>()
    };
    let (before, after) = (render(before), render(after));
    TextDiff::from_lines(&before, &after)
        .unified_diff()
        .context_radius(3)
        .missing_newline_hint(false)
        .header(zone_name, zone_name)
        .to_string()
        .trim_end_matches('\n')
        .to_owned()
}

/// Explain a collection built from freshly fetched records, including refreshes.
fn fresh_collection_reasons(
    c: &Config,
    previous: Option<&CollectionPackage>,
    records: &Records,
    config_sha256: &str,
    refresh_due: bool,
) -> Result<Vec<String>> {
    let mut reasons = Vec::new();
    if previous.is_some_and(|package| package.config_sha256 != config_sha256) {
        reasons.push("configuration changed".into());
    }
    if refresh_due {
        reasons.push("signature refresh".into());
    }
    for zone_config in &c.zones {
        let id = dns::sanitize_zone_id_for_filename(&zone_config.name)?;
        let new = records.get(&id).context("missing configured zone")?;
        let Some(previous) = previous.and_then(|package| package.records.get(&id)) else {
            reasons.push(format!("initial publication for {id}"));
            continue;
        };
        let diff = unified_record_diff(&new.name, &previous.records, &new.records);
        if !diff.is_empty() {
            reasons.push(diff);
        }
    }
    Ok(reasons)
}

pub fn collect(c: &Config) -> Result<()> {
    fs::create_dir_all(&c.state_dir)?;
    log::info!(
        "Collecting {} zones from NetBox view {}",
        c.zones.len(),
        c.netbox.view
    );
    let (mut current, old) = read_current_collection(c, true)?;
    let config_sha256 = util::digest(&serde_json::to_vec(c)?);
    // Only a due package with matching configuration can be refreshed offline.
    let due_refresh_candidate = old
        .as_ref()
        .filter(|package| is_refresh_due(c, package, &config_sha256));

    let fetched = Source::new(&c.netbox)?.stable(c);
    // previous_unsigneds is only present when doing an offline sign refresh
    // In this case, it contains all unsigned files in the last signing
    let (records, previous_unsigneds, reasons) = match fetched {
        Ok(records) => {
            let unchanged = old.as_ref().is_some_and(|package| {
                package.config_sha256 == config_sha256 && records == package.records
            });
            if unchanged && due_refresh_candidate.is_none() {
                log::info!("Collection unchanged");
                return Ok(());
            }
            // A successful collection is authoritative even when unchanged. A
            // due refresh renders and signs those freshly collected records.
            let reasons = fresh_collection_reasons(
                c,
                old.as_ref(),
                &records,
                &config_sha256,
                due_refresh_candidate.is_some(),
            )?;
            (records, None, reasons)
        }
        Err(error) => {
            let Some(package) = due_refresh_candidate else {
                return Err(error);
            };
            log::warn!("NetBox collection failed during signature refresh: {error:#}");
            (
                package.records.clone(),
                Some(&package.unsigneds),
                vec!["signature refresh from previous package after NetBox failure".into()],
            )
        }
    };

    // Prepare and validate the complete package before reserving its serial.
    let package = prepare_collection(
        c,
        current.last_serial,
        reasons,
        records,
        previous_unsigneds,
        config_sha256,
    )?;
    let files = serialize_collection(&package)?;

    // Persist the reservation first, retaining the old selection until the new
    // package is durable. A failed save must not allow this serial to be reused.
    let current_path = c.state_dir.join("current.json");
    current.last_serial = package.collection.serial;
    util::atomic_write(&current_path, &serde_json::to_vec_pretty(&current)?)?;
    save_collection(c, package.collection.id, files)?;
    current.collection_id = Some(package.collection.id);
    util::atomic_write(&current_path, &serde_json::to_vec_pretty(&current)?)?;

    log::info!(
        "Collected {}: serial {}; {}",
        package.collection.id,
        package.collection.serial,
        package.collection.reasons.join("; ")
    );
    Ok(())
}

pub fn publish(c: &Config) -> Result<()> {
    let (_, package) = read_current_collection(c, false)?;
    let package = package.context("no current collection")?;
    ensure!(
        package.config_sha256 == util::digest(&serde_json::to_vec(c)?),
        "configuration changed; collect a new release before publishing"
    );

    let mut accepted = BTreeMap::new();
    for zone_config in &c.zones {
        let id = dns::sanitize_zone_id_for_filename(&zone_config.name)?;
        let unsigned = package
            .unsigneds
            .get(&id)
            .context("missing unsigned zone")?;
        let contents = package.finals.get(&id).context("missing final zone")?;
        let result = (|| -> Result<()> {
            validate_with_bind(c, &zone_config.name, unsigned)?;
            ensure!(
                dns::final_matches_unsigned(&zone_config.name, unsigned, contents)?,
                "final zone does not match authoritative unsigned zone"
            );
            validate_with_bind(c, &zone_config.name, contents)?;
            if zone_config.sign {
                verify_signed_zone(c, zone_config, contents)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            log::error!("Rejecting {id}: {error:#}");
            continue;
        }
        accepted.insert(id.clone(), contents.clone());
    }

    for (id, contents) in &accepted {
        for target in &c.targets {
            if let Err(error) = deployment::install(target, id, contents) {
                log::error!("{id} to {}: {error:#}", target.name);
            }
        }
    }
    log::debug!(
        "Publication of collection {} complete",
        package.collection.id
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{next_collection_id, next_serial};
    use std::fs;
    use time::{Date, Month};

    #[test]
    fn serials_start_at_one_increment_and_reset_on_the_next_utc_day() {
        let today = Date::from_calendar_date(2026, Month::September, 26).unwrap();
        for (last, expected) in [
            (0, 2026092601),
            (2026092599, 2026092601),
            (2026092601, 2026092602),
            (2026092698, 2026092699),
        ] {
            assert_eq!(next_serial(last, today).unwrap(), expected);
        }
    }

    #[test]
    fn serial_allocation_rejects_clock_rollback_daily_exhaustion_and_overflow() {
        let today = Date::from_calendar_date(2026, Month::September, 26).unwrap();
        for (last, expected) in [
            (2026092701, "clock moved behind"),
            (2026092699, "99 releases per UTC day exhausted"),
        ] {
            assert!(
                next_serial(last, today)
                    .unwrap_err()
                    .to_string()
                    .contains(expected)
            );
        }
        let future = Date::from_calendar_date(5000, Month::January, 1).unwrap();
        assert!(
            next_serial(0, future)
                .unwrap_err()
                .to_string()
                .contains("serial date exceeds u32")
        );
    }

    #[test]
    fn collection_ids_skip_completed_and_abandoned_packages() {
        let root = tempfile::tempdir().unwrap();
        // Well beyond the wall clock, so this assertion needs no sleeps.
        fs::create_dir(root.path().join("9000000000000")).unwrap();
        fs::create_dir(root.path().join(".9000000000001.tmp")).unwrap();
        fs::write(root.path().join("unrelated"), "").unwrap();
        assert_eq!(next_collection_id(root.path()).unwrap(), 9000000000002);
        fs::create_dir(root.path().join(u64::MAX.to_string())).unwrap();
        assert!(
            next_collection_id(root.path())
                .unwrap_err()
                .to_string()
                .contains("collection ID exhausted")
        );
    }
}
