use anyhow::{Result, ensure};
use domain::{
    base::{
        Name, Serial,
        iana::Rtype,
        name::{ToName, UncertainName},
        zonefile_fmt::{DisplayKind, ZonefileFmt},
    },
    rdata::{Soa, ZoneRecordData},
    zonefile::inplace::{Entry, ScannedRecord},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write},
    str::FromStr,
};
/// The project's flat record DTO, used for stable JSON snapshots and diffs.
///
/// NetBox initially supplies these fields as untrusted presentation text.
/// After `canonicalize`, all names and `value` use domain's canonical zone-file
/// presentation and the SOA serial is zero.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct InternalRecord {
    pub name: String,
    pub ttl: u32,
    pub rr_type: String,
    pub value: String,
}

impl InternalRecord {
    /// Convert a parsed source record into the flat record DTO.
    fn from_scanned_record(record: &ScannedRecord) -> InternalRecord {
        InternalRecord {
            name: record
                .owner()
                .fmt_with_dot()
                .to_string()
                .to_ascii_lowercase(),
            ttl: record.ttl().as_secs(),
            rr_type: record.rtype().to_string(),
            value: record
                .data()
                .display_zonefile(DisplayKind::Simple)
                .to_string(),
        }
    }
}

impl fmt::Display for InternalRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} IN {} {}",
            self.name, self.ttl, self.rr_type, self.value
        )
    }
}

/// A zone's sorted, deduplicated normalized records. The SOA serial is zeroed during
/// normalization: source serials are never published, so identical records stay
/// equal across serial bumps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Zone {
    pub name: String,
    #[serde(alias = "rows")]
    pub records: Vec<InternalRecord>,
}

/// Normalized records per canonical zone ID.
pub type Records = BTreeMap<String, Zone>;
pub fn canonicalize_name(input: &str) -> Result<String> {
    ensure!(
        !input.is_empty() && !input.chars().any(char::is_whitespace),
        "invalid DNS name"
    );
    let mut n: Name<Vec<u8>> = if input.ends_with('.') {
        input.to_owned()
    } else {
        format!("{input}.")
    }
    .parse()?;
    n.make_canonical();
    Ok(n.fmt_with_dot().to_string())
}

/// Sanitize zone name to a ID safe for filename
pub fn sanitize_zone_id_for_filename(zone_name: &str) -> Result<String> {
    let canonical = canonicalize_name(zone_name)?;
    let stem = canonical.strip_suffix('.').unwrap();
    ensure!(!stem.is_empty(), "root zone is outside publisher scope");
    let mut id = String::new();
    // Sanitize illegal path characters (esp. [back]slash)
    for (index, byte) in stem.bytes().enumerate() {
        if byte.is_ascii_alphanumeric()
            || b"-_".contains(&byte)
            || (byte == b'.' && index + 1 < stem.len())
        {
            id.push(byte as char);
        } else {
            id.push_str(&format!("%{byte:02x}"));
        }
    }
    // Prevent illegal names on Windows
    let first = id.split('.').next().unwrap();
    if matches!(first, "con" | "prn" | "aux" | "nul")
        || (first.len() == 4
            && (first.starts_with("com") || first.starts_with("lpt"))
            && matches!(first.as_bytes()[3], b'1'..=b'9'))
    {
        id.replace_range(..1, &format!("%{:02x}", id.as_bytes()[0]));
    }
    // Prevent oversized id
    if id.len() > 180 {
        id = format!(
            "{}%h{}",
            &id[..110],
            crate::util::digest(canonical.as_bytes())
        );
    }
    Ok(id)
}

/// Parse one or more presentation-format records into domain's owned record type.
pub fn parse(zone_name: &str, text: &str) -> Result<Vec<ScannedRecord>> {
    let zone_name = canonicalize_name(zone_name)?;
    parse_with_origin(&zone_name, text)
}

fn parse_with_origin(zone_name: &str, text: &str) -> Result<Vec<ScannedRecord>> {
    let input = format!("$ORIGIN {zone_name}\n{text}");
    let mut file = domain::zonefile::inplace::Zonefile::load(&mut input.as_bytes())?;
    let mut records = Vec::new();
    while let Some(entry) = file.next_entry()? {
        match entry {
            Entry::Record(record) => records.push(record),
            // The scanner returns includes as entries; it never opens the path.
            Entry::Include { .. } => anyhow::bail!("zone includes are not allowed"),
        }
    }
    Ok(records)
}

/// Convert InternalRecord (used for persistence and pulled from NetBox)
/// to domain crate ScannedRecord
pub fn internal_to_scanned_records(
    zone_name: &str,
    records: &[InternalRecord],
) -> Result<Vec<ScannedRecord>> {
    let zone_name = canonicalize_name(zone_name)?;
    let origin: CanonicalName = zone_name.parse()?;
    let mut text = String::new();
    let mut expected = Vec::with_capacity(records.len());

    for record in records {
        ensure!(
            !record.name.is_empty() && !record.name.contains(['\n', '\r']),
            "empty or multiline record name rejected"
        );
        ensure!(
            !record.rr_type.chars().any(char::is_whitespace),
            "whitespace in record type rejected"
        );
        let rrtype = Rtype::from_str(&record.rr_type)?;
        ensure!(
            !matches!(rrtype, Rtype::AXFR | Rtype::IXFR | Rtype::ANY | Rtype::OPT),
            "unsupported record type {}",
            record.rr_type
        );
        let owner = if record.name == "@" {
            origin.clone()
        } else {
            let owner: UncertainName<Vec<u8>> = record.name.parse()?;
            owner.chain(origin.clone())?.to_canonical_name()
        };
        expected.push((owner, rrtype, record.ttl));
        writeln!(text, "{record}").expect("writing to a String cannot fail");
    }

    // ZoneRecordData has no generic FromStr implementation: RDATA parsing needs
    // the zone-file scanner for tokenization and origin-relative names.
    let records = parse_with_origin(&zone_name, &text)?;
    ensure!(
        records.len() == expected.len(),
        "internal records must convert one-to-one"
    );
    for (record, (owner, rrtype, ttl)) in records.iter().zip(expected) {
        ensure!(
            canonical_name(record.owner()) == owner
                && record.rtype() == rrtype
                && record.ttl().as_secs() == ttl,
            "record owner/type/TTL changed during parsing"
        );
    }
    Ok(records)
}

type CanonicalName = Name<Vec<u8>>;

fn canonical_name(name: &impl ToName) -> CanonicalName {
    name.to_canonical_name()
}

pub fn final_matches_unsigned(zone_name: &str, unsigned: &str, final_zone: &str) -> Result<bool> {
    let unsigned = parse(zone_name, unsigned)?
        .iter()
        .map(InternalRecord::from_scanned_record)
        .collect::<BTreeSet<_>>();
    let final_zone = parse(zone_name, final_zone)?
        .iter()
        .filter(|record| {
            !matches!(
                record.rtype(),
                Rtype::DNSKEY | Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3 | Rtype::NSEC3PARAM
            )
        })
        .map(InternalRecord::from_scanned_record)
        .collect::<BTreeSet<_>>();
    Ok(unsigned == final_zone)
}

/// Enforce source policies that `named-checkzone -i local` does not reject.
/// DNS zone loadability is checked by BIND after rendering.
fn validate_source_policy(origin: &CanonicalName, records: &[ScannedRecord]) -> Result<()> {
    let mut rrset_ttls = BTreeMap::<(CanonicalName, Rtype), u32>::new();
    let mut delegations = BTreeMap::<CanonicalName, BTreeSet<CanonicalName>>::new();

    for record in records {
        let owner = canonical_name(record.owner());
        let rtype = record.rtype();

        ensure!(owner.ends_with(origin), "record outside zone: {}", owner);
        ensure!(
            !matches!(
                rtype,
                Rtype::DNSKEY
                    | Rtype::RRSIG
                    | Rtype::NSEC
                    | Rtype::NSEC3
                    | Rtype::NSEC3PARAM
                    | Rtype::CDS
                    | Rtype::CDNSKEY
            ),
            "generated DNSSEC data must not be a source record"
        );

        let ttl = record.ttl().as_secs();
        if let Some(previous) = rrset_ttls.insert((owner.clone(), rtype), ttl) {
            ensure!(
                previous == ttl,
                "inconsistent TTL for {} {rtype} RRset",
                owner.fmt_with_dot()
            );
        }

        match record.data() {
            ZoneRecordData::Ns(ns) if owner != origin => {
                let target = canonical_name(ns.nsdname());
                delegations.entry(owner).or_default().insert(target);
            }
            _ => {}
        }
    }

    // BIND loads and retains occluded data below a delegation. The publisher
    // rejects it so snapshots contain only authoritative data and supplied glue.
    for record in records {
        let owner = canonical_name(record.owner());
        for (cut, targets) in &delegations {
            if !owner.ends_with(cut) {
                continue;
            }
            let at_cut = owner == cut && matches!(record.rtype(), Rtype::NS | Rtype::DS);
            let is_glue =
                targets.contains(&owner) && matches!(record.rtype(), Rtype::A | Rtype::AAAA);
            ensure!(
                at_cut || is_glue,
                "non-glue data below delegation {}: {} {}",
                cut.fmt_with_dot(),
                owner.fmt_with_dot(),
                record.rtype()
            );
        }
    }

    Ok(())
}

/// Canonicalize a set of InternalRecord into a Zone
pub fn canonicalize(zone_name: &str, records: Vec<InternalRecord>) -> Result<Zone> {
    let zone_name = canonicalize_name(zone_name)?;
    let origin: CanonicalName = zone_name.parse()?;

    // Canonicalize with a trip to domain crate ScannedRecord
    let scanned_records = internal_to_scanned_records(&zone_name, &records)?;
    validate_source_policy(&origin, &scanned_records)?;

    // Convert back and generate zone
    let mut normalized_records = Vec::with_capacity(scanned_records.len());
    for mut record in scanned_records {
        if let ZoneRecordData::Soa(soa) = record.data_mut() {
            // Source serials are ignored: the publisher owns serial allocation.
            *soa = Soa::new(
                soa.mname().clone(),
                soa.rname().clone(),
                Serial::from(0),
                soa.refresh(),
                soa.retry(),
                soa.expire(),
                soa.minimum(),
            );
        }
        let normalized = InternalRecord::from_scanned_record(&record);
        normalized_records.push(normalized);
    }
    Ok(Zone {
        name: zone_name,
        records: normalized_records
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    })
}

/// Set the published SOA serial and render typed records once.
pub fn render_with_serial(
    zone_name: &str,
    records: Vec<ScannedRecord>,
    serial: u32,
) -> Result<String> {
    let zone_name = canonicalize_name(zone_name)?;
    let mut output = format!("$ORIGIN {zone_name}\n");
    for mut record in records {
        if let ZoneRecordData::Soa(soa) = record.data_mut() {
            *soa = Soa::new(
                soa.mname().clone(),
                soa.rname().clone(),
                Serial::from(serial),
                soa.refresh(),
                soa.retry(),
                soa.expire(),
                soa.minimum(),
            );
        }
        output.push_str(&record.display_zonefile(DisplayKind::Simple).to_string());
        output.push('\n');
    }
    Ok(output)
}

/// Locate the SOA record and get the serial
pub fn soa_serial(zone_name: &str, records: &[ScannedRecord]) -> Result<u32> {
    let origin: CanonicalName = canonicalize_name(zone_name)?.parse()?;
    for record in records {
        if let ZoneRecordData::Soa(soa) = record.data() {
            ensure!(
                canonical_name(record.owner()) == origin,
                "SOA owner mismatch"
            );
            return Ok(soa.serial().into_int());
        }
    }
    anyhow::bail!("zone requires SOA")
}
