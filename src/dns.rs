use anyhow::{Result, ensure};
use domain::{
    base::{
        Name, Serial, UnknownRecordData,
        iana::{Class, Rtype},
        name::{ToName, UncertainName},
        rdata::ComposeRecordData,
        zonefile_fmt::{DisplayKind, ZonefileFmt},
    },
    rdata::{Soa, ZoneRecordData},
    zonefile::inplace::{Entry, ScannedRecord},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};
/// Typed source records. Rendering sorts and deduplicates them; comparisons
/// ignore SOA serials without changing the retained records.
#[derive(Clone, Debug)]
pub struct Zone {
    pub name: String,
    pub records: Vec<ScannedRecord>,
}

impl Zone {
    pub fn new(name: &str, records: Vec<ScannedRecord>) -> Result<Self> {
        let name = canonicalize_name(name)?;
        validate_source_policy(&name.parse()?, &records)?;
        Ok(Self { name, records })
    }

    pub fn comparison_text(&self) -> String {
        self.render_with_serial(0)
    }

    pub fn render_with_serial(&self, serial: u32) -> String {
        let lines: BTreeSet<_> = self
            .records
            .iter()
            .map(|record| {
                let mut record = record.clone();
                set_soa_serial(&mut record, serial);
                record_line(&record)
            })
            .collect();
        let origin: CanonicalName = self.name.parse().expect("zone has a validated name");
        let mut output = format!("$ORIGIN {}\n", zonefile_name(&origin));
        for line in lines {
            output.push_str(&line);
            output.push('\n');
        }
        output
    }
}

// domain::Record equality ignores TTL; the comparison view includes it.
impl PartialEq for Zone {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.comparison_text() == other.comparison_text()
    }
}

impl Eq for Zone {}

/// Typed zones per canonical zone ID.
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
    let origin: CanonicalName = zone_name.parse()?;
    let input = format!("$ORIGIN {}\n{text}", zonefile_name(&origin));
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

/// Parse one untrusted API record, resolving relative names against the zone.
pub fn parse_record(
    zone_name: &str,
    name: &str,
    ttl: u32,
    rr_type: &str,
    value: &str,
) -> Result<ScannedRecord> {
    let zone_name = canonicalize_name(zone_name)?;
    let origin: CanonicalName = zone_name.parse()?;
    ensure!(
        !name.is_empty() && !name.contains(['\n', '\r']),
        "empty or multiline record name rejected"
    );
    ensure!(
        !rr_type.chars().any(char::is_whitespace),
        "whitespace in record type rejected"
    );
    let rrtype = Rtype::from_str(rr_type)?;
    ensure!(
        !matches!(rrtype, Rtype::AXFR | Rtype::IXFR | Rtype::ANY | Rtype::OPT),
        "unsupported record type {rr_type}"
    );
    let owner = if name == "@" {
        origin.clone()
    } else {
        let owner: UncertainName<Vec<u8>> = name.parse()?;
        owner.chain(origin)?.to_canonical_name()
    };

    // RDATA scanning handles tokenization, binary escapes and relative names.
    let text = format!("{name} {ttl} IN {rr_type} {value}\n");
    let mut records = parse_with_origin(&zone_name, &text)?;
    ensure!(
        records.len() == 1,
        "source record must parse as exactly one record"
    );
    let record = records.pop().unwrap();
    ensure!(
        canonical_name(record.owner()) == owner
            && record.rtype() == rrtype
            && record.ttl().as_secs() == ttl
            && record.class() == Class::IN,
        "record owner/type/TTL/class changed during parsing"
    );
    Ok(record)
}

type CanonicalName = Name<Vec<u8>>;

fn canonical_name(name: &impl ToName) -> CanonicalName {
    name.to_canonical_name()
}

pub fn final_matches_unsigned(zone_name: &str, unsigned: &str, final_zone: &str) -> Result<bool> {
    let unsigned = parse(zone_name, unsigned)?
        .iter()
        .map(record_line)
        .collect::<BTreeSet<_>>();
    let final_zone = parse(zone_name, final_zone)?
        .iter()
        .filter(|record| {
            !matches!(
                record.rtype(),
                Rtype::DNSKEY | Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3 | Rtype::NSEC3PARAM
            )
        })
        .map(record_line)
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

/// Escape names only at the zone-file boundary. Canonical identities and
/// filename encoding deliberately retain their existing representation.
fn zonefile_name(name: &impl ToName) -> String {
    let mut output = String::new();
    for label in name.iter_labels() {
        if label.as_slice().is_empty() {
            if output.is_empty() {
                output.push('.');
            }
            break;
        }
        for byte in label.iter() {
            match byte {
                b' ' | b'.' | b'\\' => {
                    output.push('\\');
                    output.push(byte as char);
                }
                b';' | b'(' | b')' | b'"' | b'@' | b'$' => {
                    output.push_str(&format!("\\{byte:03}"));
                }
                0x21..=0x7e => output.push(byte as char),
                _ => output.push_str(&format!("\\{byte:03}")),
            }
        }
        output.push('.');
    }
    output
}

fn rdata_bytes(record: &ScannedRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    // A Vec composer cannot fail or emit name-compression pointers.
    record.data().compose_rdata(&mut bytes).unwrap();
    bytes
}

fn record_line(record: &ScannedRecord) -> String {
    let header = format!(
        "{} {} {} {}",
        zonefile_name(&canonical_name(record.owner())),
        record.ttl().as_secs(),
        record.class(),
        record.rtype(),
    );
    // The scanner retains RFC 3597 input as Unknown, even for known types.
    // Keep SOA/NS readable so snapshot reloads retain serial/delegation semantics.
    let rdata = match record.data() {
        ZoneRecordData::Soa(soa) => format!(
            "{} {} {} {} {} {} {}",
            zonefile_name(soa.mname()),
            zonefile_name(soa.rname()),
            soa.serial().into_int(),
            soa.refresh().as_secs(),
            soa.retry().as_secs(),
            soa.expire().as_secs(),
            soa.minimum().as_secs(),
        ),
        ZoneRecordData::Ns(ns) => zonefile_name(ns.nsdname()),
        data => data.display_zonefile(DisplayKind::Simple).to_string(),
    };
    let readable = format!("{header} {rdata}\n");
    let bytes = rdata_bytes(record);
    // Some domain formatters lose escaping in embedded names. Accept readable
    // output only when a fresh scanner recovers the same record and RDATA bytes.
    if let Ok(parsed) = parse_with_origin(".", &readable)
        && let [parsed] = parsed.as_slice()
        && parsed.owner().name_eq(record.owner())
        && parsed.ttl() == record.ttl()
        && parsed.class() == record.class()
        && parsed.rtype() == record.rtype()
        && rdata_bytes(parsed) == bytes
    {
        return readable.trim_end_matches('\n').to_owned();
    }
    // Use the same generic formatter as reloaded snapshots, keeping comparison
    // text stable across signing and reloads (including hex spacing/case).
    let generic = UnknownRecordData::from_octets(record.rtype(), bytes)
        .expect("parsed RDATA fits its wire length");
    format!("{header} {}", generic.display_zonefile(DisplayKind::Simple))
}

fn set_soa_serial(record: &mut ScannedRecord, serial: u32) {
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
