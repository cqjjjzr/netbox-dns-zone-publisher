use crate::{
    config::{Config, NetBox},
    dns::{self, InternalRecord, Records},
};
use anyhow::{Context, Result, ensure};
use reqwest::{
    blocking::Client,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    fs,
    time::{Duration, Instant},
};
use url::Url;
/// A nested NetBox object reference carrying only its ID.
#[derive(Debug, Deserialize)]
struct Ref {
    id: u64,
}
/// A NetBox DNS view from the plugin API.
#[derive(Debug, Deserialize)]
struct ApiView {
    id: u64,
    name: String,
}
/// A NetBox DNS zone from the plugin API.
#[derive(Debug, Deserialize)]
struct ApiZone {
    id: u64,
    name: String,
    view: Ref,
    default_ttl: Option<u32>,
    active: bool,
}
/// A NetBox DNS record from the plugin API.
#[derive(Debug, Deserialize)]
struct ApiRecord {
    id: u64,
    zone: Ref,
    fqdn: String,
    ttl: Option<u32>,
    #[serde(rename = "type")]
    kind: String,
    value: String,
    absolute_value: Option<String>,
    active: bool,
}
/// One page of a paginated NetBox response.
#[derive(Debug, Deserialize)]
struct Page<T> {
    count: usize,
    next: Option<String>,
    results: Vec<T>,
}
/// A NetBox source that reads stable normalized zone records.
pub struct Source {
    client: Client,
    base: Url,
    max_records: usize,
    collection_timeout: Duration,
    request_timeout: Duration,
}

impl Source {
    pub fn new(c: &NetBox) -> Result<Self> {
        let url = &c.url;
        ensure!(
            url.query().is_none() && url.fragment().is_none(),
            "NetBox URL must not contain query or fragment"
        );
        ensure!(url.path().ends_with('/'), "NetBox URL must end with /");
        ensure!(
            c.timeout_secs > 0 && c.max_records > 0,
            "invalid collection bounds"
        );
        ensure!(
            url.username().is_empty() && url.password().is_none(),
            "NetBox URL credentials are not allowed"
        );
        let token = fs::read_to_string(&c.token_file).context("read NetBox token file")?;
        let mut auth = HeaderValue::from_str(&format!("Token {}", token.trim()))?;
        auth.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth);
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(c.timeout_secs))
            .build()?;
        Ok(Self {
            client,
            base: url.clone(),
            max_records: c.max_records,
            collection_timeout: Duration::from_secs(c.timeout_secs.saturating_mul(4)),
            request_timeout: Duration::from_secs(c.timeout_secs),
        })
    }
    fn get<T: DeserializeOwned>(&self, url: &Url, deadline: Instant) -> Result<T> {
        ensure!(
            url.origin() == self.base.origin(),
            "cross-origin collection URL rejected"
        );
        ensure!(Instant::now() < deadline, "collection deadline exceeded");
        let response = self
            .client
            .get(url.clone())
            .timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(self.request_timeout),
            )
            .send()
            .context("NetBox request failed")?;
        ensure!(
            response.status().is_success(),
            "NetBox returned HTTP {}",
            response.status()
        );
        let bytes = crate::util::bounded_read(response)?;
        serde_json::from_slice(&bytes).context("invalid NetBox JSON/schema")
    }
    pub fn collect(&self, c: &Config) -> Result<Records> {
        let deadline = Instant::now() + self.collection_timeout;

        // Find the specified view
        let mut records = Records::new();
        let mut endpoint = self.base.join("api/plugins/netbox-dns/views/")?;
        endpoint
            .query_pairs_mut()
            .append_pair("name", &c.netbox.view);
        let mut views: Page<ApiView> = self.get(&endpoint, deadline)?;
        ensure!(
            views.count == 1 && views.results.len() == 1 && views.next.is_none(),
            "NetBox view must resolve uniquely"
        );
        let view = views.results.remove(0);
        ensure!(
            view.id > 0 && view.name == c.netbox.view,
            "NetBox view identity mismatch"
        );

        // Find each zone configured
        for zone_config in &c.zones {
            // Locate the zone
            let canonical = dns::canonicalize_name(&zone_config.name)?;
            let mut endpoint = self.base.join("api/plugins/netbox-dns/zones/")?;
            endpoint
                .query_pairs_mut()
                .append_pair("name", canonical.trim_end_matches('.'))
                .append_pair("view_id", &view.id.to_string());
            let mut zones: Page<ApiZone> = self.get(&endpoint, deadline)?;
            ensure!(
                zones.count == 1 && zones.results.len() == 1 && zones.next.is_none(),
                "NetBox zone must resolve uniquely: {}",
                zone_config.name
            );
            let api_zone = zones.results.remove(0);
            ensure!(
                api_zone.id > 0
                    && api_zone.view.id == view.id
                    && dns::canonicalize_name(&api_zone.name)? == canonical
                    && api_zone.active,
                "NetBox zone scope/identity/active mismatch for {}",
                api_zone.name
            );

            // Fetch by pages (next page as a URL in response)
            let initial = self.base.join(&format!(
                "api/plugins/netbox-dns/records/?zone_id={}&limit=1000",
                api_zone.id
            ))?;
            let mut url = Some(initial.clone());
            let mut seen_pages = BTreeSet::new();
            let mut ids = BTreeSet::new();
            let mut expected = None;
            let mut internal_records = Vec::new();
            while let Some(page_url) = url {
                ensure!(
                    seen_pages.insert(page_url.as_str().to_owned()),
                    "pagination cycle"
                );
                ensure!(
                    page_url.origin() == initial.origin()
                        && page_url.path() == initial.path()
                        && page_url.username().is_empty()
                        && page_url.password().is_none(),
                    "unsafe pagination URL"
                );
                let page: Page<ApiRecord> = self.get(&page_url, deadline)?;
                ensure!(page.count <= self.max_records, "record count exceeds limit");
                if let Some(count) = expected {
                    ensure!(count == page.count, "pagination count changed");
                } else {
                    expected = Some(page.count);
                }
                ensure!(
                    !page.results.is_empty() || page.next.is_none(),
                    "empty non-final page"
                );
                for r in page.results {
                    ensure!(
                        r.zone.id == api_zone.id && ids.insert(r.id),
                        "record scope mismatch or duplicate ID"
                    );
                    ensure!(ids.len() <= self.max_records, "record limit exceeded");
                    if r.active {
                        internal_records.push(InternalRecord {
                            name: r.fqdn,
                            ttl: r
                                .ttl
                                .or(api_zone.default_ttl)
                                .context("record and zone both lack an effective TTL")?,
                            rr_type: r.kind,
                            value: r.absolute_value.unwrap_or(r.value),
                        });
                    }
                }
                url = page.next.map(|u| page_url.join(&u)).transpose()?;
            }
            ensure!(Some(ids.len()) == expected, "incomplete pagination");
            let normalized = dns::canonicalize(&api_zone.name, internal_records)?;
            records.insert(
                dns::sanitize_zone_id_for_filename(&api_zone.name)?,
                normalized,
            );
        }
        Ok(records)
    }

    /// Collect twice to detect concurrent change or transient error
    pub fn stable(&self, c: &Config) -> Result<Records> {
        let first = self.collect(c)?;
        let second = self.collect(c)?;
        ensure!(
            first == second,
            "source records changed between collections"
        );
        Ok(second)
    }
}
