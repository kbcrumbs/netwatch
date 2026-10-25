//! Offline IP enrichment: DB-IP Lite country/ASN databases and public threat
//! blocklists. Everything is downloaded to the app's data folder and matched
//! locally, so looking up an IP never sends it anywhere.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use maxminddb::Reader;
use serde::{Deserialize, Serialize};

use crate::monitor::now_ms;

const FEED_MAX_AGE: Duration = Duration::from_secs(12 * 3600);
const GEO_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
const CHECK_EVERY: Duration = Duration::from_secs(3600);
const MAX_DOWNLOAD: u64 = 256 * 1024 * 1024;

struct FeedDef {
    id: &'static str,
    name: &'static str,
    url: &'static str,
    /// What a match means, shown to the user.
    label: &'static str,
    severity: &'static str,
}

const FEEDS: &[FeedDef] = &[
    FeedDef {
        id: "feodo",
        name: "abuse.ch Feodo Tracker",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        label: "Botnet command-and-control server",
        severity: "high",
    },
    FeedDef {
        id: "spamhaus-drop-v4",
        name: "Spamhaus DROP (IPv4)",
        url: "https://www.spamhaus.org/drop/drop_v4.json",
        label: "Network controlled by criminals",
        severity: "high",
    },
    FeedDef {
        id: "spamhaus-drop-v6",
        name: "Spamhaus DROP (IPv6)",
        url: "https://www.spamhaus.org/drop/drop_v6.json",
        label: "Network controlled by criminals",
        severity: "high",
    },
    FeedDef {
        id: "et-compromised",
        name: "Emerging Threats compromised IPs",
        url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        label: "Known compromised host",
        severity: "high",
    },
    FeedDef {
        id: "cins",
        name: "CINS Army",
        url: "https://cinsscore.com/list/ci-badguys.txt",
        label: "Known attacker or scanner",
        severity: "medium",
    },
    FeedDef {
        id: "tor-exit",
        name: "Tor exit nodes",
        url: "https://check.torproject.org/torbulkexitlist",
        label: "Tor exit node",
        severity: "medium",
    },
];

const GEO_DBS: &[(&str, &str)] = &[
    ("country", "https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz"),
    ("asn", "https://download.db-ip.com/free/dbip-asn-lite-{month}.mmdb.gz"),
];

/* ---------- IP range sets ---------- */

#[derive(Default)]
struct Ranges {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl Ranges {
    fn parse(text: &str) -> Self {
        let mut r = Ranges::default();
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            // Spamhaus JSON lines: {"cidr":"1.10.16.0/20",...}
            let token = match line.find("\"cidr\"") {
                Some(i) => line[i + 6..]
                    .trim_start_matches([':', ' ', '"'])
                    .split('"')
                    .next()
                    .unwrap_or(""),
                None => line.split([' ', '\t', ',']).next().unwrap_or(""),
            };
            r.add_cidr(token);
        }
        r.v4 = merge(std::mem::take(&mut r.v4));
        r.v6 = merge(std::mem::take(&mut r.v6));
        r
    }

    fn add_cidr(&mut self, s: &str) {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, p.parse::<u32>().ok()),
            None => (s, None),
        };
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => {
                let p = prefix.unwrap_or(32).min(32);
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                let start = u32::from(a) & mask;
                self.v4.push((start, start | !mask));
            }
            Ok(IpAddr::V6(a)) => {
                let p = prefix.unwrap_or(128).min(128);
                let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                let start = u128::from(a) & mask;
                self.v6.push((start, start | !mask));
            }
            Err(_) => {}
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => in_ranges(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(m) => in_ranges(&self.v4, u32::from(m)),
                None => in_ranges(&self.v6, u128::from(a)),
            },
        }
    }

    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

fn merge<T: Ord + Copy + num_succ::Succ>(mut v: Vec<(T, T)>) -> Vec<(T, T)> {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1.succ() => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => out.push((s, e)),
        }
    }
    out
}

mod num_succ {
    /// Saturating +1, so adjacent ranges merge.
    pub trait Succ {
        fn succ(self) -> Self;
    }
    impl Succ for u32 {
        fn succ(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl Succ for u128 {
        fn succ(self) -> Self {
            self.saturating_add(1)
        }
    }
}

fn in_ranges<T: Ord + Copy>(v: &[(T, T)], x: T) -> bool {
    let i = v.partition_point(|r| r.0 <= x);
    i > 0 && v[i - 1].1 >= x
}

/* ---------- Public types ---------- */

#[derive(Serialize, Clone, Debug)]
pub struct IntelHit {
    pub feed: &'static str,
    pub label: &'static str,
    pub severity: &'static str,
}

#[derive(Serialize, Clone, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GeoInfo {
    pub country: Option<String>,
    pub country_name: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FeedStatus {
    pub id: &'static str,
    pub name: &'static str,
    pub entries: usize,
    pub updated: Option<u64>,
    pub error: Option<String>,
}

#[derive(Serialize, Clone, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GeoStatus {
    pub ready: bool,
    /// Build date of the loaded database, e.g. "2026-10-01".
    pub edition: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Clone, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IntelStatus {
    pub updating: bool,
    pub last_check: Option<u64>,
    pub geo: GeoStatus,
    pub feeds: Vec<FeedStatus>,
}

#[derive(Deserialize)]
struct CountryRec {
    country: Option<CountryField>,
}

#[derive(Deserialize)]
struct CountryField {
    iso_code: Option<String>,
    names: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct AsnRec {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

#[derive(Default)]
struct Db {
    feeds: Vec<(usize, Ranges)>,
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

pub struct Intel {
    db: RwLock<Db>,
    status: Mutex<IntelStatus>,
    dir: PathBuf,
}

impl Intel {
    /// Loads cached data immediately, then keeps it fresh on a background
    /// thread. Sending on the returned channel forces a re-download.
    pub fn start(dir: PathBuf) -> (Arc<Intel>, Sender<()>) {
        let _ = fs::create_dir_all(&dir);
        let intel = Arc::new(Intel {
            db: RwLock::default(),
            status: Mutex::new(IntelStatus {
                feeds: FEEDS
                    .iter()
                    .map(|f| FeedStatus { id: f.id, name: f.name, entries: 0, updated: None, error: None })
                    .collect(),
                ..Default::default()
            }),
            dir,
        });
        // Load what's on disk before the first poll so it's enriched too.
        intel.load_cached();
        let (tx, rx) = mpsc::channel();
        let worker = intel.clone();
        std::thread::Builder::new()
            .name("intel-update".into())
            .spawn(move || worker.run(rx))
            .expect("spawn intel updater");
        (intel, tx)
    }

    pub fn status(&self) -> IntelStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn geo(&self, ip: IpAddr) -> GeoInfo {
        let db = self.db.read().unwrap();
        let mut g = GeoInfo::default();
        // A lookup error just means the address isn't in the database.
        if let Some(Ok(rec)) = db.country.as_ref().map(|r| r.lookup::<CountryRec>(ip)) {
            if let Some(c) = rec.country {
                g.country_name = c.names.and_then(|mut n| n.remove("en"));
                g.country = c.iso_code;
            }
        }
        if let Some(Ok(rec)) = db.asn.as_ref().map(|r| r.lookup::<AsnRec>(ip)) {
            g.asn = rec.autonomous_system_number;
            g.org = rec.autonomous_system_organization;
        }
        g
    }

    pub fn hits(&self, ip: IpAddr) -> Vec<IntelHit> {
        let db = self.db.read().unwrap();
        db.feeds
            .iter()
            .filter(|(_, ranges)| ranges.contains(ip))
            .map(|(i, _)| IntelHit { feed: FEEDS[*i].name, label: FEEDS[*i].label, severity: FEEDS[*i].severity })
            .collect()
    }

    fn run(&self, rx: Receiver<()>) {
        let mut force = false;
        loop {
            self.update(force);
            force = match rx.recv_timeout(CHECK_EVERY) {
                Ok(()) => true,
                Err(RecvTimeoutError::Timeout) => false,
                Err(RecvTimeoutError::Disconnected) => return,
            };
        }
    }

    fn feed_path(&self, f: &FeedDef) -> PathBuf {
        self.dir.join(format!("{}.txt", f.id))
    }

    fn geo_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("dbip-{name}-lite.mmdb"))
    }

    fn load_cached(&self) {
        for (i, f) in FEEDS.iter().enumerate() {
            let path = self.feed_path(f);
            if let Ok(text) = fs::read_to_string(&path) {
                self.install_feed(i, Ranges::parse(&text), modified_ms(&path), None);
            }
        }
        for (name, _) in GEO_DBS {
            let path = self.geo_path(name);
            if let Ok(bytes) = fs::read(&path) {
                let _ = self.install_geo(name, bytes);
            }
        }
    }

    fn update(&self, force: bool) {
        self.status.lock().unwrap().updating = true;

        for (i, f) in FEEDS.iter().enumerate() {
            let path = self.feed_path(f);
            if !force && is_fresh(&path, FEED_MAX_AGE) {
                continue;
            }
            match download(f.url).and_then(|b| String::from_utf8(b).map_err(|e| e.to_string())) {
                Ok(text) => {
                    let ranges = Ranges::parse(&text);
                    if ranges.len() == 0 {
                        self.set_feed_error(i, "Downloaded list was empty or unreadable".into());
                        continue;
                    }
                    let _ = write_atomic(&path, text.as_bytes());
                    self.install_feed(i, ranges, Some(now_ms()), None);
                }
                Err(e) => self.set_feed_error(i, e),
            }
        }

        for (name, url_tpl) in GEO_DBS {
            let path = self.geo_path(name);
            if !force && is_fresh(&path, GEO_MAX_AGE) {
                continue;
            }
            match download_geo(url_tpl).and_then(|bytes| {
                self.install_geo(name, bytes.clone())?;
                write_atomic(&path, &bytes).map_err(|e| e.to_string())
            }) {
                Ok(()) => {}
                Err(e) => {
                    let mut st = self.status.lock().unwrap();
                    st.geo.error = Some(format!("{name} database: {e}"));
                }
            }
        }

        let mut st = self.status.lock().unwrap();
        st.updating = false;
        st.last_check = Some(now_ms());
    }

    fn install_feed(&self, i: usize, ranges: Ranges, updated: Option<u64>, error: Option<String>) {
        let entries = ranges.len();
        {
            let mut db = self.db.write().unwrap();
            db.feeds.retain(|(j, _)| *j != i);
            db.feeds.push((i, ranges));
        }
        let mut st = self.status.lock().unwrap();
        let fs = &mut st.feeds[i];
        fs.entries = entries;
        fs.updated = updated;
        fs.error = error;
    }

    fn set_feed_error(&self, i: usize, e: String) {
        self.status.lock().unwrap().feeds[i].error = Some(e);
    }

    fn install_geo(&self, name: &str, bytes: Vec<u8>) -> Result<(), String> {
        let reader = Reader::from_source(bytes).map_err(|e| e.to_string())?;
        let edition = date_from_epoch(reader.metadata.build_epoch);
        {
            let mut db = self.db.write().unwrap();
            match name {
                "country" => db.country = Some(reader),
                _ => db.asn = Some(reader),
            }
        }
        let mut st = self.status.lock().unwrap();
        let db = self.db.read().unwrap();
        st.geo.ready = db.country.is_some() && db.asn.is_some();
        st.geo.edition = Some(edition);
        st.geo.error = None;
        Ok(())
    }
}

/* ---------- Helpers ---------- */

fn download(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .set("User-Agent", "NetWatch/0.1 (personal connection monitor)")
        .timeout(Duration::from_secs(90))
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("HTTP {code}"),
            other => other.to_string(),
        })?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_DOWNLOAD)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

/// DB-IP publishes one file per month; early in a month the new one may not
/// be out yet, so fall back to last month's.
fn download_geo(url_tpl: &str) -> Result<Vec<u8>, String> {
    let (y, m) = year_month(now_ms() / 1000);
    let prev = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    let mut last_err = String::new();
    for (y, m) in [(y, m), prev] {
        let url = url_tpl.replace("{month}", &format!("{y:04}-{m:02}"));
        match download(&url) {
            Ok(gz) => {
                let mut out = Vec::new();
                flate2::read::GzDecoder::new(&gz[..])
                    .take(MAX_DOWNLOAD)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("decompress: {e}"))?;
                return Ok(out);
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

fn modified_ms(path: &Path) -> Option<u64> {
    let t = fs::metadata(path).ok()?.modified().ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_millis() as u64)
}

fn is_fresh(path: &Path, max_age: Duration) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < max_age)
}

/// Civil date from Unix seconds (Howard Hinnant's algorithm).
fn civil(secs: u64) -> (i64, u32, u32) {
    let z = (secs / 86400) as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

fn year_month(secs: u64) -> (i64, u32) {
    let (y, m, _) = civil(secs);
    (y, m)
}

fn date_from_epoch(secs: u64) -> String {
    let (y, m, d) = civil(secs);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_formats() {
        let r = Ranges::parse(
            "# comment\n1.2.3.4\n10.0.0.0/8 ; SBL1\n{\"cidr\":\"5.6.0.0/16\",\"sblid\":\"x\"}\n2001:db8::/32\n",
        );
        assert!(r.contains("1.2.3.4".parse().unwrap()));
        assert!(!r.contains("1.2.3.5".parse().unwrap()));
        assert!(r.contains("10.200.1.1".parse().unwrap()));
        assert!(r.contains("5.6.255.255".parse().unwrap()));
        assert!(!r.contains("5.7.0.0".parse().unwrap()));
        assert!(r.contains("2001:db8:1::1".parse().unwrap()));
        assert!(r.contains("::ffff:1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(date_from_epoch(0), "1970-01-01");
        assert_eq!(date_from_epoch(1792422842), "2026-10-19");
        assert_eq!(date_from_epoch(951782400), "2000-02-29");
    }
}
