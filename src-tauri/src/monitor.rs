//! Turns raw connection tables into enriched views, stats and alerts, and
//! records history and the baseline in the store.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::dns::DnsNames;
use crate::ifaces;
use crate::intel::{GeoInfo, Intel, IntelHit, IntelStatus};
use crate::net::{self, Proto, TCP_ESTABLISHED, TCP_LISTEN};
use crate::procs;
use crate::rdns::Rdns;
use crate::services;
use crate::sig::{self, SigInfo};
use crate::store::{Alert, Closed, NewConn, Store, TickWrites};

const MAX_ALERTS: u32 = 500;
/// Refresh last_seen of open history rows every this many polls.
const TOUCH_EVERY: u64 = 10;
/// Re-run retention pruning every this many polls (~1 hour).
const PRUNE_EVERY: u64 = 2400;
const DAY_MS: u64 = 24 * 3600 * 1000;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConnView {
    pub id: String,
    pub proto: &'static str,
    pub ipv: u8,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: &'static str,
    /// "outbound", "inbound", "listen" or "udp".
    pub direction: &'static str,
    /// Scope of the remote address, or of the bind address for listeners/UDP.
    pub scope: &'static str,
    pub pid: u32,
    pub process: String,
    /// Windows services hosted by the process (svchost.exe and friends).
    pub services: Vec<String>,
    pub path: Option<String>,
    pub sig: &'static str,
    pub signer: Option<String>,
    pub first_seen: u64,
    /// Adapter that owns the local address, and whether it is a VPN tunnel.
    pub iface: Option<String>,
    pub via_vpn: Option<bool>,
    /// Name the remote host was looked up by, else its reverse-DNS name.
    pub host: Option<String>,
    #[serde(flatten)]
    pub geo: GeoInfo,
    /// Threat feeds that list the remote address.
    pub intel: Vec<IntelHit>,
    /// User's name for the remote address.
    pub label: Option<String>,
    pub ip_trusted: bool,
    pub program_trusted: bool,
    /// When this program was first seen using the network (any run).
    pub program_since: Option<u64>,
    /// First seen after the initial baseline, within the last day.
    pub program_new: bool,
    /// "high", "medium" or "none".
    pub risk: &'static str,
    pub reasons: Vec<String>,
}

impl ConnView {
    fn exe(&self) -> String {
        self.path.clone().unwrap_or_else(|| self.process.clone())
    }

    /// Process name plus its hosted services, e.g. "svchost.exe (Windows Update)".
    fn who(&self) -> String {
        match self.services.as_slice() {
            [] => self.process.clone(),
            [one] => format!("{} ({one})", self.process),
            [first, rest @ ..] => format!("{} ({first} +{})", self.process, rest.len()),
        }
    }
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub total: usize,
    pub established: usize,
    pub outbound: usize,
    pub inbound: usize,
    pub listening: usize,
    pub udp: usize,
    pub remote_hosts: usize,
    pub public_hosts: usize,
    pub processes: usize,
    pub risky: usize,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub ts: u64,
    pub started: u64,
    pub tick: u64,
    /// True while the very first run is recording what's normal.
    pub learning: bool,
    pub known_programs: usize,
    /// Name of the VPN adapter that is up, if any.
    pub vpn: Option<String>,
    /// Hostnames come from Windows' DNS lookups (not just reverse DNS).
    pub dns_names: bool,
    pub conns: Vec<ConnView>,
    pub stats: Stats,
    pub alerts: Vec<Alert>,
    pub intel: IntelStatus,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Remote ports commonly used by malware, remote-control tools or anonymizers.
fn suspicious_port(port: u16) -> Option<&'static str> {
    Some(match port {
        23 => "Telnet (unencrypted remote shell)",
        1337 | 31337 => "classic backdoor port",
        3389 => "Remote Desktop",
        4444 => "Metasploit default port",
        5555 => "ADB / common RAT port",
        5900..=5903 => "VNC remote control",
        6660..=6669 | 6697 => "IRC (used by botnets)",
        9001 | 9030 | 9050 | 9051 | 9150 => "Tor",
        _ => return None,
    })
}

/// Ports that are risky to expose on all interfaces.
fn risky_listener(port: u16) -> Option<&'static str> {
    Some(match port {
        23 => "Telnet",
        3389 => "Remote Desktop",
        5900..=5903 => "VNC",
        4444 | 1337 | 31337 => "backdoor-style port",
        _ => return None,
    })
}

fn suspicious_location(path: &str) -> Option<&'static str> {
    let p = path.to_ascii_lowercase();
    if p.contains("\\appdata\\local\\temp\\") || p.contains("\\windows\\temp\\") {
        Some("runs from a Temp folder")
    } else if p.contains("\\downloads\\") {
        Some("runs from Downloads")
    } else if p.contains("\\users\\public\\") {
        Some("runs from the Public user folder")
    } else if p.contains("\\$recycle.bin\\") {
        Some("runs from the Recycle Bin")
    } else {
        None
    }
}

fn fmt_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// A history row that is still open: its id, the worst risk seen so far, and
/// whether it has a hostname (DNS events can land a poll after the connection).
struct OpenRow {
    id: i64,
    risk: &'static str,
    named: bool,
}

pub struct Monitor {
    started: u64,
    tick: u64,
    first_seen: HashMap<String, u64>,
    /// pid -> (exe name from the process list, image path)
    paths: HashMap<u32, (String, Option<String>)>,
    sigs: Arc<Mutex<HashMap<String, SigInfo>>>,
    sig_tx: Sender<String>,
    store: Arc<Store>,
    /// exe -> first time it used the network, across all runs.
    known_programs: HashMap<String, u64>,
    known_listeners: HashSet<(String, u16)>,
    /// First-ever run: record the baseline without "first time" alerts.
    learning: bool,
    baseline_at: u64,
    alerted: HashSet<String>,
    open_rows: HashMap<String, OpenRow>,
    writes: TickWrites,
    intel: Arc<Intel>,
    rdns: Rdns,
    dns: Arc<DnsNames>,
    /// pid -> hosted service names, refreshed periodically.
    services: HashMap<u32, Vec<String>>,
    /// VPN adapter that is up during the current poll.
    vpn: Option<String>,
    /// Our own PID; NetWatch's feed downloads are never flagged.
    me: u32,
}

impl Monitor {
    pub fn new(intel: Arc<Intel>, store: Arc<Store>, dns: Arc<DnsNames>) -> Self {
        let sigs: Arc<Mutex<HashMap<String, SigInfo>>> = Arc::default();
        let (sig_tx, sig_rx) = mpsc::channel::<String>();

        // Signature checks can take tens of ms each, so they run off the poll loop.
        let worker_sigs = sigs.clone();
        std::thread::Builder::new()
            .name("sig-verify".into())
            .spawn(move || {
                for path in sig_rx {
                    let info = sig::verify(&path);
                    worker_sigs.lock().unwrap().insert(path, info);
                }
            })
            .expect("spawn signature worker");

        let known_programs = store.known_programs().unwrap_or_default();
        let known_listeners = store.known_listeners().unwrap_or_default();
        let alerted = store.alert_keys().unwrap_or_default();

        Self {
            started: now_ms(),
            tick: 0,
            first_seen: HashMap::new(),
            paths: HashMap::new(),
            sigs,
            sig_tx,
            learning: known_programs.is_empty(),
            baseline_at: store.baseline_at().unwrap_or(0),
            known_programs,
            known_listeners,
            alerted,
            open_rows: HashMap::new(),
            writes: TickWrites::default(),
            store,
            intel,
            rdns: Rdns::new(),
            dns,
            services: HashMap::new(),
            vpn: None,
            me: std::process::id(),
        }
    }

    fn sig_for(&self, path: &str) -> SigInfo {
        let mut sigs = self.sigs.lock().unwrap();
        if let Some(info) = sigs.get(path) {
            return info.clone();
        }
        sigs.insert(path.to_string(), SigInfo::pending());
        let _ = self.sig_tx.send(path.to_string());
        SigInfo::pending()
    }

    fn alert(&mut self, key: String, severity: &'static str, title: String, detail: String, c: &ConnView) {
        if !self.alerted.insert(key.clone()) {
            return;
        }
        let alert = Alert {
            id: 0,
            ts: now_ms(),
            severity: severity.to_string(),
            title,
            detail,
            process: c.who(),
            exe: c.exe(),
            pid: c.pid,
            acked: false,
        };
        if let Err(e) = self.store.add_alert(&key, &alert) {
            eprintln!("failed to save alert: {e}");
        }
    }

    pub fn tick(&mut self) -> Snapshot {
        let now = now_ms();
        let first_tick = self.tick == 0;
        self.tick += 1;

        let raw = net::collect();
        let names = procs::process_names();
        let rules = self.store.rules.read().unwrap().clone();
        let ifaces = ifaces::collect();
        self.vpn = ifaces.vpn.clone();

        // Drop cached paths for PIDs that exited or were reused by another exe.
        self.paths.retain(|pid, (name, _)| names.get(pid) == Some(name));

        // Service hosts come and go rarely; re-enumerate periodically or when
        // a service host we haven't mapped yet owns a socket.
        let unmapped_host = raw.iter().any(|c| {
            !self.services.contains_key(&c.pid)
                && names.get(&c.pid).is_some_and(|n| n.eq_ignore_ascii_case("svchost.exe"))
        });
        if first_tick || unmapped_host || self.tick % TOUCH_EVERY == 0 {
            self.services = services::by_pid();
        }

        let tcp_listen_ports: HashSet<u16> = raw
            .iter()
            .filter(|c| c.proto == Proto::Tcp && c.state == TCP_LISTEN)
            .map(|c| c.local.port())
            .collect();

        let mut live_ids = HashSet::with_capacity(raw.len());
        let mut conns = Vec::with_capacity(raw.len());

        for c in &raw {
            let exe_name = names.get(&c.pid).cloned();
            let process = match c.pid {
                0 => "System Idle".to_string(),
                4 => "System".to_string(),
                pid if pid == self.me => "NetWatch (this app)".to_string(),
                pid => exe_name.clone().unwrap_or_else(|| format!("PID {pid}")),
            };
            let path = match (c.pid, exe_name) {
                (0..=4, _) | (_, None) => None,
                (pid, Some(name)) => self
                    .paths
                    .entry(pid)
                    .or_insert_with(|| (name, procs::process_path(pid)))
                    .1
                    .clone(),
            };
            let sig = match (&path, c.pid) {
                (_, 0 | 4) => SigInfo { status: "system", signer: Some("Windows kernel".into()) },
                (Some(p), _) => self.sig_for(p),
                (None, _) => SigInfo { status: "unknown", signer: None },
            };

            let proto = match c.proto {
                Proto::Tcp => "TCP",
                Proto::Udp => "UDP",
            };
            let remote_str = c.remote.map(|r| format!("{}:{}", fmt_ip(r.ip()), r.port()));
            let id = format!(
                "{proto}|{}:{}|{}|{}",
                fmt_ip(c.local.ip()),
                c.local.port(),
                remote_str.as_deref().unwrap_or("-"),
                c.pid
            );
            let first_seen = *self.first_seen.entry(id.clone()).or_insert(now);
            live_ids.insert(id.clone());

            let direction = match (c.proto, c.state) {
                (Proto::Udp, _) => "udp",
                (Proto::Tcp, TCP_LISTEN) => "listen",
                _ if tcp_listen_ports.contains(&c.local.port()) => "inbound",
                _ => "outbound",
            };
            let scope = match c.remote {
                Some(r) => net::scope(r.ip()),
                None => net::scope(c.local.ip()),
            };
            let state = match c.proto {
                Proto::Tcp => net::tcp_state_name(c.state),
                Proto::Udp => "Bound",
            };
            let remote_ip = c.remote.map(|r| r.ip()).filter(|_| matches!(scope, "public" | "private"));
            let (host, geo, intel) = match remote_ip {
                Some(ip) => (
                    self.dns.lookup(ip).or_else(|| self.rdns.lookup(ip)),
                    if scope == "public" { self.intel.geo(ip) } else { GeoInfo::default() },
                    self.intel.hits(ip),
                ),
                None => (None, GeoInfo::default(), Vec::new()),
            };
            let remote_addr = c.remote.map(|r| fmt_ip(r.ip()));
            let ip_rule = remote_addr.as_deref().and_then(|a| rules.ip(a));
            let exe_key = path.clone().unwrap_or_else(|| process.clone());
            let program_trusted = rules.program(&exe_key).is_some_and(|r| r.trusted);
            let adapter = ifaces.adapter(c.local.ip());

            conns.push(ConnView {
                id,
                proto,
                ipv: if c.local.is_ipv4() { 4 } else { 6 },
                local_addr: fmt_ip(c.local.ip()),
                local_port: c.local.port(),
                remote_addr,
                remote_port: c.remote.map(|r| r.port()),
                state,
                direction,
                scope,
                pid: c.pid,
                process,
                services: self.services.get(&c.pid).cloned().unwrap_or_default(),
                path,
                sig: sig.status,
                signer: sig.signer,
                first_seen,
                iface: adapter.map(|a| a.name.clone()),
                via_vpn: adapter.map(|a| a.vpn),
                host,
                geo,
                intel,
                label: ip_rule.and_then(|r| r.label.clone()),
                ip_trusted: ip_rule.is_some_and(|r| r.trusted),
                program_trusted,
                program_since: None,
                program_new: false,
                risk: "none",
                reasons: Vec::new(),
            });
        }

        self.first_seen.retain(|id, _| live_ids.contains(id));

        for i in 0..conns.len() {
            self.evaluate(&mut conns, i);
        }
        for c in &mut conns {
            c.program_since = self.known_programs.get(&c.exe()).copied();
            // The baseline tick itself takes a moment; allow a minute of slack.
            c.program_new = c
                .program_since
                .is_some_and(|t| t > self.baseline_at + 60_000 && now.saturating_sub(t) < DAY_MS);
        }

        self.record_history(&conns);
        if first_tick {
            // The baseline is captured; later runs alert on anything new.
            self.learning = false;
        }
        if self.tick % PRUNE_EVERY == 0 {
            let _ = self.store.prune();
        }

        let stats = compute_stats(&conns);
        Snapshot {
            ts: now,
            started: self.started,
            tick: self.tick,
            learning: self.learning,
            known_programs: self.known_programs.len(),
            vpn: self.vpn.clone(),
            dns_names: self.dns.active(),
            conns,
            stats,
            alerts: self.store.recent_alerts(MAX_ALERTS).unwrap_or_default(),
            intel: self.intel.status(),
        }
    }

    /// Writes opened/closed connections plus baseline changes for this poll.
    fn record_history(&mut self, conns: &[ConnView]) {
        let mut w = std::mem::take(&mut self.writes);
        let mut live = HashSet::new();

        for c in conns {
            // Only real remote traffic with a known owner; TIME_WAIT rows
            // (PID 0) are the tail end of connections already recorded.
            let recordable = c.pid != 0
                && c.pid != self.me
                && matches!(c.direction, "outbound" | "inbound")
                && matches!(c.scope, "public" | "private");
            if !recordable {
                continue;
            }
            live.insert(c.id.clone());
            match self.open_rows.get_mut(&c.id) {
                Some(row) => {
                    if c.risk == "high" || (c.risk == "medium" && row.risk == "none") {
                        row.risk = c.risk;
                    }
                    if let (false, Some(host)) = (row.named, &c.host) {
                        w.named.push((row.id, host.clone()));
                        row.named = true;
                    }
                }
                None => w.opened.push((
                    c.id.clone(),
                    NewConn {
                        exe: c.exe(),
                        process: c.who(),
                        pid: c.pid,
                        proto: c.proto,
                        local_port: c.local_port,
                        remote_ip: c.remote_addr.clone().unwrap_or_default(),
                        remote_port: c.remote_port.unwrap_or(0),
                        direction: c.direction,
                        host: c.host.clone(),
                        country: c.geo.country.clone(),
                        org: c.geo.org.clone(),
                        first_seen: c.first_seen,
                        risk: c.risk,
                    },
                )),
            }
        }

        // A closing connection is usually still listed (as TIME_WAIT under PID 0),
        // so look its enrichment up by remote address.
        let by_remote: HashMap<&str, &ConnView> = conns
            .iter()
            .filter_map(|c| c.remote_addr.as_deref().map(|a| (a, c)))
            .collect();
        let gone: Vec<String> = self.open_rows.keys().filter(|k| !live.contains(*k)).cloned().collect();
        for key in gone {
            if let Some(row) = self.open_rows.remove(&key) {
                let remote = key.split('|').nth(2).and_then(|r| r.rsplit_once(':')).map(|(ip, _)| ip);
                let seen = remote.and_then(|ip| by_remote.get(ip));
                let dns_name = remote.and_then(|ip| ip.parse().ok()).and_then(|ip| self.dns.lookup(ip));
                w.closed.push(Closed {
                    id: row.id,
                    host: seen.and_then(|c| c.host.clone()).or(dns_name),
                    country: seen.and_then(|c| c.geo.country.clone()),
                    org: seen.and_then(|c| c.geo.org.clone()),
                    risk: row.risk,
                });
            }
        }
        if self.tick % TOUCH_EVERY == 0 {
            w.touch = self.open_rows.values().map(|r| r.id).collect();
            let seen: HashSet<String> = conns
                .iter()
                .filter(|c| c.state == "Established" && matches!(c.scope, "public" | "private"))
                .map(|c| c.exe())
                .collect();
            w.seen_programs = seen.into_iter().collect();
        }

        match self.store.write_tick(w) {
            Ok(ids) => {
                for (key, id) in ids {
                    let opened = conns.iter().find(|c| c.id == key);
                    let risk = opened.map_or("none", |c| c.risk);
                    let named = opened.is_some_and(|c| c.host.is_some());
                    self.open_rows.insert(key, OpenRow { id, risk, named });
                }
            }
            Err(e) => eprintln!("failed to write history: {e}"),
        }
    }

    /// Applies the detection rules to one connection, tagging it and raising alerts.
    fn evaluate(&mut self, conns: &mut [ConnView], i: usize) {
        let c = conns[i].clone();
        if c.pid == self.me {
            return;
        }
        let exe = c.exe();
        let talks_out = matches!(c.scope, "public" | "private")
            && matches!(c.direction, "outbound" | "inbound")
            && c.state == net::tcp_state_name(TCP_ESTABLISHED);
        let is_listener = c.direction == "listen";
        let all_ifaces = c.local_addr == "0.0.0.0" || c.local_addr == "::";
        // Trusted programs skip the heuristic rules, not the threat-feed ones.
        let heuristics = !c.program_trusted;
        let target = c
            .remote_addr
            .as_ref()
            .map(|a| {
                let name = c.label.as_deref().or(c.host.as_deref());
                format!("{a}:{}{}", c.remote_port.unwrap_or(0), name.map(|n| format!(" ({n})")).unwrap_or_default())
            })
            .unwrap_or_default();

        let mut risk = "none";
        let mut reasons = Vec::new();
        let mut raise = |r: &'static str| {
            if r == "high" || risk == "none" {
                risk = r;
            }
        };

        // Any contact with a listed host counts, including half-open and
        // closing connections: those still mean traffic was exchanged.
        if !c.ip_trusted {
            for hit in &c.intel {
                raise(hit.severity);
                reasons.push(format!("Remote host is a {} ({})", hit.label.to_lowercase(), hit.feed));
                let who = if c.pid == 0 { "A recently closed connection".to_string() } else { c.process.clone() };
                let verb = if c.direction == "inbound" { "accepted a connection from" } else { "contacted" };
                self.alert(
                    format!("intel|{}|{}|{exe}", hit.feed, c.remote_addr.as_deref().unwrap_or("")),
                    hit.severity,
                    format!("{who} {verb} a {}", hit.label.to_lowercase()),
                    format!(
                        "{target}{}\nListed by {}\n{exe}",
                        c.geo.org.as_deref().map(|o| format!(" · {o}")).unwrap_or_default(),
                        hit.feed
                    ),
                    &c,
                );
            }
        }

        if heuristics && (talks_out || (is_listener && all_ifaces)) {
            match c.sig {
                "unsigned" => {
                    raise("high");
                    reasons.push("Program is not digitally signed".to_string());
                }
                "invalid" => {
                    raise("high");
                    reasons.push("Digital signature is invalid or untrusted".to_string());
                }
                _ => {}
            }
            if let Some(why) = c.path.as_deref().and_then(suspicious_location) {
                raise("high");
                reasons.push(format!("Program {why}"));
            }
        }

        if talks_out {
            if let Some(port) = c.remote_port.filter(|_| c.direction == "outbound" && heuristics && !c.ip_trusted) {
                if let Some(what) = suspicious_port(port) {
                    raise("medium");
                    reasons.push(format!("Remote port {port}: {what}"));
                    self.alert(
                        format!("port|{exe}|{port}"),
                        "medium",
                        format!("{} connected to port {port}", c.who()),
                        format!("{target} — {what}"),
                        &c,
                    );
                }
            }
            // With a VPN up, public traffic should leave through the tunnel. VPN
            // clients themselves talk to their servers outside it, so skip them.
            let vpn_client = c.process.to_ascii_lowercase().contains("vpn");
            if let (Some(vpn), Some(false)) = (self.vpn.clone(), c.via_vpn) {
                if c.direction == "outbound" && c.scope == "public" && heuristics && !c.ip_trusted && !vpn_client {
                    let iface = c.iface.as_deref().unwrap_or("another adapter");
                    raise("medium");
                    reasons.push(format!("Bypasses the VPN: sent over {iface} while {vpn} is connected"));
                    self.alert(
                        format!("leak|{exe}"),
                        "medium",
                        format!("{} is bypassing the VPN", c.who()),
                        format!("{target} via {iface} while {vpn} is connected\n{exe}"),
                        &c,
                    );
                }
            }
            if heuristics && matches!(c.sig, "unsigned" | "invalid") {
                self.alert(
                    format!("sig|{exe}"),
                    "high",
                    format!("{} program is using the network", if c.sig == "unsigned" { "Unsigned" } else { "Invalid-signature" }),
                    format!("{} → {target}\n{exe}", c.process),
                    &c,
                );
            }
            if let Some(why) = c.path.as_deref().and_then(suspicious_location).filter(|_| heuristics) {
                self.alert(
                    format!("loc|{exe}"),
                    "high",
                    format!("Network activity from a program that {why}"),
                    format!("{} → {target}\n{exe}", c.process),
                    &c,
                );
            }
            if c.pid != 0 && !self.known_programs.contains_key(&exe) {
                self.known_programs.insert(exe.clone(), now_ms());
                self.writes.new_programs.push((exe.clone(), c.process.clone()));
                if !self.learning && heuristics {
                    self.alert(
                        format!("first|{exe}"),
                        "info",
                        format!("{} used the network for the first time", c.who()),
                        format!("{target}\n{exe}"),
                        &c,
                    );
                }
            }
        }

        if is_listener && all_ifaces && heuristics {
            if let Some(what) = risky_listener(c.local_port) {
                raise("medium");
                reasons.push(format!("{what} exposed on all network interfaces"));
                self.alert(
                    format!("rlisten|{}|{exe}", c.local_port),
                    "medium",
                    format!("{what} is open to the network (port {})", c.local_port),
                    format!("{} listens on {}:{}", c.who(), c.local_addr, c.local_port),
                    &c,
                );
            }
            if matches!(c.sig, "unsigned" | "invalid") {
                self.alert(
                    format!("slisten|{}|{exe}", c.local_port),
                    "high",
                    format!("Unsigned program accepting connections on port {}", c.local_port),
                    format!("{}\n{exe}", c.process),
                    &c,
                );
            }
        }

        if is_listener && self.known_listeners.insert((exe.clone(), c.local_port)) {
            self.writes.new_listeners.push((exe.clone(), c.local_port));
            if !self.learning && heuristics {
                self.alert(
                    format!("listen|{}|{exe}", c.local_port),
                    "info",
                    format!("New listening port {}", c.local_port),
                    format!("{} on {}:{}", c.who(), c.local_addr, c.local_port),
                    &c,
                );
            }
        }

        conns[i].risk = risk;
        conns[i].reasons = reasons;
    }
}

fn compute_stats(conns: &[ConnView]) -> Stats {
    let mut s = Stats { total: conns.len(), ..Default::default() };
    let mut hosts = HashSet::new();
    let mut public = HashSet::new();
    let mut pids = HashSet::new();
    for c in conns {
        match c.direction {
            "listen" => s.listening += 1,
            "udp" => s.udp += 1,
            "outbound" if c.state == "Established" => s.outbound += 1,
            "inbound" if c.state == "Established" => s.inbound += 1,
            _ => {}
        }
        if c.state == "Established" {
            s.established += 1;
            if let Some(a) = &c.remote_addr {
                if c.scope != "loopback" {
                    hosts.insert(a.clone());
                    pids.insert(c.pid);
                }
                if c.scope == "public" {
                    public.insert(a.clone());
                }
            }
        }
        if c.risk != "none" {
            s.risky += 1;
        }
    }
    s.remote_hosts = hosts.len();
    s.public_hosts = public.len();
    s.processes = pids.len();
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Rule;

    #[test]
    fn live_scan_smoke() {
        let base = std::env::temp_dir().join("netwatch-test");
        let _ = std::fs::remove_file(base.join("test.db"));
        let (intel, _refresh) = Intel::start(base.join("intel"));
        let store = Arc::new(Store::open(&base.join("test.db")).unwrap());
        let mut m = Monitor::new(intel.clone(), store.clone(), Arc::default());
        assert!(m.learning, "fresh database starts in learning mode");
        m.tick();
        assert!(!m.learning);
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let st = intel.status();
            if st.last_check.is_some() && !st.updating {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
        let s = m.tick();
        println!(
            "stats: total={} est={} out={} listen={} hosts={} risky={} known_programs={}",
            s.stats.total, s.stats.established, s.stats.outbound, s.stats.listening,
            s.stats.remote_hosts, s.stats.risky, s.known_programs
        );
        assert!(s.known_programs > 0, "baseline recorded programs");

        // Trust/label rules flow into the next poll.
        let target = s.conns.iter().find(|c| c.remote_addr.is_some() && c.scope != "loopback").unwrap();
        let ip = target.remote_addr.clone().unwrap();
        store
            .set_rule(Rule { kind: "ip".into(), target: ip.clone(), label: Some("Test label".into()), trusted: true, created: 0 })
            .unwrap();
        let s = m.tick();
        let labelled = s.conns.iter().find(|c| c.remote_addr.as_deref() == Some(&ip)).unwrap();
        assert_eq!(labelled.label.as_deref(), Some("Test label"));
        assert!(labelled.ip_trusted);

        let info = store.info().unwrap();
        let hist = store.history(0, "", 20).unwrap();
        println!("db: programs={} connections={} bytes={}", info.programs, info.connections, info.bytes);
        for r in hist.rows.iter().take(5) {
            println!("hist {:<22} {:<40} {:<5} {:<4} {}", r.process, r.remote_ip, r.remote_port, r.country.clone().unwrap_or_default(), r.host.clone().unwrap_or_default());
        }
        assert!(info.connections > 0, "history rows written");

        // A restarted monitor keeps the baseline and doesn't relearn.
        let m2 = Monitor::new(intel, store, Arc::default());
        assert!(!m2.learning);
    }
}
