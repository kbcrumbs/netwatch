//! Turns raw connection tables into enriched views, stats and alerts, and
//! records history and the baseline in the store.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::devices::{self, PortScanner, Sweeper, SweepStatus, Vendors};
use crate::dns::DnsNames;
use crate::ifaces;
use crate::localnames::LocalNames;
use crate::intel::{GeoInfo, Intel, IntelHit, IntelStatus};
use crate::net::{self, Proto, TCP_ESTABLISHED, TCP_LISTEN};
use crate::procs;
use crate::rdns::Rdns;
use crate::services;
use crate::sig::{self, SigInfo};
use crate::store::{Alert, Closed, Device, NewConn, Store, TickWrites};

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
pub struct DeviceView {
    #[serde(flatten)]
    pub device: Device,
    /// In the neighbor table right now.
    pub online: bool,
    /// Randomized MAC: no manufacturer, may change between networks.
    pub private_mac: bool,
    /// First seen after the device baseline, within the last day.
    pub new: bool,
    /// The default gateway of a local adapter.
    pub router: bool,
    /// User's name for the device, and whether they trust it.
    pub label: Option<String>,
    pub trusted: bool,
    /// A port check is queued or running.
    pub checking_ports: bool,
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
    pub devices: Vec<DeviceView>,
    pub sweep: SweepStatus,
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

/// Alert severity for a program in a suspicious folder. Installers and updaters
/// (e.g. Visual Studio's) run signed copies of themselves from Temp, so signed
/// ones are informational; None while the signature check is still running.
fn location_severity(sig: &str) -> Option<&'static str> {
    match sig {
        "pending" => None,
        "signed" => Some("info"),
        _ => Some("high"),
    }
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
    vendors: Arc<Vendors>,
    /// mac -> device, every device seen within the retention window.
    devices: HashMap<String, Device>,
    devices_baseline_at: u64,
    /// No devices recorded yet: the first poll records them without alerts.
    devices_learning: bool,
    sweeper: Arc<Sweeper>,
    /// The first sweep's answers become baseline too: devices that were already
    /// on the network but never talked to this PC shouldn't each raise an alert.
    sweep_learning: bool,
    ports: Arc<PortScanner>,
    /// Names devices announce for themselves (NetBIOS / mDNS).
    local_names: Arc<LocalNames>,
    gateways: HashSet<IpAddr>,
    /// Gateway IP -> the MAC it last answered from (cached from the store).
    gateway_macs: HashMap<String, String>,
    /// Our own PID; NetWatch's feed downloads are never flagged.
    me: u32,
}

impl Monitor {
    pub fn new(
        intel: Arc<Intel>,
        store: Arc<Store>,
        dns: Arc<DnsNames>,
        vendors: Arc<Vendors>,
        sweeper: Arc<Sweeper>,
        ports: Arc<PortScanner>,
        local_names: Arc<LocalNames>,
    ) -> Self {
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
        let devices_baseline_at = store.devices_baseline_at().unwrap_or(0);
        let sweep_learning = !store.sweep_baselined().unwrap_or(true);
        let devices: HashMap<String, Device> =
            store.devices().unwrap_or_default().into_iter().map(|d| (d.mac.clone(), d)).collect();

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
            vendors,
            devices_learning: devices.is_empty(),
            devices_baseline_at,
            devices,
            sweeper,
            sweep_learning,
            ports,
            local_names,
            gateways: HashSet::new(),
            gateway_macs: HashMap::new(),
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
        self.raise_alert(key, severity, title, detail, c.who(), c.exe(), c.pid);
    }

    #[allow(clippy::too_many_arguments)]
    fn raise_alert(
        &mut self,
        key: String,
        severity: &'static str,
        title: String,
        detail: String,
        process: String,
        exe: String,
        pid: u32,
    ) {
        if !self.alerted.insert(key.clone()) {
            return;
        }
        let alert = Alert {
            id: 0,
            ts: now_ms(),
            severity: severity.to_string(),
            title,
            detail,
            process,
            exe,
            pid,
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
        self.gateways = ifaces.gateways.clone();

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

        let (sweep, answered) = self.sweeper.take();
        let mut seen = devices::neighbors(&ifaces.lan);
        seen.extend(answered);
        let devices = self.merge_devices(&seen, &sweep, now);
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
            devices,
            sweep,
            stats,
            alerts: self.store.recent_alerts(MAX_ALERTS).unwrap_or_default(),
            intel: self.intel.status(),
        }
    }

    /// Until the first sweep has landed, anything new is part of the baseline:
    /// devices already on the network shouldn't each raise an alert just
    /// because Windows happened to talk to them before the sweep finished.
    fn merge_devices(&mut self, seen: &[devices::Neighbor], sweep: &SweepStatus, now: u64) -> Vec<DeviceView> {
        let (checking, finished) = self.ports.take();
        for r in finished {
            self.record_ports(r);
        }
        let mut views = self.update_devices(seen, now, self.sweep_learning);
        for v in &mut views {
            v.checking_ports = checking.contains(&v.device.mac);
        }
        if self.sweep_learning && sweep.last_scan.is_some() {
            self.sweep_learning = false;
            let _ = self.store.mark_sweep_baselined();
        }
        views
    }

    fn record_ports(&mut self, r: devices::PortResult) {
        let rule = self.store.rules.read().unwrap().device(&r.mac).cloned();
        let Some(d) = self.devices.get_mut(&r.mac) else { return };
        d.ports = Some(r.open.clone());
        d.ports_at = Some(r.at);
        let d = d.clone();
        self.writes.devices.push(d.clone());
        if rule.as_ref().is_some_and(|r| r.trusted) {
            return;
        }
        let who = rule
            .and_then(|r| r.label)
            .or(d.name.clone())
            .or(d.vendor.clone())
            .unwrap_or_else(|| "A device".into());
        for port in r.open {
            if let Some(what) = devices::risky_port(port) {
                self.raise_alert(
                    format!("dport|{}|{port}", d.mac),
                    "medium",
                    format!("{who} has {what} open (port {port})"),
                    format!("{} · {}\nAnyone on your network can try to log in to it.", d.ip, d.mac),
                    "Local network".into(),
                    String::new(),
                    0,
                );
            }
        }
    }

    /// A router that suddenly answers from a different MAC is the classic sign
    /// of ARP spoofing: another device claiming its address to intercept traffic.
    fn check_gateway(&mut self, ip: &str, mac: &str, vendor: Option<&str>) {
        let key = format!("gateway_mac|{ip}");
        if !self.gateway_macs.contains_key(ip) {
            if let Ok(Some(known)) = self.store.meta(&key) {
                self.gateway_macs.insert(ip.to_string(), known);
            }
        }
        match self.gateway_macs.get(ip) {
            Some(known) if known == mac => {}
            Some(known) => {
                let known = known.clone();
                self.raise_alert(
                    format!("gwmac|{ip}|{mac}"),
                    "high",
                    format!("Your router's hardware address changed ({ip})"),
                    format!(
                        "Was {known}, now {mac}{}.\nExpected if you replaced your router; otherwise another device may be impersonating it (ARP spoofing).",
                        vendor.map(|v| format!(" ({v})")).unwrap_or_default()
                    ),
                    "Local network".into(),
                    String::new(),
                    0,
                );
            }
            None => {}
        }
        if self.gateway_macs.get(ip).map(String::as_str) != Some(mac) {
            self.gateway_macs.insert(ip.to_string(), mac.to_string());
            let _ = self.store.set_meta(&key, mac);
        }
    }

    /// Merges this poll's neighbor table into the device list, queues database
    /// writes and alerts on devices never seen before.
    fn update_devices(&mut self, seen: &[devices::Neighbor], now: u64, quiet: bool) -> Vec<DeviceView> {
        let mut online = HashSet::new();
        for n in seen {
            let mac = devices::fmt_mac(&n.mac);
            let ip = fmt_ip(n.ip);
            // A device's own name beats whatever the router's DNS calls it.
            let announced = match n.ip {
                IpAddr::V4(v4) => self.local_names.name(&mac, v4),
                IpAddr::V6(_) => None,
            };
            let name = announced.or_else(|| self.rdns.lookup(n.ip));
            let vendor = self.vendors.lookup(&n.mac);
            online.insert(mac.clone());
            if self.gateways.contains(&n.ip) {
                self.check_gateway(&ip, &mac, vendor.as_deref());
            }
            match self.devices.get_mut(&mac) {
                Some(d) => {
                    let changed = d.ip != ip
                        || (name.is_some() && d.name != name)
                        || (vendor.is_some() && d.vendor.is_none());
                    d.ip = ip;
                    d.name = name.or(d.name.take());
                    d.vendor = vendor.or(d.vendor.take());
                    d.last_seen = now;
                    if changed || self.tick % TOUCH_EVERY == 0 {
                        self.writes.devices.push(d.clone());
                    }
                }
                None => {
                    let d = Device {
                        mac: mac.clone(),
                        ip,
                        name,
                        vendor,
                        first_seen: now,
                        last_seen: now,
                        ports: None,
                        ports_at: None,
                    };
                    if !self.devices_learning && !quiet {
                        let what = d.name.clone().or(d.vendor.clone()).unwrap_or_else(|| {
                            let kind = if devices::is_private_mac(&n.mac) { "Device with a private MAC" } else { "Unknown device" };
                            kind.to_string()
                        });
                        // Devices that were already around trickle in as Windows talks to
                        // them, so the first day after the baseline is informational.
                        let severity = if now < self.devices_baseline_at + DAY_MS { "info" } else { "medium" };
                        let vendor = d.vendor.as_deref().map(|v| format!(" · {v}")).unwrap_or_default();
                        self.raise_alert(
                            format!("device|{mac}"),
                            severity,
                            format!("New device on your network: {what}"),
                            format!("{} · {mac}{vendor}", d.ip),
                            "Local network".into(),
                            String::new(),
                            0,
                        );
                    }
                    self.writes.devices.push(d.clone());
                    self.devices.insert(mac, d);
                }
            }
        }
        self.devices_learning = false;

        let rules = self.store.rules.read().unwrap().clone();
        let mut views: Vec<DeviceView> = self
            .devices
            .values()
            .map(|d| DeviceView {
                label: rules.device(&d.mac).and_then(|r| r.label.clone()),
                trusted: rules.device(&d.mac).is_some_and(|r| r.trusted),
                online: online.contains(&d.mac),
                private_mac: u8::from_str_radix(&d.mac[..2], 16).is_ok_and(|b| b & 0x02 != 0),
                new: d.first_seen > self.devices_baseline_at + 60_000 && now.saturating_sub(d.first_seen) < DAY_MS,
                router: d.ip.parse().is_ok_and(|ip| self.gateways.contains(&ip)),
                checking_ports: false,
                device: d.clone(),
            })
            .collect();
        views.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.device.ip.cmp(&b.device.ip)));
        views
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
            // Installers and updaters (e.g. Visual Studio's) legitimately run signed
            // copies of themselves from Temp; only unsigned ones there are suspicious.
            if let Some(why) = c.path.as_deref().and_then(suspicious_location) {
                if c.sig != "signed" {
                    raise("high");
                }
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
            let located = c.path.as_deref().and_then(suspicious_location).filter(|_| heuristics);
            if let (Some(why), Some(severity)) = (located, location_severity(c.sig)) {
                let signed_by = match (c.sig, c.signer.as_deref()) {
                    ("signed", signer) => format!(" (signed by {})", signer.unwrap_or("a trusted publisher")),
                    _ => String::new(),
                };
                self.alert(
                    format!("loc|{exe}"),
                    severity,
                    format!("Network activity from a program that {why}{signed_by}"),
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

    fn neighbor(last: u8) -> devices::Neighbor {
        devices::Neighbor { mac: [0x00, 0x11, 0x22, 0x33, 0x44, last], ip: IpAddr::from([192, 0, 2, last]) }
    }

    fn device_alerts(store: &Store) -> usize {
        store.recent_alerts(100).unwrap().iter().filter(|a| a.title.starts_with("New device")).count()
    }

    /// Devices already on the network stay quiet until the first sweep is in;
    /// only devices that appear after that raise alerts.
    #[test]
    fn device_baseline_waits_for_first_sweep() {
        let base = std::env::temp_dir().join("netwatch-test");
        let db = base.join("devices-test.db");
        let _ = std::fs::remove_file(&db);
        let (intel, _refresh) = Intel::start(base.join("intel"));
        let store = Arc::new(Store::open(&db).unwrap());
        let mut m =
            Monitor::new(
                intel,
                store.clone(),
                Arc::default(),
                Arc::default(),
                Arc::default(),
                Arc::default(),
                Arc::default(),
            );

        let not_yet = SweepStatus::default();
        let swept = SweepStatus { last_scan: Some(2_500), ..Default::default() };

        m.merge_devices(&[neighbor(1)], &not_yet, 1_000);
        assert!(!m.devices_learning, "first poll is the passive baseline");
        // Before the first sweep finishes, more existing devices trickle in.
        m.merge_devices(&[neighbor(1), neighbor(2)], &not_yet, 2_000);
        assert_eq!(device_alerts(&store), 0, "no alerts before the first sweep");
        // The first sweep's answers are baseline too.
        m.merge_devices(&[neighbor(1), neighbor(2), neighbor(3)], &swept, 3_000);
        assert_eq!(device_alerts(&store), 0, "first sweep is quiet");
        assert!(store.sweep_baselined().unwrap());

        let views = m.merge_devices(&[neighbor(1), neighbor(4)], &swept, 4_000);
        assert_eq!(device_alerts(&store), 1, "a device joining after the sweep alerts");
        assert_eq!(views.len(), 4);
        assert_eq!(views.iter().filter(|v| v.online).count(), 2);
    }

    /// The router answering from a new MAC raises a high alert; the first
    /// sighting and repeat sightings don't.
    #[test]
    fn router_mac_change_alerts() {
        let base = std::env::temp_dir().join("netwatch-test");
        let db = base.join("gateway-test.db");
        let _ = std::fs::remove_file(&db);
        let (intel, _refresh) = Intel::start(base.join("intel"));
        let store = Arc::new(Store::open(&db).unwrap());
        let mut m =
            Monitor::new(
                intel,
                store.clone(),
                Arc::default(),
                Arc::default(),
                Arc::default(),
                Arc::default(),
                Arc::default(),
            );
        let spoof_alerts = |s: &Store| s.recent_alerts(100).unwrap().iter().filter(|a| a.severity == "high").count();

        m.check_gateway("192.0.2.1", "00:11:22:33:44:01", None);
        m.check_gateway("192.0.2.1", "00:11:22:33:44:01", None);
        assert_eq!(spoof_alerts(&store), 0, "first sighting is the baseline");
        m.check_gateway("192.0.2.1", "00:11:22:33:44:99", None);
        assert_eq!(spoof_alerts(&store), 1);
        assert_eq!(store.meta("gateway_mac|192.0.2.1").unwrap().as_deref(), Some("00:11:22:33:44:99"));
    }

    #[test]
    fn temp_folder_severity_follows_signature() {
        assert!(suspicious_location(r"C:\Users\someone\AppData\Local\Temp\x1\setup.exe").is_some());
        assert_eq!(location_severity("signed"), Some("info"));
        assert_eq!(location_severity("unsigned"), Some("high"));
        assert_eq!(location_severity("invalid"), Some("high"));
        assert_eq!(location_severity("pending"), None, "wait for the signature check");
    }

    /// Risky open ports alert, except on devices the user trusts.
    #[test]
    fn trusted_devices_skip_port_alerts() {
        let base = std::env::temp_dir().join("netwatch-test");
        let db = base.join("trust-test.db");
        let _ = std::fs::remove_file(&db);
        let (intel, _refresh) = Intel::start(base.join("intel"));
        let store = Arc::new(Store::open(&db).unwrap());
        let mut m = Monitor::new(
            intel,
            store.clone(),
            Arc::default(),
            Arc::default(),
            Arc::default(),
            Arc::default(),
            Arc::default(),
        );
        m.update_devices(&[neighbor(1), neighbor(2)], 1_000, true);
        let mac = |n: u8| devices::fmt_mac(&neighbor(n).mac);
        store
            .set_rule(Rule { kind: "device".into(), target: mac(1).to_uppercase(), label: Some("Desk PC".into()), trusted: true, created: 0 })
            .unwrap();
        let port_alerts = |s: &Store| s.recent_alerts(100).unwrap().iter().filter(|a| a.title.contains("port 3389")).count();

        m.record_ports(devices::PortResult { mac: mac(1), open: vec![3389], at: 2_000 });
        assert_eq!(port_alerts(&store), 0, "trusted device (rule matched case-insensitively)");
        m.record_ports(devices::PortResult { mac: mac(2), open: vec![3389], at: 2_000 });
        assert_eq!(port_alerts(&store), 1, "untrusted device alerts");

        let views = m.update_devices(&[neighbor(1)], 3_000, true);
        let desk = views.iter().find(|v| v.device.mac == mac(1)).unwrap();
        assert_eq!(desk.label.as_deref(), Some("Desk PC"));
        assert!(desk.trusted);
    }

    #[test]
    fn live_scan_smoke() {
        let base = std::env::temp_dir().join("netwatch-test");
        let _ = std::fs::remove_file(base.join("test.db"));
        let (intel, _refresh) = Intel::start(base.join("intel"));
        let store = Arc::new(Store::open(&base.join("test.db")).unwrap());
        let mut m = Monitor::new(
            intel.clone(),
            store.clone(),
            Arc::default(),
            Arc::default(),
            Arc::default(),
            Arc::default(),
            Arc::default(),
        );
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
        let m2 = Monitor::new(intel, store, Arc::default(), Arc::default(), Arc::default(), Arc::default(), Arc::default());
        assert!(!m2.learning);
    }
}
