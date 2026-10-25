//! Devices on the local network, read passively from Windows' neighbor (ARP/NDP)
//! table, with manufacturer names from the IEEE MAC address registry.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, NlnsIncomplete, NlnsUnreachable,
};

use crate::intel;

const OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";
const OUI_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
const OUI_RETRY: Duration = Duration::from_secs(6 * 3600);

/// A device seen in the neighbor table during this poll.
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub mac: [u8; 6],
    pub ip: IpAddr,
}

pub fn fmt_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Phones and newer laptops randomize their MAC per network for privacy; those
/// set the "locally administered" bit and have no registered manufacturer.
pub fn is_private_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

/// Real unicast hardware addresses only: no multicast, broadcast or empty entries.
fn is_device_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 0x01 == 0 && *mac != [0; 6] && *mac != [0xff; 6]
}

fn is_device_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !(a.is_multicast() || a.is_broadcast() || a.is_unspecified() || a.octets()[3] == 255),
        IpAddr::V6(a) => !(a.is_multicast() || a.is_unspecified()),
    }
}

/// One entry per device on the given interfaces, preferring its IPv4 address.
pub fn neighbors(lan: &HashSet<u32>) -> Vec<Neighbor> {
    let mut by_mac: HashMap<[u8; 6], IpAddr> = HashMap::new();
    unsafe {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        if GetIpNetTable2(AF_UNSPEC, &mut table) != NO_ERROR || table.is_null() {
            return Vec::new();
        }
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for r in rows {
            if !lan.contains(&r.InterfaceIndex)
                || r.PhysicalAddressLength != 6
                || r.State == NlnsUnreachable
                || r.State == NlnsIncomplete
            {
                continue;
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&r.PhysicalAddress[..6]);
            let ip = match r.Address.si_family {
                AF_INET => IpAddr::V4(Ipv4Addr::from(r.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())),
                AF_INET6 => IpAddr::V6(Ipv6Addr::from(r.Address.Ipv6.sin6_addr.u.Byte)),
                _ => continue,
            };
            if !is_device_mac(&mac) || !is_device_ip(ip) {
                continue;
            }
            let slot = by_mac.entry(mac).or_insert(ip);
            if slot.is_ipv6() && ip.is_ipv4() {
                *slot = ip;
            }
        }
        FreeMibTable(table as *const _);
    }
    by_mac.into_iter().map(|(mac, ip)| Neighbor { mac, ip }).collect()
}

/* ---------- Manufacturer lookup ---------- */

#[derive(Default)]
pub struct Vendors {
    /// First three MAC bytes -> registered organization.
    oui: RwLock<HashMap<u32, String>>,
}

impl Vendors {
    /// Loads the cached registry and keeps it fresh in the background.
    pub fn start(dir: PathBuf) -> Arc<Self> {
        let me = Arc::new(Self::default());
        let worker = me.clone();
        std::thread::Builder::new()
            .name("oui-update".into())
            .spawn(move || worker.run(dir.join("oui.csv")))
            .expect("spawn OUI updater");
        me
    }

    fn run(&self, path: PathBuf) {
        if let Ok(text) = fs::read_to_string(&path) {
            self.install(&text);
        }
        loop {
            if !intel::is_fresh(&path, OUI_MAX_AGE) {
                match intel::download(OUI_URL).and_then(|b| String::from_utf8(b).map_err(|e| e.to_string())) {
                    Ok(text) if text.starts_with("Registry,") => {
                        self.install(&text);
                        let _ = intel::write_atomic(&path, text.as_bytes());
                    }
                    Ok(_) => eprintln!("OUI registry download returned unexpected content"),
                    Err(e) => eprintln!("OUI registry download failed: {e}"),
                }
            }
            std::thread::sleep(OUI_RETRY);
        }
    }

    fn install(&self, csv: &str) {
        let map = parse_oui(csv);
        if !map.is_empty() {
            *self.oui.write().unwrap() = map;
        }
    }

    pub fn lookup(&self, mac: &[u8; 6]) -> Option<String> {
        if is_private_mac(mac) {
            return None;
        }
        let key = u32::from_be_bytes([0, mac[0], mac[1], mac[2]]);
        self.oui.read().unwrap().get(&key).cloned()
    }
}

/// Rows look like `MA-L,286FB9,"Some Company, Inc.",Address...`.
fn parse_oui(csv: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in csv.lines().skip(1) {
        let Some(rest) = line.strip_prefix("MA-L,") else { continue };
        let Some((hex, rest)) = rest.split_once(',') else { continue };
        let Ok(key) = u32::from_str_radix(hex, 16) else { continue };
        let name = match rest.strip_prefix('"') {
            Some(quoted) => quoted.split_once("\",").map_or(quoted, |(n, _)| n).replace("\"\"", "\""),
            None => rest.split(',').next().unwrap_or("").to_string(),
        };
        let name = name.trim();
        if !name.is_empty() {
            map.insert(key, name.to_string());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_rows() {
        let csv = "Registry,Assignment,Organization Name,Organization Address\n\
                   MA-L,0A1B2C,\"Example Networks, Inc.\",1 Example Way\n\
                   MA-L,1A2B3C,Plain Name Ltd,Somewhere\n\
                   MA-M,4D5E6F7,Ignored Medium Block,Nowhere\n";
        let map = parse_oui(csv);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&0x0A1B2C], "Example Networks, Inc.");
        assert_eq!(map[&0x1A2B3C], "Plain Name Ltd");
    }

    #[test]
    fn classifies_macs() {
        assert!(is_device_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert!(!is_device_mac(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]), "multicast");
        assert!(!is_device_mac(&[0xff; 6]), "broadcast");
        assert!(!is_device_mac(&[0; 6]));
        assert!(is_private_mac(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert!(!is_private_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(fmt_mac(&[0x00, 0x0a, 0xff, 0x01, 0x02, 0x03]), "00:0a:ff:01:02:03");
    }

    /// Reads this PC's neighbor table; prints only a count, never addresses.
    #[test]
    fn reads_neighbor_table() {
        let lan = crate::ifaces::collect().lan;
        let found = neighbors(&lan);
        println!("{} devices on {} local interfaces", found.len(), lan.len());
        assert!(found.iter().all(|n| is_device_mac(&n.mac)));
    }
}
