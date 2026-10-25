//! Names devices give themselves on the local network: NetBIOS (Windows PCs,
//! NAS boxes, printers) and mDNS (phones, Macs, TVs, casting devices).
//!
//! Every query is a unicast packet sent straight to one device. Nothing is
//! multicast, so this PC never announces itself, and it works with NetBIOS
//! and mDNS turned off in Windows.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::monitor::now_ms;

const TIMEOUT: Duration = Duration::from_millis(600);
/// Devices that didn't answer are asked again after this long.
const RETRY_MS: u64 = 30 * 60 * 1000;

/* ---------- NetBIOS node status ---------- */

/// A node status (NBSTAT) request for the wildcard name "*".
fn netbios_query(id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // flags, 1 question
    p.push(32);
    // First-level encoding: each byte becomes two letters 'A' + nibble.
    let mut name = [0u8; 16];
    name[0] = b'*';
    for b in name {
        p.push(b'A' + (b >> 4));
        p.push(b'A' + (b & 0x0f));
    }
    p.push(0);
    p.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
    p
}

/// The machine name from a node status reply: the first unique name with suffix 0x00.
fn parse_netbios(resp: &[u8], id: u16) -> Option<String> {
    if resp.len() < 57 || resp[..2] != id.to_be_bytes() {
        return None;
    }
    // Header (12) + encoded name (34) + type, class, TTL, length (10).
    let count = resp[56] as usize;
    let table = resp.get(57..57 + count * 18)?;
    table.chunks_exact(18).find_map(|e| {
        let group = e[16] & 0x80 != 0;
        (e[15] == 0x00 && !group).then(|| String::from_utf8_lossy(&e[..15]).trim_end().to_string())
    })
    .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_graphic()))
}

/* ---------- mDNS reverse lookup ---------- */

/// A PTR query for `d.c.b.a.in-addr.arpa`, sent unicast to the device's port 5353.
fn mdns_query(id: u16, ip: Ipv4Addr) -> Vec<u8> {
    let mut p = Vec::with_capacity(48);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let o = ip.octets();
    for label in [o[3].to_string(), o[2].to_string(), o[1].to_string(), o[0].to_string()]
        .iter()
        .map(String::as_str)
        .chain(["in-addr", "arpa"])
    {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]); // PTR, IN
    p
}

/// Reads a possibly compressed DNS name at `pos`; returns it and the offset after it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = ptr;
            continue;
        }
        labels.push(String::from_utf8_lossy(msg.get(pos + 1..pos + 1 + len)?).into_owned());
        pos += 1 + len;
    }
    None
}

/// The hostname from the first PTR answer, without the ".local" suffix.
fn parse_mdns(resp: &[u8], id: u16) -> Option<String> {
    if resp.len() < 12 || resp[..2] != id.to_be_bytes() || resp[2] & 0x80 == 0 {
        return None;
    }
    let questions = u16::from_be_bytes([resp[4], resp[5]]);
    let answers = u16::from_be_bytes([resp[6], resp[7]]);
    let mut pos = 12;
    for _ in 0..questions {
        pos = read_name(resp, pos)?.1 + 4;
    }
    for _ in 0..answers {
        let (_, after) = read_name(resp, pos)?;
        let rtype = u16::from_be_bytes([*resp.get(after)?, *resp.get(after + 1)?]);
        let rdlen = u16::from_be_bytes([*resp.get(after + 8)?, *resp.get(after + 9)?]) as usize;
        let rdata = after + 10;
        if rtype == 12 {
            let (name, _) = read_name(resp, rdata)?;
            let name = name.trim_end_matches('.');
            let name = name.strip_suffix(".local").unwrap_or(name);
            return (!name.is_empty()).then(|| name.to_string());
        }
        pos = rdata + rdlen;
    }
    None
}

fn ask(ip: Ipv4Addr, port: u16, packet: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(TIMEOUT)).ok()?;
    sock.send_to(packet, SocketAddr::from((ip, port))).ok()?;
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = sock.recv_from(&mut buf).ok()?;
        if from.ip() == ip {
            return Some(buf[..n].to_vec());
        }
    }
}

/// The name a device announces for itself, preferring NetBIOS (it's the name
/// Windows shows), then mDNS.
pub fn lookup(ip: Ipv4Addr) -> Option<String> {
    let id = (now_ms() & 0xffff) as u16;
    ask(ip, 137, &netbios_query(id))
        .and_then(|r| parse_netbios(&r, id))
        .or_else(|| ask(ip, 5353, &mdns_query(id, ip)).and_then(|r| parse_mdns(&r, id)))
}

/* ---------- Background resolver ---------- */

#[derive(Default)]
struct State {
    /// mac -> announced name.
    names: HashMap<String, String>,
    /// mac -> when it was last asked (answered or not).
    asked: HashMap<String, u64>,
    busy: HashSet<String>,
}

/// Asks devices for their names in the background, one at a time.
#[derive(Default)]
pub struct LocalNames {
    state: Mutex<State>,
    tx: Mutex<Option<Sender<(String, Ipv4Addr)>>>,
}

impl LocalNames {
    pub fn start() -> Arc<Self> {
        let me = Arc::new(Self::default());
        let (tx, rx) = mpsc::channel::<(String, Ipv4Addr)>();
        *me.tx.lock().unwrap() = Some(tx);
        let worker = me.clone();
        std::thread::Builder::new()
            .name("local-names".into())
            .spawn(move || {
                for (mac, ip) in rx {
                    let name = lookup(ip);
                    let mut st = worker.state.lock().unwrap();
                    st.busy.remove(&mac);
                    if let Some(n) = name {
                        st.names.insert(mac, n);
                    }
                }
            })
            .expect("spawn local name resolver");
        me
    }

    /// The device's announced name, queueing a lookup if it's due.
    pub fn name(&self, mac: &str, ip: Ipv4Addr) -> Option<String> {
        let now = now_ms();
        let mut st = self.state.lock().unwrap();
        let due = st.asked.get(mac).is_none_or(|t| now.saturating_sub(*t) > RETRY_MS);
        if due && !st.busy.contains(mac) {
            if let Some(tx) = self.tx.lock().unwrap().as_ref() {
                st.asked.insert(mac.to_string(), now);
                st.busy.insert(mac.to_string());
                let _ = tx.send((mac.to_string(), ip));
            }
        }
        st.names.get(mac).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_netbios_query() {
        let q = netbios_query(0x1234);
        assert_eq!(q.len(), 50);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[13..15], b"CK", "'*' encodes as CK");
        assert_eq!(&q[15..17], b"AA", "padding encodes as AA");
        assert_eq!(&q[46..], &[0x00, 0x21, 0x00, 0x01]);
    }

    #[test]
    fn parses_netbios_reply() {
        let id: u16 = 0x0101;
        let mut r = vec![0u8; 56];
        r[..2].copy_from_slice(&id.to_be_bytes());
        r.push(2); // two names
        let mut group = b"WORKGROUP      ".to_vec();
        group.extend_from_slice(&[0x00, 0x84, 0x00]); // suffix 0, group flag
        let mut host = b"EXAMPLE-PC     ".to_vec();
        host.extend_from_slice(&[0x00, 0x04, 0x00]); // suffix 0, unique
        r.extend(group);
        r.extend(host);
        assert_eq!(parse_netbios(&r, id).as_deref(), Some("EXAMPLE-PC"));
        assert_eq!(parse_netbios(&r, 0x9999), None, "wrong transaction id");
    }

    #[test]
    fn mdns_round_trip() {
        let id: u16 = 0x0202;
        let q = mdns_query(id, Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(read_name(&q, 12).unwrap().0, "7.2.0.192.in-addr.arpa");

        // Reply: the question echoed, then a PTR answer whose owner name points back at it.
        let mut r = q.clone();
        r[2] = 0x84; // response, authoritative
        r[7] = 1; // one answer
        r.extend_from_slice(&[0xc0, 12, 0x00, 0x0c, 0x80, 0x01, 0, 0, 0, 120]);
        let target = b"\x0bliving-room\x05local\x00";
        r.extend_from_slice(&(target.len() as u16).to_be_bytes());
        r.extend_from_slice(target);
        assert_eq!(parse_mdns(&r, id).as_deref(), Some("living-room"));
        assert_eq!(parse_mdns(&q, id), None, "a query isn't a reply");
    }

    /// Asks this PC's real neighbors; prints only counts, never names.
    #[test]
    fn names_local_devices() {
        let lan = crate::ifaces::collect().lan;
        let v4: Vec<Ipv4Addr> = crate::devices::neighbors(&lan)
            .into_iter()
            .filter_map(|n| match n.ip {
                std::net::IpAddr::V4(a) => Some(a),
                _ => None,
            })
            .collect();
        let named = v4.iter().filter(|ip| lookup(**ip).is_some()).count();
        println!("{named} of {} devices announced a name", v4.len());
    }
}
