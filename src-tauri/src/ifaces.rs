//! Network adapters and their addresses, used to tell which interface a
//! connection leaves through and whether a VPN tunnel is up.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IF_TYPE_PROP_VIRTUAL, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

#[derive(Clone, Debug)]
pub struct Adapter {
    pub name: String,
    pub vpn: bool,
}

/// An IPv4 subnet this PC is on, outside any VPN tunnel.
#[derive(Clone, Debug)]
pub struct LanNet {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Default)]
pub struct Interfaces {
    /// Local address -> the adapter that owns it.
    by_addr: HashMap<IpAddr, Adapter>,
    /// Name of the first VPN adapter that is up, if any.
    pub vpn: Option<String>,
    /// Interface indexes of non-VPN adapters with an address: the local network.
    pub lan: HashSet<u32>,
    /// IPv4 subnets of those adapters (link-local addresses excluded).
    pub lan_v4: Vec<LanNet>,
}

impl Interfaces {
    pub fn adapter(&self, local: IpAddr) -> Option<&Adapter> {
        let ip = match local {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(local),
            v4 => v4,
        };
        self.by_addr.get(&ip)
    }
}

/// WireGuard/Wintun/OpenVPN-style tunnels: virtual or tunnel interface types,
/// or a name that says so. WAN Miniports are system plumbing, not VPNs.
fn looks_like_vpn(if_type: u32, name: &str, desc: &str) -> bool {
    let text = format!("{name} {desc}").to_lowercase();
    if text.contains("miniport") {
        return false;
    }
    if_type == IF_TYPE_PROP_VIRTUAL
        || if_type == IF_TYPE_TUNNEL
        || ["vpn", "wireguard", "wintun", "tap-windows", "openvpn"].iter().any(|k| text.contains(k))
}

pub fn collect() -> Interfaces {
    let mut out = Interfaces::default();
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // u64 buffer keeps the adapter structs aligned.
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut ok = false;
    for _ in 0..4 {
        buf = vec![0u64; size as usize / 8 + 1];
        size = (buf.len() * 8) as u32;
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if rc == NO_ERROR.0 {
            ok = true;
            break;
        }
        if rc != ERROR_BUFFER_OVERFLOW.0 {
            break;
        }
    }
    if !ok {
        return out;
    }

    unsafe {
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            cur = a.Next;
            if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            let name = a.FriendlyName.to_string().unwrap_or_default();
            let desc = a.Description.to_string().unwrap_or_default();
            let adapter = Adapter { vpn: looks_like_vpn(a.IfType, &name, &desc), name };

            let mut has_addr = false;
            let mut ua = a.FirstUnicastAddress;
            while !ua.is_null() {
                let u = &*ua;
                ua = u.Next;
                let sa = u.Address.lpSockaddr;
                if sa.is_null() {
                    continue;
                }
                let ip = match (*sa).sa_family {
                    AF_INET => {
                        let sin = &*(sa as *const SOCKADDR_IN);
                        IpAddr::V4(Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes()))
                    }
                    AF_INET6 => {
                        let sin6 = &*(sa as *const SOCKADDR_IN6);
                        IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.u.Byte))
                    }
                    _ => continue,
                };
                has_addr = true;
                out.by_addr.insert(ip, adapter.clone());
                if let IpAddr::V4(v4) = ip {
                    if !adapter.vpn && !v4.is_link_local() {
                        out.lan_v4.push(LanNet { ip: v4, prefix: u.OnLinkPrefixLength });
                    }
                }
            }
            if adapter.vpn && has_addr && out.vpn.is_none() {
                out.vpn = Some(adapter.name.clone());
            }
            if !adapter.vpn && has_addr {
                out.lan.insert(a.Anonymous1.Anonymous.IfIndex);
                out.lan.insert(a.Ipv6IfIndex);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_adapters() {
        let i = super::collect();
        for (ip, a) in &i.by_addr {
            println!("{ip:<40} {:<30} vpn={}", a.name, a.vpn);
        }
        println!("vpn up: {:?}", i.vpn);
        assert!(!i.by_addr.is_empty(), "at least one adapter with an address is up");
    }
}
