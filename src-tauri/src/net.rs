//! Reads the Windows TCP/UDP tables (IPv4 + IPv6) with owning PIDs.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

pub const TCP_LISTEN: u32 = 2;
pub const TCP_ESTABLISHED: u32 = 5;

#[derive(Clone, Debug)]
pub struct RawConn {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    /// MIB_TCP_STATE value; 0 for UDP.
    pub state: u32,
    pub pid: u32,
}

pub fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "Closed",
        2 => "Listening",
        3 => "SYN sent",
        4 => "SYN received",
        5 => "Established",
        6 => "FIN wait 1",
        7 => "FIN wait 2",
        8 => "Close wait",
        9 => "Closing",
        10 => "Last ACK",
        11 => "Time wait",
        12 => "Delete TCB",
        _ => "Unknown",
    }
}

/// Port fields in the MIB rows hold a network-order u16 in the low bytes.
fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

fn v4(raw: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
}

fn v6(raw: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(raw))
}

/// Calls a size-probing IP Helper function until the buffer is big enough.
/// Uses a u32 buffer so the table structs are correctly aligned.
fn fetch_table(call: impl Fn(Option<*mut c_void>, &mut u32) -> u32) -> Option<Vec<u32>> {
    let mut size: u32 = 0;
    let mut buf: Vec<u32> = Vec::new();
    for _ in 0..8 {
        let ptr = if buf.is_empty() {
            None
        } else {
            Some(buf.as_mut_ptr() as *mut c_void)
        };
        let rc = call(ptr, &mut size);
        if rc == NO_ERROR.0 && !buf.is_empty() {
            return Some(buf);
        }
        if rc == ERROR_INSUFFICIENT_BUFFER.0 || (rc == NO_ERROR.0 && buf.is_empty()) {
            // Leave headroom: the table can grow between the probe and the read.
            buf = vec![0u32; (size as usize / 4) + 1024];
            size = (buf.len() * 4) as u32;
            continue;
        }
        return None;
    }
    None
}

fn tcp_table(af: u32) -> Option<Vec<u32>> {
    fetch_table(|ptr, size| unsafe {
        GetExtendedTcpTable(ptr, size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
    })
}

fn udp_table(af: u32) -> Option<Vec<u32>> {
    fetch_table(|ptr, size| unsafe {
        GetExtendedUdpTable(ptr, size, false, af, UDP_TABLE_OWNER_PID, 0)
    })
}

pub fn collect() -> Vec<RawConn> {
    let mut out = Vec::with_capacity(512);

    if let Some(buf) = tcp_table(AF_INET.0 as u32) {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let rows = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        for r in rows {
            let listening = r.dwState == TCP_LISTEN;
            out.push(RawConn {
                proto: Proto::Tcp,
                local: SocketAddr::new(v4(r.dwLocalAddr), port(r.dwLocalPort)),
                remote: (!listening)
                    .then(|| SocketAddr::new(v4(r.dwRemoteAddr), port(r.dwRemotePort))),
                state: r.dwState,
                pid: r.dwOwningPid,
            });
        }
    }

    if let Some(buf) = tcp_table(AF_INET6.0 as u32) {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let rows = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        for r in rows {
            let listening = r.dwState == TCP_LISTEN;
            out.push(RawConn {
                proto: Proto::Tcp,
                local: SocketAddr::new(v6(r.ucLocalAddr), port(r.dwLocalPort)),
                remote: (!listening)
                    .then(|| SocketAddr::new(v6(r.ucRemoteAddr), port(r.dwRemotePort))),
                state: r.dwState,
                pid: r.dwOwningPid,
            });
        }
    }

    if let Some(buf) = udp_table(AF_INET.0 as u32) {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let rows = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        for r in rows {
            out.push(RawConn {
                proto: Proto::Udp,
                local: SocketAddr::new(v4(r.dwLocalAddr), port(r.dwLocalPort)),
                remote: None,
                state: 0,
                pid: r.dwOwningPid,
            });
        }
    }

    if let Some(buf) = udp_table(AF_INET6.0 as u32) {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let rows = unsafe {
            std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
        };
        for r in rows {
            out.push(RawConn {
                proto: Proto::Udp,
                local: SocketAddr::new(v6(r.ucLocalAddr), port(r.dwLocalPort)),
                remote: None,
                state: 0,
                pid: r.dwOwningPid,
            });
        }
    }

    out
}

/// "public", "private", "loopback" or "none" (unspecified).
pub fn scope(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(a) => scope_v4(a),
        IpAddr::V6(a) => {
            if let Some(m) = a.to_ipv4_mapped() {
                return scope_v4(m);
            }
            let seg0 = a.segments()[0];
            if a.is_loopback() {
                "loopback"
            } else if a.is_unspecified() {
                "none"
            } else if (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80 {
                "private"
            } else {
                "public"
            }
        }
    }
}

fn scope_v4(a: Ipv4Addr) -> &'static str {
    let o = a.octets();
    if a.is_loopback() {
        "loopback"
    } else if a.is_unspecified() {
        "none"
    } else if a.is_private()
        || a.is_link_local()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64/10
        || a.is_multicast()
        || a.is_broadcast()
    {
        "private"
    } else {
        "public"
    }
}
