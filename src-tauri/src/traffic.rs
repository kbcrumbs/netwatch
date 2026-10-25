//! Bytes sent and received per process, from the Kernel-Network ETW provider
//! (one event per send/receive with the PID and size). Traffic that never
//! leaves the PC (loopback) isn't counted. Needs admin.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, UserTrace};
use ferrisetw::EventRecord;

const TRACE_NAME: &str = "NetWatch-Traffic";
/// Microsoft-Windows-Kernel-Network
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

/// TCP and UDP, IPv4 and IPv6 data events.
fn direction(event_id: u16) -> Option<bool> {
    match event_id {
        10 | 26 | 42 | 58 => Some(true),  // sent
        11 | 27 | 43 | 59 => Some(false), // received
        _ => None,
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bytes {
    pub sent: u64,
    pub recv: u64,
}

#[derive(Default)]
pub struct Traffic {
    /// pid -> bytes since NetWatch started.
    totals: Mutex<HashMap<u32, Bytes>>,
    active: AtomicBool,
}

impl Traffic {
    pub fn start() -> Arc<Self> {
        Self::start_named(TRACE_NAME)
    }

    fn start_named(trace_name: &str) -> Arc<Self> {
        let me = Arc::new(Self::default());
        let sink = me.clone();
        // A killed earlier run leaves its session behind, which would block ours.
        let _ = stop_trace_by_name(trace_name);
        let provider = Provider::by_guid(KERNEL_NETWORK)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                let Some(sent) = direction(record.event_id()) else { return };
                let Ok(schema) = locator.event_schema(record) else { return };
                let parser = Parser::create(record, &schema);
                let (Ok(pid), Ok(size)) = (parser.try_parse::<u32>("PID"), parser.try_parse::<u32>("size")) else {
                    return;
                };
                if parser.try_parse::<IpAddr>("daddr").is_ok_and(|a| a.is_loopback()) {
                    return;
                }
                sink.add(pid, sent, size as u64);
            })
            .build();
        match UserTrace::new().named(trace_name.into()).enable(provider).start_and_process() {
            Ok(trace) => {
                me.active.store(true, Ordering::Relaxed);
                // Runs for the life of the app; stopped on exit or by the next start.
                std::mem::forget(trace);
            }
            Err(e) => eprintln!("traffic accounting unavailable: {e:?}"),
        }
        me
    }

    /// Ends the app's ETW session; call on exit.
    pub fn stop() {
        let _ = stop_trace_by_name(TRACE_NAME);
    }

    pub fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    fn add(&self, pid: u32, sent: bool, size: u64) {
        let mut totals = self.totals.lock().unwrap();
        let b = totals.entry(pid).or_default();
        if sent {
            b.sent += size;
        } else {
            b.recv += size;
        }
    }

    pub fn totals(&self) -> HashMap<u32, Bytes> {
        self.totals.lock().unwrap().clone()
    }

    /// Drops counters for processes that have exited.
    pub fn retain(&self, alive: impl Fn(u32) -> bool) {
        self.totals.lock().unwrap().retain(|pid, _| alive(*pid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_by_direction() {
        let t = Traffic::default();
        assert_eq!(direction(10), Some(true));
        assert_eq!(direction(59), Some(false));
        assert_eq!(direction(12), None, "connect events aren't data");
        t.add(7, true, 100);
        t.add(7, false, 1_000);
        t.add(7, false, 24);
        assert_eq!(t.totals()[&7], Bytes { sent: 100, recv: 1_024 });
        t.retain(|pid| pid != 7);
        assert!(t.totals().is_empty());
    }

    /// Needs an elevated shell; skipped otherwise. Prints only byte counts.
    #[test]
    fn counts_live_traffic() {
        if !crate::procs::is_elevated() {
            println!("skipped: not elevated");
            return;
        }
        let t = Traffic::start_named("NetWatch-Traffic-test");
        assert!(t.active());
        std::thread::sleep(std::time::Duration::from_secs(2));
        // Some real traffic of our own: a DNS lookup and a short HTTPS connection.
        let _ = dns_lookup::lookup_host("example.com");
        let _ = std::net::TcpStream::connect(("example.com", 443));
        std::thread::sleep(std::time::Duration::from_secs(3));
        let all = t.totals();
        let total: u64 = all.values().map(|b| b.sent + b.recv).sum();
        println!("{} processes moved {total} bytes", all.len());
        let _ = stop_trace_by_name("NetWatch-Traffic-test");
        assert!(total > 0, "some traffic was seen");
    }
}
