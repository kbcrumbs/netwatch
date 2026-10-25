//! Hostnames from Windows' own DNS lookups. Listens to the DNS-Client ETW
//! provider and remembers which queried name each answered address came from.
//! Unlike reverse DNS, this works for clouds and CDNs that publish no PTR
//! records. Needs admin; without it NetWatch falls back to reverse DNS.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, UserTrace};
use ferrisetw::EventRecord;

use crate::monitor::now_ms;

const TRACE_NAME: &str = "NetWatch-DNS";
/// Microsoft-Windows-DNS-Client
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
/// "DNS query is completed": carries the name, status and answers.
const QUERY_COMPLETED: u16 = 3008;
const MAX_ENTRIES: usize = 50_000;
const HOUR_MS: u64 = 3600 * 1000;

#[derive(Default)]
pub struct DnsNames {
    /// Answered address -> (queried name, when it was last answered).
    names: Mutex<HashMap<IpAddr, (String, u64)>>,
    active: AtomicBool,
}

impl DnsNames {
    pub fn start() -> Arc<Self> {
        Self::start_named(TRACE_NAME)
    }

    fn start_named(trace_name: &str) -> Arc<Self> {
        let me = Arc::new(Self::default());
        let sink = me.clone();
        // A killed earlier run leaves its session behind, which would block ours.
        let _ = stop_trace_by_name(trace_name);
        let provider = Provider::by_guid(DNS_CLIENT)
            .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                if record.event_id() != QUERY_COMPLETED {
                    return;
                }
                let Ok(schema) = locator.event_schema(record) else { return };
                let parser = Parser::create(record, &schema);
                if parser.try_parse::<u32>("QueryStatus").unwrap_or(1) != 0 {
                    return;
                }
                if let (Ok(name), Ok(results)) =
                    (parser.try_parse::<String>("QueryName"), parser.try_parse::<String>("QueryResults"))
                {
                    sink.record(&name, &results);
                }
            })
            .build();
        match UserTrace::new().named(trace_name.into()).enable(provider).start_and_process() {
            Ok(trace) => {
                me.active.store(true, Ordering::Relaxed);
                // The session runs for the life of the app; the next start
                // clears it if we exit without stopping it.
                std::mem::forget(trace);
            }
            Err(e) => eprintln!("DNS name capture unavailable: {e:?}"),
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

    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.names.lock().unwrap().get(&normalize(ip)).map(|(n, _)| n.clone())
    }

    /// `results` looks like "type: 5 edge.example.net;::ffff:1.2.3.4;2606:4700::1;":
    /// CNAME hops are tagged with their type, addresses are bare.
    fn record(&self, name: &str, results: &str) {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return;
        }
        let now = now_ms();
        let mut names = self.names.lock().unwrap();
        for part in results.split(';').map(str::trim) {
            if let Ok(ip) = part.parse::<IpAddr>() {
                names.insert(normalize(ip), (name.clone(), now));
            }
        }
        if names.len() > MAX_ENTRIES {
            names.retain(|_, (_, at)| now.saturating_sub(*at) < HOUR_MS);
        }
    }
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_results() {
        let d = DnsNames::default();
        d.record("Download.WindowsUpdate.com.", "type: 5 wu.ec.azureedge.net;::ffff:93.184.221.240;2606:2800:233::1;");
        assert_eq!(d.lookup("93.184.221.240".parse().unwrap()).as_deref(), Some("download.windowsupdate.com"));
        assert_eq!(d.lookup("::ffff:93.184.221.240".parse().unwrap()).as_deref(), Some("download.windowsupdate.com"));
        assert_eq!(d.lookup("2606:2800:233::1".parse().unwrap()).as_deref(), Some("download.windowsupdate.com"));
        assert_eq!(d.lookup("1.1.1.1".parse().unwrap()), None);
    }

    /// Needs an elevated shell; skipped otherwise.
    #[test]
    fn captures_live_lookups() {
        if !crate::procs::is_elevated() {
            println!("skipped: not elevated");
            return;
        }
        // Own session name, so a running NetWatch keeps its session.
        let d = DnsNames::start_named("NetWatch-DNS-test");
        assert!(d.active(), "ETW session started");
        std::thread::sleep(std::time::Duration::from_secs(2));
        let ips: Vec<IpAddr> = dns_lookup::lookup_host("example.com").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(3));
        for ip in &ips {
            println!("{ip} -> {:?}", d.lookup(*ip));
        }
        let _ = stop_trace_by_name("NetWatch-DNS-test");
        assert!(ips.iter().any(|ip| d.lookup(*ip).as_deref() == Some("example.com")));
    }
}
