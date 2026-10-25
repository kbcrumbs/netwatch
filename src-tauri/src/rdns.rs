//! Background reverse-DNS lookups with a shared cache. Lookups block for up
//! to several seconds, so they run on a small worker pool, never the poll loop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};

const WORKERS: usize = 4;
const MAX_CACHE: usize = 50_000;

#[derive(Clone)]
enum Entry {
    Pending,
    Done(Option<String>),
}

pub struct Rdns {
    cache: Arc<Mutex<HashMap<IpAddr, Entry>>>,
    tx: Sender<IpAddr>,
}

impl Rdns {
    pub fn new() -> Self {
        let cache: Arc<Mutex<HashMap<IpAddr, Entry>>> = Arc::default();
        let (tx, rx) = mpsc::channel::<IpAddr>();
        let rx = Arc::new(Mutex::new(rx));
        for n in 0..WORKERS {
            let rx = rx.clone();
            let cache = cache.clone();
            std::thread::Builder::new()
                .name(format!("rdns-{n}"))
                .spawn(move || loop {
                    let Ok(ip) = rx.lock().unwrap().recv() else { return };
                    let host = dns_lookup::lookup_addr(&ip)
                        .ok()
                        .filter(|h| !h.is_empty() && h.parse::<IpAddr>().is_err());
                    cache.lock().unwrap().insert(ip, Entry::Done(host));
                })
                .expect("spawn rdns worker");
        }
        Self { cache, tx }
    }

    /// Cached host name, queueing a lookup the first time an IP is seen.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let mut cache = self.cache.lock().unwrap();
        match cache.get(&ip) {
            Some(Entry::Done(h)) => h.clone(),
            Some(Entry::Pending) => None,
            None => {
                if cache.len() >= MAX_CACHE {
                    cache.retain(|_, e| matches!(e, Entry::Pending));
                }
                cache.insert(ip, Entry::Pending);
                let _ = self.tx.send(ip);
                None
            }
        }
    }
}
