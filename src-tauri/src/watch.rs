//! Watches Windows settings that malware and updates like to change: services,
//! startup entries, scheduled tasks and a few privacy switches. The first run
//! records a baseline; after that, changes raise alerts.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use winreg::{RegKey, HKCU, HKLM};

use crate::monitor::now_ms;
use crate::store::{Alert, Store};

const CHECK_EVERY: Duration = Duration::from_secs(60);

const SERVICE_WIN32: u32 = 0x30;
/// Per-logon copies of per-user services (e.g. `Foo_1a2b3c`); new ones appear every sign-in.
const SERVICE_USER_INSTANCE: u32 = 0x80;

/// Item kind, from the key prefix.
fn kind(key: &str) -> &str {
    key.split_once(':').map_or("", |(k, _)| k)
}

/* ---------- Reading the current state ---------- */

fn reg_string(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name).ok()
}

fn services(out: &mut HashMap<String, String>, names: &mut HashMap<String, String>) {
    let Ok(root) = HKLM.open_subkey(r"SYSTEM\CurrentControlSet\Services") else { return };
    for name in root.enum_keys().flatten() {
        let Ok(svc) = root.open_subkey(&name) else { continue };
        let ty: u32 = svc.get_value("Type").unwrap_or(0);
        let Ok(start) = svc.get_value::<u32, _>("Start") else { continue };
        if ty & SERVICE_WIN32 == 0 || ty & SERVICE_USER_INSTANCE != 0 {
            continue;
        }
        let key = format!("svc:{name}");
        let display = reg_string(&svc, "DisplayName").filter(|d| !d.starts_with('@')).unwrap_or_else(|| name.clone());
        let image = reg_string(&svc, "ImagePath").unwrap_or_default();
        names.insert(key.clone(), format!("{display}\n{image}"));
        out.insert(key, start.to_string());
    }
}

fn run_keys(out: &mut HashMap<String, String>) {
    let keys: [(&RegKey, &str, &str); 5] = [
        (&HKLM, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (&HKLM, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (&HKLM, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (&HKCU, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (&HKCU, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ];
    for (hive, hive_name, path) in keys {
        let Ok(k) = hive.open_subkey(path) else { continue };
        for (name, value) in k.enum_values().flatten() {
            out.insert(format!(r"run:{hive_name}\{path}\{name}"), value.to_string());
        }
    }
}

fn list_files(dir: &Path, prefix: &str, out: &mut HashMap<String, String>, skip_top: Option<&str>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = e.path();
        if path.is_dir() {
            if skip_top.is_some_and(|s| s.eq_ignore_ascii_case(&name)) {
                continue;
            }
            list_files(&path, &format!(r"{prefix}{name}\"), out, None);
        } else if !name.eq_ignore_ascii_case("desktop.ini") {
            out.insert(format!("{prefix}{name}"), String::new());
        }
    }
}

fn startup_and_tasks(out: &mut HashMap<String, String>) {
    let env = |v: &str| std::env::var(v).unwrap_or_default();
    let mut files = HashMap::new();
    for dir in [
        format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", env("APPDATA")),
        format!(r"{}\Microsoft\Windows\Start Menu\Programs\StartUp", env("ProgramData")),
    ] {
        list_files(Path::new(&dir), &format!(r"startup:{dir}\"), &mut files, None);
    }
    // Windows' own tasks live under \Microsoft and churn with updates.
    list_files(Path::new(&format!(r"{}\System32\Tasks", env("SystemRoot"))), r"task:\", &mut files, Some("Microsoft"));
    out.extend(files);
}

fn netbios_label(opt: Option<u32>) -> String {
    match opt {
        None | Some(0) => "default (on unless the network turns it off)".into(),
        Some(1) => "enabled".into(),
        Some(2) => "disabled".into(),
        Some(n) => n.to_string(),
    }
}

fn privacy_settings(out: &mut HashMap<String, String>) {
    let dword = |hive: &RegKey, path: &str, name: &str| hive.open_subkey(path).ok()?.get_value::<u32, _>(name).ok();
    let set_or_not = |v: Option<u32>| v.map_or("not set".to_string(), |n| n.to_string());

    let mdns = dword(&HKLM, r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableMDNS");
    out.insert("setting:Windows mDNS (EnableMDNS)".into(), set_or_not(mdns));
    let llmnr = dword(&HKLM, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast");
    out.insert("setting:LLMNR policy (EnableMulticast)".into(), set_or_not(llmnr));
    let cast = dword(&HKLM, r"SOFTWARE\Policies\Google\Chrome", "EnableMediaRouter");
    out.insert("setting:Chrome casting policy (EnableMediaRouter)".into(), set_or_not(cast));

    // NetBIOS per adapter, named by the adapter's connection name.
    let Ok(ifs) = HKLM.open_subkey(r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces") else { return };
    let net = HKLM.open_subkey(r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}").ok();
    for sub in ifs.enum_keys().flatten() {
        let Some(guid) = sub.strip_prefix("Tcpip_") else { continue };
        let name = net
            .as_ref()
            .and_then(|n| n.open_subkey(format!(r"{guid}\Connection")).ok())
            .and_then(|c| reg_string(&c, "Name"));
        // Interfaces without a connection name are leftovers of removed adapters.
        let Some(name) = name else { continue };
        let opt = ifs.open_subkey(&sub).ok().and_then(|k| k.get_value::<u32, _>("NetbiosOptions").ok());
        out.insert(format!("setting:NetBIOS on {name}"), netbios_label(opt));
    }
}

/// Everything watched, as key -> value, plus descriptions for services.
pub fn collect() -> (HashMap<String, String>, HashMap<String, String>) {
    let mut out = HashMap::new();
    let mut names = HashMap::new();
    services(&mut out, &mut names);
    run_keys(&mut out);
    startup_and_tasks(&mut out);
    privacy_settings(&mut out);
    (out, names)
}

/* ---------- Comparing against the baseline ---------- */

pub struct Change {
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
}

fn start_type(v: &str) -> &str {
    match v {
        "0" | "1" => "boot",
        "2" => "automatic",
        "3" => "manual",
        "4" => "disabled",
        other => other,
    }
}

/// Task names with version numbers and GUIDs stripped, so an updater that
/// replaces its own task ("FooUpdate1.2.3") reads as an update, not a newcomer.
fn task_family(key: &str) -> String {
    key.chars().filter(|c| !c.is_ascii_digit() && !"{}-._".contains(*c)).collect::<String>().to_lowercase()
}

/// What changed between the baseline and now. Removals aren't alerts.
pub fn diff(old: &HashMap<String, String>, new: &HashMap<String, String>, names: &HashMap<String, String>) -> Vec<Change> {
    let removed_tasks: Vec<String> =
        old.keys().filter(|k| kind(k) == "task" && !new.contains_key(*k)).map(|k| task_family(k)).collect();
    let mut changes = Vec::new();
    let mut keys: Vec<&String> = new.keys().collect();
    keys.sort();
    for key in keys {
        let value = &new[key];
        let before = old.get(key);
        if before == Some(value) {
            continue;
        }
        let item = key.split_once(':').map_or(key.as_str(), |(_, rest)| rest);
        let (label, extra) = names
            .get(key)
            .and_then(|n| n.split_once('\n'))
            .map_or((item.to_string(), String::new()), |(d, i)| (d.to_string(), i.to_string()));
        let change = match (kind(key), before) {
            ("svc", None) => Change {
                severity: "medium",
                title: format!("New service installed: {label}"),
                detail: format!("Starts: {}\n{extra}", start_type(value)),
            },
            // Only disabled -> enabled matters; Windows shuffles auto/manual itself.
            ("svc", Some(b)) if b == "4" => Change {
                severity: "medium",
                title: format!("Disabled service turned back on: {label}"),
                detail: format!("Start type: disabled → {}\n{extra}", start_type(value)),
            },
            ("svc", Some(_)) => continue,
            ("run", None) => Change {
                severity: "medium",
                title: format!("New startup program: {}", item.rsplit('\\').next().unwrap_or(item)),
                detail: format!("{value}\n{item}"),
            },
            ("run", Some(b)) => Change {
                severity: "medium",
                title: format!("Startup program changed: {}", item.rsplit('\\').next().unwrap_or(item)),
                detail: format!("{b} → {value}\n{item}"),
            },
            ("startup", _) => Change {
                severity: "medium",
                title: format!("New file in a Startup folder: {}", item.rsplit('\\').next().unwrap_or(item)),
                detail: item.to_string(),
            },
            ("task", _) if removed_tasks.contains(&task_family(key)) => Change {
                severity: "info",
                title: format!("Scheduled task updated: {item}"),
                detail: "An existing task was replaced by a newer version of itself.".into(),
            },
            ("task", _) => Change {
                severity: "medium",
                title: format!("New scheduled task: {item}"),
                detail: "Programs can use scheduled tasks to run at startup or on a timer.".into(),
            },
            ("setting", Some(b)) => Change {
                severity: "medium",
                title: format!("Setting changed: {item}"),
                detail: format!("{b} → {value}"),
            },
            _ => continue,
        };
        changes.push(change);
    }
    changes
}

/* ---------- Background watcher ---------- */

pub fn start(store: Arc<Store>) {
    std::thread::Builder::new()
        .name("settings-watch".into())
        .spawn(move || run(store))
        .expect("spawn settings watcher");
}

fn run(store: Arc<Store>) {
    let mut baseline = store.watch_baseline().unwrap_or_default();
    loop {
        let (now, names) = collect();
        if baseline.is_empty() {
            let _ = store.save_watch(&now, &[]);
        } else {
            for c in diff(&baseline, &now, &names) {
                let ts = now_ms();
                let alert = Alert {
                    id: 0,
                    ts,
                    severity: c.severity.to_string(),
                    title: c.title,
                    detail: c.detail,
                    process: "Windows settings".into(),
                    exe: String::new(),
                    pid: 0,
                    acked: false,
                };
                let _ = store.add_alert(&format!("watch|{ts}|{}", alert.title), &alert);
            }
            let changed: HashMap<String, String> =
                now.iter().filter(|(k, v)| baseline.get(*k) != Some(*v)).map(|(k, v)| (k.clone(), v.clone())).collect();
            let removed: Vec<String> = baseline.keys().filter(|k| !now.contains_key(*k)).cloned().collect();
            if !changed.is_empty() || !removed.is_empty() {
                let _ = store.save_watch(&changed, &removed);
            }
        }
        baseline = now;
        std::thread::sleep(CHECK_EVERY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn classifies_changes() {
        let old = map(&[
            ("svc:ExampleSvc", "4"),
            ("svc:OtherSvc", "2"),
            (r"task:\ExampleUpdaterTask1.2.3", ""),
            ("setting:NetBIOS on Ethernet", "disabled"),
            (r"run:HKCU\Run\Old", "old.exe"),
        ]);
        let new = map(&[
            ("svc:ExampleSvc", "2"),
            ("svc:OtherSvc", "3"),
            ("svc:BrandNew", "2"),
            (r"task:\ExampleUpdaterTask1.2.4", ""),
            (r"task:\Totally New", ""),
            ("setting:NetBIOS on Ethernet", "enabled"),
        ]);
        let names = map(&[("svc:BrandNew", "Brand New Service\nC:\\Example\\svc.exe")]);
        let titles: Vec<(String, &str)> = diff(&old, &new, &names).into_iter().map(|c| (c.title, c.severity)).collect();
        assert!(titles.contains(&("Disabled service turned back on: ExampleSvc".into(), "medium")));
        assert!(titles.contains(&("New service installed: Brand New Service".into(), "medium")));
        assert!(titles.contains(&(r"Scheduled task updated: \ExampleUpdaterTask1.2.4".into(), "info")));
        assert!(titles.contains(&(r"New scheduled task: \Totally New".into(), "medium")));
        assert!(titles.contains(&("Setting changed: NetBIOS on Ethernet".into(), "medium")));
        assert!(!titles.iter().any(|(t, _)| t.contains("OtherSvc")), "auto -> manual is noise");
        assert!(!titles.iter().any(|(t, _)| t.contains("Old")), "removals don't alert");
        assert_eq!(titles.len(), 5);
    }

    /// Reads this PC's real settings; prints only counts.
    #[test]
    fn collects_this_pc() {
        let (now, _) = collect();
        let count = |k: &str| now.keys().filter(|key| kind(key) == k).count();
        println!(
            "services {}, run entries {}, startup files {}, tasks {}, settings {}",
            count("svc"),
            count("run"),
            count("startup"),
            count("task"),
            count("setting")
        );
        assert!(count("svc") > 50);
        assert!(count("setting") >= 3);
    }
}
