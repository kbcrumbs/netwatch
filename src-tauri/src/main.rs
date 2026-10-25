// Hide the console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
mod devices;
mod dns;
mod ifaces;
mod localnames;
mod intel;
mod monitor;
mod net;
mod procs;
mod rdns;
mod services;
mod sig;
mod store;
mod tray;
mod watch;

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::{Emitter, Manager, State};

use monitor::{Monitor, Snapshot};
use store::{DbInfo, HistoryResult, Rule, Store};

const POLL_INTERVAL: Duration = Duration::from_millis(1500);
const HISTORY_LIMIT: u32 = 1000;

type Latest = Arc<Mutex<Option<Snapshot>>>;

struct IntelRefresh(Mutex<Option<Sender<()>>>);

struct DeviceScan(Mutex<Option<Sender<()>>>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfo {
    admin: bool,
    hostname: String,
    poll_ms: u64,
}

#[tauri::command]
fn get_snapshot(latest: State<Latest>) -> Option<Snapshot> {
    latest.lock().unwrap().clone()
}

#[tauri::command]
fn system_info() -> SystemInfo {
    SystemInfo {
        admin: procs::is_elevated(),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
        poll_ms: POLL_INTERVAL.as_millis() as u64,
    }
}

/// Re-downloads all threat feeds and geo databases now.
#[tauri::command]
fn refresh_intel(refresh: State<IntelRefresh>) {
    if let Some(tx) = refresh.0.lock().unwrap().as_ref() {
        let _ = tx.send(());
    }
}

/// Sweeps the local network for devices now instead of at the next interval.
#[tauri::command]
fn scan_devices(scan: State<DeviceScan>) {
    if let Some(tx) = scan.0.lock().unwrap().as_ref() {
        let _ = tx.send(());
    }
}

/// Checks a local device's common ports in the background.
#[tauri::command]
fn scan_ports(ports: State<Arc<devices::PortScanner>>, mac: String, ip: String) -> Result<(), String> {
    let ip = ip.parse().map_err(|_| "invalid IP address".to_string())?;
    ports.request(mac, ip)
}

#[tauri::command]
fn get_autostart() -> bool {
    autostart::enabled()
}

/// Turns launch at login on or off; returns the resulting state.
#[tauri::command]
fn set_autostart(enabled: bool) -> Result<bool, String> {
    autostart::set(enabled)?;
    Ok(autostart::enabled())
}

/// Connections first seen within the last `hours`, newest first.
#[tauri::command]
fn history(store: State<Arc<Store>>, hours: u64, search: String) -> Result<HistoryResult, String> {
    let since = monitor::now_ms().saturating_sub(hours * 3600 * 1000);
    store.history(since, &search, HISTORY_LIMIT).map_err(|e| e.to_string())
}

#[tauri::command]
fn db_info(store: State<Arc<Store>>) -> Result<DbInfo, String> {
    store.info().map_err(|e| e.to_string())
}

#[tauri::command]
fn list_rules(store: State<Arc<Store>>) -> Result<Vec<Rule>, String> {
    store.list_rules().map_err(|e| e.to_string())
}

#[tauri::command]
fn set_rule(store: State<Arc<Store>>, rule: Rule) -> Result<(), String> {
    if !matches!(rule.kind.as_str(), "program" | "ip" | "device") || rule.target.trim().is_empty() {
        return Err("invalid rule".into());
    }
    store.set_rule(rule).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_rule(store: State<Arc<Store>>, kind: String, target: String) -> Result<(), String> {
    store.delete_rule(&kind, &target).map_err(|e| e.to_string())
}

/// Dismisses the given alerts, or all of them when `ids` is empty.
#[tauri::command]
fn ack_alerts(store: State<Arc<Store>>, ids: Vec<i64>) -> Result<(), String> {
    store.ack_alerts(&ids).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .on_window_event(|window, event| {
            // Closing the window keeps NetWatch watching from the tray.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                tray::hide_to_tray(window);
            }
        })
        .manage(Latest::default())
        .manage(IntelRefresh(Mutex::new(None)))
        .manage(DeviceScan(Mutex::new(None)))
        .setup(|app| {
            let handle = app.handle().clone();
            let latest = app.state::<Latest>().inner().clone();
            let data_dir = app.path().app_local_data_dir()?;
            let store = Arc::new(Store::open(&data_dir.join("netwatch.db"))?);
            app.manage(store.clone());
            watch::start(store.clone());
            let (intel, refresh_tx) = intel::Intel::start(data_dir.join("intel"));
            let vendors = devices::Vendors::start(data_dir.join("intel"));
            let (sweeper, scan_tx) = devices::Sweeper::start();
            let ports = devices::PortScanner::start();
            app.manage(ports.clone());
            *app.state::<DeviceScan>().0.lock().unwrap() = Some(scan_tx);
            *app.state::<IntelRefresh>().0.lock().unwrap() = Some(refresh_tx);
            tray::install(app)?;
            // Started at login: stay in the tray until opened.
            if std::env::args().any(|a| a == "--minimized") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            std::thread::Builder::new()
                .name("net-poller".into())
                .spawn(move || {
                    let mut monitor = Monitor::new(
                        intel,
                        store,
                        dns::DnsNames::start(),
                        vendors,
                        sweeper,
                        ports,
                        localnames::LocalNames::start(),
                    );
                    let mut notifier = tray::Notifier::default();
                    loop {
                        let snap = monitor.tick();
                        notifier.check(&handle, &snap.alerts);
                        let _ = handle.emit("snapshot", &snap);
                        *latest.lock().unwrap() = Some(snap);
                        std::thread::sleep(POLL_INTERVAL);
                    }
                })?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            system_info,
            refresh_intel,
            scan_devices,
            scan_ports,
            get_autostart,
            set_autostart,
            history,
            db_info,
            list_rules,
            set_rule,
            delete_rule,
            ack_alerts
        ])
        .build(tauri::generate_context!())
        .expect("error while building NetWatch")
        .run(|_, event| {
            if let tauri::RunEvent::Exit = event {
                dns::DnsNames::stop();
            }
        });
}
