//! Tray icon, close-to-tray, and desktop notifications for new alerts, so
//! NetWatch keeps watching (and telling you) with its window closed.

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{App, AppHandle, Manager, Runtime, Window};
use tauri_plugin_notification::NotificationExt;

use crate::store::Alert;

/// More new alerts than this in one poll become a single summary notification.
const MAX_SEPARATE: usize = 3;

static HINT_SHOWN: AtomicBool = AtomicBool::new(false);

pub fn install(app: &App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open NetWatch", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit NetWatch", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("NetWatch")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

pub fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Closing the window hides it; Quit in the tray menu exits.
pub fn hide_to_tray<R: Runtime>(window: &Window<R>) {
    let _ = window.hide();
    if !HINT_SHOWN.swap(true, Ordering::Relaxed) {
        notify(
            window.app_handle(),
            "NetWatch is still running",
            "It keeps watching from the system tray. Right-click the tray icon to quit.",
        );
    }
}

fn notify<R: Runtime>(app: &AppHandle<R>, title: &str, body: &str) {
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        eprintln!("notification failed: {e}");
    }
}

/// Notifies about medium and high alerts raised since the last check.
#[derive(Default)]
pub struct Notifier {
    /// Highest alert id already handled; None until the first snapshot, whose
    /// alerts are history rather than news.
    seen: Option<i64>,
}

impl Notifier {
    pub fn check<R: Runtime>(&mut self, app: &AppHandle<R>, alerts: &[Alert]) {
        let fresh = self.fresh(alerts);
        match fresh.as_slice() {
            [] => {}
            few if few.len() <= MAX_SEPARATE => {
                for a in few {
                    notify(app, &format!("NetWatch: {} alert", a.severity), &a.title);
                }
            }
            many => {
                let high = many.iter().filter(|a| a.severity == "high").count();
                notify(
                    app,
                    &format!("NetWatch: {} new alerts", many.len()),
                    &format!("{high} high, {} medium. Open NetWatch to review them.", many.len() - high),
                );
            }
        }
    }

    fn fresh<'a>(&mut self, alerts: &'a [Alert]) -> Vec<&'a Alert> {
        let newest = alerts.iter().map(|a| a.id).max().unwrap_or(0);
        let Some(seen) = self.seen.replace(newest.max(self.seen.unwrap_or(0))) else {
            return Vec::new();
        };
        let mut fresh: Vec<&Alert> = alerts
            .iter()
            .filter(|a| a.id > seen && !a.acked && matches!(a.severity.as_str(), "medium" | "high"))
            .collect();
        fresh.sort_by_key(|a| a.id);
        fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(id: i64, severity: &str) -> Alert {
        Alert {
            id,
            ts: 0,
            severity: severity.into(),
            title: format!("alert {id}"),
            detail: String::new(),
            process: String::new(),
            exe: String::new(),
            pid: 0,
            acked: false,
        }
    }

    #[test]
    fn only_new_medium_and_high_alerts_notify() {
        let mut n = Notifier::default();
        let old = vec![alert(1, "high"), alert(2, "medium")];
        assert!(n.fresh(&old).is_empty(), "alerts present at startup are history");

        let mut now = old.clone();
        now.extend([alert(3, "info"), alert(4, "medium"), alert(5, "high")]);
        let ids: Vec<i64> = n.fresh(&now).iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![4, 5], "info alerts stay quiet");
        assert!(n.fresh(&now).is_empty(), "each alert notifies once");
    }
}
