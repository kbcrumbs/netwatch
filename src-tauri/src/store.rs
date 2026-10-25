//! Local SQLite store: connection history, the "seen before" baseline,
//! persisted alerts, and the user's trust/label rules.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::monitor::now_ms;

const DAY_MS: u64 = 24 * 3600 * 1000;
pub const HISTORY_DAYS: u64 = 30;
const ALERT_DAYS: u64 = 90;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS programs (
    exe TEXT PRIMARY KEY, name TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS listeners (
    exe TEXT NOT NULL, port INTEGER NOT NULL, first_seen INTEGER NOT NULL,
    PRIMARY KEY (exe, port)
);
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY, exe TEXT NOT NULL, process TEXT NOT NULL, pid INTEGER NOT NULL,
    proto TEXT NOT NULL, local_port INTEGER NOT NULL, remote_ip TEXT NOT NULL, remote_port INTEGER NOT NULL,
    direction TEXT NOT NULL, host TEXT, country TEXT, org TEXT,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, open INTEGER NOT NULL, risk TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS connections_first_seen ON connections (first_seen);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, key TEXT NOT NULL, ts INTEGER NOT NULL, severity TEXT NOT NULL,
    title TEXT NOT NULL, detail TEXT NOT NULL, process TEXT NOT NULL, exe TEXT NOT NULL,
    pid INTEGER NOT NULL, acked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE TABLE IF NOT EXISTS rules (
    kind TEXT NOT NULL, target TEXT NOT NULL, label TEXT, trusted INTEGER NOT NULL, created INTEGER NOT NULL,
    PRIMARY KEY (kind, target)
);
";

/* ---------- Rules ---------- */

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    /// "program" (target = exe path) or "ip" (target = address).
    pub kind: String,
    pub target: String,
    pub label: Option<String>,
    pub trusted: bool,
    #[serde(default)]
    pub created: u64,
}

#[derive(Default, Clone)]
pub struct Rules {
    programs: HashMap<String, Rule>,
    ips: HashMap<String, Rule>,
}

impl Rules {
    fn key(kind: &str, target: &str) -> String {
        // Windows paths are case-insensitive.
        if kind == "program" { target.to_lowercase() } else { target.to_string() }
    }

    fn insert(&mut self, r: Rule) {
        let key = Self::key(&r.kind, &r.target);
        match r.kind.as_str() {
            "program" => self.programs.insert(key, r),
            _ => self.ips.insert(key, r),
        };
    }

    fn remove(&mut self, kind: &str, target: &str) {
        let key = Self::key(kind, target);
        match kind {
            "program" => self.programs.remove(&key),
            _ => self.ips.remove(&key),
        };
    }

    pub fn program(&self, exe: &str) -> Option<&Rule> {
        self.programs.get(&exe.to_lowercase())
    }

    pub fn ip(&self, ip: &str) -> Option<&Rule> {
        self.ips.get(ip)
    }
}

/* ---------- Records ---------- */

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: i64,
    pub ts: u64,
    /// "high", "medium" or "info".
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub process: String,
    pub exe: String,
    pub pid: u32,
    pub acked: bool,
}

pub struct NewConn {
    pub exe: String,
    pub process: String,
    pub pid: u32,
    pub proto: &'static str,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub direction: &'static str,
    pub host: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
    pub first_seen: u64,
    pub risk: &'static str,
}

/// A connection that ended. Enrichment that arrived after it opened (rDNS,
/// geo) fills in fields that were empty at insert time.
pub struct Closed {
    pub id: i64,
    pub host: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
    /// Worst risk seen while it was open.
    pub risk: &'static str,
}

/// Everything one poll needs to persist, written in a single transaction.
#[derive(Default)]
pub struct TickWrites {
    pub opened: Vec<(String, NewConn)>,
    pub closed: Vec<Closed>,
    pub touch: Vec<i64>,
    /// Hostnames that became known after a connection was recorded.
    pub named: Vec<(i64, String)>,
    pub new_programs: Vec<(String, String)>,
    pub seen_programs: Vec<String>,
    pub new_listeners: Vec<(String, u16)>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistRow {
    pub id: i64,
    pub exe: String,
    pub process: String,
    pub proto: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub direction: String,
    pub host: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub open: bool,
    pub risk: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownProgram {
    pub exe: String,
    pub name: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryResult {
    pub rows: Vec<HistRow>,
    pub total: u64,
    pub new_programs: Vec<KnownProgram>,
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DbInfo {
    pub programs: u64,
    pub connections: u64,
    pub oldest: Option<u64>,
    pub bytes: u64,
    pub retention_days: u64,
}

/* ---------- Store ---------- */

pub struct Store {
    conn: Mutex<Connection>,
    pub rules: RwLock<Rules>,
    path: PathBuf,
}

type Res<T> = rusqlite::Result<T>;

impl Store {
    pub fn open(path: &Path) -> Res<Store> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        // Rows left open by a previous run ended when that run did.
        conn.execute("UPDATE connections SET open = 0 WHERE open = 1", [])?;
        let store = Store { conn: Mutex::new(conn), rules: RwLock::default(), path: path.to_path_buf() };
        store.prune()?;
        let mut rules = Rules::default();
        for r in store.list_rules()? {
            rules.insert(r);
        }
        *store.rules.write().unwrap() = rules;
        Ok(store)
    }

    pub fn prune(&self) -> Res<()> {
        let now = now_ms();
        let c = self.conn.lock().unwrap();
        c.execute("DELETE FROM connections WHERE last_seen < ?1", [now.saturating_sub(HISTORY_DAYS * DAY_MS)])?;
        c.execute("DELETE FROM alerts WHERE ts < ?1", [now.saturating_sub(ALERT_DAYS * DAY_MS)])?;
        Ok(())
    }

    /// When the first-ever baseline was captured; set on first call.
    pub fn baseline_at(&self) -> Res<u64> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('baseline_at', ?1)",
            [now_ms().to_string()],
        )?;
        let v: String = c.query_row("SELECT value FROM meta WHERE key = 'baseline_at'", [], |r| r.get(0))?;
        Ok(v.parse().unwrap_or(0))
    }

    pub fn known_programs(&self) -> Res<HashMap<String, u64>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT exe, first_seen FROM programs")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?)))?;
        rows.collect()
    }

    pub fn known_listeners(&self) -> Res<HashSet<(String, u16)>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT exe, port FROM listeners")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u16>(1)?)))?;
        rows.collect()
    }

    /// Alert keys raised recently, so restarting doesn't repeat them.
    pub fn alert_keys(&self) -> Res<HashSet<String>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT DISTINCT key FROM alerts")?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    /// Persists one poll's changes; returns the row ids of newly opened connections.
    pub fn write_tick(&self, w: TickWrites) -> Res<Vec<(String, i64)>> {
        let now = now_ms();
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let mut ids = Vec::with_capacity(w.opened.len());
        {
            let mut ins = tx.prepare_cached(
                "INSERT INTO connections (exe, process, pid, proto, local_port, remote_ip, remote_port, direction,
                 host, country, org, first_seen, last_seen, open, risk)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, 1, ?13)",
            )?;
            for (key, n) in &w.opened {
                ins.execute(params![
                    n.exe, n.process, n.pid, n.proto, n.local_port, n.remote_ip, n.remote_port, n.direction,
                    n.host, n.country, n.org, n.first_seen, n.risk
                ])?;
                ids.push((key.clone(), tx.last_insert_rowid()));
            }
            let mut close = tx.prepare_cached(
                "UPDATE connections SET open = 0, last_seen = ?1, host = COALESCE(host, ?2),
                 country = COALESCE(country, ?3), org = COALESCE(org, ?4),
                 risk = CASE WHEN risk = 'none' THEN ?5 ELSE risk END WHERE id = ?6",
            )?;
            for c in &w.closed {
                close.execute(params![now, c.host, c.country, c.org, c.risk, c.id])?;
            }
            let mut name = tx.prepare_cached("UPDATE connections SET host = COALESCE(host, ?1) WHERE id = ?2")?;
            for (id, host) in &w.named {
                name.execute(params![host, id])?;
            }
            let mut touch = tx.prepare_cached("UPDATE connections SET last_seen = ?1 WHERE id = ?2")?;
            for id in &w.touch {
                touch.execute(params![now, id])?;
            }
            let mut prog = tx.prepare_cached(
                "INSERT OR IGNORE INTO programs (exe, name, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)",
            )?;
            for (exe, name) in &w.new_programs {
                prog.execute(params![exe, name, now])?;
            }
            let mut seen = tx.prepare_cached("UPDATE programs SET last_seen = ?1 WHERE exe = ?2")?;
            for exe in &w.seen_programs {
                seen.execute(params![now, exe])?;
            }
            let mut lis = tx.prepare_cached(
                "INSERT OR IGNORE INTO listeners (exe, port, first_seen) VALUES (?1, ?2, ?3)",
            )?;
            for (exe, port) in &w.new_listeners {
                lis.execute(params![exe, port, now])?;
            }
        }
        tx.commit()?;
        Ok(ids)
    }

    /* ----- Alerts ----- */

    pub fn add_alert(&self, key: &str, a: &Alert) -> Res<i64> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO alerts (key, ts, severity, title, detail, process, exe, pid) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![key, a.ts, a.severity, a.title, a.detail, a.process, a.exe, a.pid],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn recent_alerts(&self, limit: u32) -> Res<Vec<Alert>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare_cached(
            "SELECT id, ts, severity, title, detail, process, exe, pid, acked FROM alerts ORDER BY ts DESC, id DESC LIMIT ?1",
        )?;
        let rows = st.query_map([limit], |r| {
            Ok(Alert {
                id: r.get(0)?,
                ts: r.get(1)?,
                severity: r.get(2)?,
                title: r.get(3)?,
                detail: r.get(4)?,
                process: r.get(5)?,
                exe: r.get(6)?,
                pid: r.get(7)?,
                acked: r.get(8)?,
            })
        })?;
        rows.collect()
    }

    /// Empty `ids` dismisses every alert.
    pub fn ack_alerts(&self, ids: &[i64]) -> Res<()> {
        let c = self.conn.lock().unwrap();
        if ids.is_empty() {
            c.execute("UPDATE alerts SET acked = 1 WHERE acked = 0", [])?;
        } else {
            let mut st = c.prepare_cached("UPDATE alerts SET acked = 1 WHERE id = ?1")?;
            for id in ids {
                st.execute([id])?;
            }
        }
        Ok(())
    }

    /* ----- Rules ----- */

    pub fn list_rules(&self) -> Res<Vec<Rule>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT kind, target, label, trusted, created FROM rules ORDER BY created DESC")?;
        let rows = st.query_map([], |r| {
            Ok(Rule { kind: r.get(0)?, target: r.get(1)?, label: r.get(2)?, trusted: r.get(3)?, created: r.get(4)? })
        })?;
        rows.collect()
    }

    pub fn set_rule(&self, mut rule: Rule) -> Res<()> {
        rule.label = rule.label.map(|l| l.trim().to_string()).filter(|l| !l.is_empty());
        rule.created = now_ms();
        {
            let c = self.conn.lock().unwrap();
            c.execute(
                "INSERT INTO rules (kind, target, label, trusted, created) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (kind, target) DO UPDATE SET label = excluded.label, trusted = excluded.trusted",
                params![rule.kind, rule.target, rule.label, rule.trusted, rule.created],
            )?;
        }
        self.rules.write().unwrap().insert(rule);
        Ok(())
    }

    pub fn delete_rule(&self, kind: &str, target: &str) -> Res<()> {
        {
            let c = self.conn.lock().unwrap();
            c.execute("DELETE FROM rules WHERE kind = ?1 AND target = ?2", params![kind, target])?;
        }
        self.rules.write().unwrap().remove(kind, target);
        Ok(())
    }

    /* ----- History ----- */

    pub fn history(&self, since: u64, search: &str, limit: u32) -> Res<HistoryResult> {
        let pattern = format!(
            "%{}%",
            search.trim().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
        );
        let filter = "first_seen >= ?1 AND (?2 = '%%' OR exe LIKE ?2 ESCAPE '\\' OR process LIKE ?2 ESCAPE '\\'
            OR remote_ip LIKE ?2 ESCAPE '\\' OR host LIKE ?2 ESCAPE '\\' OR org LIKE ?2 ESCAPE '\\'
            OR country LIKE ?2 ESCAPE '\\' OR CAST(remote_port AS TEXT) = ?3)";
        let c = self.conn.lock().unwrap();
        let total: u64 = c.query_row(
            &format!("SELECT COUNT(*) FROM connections WHERE {filter}"),
            params![since, pattern, search.trim()],
            |r| r.get(0),
        )?;
        let mut st = c.prepare(&format!(
            "SELECT id, exe, process, proto, local_port, remote_ip, remote_port, direction, host, country, org,
                    first_seen, last_seen, open, risk
             FROM connections WHERE {filter} ORDER BY first_seen DESC LIMIT ?4"
        ))?;
        let rows = st
            .query_map(params![since, pattern, search.trim(), limit], |r| {
                Ok(HistRow {
                    id: r.get(0)?,
                    exe: r.get(1)?,
                    process: r.get(2)?,
                    proto: r.get(3)?,
                    local_port: r.get(4)?,
                    remote_ip: r.get(5)?,
                    remote_port: r.get(6)?,
                    direction: r.get(7)?,
                    host: r.get(8)?,
                    country: r.get(9)?,
                    org: r.get(10)?,
                    first_seen: r.get(11)?,
                    last_seen: r.get(12)?,
                    open: r.get(13)?,
                    risk: r.get(14)?,
                })
            })?
            .collect::<Res<Vec<_>>>()?;
        // Programs captured by the initial baseline weren't "new", just already there.
        let mut st = c.prepare(
            "SELECT exe, name, first_seen, last_seen FROM programs
             WHERE first_seen >= ?1
               AND first_seen > COALESCE((SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'baseline_at'), 0) + 60000
             ORDER BY first_seen DESC LIMIT 50",
        )?;
        let new_programs = st
            .query_map([since], |r| {
                Ok(KnownProgram { exe: r.get(0)?, name: r.get(1)?, first_seen: r.get(2)?, last_seen: r.get(3)? })
            })?
            .collect::<Res<Vec<_>>>()?;
        Ok(HistoryResult { rows, total, new_programs })
    }

    pub fn info(&self) -> Res<DbInfo> {
        let c = self.conn.lock().unwrap();
        let programs = c.query_row("SELECT COUNT(*) FROM programs", [], |r| r.get(0))?;
        let connections = c.query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))?;
        let oldest = c.query_row("SELECT MIN(first_seen) FROM connections", [], |r| r.get(0))?;
        let bytes = ["", "-wal"]
            .iter()
            .filter_map(|suffix| {
                let mut p = self.path.clone().into_os_string();
                p.push(suffix);
                std::fs::metadata(p).ok()
            })
            .map(|m| m.len())
            .sum();
        Ok(DbInfo { programs, connections, oldest, bytes, retention_days: HISTORY_DAYS })
    }
}
