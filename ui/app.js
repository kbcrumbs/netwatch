"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const state = {
  snap: null,
  info: null,
  tab: "connections",
  paused: false,
  search: "",
  sort: {
    connections: { key: "risk", dir: -1 },
    destinations: { key: "risk", dir: -1 },
    processes: { key: "risk", dir: -1 },
    listening: { key: "port", dir: 1 },
    devices: { key: "status", dir: 1 },
  },
  history: null,
  histHours: 24,
  rules: [],
  dbInfo: null,
};

const DAY_MS = 24 * 3600 * 1000;
/* Tabs whose data comes from commands, not the live snapshot; they only
   re-render when that data changes, so open dropdowns aren't destroyed. */
const STATIC_TABS = new Set(["history", "rules"]);

const RISK_RANK = { high: 2, medium: 1, none: 0 };
const SIG_LABEL = {
  signed: "Signed",
  system: "System",
  unsigned: "Unsigned",
  invalid: "Bad sig",
  unknown: "Unknown",
  pending: "Checking…",
};
const SIG_RANK = { invalid: 0, unsigned: 1, unknown: 2, pending: 3, signed: 4, system: 5 };

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function ago(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d`;
}

function clock(ms) {
  return new Date(ms).toLocaleTimeString();
}

function addr(ip, port) {
  if (ip == null) return "";
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

function sigBadge(c) {
  const title = c.signer ? `Signed by ${c.signer}` : SIG_LABEL[c.sig];
  return `<span class="sig ${c.sig}" title="${esc(title)}">${SIG_LABEL[c.sig] ?? esc(c.sig)}</span>`;
}

function intelBadges(hits) {
  const seen = new Set();
  return hits
    .filter((h) => !seen.has(h.label) && seen.add(h.label))
    .map((h) => `<span class="listed ${h.severity}" title="${esc(`${h.label} (listed by ${h.feed})`)}">${esc(h.label)}</span>`)
    .join("");
}

function where(c) {
  if (!c.country && !c.org) {
    const local = { private: "Local network", loopback: "This PC" }[c.scope];
    return `<span class="dim">${local ?? "—"}</span>`;
  }
  const cc = c.country ? `<span class="cc" title="${esc(c.countryName ?? c.country)}">${esc(c.country)}</span>` : "";
  const org = c.org ? `<span class="org" title="${esc(`${c.org} (AS${c.asn})`)}">${esc(c.org)}</span>` : "";
  return cc + org;
}

function remoteCell(c) {
  if (c.remoteAddr == null) return `<span class="dim">—</span>`;
  const host = c.host ? `<span class="host" title="${esc(c.host)}">${esc(c.host)}</span>` : "";
  const label = c.label ? `<span class="label-name">${esc(c.label)}</span> ` : "";
  return `${label}${esc(addr(c.remoteAddr, c.remotePort))}${c.ipTrusted ? trustedTag() : ""}${intelBadges(c.intel)}${host}`;
}

function trustedTag() {
  return `<span class="tag trusted" title="You marked this as trusted">Trusted</span>`;
}

function serviceTag(services) {
  if (!services?.length) return "";
  const text = services.length === 1 ? services[0] : `${services[0]} +${services.length - 1}`;
  return `<span class="svc" title="${esc(services.join("\n"))}">${esc(text)}</span>`;
}

function rowTitle(c) {
  return [c.path, c.iface && `Via ${c.iface}${c.viaVpn ? " (VPN)" : ""}`].filter(Boolean).join("\n");
}

function programTags(c) {
  const newTag = c.programNew
    ? `<span class="tag new" title="First used the network ${esc(new Date(c.programSince).toLocaleString())}">New</span>`
    : "";
  return newTag + (c.programTrusted ? trustedTag() : "");
}

function enrichFields(c) {
  return [c.host, c.label, c.country, c.countryName, c.org, c.asn && `AS${c.asn}`, ...c.intel.map((h) => h.label)];
}

function isNew(c) {
  const s = state.snap;
  return s && s.tick > 1 && c.firstSeen > s.started && Date.now() - c.firstSeen < 8000;
}

function matchesSearch(fields) {
  const q = state.search;
  if (!q) return true;
  return fields.some((f) => f != null && String(f).toLowerCase().includes(q));
}

function filters() {
  return {
    loopback: $("f-loopback").checked,
    established: $("f-established").checked,
    risky: $("f-risky").checked,
    udp: $("f-udp").checked,
  };
}

function cmp(a, b) {
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a ?? "").localeCompare(String(b ?? ""), undefined, { numeric: true, sensitivity: "base" });
}

function sortRows(rows, view, getters) {
  const { key, dir } = state.sort[view];
  const get = getters[key];
  if (!get) return rows;
  return rows.sort((a, b) => dir * cmp(get(a), get(b)) || cmp(a.process, b.process));
}

function th(view, key, label) {
  const s = state.sort[view];
  const cls = s.key === key ? `sorted ${s.dir > 0 ? "asc" : ""}` : "";
  return `<th class="${cls}" data-sort="${key}" data-view="${view}">${label}</th>`;
}

/* ---------- Stats ---------- */

function renderStats() {
  const st = state.snap.stats;
  const alerts = state.snap.alerts.filter((a) => !a.acked);
  const high = alerts.filter((a) => a.severity === "high").length;
  const cards = [
    ["Outbound", st.outbound, "Established connections this PC opened"],
    ["Inbound", st.inbound, "Established connections into this PC", st.inbound ? "warn" : ""],
    ["Open ports", st.listening, "TCP ports listening for connections"],
    ["Remote hosts", st.remoteHosts, `${st.publicHosts} on the public internet`],
    ["Programs online", st.processes, "Programs with live non-loopback connections"],
    ["Flagged", st.risky, "Connections matching a risk rule", st.risky ? "bad" : ""],
    ["High alerts", high, "High-severity alerts you haven't dismissed", high ? "bad" : ""],
    ["Known programs", state.snap.knownPrograms, "Programs that have used the network since NetWatch was installed"],
    ["Devices", state.snap.devices.filter((d) => d.online).length, `Devices on your local network right now (${state.snap.devices.length} known)`],
  ];
  $("stats").innerHTML = cards
    .map(([k, v, t, cls = ""]) => `<div class="stat ${cls}" title="${esc(t)}"><div class="v">${v}</div><div class="k">${k}</div></div>`)
    .join("");

  const badge = $("alert-count");
  const medium = alerts.filter((a) => a.severity === "medium").length;
  const n = high || medium;
  badge.hidden = !n;
  badge.textContent = n;
  badge.className = high ? "count" : "count medium";
}

/* ---------- Connections ---------- */

const CONN_GET = {
  risk: (c) => RISK_RANK[c.risk] * 10 + (c.state === "Established" ? 1 : 0),
  process: (c) => c.process,
  pid: (c) => c.pid,
  proto: (c) => c.proto,
  local: (c) => c.localPort,
  remote: (c) => c.remoteAddr ?? "",
  rport: (c) => c.remotePort ?? -1,
  where: (c) => `${c.country ?? "~"} ${c.org ?? ""}`,
  state: (c) => c.state,
  direction: (c) => c.direction,
  scope: (c) => c.scope,
  age: (c) => -c.firstSeen,
};

function renderConnections() {
  const f = filters();
  let rows = state.snap.conns.filter((c) => {
    if (c.direction === "listen") return false;
    if (c.proto === "UDP" && !f.udp) return false;
    if (f.loopback && c.scope === "loopback") return false;
    if (f.established && c.state !== "Established") return false;
    if (f.risky && c.risk === "none") return false;
    return matchesSearch([c.process, ...c.services, c.pid, c.path, c.signer, c.iface, c.remoteAddr, c.remotePort, c.localPort, c.state, c.localAddr, ...enrichFields(c)]);
  });
  rows = sortRows(rows, "connections", CONN_GET);
  $("shown").textContent = `${rows.length} shown`;

  if (!rows.length) return emptyState("No connections match these filters.");

  const body = rows
    .map((c) => {
      const cls = [c.risk !== "none" ? `risk-${c.risk}` : "", isNew(c) ? "new" : ""].join(" ");
      const reasons = c.reasons.length ? `<div class="reasons">${c.reasons.map(esc).join(" · ")}</div>` : "";
      return `<tr class="${cls}" title="${esc(rowTitle(c))}">
        <td><span class="proc">${esc(c.process)}</span>${serviceTag(c.services)}${sigBadge(c)}${programTags(c)}${reasons}</td>
        <td class="mono dim">${c.pid}</td>
        <td class="mono">${c.proto}${c.ipv === 6 ? "6" : ""}</td>
        <td class="mono">${esc(addr(c.localAddr, c.localPort))}</td>
        <td class="mono">${remoteCell(c)}</td>
        <td>${where(c)}</td>
        <td>${esc(c.state)}</td>
        <td><span class="dir ${c.direction}">${c.direction === "udp" ? "—" : c.direction}</span></td>
        <td class="dim">${ago(c.firstSeen)}</td>
      </tr>`;
    })
    .join("");

  $("view").innerHTML = `<table>
    <thead><tr>
      ${th("connections", "process", "Program")}
      ${th("connections", "pid", "PID")}
      ${th("connections", "proto", "Proto")}
      ${th("connections", "local", "Local")}
      ${th("connections", "remote", "Remote")}
      ${th("connections", "where", "Where")}
      ${th("connections", "state", "State")}
      ${th("connections", "direction", "Direction")}
      ${th("connections", "age", "Seen for")}
    </tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

/* ---------- Destinations ---------- */

const DEST_GET = {
  risk: (d) => RISK_RANK[d.risk] * 1000 + d.conns,
  ip: (d) => d.ip,
  where: (d) => `${d.country ?? "~"} ${d.countryName ?? ""}`,
  org: (d) => d.org ?? "~",
  programs: (d) => d.programs.size,
  conns: (d) => d.conns,
  age: (d) => -d.firstSeen,
};

function groupDestinations() {
  const map = new Map();
  for (const c of state.snap.conns) {
    if (c.remoteAddr == null || c.scope === "loopback" || c.scope === "none") continue;
    let d = map.get(c.remoteAddr);
    if (!d) {
      d = { ip: c.remoteAddr, host: c.host, country: c.country, countryName: c.countryName, org: c.org, asn: c.asn, scope: c.scope,
        intel: c.intel, label: c.label, trusted: c.ipTrusted, programs: new Set(), ports: new Set(), conns: 0, established: 0, risk: "none", firstSeen: c.firstSeen, process: "" };
      map.set(c.remoteAddr, d);
    }
    if (c.pid !== 0) d.programs.add(c.process);
    d.ports.add(c.remotePort);
    d.conns++;
    if (c.state === "Established") d.established++;
    if (RISK_RANK[c.risk] > RISK_RANK[d.risk]) d.risk = c.risk;
    d.host ??= c.host;
    d.firstSeen = Math.min(d.firstSeen, c.firstSeen);
  }
  for (const d of map.values()) d.process = [...d.programs].join(", ");
  return [...map.values()];
}

function barList(title, entries, unit) {
  if (!entries.length) return `<div class="card"><h3>${esc(title)}</h3><div class="dim">No public destinations yet.</div></div>`;
  const max = entries[0][1].conns;
  const rows = entries
    .map(([label, v]) => {
      const tip = `${label}: ${v.conns} connection${v.conns === 1 ? "" : "s"} to ${v.hosts.size} host${v.hosts.size === 1 ? "" : "s"}`;
      return `<div class="bar-row" title="${esc(tip)}">
        <span class="bar-label">${esc(label)}</span>
        <span class="bar-track"><span class="bar-fill" style="display:block;width:${(v.conns / max) * 100}%"></span></span>
        <span class="bar-val">${v.conns}</span>
      </div>`;
    })
    .join("");
  return `<div class="card"><h3>${esc(title)} <span class="dim">· ${unit}</span></h3><div class="bars">${rows}</div></div>`;
}

function topBy(dests, keyFn, n = 6) {
  const m = new Map();
  for (const d of dests) {
    if (d.scope !== "public") continue;
    const k = keyFn(d);
    if (!k) continue;
    const v = m.get(k) ?? { conns: 0, hosts: new Set() };
    v.conns += d.conns;
    v.hosts.add(d.ip);
    m.set(k, v);
  }
  return [...m.entries()].sort((a, b) => b[1].conns - a[1].conns).slice(0, n);
}

function intelCard() {
  const st = state.snap.intel;
  const feeds = st.feeds
    .map((f) => {
      const err = f.error && !f.entries;
      const n = err ? "Failed" : f.entries ? f.entries.toLocaleString() : "…";
      return `<div class="feed-row ${err ? "err" : ""}" title="${esc(f.error ?? (f.updated ? `Updated ${new Date(f.updated).toLocaleString()}` : ""))}">
        <span>${esc(f.name)}</span><span class="n">${n}</span></div>`;
    })
    .join("");
  const geo = st.geo.ready ? `DB-IP Lite ${esc(st.geo.edition ?? "")}` : st.geo.error ? `Geo failed: ${esc(st.geo.error)}` : "Geo database loading…";
  const checked = st.updating ? "Updating now…" : st.lastCheck ? `Checked ${clock(st.lastCheck)}` : "Not checked yet";
  return `<div class="card"><h3>Threat intel · matched offline</h3>
    <div class="feed-list">${feeds}</div>
    <div class="actions"><span>${geo} · ${checked}</span>
      <button class="btn" id="refresh-intel" type="button" ${st.updating ? "disabled" : ""}>Update now</button></div>
  </div>`;
}

function renderDestinations() {
  const f = filters();
  const all = groupDestinations();
  let rows = all.filter((d) => {
    if (f.established && !d.established) return false;
    if (f.risky && d.risk === "none") return false;
    return matchesSearch([d.ip, d.host, d.label, d.country, d.countryName, d.org, d.asn && `AS${d.asn}`, d.process, ...d.ports, ...d.intel.map((h) => h.label)]);
  });
  rows = sortRows(rows, "destinations", DEST_GET);
  $("shown").textContent = `${rows.length} remote hosts`;

  const overview = `<div class="overview">
    ${barList("Top countries", topBy(all, (d) => d.countryName ?? d.country), "connections")}
    ${barList("Top networks", topBy(all, (d) => d.org), "connections")}
    ${intelCard()}
  </div>`;

  const body = rows
    .map((d) => {
      const ports = [...d.ports].sort((a, b) => a - b);
      return `<tr class="${d.risk !== "none" ? `risk-${d.risk}` : ""}">
        <td class="mono">${d.label ? `<span class="label-name">${esc(d.label)}</span> ` : ""}${esc(d.ip)}${d.trusted ? trustedTag() : ""}${intelBadges(d.intel)}${d.host ? `<span class="host" title="${esc(d.host)}">${esc(d.host)}</span>` : ""}</td>
        <td>${d.country ? `<span class="cc">${esc(d.country)}</span>${esc(d.countryName ?? "")}` : `<span class="dim">${d.scope === "private" ? "Local network" : "—"}</span>`}</td>
        <td>${d.org ? `<span class="org" title="${esc(d.org)}">${esc(d.org)}</span> <span class="dim mono">AS${d.asn}</span>` : '<span class="dim">—</span>'}</td>
        <td>${d.programs.size ? esc(d.process) : '<span class="dim">closed</span>'}</td>
        <td class="mono">${d.established}<span class="dim"> / ${d.conns}</span></td>
        <td class="mono">${ports.slice(0, 5).join(", ")}${ports.length > 5 ? ` +${ports.length - 5}` : ""}</td>
        <td class="dim">${ago(d.firstSeen)}</td>
        <td class="actions"><button class="btn sm" type="button" data-action="label-ip" data-ip="${esc(d.ip)}">${d.label || d.trusted ? "Edit" : "Label"}</button></td>
      </tr>`;
    })
    .join("");

  const table = rows.length
    ? `<table>
      <thead><tr>
        ${th("destinations", "ip", "Remote host")}
        ${th("destinations", "where", "Country")}
        ${th("destinations", "org", "Network owner")}
        ${th("destinations", "programs", "Programs")}
        ${th("destinations", "conns", "Live / total")}
        <th>Ports</th>
        ${th("destinations", "age", "Seen for")}
        <th></th>
      </tr></thead>
      <tbody>${body}</tbody>
    </table>`
    : `<div class="empty">No remote hosts match these filters.</div>`;

  $("view").innerHTML = overview + table;
}

/* ---------- Programs ---------- */

const PROC_GET = {
  risk: (p) => RISK_RANK[p.risk] * 1000 + p.conns,
  process: (p) => p.process,
  sig: (p) => SIG_RANK[p.sig] ?? 9,
  conns: (p) => p.conns,
  hosts: (p) => p.hosts.size,
  ports: (p) => p.ports.size,
  path: (p) => p.path ?? "",
  since: (p) => p.programSince ?? Infinity,
};

function groupPrograms() {
  const f = filters();
  const map = new Map();
  for (const c of state.snap.conns) {
    if (c.proto === "UDP" && !f.udp) continue;
    if (f.loopback && c.scope === "loopback") continue;
    const key = c.path ?? `${c.process}#${c.pid}`;
    let p = map.get(key);
    if (!p) {
      p = { key, process: c.process, path: c.path, sig: c.sig, signer: c.signer, programSince: c.programSince, programNew: c.programNew,
        programTrusted: c.programTrusted, pids: new Set(), services: new Set(), conns: 0, hosts: new Set(), ports: new Set(), risk: "none", reasons: new Set(), enrich: [] };
      map.set(key, p);
    }
    p.pids.add(c.pid);
    c.services.forEach((n) => p.services.add(n));
    if (c.direction === "listen") p.ports.add(c.localPort);
    if (c.state === "Established") {
      p.conns++;
      if (c.remoteAddr) p.hosts.add(c.remoteAddr);
    }
    if (RISK_RANK[c.risk] > RISK_RANK[p.risk]) p.risk = c.risk;
    c.reasons.forEach((r) => p.reasons.add(r));
    p.enrich.push(...enrichFields(c));
  }
  return [...map.values()];
}

function renderPrograms() {
  const f = filters();
  let rows = groupPrograms().filter((p) => {
    if (f.established && !p.conns) return false;
    if (f.risky && p.risk === "none") return false;
    return matchesSearch([p.process, ...p.services, p.path, p.signer, ...p.pids, ...p.hosts, ...p.ports, ...p.enrich]);
  });
  rows = sortRows(rows, "processes", PROC_GET);
  $("shown").textContent = `${rows.length} programs`;
  if (!rows.length) return emptyState("No programs match these filters.");

  const body = rows
    .map((p) => {
      const hosts = [...p.hosts];
      const hostText = hosts.slice(0, 2).join(", ") + (hosts.length > 2 ? ` +${hosts.length - 2}` : "");
      const reasons = p.reasons.size ? `<div class="reasons">${[...p.reasons].map(esc).join(" · ")}</div>` : "";
      // Trust needs a real path; nameless system processes can't be trusted.
      const canTrust = p.path && p.pids.size && ![...p.pids].includes(0);
      const action = canTrust
        ? `<button class="btn sm" type="button" data-action="${p.programTrusted ? "untrust" : "trust"}" data-exe="${esc(p.path)}">${p.programTrusted ? "Untrust" : "Trust"}</button>`
        : "";
      return `<tr class="${p.risk !== "none" ? `risk-${p.risk}` : ""}">
        <td><span class="proc">${esc(p.process)}</span> <span class="dim mono" title="PIDs ${[...p.pids].join(", ")}">${[...p.pids].slice(0, 2).join(", ")}${p.pids.size > 2 ? ` +${p.pids.size - 2}` : ""}</span>${serviceTag([...p.services].sort())}${programTags(p)}${reasons}</td>
        <td>${sigBadge(p)} <span class="dim">${esc(p.signer ?? "")}</span> ${action}</td>
        <td class="mono">${p.conns}</td>
        <td class="mono clip" title="${esc(hosts.join("\n"))}">${hosts.length ? esc(hostText) : '<span class="dim">—</span>'}</td>
        <td class="mono">${p.ports.size ? [...p.ports].sort((a, b) => a - b).join(", ") : '<span class="dim">—</span>'}</td>
        <td class="dim">${p.programSince ? esc(new Date(p.programSince).toLocaleDateString()) : "—"}</td>
        <td><span class="path" title="${esc(p.path ?? "")}">${esc(p.path ?? "Path unavailable (protected or exited)")}</span></td>
      </tr>`;
    })
    .join("");

  $("view").innerHTML = `<table>
    <thead><tr>
      ${th("processes", "process", "Program / PIDs")}
      ${th("processes", "sig", "Signature")}
      ${th("processes", "conns", "Live conns")}
      ${th("processes", "hosts", "Remote hosts")}
      ${th("processes", "ports", "Open ports")}
      ${th("processes", "since", "Known since")}
      ${th("processes", "path", "Path")}
    </tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

/* ---------- Open ports ---------- */

function exposure(c) {
  if (c.localAddr === "0.0.0.0" || c.localAddr === "::") return ["All interfaces", "public"];
  if (c.scope === "loopback") return ["This PC only", "loopback"];
  return [`Only ${c.localAddr}`, "private"];
}

const LISTEN_GET = {
  port: (c) => c.localPort,
  proto: (c) => c.proto,
  bind: (c) => exposure(c)[0],
  process: (c) => c.process,
  sig: (c) => SIG_RANK[c.sig] ?? 9,
  risk: (c) => RISK_RANK[c.risk],
};

function renderListening() {
  const f = filters();
  let rows = state.snap.conns.filter((c) => {
    const isListen = c.direction === "listen" || (f.udp && c.proto === "UDP");
    if (!isListen) return false;
    if (f.loopback && c.scope === "loopback") return false;
    if (f.risky && c.risk === "none") return false;
    return matchesSearch([c.process, ...c.services, c.pid, c.path, c.signer, c.localPort, c.localAddr]);
  });
  rows = sortRows(rows, "listening", LISTEN_GET);
  $("shown").textContent = `${rows.length} open ports`;
  if (!rows.length) return emptyState("No open ports match these filters.");

  const body = rows
    .map((c) => {
      const [label, cls] = exposure(c);
      const reasons = c.reasons.length ? `<div class="reasons">${c.reasons.map(esc).join(" · ")}</div>` : "";
      return `<tr class="${[c.risk !== "none" ? `risk-${c.risk}` : "", isNew(c) ? "new" : ""].join(" ")}" title="${esc(c.path ?? "")}">
        <td class="mono"><strong>${c.localPort}</strong></td>
        <td class="mono">${c.proto}${c.ipv === 6 ? "6" : ""}</td>
        <td><span class="scope ${cls}">${esc(label)}</span> <span class="dim mono">${esc(c.localAddr)}</span></td>
        <td><span class="proc">${esc(c.process)}</span> <span class="dim mono">${c.pid}</span>${serviceTag(c.services)}${reasons}</td>
        <td>${sigBadge(c)}</td>
      </tr>`;
    })
    .join("");

  $("view").innerHTML = `<table>
    <thead><tr>
      ${th("listening", "port", "Port")}
      ${th("listening", "proto", "Proto")}
      ${th("listening", "bind", "Reachable from")}
      ${th("listening", "process", "Program")}
      ${th("listening", "sig", "Signature")}
    </tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

/* ---------- Devices ---------- */

/** Sorts IPv4 numerically and puts IPv6 after it. */
function ipKey(ip) {
  const v4 = ip.split(".");
  return v4.length === 4 ? v4.map((o) => o.padStart(3, "0")).join(".") : `~${ip}`;
}

const DEV_GET = {
  status: (d) => (d.online ? 0 : 1),
  name: (d) => (d.name ?? d.vendor ?? "").toLowerCase(),
  ip: (d) => ipKey(d.ip),
  mac: (d) => d.mac,
  vendor: (d) => (d.vendor ?? "").toLowerCase(),
  first: (d) => d.firstSeen,
  last: (d) => d.lastSeen,
};

function renderDevices() {
  let rows = state.snap.devices.filter((d) => matchesSearch([d.name, d.ip, d.mac, d.vendor, d.privateMac && "private mac"]));
  // Pre-sorting by address keeps ties in address order (the sort is stable).
  rows.sort((a, b) => cmp(ipKey(a.ip), ipKey(b.ip)));
  rows = sortRows(rows, "devices", DEV_GET);
  const online = state.snap.devices.filter((d) => d.online).length;
  $("shown").textContent = `${online} online · ${state.snap.devices.length} known`;
  if (!rows.length) {
    return emptyState(
      state.search ? "No devices match this filter." : "Devices appear here as this PC talks to them on the local network.",
      state.search ? "" : "No devices yet"
    );
  }

  const body = rows
    .map((d) => {
      const name = d.name ?? d.vendor ?? (d.privateMac ? "Private device" : "Unknown device");
      const tags = (d.new ? `<span class="tag new" title="First seen ${esc(new Date(d.firstSeen).toLocaleString())}">New</span>` : "")
        + (d.privateMac ? `<span class="tag" title="Randomized MAC address: phones and laptops use these for privacy, so there's no manufacturer">Private MAC</span>` : "");
      return `<tr class="${d.online ? "" : "offline"}">
        <td><span class="state-dot ${d.online ? "on" : ""}" title="${d.online ? "Online" : "Not seen right now"}"></span></td>
        <td><span class="proc">${esc(name)}</span>${tags}</td>
        <td class="mono">${esc(d.ip)}</td>
        <td class="mono">${esc(d.mac)}</td>
        <td>${d.vendor ? esc(d.vendor) : '<span class="dim">—</span>'}</td>
        <td class="dim" title="${esc(new Date(d.firstSeen).toLocaleString())}">${when(d.firstSeen)}</td>
        <td class="dim" title="${esc(new Date(d.lastSeen).toLocaleString())}">${d.online ? "Now" : when(d.lastSeen)}</td>
      </tr>`;
    })
    .join("");

  $("view").innerHTML = `<table>
    <thead><tr>
      ${th("devices", "status", "")}
      ${th("devices", "name", "Device")}
      ${th("devices", "ip", "IP address")}
      ${th("devices", "mac", "MAC address")}
      ${th("devices", "vendor", "Manufacturer")}
      ${th("devices", "first", "First seen")}
      ${th("devices", "last", "Last seen")}
    </tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

/* ---------- Alerts ---------- */

function when(ms) {
  const d = new Date(ms);
  return Date.now() - ms < DAY_MS && d.getDate() === new Date().getDate() ? clock(ms) : d.toLocaleString();
}

function alertText(a) {
  return [
    `[${a.severity.toUpperCase()}] ${new Date(a.ts).toLocaleString()}`,
    a.title,
    a.detail,
    `${a.process}${a.pid ? ` (PID ${a.pid})` : ""}`,
  ].join("\n");
}

// Remembers what was just copied so the "Copied" label survives re-renders.
const copied = { key: null, until: 0 };

function copyLabel(key, idle) {
  return copied.key === key && Date.now() < copied.until ? "Copied" : idle;
}

async function copyText(key, text) {
  await navigator.clipboard.writeText(text);
  Object.assign(copied, { key, until: Date.now() + 1500 });
  render();
  setTimeout(render, 1600);
}

function renderAlerts() {
  const showAcked = $("f-acked").checked;
  const all = state.snap.alerts;
  const unacked = all.filter((a) => !a.acked).length;
  $("ack-all").disabled = !unacked;
  const alerts = all.filter((a) => (showAcked || !a.acked) && matchesSearch([a.title, a.detail, a.process, a.pid, a.exe]));
  state.shownAlerts = alerts;
  $("copy-alerts").disabled = !alerts.length;
  $("copy-alerts").textContent = copyLabel("all", "Copy all");
  $("shown").textContent = `${unacked} new · ${all.length - unacked} dismissed`;
  if (!alerts.length) {
    return emptyState(
      state.search ? "No alerts match this filter." : all.length ? "Every alert has been dismissed." : "Nothing suspicious has been seen yet.",
      state.search ? "" : "All clear"
    );
  }
  const rules = new Set(state.snap.conns.filter((c) => c.programTrusted).map((c) => (c.path ?? "").toLowerCase()));
  $("view").innerHTML = `<div class="alerts">${alerts
    .map((a) => {
      const trustable = a.exe.includes("\\") && !rules.has(a.exe.toLowerCase());
      return `<div class="alert ${a.severity} ${a.acked ? "acked" : ""}">
        <div class="sev">${a.severity}</div>
        <div><div class="title">${esc(a.title)}</div><div class="detail">${esc(a.detail)}</div></div>
        <div class="acts">
          <span class="when" title="${esc(new Date(a.ts).toLocaleString())}">${when(a.ts)}</span>
          <div class="row-actions">
            <button class="btn sm" type="button" data-action="copy-alert" data-id="${a.id}">${copyLabel(a.id, "Copy")}</button>
            ${trustable && a.severity !== "info" ? `<button class="btn sm" type="button" data-action="trust" data-exe="${esc(a.exe)}">Trust program</button>` : ""}
            ${a.acked ? "" : `<button class="btn sm" type="button" data-action="ack" data-id="${a.id}">Dismiss</button>`}
          </div>
        </div>
      </div>`;
    })
    .join("")}</div>`;
}

/* ---------- History ---------- */

function duration(ms) {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

let histTimer = null;
function loadHistory() {
  clearTimeout(histTimer);
  histTimer = setTimeout(async () => {
    try {
      const [history, dbInfo] = await Promise.all([
        invoke("history", { hours: state.histHours, search: state.search }),
        invoke("db_info"),
      ]);
      Object.assign(state, { history, dbInfo });
    } catch (e) {
      state.history = { error: String(e) };
    }
    if (state.tab === "history") renderHistory();
  }, 250);
}

function renderHistory() {
  const h = state.history;
  if (!h) return emptyState("Loading history…");
  if (h.error) return emptyState(`Couldn't read history: ${h.error}`);
  const db = state.dbInfo;
  $("shown").textContent = h.total > h.rows.length ? `Newest ${h.rows.length} of ${h.total.toLocaleString()}` : `${h.total.toLocaleString()} connections`;

  const range = $("hist-range").selectedOptions[0].textContent.toLowerCase();
  const newProgs = h.newPrograms.length
    ? h.newPrograms
        .map((p) => `<div class="feed-row" title="${esc(p.exe)}"><span>${esc(p.name)}</span><span class="n">${esc(when(p.firstSeen))}</span></div>`)
        .join("")
    : `<div class="dim">None. Everything that used the network was seen before.</div>`;
  const dbCard = db
    ? `<div class="feed-list">
        <div class="feed-row"><span>Connections stored</span><span class="n">${db.connections.toLocaleString()}</span></div>
        <div class="feed-row"><span>Programs in baseline</span><span class="n">${db.programs.toLocaleString()}</span></div>
        <div class="feed-row"><span>Recording since</span><span class="n">${db.oldest ? esc(new Date(db.oldest).toLocaleString()) : "—"}</span></div>
        <div class="feed-row"><span>Database size</span><span class="n">${(db.bytes / 1048576).toFixed(1)} MB</span></div>
      </div>
      <div class="actions"><span>Kept for ${db.retentionDays} days, then deleted automatically.</span></div>`
    : "";

  const overview = `<div class="overview">
    <div class="card"><h3>Programs new to the network · ${esc(range)}</h3><div class="feed-list">${newProgs}</div></div>
    <div class="card"><h3>Stored on this PC</h3>${dbCard}</div>
  </div>`;

  if (!h.rows.length) {
    $("view").innerHTML = overview + `<div class="empty">No connections recorded in this range${state.search ? " match this filter" : ""}.</div>`;
    return;
  }
  const body = h.rows
    .map((r) => {
      const remote = addr(r.remoteIp, r.remotePort);
      const where = r.country || r.org ? `${r.country ? `<span class="cc">${esc(r.country)}</span>` : ""}<span class="org">${esc(r.org ?? "")}</span>` : '<span class="dim">Local network</span>';
      return `<tr class="${r.risk !== "none" ? `risk-${r.risk}` : ""}" title="${esc(r.exe)}">
        <td class="dim">${esc(when(r.firstSeen))}</td>
        <td class="mono">${r.open ? '<span class="tag new">Open</span>' : esc(duration(r.lastSeen - r.firstSeen))}</td>
        <td><span class="proc">${esc(r.process)}</span></td>
        <td class="mono">${esc(remote)}${r.host ? `<span class="host">${esc(r.host)}</span>` : ""}</td>
        <td>${where}</td>
        <td><span class="dir ${r.direction}">${esc(r.direction)}</span></td>
      </tr>`;
    })
    .join("");
  $("view").innerHTML = `${overview}<table>
    <thead><tr><th>Started</th><th>Lasted</th><th>Program</th><th>Remote</th><th>Where</th><th>Direction</th></tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

/* ---------- Trusted & labels ---------- */

async function loadRules() {
  try {
    state.rules = await invoke("list_rules");
  } catch (e) {
    console.error(e);
  }
  if (state.tab === "rules") renderRules();
}

function renderRules() {
  const rules = state.rules.filter((r) => matchesSearch([r.target, r.label]));
  $("shown").textContent = `${rules.length} rules`;
  if (!rules.length) {
    return emptyState(
      "Use Trust on the Programs tab or Label on Destinations to add one. Trusted programs skip signature, location and port alerts; threat-feed matches always alert.",
      state.search ? "" : "Nothing trusted or labelled yet"
    );
  }
  const body = rules
    .map(
      (r) => `<tr>
        <td>${r.kind === "program" ? "Program" : "Address"}</td>
        <td class="mono">${esc(r.target)}</td>
        <td>${r.label ? `<span class="label-name">${esc(r.label)}</span>` : '<span class="dim">—</span>'}</td>
        <td>${r.trusted ? trustedTag() : '<span class="dim">Label only</span>'}</td>
        <td class="dim">${esc(new Date(r.created).toLocaleDateString())}</td>
        <td class="actions"><div class="row-actions">
          ${r.kind === "ip" ? `<button class="btn sm" type="button" data-action="label-ip" data-ip="${esc(r.target)}">Edit</button>` : ""}
          <button class="btn sm danger" type="button" data-action="delete-rule" data-kind="${esc(r.kind)}" data-target="${esc(r.target)}">Remove</button>
        </div></td>
      </tr>`
    )
    .join("");
  $("view").innerHTML = `<table>
    <thead><tr><th>Type</th><th>Target</th><th>Name</th><th>Trust</th><th>Added</th><th></th></tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

/* ---------- Label / trust dialog ---------- */

const modal = { ip: null };

function openLabelDialog(ip) {
  const rule = state.rules.find((r) => r.kind === "ip" && r.target === ip);
  const c = state.snap?.conns.find((x) => x.remoteAddr === ip);
  modal.ip = ip;
  $("modal-title").textContent = rule ? "Edit address" : "Label address";
  $("modal-sub").textContent = [ip, c?.host, c?.org].filter(Boolean).join(" · ");
  $("modal-label").value = rule?.label ?? "";
  $("modal-trust").checked = rule?.trusted ?? false;
  $("modal-trust-text").textContent = "Trust this address";
  $("modal-hint").textContent = "Trusted addresses don't raise threat-feed or suspicious-port alerts.";
  $("modal-remove").hidden = !rule;
  $("modal").hidden = false;
  $("modal-label").focus();
}

function closeDialog() {
  $("modal").hidden = true;
  modal.ip = null;
}

async function afterRuleChange() {
  await loadRules();
  const s = await invoke("get_snapshot");
  if (s) state.snap = s;
  render();
}

$("modal-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const label = $("modal-label").value.trim();
  const trusted = $("modal-trust").checked;
  if (!label && !trusted) {
    await invoke("delete_rule", { kind: "ip", target: modal.ip });
  } else {
    await invoke("set_rule", { rule: { kind: "ip", target: modal.ip, label: label || null, trusted } });
  }
  closeDialog();
  afterRuleChange();
});
$("modal-cancel").addEventListener("click", closeDialog);
$("modal-remove").addEventListener("click", async () => {
  await invoke("delete_rule", { kind: "ip", target: modal.ip });
  closeDialog();
  afterRuleChange();
});
$("modal").addEventListener("click", (e) => e.target === $("modal") && closeDialog());
document.addEventListener("keydown", (e) => e.key === "Escape" && !$("modal").hidden && closeDialog());

function emptyState(text, heading = "") {
  $("view").innerHTML = `<div class="empty">${heading ? `<strong>${esc(heading)}</strong>` : ""}${esc(text)}</div>`;
}

/* ---------- Render loop ---------- */

function renderIntelBadge() {
  const st = state.snap.intel;
  const loaded = st.feeds.filter((f) => f.entries > 0).length;
  const failed = st.feeds.filter((f) => f.error && !f.entries);
  const b = $("intel-badge");
  const allGood = loaded === st.feeds.length && st.geo.ready;
  b.textContent = st.updating && !loaded ? "Downloading threat intel…" : `Threat intel ${loaded}/${st.feeds.length}`;
  b.className = `badge ${allGood ? "ok" : loaded || st.updating ? "" : "warn"}`;
  const total = st.feeds.reduce((n, f) => n + f.entries, 0);
  b.title = [
    `${total.toLocaleString()} listed addresses/ranges from ${loaded} feeds, matched on this PC.`,
    st.geo.ready ? `Geolocation: DB-IP Lite ${st.geo.edition}` : "Geolocation database not loaded yet",
    state.snap.dnsNames
      ? "Hostnames: from Windows DNS lookups, then reverse DNS"
      : "Hostnames: reverse DNS only (DNS lookup capture needs admin)",
    ...failed.map((f) => `${f.name}: ${f.error}`),
  ].join("\n");
}

function renderVpnBadge() {
  const vpn = state.snap.vpn;
  const b = $("vpn-badge");
  b.textContent = vpn ? `VPN: ${vpn}` : "No VPN";
  b.className = `badge ${vpn ? "ok" : ""}`;
  b.title = vpn
    ? `Public traffic should leave through ${vpn}. Programs that send it over another adapter are flagged.`
    : "No VPN tunnel is up, so VPN leak checks are off.";
}

const VIEWS = {
  connections: renderConnections,
  destinations: renderDestinations,
  processes: renderPrograms,
  listening: renderListening,
  devices: renderDevices,
  history: renderHistory,
  alerts: renderAlerts,
  rules: renderRules,
};

function render(fromTick = false) {
  if (!state.snap) return;
  const main = $("view");
  const scroll = main.scrollTop;
  renderStats();
  renderIntelBadge();
  renderVpnBadge();
  if (!(fromTick && STATIC_TABS.has(state.tab))) VIEWS[state.tab]();
  main.scrollTop = scroll;
  $("updated").textContent = `Last scan ${clock(state.snap.ts)} · ${state.snap.stats.total} sockets · watching since ${clock(state.snap.started)}`;
}

function setLive() {
  const live = $("live");
  live.className = `live ${state.paused ? "paused" : state.snap ? "on" : ""}`;
  $("live-text").textContent = state.paused ? "Paused" : state.snap ? "Live" : "Starting";
  $("pause").textContent = state.paused ? "Resume" : "Pause";
}

document.querySelectorAll(".tab").forEach((btn) =>
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
    state.tab = btn.dataset.tab;
    const live = !["alerts", "history", "rules"].includes(state.tab);
    document.querySelectorAll("#toolbar .chip").forEach((c) => (c.hidden = !live));
    $("hist-range").hidden = state.tab !== "history";
    $("show-acked-chip").hidden = $("ack-all").hidden = $("copy-alerts").hidden = state.tab !== "alerts";
    $("view").scrollTop = 0;
    if (state.tab === "history") loadHistory();
    if (state.tab === "rules") loadRules();
    render();
  })
);

async function runAction(btn) {
  const { action } = btn.dataset;
  if (action === "label-ip") return openLabelDialog(btn.dataset.ip);
  if (action === "copy-alert") {
    const a = state.snap.alerts.find((x) => x.id === Number(btn.dataset.id));
    return a && copyText(a.id, alertText(a)).catch(console.error);
  }
  btn.disabled = true;
  try {
    if (action === "trust") await invoke("set_rule", { rule: { kind: "program", target: btn.dataset.exe, label: null, trusted: true } });
    if (action === "untrust") await invoke("delete_rule", { kind: "program", target: btn.dataset.exe });
    if (action === "delete-rule") await invoke("delete_rule", { kind: btn.dataset.kind, target: btn.dataset.target });
    if (action === "ack") await invoke("ack_alerts", { ids: [Number(btn.dataset.id)] });
    await afterRuleChange();
  } catch (e) {
    console.error(e);
    btn.disabled = false;
  }
}

$("view").addEventListener("click", (e) => {
  if (e.target.closest("#refresh-intel")) {
    e.target.disabled = true;
    e.target.textContent = "Updating…";
    invoke("refresh_intel");
    return;
  }
  const actionBtn = e.target.closest("button[data-action]");
  if (actionBtn) return runAction(actionBtn);
  const head = e.target.closest("th[data-sort]");
  if (!head) return;
  const s = state.sort[head.dataset.view];
  if (s.key === head.dataset.sort) s.dir = -s.dir;
  else Object.assign(s, { key: head.dataset.sort, dir: head.dataset.sort === "risk" ? -1 : 1 });
  render();
});

$("search").addEventListener("input", (e) => {
  state.search = e.target.value.trim().toLowerCase();
  if (state.tab === "history") loadHistory();
  render();
});
["f-loopback", "f-established", "f-risky", "f-udp", "f-acked"].forEach((id) => $(id).addEventListener("change", () => render()));
$("hist-range").addEventListener("change", (e) => {
  state.histHours = Number(e.target.value);
  loadHistory();
});
$("copy-alerts").addEventListener("click", () => {
  const text = (state.shownAlerts ?? []).map(alertText).join("\n\n");
  if (text) copyText("all", text).catch(console.error);
});
$("ack-all").addEventListener("click", async () => {
  await invoke("ack_alerts", { ids: [] });
  afterRuleChange();
});

$("pause").addEventListener("click", () => {
  state.paused = !state.paused;
  setLive();
  if (!state.paused) invoke("get_snapshot").then((s) => s && ((state.snap = s), render()));
});

listen("snapshot", (e) => {
  if (state.paused) return;
  state.snap = e.payload;
  setLive();
  render(true);
  // Keep the History tab current without re-rendering it every poll.
  if (state.tab === "history" && state.snap.tick % 10 === 0) loadHistory();
});

loadRules();

invoke("system_info").then((info) => {
  state.info = info;
  $("host").textContent = `${info.hostname || "This PC"} · scanning every ${(info.pollMs / 1000).toFixed(1)}s`;
  const b = $("admin-badge");
  b.textContent = info.admin ? "Administrator" : "Limited: not admin";
  b.className = `badge ${info.admin ? "ok" : "warn"}`;
  b.title = info.admin
    ? "Running elevated: every program's path and signature can be checked."
    : "Not elevated: some system programs can't be inspected. Release builds always ask for admin.";
});

invoke("get_snapshot").then((s) => {
  if (s && !state.snap) {
    state.snap = s;
    setLive();
    render();
  }
});
