# NetWatch

A live security dashboard for Windows that shows every incoming and outgoing
network connection on your PC, which program owns it, and whether anything
looks suspicious.

NetWatch only watches. It never blocks, kills or changes anything.

## Features

- **Live connection table**: TCP and UDP, IPv4 and IPv6, with the owning
  program, its digital signature and its full path, refreshed every 1.5 s.
- **Service names**: shared hosts like `svchost.exe` show the Windows service
  that owns each connection, e.g. `svchost.exe (Windows Update)`.
- **Real hostnames**: names come from Windows' own DNS lookups (via the
  DNS-Client ETW provider), so cloud and CDN addresses show the site that was
  actually requested instead of a blank. Reverse DNS is the fallback.
- **Threat intelligence**: remote addresses are matched against public
  blocklists (see [Data sources](#data-sources)), refreshed automatically.
- **Detections and alerts**:
  - contact with a listed host
  - unsigned or invalid-signature programs using the network
  - programs running from Temp, Downloads, Public or the Recycle Bin
  - connections to ports used by backdoors, remote-control tools, IRC or Tor
  - risky services (RDP, VNC, Telnet) exposed on all interfaces
  - **VPN leaks**: public traffic leaving through another adapter while a VPN
    tunnel is up
  - programs and listening ports that are new since the first run
- **Devices on your network**: every device this PC sees on the local network
  (read passively from Windows' neighbor table, never through the VPN tunnel),
  with its manufacturer from the IEEE MAC registry. Phones that use private,
  randomized MAC addresses are marked as such. Devices that join after the
  first run raise an alert.
- **Geolocation and ownership**: country and network owner (ASN) for every
  public address.
- **History**: 30 days of connections in a local SQLite database, searchable.
- **Rules**: trust programs or label and trust addresses to cut noise.

## Requirements

- Windows 10 or 11
- [Rust](https://rustup.rs) with the MSVC toolchain (Visual Studio Build Tools)
- Microsoft Edge WebView2 Runtime (preinstalled on Windows 11)

NetWatch asks for administrator rights when it starts. It needs them to read
every program's path and signature and to capture DNS lookups.

## Build and run

```powershell
cd src-tauri
cargo build            # debug build: target\debug\netwatch.exe
cargo build --release  # optimized build: target\release\netwatch.exe
cargo test             # some tests need an elevated shell and skip otherwise
```

To build an installer, install the Tauri CLI (`cargo install tauri-cli`) and
run `cargo tauri build`.

## Where data is stored

Everything stays on your PC, in `%LOCALAPPDATA%\com.netwatch.dashboard\`:

- `netwatch.db`: connection history, devices, alerts and your rules
- `intel\`: downloaded blocklists, geolocation and manufacturer databases

The only network requests NetWatch makes itself are the downloads of the data
sources below.

## Data sources

NetWatch downloads these at runtime; none of the data is included in this
repository. Each source has its own terms of use, which you are responsible
for following.

| Source | Used for |
|---|---|
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet command-and-control servers |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Networks controlled by criminals |
| [Emerging Threats](https://rules.emergingthreats.net/) | Known compromised hosts |
| [CINS Army](https://cinsscore.com/) | Known attackers and scanners |
| [Tor Project](https://check.torproject.org/torbulkexitlist) | Tor exit nodes |
| [DB-IP Lite](https://db-ip.com/db/lite.php) | Country and ASN geolocation |
| [IEEE MA-L registry](https://standards-oui.ieee.org/) | Device manufacturers from MAC addresses |

IP geolocation by [DB-IP](https://db-ip.com), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## License

[MIT](LICENSE)
