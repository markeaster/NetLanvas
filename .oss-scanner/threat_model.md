# Threat model

## What this project does and where untrusted input enters
NetLanvas is a self-hosted network monitoring and topology-mapping appliance
for home and small-business networks. It runs continuously on a box the
owner controls (Raspberry Pi, a small server, or a native Windows/macOS
install) and builds a live map of devices on the local network.

Untrusted input enters mainly from the network being monitored, not from
end users. This build (the Dockerfile builds and runs on Linux) uses the
system `fping`/net-snmp CLI tools directly; `tools/ping_sweep_helper` and
`tools/snmp_helper` are Go binaries used ONLY on the Windows and macOS
native ports respectively (see their own `//go:build windows` /
`//go:build darwin` tags) -- they are out of scope for this build since
they never run on Linux. Treat the Python code below as the real
network-input-parsing surface here:
- **SNMP polling** (`src/engine/snmp_adapter.py`, `src/engine/snmp_pipeline.py`,
  `src/pollers/snmp_default_community_detector.py`,
  `src/pollers/vlan_registry.py`, `src/pollers/lldp_scraper.py`,
  `src/pollers/fingerprinter.py`, `src/snmp_dump.py`) -- these shell out to
  `snmpget`/`snmpwalk` and parse the text output (sysDescr, interface
  tables, FDB/ARP tables, LLDP neighbors, etc.) from switches, routers and
  other managed devices. Any SNMP-speaking device on the network is an
  untrusted input source here -- this is probably the single highest-value
  target in the repo on this platform.
- **ARP/ICMP discovery and ping sweeps** (`src/pollers/ping_sweeper.py`) --
  parses the output of the system `fping` binary. Any device on the LAN
  shapes what gets parsed here.
- **Device banners / HTTP headers / mDNS / zeroconf responses** picked up
  during discovery and stored in the SQLite database, then later rendered
  in the web UI (`src/` -- FastAPI backend, templated/JS frontend).
- **The web UI and API** (`src/api/server.py` and friends) -- an
  authenticated admin interface (argon2 password hashing, see
  `src/security/auth.py`), but still a meaningful surface: settings
  upload/import, device-credential storage (`src/security/credential_vault.py`
  encrypts stored SNMP/switch credentials at rest), and the Time Machine
  archive feature which loads arbitrary past-captured SQLite database files.
- **`settings.yaml` / config parsing** (PyYAML) -- local file, lower
  priority than the network-facing surfaces above but still worth a look
  for unsafe loading patterns.

## Components that matter most / least
- **Highest priority:** the SNMP/ping-output parsing code listed above
  under `src/engine/` and `src/pollers/` -- untrusted network input flows
  directly into Python here. `tools/ping_sweep_helper` and
  `tools/snmp_helper` are Windows/macOS-only (see above) and not part of
  this build; they're a secondary concern to flag separately if ever
  scanned on those platforms, but out of scope for this Linux image.
- **High priority:** `src/security/` (auth, credential vault, TLS cert
  manager) and anything in `src/api/` that is reachable without
  authentication -- check `src/middleware.py`'s `UNAUTHENTICATED_API_PATHS`
  for the exact unauthenticated surface.
- **Medium priority:** the rest of the FastAPI backend and the device
  discovery/classification logic in `src/` generally.
- **Lower priority but still in scope:** the web frontend (XSS from stored
  device data rendered in the UI is a real concern given untrusted
  banners/hostnames get stored and displayed).
- **Out of scope:** anything not in this repository. The production
  telemetry *server* (PHP, receives anonymized install telemetry) lives in
  a separate private repository and is not part of this checkout -- only
  the client-side telemetry code that ships in this repo is in scope.
  `tools/demo-video/` and other packaging/release scripts are not
  security-relevant and are low priority.

## How to exercise it
- There is no automated test suite in this repository yet. The Dockerfile's
  build step (`python -m compileall`) only confirms the Python source
  parses; it does not exercise runtime behavior.
- The SNMP/ping parsing functions in `src/engine/` and `src/pollers/` can
  be exercised directly by feeding them crafted `snmpget`/`snmpwalk`/
  `fping` output text (they parse subprocess stdout, not raw sockets
  themselves, on this platform) without needing the full application
  running.
- The FastAPI app can be started with `python src/main.py` once
  dependencies are installed; it listens on a local port and serves both
  the API and the web UI.

## How you rate severity
- Command/argument injection into the `snmpget`/`snmpwalk`/`fping`
  subprocess calls (e.g. via a device-supplied community string, OID, or
  hostname that isn't properly escaped before being passed to
  `subprocess`) is **critical** -- it would let a single device on the LAN
  run arbitrary commands on the appliance.
- A parsing bug in the SNMP/ping output handlers that crashes the process
  or corrupts stored data, triggerable by any device on the LAN, is
  **high** (even without a working PoC -- this is an appliance meant to run
  unattended).
- Authentication bypass or privilege escalation in the web UI/API is
  **critical**.
- Credential exposure (device SNMP/switch credentials from the vault, or
  the TLS private key) is **high**.
- Stored XSS via device-supplied data (hostname, banner, SNMP sysDescr,
  etc.) rendered in the UI is **high** given it would let one compromised
  or spoofed LAN device attack the admin viewing the dashboard.
- Denial of service in the discovery/polling paths is **medium** -- this is
  a monitoring tool, not safety-critical control infrastructure, but it
  does run unattended and a crash loop would be a real operational
  problem for self-hosters.
- Issues requiring an already-authenticated admin session to trigger
  (e.g. a config-upload path only an authenticated user can reach) are
  capped at **medium** unless they also break out of the admin's own
  intended privileges.

## Anything to leave alone
- Nothing known at this time. If the scanner finds something in
  `tools/demo-video/` or other build/release tooling, treat it as very
  low priority -- those scripts run only on maintainer-controlled build
  machines, never on a user's appliance.
