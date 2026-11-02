# Changelog

All notable changes to NetLanvas's appliance/client are recorded here,
newest first.

This file starts fresh as of the public open-source release. NetLanvas
has been in development and use since 2026, and the current release
reflects that history, but earlier internal change history isn't
included here.

## v3.30.3 - 2026-11-02

### Fixed

- A device wired directly into a router port (no switch in between)
  could render as a disconnected node instead of showing a real edge
  into the router. Three compounding bugs: an SNMP walk spanning
  several merged bridge instances could come back with entries
  slightly out of order, which the SNMP client treated as a fatal
  error and discarded the whole table instead of tolerating it; a
  never-before-seen router port got an unconditional "this must be
  backbone" penalty the instant it was seen at all, with no check
  against actual traffic fan-out or the device's other known
  locations; and a switch/router's own bridge table can list its own
  interface's MAC as a "self" entry on its own port, inflating that
  port's apparent device count and wrongly re-triggering the previous
  bug's penalty. All three fixed.
- Windows uninstall could hang for hours if the app's shutdown wedged
  (the uninstaller's own stop step had no timeout of its own), or
  could bring the service right back a few seconds after removing it
  (force-killing it made Windows' Service Control Manager treat that
  as a crash and restart it). Both fixed.
- Clicking into a device's detail page while viewing a Time Machine
  archive could silently show the wrong device's data -- that one
  endpoint had never been taught to respect archive mode the way the
  rest of the app already does.
- The passive listener for D-Link's discovery protocol could bind to
  every network interface instead of scoping itself the way every
  other discovery listener already does, and now drops packets
  arriving from outside its own subnet.
- A routine log line describing a detected switch could collide with
  the Community Telemetry backend's own injection-detection heuristic,
  causing that submission to be rejected as malicious content on
  affected installs. Fixed; no security check was weakened.

## v3.30.0 - 2026-10-06

### New

- **Credential recovery** for the native (Windows/macOS) app: if you
  forget your admin username or password, a one-time recovery token
  can be generated and read from a local file that only someone with
  access to the machine itself can see -- no email address or cloud
  account required. The native app can even fetch the token for you
  directly, since reaching that page at all already proves you're on
  the same machine.
- **Multi-Site Inventory Sync**: securely sync network inventory data
  between separate NetLanvas instances (for example, across multiple
  sites), gated behind an explicit "Site Stamp" confirmation so
  nothing leaves the appliance without you opting in first.
- Device discovery now recognizes D-Link's proprietary discovery
  protocol (DDP) as a passive listener, alongside the existing
  SSDP/SNMP/mDNS methods.

### Fixed

- A broad set of topology-accuracy and stability fixes: stale ARP
  entries now retire reliably instead of lingering after a device
  goes offline, multi-homed devices no longer fan out into duplicate
  entries in a couple of previously-missed views, and the Windows
  installer handles a few edge cases (stale version strings, a
  stuck data-wipe uninstall step) more robustly.

## v3.20.1 - 2026-09-22

- Initial public release of the appliance/client source, under Apache
  2.0.
- Inference of a likely wireless access point on a network segment from
  its clients, when the access point itself doesn't answer SNMP directly.
- Smart-switch classification for budget/managed switches that only speak
  bare SNMP (no BRIDGE-MIB/LLDP), alongside the existing SSDP-based path.
- Fixed stale data lingering indefinitely in a few places: ARP-cache-
  sourced records, smart-switch suggestions, and fully-orphaned topology
  nodes (a device removed from the network) now all age out and clear
  themselves automatically instead of sitting forever.
- Fixed a topology display bug where a device owning more than one IP
  address (for example, a Docker host with its own internal bridge
  network) could be miscounted or shown more than once in the network
  diagram.
- Fixed a false positive in hidden-switch detection triggered when a
  Wi-Fi access point's own wireless clients legitimately shared its
  single wired uplink port.
- DHCP-based hostname discovery now works on native Windows installs
  (previously Linux/Docker only).
- Enabled full CodeQL static analysis (Go, Python, JavaScript/TypeScript)
  against this repository via an advanced-setup workflow, since GitHub's
  automatic setup couldn't build this repo's Go modules. See
  [`CODE_SCANNING_REVIEW.md`](CODE_SCANNING_REVIEW.md) for the full
  results and reasoning.
- Fixed: the DHCP-sniffing poller didn't honor a configured
  `SCAN_INTERFACE_OVERRIDE` the way every other discovery mechanism
  already did, so it could capture broadcast traffic on interfaces
  outside the intended scan scope. Found via the CodeQL run above.
