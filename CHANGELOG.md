# Changelog

All notable changes to NetLanvas's appliance/client are recorded here,
newest first.

This file starts fresh as of the public open-source release. NetLanvas
has been in development and use since 2026, and the current release
reflects that history, but earlier internal change history isn't
included here.

## Unreleased

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
