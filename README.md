# NetLanvas

Self-hosted network discovery and mapping for your own LAN. Nothing about
your network — device inventory, SNMP credentials, topology — ever leaves
the box.

## What it does

NetLanvas runs on your own hardware (a Raspberry Pi, a NAS, a spare box —
anywhere Docker runs, or natively on Windows/macOS) and continuously builds
a live picture of your network:

- **Discovery** — ARP, LLDP, mDNS, DHCP, and active ping sweeps combine to
  find devices the moment they show up, with no manual entry required.
- **Topology mapping** — a live, force-directed map of how everything on
  your network actually connects, including switches and multi-interface
  hosts.
- **Device fingerprinting** — OS detection, web-server detection, vendor
  identification (OUI), and WiFi client visibility on supported access
  points.
- **VLAN and subnet awareness** — reads switch/router VLAN registries and
  groups devices accordingly, instead of treating your network as one flat
  segment.
- **Security scanning** — flags default SNMP community strings and
  public SNMP exposure on your own devices, so misconfigurations don't sit
  unnoticed.
- **Alerting** — configurable notifications when devices join, leave, or
  change in ways you care about.
- **History** — a time-machine view of what your network looked like at
  any point in the past, not just right now.

## Architecture: what's in this repo, and what isn't

This repository is the **appliance** — everything that runs on your own
device, entirely open source (Apache 2.0). It's the whole reason this repo
exists: the "nothing leaves the box" claim above shouldn't have to be taken
on faith, so the code that decides what happens to your network data is
published and auditable.

NetLanvas also offers optional account-based features (device sync across
installs, premium vendor classification, and similar). The server that
backs those features — accounts, entitlement, payment — is **not** in this
repository and stays closed source, deliberately: that's where the actual
enforcement of paid features and protection of account data lives, and
keeping that server-side and private is a security decision, not a
convenience one. Using NetLanvas itself does not require an account or any
of that infrastructure — the appliance is fully functional standalone.

## Quick start

```bash
git clone https://github.com/markeaster/NetLanvas.git
cd NetLanvas
cp .env.example .env      # adjust as needed
docker compose -f docker-compose.dist.yaml up -d
```

Then open `https://<this-machine>:8899` in a browser.

Pre-built multi-arch images (`amd64`/`arm64`) are published to
`netlanvas.com/netlanvas:latest`, which is what the command above
actually pulls — there's nothing else to configure.

Windows and macOS native installers are available from the
[Install page](https://netlanvas.com/install.html) for platforms where
Docker isn't the preferred fit.

## Platforms

- Linux (Docker) — recommended, most tested
- Windows — native installer
- macOS — native installer

## License

Apache 2.0 — see [LICENSE](LICENSE). You're free to run, modify, and fork
this. The `NetLanvas` name and logo are not covered by the code license —
see the license's trademark clause.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Links

- [netlanvas.com](https://netlanvas.com)
- [Blog](https://netlanvas.com/blog)
