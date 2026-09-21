import sqlite3
import struct
import socket
import logging
import ipaddress
import subprocess
import platform
import re
import os
import json

from engine.config_loader import config

logger = logging.getLogger("Netlanvas.AutoDiscovery")
DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")

# NET-2: Docker auto-allocates each compose project's bridge network
# sequentially from this exact block (172.17.0.0/16 for the default
# bridge, 172.18.0.0/16 upward for every custom network after it). A
# device's own locally-configured container interfaces can legitimately
# end up in l3_bindings here -- see fingerprinter.py's SNMP_IP_TABLE
# walk, which unification.py's Docker Host classification deliberately
# depends on -- but that's never a real ROUTED LAN segment worth
# actively ping-sweeping. Only applied to the /24 *guess* fallback
# below, never to a router_subnets-confirmed match: a real VLAN that
# genuinely happens to sit in this same RFC1918 block still sweeps
# correctly, since it's caught by the confirmed_match branch first.
DOCKER_BRIDGE_RANGE = ipaddress.ip_network("172.16.0.0/12")

def _detect_default_gateway_windows():
    """
    NATIVE-2: Windows has no /proc/net/route and no `ip` binary --
    `route print -4 0.0.0.0` is the dependency-free equivalent (built
    into every Windows install, no admin rights needed for a read-only
    route query). Multiple default routes are possible (a VPN adapter
    installs its own 0.0.0.0/0 alongside the real one) -- picks the
    LOWEST metric, mirroring `ip route show default`'s own metric-
    sorted output on the Linux path below.
    """
    try:
        proc = subprocess.run(
            ["route", "print", "-4", "0.0.0.0"],
            capture_output=True, text=True, timeout=2,
        )
        candidates = []
        in_table = False
        for line in proc.stdout.splitlines():
            if "Active Routes" in line:
                in_table = True
                continue
            if not in_table:
                continue
            stripped = line.strip()
            if not stripped:
                if candidates:
                    break
                continue
            if stripped.startswith("="):
                continue
            parts = stripped.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gateway = parts[2]
                try:
                    metric = int(parts[4])
                except ValueError:
                    metric = 0
                candidates.append((metric, gateway))
        if candidates:
            candidates.sort(key=lambda c: c[0])
            return candidates[0][1]
    except Exception as e:
        logger.error(f"Failed to parse Windows routing table via 'route print': {e}")
    return None


def _detect_default_gateway_macos():
    """
    NATIVE-8 (macOS): `route -n get default` asks the BSD routing
    subsystem directly for whichever default route the kernel actually
    has selected -- unlike Linux/Windows, this returns exactly one
    resolved answer rather than a full table to sort by metric, so
    there's no candidate-ranking step needed here. Format is BSD
    `route`'s long-standing key/value block, e.g.:

        route to: default
        destination: default
        gateway: 192.168.1.1
        interface: en0
        ...

    Verified live 2026-09-04 against a real Mac (over its own OpenVPN
    tunnel, once the server was fixed to push a route back to the
    querying host) -- `gateway: 192.168.1.1` parsed correctly to
    '192.168.1.1', exactly as this function expects.
    """
    try:
        proc = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=2,
        )
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("gateway:"):
                gateway = stripped.split(":", 1)[1].strip()
                if gateway:
                    return gateway
    except Exception as e:
        logger.error(f"Failed to parse macOS routing table via 'route -n get default': {e}")
    return None


def bind_socket_to_scan_interface(sock) -> None:
    """
    SCOPE-1: SCAN_INTERFACE_OVERRIDE previously only scoped the unicast
    ICMP-sweep + SNMP gateway path (detect_default_gateway() and
    everything downstream of it) -- every BROADCAST/MULTICAST discovery
    socket in the appliance (smart_switch_pipeline.py's SSDP/NSDP
    sweeps, os_fingerprinter.py's SSDP sweep, hostname_discovery.py's
    mDNS reverse lookup) had no interface scoping at all, so the kernel
    picked whatever the box's REAL default route was for outbound
    broadcast/multicast traffic -- the management NIC, never the
    override interface. Confirmed live 2026-09-11 on a multi-homed test
    gateway: real production-LAN devices (two management-network Netgear
    switches) were discovered and logged by an appliance that was
    supposed to be strictly isolated to its own test segment.

    SO_BINDTODEVICE pins a socket to a specific NIC for BOTH send and
    receive, at the kernel level, ahead of normal routing-table
    selection -- the right primitive here, unlike IP_MULTICAST_IF
    (send-side multicast only, doesn't touch broadcast at all) or
    bind()-ing to the interface's own address (doesn't affect
    broadcast/multicast route selection either). Requires
    CAP_NET_RAW, which netlanvas_core's docker-compose.yaml already
    grants for other reasons.

    Linux-only, same scope as SCAN_INTERFACE_OVERRIDE itself; silently
    no-ops everywhere the override is unset -- every existing
    single-NIC install is completely unaffected. Call this on a UDP
    socket right after creating it, before bind()/sendto().
    """
    if platform.system() != "Linux":
        return
    override_iface = str(config._get_setting("SCAN_INTERFACE_OVERRIDE", "") or "").strip()
    if not override_iface:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, override_iface.encode())
    except OSError as e:
        logger.warning(f"Could not bind discovery socket to SCAN_INTERFACE_OVERRIDE ('{override_iface}'): {e} -- this probe may leak onto the wrong network this tick.")


def scan_interface_ip_for_zeroconf() -> list | None:
    """
    SCOPE-1 (continued): python-zeroconf has no SO_BINDTODEVICE
    equivalent -- AsyncZeroconf() takes a list of interface IP
    addresses via its `interfaces=` kwarg instead, defaulting to ALL
    interfaces when omitted (see os_fingerprinter.py's run_mdns_sweep).
    Returns [ip] for that kwarg when SCAN_INTERFACE_OVERRIDE is set and
    currently has an address; None otherwise (caller omits the kwarg,
    preserving today's all-interfaces behavior -- every existing
    single-NIC install is unaffected).
    """
    if platform.system() != "Linux":
        return None
    override_iface = str(config._get_setting("SCAN_INTERFACE_OVERRIDE", "") or "").strip()
    if not override_iface:
        return None
    for entry in enumerate_host_network_interfaces():
        if entry["name"] == override_iface and entry["ipv4"]:
            return [entry["ipv4"]]
    logger.warning(f"SCAN_INTERFACE_OVERRIDE is set to '{override_iface}' but it has no IPv4 address right now -- this tick's mDNS sweep will use the OS's default interface selection instead.")
    return None


def enumerate_host_network_interfaces():
    """
    Real network interfaces on this host -- Linux only so far, matching
    SCAN_INTERFACE_OVERRIDE's own platform scope. Powers the Settings
    page's Polling Source dropdown.

    IMPORTANT: only correct when called from a process that actually
    shares the host's network namespace. In the Docker deployment
    that's netlanvas_core (network_mode: host) -- netlanvas_api sits on
    the isolated netlanvas_internal bridge and would see only its own
    container-internal veth interface if it called this directly (bug
    caught live 2026-09-11: the Settings dropdown showed netlanvas_api's
    own 172.28.x.x bridge address instead of the host's real eth0).
    netlanvas_core publishes the result to Redis (HOST_NETWORK_INTERFACES)
    once per tick specifically so the isolated API container can read
    it instead of ever calling this itself in Docker mode -- see
    main.py's stage_publish_host_identity()-adjacent tick logic and
    api/server.py's /api/settings/network-interfaces, which only calls
    this function directly in native mode (no container isolation
    there at all, so it's already correct).

    NETIF-1 (found 2026-09-16): the docstring above already said "Linux
    only so far" but nothing actually enforced it here -- this function
    unconditionally shelled out to `ip`, so main.py's per-tick
    stage_publish_network_interfaces() called it every single tick on
    every platform, not just Linux. On Windows (confirmed live on a real
    Windows box) that's a FileNotFoundError ([WinError 2]) logged at ERROR
    level every tick, forever -- harmless (falls back to an empty list,
    which native Windows/macOS never even read back out, since
    /api/settings/network-interfaces already gates on Linux before ever
    calling this in native mode too), but pure noise and a wasted
    subprocess-spawn attempt on every single tick. macOS has no `ip`
    binary either, so it would hit the same thing with a different OS
    error string. Guarding here, at the actual source of the Linux
    dependency, closes this for every current and future caller at
    once rather than requiring each call site to remember to check.
    """
    if platform.system() != "Linux":
        return []
    try:
        proc = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True, text=True, timeout=3,
        )
        raw = json.loads(proc.stdout)
    except Exception as e:
        logger.error(f"Failed to enumerate host network interfaces: {e}")
        return []

    interfaces = []
    for entry in raw:
        name = entry.get("ifname", "")
        if name == "lo" or name.startswith(("docker", "veth", "br-")):
            continue
        # SELFGW-2: an interface can legitimately carry MULTIPLE inet
        # addresses at once (a real static/DHCP address alongside a
        # stray 169.254.0.0/16 link-local autoconf one, kernel-assigned
        # whenever an interface comes up before DHCP/static config
        # lands). Taking the first addr_info entry silently picked
        # whichever the kernel happened to list first -- confirmed live
        # 2026-09-11: enp1s0's real 192.168.100.1 was listed SECOND,
        # after a 169.254.x.x link-local entry, so this dropdown was
        # showing the wrong address entirely. Prefer global scope
        # (a real routable address) over link scope; only fall back to
        # a link-local if that's genuinely all the interface has.
        ipv4_entries = [a for a in entry.get("addr_info", []) if a.get("family") == "inet"]
        global_ipv4 = next((a.get("local") for a in ipv4_entries if a.get("scope") == "global"), None)
        ipv4 = global_ipv4 or (ipv4_entries[0].get("local") if ipv4_entries else None)
        interfaces.append({
            "name": name,
            "state": str(entry.get("operstate", "UNKNOWN")).lower(),
            "ipv4": ipv4,
        })
    return interfaces


def resolve_own_interface_mac(ip: str) -> str | None:
    """
    SELFGW-1: `ip` might not be a separate device at all -- it might be
    one of THIS machine's own interface addresses. Happens for real on
    a multi-homed testing appliance deliberately acting as its own
    "router" (see SCAN_INTERFACE_OVERRIDE's design doc): the "gateway"
    detect_default_gateway() resolves is this box's own enp1s0, served
    by its own dnsmasq. resolve_local_arp_mac() can never cover this --
    a machine never ARPs its own address, there's structurally no entry
    for it in the kernel's neighbor table -- and SNMP self-report can't
    either, since the box runs no SNMP agent against itself. Confirmed
    live 2026-09-11: a self-gateway box got stuck permanently logging
    "Could not resolve a MAC for gateway" every tick, forever, since
    neither of ROUTER-1's two signals was ever going to fire.

    Checked FIRST, before either ARP or SNMP get a chance to fail --
    when `ip` is genuinely our own, the interface's own MAC (right in
    `ip -j addr show`'s "address" field) is authoritative and free,
    not a fallback guess.

    NETIF-1 (found 2026-09-16, same underlying gap as
    enumerate_host_network_interfaces() above): the self-gateway
    scenario this exists for (a multi-homed Linux testing-gateway
    appliance acting as its own router) is Linux-only by construction,
    but this function had no platform guard of its own and ran every
    tick on every platform regardless -- confirmed live on a real
    Windows box, one wasted `ip` subprocess-spawn attempt and a caught
    FileNotFoundError per tick, forever. Harmless (falls through to
    the existing ARP/SNMP resolution same as if this returned None
    normally) but pure wasted work with zero chance of ever matching
    on a non-Linux native install.
    """
    if platform.system() != "Linux":
        return None
    try:
        proc = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True, text=True, timeout=3,
        )
        raw = json.loads(proc.stdout)
    except Exception as e:
        logger.debug(f"Failed to check own interfaces for self-gateway match on {ip}: {e}")
        return None

    for entry in raw:
        # SELFGW-2: check EVERY inet address on the interface, not just
        # the first -- an interface can hold a real address alongside a
        # stray link-local one (see enumerate_host_network_interfaces'
        # own comment on this same underlying issue), and `ip` needs to
        # match any of them, not just whichever the kernel lists first.
        own_ipv4s = [a.get("local") for a in entry.get("addr_info", []) if a.get("family") == "inet"]
        if ip in own_ipv4s:
            mac = entry.get("address")
            if mac and _MAC_RE.match(mac):
                return mac.lower()
    return None


def _detect_gateway_for_interface(iface):
    """
    SCAN_INTERFACE_OVERRIDE support (Linux only so far -- see
    detect_default_gateway()): reads the real gateway a specific named
    interface's own DHCP lease advertised, via its own route table
    entry -- NOT the interface's own address. auto_discover_network()
    (pollers/ping_sweeper.py) expects a genuine, SNMP-reachable router
    at whatever IP it's handed, and will persist that IP as a Router
    device; handing it the appliance's own interface address would
    mis-classify the appliance itself as a router on its own topology.

    This works even when that interface's default route was demoted to
    a very high metric specifically so it can never win the box's own
    real default route (see a multi-homed testing-gateway's own network
    config) -- the route still exists, just deprioritized, so it's
    still readable here by explicitly filtering to `dev <iface>`
    instead of asking for "the" system-wide default.
    """
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "show", "dev", iface],
            capture_output=True, text=True, timeout=2,
        )
        for line in proc.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] == "default" and "via" in parts:
                gateway_index = parts.index("via") + 1
                if gateway_index < len(parts):
                    return parts[gateway_index]
    except Exception as e:
        logger.error(f"Failed to read route table for override interface '{iface}': {e}")
    return None


def detect_default_gateway():
    """
    Executes a metric-aware gateway extraction using iproute2.
    Falls back to raw /proc/net/route parsing if the subprocess fails.

    SCAN_INTERFACE_OVERRIDE (Settings > Polling Source, empty by
    default -- every existing install is unaffected): when set, scopes
    discovery to a specific named network interface instead of
    whichever route the OS considers "the" default -- built for
    multi-homed testing-gateway appliances (e.g. one NIC for
    management, a separate isolated NIC for whatever network is
    actually under test). Linux-only for now; other platforms fall
    through to the normal behavior below with a warning logged, same
    as if the override silently failed to resolve anything on Linux.
    """
    override_iface = str(config._get_setting("SCAN_INTERFACE_OVERRIDE", "") or "").strip()
    if override_iface:
        if platform.system() != "Linux":
            logger.warning(f"SCAN_INTERFACE_OVERRIDE ('{override_iface}') is set, but interface-scoped discovery is only supported on Linux so far -- falling back to normal default-gateway detection on this platform.")
        else:
            gw = _detect_gateway_for_interface(override_iface)
            if gw:
                return gw
            logger.warning(f"SCAN_INTERFACE_OVERRIDE is set to '{override_iface}' but no gateway could be found on that interface (no cable connected? nothing serving DHCP on that segment?) -- falling back to normal default-gateway detection this tick.")

    if platform.system() == "Windows":
        return _detect_default_gateway_windows()
    if platform.system() == "Darwin":
        return _detect_default_gateway_macos()

    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=True,
            timeout=2
        )
        
        for line in proc.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                gateway_index = parts.index("via") + 1
                if gateway_index < len(parts):
                    return parts[gateway_index]
                    
    except Exception as e:
        logger.debug(f"Subprocess iproute2 execution failed, falling back to procfs: {e}")

    try:
        with open("/proc/net/route", "r") as f:
            lines = f.readlines()

        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 3 and parts[1] == "00000000":
                gw_hex = parts[2]
                gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                if gw_ip != "0.0.0.0":
                    return gw_ip
    except Exception as e:
        logger.error(f"Failed to dynamically decode routing table via procfs fallback: {e}")

    return None

_MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')


def resolve_local_arp_mac(ip: str) -> str | None:
    """
    ROUTER-1: reads THIS machine's own OS-level ARP/neighbor table for
    `ip` -- works with ZERO cooperation from the target device (no
    SNMP, no LLDP needed), since ARP resolution is a mandatory part of
    IPv4 itself. Any device that has sent even one packet toward `ip`
    already has this entry -- the appliance's own default gateway is a
    near-certainty to already be resolved by the time this runs, since
    routing ANY external request (e.g. the telemetry ping at boot)
    requires ARP-resolving the gateway first. Confirmed live: a real
    router's local-ARP MAC (learned by the OS automatically) and its
    SNMP-self-reported MAC differ, both legitimately -- RouterOS-style
    multi-interface devices genuinely have a distinct MAC per
    interface/VLAN bridge; this one specifically reflects whichever
    interface faces THIS machine.

    Only reliable for a device on the SAME L2 segment as this machine,
    which the appliance's own default gateway always is by
    construction (a routed hop can't be your gateway). Complements
    pollers/fingerprinter.py's SNMP-based resolve_own_mac() -- this
    still works when the target has no SNMP at all; that one still
    works for devices this machine can't directly ARP for.
    """
    try:
        if platform.system() == "Windows":
            proc = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2)
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    mac = parts[1].replace("-", ":").lower()
                    if _MAC_RE.match(mac):
                        return mac
            return None

        if platform.system() == "Darwin":
            # NATIVE-8 (macOS): `arp -n <ip>` prints e.g.
            # "? (192.168.1.1) at 4:f4:1c:f5:88:94 on en0 ifscope [ethernet]"
            # -- notably, BSD arp omits leading zeros per octet (single
            # hex digit where Linux/Windows always show two), so each
            # octet needs zero-padding before it can match _MAC_RE.
            # Verified live 2026-09-04 against a real Mac: a genuine
            # single-digit-octet entry ("a:b2:54:3c:5:d2") correctly
            # zero-padded to "0a:b2:54:3c:05:d2" and matched _MAC_RE,
            # alongside normal double-digit entries and a graceful
            # None for an invalid/absent IP.
            proc = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=2)
            m = re.search(r'\bat\s+([0-9a-fA-F:]+)\s+on\b', proc.stdout)
            if m:
                octets = m.group(1).split(":")
                if len(octets) == 6:
                    mac = ":".join(o.zfill(2) for o in octets).lower()
                    if _MAC_RE.match(mac):
                        return mac
            return None

        with open("/proc/net/arp", "r") as f:
            next(f, None)  # header row
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].lower()
                    if mac != "00:00:00:00:00:00" and _MAC_RE.match(mac):
                        return mac
    except Exception as e:
        logger.debug(f"Local ARP lookup failed for {ip}: {e}")
    return None


def discover_active_subnets():
    """
    Queries the database for all logged IP addresses and groups them
    into subnets to feed the active ping sweeps.

    NET-1: uses the router's own confirmed subnet size (router_subnets,
    populated by pollers/vlan_registry.py's discover_router_vlan_subnets
    from each router's real ipAdEntNetMask) wherever an IP falls inside
    one, instead of always assuming /24. A /24 assumption is only ever
    wrong in one direction that matters here -- undersized, it would
    under-sweep a real subnet the router says is larger (e.g. missing
    a /23's second half); oversized, it just wastes a bit of scan time
    on addresses outside the real range. Falls back to the /24 guess
    only for IPs with no router-confirmed subnet at all, which is most
    of them (router_subnets only covers the router's own direct
    interfaces) -- this is a strict accuracy improvement layered on top
    of the existing behavior, not a replacement for it.
    """
    subnets = set()
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT ip_address FROM l3_bindings WHERE ip_address IS NOT NULL AND is_public = 0")
        records = cursor.fetchall()

        confirmed_networks = []
        try:
            cursor.execute("SELECT subnet FROM router_subnets")
            for (subnet_str,) in cursor.fetchall():
                try:
                    confirmed_networks.append(ipaddress.ip_network(subnet_str, strict=False))
                except ValueError:
                    continue
        except sqlite3.OperationalError:
            pass  # router_subnets may not exist yet on a brand-new DB before the first deep-scan
        conn.close()

        for (ip,) in records:
            if ip.startswith("169.254.") or ip.startswith("127."):
                continue

            try:
                ip_obj = ipaddress.IPv4Address(ip)
                if not ip_obj.is_private:
                    continue
            except ValueError:
                continue

            confirmed_match = next((net for net in confirmed_networks if ip_obj in net), None)
            if confirmed_match:
                subnets.add(str(confirmed_match))
                continue

            if ip_obj in DOCKER_BRIDGE_RANGE:
                continue

            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                derived_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                subnets.add(derived_subnet)

    except Exception as e:
        logger.error(f"Error extracting subnets from database ledger: {e}")

    return list(subnets)
