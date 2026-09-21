import asyncio
import logging
import ipaddress
import os
import platform
import sqlite3
from pysnmp.hlapi.v3arch.asyncio import *
from engine.auto_discovery import detect_default_gateway, resolve_local_arp_mac, resolve_own_interface_mac
from engine.config_loader import config as global_config
from engine.snmp_adapter import get_working_credential
from engine.snmp_credential import SNMPVersion
from engine.pysnmp_credential_adapter import to_pysnmp_auth_data
from pollers.fingerprinter import resolve_own_mac
logger = logging.getLogger("Netlanvas.ARPSweeper")

# NATIVE-2 (Windows) / NATIVE-10 (macOS): no vetted third-party fping
# port exists for either platform (same reasoning as WIN-9's
# snmp_helper) -- tools/ping_sweep_helper builds a small Go binary per
# platform (Windows: IcmpSendEcho via iphlpapi.dll; macOS: unprivileged
# ICMP via golang.org/x/net/icmp's udp4 mode, confirmed live against
# real Apple Silicon hardware), the same non-privileged mechanism each
# OS's own ping tool uses. Default path assumes the repo layout during
# dev/testing; packaging will point this at wherever PyInstaller
# actually bundles it and should set the env var rather than relying
# on this fallback.
PING_SWEEP_HELPER_PATH = os.getenv(
    "NETLANVAS_PING_SWEEP_HELPER",
    os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "tools", "ping_sweep_helper",
        "netlanvas_ping_sweep.exe" if platform.system() == "Windows" else "netlanvas_ping_sweep",
    )),
)

# MEM-1: was previously instantiated fresh inside auto_discover_network()
# on every call -- and that function runs every tick via
# stage_active_ping_sweeps() (not gated to deep-scans), so a brand new
# SnmpEngine was being created every ~2 minutes, for hours, and never
# closed. Confirmed live: netlanvas_core's RSS grew unboundedly over a
# session, degrading tick duration enough to push it past
# OFFLINE_GRACE_SECONDS and cause synchronized false "device offline"
# alerts across unrelated devices. pysnmp's SnmpEngine sets up its own
# transport dispatcher hooked into the event loop -- a genuinely heavy
# object meant to be created once and reused, exactly like
# lldp_scraper.py's own module-level instance already does. One shared
# instance for the process lifetime, not one per call.
snmp_engine = SnmpEngine()

def _persist_local_arp_bindings(ip_mac_pairs):
    """
    NOARP-1 (2026-09-04): the ping-sweep-alive-but-no-MAC gap. ICMP alone
    was always known to reveal no MAC (see run_ping_sweeper's own
    ALERT-5 comment below) -- but the fix assumed then was "needs
    ARP-cache-scrape [i.e. stage_arp_scrape's SNMP walk] or another
    discovery source", missing that this machine's own OS ARP table is
    already a valid, zero-cooperation source for any L2-adjacent device
    (the kernel populates it automatically after any successful ping,
    standard IPv4 behavior -- exactly what resolve_local_arp_mac()
    already reads for the gateway's own IP, just never generalized to
    every OTHER alive IP the sweep finds).

    Confirmed live: on a network whose router has no working SNMP
    credential, stage_arp_scrape's entire MAC-resolution mechanism
    (SNMP ARP-table walk + SNMP self-report) produces nothing at all --
    the gateway gets a MAC via its own hardcoded local-ARP special case,
    but every other real device the ping sweep finds alive (confirmed:
    "L3 Sweep Complete. 4 routed endpoints responded" every single
    tick) never gets promoted into a tracked node, since nothing else
    in the pipeline resolves a MAC for a non-infrastructure IP without
    SNMP. This is a systemic gap, not an edge case -- most home routers
    don't run SNMP at all.

    Only ever CREATES a row for an IP genuinely new to l3_bindings (an
    IP already tracked via a stronger source like ROUTER_ARP_CACHE or
    GATEWAY_SELF_REPORT is left alone -- this is a last-resort fallback,
    not meant to override a better signal).
    """
    if not ip_mac_pairs:
        return 0
    conn = sqlite3.connect(global_config.DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    created = 0
    try:
        for ip, mac in ip_mac_pairs:
            conn.execute('INSERT INTO l2_interfaces (mac_address) VALUES (?) ON CONFLICT(mac_address) DO NOTHING', (mac,))
            cursor = conn.execute(
                "INSERT INTO l3_bindings (ip_address, mac_address, discovery_source, last_seen) "
                "VALUES (?, ?, 'LOCAL_ARP_ICMP', CURRENT_TIMESTAMP) "
                "ON CONFLICT(ip_address) DO NOTHING",
                (ip, mac),
            )
            created += cursor.rowcount
        conn.commit()
    finally:
        conn.close()
    return created


def _persist_gateway_self_binding(router_ip, mac):
    conn = sqlite3.connect(global_config.DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        conn.execute('INSERT INTO l2_interfaces (mac_address) VALUES (?) ON CONFLICT(mac_address) DO NOTHING', (mac,))
        conn.execute('''
            INSERT INTO l3_bindings (ip_address, mac_address, discovery_source, last_seen)
            VALUES (?, ?, 'GATEWAY_SELF_REPORT', CURRENT_TIMESTAMP)
            ON CONFLICT(ip_address) DO UPDATE SET
                mac_address=excluded.mac_address,
                discovery_source=excluded.discovery_source,
                last_seen=CURRENT_TIMESTAMP
        ''', (router_ip, mac))
        conn.commit()
    finally:
        conn.close()


async def auto_discover_network(router_ip):
    discovered_subnets = set()
    router_interfaces = set()
    logger.info(f"Zero-Touch: Mapping network architecture via gateway ({router_ip})...")

    # ROUTER-1: resolve and persist the gateway's OWN identity first,
    # before anything below that depends on SNMP even being available.
    # Every OTHER mechanism in this appliance discovers a device
    # INDIRECTLY -- out of some other device's ARP table, LLDP
    # neighbor table, or switch FDB -- and a device can never appear
    # in its own. Confirmed live: a fully SNMP-reachable router was
    # never once created as an l3_bindings row by anything, because
    # nothing else in the pipeline ever tries. Two independent
    # signals, either is sufficient on its own:
    #   1. This machine's own OS-level ARP table (needs zero
    #      cooperation from the router -- works with no SNMP, no LLDP
    #      at all, since ARP is mandatory IPv4, not an opt-in feature).
    #   2. The router's own SNMP self-report (ifPhysAddress/
    #      ipAdEntIfIndex -- works even when this machine isn't
    #      L2-adjacent to the router, which local ARP can't cover).
    # SELFGW-1: checked before either of those -- `router_ip` might be
    # one of THIS machine's own interface addresses (a multi-homed
    # appliance acting as its own gateway), which neither ARP nor SNMP
    # self-report can ever resolve, since a device never ARPs itself
    # and won't SNMP-query itself either. See resolve_own_interface_mac's
    # own docstring.
    own_mac = resolve_own_interface_mac(router_ip) or resolve_local_arp_mac(router_ip)
    credential = await get_working_credential(router_ip)
    if not own_mac and credential is not None:
        try:
            own_mac = await resolve_own_mac(router_ip)
        except Exception as e:
            logger.debug(f"SNMP self-report MAC resolution failed for gateway {router_ip}: {e}")
    if own_mac:
        try:
            _persist_gateway_self_binding(router_ip, own_mac)
        except Exception as e:
            logger.error(f"Failed to persist gateway self-binding for {router_ip}: {e}")
    else:
        logger.warning(f"Could not resolve a MAC for gateway {router_ip} via local ARP or SNMP -- it will not appear as a node until one succeeds.")

    # get_working_credential() now returns an SNMPCredential, not a
    # bare string -- this used to pass that value straight into
    # CommunityData(community, mpModel=1), which broke ("cannot convert
    # 'SNMPCredential' object to bytes") the moment that return type
    # changed. Uses the same shared translator as lldp_scraper.py
    # rather than duplicating the logic -- see punch list SNMP-3.
    # v2c keeps the original's mpModel=1-only choice (no v1 fallback
    # attempted here -- this is a single best-effort auxiliary
    # discovery step, not the main credential-resolution path). v3
    # uses whatever protocol pairing was already resolved and cached
    # for this IP.
    if credential is None:
        logger.warning(f"No credential available for gateway {router_ip} -- skipping SNMP-based subnet discovery.")
        return [], [router_ip]
    if credential.version == SNMPVersion.V2C:
        auth_data = to_pysnmp_auth_data(credential, mp_model=1)
    else:
        auth_data = to_pysnmp_auth_data(credential)
    if auth_data is None:
        logger.warning(f"Could not build a usable SNMP credential for gateway {router_ip} -- skipping SNMP-based subnet discovery.")
        return [], [router_ip]

    try:
        target = await UdpTransportTarget.create((router_ip, 161), timeout=2.0, retries=2)
        mask_oid = ObjectType(ObjectIdentity('1.3.6.1.2.1.4.20.1.3'))
        iterator = walk_cmd(snmp_engine, auth_data, target, ContextData(), mask_oid, lexicographicMode=False)
        async for errorIndication, errorStatus, errorIndex, varBinds in iterator:
            if errorIndication or errorStatus: break
            for varBind in varBinds:
                oid = varBind[0].prettyPrint()
                mask = varBind[1].prettyPrint()
                ip_address = ".".join(oid.split('.')[-4:])
                if ip_address.startswith("127.") or mask in ["0.0.0.0", "255.255.255.255"]: continue
                try:
                    ip_obj = ipaddress.IPv4Address(ip_address)
                    if ip_obj.is_private or ip_obj.is_link_local:
                        network = ipaddress.IPv4Network(f"{ip_address}/{mask}", strict=False)
                        discovered_subnets.add(str(network))
                except ValueError: pass
                router_interfaces.add(ip_address)
        return list(discovered_subnets), list(router_interfaces)
    except Exception as e:
        logger.error(f"Network discovery interrogation failed: {e}")
        return [], [router_ip]
async def fping_sweep(subnet):
    if platform.system() in ("Windows", "Darwin"):
        # NATIVE-10: macOS joins Windows on the bundled-helper path here
        # -- fping isn't part of base macOS (Homebrew-only), so the
        # Linux branch below isn't available on a real native macOS
        # install either, same reasoning as Windows never having it.
        # Same output contract for both (one alive IP per stdout line)
        # -- see PING_SWEEP_HELPER_PATH's comment.
        proc = await asyncio.create_subprocess_exec(
            PING_SWEEP_HELPER_PATH, subnet,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return [ip.strip() for ip in stdout.decode().splitlines() if ip.strip()]

    # Execute highly concurrent C-based ICMP blast to prime downstream gateway caches
    proc = await asyncio.create_subprocess_exec(
        "fping", "-a", "-g", "-q", "-r", "1", "-i", "1", "-t", "200", subnet,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await proc.communicate()
    return [ip.strip() for ip in stdout.decode().splitlines() if ip.strip()]
async def run_ping_sweeper(override_subnets=None):
    router_ip = detect_default_gateway() or global_config.GATEWAY_IP
    if not router_ip:
        logger.warning("No default gateway detected dynamically or in config. Aborting sweep.")
        return 0
    discovered_subnets, _ = await auto_discover_network(router_ip)
    if not discovered_subnets:
        # auto_discover_network()'s subnet expansion only works when the
        # gateway itself is a real, SNMP-reachable router -- it was
        # never designed for a gateway with no SNMP agent at all (a
        # consumer router with SNMP disabled, or -- the case this was
        # actually caught against, 2026-09-11 -- a multi-homed testing
        # appliance acting as its own gateway via a plain DHCP server,
        # which obviously runs no SNMP service on itself). Previously,
        # a total SNMP failure meant zero subnets got swept, full stop
        # -- not even a plain ICMP sweep, which needs no cooperation
        # from the gateway at all. Falling back to a same-shape /24
        # guess around the gateway's own IP (matching
        # discover_active_subnets()'s own fallback for any IP with no
        # router-confirmed subnet) is a safe floor: worse than a real
        # SNMP-confirmed subnet size, never worse than sweeping nothing.
        ip_parts = router_ip.split('.')
        if len(ip_parts) == 4:
            fallback_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            discovered_subnets = [fallback_subnet]
            logger.info(f"No SNMP-confirmed subnets from gateway {router_ip} -- falling back to a /24 ICMP sweep around it ({fallback_subnet}).")
    merged_subnets = list(set(discovered_subnets + (override_subnets or [])))
    if not merged_subnets:
        return 0
    logger.info(f"L3 Ghost Hunter active. Stimulating remote gateways across {len(merged_subnets)} subnets via ICMP...")
    tasks = [fping_sweep(subnet) for subnet in merged_subnets]
    results = await asyncio.gather(*tasks)
    alive_ips = [ip for sublist in results for ip in sublist]
    total_alive = len(alive_ips)
    logger.info(f"L3 Sweep Complete. {total_alive} routed endpoints responded. Hardware ARP caches primed for Step 35 extraction.")

    # ALERT-5: refresh l3_bindings.last_seen for every IP that answered
    # ICMP this tick -- direct proof of reachability, and this sweep
    # already runs every tick (not gated to deep-scans), covering the
    # exact same subnets stage_arp_scrape does. Confirmed live as a
    # real gap: stage_arp_scrape can only ever refresh an IP that
    # appears INSIDE some OTHER device's ARP table -- a device never
    # ARPs for its own address, so a router's (or any L3 device's) own
    # interface IPs structurally never get refreshed that way. That
    # gap was the root cause of a router repeatedly, falsely alerting
    # "critical offline" for several minutes at a time overnight,
    # non-simultaneously across two otherwise-identical instances
    # watching the same physical router -- each host's false read was
    # tied to its own deep-scan phase rather than any real outage.
    # Only updates EXISTING rows (ip_address already known) -- ICMP
    # alone reveals no MAC address, so a genuinely new/unknown IP still
    # needs ARP-cache-scrape or another discovery source to create its
    # l3_bindings row in the first place; this can't and shouldn't try.
    if alive_ips:
        conn = sqlite3.connect(global_config.DB_PATH)
        try:
            conn.executemany(
                "UPDATE l3_bindings SET last_seen = CURRENT_TIMESTAMP WHERE ip_address = ?",
                [(ip,) for ip in alive_ips],
            )
            conn.commit()
        finally:
            conn.close()

    # NOARP-1: the comment above was only half right -- ICMP alone
    # reveals no MAC, but this machine's own OS ARP table (freshly
    # primed by the sweep that just ran) often already has one for any
    # L2-adjacent device, with zero cooperation needed from the target
    # (see resolve_local_arp_mac's own docstring -- the same mechanism
    # already used for the gateway's own IP, generalized here to every
    # other alive IP). Confirmed live as a systemic gap on any network
    # whose router has no working SNMP credential: stage_arp_scrape's
    # entire MAC-resolution mechanism (SNMP ARP-table walk + SNMP
    # self-report) produces nothing at all, so a device that only ever
    # answers ICMP -- true for most consumer routers, phones, laptops
    # -- was never promoted into a tracked node, no matter how many
    # ticks passed. Deliberately last-resort and additive only: a
    # stronger discovery source (ROUTER_ARP_CACHE, GATEWAY_SELF_REPORT)
    # is never overwritten (see _persist_local_arp_bindings' own
    # ON CONFLICT DO NOTHING), and this only ever runs for IPs ICMP
    # itself just proved are alive right now.
    if alive_ips:
        resolved = await asyncio.gather(
            *(asyncio.to_thread(resolve_local_arp_mac, ip) for ip in alive_ips)
        )
        new_pairs = [(ip, mac) for ip, mac in zip(alive_ips, resolved) if mac]
        if new_pairs:
            created = await asyncio.to_thread(_persist_local_arp_bindings, new_pairs)
            if created:
                logger.info(f"[NOARP-1] Local ARP resolution created {created} new l3_binding(s) for ICMP-alive device(s) with no other discovery source.")

    return total_alive
