import sqlite3
import re
import logging
import ipaddress
from engine.config_loader import config
from engine.snmp_adapter import get_working_credential, run_snmp_command

logger = logging.getLogger("Netlanvas.VLANRegistry")

IFDESCR_OID = "1.3.6.1.2.1.2.2.1.2"
IP_AD_ENT_IFINDEX_OID = "1.3.6.1.2.1.4.20.1.2"
IP_AD_ENT_NETMASK_OID = "1.3.6.1.2.1.4.20.1.3"

# A router-reported ipAdEntNetMask is untrusted input (CWE-918): a
# forged/compromised device can claim an arbitrarily broad netmask
# (e.g. 128.0.0.0) paired with a private-looking host IP, which
# ipaddress.ip_network(..., strict=False) will happily AND down into a
# network far broader than any real LAN -- and router_subnets feeds
# straight into auto_discovery.py's ping-sweep targeting (NET-1), so an
# oversized entry here turns into a network-wide (or internet-wide)
# sweep. /32 is always accepted regardless of this bound -- see the
# docstring below, a genuine WAN/PPPoE interface can legitimately
# report a /32 that's a public IP, but a /32 can never match more than
# its own single address, so it carries no sweep-breadth risk. Anything
# broader than /32 must both be reported against a private/link-local
# host IP AND meet this minimum prefix length -- a /16 (65536 addresses)
# is already generous for any real LAN segment seen in this codebase
# (every plain internal interface confirmed live is /24; NET-2's own
# Docker bridge block is /16-per-project).
MIN_ROUTER_SUBNET_PREFIXLEN = 16

# Same pattern already proven in snmp_pipeline.py's step_30_iftable,
# applied here to the router's own interface names -- matches every
# naming style confirmed live on a real MikroTik RB5009 (2026-08-18):
# "vlan10-on SFP", "vlan10-on Bridge", "bridge-VLAN10", "vlan50 - on SFP".
VLAN_IFACE_NAME_PATTERN = re.compile(r'vlan\s*(\d+)', re.IGNORECASE)

# Standard Q-BRIDGE-MIB dot1qVlanStaticName table -- confirmed live
# against real hardware (2026-08-18): returns real admin-assigned VLAN
# names on a Netgear GS748Tv5 and GS110TPv3 (e.g. "Guest-VLAN",
# "IOT-VLAN"). Not supported everywhere -- a GS716Tv2 and MikroTik
# RouterOS gateways on the same network returned nothing for this OID,
# which is expected (RouterOS exposes VLANs via its own private MIB,
# not this standard one) and degrades gracefully, same as every other
# optional MIB branch elsewhere in this app.
DOT1Q_VLAN_STATIC_NAME_OID = "1.3.6.1.2.1.17.7.1.4.3.1.1"

# CISCO-VTP-MIB (vtpVlanName) -- a Cisco-proprietary supplementary
# source, NOT a replacement for dot1qVlanStaticName above. Exists
# specifically because classic Cisco Catalyst switches implement
# "Community String Indexing": the standard Bridge-MIB tree that
# dot1qVlanStaticName lives under is instantiated ONCE PER VLAN, and a
# plain community string (no suffix) only ever reaches VLAN 1's
# instance -- reaching any other VLAN requires appending "@<vlan_id>"
# to the community string itself (e.g. "public@25"). This app's shared
# credential mechanism (get_working_credential) has no concept of a
# per-VLAN community suffix, so on this class of hardware the plain
# dot1qVlanStaticName walk above would silently see only VLAN 1 -- not
# error, just quietly incomplete. CISCO-VTP-MIB sidesteps this
# entirely: it's indexed by (managementDomainIndex, vlanIndex) directly
# in the OID, so a single plain walk returns every VLAN.
#
# IMPORTANT: unlike every other OID in this file, this one is NOT
# verified against real hardware -- this network has no Cisco
# equipment. Implemented from cross-referenced documentation only
# (Cisco's own community-indexing writeup, a Cisco support doc on
# retrieving Catalyst VLAN info, a third-party network-monitoring
# tool's working implementation, and a Perl SNMP library's CISCO-VTP-
# MIB module docs -- 2026-08-18). Degrades silently like every other
# optional MIB branch here if it's wrong or unsupported on some model,
# same as dot1qVlanStaticName already does for RouterOS/GS716Tv2 --
# but treat any Cisco-sourced result with more scrutiny than the rest
# of this file until it's actually confirmed against real hardware.
CISCO_VTP_VLAN_NAME_OID = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"


def _record_vlan_name(cursor, vlan_id, switch_ip, vlan_name) -> bool:
    """
    Shared upsert used by both run_vlan_parser and run_cisco_vtp_parser
    -- same two writes regardless of which MIB the name came from.
    Returns True if the protected display name (network_vlans) was
    actually written, i.e. this wasn't skipped for an admin override.
    """
    # Raw per-source telemetry -- always overwritten, never protected.
    # This is what lets the UI show "which switch(es) said what",
    # independent of whichever name actually won the display-name
    # upsert below.
    cursor.execute('''
        INSERT INTO vlan_sources (vlan_id, switch_ip, reported_name, last_seen)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(vlan_id, switch_ip) DO UPDATE SET
            reported_name = excluded.reported_name,
            last_seen = CURRENT_TIMESTAMP
    ''', (vlan_id, switch_ip, vlan_name))

    # WHERE clause on the upsert (not a separate SELECT-then-UPDATE) --
    # see VLAN-3: an admin-set name (is_admin_named=1, set via POST
    # /api/vlans) must survive future scans. Same anti-clobber
    # principle as weld_confidence elsewhere in this app, just
    # expressed as an atomic conditional UPSERT instead of an
    # app-level check.
    cursor.execute('''
        INSERT INTO network_vlans (vlan_id, vlan_name, is_admin_named)
        VALUES (?, ?, 0)
        ON CONFLICT(vlan_id) DO UPDATE SET vlan_name = excluded.vlan_name
        WHERE network_vlans.is_admin_named = 0
    ''', (vlan_id, vlan_name))
    return cursor.rowcount > 0


async def run_vlan_parser(switch_ip):
    """
    Walks dot1qVlanStaticName directly against a single device and
    upserts any named VLANs into network_vlans. Previously this function
    piggybacked on snmp_pipeline's step 30 (ifDescr regex-matching for
    "vlan123"-style interface names) and always wrote a generic
    "VLAN {id}" placeholder name -- that only ever discovered VLANs
    already visible on some interface's description, and never
    surfaced the device's own real VLAN names. Querying the static VLAN
    table directly is both more complete (every statically-defined
    VLAN, not just ones an interface name happens to mention) and gives
    real names when the device supports this MIB branch.
    """
    credential = await get_working_credential(switch_ip)
    res = await run_snmp_command(switch_ip, DOT1Q_VLAN_STATIC_NAME_OID, credential, walk=True, timeout=3, retries=2)
    if not res:
        logger.debug(f"[VLAN] {switch_ip}: no dot1qVlanStaticName data (unsupported device, or no static VLANs defined).")
        return 0

    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    registered = 0
    for line in res:
        try:
            if " " not in line:
                continue
            oid_part, name_part = line.split(" ", 1)
            vlan_id = int(oid_part.strip().split(".")[-1])
            vlan_name = name_part.strip().strip('"').strip()
            if not vlan_name:
                continue
            if _record_vlan_name(cursor, vlan_id, switch_ip, vlan_name):
                registered += 1
        except (ValueError, IndexError):
            continue
    conn.commit()
    conn.close()

    if registered:
        logger.info(f"[*] VLAN Registry: {switch_ip} registered {registered} named VLAN(s).")
    return registered


async def run_cisco_vtp_parser(switch_ip):
    """
    Best-effort CISCO-VTP-MIB fallback -- see the module-level comment
    on CISCO_VTP_VLAN_NAME_OID above for why this exists and its
    UNVERIFIED status (no Cisco hardware available to test against).
    Tried in addition to, not instead of, run_vlan_parser's standard
    dot1qVlanStaticName walk, since it's plausible a given Cisco device
    answers one, both, or neither depending on model/IOS version.
    """
    credential = await get_working_credential(switch_ip)
    res = await run_snmp_command(switch_ip, CISCO_VTP_VLAN_NAME_OID, credential, walk=True, timeout=3, retries=2)
    if not res:
        return 0

    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    registered = 0
    for line in res:
        try:
            if " " not in line:
                continue
            oid_part, name_part = line.split(" ", 1)
            # Indexed by (managementDomainIndex, vlanIndex) -- the VLAN
            # ID is the LAST OID component, same extraction as
            # dot1qVlanStaticName even though the full index has one
            # more leading component (the management domain) that we
            # don't need.
            vlan_id = int(oid_part.strip().split(".")[-1])
            vlan_name = name_part.strip().strip('"').strip()
            if not vlan_name:
                continue
            if _record_vlan_name(cursor, vlan_id, switch_ip, vlan_name):
                registered += 1
        except (ValueError, IndexError):
            continue
    conn.commit()
    conn.close()

    if registered:
        logger.warning(f"[*] VLAN Registry: {switch_ip} registered {registered} VLAN(s) via CISCO-VTP-MIB (UNVERIFIED against real hardware -- please confirm if this fires correctly).")
    return registered


async def discover_router_vlan_subnets(router_ip):
    """
    Confirms every subnet bound to a router interface -- VLAN-tagged or
    not -- by cross-referencing ifDescr (interface names) against the
    router's own IP address table (ipAdEntAddr -> ipAdEntIfIndex ->
    ipAdEntNetMask). This is the authoritative source for subnet
    identity, used two ways: written to router_subnets for EVERY
    interface (general-purpose, see NET-1 -- consumed by
    auto_discovery.py's discover_active_subnets() for accurate
    ping-sweep targeting and by the dashboard for accurate display),
    and additionally to vlan_subnets for the subset whose interface name
    matched a VLAN naming pattern (VLAN-3/8 -- subnet<->VLAN binding).

    Confirmed live against a real MikroTik RouterOS gateway
    (2026-08-18): interfaces named e.g. "bridge-VLAN50" or "vlan10-on
    SFP" hold the actual gateway IP for that VLAN's subnet, while a
    device's plain physical interfaces (e.g. "ether8", "sfp-sfpplus1",
    the base "bridge") correctly have no VLAN match -- those subnets
    are genuinely untagged, not "VLAN 1", but are still real, confirmable
    subnets in their own right.

    The real subnet size is read from ipAdEntNetMask, not assumed --
    confirmed live that this matters: every internal interface here is
    genuinely /24, but the router's own WAN/PPPoE address in the same
    table is /32 (255.255.255.255), which a hardcoded /24 would have
    gotten flatly wrong.
    """
    credential = await get_working_credential(router_ip)

    ifdescr_res = await run_snmp_command(router_ip, IFDESCR_OID, credential, walk=True, timeout=3, retries=2)
    if not ifdescr_res:
        return 0

    # Every interface's name (general -- used for router_subnets/NET-1),
    # plus which of those also match the VLAN naming pattern (the subset
    # used for vlan_subnets, unchanged from before). Deliberately no
    # early-return when nothing matches the VLAN pattern: a router with
    # zero VLAN-tagged interfaces still has real, confirmable subnets on
    # its plain physical interfaces, and NET-1 needs those too.
    ifname_by_ifindex = {}
    vlan_by_ifindex = {}
    for line in ifdescr_res:
        try:
            if " " not in line:
                continue
            oid_part, name_part = line.split(" ", 1)
            if_idx = int(oid_part.strip().split(".")[-1])
            name = name_part.strip().strip('"')
            ifname_by_ifindex[if_idx] = name
            match = VLAN_IFACE_NAME_PATTERN.search(name)
            if match:
                vlan_by_ifindex[if_idx] = int(match.group(1))
        except (ValueError, IndexError):
            continue

    ip_table_res = await run_snmp_command(router_ip, IP_AD_ENT_IFINDEX_OID, credential, walk=True, timeout=3, retries=2)
    if not ip_table_res:
        return 0

    netmask_res = await run_snmp_command(router_ip, IP_AD_ENT_NETMASK_OID, credential, walk=True, timeout=3, retries=2)
    netmask_by_ip = {}
    for line in (netmask_res or []):
        try:
            if " " not in line:
                continue
            oid_part, val_part = line.split(" ", 1)
            ip_address = ".".join(oid_part.strip().split(".")[-4:])
            netmask_by_ip[ip_address] = val_part.strip()
        except (ValueError, IndexError):
            continue

    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    registered = 0
    for line in ip_table_res:
        try:
            if " " not in line:
                continue
            oid_part, val_part = line.split(" ", 1)
            # ipAdEntIfIndex is indexed BY the IP address itself -- the
            # last 4 OID components are the dotted-quad, the returned
            # value is the ifIndex it's bound to.
            ip_address = ".".join(oid_part.strip().split(".")[-4:])
            if_idx = int(val_part.strip())
            iface_name = ifname_by_ifindex.get(if_idx)
            if iface_name is None:
                continue
            vlan_id = vlan_by_ifindex.get(if_idx)

            netmask = netmask_by_ip.get(ip_address)
            if not netmask:
                # No netmask entry for this IP in the same table walk --
                # don't guess a size, just skip rather than risk a wrong
                # CIDR (e.g. silently assuming /24).
                logger.debug(f"[VLAN] {router_ip}: no ipAdEntNetMask for {ip_address} -- skipping, not guessing subnet size.")
                continue
            if netmask == "0.0.0.0":
                # A router (or a forged SNMP reply spoofing one) can
                # never legitimately report this for a real interface --
                # AND'd against any host IP it computes a /0, i.e. the
                # entire IPv4 space. Reject outright rather than let it
                # reach the prefix-length check below.
                logger.debug(f"[VLAN] {router_ip}: netmask 0.0.0.0 for {ip_address} -- rejecting, not a real subnet.")
                continue
            try:
                network = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)
            except ValueError:
                logger.debug(f"[VLAN] {router_ip}: unparseable netmask '{netmask}' for {ip_address} -- skipping.")
                continue

            # CWE-918: ip_address/netmask are untrusted, router-reported
            # SNMP data (or forged data from a device impersonating the
            # router), and this record feeds straight into
            # auto_discovery.py's ping-sweep targeting (NET-1). A /32
            # can never match more than its own single address, so it's
            # always safe regardless of whether it's public (see the
            # docstring above -- a genuine WAN/PPPoE /32 is expected and
            # must keep working). Anything broader must be reported
            # against a private/link-local host IP AND meet the minimum
            # prefix-length bound -- a broad-but-nonzero netmask (e.g.
            # 128.0.0.0) paired with a private-looking host IP would
            # otherwise still AND down into a network far larger than
            # any real LAN.
            if network.prefixlen != 32:
                try:
                    host_ip_obj = ipaddress.IPv4Address(ip_address)
                    host_is_local = host_ip_obj.is_private or host_ip_obj.is_link_local
                except ValueError:
                    host_is_local = False
                if not host_is_local:
                    logger.debug(f"[VLAN] {router_ip}: reported host IP {ip_address} is not private/link-local (netmask {netmask}, computed network {network}) -- rejecting, refusing to trust an unbounded/public subnet.")
                    continue
                if network.prefixlen < MIN_ROUTER_SUBNET_PREFIXLEN:
                    logger.debug(f"[VLAN] {router_ip}: computed network {network} for {ip_address}/{netmask} is broader than the minimum accepted prefix length (/{MIN_ROUTER_SUBNET_PREFIXLEN}) -- rejecting.")
                    continue
            subnet = str(network)

            # General record (NET-1) -- every confirmed interface,
            # tagged or not. vlan_id is NULL for genuinely untagged
            # interfaces, which is itself meaningful information (not a
            # missing value to paper over).
            cursor.execute('''
                INSERT INTO router_subnets (subnet, router_ip, interface_name, vlan_id, last_seen)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(subnet) DO UPDATE SET
                    router_ip = excluded.router_ip,
                    interface_name = excluded.interface_name,
                    vlan_id = excluded.vlan_id,
                    last_seen = CURRENT_TIMESTAMP
            ''', (subnet, router_ip, iface_name, vlan_id))

            # VLAN-specific record (VLAN-3/8, unchanged) -- only for the
            # subset that actually matched a VLAN-tagged interface name.
            if vlan_id is not None:
                cursor.execute('''
                    INSERT INTO vlan_subnets (vlan_id, subnet, router_ip, interface_name, last_seen)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(vlan_id, subnet) DO UPDATE SET
                        router_ip = excluded.router_ip,
                        interface_name = excluded.interface_name,
                        last_seen = CURRENT_TIMESTAMP
                ''', (vlan_id, subnet, router_ip, iface_name))
            registered += 1
        except (ValueError, IndexError):
            continue
    conn.commit()
    conn.close()

    if registered:
        logger.info(f"[*] VLAN Registry: {router_ip} confirmed {registered} router-side subnet binding(s) (VLAN-tagged and untagged).")
    return registered


async def run_vlan_registry_scan():
    """
    Runs run_vlan_parser against every known Switch/Router/Switch-WAP,
    plus discover_router_vlan_subnets against Routers specifically (the
    L3 boundary -- only a router's own interface table can authoritatively
    confirm which subnet belongs to which VLAN). This is the actual
    stage entry point wired into main.py's deep-scan cycle -- see punch
    list VLAN-1.
    """
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT b.ip_address, n.device_type
        FROM logical_nodes n
        JOIN l2_interfaces i ON n.id = i.node_id
        JOIN l3_bindings b ON i.mac_address = b.mac_address
        WHERE n.device_type IN ('Switch', 'Router', 'Switch / WAP') AND b.ip_address IS NOT NULL
    ''')
    targets = cursor.fetchall()
    conn.close()

    if not targets:
        return

    logger.info(f"[*] VLAN Registry: Scanning {len(targets)} infrastructure device(s) for named VLANs...")
    total = 0
    for ip, device_type in targets:
        total += await run_vlan_parser(ip)
        total += await run_cisco_vtp_parser(ip)
        if device_type == "Router":
            await discover_router_vlan_subnets(ip)
    if total:
        logger.info(f"[*] VLAN Registry: Scan complete. {total} named VLAN(s) registered/updated.")
