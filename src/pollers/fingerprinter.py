import asyncio
import logging
import sqlite3
import re
import os
import ipaddress
from engine.oui_manager import get_vendor_info, get_vendor_from_sysobjectid
from engine.auto_discovery import detect_default_gateway
from engine.snmp_adapter import adaptive_snmp_query, clean_snmp_string
from engine.hostname_registry import set_hostname_by_mac, is_usable_hostname, PRIORITY_SNMP_SYSNAME

logger = logging.getLogger("Netlanvas.Fingerprint")
DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")

def is_valid_ipv4(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False

# SNMP-SWITCH-1 (2026-09-19): budget "smart managed" switches that only
# implement bare MIB-II (system/interfaces) over SNMP -- no BRIDGE-MIB,
# no LLDP-MIB -- never hit the is_bridge/is_lldp branch below and fell
# through to plain "Endpoint" with no error, silently. Real case: a
# D-Link DGS-1100-05V2's own sysDescr literally reads "...Gigabit
# Ethernet Switch", but neither MIB it doesn't implement ever fires.
# sysDescr is the device's own self-reported identity over a real,
# documented protocol -- the same category of evidence as an SSDP
# reply, not a guessed proprietary byte layout like NSDP/ESCP -- so
# this feeds smart_switch_candidates at the SAME high-confidence tier
# SSDP uses (see unification.py's _SELF_IDENTIFYING_PROTOCOLS), not a
# new standalone classification path here.
_SNMP_SWITCH_DESCR_PATTERN = re.compile(r'\bswitch\b', re.IGNORECASE)

def _write_snmp_switch_candidate(mac, vendor, sys_descr):
    """Mirrors main.py's stage_smart_switch_discovery() upsert into the
    same smart_switch_candidates table -- SNMP is just another producer
    into the existing pipeline, not a separate mechanism."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS smart_switch_candidates (
                mac_address TEXT PRIMARY KEY,
                vendor TEXT,
                model TEXT,
                protocol TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute(
            "INSERT INTO smart_switch_candidates (mac_address, vendor, model, protocol, last_seen) "
            "VALUES (?, ?, ?, 'SNMP', CURRENT_TIMESTAMP) "
            "ON CONFLICT(mac_address) DO UPDATE SET vendor=excluded.vendor, model=excluded.model, "
            "protocol=excluded.protocol, last_seen=CURRENT_TIMESTAMP",
            (mac, vendor, sys_descr),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug(f"[!] SNMP switch candidate write failed for {mac}: {e}")

# OID prefixes for the two extra walks used to resolve a multi-homed
# device's self-reported IPs (ipAdEntAddr) to the CORRECT per-interface
# MAC, instead of blindly attributing every self-reported IP to
# whichever single MAC happened to be fingerprinted. Confirmed live:
# a MikroTik router's VLAN bridge sub-interfaces (bridge-VLAN10,
# bridge-VLAN20) each carry their OWN distinct MAC, entirely different
# from the router's physical-port MAC -- without this, every
# self-reported IP on a multi-interface device was landing on the one
# MAC being profiled, silently wrong for every IP except that one.
_IP_AD_ENT_IFINDEX_OID = "1.3.6.1.2.1.4.20.1.2"
_IF_PHYS_ADDRESS_OID = "1.3.6.1.2.1.2.2.1.6"

def _parse_ip_to_ifindex(lines):
    """ipAdEntIfIndex walk (-On -Oq) -> {ip: ifindex}. The OID suffix
    of this table IS the IP address itself (ipAddrTable is indexed by
    IP), so the mapping comes straight from the OID, not the value."""
    prefix = _IP_AD_ENT_IFINDEX_OID + "."
    result = {}
    for line in lines or []:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        oid = parts[0].lstrip(".")
        if not oid.startswith(prefix):
            continue
        ip_part = oid[len(prefix):]
        if not is_valid_ipv4(ip_part):
            continue
        try:
            result[ip_part] = int(parts[1])
        except ValueError:
            continue
    return result

def _parse_ifindex_to_mac(lines):
    """ifPhysAddress walk (-On -Oq) -> {ifindex: "aa:bb:cc:dd:ee:ff"}.
    net-snmp prints this OCTET STRING as space-separated hex pairs in
    quotes (e.g. '"04 F4 BC F5 8B D1 "'), not colon-hex -- extract every
    2-hex-digit token rather than relying on quote/whitespace layout.

    ROUTER-2 (2026-09-09) follow-up: a VLAN/bridge/loopback-type
    interface genuinely has no real L2 hardware and reports
    00:00:00:00:00:00 here -- confirmed live this slips through even
    after filtering resolve_own_mac()'s own single-ifindex lookup,
    because worker()'s own_interface_macs/owned_ip_macs are built
    straight from this function's FULL result set, a different call
    site resolve_own_mac() doesn't share. Filtering it once, here, at
    the one place both paths originate, closes the gap for every
    current and future caller instead of needing the same check
    repeated at each consumer."""
    prefix = _IF_PHYS_ADDRESS_OID + "."
    result = {}
    for line in lines or []:
        parts = line.strip().split(None, 1)
        if len(parts) < 2:
            continue
        oid, rest = parts
        oid = oid.lstrip(".")
        if not oid.startswith(prefix):
            continue
        try:
            ifindex = int(oid[len(prefix):])
        except ValueError:
            continue
        octets = re.findall(r'[0-9A-Fa-f]{2}', rest)
        if len(octets) != 6:
            continue
        mac = ":".join(o.lower() for o in octets)
        if mac == "00:00:00:00:00:00":
            continue
        result[ifindex] = mac
    return result

def get_nodes_to_reverify():
    """
    Returns one (mac, ip, device_type, sibling_macs, os_family) target
    per logical node instead of one row per known IP -- a node with
    multiple interfaces (confirmed via TOPO-1: a single router can have
    6+ IPs across 4+ distinct MACs) was independently SNMP-fingerprinted
    once per IP for an identical result. See punch list POLL-1.

    sibling_macs lists any OTHER MACs already known to belong to the
    same node, so the caller can still write the SAME fingerprint
    result (sysdescr, classification) to each of them -- preserving
    per-interface display in the UI -- without separately querying the
    device again for each one. Devices with no resolved node_id yet
    (not unified) are kept exactly as before, one row each with no
    siblings -- they're not yet known to share a node with anything.

    os_family (2026-09-08): os_fingerprinter.py's mDNS/SSDP sweep
    already runs earlier in the same tick and writes this for any
    device that answered. The caller uses it to skip the expensive
    SNMP credential cascade for devices already confirmed (not
    guessed) to be a category that never runs an SNMP agent -- see
    run_fingerprinter()'s worker() for exactly which category and why
    it's narrowly scoped.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT b.mac_address, b.ip_address, ln.device_type, i.node_id, ln.os_family
        FROM l3_bindings b
        LEFT JOIN l2_interfaces i ON b.mac_address = i.mac_address
        LEFT JOIN logical_nodes ln ON i.node_id = ln.id
        WHERE b.ip_address IS NOT NULL
    ''')
    rows = cursor.fetchall()
    conn.close()

    by_node = {}
    targets = []
    for mac, ip, device_type, node_id, os_family in rows:
        if node_id is None:
            targets.append((mac, ip, device_type, [], os_family))
        else:
            by_node.setdefault(node_id, []).append((mac, ip, device_type, os_family))

    for entries in by_node.values():
        # entries can repeat the SAME mac (one row per known IP for
        # that mac in l3_bindings, e.g. a past DHCP lease change) --
        # dedupe to unique MACs before splitting into primary +
        # siblings, otherwise the primary mac could end up listed as
        # its own "sibling" and get re-fingerprinted redundantly.
        unique_macs = {}
        for mac, ip, device_type, os_family in entries:
            unique_macs.setdefault(mac, (ip, device_type, os_family))

        mac_list = list(unique_macs.items())
        primary_mac, (primary_ip, device_type, os_family) = mac_list[0]
        sibling_macs = [mac for mac, _ in mac_list[1:]]
        targets.append((primary_mac, primary_ip, device_type, sibling_macs, os_family))

    return targets

def update_device_fingerprint(mac, sys_descr=None, sys_name=None, device_type=None, vendor=None, category=None, market_segment=None, confidence=100, owned_ips=None, owned_ip_macs=None, own_interface_macs=None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    if sys_descr:
        cursor.execute('''
            INSERT INTO device_fingerprints (mac_address, snmp_sysdescr)
            VALUES (?, ?)
            ON CONFLICT(mac_address) DO UPDATE SET
                snmp_sysdescr = excluded.snmp_sysdescr,
                last_updated = CURRENT_TIMESTAMP
        ''', (mac, sys_descr))

    display_name = sys_descr if sys_descr else (vendor if vendor else "Unknown Device")

    # Fetch current node state to enforce anti-clobbering logic
    cursor.execute('''
        SELECT ln.id, ln.weld_confidence, ln.device_type, ln.hostname
        FROM l2_interfaces i
        JOIN logical_nodes ln ON i.node_id = ln.id
        WHERE i.mac_address = ?
    ''', (mac,))
    row = cursor.fetchone()

    target_node_id = None
    if row:
        target_node_id, current_conf, current_type, current_host = row
        current_conf = current_conf or 0

        final_type = device_type
        final_conf = confidence

        # --- Anti-Clobber Protection (device_type / weld_confidence
        # only -- hostname is handled entirely by the priority registry
        # below, via set_hostname_by_mac, not by this block anymore.
        # See HOSTNAME-1. ---

        # 1. Protect High-Confidence Profiles from Low-Confidence Overwrites
        if current_conf == 100 and confidence < 100:
            final_type = current_type
            final_conf = current_conf
        else:
            # 2. Infrastructure Type Locking (Don't downgrade Routers/APs to Switches/Endpoints)
            if current_type in ['Router', 'Access Point'] and device_type in ['Switch', 'Endpoint']:
                final_type = current_type

        cursor.execute('''
            UPDATE logical_nodes
            SET device_type = ?, weld_confidence = ?
            WHERE id = ?
        ''', (final_type, final_conf, target_node_id))
        cursor.execute('UPDATE l2_interfaces SET vendor = ?, category = ?, market_segment = ? WHERE mac_address = ?', (vendor, category, market_segment, mac))
    else:
        cursor.execute('INSERT INTO logical_nodes (hostname, device_type, weld_confidence) VALUES (?, ?, ?)', (display_name, device_type, confidence))
        target_node_id = cursor.lastrowid
        cursor.execute('UPDATE l2_interfaces SET node_id = ?, vendor = ?, category = ?, market_segment = ? WHERE mac_address = ?', (target_node_id, vendor, category, market_segment, mac))

    # HOSTNAME-1: sysName (admin-configured, when the device answered
    # SNMP) at the top priority tier; sysDescr/vendor fallback
    # (display_name -- the same text this field always used to hold) at
    # the bottom tier, so it only ever fills in when nothing better is
    # already known. Both routed through the SAME priority-aware
    # writer, so whichever is actually best wins regardless of call
    # order -- no separate special-case needed for a brand-new node
    # either, since the INSERT above already seeded hostname=
    # display_name at priority 0 by default.
    if is_usable_hostname(sys_name):
        set_hostname_by_mac(cursor, mac, sys_name, PRIORITY_SNMP_SYSNAME)
    set_hostname_by_mac(cursor, mac, display_name, 0)

    owned_ip_macs = owned_ip_macs or {}
    own_interface_macs = own_interface_macs or set()
    resolved_type = final_type if row else device_type

    # F7-FOLLOWUP: own_interface_macs is the device's OWN ifPhysAddress
    # table -- every MAC across every one of ITS OWN interfaces,
    # confirmed live to include cases like a MikroTik's per-VLAN bridge
    # sub-interfaces, each with a distinct MAC unrelated (numerically
    # far apart) from the router's physical-port MAC, so neither
    # proximity-based weld pass in engine.unification ever catches
    # them. This is a fundamentally different self-report category
    # than the owned_ips path above: "list my OWN interfaces" cannot
    # be used to make a claim ABOUT ANOTHER DEVICE's identity the way
    # ipAdEntAddr (F7's actual hazard) can.
    #
    # Restricted to Router-classified devices only (max-trust tier
    # here, reachable only via ip==gw_ip, never self-report -- see F7
    # above) -- confirmed live this was needed: applying it to EVERY
    # SNMP-alive device pulled in every Access Point's own radio/VAP
    # virtual BSSID MACs (one per SSID per band, 3-8 per AP) as
    # "sibling interfaces" of that AP's node, which is real device
    # inventory noise, not the router-VLAN-unification case this was
    # built for. The only self-report worth trusting THIS broadly is
    # the one device class whose classification is itself
    # independently derived, not self-claimed.
    #
    # A ghost MAC (no existing l2_interfaces row, or a row with no
    # node_id yet) has no independently-established owner to steal
    # from, so adopting it here is safe. An ALREADY-independently-
    # bound MAC is a different matter -- reassigning it purely on this
    # device's say-so would reopen exactly the F7 hazard. That's only
    # allowed when the existing node being absorbed has no independent
    # high-trust classification of its own to protect (Router/Access
    # Point stay locked, same as the Infrastructure Type Locking rule
    # above -- a real second router or AP must never be silently
    # swallowed this way, which is exactly what went wrong when
    # engine.unification briefly tried a sysDescr-based weld and
    # merged 4 distinct Ubiquiti APs into one). A node that only ever
    # reached its current grouping via a plain proximity/hardware-weld
    # heuristic (no independent verification) has nothing comparable
    # to protect.
    if own_interface_macs and target_node_id and resolved_type == "Router":
        for iface_mac in own_interface_macs:
            if iface_mac == mac:
                continue
            existing = cursor.execute('SELECT node_id FROM l2_interfaces WHERE mac_address = ?', (iface_mac,)).fetchone()
            if existing is None:
                iface_vendor_info = get_vendor_info(iface_mac)
                cursor.execute('INSERT INTO l2_interfaces (mac_address, node_id, vendor, category, market_segment) VALUES (?, ?, ?, ?, ?)', (iface_mac, target_node_id, iface_vendor_info["vendor"], iface_vendor_info.get("category"), iface_vendor_info.get("market_segment")))
            elif existing[0] is None:
                iface_vendor_info = get_vendor_info(iface_mac)
                cursor.execute('UPDATE l2_interfaces SET node_id = ?, vendor = ?, category = ?, market_segment = ? WHERE mac_address = ?', (target_node_id, iface_vendor_info["vendor"], iface_vendor_info.get("category"), iface_vendor_info.get("market_segment"), iface_mac))
            elif existing[0] == target_node_id:
                pass
            else:
                existing_type_row = cursor.execute('SELECT device_type FROM logical_nodes WHERE id = ?', (existing[0],)).fetchone()
                existing_type = existing_type_row[0] if existing_type_row else None
                if resolved_type == "Router" and existing_type not in ("Router", "Access Point"):
                    iface_vendor_info = get_vendor_info(iface_mac)
                    cursor.execute('UPDATE l2_interfaces SET node_id = ?, vendor = ?, category = ?, market_segment = ? WHERE mac_address = ?', (target_node_id, iface_vendor_info["vendor"], iface_vendor_info.get("category"), iface_vendor_info.get("market_segment"), iface_mac))
                    logger.info(f"[FINGERPRINT] Welding {iface_mac} (was node {existing[0]}) into router node {target_node_id} -- confirmed via the router's own interface table (ifPhysAddress).")
                else:
                    logger.warning(f"[FINGERPRINT] {mac} lists {iface_mac} in its own interface table, but that MAC is already bound to a different, independently-established node -- ignoring the claim, not reassigning identity.")

    # Runs AFTER the own_interface_macs weld above, not before: an
    # owned_ip's correct_mac (from the SAME ifTable data) must already
    # have an l2_interfaces row by the time this INSERTs into
    # l3_bindings, or l3_bindings.mac_address's FK constraint fails --
    # confirmed live, this ordering crashed the polling engine mid-tick
    # the first time (FOREIGN KEY constraint failed, right after a
    # multi-homed device with a brand-new ghost interface MAC).
    if owned_ips and target_node_id:
        for owned_ip in owned_ips:
            cursor.execute('SELECT mac_address FROM l3_bindings WHERE ip_address = ?', (owned_ip,))
            ip_row = cursor.fetchone()
            if ip_row:
                owned_mac = ip_row[0]
                # F7: a device's own unauthenticated SNMP self-report
                # must never reassign l2_interfaces.node_id for a MAC
                # that already has an independently-established
                # binding to a DIFFERENT mac -- that is exactly how a
                # rogue/misbehaving SNMP responder can hijack another
                # device's tracked identity. Legitimate multi-homed
                # devices are welded by engine.unification's dedicated
                # passes instead, which only ever weld MACs that have
                # no existing independent binding to begin with, so
                # they can't be tricked into re-parenting an
                # already-established device the way this self-report
                # path could.
                if owned_mac == mac:
                    cursor.execute('UPDATE l2_interfaces SET node_id = ? WHERE mac_address = ?', (target_node_id, owned_mac))
                else:
                    owned_node_row = cursor.execute('SELECT node_id FROM l2_interfaces WHERE mac_address = ?', (owned_mac,)).fetchone()
                    if owned_node_row and owned_node_row[0] == target_node_id:
                        # Already the same logical device -- e.g. a
                        # sibling interface unification's independent,
                        # ARP-confirmed weld pass already merged this
                        # MAC onto the same node via a DIFFERENT
                        # signal (hardware proximity or a matching
                        # sysDescr banner). Not a conflict, nothing to
                        # do; warning here would be a false positive
                        # every cycle for a perfectly legitimate,
                        # already-resolved multi-interface device.
                        pass
                    else:
                        logger.warning(f"[FINGERPRINT] {mac} self-reported owning {owned_ip}, which is already independently bound to a different MAC ({owned_mac}) -- ignoring the claim, not reassigning identity.")
            else:
                # Use the CORRECT per-interface mac when this
                # multi-homed device's own ifTable resolved one for
                # this specific IP (owned_ip_macs), not blindly the
                # single mac being profiled -- see the OID walk in
                # worker(). Falls back to `mac` for devices where that
                # resolution wasn't available (single-interface
                # devices, or a walk that failed this cycle) --
                # AND when the resolved mac has no l2_interfaces row
                # at all. The own_interface_macs block above only
                # creates rows for Router-classified devices (see its
                # comment); for any other device type, correct_mac
                # might be a MAC nothing has independently seen yet,
                # and l3_bindings.mac_address has a FK to
                # l2_interfaces.mac_address -- confirmed live, this
                # crashed the polling engine a second time (a
                # non-router multi-homed device this time) when that
                # wasn't checked.
                correct_mac = owned_ip_macs.get(owned_ip, mac)
                if correct_mac != mac and not cursor.execute('SELECT 1 FROM l2_interfaces WHERE mac_address = ?', (correct_mac,)).fetchone():
                    correct_mac = mac
                cursor.execute('''
                    INSERT INTO l3_bindings (ip_address, mac_address, discovery_source, last_seen)
                    VALUES (?, ?, 'SNMP_IP_TABLE', CURRENT_TIMESTAMP)
                    ON CONFLICT(ip_address) DO NOTHING
                ''', (owned_ip, correct_mac))

    conn.commit()
    conn.close()

async def resolve_own_mac(ip):
    """
    ROUTER-1: returns the MAC of the interface holding `ip`, on the
    device AT `ip` itself, via the same ifPhysAddress/ipAdEntIfIndex
    self-report F7-FOLLOWUP already trusts elsewhere in this file for
    a device's OTHER owned IPs.

    Exists because every mechanism that creates an l3_bindings row
    today discovers a device INDIRECTLY -- out of some other device's
    ARP table, LLDP neighbor table, or switch FDB. A router/switch
    can never appear in its OWN ARP cache (a device doesn't ARP for
    itself), and this appliance only ARP-scrapes routers/switches, never
    ordinary client devices (whose ARP caches WOULD contain it).
    Confirmed live: a router was fully, successfully SNMP-polled every
    tick (sysDescr, ARP cache, everything) yet never appeared as a node
    at all -- its own IP/MAC binding structurally never got created by
    anything. stage_arp_scrape() calls this against the same gateway/
    representative-target IP it already queries directly, feeding the
    result into the exact same ARP-cache ingestion path used for every
    other discovered device, rather than needing new ingestion logic.
    """
    ifindex_to_mac = _parse_ifindex_to_mac(await adaptive_snmp_query(ip, _IF_PHYS_ADDRESS_OID, walk=True))
    ip_to_ifindex = _parse_ip_to_ifindex(await adaptive_snmp_query(ip, _IP_AD_ENT_IFINDEX_OID, walk=True))
    ifindex = ip_to_ifindex.get(ip)
    if ifindex is None:
        return None
    mac = ifindex_to_mac.get(ifindex)
    # ROUTER-2 (2026-09-09): confirmed live -- `ip` can resolve to a
    # VLAN/bridge/loopback-type ifindex whose own ifPhysAddress is
    # genuinely all-zeros (no real L2 hardware on that logical
    # interface), which this function then handed straight to the
    # shared ARP-cache ingestion path in main.py as if it were a real
    # MAC. Wrote a bogus 00:00:00:00:00:00 l3_bindings row for the
    # router's own gateway IP, which briefly out-raced the correct
    # GATEWAY_SELF_REPORT/ROUTER_ARP_CACHE write for the same IP and
    # got caught by the SNMPv3 finding detector while it stood --
    # producing a permanently-orphaned finding keyed to that fake MAC
    # (the real MAC's own finding is unrelated and unaffected, but nothing
    # ever resolves the wrong-keyed one, since detectors reconcile by
    # "is this MAC still reporting X", not by IP identity). Every other
    # MAC-producing path in this codebase already guards this exact
    # sentinel (dhcp_sniffer.py, auto_discovery.py,
    # smart_switch_pipeline.py, snmp_pipeline.py's own ARP walk) --
    # this was the one gap.
    if mac == "00:00:00:00:00:00":
        return None
    return mac

async def run_fingerprinter():
    targets = get_nodes_to_reverify()
    if not targets: return
    logger.info(f"Stage 5: Profiling {len(targets)} nodes...")

    gw_ip = detect_default_gateway()
    # Raised 5 -> 25 -> 100 (both 2026-09-08, same day): each worker
    # only ever has ONE snmpget/snmpwalk subprocess in flight at a time
    # (the SNMPv3 auth/priv cascade in adaptive_snmp_query() is
    # sequential within a worker, not spawned all at once), so this
    # multiplies peak concurrent subprocess count by Nx, not by the
    # 24-combinations cascade depth. The second raise (25->100) was
    # root-caused live via PERF-2's per-device credential-search timing
    # log: a genuinely non-SNMP device pays a fixed ~103s (every one of
    # up to 51 credential/protocol attempts times out with zero
    # response -- confirmed identical ~103.3s across dozens of devices
    # in the same batch), so wall-clock for the whole non-SNMP
    # population is ceil(devices / semaphore) * ~103s regardless of how
    # fast any individual device resolves -- raising the batch width is
    # the direct lever on that ceil(). Deliberately NOT "assume every
    # gateway-looking IP is the same physical router and dedupe before
    # searching" (the alternative considered first) -- that assumption
    # doesn't hold in general (multiple independent routers/VRRP pairs
    # are real topologies), where a wider semaphore has no such
    # correctness risk, just a resource-headroom one. A Raspberry Pi
    # appliance is genuinely memory-constrained (990MB total, already using swap at
    # the time this was raised) -- confirmed net-snmp CLI subprocesses
    # are small and short-lived enough that Semaphore(25)'s own
    # ~30-90MB estimate scaled to 100 stays well within that budget,
    # but this number should be revisited if it's ever raised again on
    # a similarly small box.
    semaphore = asyncio.Semaphore(100)

    async def worker(mac, ip, current_type, sibling_macs, os_family):
        # THE FIX: Shield PySNMP from attempting to DNS-resolve Pseudo-IPs
        if not is_valid_ipv4(ip): return

        # Skip the SNMP credential cascade entirely for a CONFIRMED
        # Apple mobile device (2026-09-08) -- os_fingerprinter.py's
        # mDNS sweep already ran earlier this same tick, so os_family
        # here is a real device-model resolution, not a guess.
        # Deliberately narrow: Apple never ships an SNMP agent on
        # iOS/iPadOS, so this is a zero-risk skip, unlike broader
        # categories (printers, NAS, some smart TVs) that legitimately
        # DO run SNMP alongside mDNS/SSDP -- excluding those would risk
        # silently losing real infrastructure data to save time. Every
        # Apple model code/name (raw, e.g. "iPhone16,2", or translated,
        # e.g. "iPhone 15 Pro") starts with one of these two prefixes
        # by Apple's own naming convention.
        if os_family and (os_family.startswith("iPhone") or os_family.startswith("iPad")):
            return

        async with semaphore:
            snmp_alive = await adaptive_snmp_query(ip, "1.3.6.1.2.1.1.2", walk=True)
            vendor_info = get_vendor_info(mac)
            vendor = vendor_info["vendor"]
            category = vendor_info.get("category")
            market_segment = vendor_info.get("market_segment")
            # ENT-1 (2026-09-07): snmp_alive here IS the sysObjectID walk
            # result -- already fetched as the reachability gate, so this
            # is a free second opinion, not a new query. Only used when
            # the MAC-based lookup came back empty (randomized MAC, or an
            # OUI block we don't have data for yet); never overrides a
            # real OUI match, since sysObjectID identifies the firmware
            # vendor, which is usually but not always the same as the
            # NIC's silicon vendor.
            if snmp_alive and vendor in ("Unknown Hardware", "Private (Randomized MAC)"):
                ent_vendor = get_vendor_from_sysobjectid(snmp_alive)
                if ent_vendor:
                    vendor = ent_vendor
                    # OUI-4: category/market_segment are keyed off the
                    # OUI, not the vendor string -- a sysObjectID-derived
                    # vendor identifies the FIRMWARE, sometimes a
                    # different company than whoever's OUI block the NIC
                    # actually came from, so the OUI-based classification
                    # above no longer reliably describes this device.
                    category = None
                    market_segment = None
            device_type = current_type or "Endpoint"
            confidence = 100
            sys_descr = None
            sys_name = None
            owned_ips = set()
            owned_ip_macs = {}
            own_interface_macs = set()

            if snmp_alive:
                logger.info(f"[*] SNMP ALIVE [{ip}]: Processing profiles...")
                # PERF-1 (2026-09-08): these 10 walks are all independent
                # read-only queries against the same device -- none needs
                # a prior one's result -- so run them concurrently via
                # gather() instead of chaining individual awaits. Root-
                # caused live: after POLL-3 (which only sped up FINDING a
                # credential for the no-SNMP majority), this sequential
                # chain was the single biggest remaining tick 0/1
                # bottleneck -- two real ~230s/218s log gaps landed
                # immediately after "Processing profiles..." on genuine
                # SNMP-alive infrastructure, confirmed by inspecting this
                # exact code path. Safe to parallelize: adaptive_snmp_query
                # only takes its per-IP lock on the full-reprobe path
                # (snmp_adapter.py) -- an already-cached working
                # credential (guaranteed here, since snmp_alive just
                # succeeded moments earlier) goes straight to
                # run_snmp_command with no lock at all, so these 10 calls
                # genuinely run concurrently, not serialized underneath.
                # Same asyncio.gather() pattern mac_table_scraper.py
                # already uses safely for 7 concurrent per-switch walks.
                (
                    desc_lines, name_lines, device_ips_raw,
                    ifphys_raw, ipifindex_raw,
                    is_wifi_ieee, is_wifi_ubnt, is_bridge, is_lldp, if_descrs,
                ) = await asyncio.gather(
                    adaptive_snmp_query(ip, "1.3.6.1.2.1.1.1", walk=True),
                    # HOSTNAME-1: sysName is a DIFFERENT MIB-II object
                    # from sysDescr -- confirmed live against real
                    # switches on this network (e.g.
                    # "Netgear-GS748Tv5-Works" vs the long sysDescr
                    # firmware string), it's the admin-configured device
                    # name, exactly what "hostname" should mean.
                    adaptive_snmp_query(ip, "1.3.6.1.2.1.1.5", walk=True),
                    adaptive_snmp_query(ip, "1.3.6.1.2.1.4.20.1.1", walk=True),
                    # Resolve each owned IP to its CORRECT per-interface
                    # MAC (not blindly this call's `mac`) via the
                    # device's own ipAdEntIfIndex + ifPhysAddress tables
                    # -- see the F7-FOLLOWUP comment in
                    # update_device_fingerprint.
                    adaptive_snmp_query(ip, _IF_PHYS_ADDRESS_OID, walk=True),
                    adaptive_snmp_query(ip, _IP_AD_ENT_IFINDEX_OID, walk=True),
                    adaptive_snmp_query(ip, "1.2.840.10036.1.1.1.1", walk=True),
                    adaptive_snmp_query(ip, "1.3.6.1.4.1.41112.1.6", walk=True),
                    adaptive_snmp_query(ip, "1.3.6.1.2.1.17.1.2", walk=True),
                    adaptive_snmp_query(ip, "1.0.8802.1.1.2.1.3", walk=True),
                    adaptive_snmp_query(ip, "1.3.6.1.2.1.2.2.1.2", walk=True),
                )

                if desc_lines: sys_descr = clean_snmp_string(" ".join(desc_lines))
                if name_lines: sys_name = clean_snmp_string(" ".join(name_lines))

                if device_ips_raw:
                    for line in device_ips_raw:
                        ip_match = line.split()[-1].strip('"')
                        if ip_match and is_valid_ipv4(ip_match) and not ip_match.startswith("127."):
                            owned_ips.add(ip_match)

                ifindex_to_mac = _parse_ifindex_to_mac(ifphys_raw)
                ip_to_ifindex = _parse_ip_to_ifindex(ipifindex_raw)
                owned_ip_macs = {
                    owned_ip: ifindex_to_mac[ip_to_ifindex[owned_ip]]
                    for owned_ip in owned_ips
                    if owned_ip in ip_to_ifindex and ip_to_ifindex[owned_ip] in ifindex_to_mac
                }
                own_interface_macs = set(ifindex_to_mac.values())

                has_docker = any(i.startswith("172.17.") or i.startswith("172.18.") for i in owned_ips)
                has_radio_interface = False
                if if_descrs:
                    wireless_pattern = re.compile(r'(wifi|wlan|ath|vap|ra|radio)', re.IGNORECASE)
                    for line in if_descrs:
                        if wireless_pattern.search(line):
                            has_radio_interface = True
                            logger.info(f"[*] WAP MATCH [{ip}]: Found physical radio -> {line.strip()}")
                            break

                # F7: Router classification is strictly ip == gw_ip, where
                # ip comes from l3_bindings via get_nodes_to_reverify()
                # -- an independently ARP/DHCP-established identity,
                # never the device's own self-report. A device must not
                # be able to promote itself to Router (a max-confidence,
                # anti-clobber-protected classification) purely because
                # the real gateway's IP happens to appear in its own
                # ipAdEntAddr response.
                if ip == gw_ip:
                    device_type = "Router"
                    logger.info(f"[*] Node Identified [{ip}]: {device_type} (Gateway IP Ownership Match)")
                elif is_wifi_ieee or is_wifi_ubnt or has_radio_interface:
                    device_type = "Access Point"
                    logger.info(f"[*] Node Identified [{ip}]: Access Point (Radio Interface Confirmed)")
                elif is_bridge or is_lldp:
                    device_type = "Switch"
                elif has_docker:
                    device_type = "Docker Host"
                else:
                    device_type = "Endpoint"

                # SNMP-SWITCH-1: only fires when BRIDGE-MIB/LLDP-MIB
                # already failed to identify it (is_bridge/is_lldp both
                # false) -- a device that already answered either of
                # those is already correctly "Switch" above, at higher
                # confidence than a sysDescr string match, so this never
                # runs redundantly on top of a real MIB confirmation.
                if sys_descr and not (is_bridge or is_lldp) and _SNMP_SWITCH_DESCR_PATTERN.search(sys_descr):
                    logger.info(f"[*] SNMP Switch Candidate [{ip}]: sysDescr matched \"switch\" -- {sys_descr!r}")
                    _write_snmp_switch_candidate(mac, vendor, sys_descr)
            else:
                # NOARP-2 (2026-09-04): the F7 gateway-identity check just
                # above only ever ran inside the snmp_alive branch --
                # confirmed live, a real non-SNMP consumer router (TP-Link,
                # gateway IP, no SNMP at all) stayed classified as a plain
                # "Endpoint" forever, discovered via NOARP-1's local-ARP
                # fallback but never promoted, since nothing here checked
                # ip == gw_ip for a device that never answers SNMP. Same
                # anti-clobber reasoning as F7 still applies unchanged
                # (gw_ip comes from detect_default_gateway(), an
                # independently OS-level source, never the device's own
                # self-report) -- just needed to run regardless of SNMP
                # reachability, not only when it happens to succeed.
                if ip == gw_ip:
                    device_type = "Router"
                    logger.info(f"[*] Node Identified [{ip}]: Router (Gateway IP Ownership Match, no SNMP)")
                else:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1 FROM infrastructure_links WHERE remote_system_name = ? OR LOWER(remote_system_name) = LOWER(?)", (ip, mac))
                    is_lldp_target = cursor.fetchone()
                    conn.close()
                    if is_lldp_target:
                        logger.warning(f"[!] SNMP DEAD [{ip}]: Known infrastructure device failed to answer SNMP knock! (Check Community String)")
                        device_type = "Switch"
                        confidence = 50

            update_device_fingerprint(mac, sys_descr=sys_descr, sys_name=sys_name, device_type=device_type, vendor=vendor, category=category, market_segment=market_segment, confidence=confidence, owned_ips=list(owned_ips), owned_ip_macs=owned_ip_macs, own_interface_macs=own_interface_macs)

            # POLL-1: propagate the SAME result to any sibling MACs on
            # this node -- they weren't separately SNMP-queried, but
            # still need their own device_fingerprints/l2_interfaces
            # rows kept current (e.g. per-interface sysdescr display).
            # Vendor is looked up per-MAC individually, not copied --
            # it's derived from each MAC's own OUI, not the device's
            # SNMP response, and confirmed via TOPO-1 that a node's
            # interfaces aren't guaranteed to share one OUI block.
            for sibling_mac in sibling_macs:
                sibling_vendor_info = get_vendor_info(sibling_mac)
                update_device_fingerprint(sibling_mac, sys_descr=sys_descr, sys_name=sys_name, device_type=device_type, vendor=sibling_vendor_info["vendor"], category=sibling_vendor_info.get("category"), market_segment=sibling_vendor_info.get("market_segment"), confidence=confidence, owned_ips=[])

    await asyncio.gather(*(worker(mac, ip, t, siblings, os_family) for mac, ip, t, siblings, os_family in targets))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_fingerprinter())
