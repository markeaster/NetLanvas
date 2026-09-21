import sqlite3
import logging
import re
import ipaddress
import zlib
from engine.config_loader import config
from engine.oui_manager import get_vendor_info

logger = logging.getLogger("Netlanvas.Inference")

PSEUDO_MAC_PREFIX = '02:ff:'
HYSTERESIS_SECONDS = 86400

# WAP-1 (2026-09-21): infers a single unmanaged/non-SNMP wireless access
# point per network segment from its CLIENTS, when no real AP has been
# directly confirmed on that segment (fingerprinter.py's SNMP radio-
# interface detection, device_type == 'Access Point'). Deliberately a
# fallback signal, not a competing one -- a budget/consumer AP that
# doesn't speak SNMP at all is otherwise invisible as infrastructure
# even though its wireless clients are right there in the data.
#
# Uses a SEPARATE pseudo-MAC prefix (02:fe: vs dark matter's 02:ff:) so
# the two inference mechanisms never collide over the same address
# space, but follows the exact same active-set + hysteresis purge
# pattern as run_dark_matter_detection -- see ARP-1's lesson (a
# never-purges bug already bit this codebase once in l3_bindings, and
# again in smart_switch_candidates) for why this recomputes and
# retires itself every cycle rather than only ever inserting.
WAP_PSEUDO_MAC_PREFIX = '02:fe:'

# Word-bounded so "headphone"/"smartphone"/"watchdog" don't false-match
# -- a real device hostname containing one of these as a distinct word
# is a much stronger signal than a bare substring.
_MOBILE_HOSTNAME_PATTERN = re.compile(r'\b(iphone|ipad|tablet|phone|watch)\b', re.IGNORECASE)

# Deliberately a plain substring/keyword list against oui_manager's
# base (free-tier, always-available) vendor name -- NOT the Premium-
# tier "category" field (Mobile & Wearables), which would silently
# gate this entirely behind an entitlement most appliances don't have.
_MOBILE_VENDOR_KEYWORDS = (
    'apple', 'samsung', 'huawei', 'xiaomi', 'oneplus', 'google',
    'lg electronics', 'motorola', 'garmin', 'fitbit', 'oppo', 'vivo',
    'sony mobile', 'nokia', 'honor device',
)

# Deliberately well below dark matter's UM Switch confidence (50):
# hostname is self-reported/user-editable and the OUI half of the
# signal is routinely unavailable outright on modern iOS/Android
# devices (per-network private/randomized MAC addressing, on by
# default) -- weaker evidence than a live FDB anomaly, so it should
# read that way in the UI. Confidence rises with each additional
# DISTINCT matching device on the same segment (not each sighting),
# plus one bonus tier if at least one device's OUI corroborates the
# hostname via a real (non-randomized) vendor match.
WAP_CONFIDENCE_BASE = 15
WAP_CONFIDENCE_PER_EXTRA_DEVICE = 10
WAP_CONFIDENCE_VENDOR_BONUS = 10
WAP_CONFIDENCE_CAP = 45

def run_dark_matter_detection(conn):
    cursor = conn.cursor()

    cursor.execute('''
        SELECT el.switch_ip, el.local_port, COUNT(el.mac_address) as total_macs
        FROM endpoint_locations el
        WHERE el.local_port != 'WLAN' AND el.local_port != '0' AND el.local_port != 'Bridge'
        GROUP BY el.switch_ip, el.local_port
    ''')
    ports = cursor.fetchall()
    ambiguous_ports = set()

    for switch_ip, port, total_macs in ports:
        cursor.execute('''
            SELECT n.device_type, b.ip_address
            FROM infrastructure_links il
            LEFT JOIN l3_bindings b ON il.remote_system_name = b.ip_address
            LEFT JOIN l2_interfaces i ON b.mac_address = i.mac_address
            LEFT JOIN logical_nodes n ON i.node_id = n.id
            WHERE il.local_switch_ip = ? AND CAST(il.local_port AS INTEGER) = CAST(? AS INTEGER)
        ''', (switch_ip, port))
        infra = cursor.fetchone()

        if infra:
            dev_type, target_ip = infra
            if dev_type in ('Access Point', 'Switch / WAP'):
                cursor.execute("SELECT COUNT(*) FROM endpoint_locations WHERE switch_ip = ? AND local_port = 'WLAN'", (target_ip,))
                wlan_row = cursor.fetchone()
                wlan_count = wlan_row[0] if wlan_row else 0
                if total_macs > (wlan_count + 1):
                    ambiguous_ports.add((switch_ip, str(port)))
                    cursor.execute("UPDATE infrastructure_links SET is_ambiguous = 1 WHERE local_switch_ip = ? AND CAST(local_port AS INTEGER) = CAST(? AS INTEGER)", (switch_ip, port))
                    cursor.execute("UPDATE endpoint_locations SET is_ambiguous = 1 WHERE switch_ip = ? AND CAST(local_port AS INTEGER) = CAST(? AS INTEGER)", (switch_ip, port))
        else:
            cursor.execute("UPDATE endpoint_locations SET is_ambiguous = 0 WHERE switch_ip = ? AND CAST(local_port AS INTEGER) = CAST(? AS INTEGER)", (switch_ip, port))

    cursor.execute('''
        SELECT el.switch_ip, el.local_port, COUNT(DISTINCT l2.node_id) as node_count,
               MAX(el.local_port_name) as local_port_name, MAX(el.link_speed) as link_speed
        FROM endpoint_locations el
        LEFT JOIN l2_interfaces l2 ON el.mac_address = l2.mac_address
        WHERE el.local_port != 'WLAN' AND el.local_port != '0' AND el.local_port != 'Bridge'
        AND NOT EXISTS (
            SELECT 1 FROM infrastructure_links il
            WHERE il.local_switch_ip = el.switch_ip
              AND CAST(il.local_port AS INTEGER) = CAST(el.local_port AS INTEGER)
              AND il.is_ambiguous = 0
              AND il.remote_system_name NOT LIKE ?
        )
        -- DARKMATTER-1 (2026-09-21): found live during an AP swap -- a
        -- confirmed Access Point's own WiFi clients legitimately fan
        -- out as multiple distinct MACs behind its single wired
        -- uplink port (the switch's FDB sees them all arrive on that
        -- one port, since that's how bridging works). This heuristic
        -- had no way to tell that apart from a real hidden unmanaged
        -- switch, so it false-positived a phantom UM Switch every
        -- time. If ANY device already seen on this exact port is a
        -- confirmed Access Point, the multi-MAC fan-out is expected --
        -- skip it, same as the existing WLAN-port exclusion above
        -- already does for the AP's *wireless* side.
        AND NOT EXISTS (
            SELECT 1 FROM endpoint_locations el2
            JOIN l2_interfaces l3 ON el2.mac_address = l3.mac_address
            JOIN logical_nodes n3 ON l3.node_id = n3.id
            WHERE el2.switch_ip = el.switch_ip
              AND el2.local_port = el.local_port
              AND n3.device_type = 'Access Point'
        )
        GROUP BY el.switch_ip, el.local_port
        HAVING node_count > 1
    ''', (f"{PSEUDO_MAC_PREFIX}%",))

    # local_port_name/link_speed (2026-09-08): endpoint_locations
    # already captures both from the SAME FDB scan that flagged this
    # port as hosting multiple devices in the first place -- every MAC
    # behind one physical port shares the same real port name/speed,
    # so MAX() above just picks any one non-null value (they should
    # all agree). Previously dropped entirely: this SELECT only ever
    # asked for switch_ip/local_port/node_count, so the Unmanaged
    # Switch link this function creates below had no port name or
    # speed to write even though the data was sitting right there.
    anomalies = cursor.fetchall()
    active_pseudo_macs = set()

    if anomalies: logger.info(f"Dark Matter Check: Found {len(anomalies)} ports exhibiting hidden bridging.")
    else: logger.info("Dark Matter Check: No hidden Layer 2 bridges detected.")

    cursor.execute("CREATE TABLE IF NOT EXISTS oui_index (oui TEXT PRIMARY KEY, vendor_name TEXT)")

    for anomaly in anomalies:
        switch_ip, port, node_count, local_port_name, link_speed = anomaly
        is_ambiguous = 1 if (switch_ip, str(port)) in ambiguous_ports else 0

        cursor.execute("SELECT n.device_type FROM logical_nodes n JOIN l2_interfaces i ON n.id = i.node_id JOIN l3_bindings b ON i.mac_address = b.mac_address WHERE b.ip_address = ? LIMIT 1", (switch_ip,))
        parent_type_row = cursor.fetchone()
        is_router = parent_type_row and parent_type_row[0] == 'Router'

        node_name = 'Orphaned Endpoints' if is_router else 'UM Switch'
        vendor_name = 'Netlanvas Orphan Catcher' if is_router else 'Netlanvas Inferred Unmanaged Switch'

        # Severity follows is_ambiguous, not a flat WARNING: this fires
        # every deep-scan cycle for every inferred unmanaged switch --
        # normal, permanent network topology (an unmanaged switch
        # doesn't speak SNMP, so this is simply how it gets
        # represented). A CONFIDENT inference (Ambiguous: False) isn't
        # worth an admin's attention every cycle -- INFO, matching the
        # summary line above ("Dark Matter Check: Found N ports...")
        # which already uses INFO for the same event. A genuinely
        # AMBIGUOUS one is the real signal worth surfacing: it's the
        # same flag /api/node/verify exists to let an admin clear, so
        # it stays WARNING.
        log_fn = logger.warning if is_ambiguous else logger.info
        log_fn(f"[*] Inferred Opaque Layer 2 Bridge on {switch_ip} Port {port}. Hosting {node_count} distinct nodes. (Ambiguous: {bool(is_ambiguous)})")

        ip_parts = switch_ip.split('.')
        if len(ip_parts) == 4:
            hex_ip = [f"{int(x):02x}" for x in ip_parts[:4]]
            hex_port = f"{int(port) % 256:02x}"
            pseudo_mac = f"02:ff:{hex_ip[1]}:{hex_ip[2]}:{hex_ip[3]}:{hex_port}"
            pseudo_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{int(ip_parts[3]) * 1000 + int(port)}"
            oui_base = f"02ff{hex_ip[1]}"
        else:
            pseudo_mac = f"02:ff:00:00:00:{int(port)%256:02x}"
            pseudo_ip = f"127.0.0.{1000 + int(port)}"
            oui_base = "02ff00"

        active_pseudo_macs.add(pseudo_mac)

        cursor.execute("INSERT OR IGNORE INTO oui_index VALUES (?, ?)", (oui_base, vendor_name))
        cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (pseudo_mac,))
        node_row = cursor.fetchone()

        if not node_row:
            cursor.execute("INSERT INTO logical_nodes (hostname, device_type, weld_confidence) VALUES (?, 'Unmanaged Switch', 50)", (node_name,))
            node_id = cursor.lastrowid
            cursor.execute("INSERT OR IGNORE INTO l2_interfaces (mac_address, node_id, is_virtual, vendor) VALUES (?, ?, 1, ?)", (pseudo_mac, node_id, vendor_name))
        else:
            node_id = node_row[0]
            cursor.execute("SELECT hostname FROM logical_nodes WHERE id = ?", (node_id,))
            current_hostname_row = cursor.fetchone()
            current_hostname = current_hostname_row[0] if current_hostname_row else ""

            if not current_hostname or current_hostname in ('UM Switch', 'Orphaned Endpoints'):
                cursor.execute("UPDATE logical_nodes SET hostname = ? WHERE id = ?", (node_name, node_id))

            cursor.execute("UPDATE l2_interfaces SET vendor = ? WHERE mac_address = ?", (vendor_name, pseudo_mac))

        cursor.execute('''
            INSERT INTO l3_bindings (ip_address, mac_address, discovery_source, is_public, last_seen)
            VALUES (?, ?, 'DARK_MATTER_INFERENCE', 0, CURRENT_TIMESTAMP)
            ON CONFLICT(ip_address) DO UPDATE SET mac_address=excluded.mac_address, last_seen=CURRENT_TIMESTAMP
        ''', (pseudo_ip, pseudo_mac))

        # local_port_name/link_speed (2026-09-08): sourced from the
        # anomaly query's own MAX() above, not re-derived here -- same
        # FDB scan, same port, no reason to requery. Included in the
        # ON CONFLICT UPDATE too so a port that flips from "already had
        # a confirmed device" to "now ambiguous" (or vice versa) still
        # gets its port name/speed refreshed, not just left at
        # whatever an earlier pass happened to write.
        cursor.execute('''
            INSERT INTO infrastructure_links (local_switch_ip, local_port, local_port_name, link_speed, remote_system_name, is_ambiguous, last_mapped)
            VALUES (?, CAST(? AS INTEGER), ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(local_switch_ip, local_port) DO UPDATE SET local_port_name=excluded.local_port_name, link_speed=excluded.link_speed, remote_system_name=excluded.remote_system_name, is_ambiguous=excluded.is_ambiguous, last_mapped=CURRENT_TIMESTAMP
        ''', (switch_ip, port, local_port_name, link_speed, pseudo_ip, is_ambiguous))

        cursor.execute('''
            SELECT b.ip_address, el.vlan_id
            FROM endpoint_locations el
            JOIN l3_bindings b ON el.mac_address = b.mac_address
            JOIN l2_interfaces i ON el.mac_address = i.mac_address
            JOIN logical_nodes n ON i.node_id = n.id
            WHERE el.switch_ip = ? AND CAST(el.local_port AS INTEGER) = CAST(? AS INTEGER)
            AND n.device_type IN ('Access Point', 'Switch', 'Router', 'Switch / WAP')
        ''', (switch_ip, port))
        
        downstream_infra = cursor.fetchall()
        sim_port = 1
        
        for target_ip, target_vlan in downstream_infra:
            if target_ip != pseudo_ip:
                cursor.execute('''
                    INSERT INTO infrastructure_links (local_switch_ip, local_port, remote_system_name, vlan_id, is_ambiguous, last_mapped)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(local_switch_ip, local_port) DO UPDATE SET remote_system_name=excluded.remote_system_name, vlan_id=excluded.vlan_id, is_ambiguous=excluded.is_ambiguous, last_mapped=CURRENT_TIMESTAMP
                ''', (pseudo_ip, sim_port, target_ip, target_vlan, is_ambiguous))
                sim_port += 1

    cursor.execute("SELECT mac_address, ip_address FROM l3_bindings WHERE mac_address LIKE ? AND (strftime('%s', 'now') - strftime('%s', last_seen)) > ?", (f"{PSEUDO_MAC_PREFIX}%", HYSTERESIS_SECONDS))
    expired_pseudo_devices = cursor.fetchall()
    
    if expired_pseudo_devices:
        logger.info(f"[*] Hysteresis Timeout: Purging {len(expired_pseudo_devices)} ghost bridges aged > {HYSTERESIS_SECONDS} seconds.")

    for pseudo_mac, pseudo_ip in expired_pseudo_devices:
        if pseudo_mac not in active_pseudo_macs:
            cursor.execute("DELETE FROM infrastructure_links WHERE remote_system_name = ?", (pseudo_ip,))
            cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (pseudo_mac,))
            node_row = cursor.fetchone()
            if node_row:
                cursor.execute("DELETE FROM l3_bindings WHERE ip_address = ?", (pseudo_ip,))
                cursor.execute("DELETE FROM l2_interfaces WHERE mac_address = ?", (pseudo_mac,))
                cursor.execute("DELETE FROM logical_nodes WHERE id = ?", (node_row[0],))

    conn.commit()

def _segment_for_ip(ip_str, subnets):
    """
    Resolves an IP to a segment key: the VLAN ID if router_subnets has
    a confirmed subnet containing it (the same authoritative router-
    interface data auto_discovery.py's discover_active_subnets() uses),
    else the subnet CIDR string itself when VLAN tagging isn't in play
    (a flat single-VLAN network still needs two DIFFERENT subnets to
    read as two different segments), else a naive /24 fallback so this
    still degrades gracefully before router_subnets has ever been
    populated (brand-new DB, first deep-scan not yet run).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net, key in subnets:
        if ip_obj in net:
            return key
    return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))


def run_wap_inference(conn):
    cursor = conn.cursor()

    cursor.execute("SELECT subnet, vlan_id FROM router_subnets")
    subnets = []
    for subnet_str, vlan_id in cursor.fetchall():
        try:
            subnets.append((ipaddress.ip_network(subnet_str, strict=False), vlan_id if vlan_id is not None else subnet_str))
        except ValueError:
            continue

    # Segments with a directly-confirmed AP (SNMP radio interface, see
    # fingerprinter.py) never get a competing inferred node -- WAP-1 is
    # strictly a fallback for the gap that leaves.
    cursor.execute('''
        SELECT DISTINCT b.ip_address
        FROM logical_nodes n
        JOIN l2_interfaces i ON n.id = i.node_id
        JOIN l3_bindings b ON i.mac_address = b.mac_address
        WHERE n.device_type = 'Access Point'
    ''')
    confirmed_segments = {_segment_for_ip(row[0], subnets) for row in cursor.fetchall()}

    cursor.execute('''
        SELECT n.id, i.mac_address, b.ip_address
        FROM logical_nodes n
        JOIN l2_interfaces i ON n.id = i.node_id
        JOIN l3_bindings b ON i.mac_address = b.mac_address
        WHERE i.is_virtual = 0 AND n.hostname IS NOT NULL AND n.device_type NOT IN ('Access Point', 'Router', 'Switch', 'Switch / WAP')
    ''')
    candidates_by_segment = {}
    for node_id, mac, ip in cursor.fetchall():
        cursor2 = conn.cursor()
        cursor2.execute("SELECT hostname FROM logical_nodes WHERE id = ?", (node_id,))
        hostname_row = cursor2.fetchone()
        hostname = hostname_row[0] if hostname_row else None
        if not hostname or not _MOBILE_HOSTNAME_PATTERN.search(hostname):
            continue
        segment = _segment_for_ip(ip, subnets)
        if segment is None or segment in confirmed_segments:
            continue
        candidates_by_segment.setdefault(segment, {})[node_id] = mac

    active_pseudo_macs = set()

    if candidates_by_segment:
        logger.info(f"WAP Inference: {len(candidates_by_segment)} segment(s) with mobile-hostname devices and no confirmed AP.")
    else:
        logger.info("WAP Inference: No unverified segments with mobile-device hostname matches this cycle.")

    for segment, devices in candidates_by_segment.items():
        confidence = WAP_CONFIDENCE_BASE + WAP_CONFIDENCE_PER_EXTRA_DEVICE * (len(devices) - 1)

        vendor_corroborated = False
        for mac in devices.values():
            info = get_vendor_info(mac) or {}
            vendor = (info.get("vendor") or "").lower()
            if any(kw in vendor for kw in _MOBILE_VENDOR_KEYWORDS):
                vendor_corroborated = True
                break
        if vendor_corroborated:
            confidence += WAP_CONFIDENCE_VENDOR_BONUS

        confidence = min(confidence, WAP_CONFIDENCE_CAP)
        segment_label = f"VLAN {segment}" if isinstance(segment, int) else str(segment)

        # Deterministic per-segment pseudo-identity so the SAME segment
        # always maps back to the SAME inferred node across cycles
        # (needed for the active-set purge below to recognize "this
        # segment's node is still current" rather than creating a new
        # one every cycle).
        # WAP-BUGFIX (2026-09-21, found live during first functional
        # test): a 24-bit seed only fills 3 of the 4 remaining octets
        # after the 2-octet '02:fe:' prefix, producing a malformed
        # 5-octet MAC ("02:fe:5a:c9:f2"). Needs a full 32-bit seed to
        # fill all 4 remaining octets for a valid 6-octet address.
        seed = zlib.crc32(str(segment).encode()) & 0xffffffff
        hex_seed = f"{seed:08x}"
        pseudo_mac = f"{WAP_PSEUDO_MAC_PREFIX}{hex_seed[0:2]}:{hex_seed[2:4]}:{hex_seed[4:6]}:{hex_seed[6:8]}"
        pseudo_ip = f"169.254.{(seed >> 8) & 0xff}.{seed & 0xff}"
        active_pseudo_macs.add(pseudo_mac)

        node_name = f"Inferred WAP ({segment_label})"
        vendor_name = "Netlanvas Inferred Wireless Access Point"

        cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (pseudo_mac,))
        node_row = cursor.fetchone()

        if not node_row:
            cursor.execute(
                "INSERT INTO logical_nodes (hostname, device_type, weld_confidence) VALUES (?, 'Access Point (Unverified)', ?)",
                (node_name, confidence),
            )
            node_id = cursor.lastrowid
            cursor.execute(
                "INSERT OR IGNORE INTO l2_interfaces (mac_address, node_id, is_virtual, vendor) VALUES (?, ?, 1, ?)",
                (pseudo_mac, node_id, vendor_name),
            )
        else:
            node_id = node_row[0]
            # Only touch nodes still in their own inferred state -- a
            # user who's confirmed or reclassified this node (weld_
            # confidence 100 via /api/node/verify) has moved it out of
            # 'Access Point (Unverified)' already, so this WHERE simply
            # never matches it again. Same anti-clobber shape as
            # fingerprinter.py's protected-profile check.
            cursor.execute(
                "UPDATE logical_nodes SET weld_confidence = ?, hostname = ? WHERE id = ? AND device_type = 'Access Point (Unverified)'",
                (confidence, node_name, node_id),
            )

        cursor.execute('''
            INSERT INTO l3_bindings (ip_address, mac_address, discovery_source, is_public, last_seen)
            VALUES (?, ?, 'WAP_INFERENCE', 0, CURRENT_TIMESTAMP)
            ON CONFLICT(ip_address) DO UPDATE SET mac_address=excluded.mac_address, last_seen=CURRENT_TIMESTAMP
        ''', (pseudo_ip, pseudo_mac))

        logger.info(f"[*] WAP Inference: {len(devices)} mobile-hostname device(s) on segment {segment_label}, no confirmed AP -- inferred node at confidence {confidence}{' (vendor-corroborated)' if vendor_corroborated else ''}.")

    # Retirement: same hysteresis pattern as dark matter's ghost-bridge
    # purge -- a segment that stops qualifying (real AP later confirmed,
    # or all matching devices leave/get renamed) simply stops being
    # refreshed above, and ages out here instead of lingering forever.
    cursor.execute(
        "SELECT mac_address, ip_address FROM l3_bindings WHERE mac_address LIKE ? AND (strftime('%s', 'now') - strftime('%s', last_seen)) > ?",
        (f"{WAP_PSEUDO_MAC_PREFIX}%", HYSTERESIS_SECONDS),
    )
    expired = cursor.fetchall()
    for pseudo_mac, pseudo_ip in expired:
        if pseudo_mac in active_pseudo_macs:
            continue
        cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (pseudo_mac,))
        node_row = cursor.fetchone()
        if node_row:
            cursor.execute(
                "SELECT device_type FROM logical_nodes WHERE id = ? AND device_type = 'Access Point (Unverified)'",
                (node_row[0],),
            )
            if cursor.fetchone():
                logger.info(f"[*] WAP Inference: retiring stale inferred node ({pseudo_mac}), condition no longer holds.")
                cursor.execute("DELETE FROM l3_bindings WHERE ip_address = ?", (pseudo_ip,))
                cursor.execute("DELETE FROM l2_interfaces WHERE mac_address = ?", (pseudo_mac,))
                cursor.execute("DELETE FROM logical_nodes WHERE id = ?", (node_row[0],))

    conn.commit()


# ORPHAN-1 (2026-09-21): found live via a forced topology rebuild right
# after a real AP swap -- the retired unit's node (device_type=
# 'Access Point', weld_confidence=100) had zero rows in l3_bindings AND
# zero in endpoint_locations, yet nothing in the codebase ever revisits
# a node once it's fully orphaned like that. weld_confidence=100's
# anti-clobber protection (rightly) stops a WORSE GUESS from
# downgrading a confirmed device -- this is a different case entirely,
# a total absence of signal, which that protection was never designed
# for. The Graph UI rendered it anyway (apparently defaulting a
# locationless node to "attached to the router"), permanently, since
# no purge mechanism -- ARP-1, SMARTSW-3, dark matter's or WAP-1's own
# hysteresis -- covers a node whose CHILD rows have vanished entirely
# (those all age data that's still present; here there's nothing left
# to age). device_state.last_seen is the only durable timestamp on a
# node at all (logical_nodes itself has none), so it's the retention
# clock here -- deliberately a LONGER window than ARP-1/SMARTSW-3's 3 hours: losing an entire infrastructure node is more consequential than a stale ARP entry or candidate suggestion, and deserves more grace (a longer maintenance window, an overnight outage) before being erased from the topology.
# Virtual (is_virtual=1) nodes are excluded: dark matter and WAP-1
# already own their own pseudo-nodes' lifecycle.
ORPHAN_NODE_PURGE_AGE_SECONDS = 12 * 60 * 60


def run_orphan_node_sweep(conn):
    cursor = conn.cursor()

    cursor.execute('''
        SELECT n.id, i.mac_address
        FROM logical_nodes n
        JOIN l2_interfaces i ON n.id = i.node_id
        WHERE i.is_virtual = 0
    ''')
    nodes = {}
    for node_id, mac in cursor.fetchall():
        nodes.setdefault(node_id, []).append(mac)

    purged = 0
    for node_id, macs in nodes.items():
        has_any_binding = False
        newest_last_seen = None
        for mac in macs:
            cursor.execute("SELECT 1 FROM l3_bindings WHERE mac_address = ? LIMIT 1", (mac,))
            if cursor.fetchone():
                has_any_binding = True
                break
            cursor.execute("SELECT 1 FROM endpoint_locations WHERE mac_address = ? LIMIT 1", (mac,))
            if cursor.fetchone():
                has_any_binding = True
                break
            cursor.execute("SELECT last_seen FROM device_state WHERE mac_address = ?", (mac,))
            row = cursor.fetchone()
            if row and row[0] and (newest_last_seen is None or row[0] > newest_last_seen):
                newest_last_seen = row[0]

        if has_any_binding:
            continue
        # No device_state row for any of this node's MACs at all -- can't
        # safely establish how long it's been orphaned, so skip rather
        # than risk purging a node that's simply too new to have been
        # picked up by device_state_tracker yet.
        if newest_last_seen is None:
            continue

        cursor.execute(
            "SELECT (strftime('%s', 'now') - strftime('%s', ?)) > ?",
            (newest_last_seen, ORPHAN_NODE_PURGE_AGE_SECONDS),
        )
        if not cursor.fetchone()[0]:
            continue

        cursor.execute("SELECT hostname, device_type FROM logical_nodes WHERE id = ?", (node_id,))
        hostname_row = cursor.fetchone()
        logger.info(f"[*] Orphan Sweep: retiring '{hostname_row[0] if hostname_row else node_id}' ({hostname_row[1] if hostname_row else '?'}) -- no location data for over 12 hours.")
        cursor.execute("DELETE FROM logical_nodes WHERE id = ?", (node_id,))
        purged += 1

    if purged:
        logger.info(f"[*] Orphan Sweep: purged {purged} fully-orphaned node(s).")
    conn.commit()


def run_inference_cycle():
    logger.info("--- Starting Netlanvas Inference Cycle ---")
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        run_dark_matter_detection(conn)
        run_wap_inference(conn)
        run_orphan_node_sweep(conn)
    except Exception as e: logger.error(f"Inference Cycle Failed: {e}")
    finally: conn.close()
    logger.info("--- Inference Cycle Complete ---")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_inference_cycle()
