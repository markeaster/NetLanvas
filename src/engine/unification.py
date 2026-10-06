import sqlite3
import logging
import os
from engine.config_loader import config
from engine.hostname_registry import set_hostname_by_mac, PRIORITY_LLDP_SYSNAME, PRIORITY_DHCP
from security import sync_client

logger = logging.getLogger("Netlanvas.Unification")
DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")

def mac_to_int(mac_str):
    return int(mac_str.replace(":", ""), 16)

def enforce_db_triggers():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Protect verified core infrastructure from mDNS/broadcast hijacking
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS protect_core_identity BEFORE UPDATE OF os_family, hostname ON logical_nodes
        FOR EACH ROW
        WHEN OLD.weld_confidence = 100 AND OLD.device_type IN ('Router', 'Switch', 'Docker Host', 'Hypervisor', 'Server', 'Printer')
        BEGIN
            SELECT CASE WHEN NEW.os_family = 'mDNS Node' THEN RAISE(IGNORE) END;
        END;
    ''')
    
    # Revert any corrupted identities currently in the database
    cursor.execute('''
        UPDATE logical_nodes 
        SET os_family = 'Hardware OS', 
            hostname = COALESCE((
                SELECT df.snmp_sysdescr FROM device_fingerprints df 
                JOIN l2_interfaces l2 ON df.mac_address = l2.mac_address 
                WHERE l2.node_id = logical_nodes.id LIMIT 1
            ), 'Core Infrastructure')
        WHERE id IN (
            SELECT ln.id FROM logical_nodes ln
            JOIN l2_interfaces l2 ON ln.id = l2.node_id
            JOIN device_fingerprints df ON l2.mac_address = df.mac_address
            WHERE ln.os_family = 'mDNS Node' AND df.snmp_sysdescr IS NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def run_arp_confirmed_weld_pass():
    """
    F7 follow-up: update_device_fingerprint() no longer trusts a
    device's own SNMP self-report to merge node identities (closes
    CWE-290 -- see fingerprinter.py). That was, in practice, the only
    mechanism that ever unified a router's multiple gateway-IP
    interfaces into one node: a router's own uplink MAC never gets an
    endpoint_locations row (its port is always penalized as backbone,
    per run_hardware_weld_pass's own ghost-candidate query below), so
    it can never become a "ghost" candidate for that pass either -- a
    multi-homed router was left with no safety net at all, confirmed
    live: a single physical router's gateway IPs split across 3
    separate logical_nodes rows after the F7 fix.

    This pass closes that gap using ONLY independently-observed data,
    never a device's own claim about itself: two MACs, each already
    holding at least one ROUTER_ARP_CACHE-sourced l3_bindings row (the
    router's own ARP cache, scraped by stage_arp_scrape() -- never
    anything either device self-reported), and hardware-proximate by
    the same convention run_hardware_weld_pass already uses, are
    merged into one node. Because neither side's own SNMP response is
    ever consulted, this cannot be exploited the way the removed
    self-report merge could: an attacker's rogue device would need to
    actually get itself recorded in the router's real ARP table under
    a MAC numerically close to a genuine router interface, a
    materially different bar than just answering an SNMP probe.

    NOTE: an earlier revision of this pass also merged on identical
    device_fingerprints.snmp_sysdescr as a second corroboration
    signal, meant to catch a device's radio/secondary interface
    answering from a different OUI block (e.g. a router's WiFi radio).
    Reverted after confirming live: multiple genuinely distinct
    Ubiquiti APs of the same model on the same firmware share an
    identical sysDescr banner by design (fleet-wide firmware updates),
    so that signal incorrectly merged 4 separate physical access
    points into one node. This is a common case for AP/switch fleets,
    not a rare edge case -- sysDescr alone is not safe corroboration
    for any device type that's commonly deployed in multiples. The
    original motivating case (a router's non-proximate radio MAC) is
    left unresolved for now rather than reintroducing this risk;
    needs a narrower signal (e.g. LLDP-reported local port name
    matching a known port of the primary node) designed and verified
    separately before attempting again.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    merges = 0
    for _ in range(5):  # small fixed cap -- converges quickly on real data, never loops indefinitely
        rows = cursor.execute("""
            SELECT DISTINCT i.mac_address, i.node_id
            FROM l3_bindings b
            JOIN l2_interfaces i ON b.mac_address = i.mac_address
            WHERE b.discovery_source = 'ROUTER_ARP_CACHE' AND i.node_id IS NOT NULL
        """).fetchall()

        made_a_merge = False
        for idx, (mac_a, node_a) in enumerate(rows):
            for mac_b, node_b in rows[idx + 1:]:
                if node_a == node_b:
                    continue
                try:
                    proximate = abs(mac_to_int(mac_a) - mac_to_int(mac_b)) <= 16
                except ValueError:
                    continue
                if not proximate:
                    continue
                keeper, loser = (node_a, node_b) if node_a < node_b else (node_b, node_a)
                cursor.execute('UPDATE l2_interfaces SET node_id = ? WHERE node_id = ?', (keeper, loser))
                cursor.execute('DELETE FROM logical_nodes WHERE id = ?', (loser,))
                merges += 1
                made_a_merge = True
                break
            if made_a_merge:
                break
        if not made_a_merge:
            break

    conn.commit()
    conn.close()
    return merges


def run_hardware_weld_pass():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT n.id, n.hostname, i.mac_address
        FROM logical_nodes n
        JOIN l2_interfaces i ON n.id = i.node_id
        WHERE (n.device_type IN ('Switch', 'Router', 'Access Point', 'Switch / WAP') OR n.hostname LIKE '%MikroTik%')
        AND i.mac_address IS NOT NULL
    ''')
    infra_nodes = cursor.fetchall()

    cursor.execute('''
        SELECT DISTINCT el.mac_address
        FROM endpoint_locations el
        LEFT JOIN l2_interfaces i ON el.mac_address = i.mac_address
        WHERE i.node_id IS NULL OR i.mac_address IS NULL
    ''')
    ghosts = [row[0] for row in cursor.fetchall()]

    welds_made = 0
    for ghost in ghosts:
        try: ghost_int = mac_to_int(ghost)
        except ValueError: continue

        for node_id, hostname, base_mac in infra_nodes:
            try: base_int = mac_to_int(base_mac)
            except ValueError: continue

            welded = False
            is_virtual = 0

            if abs(ghost_int - base_int) <= 16:
                welded = True
            elif ghost.startswith("04:f4:bc:") and "Routerboard" in (hostname or ""):
                welded = True
                is_virtual = 1

            if welded:
                cursor.execute('SELECT 1 FROM l2_interfaces WHERE mac_address = ?', (ghost,))
                if cursor.fetchone():
                    cursor.execute('UPDATE l2_interfaces SET node_id = ?, is_virtual = ? WHERE mac_address = ?', (node_id, is_virtual, ghost))
                else:
                    cursor.execute('INSERT INTO l2_interfaces (mac_address, node_id, is_virtual) VALUES (?, ?, ?)', (ghost, node_id, is_virtual))
                welds_made += 1
                break

    conn.commit()
    conn.close()
    return welds_made

def run_heuristic_pass():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, GROUP_CONCAT(mac_address) FROM l3_bindings GROUP BY ip_address HAVING COUNT(mac_address) > 1")
    matches = cursor.fetchall()
    welded = 0

    for ip, mac_list_str in matches:
        macs = mac_list_str.split(',')
        cursor.execute(f"SELECT node_id FROM l2_interfaces WHERE mac_address IN ({','.join(['?']*len(macs))}) AND node_id IS NOT NULL LIMIT 1", macs)
        existing_node = cursor.fetchone()

        if existing_node:
            node_id = existing_node[0]
        else:
            cursor.execute('INSERT INTO logical_nodes (hostname, device_type, weld_confidence) VALUES (?, ?, 80)', (f"Multi-homed Host: {ip}", "Aggregated Node"))
            node_id = cursor.lastrowid

        for mac in macs:
            cursor.execute('UPDATE l2_interfaces SET node_id = ? WHERE mac_address = ?', (node_id, mac))
            welded += 1

    conn.commit()
    conn.close()
    return welded

def run_singleton_pass():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()
    cursor.execute("SELECT mac_address, vendor FROM l2_interfaces WHERE node_id IS NULL")
    orphans = cursor.fetchall()
    created = 0

    for mac, vendor in orphans:
        hostname = f"Device ({vendor or 'Unknown'})"
        cursor.execute('INSERT INTO logical_nodes (hostname, device_type, weld_confidence) VALUES (?, ?, 100)', (hostname, "Endpoint"))
        node_id = cursor.lastrowid
        cursor.execute('UPDATE l2_interfaces SET node_id = ? WHERE mac_address = ?', (node_id, mac))
        created += 1

    conn.commit()
    conn.close()
    return created

def run_classification_pass():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE logical_nodes SET device_type = 'Access Point' WHERE id IN (
            SELECT ln.id FROM logical_nodes ln JOIN l2_interfaces l2 ON ln.id = l2.node_id
            JOIN device_fingerprints df ON l2.mac_address = df.mac_address
            WHERE ln.device_type != 'Access Point'
            AND (LOWER(df.snmp_sysdescr) LIKE '%access point%' OR LOWER(df.snmp_sysdescr) LIKE '%uap%' OR LOWER(df.snmp_sysdescr) LIKE '%unifi%')
        )
    ''')
    ap_updates = cursor.rowcount

    cursor.execute('''
        UPDATE logical_nodes SET device_type = 'Switch' WHERE id IN (
            SELECT ln.id FROM logical_nodes ln JOIN l2_interfaces l2 ON ln.id = l2.node_id
            JOIN l3_bindings b ON l2.mac_address = b.mac_address JOIN infrastructure_links il ON b.ip_address = il.local_switch_ip
            WHERE ln.device_type NOT IN ('Switch', 'Router', 'Access Point', 'Switch / WAP', 'Docker Host', 'Hypervisor', 'Smart Switch', 'Smart Switch (Unverified)', 'Server', 'Printer')
        )
    ''')
    switch_updates = cursor.rowcount

    # ARCHITECTURAL ENHANCEMENT: Docker Host Fingerprinting
    cursor.execute('''
        UPDATE logical_nodes SET device_type = 'Docker Host' WHERE id IN (
            SELECT ln.id FROM logical_nodes ln
            JOIN l2_interfaces l2 ON ln.id = l2.node_id
            JOIN l3_bindings b ON l2.mac_address = b.mac_address
            WHERE b.ip_address LIKE '172.17.%' OR b.ip_address LIKE '172.18.%' OR b.ip_address LIKE '172.19.%'
        ) AND device_type != 'Docker Host'
    ''')
    docker_updates = cursor.rowcount

    conn.commit()
    conn.close()
    return ap_updates, switch_updates, docker_updates

# Protocols whose replies are the device's own affirmative self-identification
# (vendor+model+firmware straight from a standard, non-reverse-engineered
# protocol, with a MAC cross-verified via the reply itself) -- trusted at the
# same tier as LLDP sysName, no human click required. See module note in
# run_smart_switch_candidate_pass() below for why this is split from the
# reverse-engineered protocols, which still require confirmation.
#
# SNMP-SWITCH-1 (2026-09-19): SNMP sysDescr belongs here too, not with
# NSDP/ESCP -- it's a device's own self-reported identity over a real,
# documented protocol (MIB-II), same category of evidence as an SSDP
# reply, not a guessed proprietary byte layout. MAC verification differs
# slightly from SSDP's (the IP polled was already ARP/DHCP-confirmed to
# that MAC before fingerprinter.py ever queried it, rather than a
# broadcast reply self-reporting its own MAC) but is equally hard to
# spoof -- a unicast SNMP reply from an already-bound IP, not injectable
# the way a broadcast response could be.
_SELF_IDENTIFYING_PROTOCOLS = {"SSDP", "SNMP"}

# Legitimate infra classifications a smart-switch candidate hit must never
# downgrade -- a real SNMP-confirmed Switch/Router/AP outranks any smart-
# switch guess, confirmed or not (INVENTORY-2, 2026-09-04, fixed after a live
# regression on main: an SNMP-answering GS110TPv3 was silently relabeled
# down to "Smart Switch (Unverified)" because this list only protected
# Router/Docker Host/Hypervisor, not Switch/AP/Switch-WAP).
_PROTECTED_DEVICE_TYPES = ('Router', 'Docker Host', 'Hypervisor', 'Switch', 'Access Point', 'Switch / WAP', 'Smart Switch', 'Server', 'Printer')


def run_smart_switch_candidate_pass():
    """
    INVENTORY-1/2 (2026-09-04, ported from main): applies
    engine/smart_switch_pipeline.py's latest findings (written by main.py's
    stage_smart_switch_discovery() into this cycle's smart_switch_candidates
    table) onto any matching node -- with the confidence split by PROTOCOL,
    not treated uniformly:

    - SSDP (_SELF_IDENTIFYING_PROTOCOLS): the device answered a standard,
      documented protocol with its own vendor+model+firmware, and the MAC
      came from the reply itself (not a guess) -- this is factual evidence
      the device volunteered, not an inference needing a human to bless it.
      Auto-confirms: device_type='Smart Switch' (not Unverified), hostname
      set via the normal hostname_registry priority system at
      PRIORITY_LLDP_SYSNAME (same tier as "a neighbor told us its name over
      a real protocol"), AND auto-written into inventory.db so it survives
      a Clean Slate purge without waiting on a manual click.
    - Everything else (NSDP, ESCP, any future reverse-engineered protocol):
      genuinely unverified -- best-effort guesses at an undocumented byte
      layout that, as of 2026-09-04, have never once produced a real reply
      against tested hardware. Stays as a low-confidence suggestion:
      device_type='Smart Switch (Unverified)', hostname offered at
      PRIORITY_DHCP (loses to literally any other real signal), NOT written
      to inventory.db -- still needs a human to confirm via
      /api/node/update or /api/promote_node.

    Either path skips a MAC that already has a human-confirmed record in
    inventory.db (strictly stronger evidence than either tier here), and
    never downgrades a node already holding a _PROTECTED_DEVICE_TYPES
    classification.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS smart_switch_candidates (
            mac_address TEXT PRIMARY KEY,
            vendor TEXT,
            model TEXT,
            protocol TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # SMARTSW-3 (2026-09-21): same never-purges shape ARP-1 found in
    # l3_bindings -- every producer (SSDP/NSDP/ESCP in
    # smart_switch_pipeline.py, SNMP in fingerprinter.py) upserts
    # last_seen correctly, but nothing ever removed a row once its
    # device stopped being re-discovered (unplugged, replaced, swapped
    # out). Left unbounded, a stale candidate sits here forever and can
    # misapply itself to a future, unrelated device that happens to
    # reuse the same MAC's node_id after a Clean Slate purge. Same
    # age-based retirement as ARP-1, same 3-hour window, no schema
    # change needed -- last_seen was already there.
    SMART_SWITCH_CANDIDATE_PURGE_AGE_SECONDS = 3 * 60 * 60
    cursor.execute(
        "DELETE FROM smart_switch_candidates WHERE (strftime('%s', 'now') - strftime('%s', last_seen)) > ?",
        (SMART_SWITCH_CANDIDATE_PURGE_AGE_SECONDS,),
    )
    purged = cursor.rowcount
    if purged:
        logger.info(f"[SmartSwitch] Purged {purged} stale candidate(s) not re-confirmed in over 3 hours.")

    candidates = cursor.execute("SELECT mac_address, vendor, model, protocol FROM smart_switch_candidates").fetchall()
    if not candidates:
        conn.commit()
        conn.close()
        return 0

    try:
        inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
        # SMARTSW-2 (2026-09-19): this used to select every mac_address
        # in verified_devices, no WHERE clause -- correct back when the
        # only way a row got created there was a genuine human
        # confirmation (/api/node/update, /api/promote_node). INVENTORY-4
        # (2026-09-09) changed that: run_inventory_snapshot_sync() now
        # writes a last_known_* snapshot row for EVERY discovered device,
        # not just human-confirmed ones -- so by a device's second
        # discovery cycle, already_verified silently contained it too,
        # permanently blocking candidate promotion from ever reconsidering
        # it. Confirmed live: a D-Link switch first discovered as a plain
        # Endpoint (before its SNMP config was finished) never promoted to
        # Smart Switch afterwards, even once SNMP started correctly identifying
        # it as one -- the stale auto-sync snapshot row blocked it. Only
        # user_given_name/confirmed_device_type ever get written by an
        # actual human action (_persist_inventory_override() in
        # server.py early-returns if both are empty) -- every other
        # column is auto-sync-only, so filtering on those two is the real
        # "a human confirmed this" signal, not "a snapshot row exists".
        already_verified = {row[0] for row in inv_conn.execute(
            "SELECT mac_address FROM verified_devices WHERE user_given_name IS NOT NULL OR confirmed_device_type IS NOT NULL"
        )}
    except Exception as e:
        logger.warning(f"[SmartSwitch] Could not read inventory.db for candidate suggestion: {e}")
        inv_conn = None
        already_verified = set()

    suggested = 0
    for mac, vendor, model, protocol in candidates:
        if mac in already_verified:
            continue
        cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (mac,))
        row = cursor.fetchone()
        if not row or row[0] is None:
            continue  # not (yet) a discovered node this cycle -- nothing to tag
        node_id = row[0]
        label = f"{vendor} {model}".strip() if model else vendor
        is_self_identifying = protocol in _SELF_IDENTIFYING_PROTOCOLS
        target_type = 'Smart Switch' if is_self_identifying else 'Smart Switch (Unverified)'
        display_name = label if is_self_identifying else f"{label} (unconfirmed -- {protocol})"
        priority = PRIORITY_LLDP_SYSNAME if is_self_identifying else PRIORITY_DHCP

        cursor.execute(
            f"UPDATE logical_nodes SET device_type = ? "
            f"WHERE id = ? AND device_type NOT IN {_PROTECTED_DEVICE_TYPES}",
            (target_type, node_id),
        )
        if cursor.rowcount:
            set_hostname_by_mac(cursor, mac, display_name, priority)
            suggested += 1

            if is_self_identifying and inv_conn is not None:
                try:
                    inv_conn.execute(
                        "INSERT INTO verified_devices (mac_address, user_given_name, confirmed_device_type, notes) "
                        "VALUES (?, ?, 'Smart Switch', ?) "
                        "ON CONFLICT(mac_address) DO UPDATE SET user_given_name=excluded.user_given_name, "
                        "confirmed_device_type=excluded.confirmed_device_type, updated_at=CURRENT_TIMESTAMP",
                        (mac, label, f"Auto-confirmed via {protocol} self-identification (not a human confirmation)."),
                    )
                    inv_conn.commit()
                except Exception as e:
                    logger.warning(f"[SmartSwitch] Could not auto-write {mac} to inventory.db: {e}")

    if inv_conn is not None:
        inv_conn.close()
    conn.commit()
    conn.close()
    return suggested


def run_inventory_overlay_pass():
    """
    INVENTORY-1 (2026-09-04, ported from main): re-applies inventory.db's
    human-confirmed device names/types onto the CURRENT network.db every
    cycle -- this is what makes a confirmation made once "stick" forever,
    surviving even a full Clean Slate purge and re-discovery. Runs LAST in
    run_unification_engine(), after classification and the smart-switch-
    candidate suggestion pass above, so a confirmed record always has final
    say over any auto-derived guess.

    inventory.db is keyed by mac_address specifically because
    logical_nodes.id is an autoincrement PK that gets regenerated from
    scratch on every purge -- nothing there could ever be a stable foreign
    key into a database meant to survive one.

    INVENTORY-3 (2026-09-09): this function itself was never the bug --
    root-caused live against a lab Raspberry Pi that a dark-matter pseudo-switch
    (see inference_engine.py's run_dark_matter_detection()) is created
    AFTER this same tick's own call to this function, since
    stage_unification_engine() runs before stage_inference_engine() in
    main.py's deep-scan block. And no further unification pass runs
    again until the NEXT deep-scan tick (main.py only runs this on tick
    0/1, never on a "structural scan bypassed" tick), so a pseudo-switch
    created this tick had no guaranteed future call to catch it -- see
    main.py's stage_inventory_reoverlay(), added specifically to close
    this gap by calling this function again once dark matter (and
    consolidation) have had their say, same tick.
    """
    try:
        inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
        verified = inv_conn.execute(
            "SELECT mac_address, user_given_name, confirmed_device_type FROM verified_devices"
        ).fetchall()
        inv_conn.close()
    except Exception as e:
        logger.warning(f"[SmartSwitch] Could not read inventory.db for overlay pass: {e}")
        return 0
    if not verified:
        return 0

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    applied = 0
    for mac, name, device_type in verified:
        cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (mac,))
        row = cursor.fetchone()
        if not row or row[0] is None:
            continue
        node_id = row[0]
        updates, params = [], []
        if name:
            updates.append("hostname = ?")
            params.append(name)
        if device_type:
            updates.append("device_type = ?")
            params.append(device_type)
        if not updates:
            continue
        updates.append("weld_confidence = 100")
        params.append(node_id)
        cursor.execute(f"UPDATE logical_nodes SET {', '.join(updates)} WHERE id = ?", params)
        applied += cursor.rowcount

    conn.commit()
    conn.close()
    return applied


def run_inventory_snapshot_sync():
    """
    INVENTORY-4 (2026-09-09): captures a "last known" snapshot of every
    currently-discovered device into inventory.db -- not just ones a
    human has explicitly confirmed. Runs the OPPOSITE direction from
    run_inventory_overlay_pass() above (network.db -> inventory.db, not
    inventory.db -> network.db), and touches an entirely different set
    of columns (last_known_*, category, market_segment,
    first_discovered, last_synced) -- notes/the asset-management fields
    (location, asset_tag, serial_number, model, purchase_date,
    warranty_expiry) stay exactly whatever a human last set them to (or
    NULL, if nobody ever has). See apply_inventory_migrations()'s own
    docstring (engine/database.py) for the full reasoning behind
    keeping auto-discovered and human-entered data on separate columns
    of the same row -- INVENTORY-8 below is a deliberate, narrow
    exception to "never touches the human columns" for exactly two of
    them.

    Runs AFTER run_inventory_overlay_pass() in the tick sequence (see
    main.py's stage_inventory_snapshot_sync(), called right after
    stage_inventory_reoverlay()) so a device's last_known_hostname
    reflects whatever the overlay pass just applied, not a stale
    pre-overlay value.

    INVENTORY-5 (2026-09-25, reported live): every device this
    instance currently sees on ITS OWN network gets stamped with this
    instance's own site_stamp/instance_id whenever Multi-Site
    Inventory Sync is enabled -- previously ONLY the human-edit path
    (/api/inventory/update et al, server.py's _persist_inventory_
    override) ever set these two columns, so the vast majority of
    devices (everything auto-discovered, which is nearly all of them --
    that's the whole point of this function) stayed permanently
    unstamped and invisible to the Inventory page's Site filter.
    site_stamp/instance_id aren't human-entered data the way
    user_given_name/notes/the asset fields are -- they're this
    instance's own attribution of "which site actually saw this device
    live," so unlike those columns this function overwrites them
    unconditionally on every currently-discovered device rather than
    only filling them in when empty: a device this instance is live-
    polling right now genuinely does belong to this instance's site,
    even if it was previously pulled in from another site's sync push
    with a different stamp. A complete no-op (both columns genuinely
    untouched, not merely set to NULL -- they're left out of the query
    entirely below) for every install that's never enabled sync, same
    as the human-edit path -- also protects a device this instance
    once stamped while sync was on from being silently wiped back to
    NULL on some later tick after sync gets disabled again.

    INVENTORY-8 (2026-09-25, reported live): a real device's inventory
    row could sit with an empty Name/Device Type in the UI forever,
    even though last_known_hostname/last_known_device_type right next
    to it on the same card were already correctly populated -- nothing
    ever copied a good auto-discovered value INTO the human-editable
    identity fields, only ever displayed it alongside them. Requested
    directly: back-fill user_given_name/confirmed_device_type from
    this tick's discovered hostname/device_type, but ONLY when the
    field is currently empty -- the exact same fill-empty-only policy
    already used for cross-site sync's _merge_pulled_devices()
    (server.py) and INVENTORY-6's own cleanup pass above, just applied
    within a single row instead of across rows. The moment a human
    sets either field to a real value (via /api/inventory/update,
    /api/node/update, or /api/promote_node), this stops touching it --
    the CASE WHEN below only ever fires while the column is still NULL
    or ''. Scoped to exactly these two columns, which have an obvious
    1:1 discovered counterpart (hostname, device_type); the asset-
    management fields (location, serial number, etc.) have no
    discovered equivalent to back-fill from and are untouched, same as
    always.
    """
    site_cols, site_vals = [], []
    if config._get_setting(sync_client.SETTING_KEY_WRAPPED):
        site_cols = ["site_stamp", "instance_id"]
        site_vals = [config._get_setting("SITE_STAMP", "") or None, config._get_setting("INSTANCE_ID")]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT i.mac_address, i.node_id, n.hostname, i.vendor, n.device_type,
               b.ip_address, n.os_family, i.category, i.market_segment, b.http_header
        FROM l2_interfaces i
        LEFT JOIN logical_nodes n ON i.node_id = n.id
        LEFT JOIN l3_bindings b ON i.mac_address = b.mac_address
    ''')
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        return 0

    # INVENTORY-6 (2026-09-25, reported live): a multihomed device
    # (e.g. a router with a dozen physical/VLAN interfaces, all
    # correctly welded into ONE logical_nodes row by the unification
    # engine) was getting ONE verified_devices row PER INTERFACE MAC
    # here, not one per logical device -- this function grouped by
    # bare mac_address, with no concept of node_id at all. Invisible
    # until the Inventory page's new device-type sort (grouping every
    # Router together) suddenly stacked a dozen identical "RB5009UG"
    # cards in a row. Grouped by node_id now (a MAC with no node_id
    # yet -- a true ghost, never welded -- keeps its own row, nothing
    # to consolidate); the "prefer the row with a real IP" tie-break
    # is unchanged, just scoped per-node instead of per-MAC. Written
    # under the group's canonical (lowest) MAC -- the exact same
    # convention pollers/snmp_default_community_detector.py's
    # _canonical_mac() already uses for findings/alerts, so a
    # multihomed device's inventory identity lines up with everywhere
    # else in the codebase that already had to solve this.
    best_data_by_group = {}
    macs_by_group = {}
    for mac, node_id, hostname, vendor, device_type, ip, os_family, category, market_segment, http_header in rows:
        key = node_id if node_id is not None else mac
        macs_by_group.setdefault(key, []).append(mac)
        existing = best_data_by_group.get(key)
        if existing is None or (ip and not existing[3]):
            best_data_by_group[key] = (hostname, vendor, device_type, ip, os_family, category, market_segment, http_header)

    by_mac = {}
    for key, data in best_data_by_group.items():
        by_mac[min(macs_by_group[key])] = data

    base_cols = ["mac_address", "last_known_hostname", "last_known_vendor",
        "last_known_device_type", "last_known_ip", "last_known_os_family", "category", "market_segment",
        "last_known_http_header"]
    all_cols = base_cols + site_cols
    # INVENTORY-8: back-fill columns, appended after everything else so
    # base_cols/site_cols' own excluded.col = excluded.col handling
    # above is untouched. Each gets its OWN conditional clause instead
    # of the blanket one the auto-only columns use -- an existing
    # human value must never be overwritten, only an empty one filled.
    identity_cols = ["user_given_name", "confirmed_device_type"]
    insert_cols = all_cols + identity_cols
    placeholders = ", ".join("?" for _ in insert_cols)
    auto_set_clause = ", ".join(f"{c} = excluded.{c}" for c in all_cols[1:])
    identity_set_clause = ", ".join(
        f"{c} = CASE WHEN {c} IS NULL OR {c} = '' THEN excluded.{c} ELSE {c} END"
        for c in identity_cols
    )
    set_clause = f"{auto_set_clause}, {identity_set_clause}, last_synced = CURRENT_TIMESTAMP"

    inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
    inv_cursor = inv_conn.cursor()

    # Self-healing cleanup for rows this bug already wrote before the
    # fix above existed (confirmed live: 12 redundant rows across 2
    # welded devices on the first real install checked). Folds any
    # non-canonical row's human-entered fields into the canonical
    # MAC's row first -- field-level fill-empty-only, same policy as
    # sync's own _merge_pulled_devices() (server.py), so an existing
    # human value is never overwritten -- then removes the redundant
    # row. A no-op every tick after the backlog is cleared; only does
    # real work again if a node's interface set changes.
    human_cols = ["user_given_name", "confirmed_device_type", "notes", "location",
        "asset_tag", "serial_number", "model", "purchase_date", "warranty_expiry"]
    for key, macs in macs_by_group.items():
        if len(macs) < 2:
            continue
        canonical_mac = min(macs)
        other_macs = [m for m in macs if m != canonical_mac]
        other_placeholders = ", ".join("?" for _ in other_macs)
        stray_rows = inv_cursor.execute(
            f"SELECT {', '.join(human_cols)} FROM verified_devices WHERE mac_address IN ({other_placeholders})",
            other_macs
        ).fetchall()
        if not stray_rows:
            continue
        canonical_row = inv_cursor.execute(
            f"SELECT {', '.join(human_cols)} FROM verified_devices WHERE mac_address = ?", (canonical_mac,)
        ).fetchone()
        canonical_vals = list(canonical_row) if canonical_row else [None] * len(human_cols)
        fill_cols, fill_vals = [], []
        for idx, col in enumerate(human_cols):
            if canonical_vals[idx] not in (None, ""):
                continue
            for stray in stray_rows:
                if stray[idx] not in (None, ""):
                    fill_cols.append(col)
                    fill_vals.append(stray[idx])
                    break
        if fill_cols:
            inv_cursor.execute("INSERT OR IGNORE INTO verified_devices (mac_address) VALUES (?)", (canonical_mac,))
            fill_set_clause = ", ".join(f"{c} = ?" for c in fill_cols)
            inv_cursor.execute(f"UPDATE verified_devices SET {fill_set_clause} WHERE mac_address = ?", [*fill_vals, canonical_mac])
        inv_cursor.executemany("DELETE FROM verified_devices WHERE mac_address = ?", [(m,) for m in other_macs])

    for mac, (hostname, vendor, device_type, ip, os_family, category, market_segment, http_header) in by_mac.items():
        base_vals = [mac, hostname, vendor, device_type, ip, os_family, category, market_segment, http_header]
        identity_vals = [hostname, device_type]
        inv_cursor.execute(f'''
            INSERT INTO verified_devices ({', '.join(insert_cols)}, first_discovered, last_synced)
            VALUES ({placeholders}, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT(mac_address) DO UPDATE SET {set_clause}
        ''', base_vals + site_vals + identity_vals)
    inv_conn.commit()
    inv_conn.close()
    return len(by_mac)


def run_verified_switch_consolidation_pass():
    """
    INVENTORY-1 (2026-09-04, ported from main): once a user has confirmed a
    specific MAC really is the switch behind a dark-matter-inferred port
    (device_type set to anything other than 'Endpoint'/unset via
    /api/node/update or /api/promote_node, persisted into inventory.db),
    this collapses the SYNTHETIC pseudo-switch
    engine/inference_engine.py's run_dark_matter_detection() created for
    that exact port into the REAL confirmed device -- re-parenting
    everything that was hanging off the pseudo node onto the real device's
    actual IP, and removing the pseudo node entirely. Runs after
    stage_inference_engine() each cycle (see main.py's tick loop), so a
    verification made once replaces the placeholder from the very next
    cycle onward.

    Recomputes each port's pseudo_ip the same deterministic way
    run_dark_matter_detection() does (from switch_ip + port) rather than
    looking it up, since that's the only thing tying a pseudo node back to
    the specific port it stands in for.
    """
    try:
        inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
        verified = dict(inv_conn.execute(
            "SELECT mac_address, confirmed_device_type FROM verified_devices WHERE confirmed_device_type IS NOT NULL"
        ).fetchall())
        inv_conn.close()
    except Exception as e:
        logger.warning(f"[SmartSwitch] Could not read inventory.db for consolidation pass: {e}")
        return 0
    if not verified:
        return 0

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    cursor.execute('''
        SELECT DISTINCT switch_ip, local_port FROM endpoint_locations
        WHERE local_port NOT IN ('WLAN', '0', 'Bridge')
    ''')
    ports = cursor.fetchall()

    consolidated = 0
    for switch_ip, port in ports:
        ip_parts = switch_ip.split('.')
        if len(ip_parts) != 4:
            continue
        try:
            pseudo_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{int(ip_parts[3]) * 1000 + int(port)}"
        except ValueError:
            continue

        cursor.execute("SELECT mac_address FROM l3_bindings WHERE ip_address = ?", (pseudo_ip,))
        row = cursor.fetchone()
        if not row or not row[0].startswith("02:ff:"):
            continue  # no dark-matter pseudo node currently standing in for this port
        pseudo_mac = row[0]

        cursor.execute(
            "SELECT mac_address FROM endpoint_locations WHERE switch_ip = ? AND CAST(local_port AS INTEGER) = CAST(? AS INTEGER)",
            (switch_ip, port),
        )
        sibling_macs = [r[0] for r in cursor.fetchall()]
        real_switch_mac = next((m for m in sibling_macs if verified.get(m) not in (None, "Endpoint")), None)
        if not real_switch_mac:
            continue

        cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (real_switch_mac,))
        row = cursor.fetchone()
        if not row or row[0] is None:
            continue
        cursor.execute("SELECT ip_address FROM l3_bindings WHERE mac_address = ? LIMIT 1", (real_switch_mac,))
        row = cursor.fetchone()
        if not row:
            continue
        real_ip = row[0]

        cursor.execute("UPDATE infrastructure_links SET local_switch_ip = ? WHERE local_switch_ip = ?", (real_ip, pseudo_ip))
        cursor.execute("UPDATE infrastructure_links SET remote_system_name = ? WHERE remote_system_name = ?", (real_ip, pseudo_ip))
        cursor.execute("DELETE FROM l3_bindings WHERE ip_address = ?", (pseudo_ip,))
        cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (pseudo_mac,))
        pseudo_node_row = cursor.fetchone()
        cursor.execute("DELETE FROM l2_interfaces WHERE mac_address = ?", (pseudo_mac,))
        if pseudo_node_row and pseudo_node_row[0] is not None:
            cursor.execute("DELETE FROM logical_nodes WHERE id = ?", (pseudo_node_row[0],))
        consolidated += 1

    conn.commit()
    conn.close()
    if consolidated:
        logger.info(f"[SmartSwitch] Consolidated {consolidated} dark-matter placeholder(s) into user-verified real devices.")
    return consolidated


def run_unification_engine():
    enforce_db_triggers()
    hw_welds = run_hardware_weld_pass()
    arp_welds = run_arp_confirmed_weld_pass()
    ip_welds = run_heuristic_pass()
    new_nodes = run_singleton_pass()
    ap_updates, switch_updates, docker_updates = run_classification_pass()
    # INVENTORY-1: candidate suggestion first (auto-inferred, unverified),
    # then the inventory overlay LAST so a human confirmation always has
    # final say over anything auto-derived above it.
    suggested = run_smart_switch_candidate_pass()
    overlaid = run_inventory_overlay_pass()

    logger.info(f"Unification complete. Hardware Welds: {hw_welds}, ARP-Confirmed Welds: {arp_welds}, IP Welds: {ip_welds}, Nodes Created: {new_nodes}")
    if ap_updates > 0 or switch_updates > 0 or docker_updates > 0:
        logger.info(f"Classification complete. APs: {ap_updates}, Switches: {switch_updates}, Docker Hosts: {docker_updates}")
    if suggested > 0 or overlaid > 0:
        logger.info(f"Inventory pass complete. Smart-switch suggestions: {suggested}, Verified overrides applied: {overlaid}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_unification_engine()
