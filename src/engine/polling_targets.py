import sqlite3
import logging
from engine.config_loader import config

logger = logging.getLogger("Netlanvas.PollingTargets")


def get_representative_targets(device_types, credential_cache=None):
    """
    Returns one representative IP per logical node matching the given
    device_type(s), instead of every IP that node happens to have.

    Confirmed live via TOPO-1: a single router can genuinely have 6+
    interface IPs, and SNMP talks to one agent process per device
    regardless of which of its own IPs is used to reach it -- querying
    all of them independently (ARP scrape, FDB scrape, LLDP crawl,
    Wi-Fi scrape, fingerprinting) returns identical data N times over,
    for N times the SNMP load on the device and the appliance's own
    polling cycle. See punch list POLL-1.

    Prefers a cache-confirmed-reachable IP when one is available
    (checked against the SNMP adapter's CREDENTIAL_CACHE, passed in by
    the caller to avoid a circular import between this module and
    snmp_adapter.py), falling back to the most recently seen IP
    otherwise. Deliberately not just "the first IP found": a node's
    first-returned IP could happen to be the one that's flaky this
    cycle while another of its IPs works fine. Blindly picking one
    without this preference would trade today's redundant-but-resilient
    behavior for a new, worse failure mode -- silently losing a node's
    data for the cycle whenever its arbitrary "first" IP is
    unreachable, instead of the other IPs picking up the slack the way
    today's try-everything approach incidentally does.
    """
    if not device_types:
        return []

    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    placeholders = ",".join("?" for _ in device_types)
    cursor.execute(f'''
        SELECT i.node_id, b.ip_address
        FROM logical_nodes n
        JOIN l2_interfaces i ON n.id = i.node_id
        JOIN l3_bindings b ON i.mac_address = b.mac_address
        WHERE n.device_type IN ({placeholders}) AND b.ip_address IS NOT NULL
        ORDER BY b.last_seen DESC
    ''', device_types)
    rows = cursor.fetchall()
    conn.close()

    ips_by_node = {}
    for node_id, ip in rows:
        ips_by_node.setdefault(node_id, []).append(ip)

    targets = []
    for node_id, ips in ips_by_node.items():
        chosen = None
        if credential_cache:
            for ip in ips:
                cached = credential_cache.get(ip)
                if cached and cached != "UNRESPONSIVE":
                    chosen = ip
                    break
        if chosen is None:
            chosen = ips[0]
        targets.append(chosen)

    if len(rows) > len(targets):
        logger.debug(f"[POLL-1] Deduplicated {len(rows)} IP(s) across {len(targets)} distinct node(s) for device_types={device_types}.")

    return targets
