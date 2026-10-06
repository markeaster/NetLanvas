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

    # Real bug found 2026-09-25, traced from a live "ambiguous
    # connection" report: a device that moves IP on the SAME subnet
    # (e.g. DHCP -> static lease) keeps its old IP's credential_cache
    # entry around from before the move. ips is already most-recent-
    # first (ORDER BY last_seen DESC above), but the credential-cache
    # preference loop below ran over the FULL list -- if the new IP
    # had never been polled yet (no cache entry at all) while the old
    # one still had a cached WORKING credential from before, the old
    # one won every time, so the new IP could never get polled, never
    # get its own cache entry, and this would never self-correct.
    # Confirmed live: wifi_scraper.py kept writing this AP's WLAN
    # client records under its old IP, which no longer matched
    # infrastructure_links' current IP, which is exactly what made
    # engine/inference_engine.py's dark-matter detection see "clients
    # present but none explained" and mark the port ambiguous.
    #
    # Collapse same-subnet duplicates to the single most-recent IP
    # BEFORE the credential-cache preference runs, so a stale IP can
    # never win via a leftover cache hit. Different-subnet IPs for the
    # same node (genuine multihoming -- this function's own docstring
    # above, POLL-1) are untouched; the credential-cache preference
    # still applies normally across those.
    def _subnet(ip):
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else ip

    targets = []
    for node_id, ips in ips_by_node.items():
        best_by_subnet = {}
        order = []
        for ip in ips:  # already most-recent-first
            key = _subnet(ip)
            if key not in best_by_subnet:
                best_by_subnet[key] = ip
                order.append(key)
        candidates = [best_by_subnet[key] for key in order]

        chosen = None
        if credential_cache:
            for ip in candidates:
                cached = credential_cache.get(ip)
                if cached and cached != "UNRESPONSIVE":
                    chosen = ip
                    break
        if chosen is None:
            chosen = candidates[0]
        targets.append(chosen)

    if len(rows) > len(targets):
        logger.debug(f"[POLL-1] Deduplicated {len(rows)} IP(s) across {len(targets)} distinct node(s) for device_types={device_types}.")

    return targets
