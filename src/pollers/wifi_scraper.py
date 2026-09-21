import logging
import asyncio
import sqlite3
from engine.config_loader import config
from engine.snmp_pipeline import run_snmp_pipeline
from engine.snmp_adapter import get_working_credential
logger = logging.getLogger("Netlanvas.Wifi")
DB_PATH = config.DB_PATH
def heuristic_upstream_inference(ap_ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT mac_address FROM l3_bindings WHERE ip_address = ?", (ap_ip,))
    ap_macs = [row[0].lower() for row in cursor.fetchall()]
    cursor.execute('''
        SELECT local_switch_ip, local_port, vlan_id
        FROM infrastructure_links
        WHERE remote_system_name = ?
    ''', (ap_ip,))
    upstream = cursor.fetchone()
    if not upstream:
        conn.close()
        return "NO_UPSTREAM_LINK"
    switch_ip, switch_port, default_vlan = upstream
    cursor.execute('''
        SELECT mac_address, vlan_id FROM endpoint_locations
        WHERE switch_ip = ? AND CAST(local_port AS INTEGER) = CAST(? AS INTEGER)
    ''', (switch_ip, switch_port))
    endpoints = cursor.fetchall()
    migrated_count = 0
    for mac, vlan in endpoints:
        if mac.lower() in ap_macs: continue
        eff_vlan = vlan if vlan else default_vlan
        cursor.execute('''
            UPDATE endpoint_locations
            SET switch_ip = ?, local_port = 'WLAN', vlan_id = ?, last_seen = CURRENT_TIMESTAMP
            WHERE mac_address = ?
        ''', (ap_ip, eff_vlan, mac))
        migrated_count += 1
    conn.commit()
    conn.close()
    return f"HEURISTIC_MAPPED_{migrated_count}"
async def poll_wifi_clients(ap_ip, is_deep_scan_tick=False):
    """
    See punch list SNMP-8: this used to receive a bare community
    string handed down from main.py (config.SNMP_COMMUNITY, singular
    and unparsed -- a pre-existing bug that bypassed the credential
    list/cache entirely). Now routes through the same
    get_working_credential() mechanism as every other SNMP call site
    -- v3-first, cache-first, full v2c fallback list -- instead of
    hardcoding a single string.
    """
    credential = await get_working_credential(ap_ip)
    _, results = await run_snmp_pipeline(ap_ip, credential, is_deep_scan_tick=is_deep_scan_tick)
    if results.get(80) == "CONTROLLER_MANAGED":
        logger.info(f"[*] {ap_ip} Controller-managed UniFi AP detected. Forcing upstream inference.")
        return heuristic_upstream_inference(ap_ip)
    client_macs = results.get(60) or results.get(70) or []
    if client_macs:
        logger.info(f"[*] {ap_ip} mapped {len(client_macs)} clients via Enterprise MIB.")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for mac in client_macs:
            cursor.execute('''
                INSERT INTO endpoint_locations (mac_address, switch_ip, local_port, vlan_id, last_seen)
                VALUES (?, ?, 'WLAN', 0, CURRENT_TIMESTAMP)
                ON CONFLICT(mac_address) DO UPDATE SET
                    switch_ip=excluded.switch_ip,
                    local_port='WLAN',
                    last_seen=CURRENT_TIMESTAMP
            ''', (mac, ap_ip))
        conn.commit()
        conn.close()
        return "STRICT_ENTERPRISE_MAPPED"
    if config.WIFI_STRICT_MODE:
        logger.info(f"[*] {ap_ip} WiFi Scrape: Strict mode enforced but no standard data returned.")
        return "NO_STRICT_SNMP_DATA"
    else:
        logger.info(f"[*] {ap_ip} WiFi Scrape: Heuristic mode active. Executing Upstream Inference...")
        return heuristic_upstream_inference(ap_ip)
