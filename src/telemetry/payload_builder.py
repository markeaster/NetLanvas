"""
payload_builder.py

Builds the Community Telemetry structured per-device payload -- queries
network.db, sanitizes every field through sanitizer.py, returns a
JSON-serializable dict. This is the single code path used for both the
real daily submission (via submitter.py) and the Preview page's
right-hand pane (/api/telemetry/preview) -- there is deliberately no
separate preview-only implementation, so what a user previews is
guaranteed to be exactly what would actually be sent (see
netlanvas-telemetry-pipeline-v6 §7).
"""

import sqlite3
from datetime import datetime, timezone

from telemetry import sanitizer

_DEVICE_QUERY = """
    SELECT
        ln.hostname AS hostname,
        ln.device_type AS device_type,
        ln.os_family AS os_family,
        l2.mac_address AS mac_address,
        l2.vendor AS vendor,
        l2.is_virtual AS is_virtual,
        l2.wireless_ssid AS wireless_ssid,
        l3.ip_address AS ip_address,
        l3.vlan_id AS vlan_id,
        nv.vlan_name AS vlan_name
    FROM l2_interfaces l2
    JOIN logical_nodes ln ON l2.node_id = ln.id
    LEFT JOIN l3_bindings l3 ON l3.mac_address = l2.mac_address AND l3.is_ghost = 0
    LEFT JOIN network_vlans nv ON nv.vlan_id = l3.vlan_id
"""
# is_ghost=0 excludes tentative/self-correcting bindings (see the
# engine's ghost-link handling) -- telemetry represents confirmed
# state, not the engine's in-progress guesses. One row per
# (device, ip) pair; a multihomed device naturally produces multiple
# rows sharing the same fuzzed MAC, which is fine -- that IS its real
# shape, just anonymized.


def query_devices(network_db_path: str) -> list[dict]:
    conn = sqlite3.connect(network_db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute(_DEVICE_QUERY)
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def _sanitize_device(config, row: dict) -> dict:
    device = {
        "device_type": row["device_type"],
        "os_family": row["os_family"],
        "vendor": row["vendor"],
        "is_virtual": bool(row["is_virtual"]),
        "has_wireless": bool(row["wireless_ssid"]),
    }
    if row["mac_address"]:
        device["mac"] = sanitizer.fuzz_mac(config, row["mac_address"])
    if row["hostname"]:
        device["hostname"] = sanitizer.fuzz_hostname(config, row["hostname"])
    if row["ip_address"]:
        device["ip"] = sanitizer.fuzz_ip(config, row["ip_address"])
    if row["vlan_id"] is not None:
        device["vlan_id"] = row["vlan_id"]
    if row["vlan_name"]:
        device["vlan_name"] = sanitizer.fuzz_vlan_name(config, row["vlan_name"])
    return device


def build_payload(config, network_db_path: str) -> dict:
    """
    `config` is anything exposing _get_setting/_set_setting (a real
    ConfigLoader in production; a test double in isolation -- see
    sanitizer.py's own docstring for why this shape was chosen).
    Returns a dict ready for JSON serialization -- callers (submitter.py,
    the preview endpoint) add instance_id/signing on top of this, it is
    not this function's concern.
    """
    rows = query_devices(network_db_path)
    devices = [_sanitize_device(config, row) for row in rows]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device_count": len(devices),
        "devices": devices,
    }
