"""
snmp_v3_available_detector.py

ALERT-6: flags any device that's confirmed to have a real SNMPv3/USM
stack (its snmpEngineID answered -- see engine/snmp_adapter.py's
PLAN-1 deferred-upgrade check, which already probes this as a normal
part of discovery) but is currently being managed over plaintext v2c
instead. v2c authenticates with a community string sent unencrypted on
the wire and readable by anyone already on that LAN segment; v3
supports real authentication and encryption. A device that's capable
of the stronger protocol and isn't using it is a genuine, actionable
hardening gap -- either no configured v3 identity matches it, or
nobody's ever bothered to switch it over.

Reads engine.snmp_adapter.V3_CAPABLE_IPS and CREDENTIAL_CACHE, both
already populated as a side effect of normal discovery -- this
detector adds no SNMP traffic of its own, same discipline as
snmp_default_community_detector.py, which this deliberately mirrors.

Resolves automatically the moment a device's cached credential becomes
v3 (whether via PLAN-1's own background upgrade succeeding, or a user
manually reconfiguring the device) -- same "only resolve on a
confirmed positive, never on absence" discipline as every other
detector here, so a device simply not queried this cycle doesn't
falsely read as fixed.
"""

import logging
import sqlite3

from engine.alerting import create_alert
from engine.snmp_credential import SNMPVersion
from engine.config_loader import config

logger = logging.getLogger("Netlanvas.Alerting")

FINDING_TYPE = "snmp_v3_available_unused"


def _friendly_name(conn: sqlite3.Connection, mac_address: str) -> str:
    row = conn.execute(
        """SELECT n.hostname, i.vendor FROM l2_interfaces i
           LEFT JOIN logical_nodes n ON i.node_id = n.id
           WHERE i.mac_address = ?""",
        (mac_address,),
    ).fetchone()
    if row is None:
        return mac_address
    hostname, vendor = row
    return hostname or (f"{vendor} device ({mac_address})" if vendor else mac_address)


def _canonical_mac(conn: sqlite3.Connection, mac_address: str) -> str:
    """Same multihoming-safe resolution as snmp_default_community_detector.py's own helper -- see that copy's docstring."""
    row = conn.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (mac_address,)).fetchone()
    if row is None or row[0] is None:
        return mac_address
    canon = conn.execute(
        "SELECT mac_address FROM l2_interfaces WHERE node_id = ? ORDER BY mac_address LIMIT 1",
        (row[0],),
    ).fetchone()
    return canon[0] if canon else mac_address


def run_snmp_v3_available_detector(db_path: str, credential_cache: dict, v3_capable_ips: set) -> None:
    if not v3_capable_ips:
        return
    conn = sqlite3.connect(db_path)
    try:
        severity = config._get_setting("SEVERITY_SNMP_V3_UNUSED", "medium")
        for ip in v3_capable_ips:
            credential = credential_cache.get(ip)
            if credential is None or credential == "UNRESPONSIVE" or isinstance(credential, tuple):
                continue  # not currently reachable this cycle -- nothing to compare

            row = conn.execute("SELECT mac_address FROM l3_bindings WHERE ip_address = ?", (ip,)).fetchone()
            if row is None:
                continue
            mac_address = _canonical_mac(conn, row[0])

            existing = conn.execute(
                "SELECT resolved_at FROM device_findings WHERE mac_address = ? AND finding_type = ?",
                (mac_address, FINDING_TYPE),
            ).fetchone()
            was_active = existing is not None and existing[0] is None

            is_v2c = credential.version == SNMPVersion.V2C
            if is_v2c:
                conn.execute(
                    """INSERT INTO device_findings (mac_address, finding_type, severity, detail)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(mac_address, finding_type) DO UPDATE SET
                           last_confirmed = CURRENT_TIMESTAMP, resolved_at = NULL, detail = excluded.detail""",
                    (mac_address, FINDING_TYPE, severity, f"{ip} has a working SNMPv3 engine but is being managed over plaintext v2c."),
                )
                if not was_active:
                    name = _friendly_name(conn, mac_address)
                    create_alert(
                        conn, "snmp_v3_available_unused", severity,
                        f"{name} supports SNMPv3 but is using v2c",
                        detail=f"{ip} answers SNMPv3's engineID probe (a real v3 stack is present) but is currently managed with a plaintext v2c community string. Configure a v3 identity for it to use authenticated, encrypted SNMP instead.",
                        mac_address=mac_address,
                    )
            elif was_active:
                conn.execute(
                    """UPDATE device_findings SET resolved_at = CURRENT_TIMESTAMP
                       WHERE mac_address = ? AND finding_type = ?""",
                    (mac_address, FINDING_TYPE),
                )
                name = _friendly_name(conn, mac_address)
                create_alert(
                    conn, "snmp_v3_available_unused_resolved", "info",
                    f"{name} is now using SNMPv3",
                    detail=f"{ip} is now managed over authenticated, encrypted SNMPv3 instead of plaintext v2c.",
                    mac_address=mac_address, is_resolution=True,
                )
        conn.commit()
    except Exception as e:
        logger.error(f"[FIND] snmp_v3_available_detector failed: {e}")
        conn.rollback()
    finally:
        conn.close()
