"""
snmp_default_community_detector.py

FIND-1: flags any device that answered SNMP using a well-known default
community string (RFC1213-era conventions like "public"/"private" --
still the single most common misconfiguration found on unmanaged
switches/APs in the wild). Reads CREDENTIAL_CACHE, the same in-memory
ip -> SNMPCredential map main.py's SNMP-driven stages (stage_arp_scrape,
device_fingerprinting, os_profiler) already populate as a side effect of
get_working_credential() -- this detector adds no SNMP traffic of its
own, it just inspects what those stages already learned this cycle.

Only ever resolves a finding when THIS cycle's credential for that same
device is confirmed non-default -- a device simply not being polled this
particular tick (CREDENTIAL_CACHE only covers whatever was actually
queried) must never be treated as "fixed", or the finding would flicker
resolved/reopened based on polling coverage rather than the device's
actual configuration.

Both findings here use 'high' severity -- unlike a transient offline
blip, a default/exposed SNMP community is a standing exploitable gap:
anyone already on the LAN can read (and on many devices, write) device
configuration for as long as it goes unfixed.

run_snmp_public_security_scan() below is a separate, active check for a
real blind spot the passive detector above can't see: get_working_
credential() stops at the first credential that works, so if a device's
real configured string succeeds, "public" never gets tried against it at
all -- even if the device would ALSO accept it. A device vulnerable to
both its real string and "public" currently looks clean, because
whatever credential won the race is the only one ever recorded. This
scan closes that gap by explicitly probing "public" against every
device whose cached working credential ISN'T already a default one.

Deliberately independent of SNMP_TRY_PUBLIC_COMMUNITY -- that setting
exists so a user can stop NetLanvas using "public" as a connectivity
fallback on networks that alarm on repeated default-credential attempts
(see its own description). Silently overriding that for this scan would
reintroduce exactly the risk someone disabled it to avoid. Gated on its
own setting, SNMP_SECURITY_SCAN_PUBLIC, instead.

The two checks above use SEPARATE finding_type values (FINDING_TYPE vs
FINDING_TYPE_ACTIVE) even though both are conceptually "SNMP default
community" issues -- they used to share one, which caused real alert
spam: the passive detector runs first each cycle, and for any device
the active scan flags (by definition, one whose OWN working credential
is non-default), the passive detector's own "credential isn't default"
branch would resolve the very finding the active scan had just opened,
which then reopened and re-alerted on the same or next cycle, forever.
Separate finding_types mean the two checks can never resolve each
other's state.
"""

import logging
import sqlite3

from engine.alerting import create_alert
from engine.snmp_adapter import run_snmp_command
from engine.snmp_credential import SNMPCredential, SNMPVersion
from engine.config_loader import config

logger = logging.getLogger("Netlanvas.Alerting")

DEFAULT_COMMUNITIES = {"public", "private"}
FINDING_TYPE = "snmp_default_community"
FINDING_TYPE_ACTIVE = "snmp_public_community_secondary"
SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"


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
    """
    A multihomed device (e.g. a router with several physical/VLAN
    interfaces) has one l2_interfaces row per MAC, but the unification
    engine already correctly welds all of them into a single
    logical_nodes row. Findings/alerts must key off that same logical
    identity, not the raw per-interface MAC that happened to answer
    this particular SNMP probe -- otherwise one physical device
    generates one finding/alert per interface instead of one overall.
    Resolves to the lowest MAC sharing the same node_id: an arbitrary
    but stable, deterministic choice, so repeated runs always converge
    on the same canonical identity regardless of which interface
    answered this cycle.
    """
    row = conn.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (mac_address,)).fetchone()
    if row is None or row[0] is None:
        return mac_address
    canon = conn.execute(
        "SELECT mac_address FROM l2_interfaces WHERE node_id = ? ORDER BY mac_address LIMIT 1",
        (row[0],),
    ).fetchone()
    return canon[0] if canon else mac_address


def run_snmp_default_community_detector(db_path: str, credential_cache: dict) -> None:
    conn = sqlite3.connect(db_path)
    try:
        # User-configurable via the Alerts page's Severity tab (ALERT-5),
        # falls back to the shipped default. Read once per run, not per
        # device -- this is a single global setting, not per-role like
        # offline severity.
        severity = config._get_setting("SEVERITY_SNMP_EXPOSURE", "high")
        for ip, credential in credential_cache.items():
            community = getattr(credential, "community", None)
            if community is None:
                continue  # v3 credential or the "UNRESPONSIVE" sentinel string

            row = conn.execute("SELECT mac_address FROM l3_bindings WHERE ip_address = ?", (ip,)).fetchone()
            if row is None:
                continue
            mac_address = _canonical_mac(conn, row[0])

            existing = conn.execute(
                "SELECT resolved_at FROM device_findings WHERE mac_address = ? AND finding_type = ?",
                (mac_address, FINDING_TYPE),
            ).fetchone()
            was_active = existing is not None and existing[0] is None

            if community.lower() in DEFAULT_COMMUNITIES:
                conn.execute(
                    """INSERT INTO device_findings (mac_address, finding_type, severity, detail)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(mac_address, finding_type) DO UPDATE SET
                           last_confirmed = CURRENT_TIMESTAMP, resolved_at = NULL, detail = excluded.detail""",
                    (mac_address, FINDING_TYPE, severity, f"{ip} responds to the default SNMP community string '{community}'."),
                )
                # Only alert on a genuine new-or-reopened finding, not
                # every cycle it's re-confirmed still present -- the
                # inbox should read as events, not a heartbeat.
                if not was_active:
                    name = _friendly_name(conn, mac_address)
                    create_alert(
                        conn, "snmp_default_community", severity,
                        f"{name} is using a default SNMP community string",
                        detail=f"{ip} responds to '{community}' -- change this to a non-default value.",
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
                    conn, "snmp_default_community_resolved", "info",
                    f"{name} is no longer using a default SNMP community string",
                    detail=f"{ip} now responds with a non-default credential.",
                    mac_address=mac_address, is_resolution=True,
                )
        conn.commit()
    except Exception as e:
        logger.error(f"[FIND] snmp_default_community_detector failed: {e}")
        conn.rollback()
    finally:
        conn.close()


async def run_snmp_public_security_scan(db_path: str, credential_cache: dict) -> None:
    """
    See module docstring. Only targets devices whose CURRENT cached
    credential is confirmed non-default (a default-community device is
    already fully handled by the passive detector above) -- including
    v3-only devices, since a device configured for v3 could still have
    v2c/"public" also enabled, which is just as real an exposure.
    Resolves a finding this scan itself opened once "public" genuinely
    stops responding, same "only resolve on a confirmed negative, never
    on absence" discipline as the passive detector.
    """
    targets = [
        ip for ip, cred in credential_cache.items()
        # (getattr(...) or "") -- a v3 credential's .community attribute
        # exists but is None (not missing), so a bare getattr fallback
        # never applies; None must be normalized to "" before .lower(),
        # and "" correctly isn't in DEFAULT_COMMUNITIES, so v3-only
        # devices are included as targets rather than crashing or being
        # silently skipped.
        if cred != "UNRESPONSIVE" and (getattr(cred, "community", None) or "").lower() not in DEFAULT_COMMUNITIES
    ]
    if not targets:
        return

    test_credential = SNMPCredential(version=SNMPVersion.V2C, community="public")
    conn = sqlite3.connect(db_path)
    try:
        severity = config._get_setting("SEVERITY_SNMP_EXPOSURE", "high")
        for ip in targets:
            responds_to_public = await run_snmp_command(ip, SYSDESCR_OID, test_credential, timeout=1, retries=1) is not None

            row = conn.execute("SELECT mac_address FROM l3_bindings WHERE ip_address = ?", (ip,)).fetchone()
            if row is None:
                continue
            mac_address = _canonical_mac(conn, row[0])

            existing = conn.execute(
                "SELECT resolved_at FROM device_findings WHERE mac_address = ? AND finding_type = ?",
                (mac_address, FINDING_TYPE_ACTIVE),
            ).fetchone()
            was_active = existing is not None and existing[0] is None

            if responds_to_public:
                conn.execute(
                    """INSERT INTO device_findings (mac_address, finding_type, severity, detail)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(mac_address, finding_type) DO UPDATE SET
                           last_confirmed = CURRENT_TIMESTAMP, resolved_at = NULL, detail = excluded.detail""",
                    (mac_address, FINDING_TYPE_ACTIVE, severity, f"{ip} also responds to the default SNMP community string 'public', separate from its configured credential."),
                )
                if not was_active:
                    name = _friendly_name(conn, mac_address)
                    create_alert(
                        conn, "snmp_public_community_secondary", severity,
                        f"{name} also accepts the default SNMP community string",
                        detail=f"{ip} responds to 'public' even though it has its own configured credential -- change this to a non-default value.",
                        mac_address=mac_address,
                    )
            elif was_active:
                conn.execute(
                    """UPDATE device_findings SET resolved_at = CURRENT_TIMESTAMP
                       WHERE mac_address = ? AND finding_type = ?""",
                    (mac_address, FINDING_TYPE_ACTIVE),
                )
                name = _friendly_name(conn, mac_address)
                create_alert(
                    conn, "snmp_public_community_secondary_resolved", "info",
                    f"{name} no longer accepts the default SNMP community string",
                    detail=f"{ip} no longer responds to 'public'.",
                    mac_address=mac_address, is_resolution=True,
                )
        conn.commit()
    except Exception as e:
        logger.error(f"[FIND] snmp_public_security_scan failed: {e}")
        conn.rollback()
    finally:
        conn.close()
