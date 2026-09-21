"""
device_state_tracker.py

STATE-1/2 (Priority 3 alerting). Runs after mac_table_scraper + wifi_scrape
each tick -- both upsert endpoint_locations, so by the time this runs it's
the freshest available "who's actually present right now" signal (wired
and wireless devices alike; see wifi_scraper.py's own upsert into the same
table with local_port='WLAN').

Compares that presence set against device_state (one row per MAC, the
device's current new/online/offline status) and:
  - inserts a 'new' row for a MAC never seen before -- fires a "new
    device" alert immediately, once.
  - quietly promotes 'new' -> 'online' the tick after (confirmation, not
    an event worth alerting on).
  - promotes 'offline' -> 'online' -- fires a "device back online" alert.
  - demotes 'online'/'new' -> 'offline' once a device has been absent for
    OFFLINE_GRACE_TICKS consecutive ticks -- fires a "device offline"
    alert. The grace period exists because a single missed FDB/ARP read
    (one dropped SNMP poll, a switch hiccup) would otherwise fire
    spurious offline/online pairs every tick; requiring the device to be
    genuinely absent across several ticks filters that out.

    STATE-3: tick-counted, not wall-clock (was OFFLINE_GRACE_SECONDS=300
    seconds) -- a fixed number of seconds races against how long a tick
    actually takes to run, which varies with load. Confirmed live: tick
    duration measured at a healthy ~95s under normal conditions, but
    275-330s under memory pressure (a since-fixed pysnmp leak in
    ping_sweeper.py), which pushed past the wall-clock threshold and
    fired synchronized false "offline" alerts across every device
    refreshed by that slow tick, not just one. Tick count tracks actual
    polling progress instead of a clock racing it -- the same reasoning
    already applied to INITIAL_POPULATION_TICK_WINDOW below.

"device offline" severity is role-dependent, not flat -- a Router
disappearing usually means the whole segment just lost its default
gateway (critical); a Switch/AP/Unmanaged Switch/Docker Host going down
affects a bounded subset of devices behind it (high); a plain Endpoint
going offline is routine and low-signal (low). "Back online" always
stays info regardless of role -- recovery isn't the event that needs
attention, the outage was.

Every status transition is also logged to device_state_transitions
(append-only). FIND-2 flapping detection reads that history: a MAC with
too many transitions inside FLAP_WINDOW_SECONDS gets a standing
'flapping' finding via device_findings (upserted, not re-alerted every
cycle -- device_findings' UNIQUE(mac_address, finding_type) means
re-detecting the same ongoing condition just bumps last_confirmed).
"""

import ipaddress
import logging
import sqlite3
import time

from engine.alerting import create_alert
from engine.config_loader import config

logger = logging.getLogger("Netlanvas.Alerting")

OFFLINE_GRACE_TICKS = 3

# Independent of OFFLINE_GRACE_TICKS above, and deliberately still
# wall-clock -- main.py's ARP-purge step uses this as a pure safety
# buffer ("has the offline alert almost certainly already fired and
# captured its context, before we delete that context"), not as the
# alert threshold itself. Sized to comfortably exceed OFFLINE_GRACE_TICKS
# worth of ticks even at the slow end (measured up to ~330s/tick under
# load) -- 3 * 330s = 990s -- with real margin, not just doubled from
# the old value. See main.py's own usage for the full reasoning.
PURGE_SAFETY_BUFFER_SECONDS = 1800

FLAP_WINDOW_SECONDS = 1800
FLAP_THRESHOLD = 4

# Any engine outage -- a deploy, a crash, a power failure, anything --
# means device_state.last_seen (and last_seen_tick) stop updating for
# every device for the entire duration the engine is down. Any device
# already close to its OFFLINE_GRACE_TICKS limit before the outage would
# otherwise cross it DURING the outage, purely because monitoring itself
# was unavailable, not because the device actually left. The first
# successful cycle after restart then fires a false offline+online
# alert pair for every device caught that way -- confirmed live: a
# burst of ~20+ simultaneous "back online" alerts with no genuine
# outage behind any of them, right after a routine redeploy.
#
# Fix: the first cycle after the engine starts is fundamentally a
# reconciliation against however-stale persisted state, not a
# real-time transition worth alerting on. State (device_state,
# device_state_transitions) still updates correctly and immediately --
# only the offline/online ALERTS are suppressed, for a short window
# after process start. new_device alerts are never suppressed -- a
# genuinely new MAC isn't an artifact of the engine's own downtime.
STARTUP_GRACE_SECONDS = 180
_PROCESS_START_TIME = time.monotonic()


def _in_startup_grace() -> bool:
    return (time.monotonic() - _PROCESS_START_TIME) < STARTUP_GRACE_SECONDS


# STATE-3: tick_counter is a per-PROCESS counter (resets to 0 on every
# restart, see main.py's background_polling_engine) -- unlike a
# wall-clock timestamp, a last_seen_tick value from a PREVIOUS process
# lifetime is meaningless after a restart, and if left as-is could make
# a device that was 'online' at crash time and is now genuinely offline
# take however many ticks its old last_seen_tick happened to be
# (potentially thousands) before ever crossing OFFLINE_GRACE_TICKS
# again -- effectively immune to offline detection until the tick
# counter catches back up. Re-baseline every row to the current tick on
# the first tick after a restart, same "first cycle is reconciliation,
# not a real transition" reasoning STARTUP_GRACE_SECONDS already applies
# to the alerts themselves.
def _reset_tick_baseline_if_needed(conn: sqlite3.Connection, tick: int) -> None:
    if tick <= 1:
        conn.execute("UPDATE device_state SET last_seen_tick = ?", (tick,))


# Separate concern from the startup-grace suppression above: discovering
# new devices is normal, expected behavior during initial population --
# either genuine first-ever setup, or right after an archive-on-restart
# wipe (see settings.html's "Archive on Boot") -- not a security/
# inventory event worth an individual alert per device. Detected once,
# on this process's first device_state_tracker call: if device_state
# was genuinely empty at that point, every "new" device found within
# the first INITIAL_POPULATION_TICK_WINDOW ticks is treated as part of
# that initial population, not alerted on individually.
#
# Tick-based, not wall-clock-based: a wall-clock window (the original
# implementation used 300s) races against how long the actual scan
# takes to enumerate every device, which scales with network size --
# confirmed live on a 76-node network where devices were still being
# discovered past a 5-minute wall-clock cutoff, so the tail of the
# initial scan alerted individually anyway. Tick count tracks actual
# scan progress instead (this tracker runs every fast tick, ~60s,
# regardless of the slower structural-deep-scan cadence), so it
# degrades gracefully on a bigger network instead of racing it.
#
# A normal restart of an already-populated appliance never triggers
# this -- device_state won't be empty -- so a genuinely new device
# joining right after a routine restart still alerts as expected.
INITIAL_POPULATION_TICK_WINDOW = 3
_initial_population_detected: bool | None = None  # None = not yet checked this process


def _in_initial_population(conn: sqlite3.Connection, tick: int) -> bool:
    global _initial_population_detected
    if _initial_population_detected is None:
        count = conn.execute("SELECT COUNT(*) FROM device_state").fetchone()[0]
        _initial_population_detected = count == 0
    return _initial_population_detected and tick <= INITIAL_POPULATION_TICK_WINDOW

# ALERT-4: mac_table_scraper's density-based edge resolution
# unconditionally purges any device whose only discoverable location is
# a backbone/uplink port -- correct for avoiding "device X is plugged
# into the trunk port" misreports, but a router's own uplink port is
# ALWAYS one of those penalized backbone ports by definition, so a
# router's MAC can structurally never get an endpoint_locations row.
# l3_bindings.last_seen is refreshed every fast tick (both main.py's
# ARP-scrape and ping_sweeper.py's ICMP sweep write it), so it's a
# reliable fallback presence signal for exactly the devices this gap
# affects (not router-specific -- anything hitting the same structural
# gap benefits).
#
# STATE-4: compared against actual tick BOUNDARIES, not a fixed
# wall-clock offset from "now" -- a static number of seconds (this used
# 120s, then 900s) is either too tight when a tick legitimately runs
# long (confirmed live: tick duration reaching ~330s under load, which
# made even 120s unreliable) or needlessly loose during healthy fast
# ticks, masking a real outage for longer than necessary. Since
# l3_bindings can't easily carry a tick number of its own (written from
# multiple files -- main.py's ARP-scrape, ping_sweeper.py's ICMP sweep
# -- that don't currently thread one through), main.py instead passes
# in tick_started_at: the wall-clock moment THIS tick began, captured
# before any stage ran. _previous_tick_started_at (below) remembers the
# PRIOR call's value, so the window is always exactly "since the start
# of the last completed tick" -- self-adjusting to however long ticks
# actually take, no arbitrary constant. Plain in-process module state,
# not persisted -- naturally resets to None on every restart, so
# there's no cross-restart staleness to handle the way last_seen_tick
# needed (see _reset_tick_baseline_if_needed).
_previous_tick_started_at: str | None = None

INFRASTRUCTURE_DEVICE_TYPES = {"Switch", "Access Point", "Unmanaged Switch", "Docker Host", "Server", "Printer"}

# UI-2: see server.py's identically-scoped DOCKER_BRIDGE_RANGE -- a
# Docker Host's own SNMP-reported internal bridge addresses shouldn't
# show up in an alert's "IP: ..." summary alongside its real LAN IP,
# it's just noise for anyone trying to go find the actual device.
DOCKER_BRIDGE_RANGE = ipaddress.ip_network("172.16.0.0/12")


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
    if hostname:
        return hostname
    if vendor:
        return f"{vendor} device ({mac_address})"
    return mac_address


def _offline_severity(conn: sqlite3.Connection, mac_address: str) -> str:
    row = conn.execute(
        """SELECT n.device_type FROM l2_interfaces i
           LEFT JOIN logical_nodes n ON i.node_id = n.id
           WHERE i.mac_address = ?""",
        (mac_address,),
    ).fetchone()
    device_type = row[0] if row else None
    # User-configurable via the Alerts page's Severity tab (ALERT-5) --
    # these _get_setting() calls fall back to the same defaults this
    # always shipped with, so an unconfigured appliance behaves exactly
    # as before this became overridable.
    if device_type == "Router":
        return config._get_setting("SEVERITY_OFFLINE_ROUTER", "critical")
    if device_type in INFRASTRUCTURE_DEVICE_TYPES:
        return config._get_setting("SEVERITY_OFFLINE_INFRASTRUCTURE", "high")
    return config._get_setting("SEVERITY_OFFLINE_ENDPOINT", "low")  # Endpoint, or not yet classified


def _device_context(conn: sqlite3.Connection, mac_address: str) -> str:
    """
    Builds an "IP: ... / VLAN: ... / AP: ..." suffix for alert detail
    text -- a bare MAC address on its own ("32:a1:c8:b4:58:8e reappeared
    on the network") isn't enough for someone to actually go find the
    device. Pulls whatever's already known without querying anything
    new: IPs from l3_bindings (a device can legitimately have several --
    see stage_arp_scrape's own TOPO-1 comment -- so all of them are
    listed, not just one), VLAN from endpoint_locations joined to
    network_vlans for a name if one's been set, and -- for wireless
    clients only -- the specific access point it's currently associated
    with. wifi_scraper.py's poll_wifi_clients()/heuristic_upstream_
    inference() both write the AP's own IP into endpoint_locations.
    switch_ip whenever local_port='WLAN' (that column means something
    different for wired devices -- the upstream switch, not an AP -- so
    this is deliberately gated on local_port to avoid a misleading
    "AP: <switch>" on a wired device). Each part is silently omitted
    when unknown, rather than printing a blank placeholder.
    """
    ip_rows = conn.execute(
        "SELECT ip_address FROM l3_bindings WHERE mac_address = ? ORDER BY last_seen DESC LIMIT 20",
        (mac_address,),
    ).fetchall()
    real_ips = []
    for (ip,) in ip_rows:
        try:
            if ipaddress.ip_address(ip) in DOCKER_BRIDGE_RANGE:
                continue
        except ValueError:
            pass
        real_ips.append(ip)
        if len(real_ips) == 5:
            break
    ips = ", ".join(real_ips)

    loc_row = conn.execute(
        """SELECT e.vlan_id, v.vlan_name, e.local_port, e.switch_ip FROM endpoint_locations e
           LEFT JOIN network_vlans v ON v.vlan_id = e.vlan_id
           WHERE e.mac_address = ?""",
        (mac_address,),
    ).fetchone()
    vlan_str = None
    ap_str = None
    if loc_row:
        vlan_id, vlan_name, local_port, switch_ip = loc_row
        if vlan_id is not None:
            vlan_str = f"VLAN {vlan_id} ({vlan_name})" if vlan_name else f"VLAN {vlan_id}"
        if local_port == "WLAN" and switch_ip:
            ap_mac_row = conn.execute("SELECT mac_address FROM l3_bindings WHERE ip_address = ?", (switch_ip,)).fetchone()
            ap_name = _friendly_name(conn, ap_mac_row[0]) if ap_mac_row else switch_ip
            ap_str = f"AP: {ap_name}"

    parts = []
    if ips:
        parts.append(f"IP: {ips}")
    if vlan_str:
        parts.append(vlan_str)
    if ap_str:
        parts.append(ap_str)
    return " -- " + " / ".join(parts) if parts else ""


def _log_transition(conn: sqlite3.Connection, mac_address: str, from_status: str | None, to_status: str) -> None:
    conn.execute(
        "INSERT INTO device_state_transitions (mac_address, from_status, to_status) VALUES (?, ?, ?)",
        (mac_address, from_status, to_status),
    )


def _check_flapping(conn: sqlite3.Connection, mac_address: str) -> None:
    # Counts only genuine offline events (to_status = 'offline'), not the
    # one-time 'new' bootstrap transitions every device gets on first
    # discovery -- otherwise a brand-new device's very first, completely
    # normal online/offline cycle would get flagged as "flapping" before
    # it's shown any real instability.
    count = conn.execute(
        """SELECT COUNT(*) FROM device_state_transitions
           WHERE mac_address = ? AND to_status = 'offline'
           AND transitioned_at >= datetime('now', ?)""",
        (mac_address, f"-{FLAP_WINDOW_SECONDS} seconds"),
    ).fetchone()[0]

    if count < FLAP_THRESHOLD:
        return

    name = _friendly_name(conn, mac_address)
    conn.execute(
        """INSERT INTO device_findings (mac_address, finding_type, severity, detail)
           VALUES (?, 'flapping', 'low', ?)
           ON CONFLICT(mac_address, finding_type) DO UPDATE SET
               last_confirmed = CURRENT_TIMESTAMP, detail = excluded.detail""",
        (mac_address, f"{name} has changed online/offline state {count} times in the last {FLAP_WINDOW_SECONDS // 60} minutes{_device_context(conn, mac_address)}."),
    )


async def run_device_state_tracker(db_path: str, tick: int, tick_started_at: str):
    global _previous_tick_started_at
    conn = sqlite3.connect(db_path)
    try:
        _reset_tick_baseline_if_needed(conn, tick)
        suppress_alerts = _in_startup_grace()
        suppress_new_device_alerts = _in_initial_population(conn, tick)
        present_macs = {row[0] for row in conn.execute("SELECT mac_address FROM endpoint_locations")}
        # See _previous_tick_started_at above -- covers devices (routers,
        # chiefly) that never get an endpoint_locations row at all.
        # Falls back to this tick's OWN start on the first call this
        # process (no prior tick to compare against yet) -- conservative,
        # and STARTUP_GRACE_SECONDS already suppresses any alert noise
        # from this exact moment regardless.
        l3_presence_cutoff = _previous_tick_started_at or tick_started_at
        present_macs |= {
            row[0] for row in conn.execute(
                "SELECT mac_address FROM l3_bindings WHERE last_seen >= ?",
                (l3_presence_cutoff,),
            )
        }
        _previous_tick_started_at = tick_started_at
        existing = {
            row[0]: (row[1], row[2])
            for row in conn.execute("SELECT mac_address, status, last_seen FROM device_state")
        }

        for mac in present_macs:
            if mac not in existing:
                conn.execute(
                    "INSERT INTO device_state (mac_address, status, last_seen_tick) VALUES (?, 'new', ?)",
                    (mac, tick),
                )
                _log_transition(conn, mac, None, "new")
                if not suppress_new_device_alerts:
                    name = _friendly_name(conn, mac)
                    create_alert(conn, "new_device", "info", f"New device discovered: {name}",
                                 detail=f"{mac} was seen on the network for the first time{_device_context(conn, mac)}.", mac_address=mac)
                continue

            status, _ = existing[mac]
            conn.execute(
                "UPDATE device_state SET last_seen = CURRENT_TIMESTAMP, last_seen_tick = ? WHERE mac_address = ?",
                (tick, mac),
            )
            if status == "new":
                conn.execute(
                    "UPDATE device_state SET status = 'online', last_status_change = CURRENT_TIMESTAMP WHERE mac_address = ?",
                    (mac,),
                )
                _log_transition(conn, mac, "new", "online")
            elif status == "offline":
                conn.execute(
                    "UPDATE device_state SET status = 'online', last_status_change = CURRENT_TIMESTAMP WHERE mac_address = ?",
                    (mac,),
                )
                _log_transition(conn, mac, "offline", "online")
                if not suppress_alerts:
                    name = _friendly_name(conn, mac)
                    create_alert(conn, "device_online", "info", f"{name} is back online",
                                 detail=f"{mac} reappeared on the network{_device_context(conn, mac)}.", mac_address=mac,
                                 is_resolution=True)
                _check_flapping(conn, mac)

        # COALESCE guards a row that somehow still has no last_seen_tick
        # (shouldn't happen post-migration + the restart reset above,
        # but treats it as "just seen this tick" rather than crashing or
        # wrongly flagging it stale on some NULL-arithmetic technicality).
        stale_candidates = conn.execute(
            """SELECT mac_address, status FROM device_state
               WHERE status IN ('new', 'online')
               AND (? - COALESCE(last_seen_tick, ?)) >= ?""",
            (tick, tick, OFFLINE_GRACE_TICKS),
        ).fetchall()
        for mac, status in stale_candidates:
            if mac in present_macs:
                continue  # last_seen was just bumped above this tick
            conn.execute(
                "UPDATE device_state SET status = 'offline', last_status_change = CURRENT_TIMESTAMP WHERE mac_address = ?",
                (mac,),
            )
            _log_transition(conn, mac, status, "offline")
            if not suppress_alerts:
                name = _friendly_name(conn, mac)
                severity = _offline_severity(conn, mac)
                create_alert(conn, "device_offline", severity, f"{name} went offline",
                             detail=f"{mac} has not been seen for {OFFLINE_GRACE_TICKS} consecutive polling cycles{_device_context(conn, mac)}.", mac_address=mac)
            _check_flapping(conn, mac)

        conn.commit()
    except Exception as e:
        logger.error(f"[STATE] device_state_tracker failed: {e}")
        conn.rollback()
    finally:
        conn.close()
