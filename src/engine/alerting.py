"""
alerting.py

Priority 3 (Free-Tier Alerting) shared primitives. ALERT-1's create_alert()
is the single write path into the `alerts` inbox table -- every alert
source (device_state_tracker, finding detectors, future ones) calls
through here so the inbox always sees a consistent row shape, regardless
of what generated it.

Severity is one of SEVERITY_LEVELS, CVSS-aligned so a simple free-tier
finding type and a future CVE-based premium finding type can share this
same scale without a later migration.

This module only ever writes to the in-app inbox (`alerts`). Whether an
alert ALSO goes out over email/webhook is a separate concern, gated by
alerting_config's own min-severity thresholds -- see the (not yet built)
delivery dispatcher. The inbox is the baseline every alert always reaches;
external delivery is opt-in on top of that.
"""

import logging
import sqlite3

from engine.config_loader import config

logger = logging.getLogger("Netlanvas.Alerting")

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {level: i for i, level in enumerate(SEVERITY_LEVELS)}

# device_state_transitions is only ever read within FLAP_WINDOW_SECONDS
# (device_state_tracker.py, 30 min) -- anything past 24h has already
# aged out of every query that could ever use it, so it's pure dead
# weight. alerts/device_findings carry real audit value, so they get a
# much longer retention instead of a short functional one.
TRANSITION_RETENTION_SECONDS = 24 * 3600
ALERT_RETENTION_DAYS = 365
RESOLVED_FINDING_RETENTION_DAYS = 365


def prune_alerting_history(db_path: str) -> None:
    """
    Bounds the growth of every alerting table that would otherwise
    accumulate forever on a long-running appliance. Safe to call as
    often as convenient -- every DELETE is idempotent and cheap when
    there's nothing to prune (indexed on the column being filtered).
    Active (unresolved) device_findings rows are never touched
    regardless of age -- they represent current state, not history.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "DELETE FROM device_state_transitions WHERE transitioned_at < datetime('now', ?)",
            (f"-{TRANSITION_RETENTION_SECONDS} seconds",),
        )
        conn.execute(
            "DELETE FROM alerts WHERE created_at < datetime('now', ?)",
            (f"-{ALERT_RETENTION_DAYS} days",),
        )
        conn.execute(
            "DELETE FROM device_findings WHERE resolved_at IS NOT NULL AND resolved_at < datetime('now', ?)",
            (f"-{RESOLVED_FINDING_RETENTION_DAYS} days",),
        )
        conn.commit()
        # No VACUUM here -- SQLite already reuses freed pages internally
        # for future writes, which is all "don't grow unbounded" needs.
        # A full VACUUM rewrites the entire file and would briefly lock
        # out the API container's concurrent reads of this same
        # database; not worth that risk for what's already a solved
        # problem without it.
    except Exception as e:
        logger.error(f"[ALERT] prune_alerting_history failed: {e}")
        conn.rollback()
    finally:
        conn.close()


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    """True if `severity` is at least as severe as `threshold`. Unknown
    values fail closed (never meet the threshold) rather than raising --
    a malformed config row shouldn't take delivery down entirely."""
    return SEVERITY_RANK.get(severity, -1) >= SEVERITY_RANK.get(threshold, len(SEVERITY_LEVELS))


def create_alert(conn: sqlite3.Connection, alert_type: str, severity: str,
                  title: str, detail: str | None = None, mac_address: str | None = None,
                  is_resolution: bool = False) -> int:
    """
    Inserts one row into the inbox and returns its id. Deliberately no
    dedup/upsert here (unlike device_findings) -- every call is a
    distinct, timestamped event a human should be able to see happened,
    even if the same condition recurs (e.g. a device going offline
    twice in one day is two separate alerts, not one row bumped twice).

    is_resolution flags a recovery/good-news event (device back online,
    a finding cleared) purely for UI treatment (see alerting.html) --
    it's independent of severity, which stays about urgency/threshold-
    filtering only. A resolution is correctly still 'info' severity
    (nobody needs an urgent ping that something got fixed), it just
    renders differently so it reads as good news, not a generic notice.
    """
    if severity not in SEVERITY_LEVELS:
        raise ValueError(f"Unknown severity {severity!r}, expected one of {SEVERITY_LEVELS}")
    cursor = conn.execute(
        "INSERT INTO alerts (alert_type, severity, mac_address, title, detail, is_resolution) VALUES (?, ?, ?, ?, ?, ?)",
        (alert_type, severity, mac_address, title, detail, is_resolution),
    )
    conn.commit()
    # Single point of truth for the sidebar's unread-badge marker --
    # every alert source goes through create_alert(), so every source
    # gets the badge for free rather than having to remember to set it
    # itself. Cleared by POST /api/alerts/mark-all-read.
    config._set_setting("ALERTS_HAS_NEW", "true")
    return cursor.lastrowid
