"""
alert_dispatcher.py

ALERT-5/6 delivery. Runs every tick (see main.py) rather than inline in
create_alert() -- decouples fast, always-succeeds local alert creation
from potentially slow/failing network delivery, and lets a config change
made after an alert was created still be picked up before it's sent
(thresholds are read fresh from alerting_config at dispatch time, not
creation time).

*_dispatched_at is set once delivery has been ATTEMPTED for that channel
(success or failure), never retried after that -- a bad webhook URL or
wrong SMTP password would otherwise get retried forever. The (not yet
built) test-webhook/test-email UI buttons are the intended way for a
user to validate their config; this dispatcher is fire-and-forget on
real alerts.

Two email paths, per ALERT-4's product decision (see alerting_config's
docstring in engine/database.py): 'relay' calls the webhost's Resend-
backed alert-relay.php, gated on device registration only (not paid
entitlement); 'smtp' sends directly via the user's own server, no
registration needed. Webhook delivery reuses device_identity's existing
Ed25519 keypair (originally built for REG-3/REG-4) to sign the payload --
unlike the relay path, a webhook receiver has no prior relationship with
this device, so the device's public key is sent alongside the signature
so any receiver can independently verify it without needing to have seen
this device before.

ALERT-7 adds a second webhook format, ntfy, alongside the original raw
JSON one (alerting_config.webhook_format, 'json' default / 'ntfy').
Unlike the JSON path, ntfy delivery isn't signed -- ntfy's publish API
has no field for a structured assertion, and the topic itself (a
per-device secret the webhost derives via HMAC, see webhost's
ntfy-topic.php) already is the access control for that channel. Uses
ntfy's JSON publish endpoint (server root, topic as a body field) rather
than its header-based one -- headers need ASCII-safe values in most
HTTP clients, and an alert title/detail can legitimately contain
non-ASCII text (e.g. a device hostname), so JSON is the safer choice.
"""

import logging
import smtplib
import sqlite3
import ssl
from email.mime.text import MIMEText

import requests

from engine.alerting import severity_meets_threshold
from security import device_identity

logger = logging.getLogger("Netlanvas.Alerting")

BACKEND_BASE_URL = "https://netlanvas.com"
DISPATCH_BATCH_LIMIT = 20
WEBHOOK_TIMEOUT = 5
SMTP_TIMEOUT = 10


def _send_webhook(webhook_url: str, alert: dict, device_public_key_b64: str | None) -> bool:
    claims = {
        "alert_id": alert["id"], "alert_type": alert["alert_type"], "severity": alert["severity"],
        "title": alert["title"], "detail": alert["detail"], "mac_address": alert["mac_address"],
        "created_at": alert["created_at"],
    }
    try:
        assertion = device_identity.build_assertion(claims)
        response = requests.post(
            webhook_url,
            json={"assertion": assertion, "device_public_key": device_public_key_b64},
            timeout=WEBHOOK_TIMEOUT,
        )
        response.raise_for_status()
        return True
    except Exception as e:
        logger.warning(f"[ALERT] Webhook delivery failed for alert {alert['id']}: {e}")
        return False


NTFY_SEVERITY_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
NTFY_SEVERITY_TAGS = {
    "critical": "rotating_light", "high": "warning", "medium": "large_orange_diamond",
    "low": "information_source", "info": "information_source",
}


def _send_webhook_ntfy(webhook_url: str, alert: dict) -> bool:
    """
    ALERT-7. webhook_url is stored as the full topic URL
    (https://<server>/<topic> -- the same one the Settings page's QR
    code/deep link/copy button all use), so the one saved value drives
    both the human-facing links and delivery -- split apart here into
    the server root ntfy's JSON endpoint wants plus the topic field,
    rather than storing them separately. Works against a self-hosted
    ntfy instance too, not just ntfy.sh, since the server root is
    derived from whatever URL setup actually returned.
    """
    server_root, _, topic = webhook_url.rpartition("/")
    if not server_root or not topic:
        logger.warning(f"[ALERT] ntfy delivery skipped for alert {alert['id']} -- malformed ntfy URL {webhook_url!r}.")
        return False
    is_resolution = bool(alert.get("is_resolution"))
    tag = "white_check_mark" if is_resolution else NTFY_SEVERITY_TAGS.get(alert["severity"], "information_source")
    try:
        response = requests.post(
            server_root + "/",
            json={
                "topic": topic,
                "message": alert["detail"] or alert["title"],
                "title": alert["title"],
                "priority": NTFY_SEVERITY_PRIORITY.get(alert["severity"], 3),
                "tags": [tag],
            },
            timeout=WEBHOOK_TIMEOUT,
        )
        response.raise_for_status()
        return True
    except Exception as e:
        logger.warning(f"[ALERT] ntfy delivery failed for alert {alert['id']}: {e}")
        return False


def _send_email_smtp(cfg: sqlite3.Row, alert: dict) -> bool:
    if not cfg["smtp_host"] or not cfg["email_to_address"]:
        logger.warning(f"[ALERT] SMTP delivery skipped for alert {alert['id']} -- smtp_host/email_to_address not configured.")
        return False
    msg = MIMEText(alert["detail"] or alert["title"])
    msg["Subject"] = f"[NetLanvas] {alert['title']}"
    msg["From"] = cfg["smtp_from_address"] or cfg["smtp_username"] or "netlanvas@localhost"
    msg["To"] = cfg["email_to_address"]
    try:
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"] or 587, timeout=SMTP_TIMEOUT) as server:
            if cfg["smtp_use_tls"]:
                server.starttls(context=ssl.create_default_context())
            if cfg["smtp_username"] and cfg["smtp_password"]:
                server.login(cfg["smtp_username"], cfg["smtp_password"])
            server.send_message(msg)
        return True
    except Exception as e:
        logger.warning(f"[ALERT] SMTP delivery failed for alert {alert['id']}: {e}")
        return False


def _send_email_relay(device_uuid: str, alert: dict) -> bool:
    try:
        assertion = device_identity.build_assertion({"device_uuid": device_uuid})
        response = requests.post(
            f"{BACKEND_BASE_URL}/api/alert-relay.php",
            json={
                "device_uuid": device_uuid, "assertion": assertion,
                "alert_title": alert["title"], "alert_detail": alert["detail"] or "",
                "severity": alert["severity"],
            },
            timeout=WEBHOOK_TIMEOUT,
        )
        response.raise_for_status()
        return bool(response.json().get("sent", False))
    except Exception as e:
        logger.warning(f"[ALERT] Relay email delivery failed for alert {alert['id']}: {e}")
        return False


def dispatch_pending_alerts(network_db_path: str, config_db_path: str) -> None:
    net_conn = sqlite3.connect(network_db_path)
    net_conn.row_factory = sqlite3.Row
    cfg_conn = sqlite3.connect(config_db_path)
    cfg_conn.row_factory = sqlite3.Row
    try:
        cfg = cfg_conn.execute("SELECT * FROM alerting_config WHERE id = 1").fetchone()
        if cfg is None:
            return  # alerting never configured -- nothing to deliver

        pending = net_conn.execute(
            """SELECT * FROM alerts
               WHERE email_dispatched_at IS NULL OR webhook_dispatched_at IS NULL
               ORDER BY created_at ASC LIMIT ?""",
            (DISPATCH_BATCH_LIMIT,),
        ).fetchall()
        if not pending:
            return

        def _app_setting(key):
            row = cfg_conn.execute("SELECT setting_value FROM app_settings WHERE setting_key = ?", (key,)).fetchone()
            return row[0] if row else None

        device_uuid = _app_setting("INSTANCE_ID")
        is_registered = str(_app_setting("IS_REGISTERED")).lower() == "true"
        pubkey_row = cfg_conn.execute("SELECT public_key_b64 FROM device_identity WHERE id = 1").fetchone()
        device_public_key_b64 = pubkey_row[0] if pubkey_row else None
        # Webhooks are a premium feature (ALERT-6 product decision) --
        # entitled comes from the same locally-cached snapshot the
        # settings page already reads (see /api/register/entitlement),
        # refreshed periodically against the backend, not re-checked
        # live here on every alert.
        entitlement_row = cfg_conn.execute("SELECT entitled FROM entitlement_cache WHERE id = 1").fetchone()
        is_entitled = bool(entitlement_row[0]) if entitlement_row else False

        for row in pending:
            alert = dict(row)

            if alert["email_dispatched_at"] is None:
                should_send = bool(cfg["email_enabled"]) and severity_meets_threshold(alert["severity"], cfg["email_min_severity"])
                sent = True  # not configured to send at all -- nothing pending, mark settled
                if should_send:
                    if cfg["email_delivery_method"] == "relay":
                        if device_uuid and is_registered:
                            sent = _send_email_relay(device_uuid, alert)
                        else:
                            logger.warning(f"[ALERT] Relay email skipped for alert {alert['id']} -- device is not registered.")
                            sent = True  # not a transient failure -- retrying won't help, don't loop on it forever
                    else:
                        sent = _send_email_smtp(cfg, alert)
                # Only mark dispatched on actual success -- a failed
                # send (network blip, relay rejecting a stale/replayed
                # assertion, SMTP target briefly unreachable) must be
                # retried on the next cycle, not silently and
                # permanently dropped. Confirmed live: this previously
                # marked dispatched unconditionally, so a transient
                # 409 from the relay meant the alert's email was never
                # sent and never would be.
                if sent:
                    net_conn.execute("UPDATE alerts SET email_dispatched_at = CURRENT_TIMESTAMP WHERE id = ?", (alert["id"],))

            if alert["webhook_dispatched_at"] is None:
                configured = bool(cfg["webhook_enabled"]) and cfg["webhook_url"] and \
                    severity_meets_threshold(alert["severity"], cfg["webhook_min_severity"])
                sent = True  # not configured, or not entitled -- nothing pending, mark settled
                if configured and is_entitled:
                    if cfg["webhook_format"] == "ntfy":
                        sent = _send_webhook_ntfy(cfg["webhook_url"], alert)
                    else:
                        sent = _send_webhook(cfg["webhook_url"], alert, device_public_key_b64)
                elif configured and not is_entitled:
                    logger.info(f"[ALERT] Webhook skipped for alert {alert['id']} -- premium feature, device not entitled.")
                # Same retry-on-failure fix as the email path above.
                if sent:
                    net_conn.execute("UPDATE alerts SET webhook_dispatched_at = CURRENT_TIMESTAMP WHERE id = ?", (alert["id"],))

        net_conn.commit()
    except Exception as e:
        logger.error(f"[ALERT] dispatch_pending_alerts failed: {e}")
    finally:
        net_conn.close()
        cfg_conn.close()
