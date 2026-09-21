"""
registration.py

Orchestrates the device registration handshake (REG-2/REG-3) and ongoing
entitlement checks (REG-4/ACCT-3). device_identity.py owns the keypair
and low-level assertion signing; this module owns the higher-level flow
-- generating/verifying the local CSRF state, calling out to the
backend, and caching the result. Same split of responsibility as
auth.py (flow) vs cert_manager.py (crypto), applied to registration.

registration_state uses the identical trust model as auth.py's
setup_token: a single in-flight attempt (id=1), only the argon2 hash of
the token is stored, the plaintext exists only transiently in the
initiate response and the browser's round trip.
"""

import json
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import requests

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from security import device_identity

logger = logging.getLogger("netlanvas.registration")

BACKEND_BASE_URL = "https://netlanvas.com"
STATE_TOKEN_BYTES = 32
STATE_LIFETIME_MINUTES = 10

_hasher = PasswordHasher()


def generate_state_token(conn: sqlite3.Connection) -> str:
    token = secrets.token_urlsafe(STATE_TOKEN_BYTES)
    token_hash = _hasher.hash(token)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=STATE_LIFETIME_MINUTES)

    conn.execute(
        "INSERT INTO registration_state (id, state_token_hash, created_at, expires_at) VALUES (1, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET state_token_hash = excluded.state_token_hash, "
        "created_at = excluded.created_at, expires_at = excluded.expires_at",
        (token_hash, now.isoformat(), expires_at.isoformat()),
    )
    conn.commit()
    return token


def verify_and_consume_state_token(conn: sqlite3.Connection, plaintext: str) -> bool:
    """
    Single-use: valid tokens are consumed (deleted) on successful
    verification so a captured/replayed local_state can't be reused.
    """
    row = conn.execute(
        "SELECT state_token_hash, expires_at FROM registration_state WHERE id = 1"
    ).fetchone()
    if row is None:
        return False

    token_hash, expires_at = row
    if datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
        conn.execute("DELETE FROM registration_state WHERE id = 1")
        conn.commit()
        return False

    try:
        _hasher.verify(token_hash, plaintext)
    except (VerifyMismatchError, InvalidHashError):
        return False

    conn.execute("DELETE FROM registration_state WHERE id = 1")
    conn.commit()
    return True


def complete_registration(device_uuid: str, pubkey_b64: str, challenge: str) -> dict:
    """
    REG-3's local callback -> REG-6. Builds a signed assertion vouching
    for this exact device_uuid/challenge and POSTs it to the backend,
    following the same requests.post(..., timeout=3) shape
    send_first_boot_telemetry() already uses. Raises on any transport
    failure -- callers decide how to surface that to the browser.
    """
    assertion = device_identity.build_assertion({
        "device_uuid": device_uuid,
        "pubkey": pubkey_b64,
        "challenge": challenge,
    })
    response = requests.post(
        f"{BACKEND_BASE_URL}/api/register-complete.php",
        json={
            "device_uuid": device_uuid,
            "pubkey": pubkey_b64,
            "challenge": challenge,
            "assertion": assertion,
        },
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def check_entitlement(device_uuid: str, submit_telemetry: bool | None = None) -> dict:
    """
    ACCT-3's ongoing check -- returns real entitled/email/plan_type/
    plan_expires_at now that compute_entitled() backs entitlement-check.php
    (see that file), not just the pre-Paddle placeholder this used to be.

    submit_telemetry, when given, piggybacks this appliance's current
    SUBMIT_TELEMETRY setting onto the same round trip so the backend can
    keep accounts.telemetry_preference in sync (last-known-value across
    however many devices this account has) -- omit it (None) for a
    routine background refresh where the caller doesn't have/need the
    current value handy; only a settings-page-triggered check needs to
    actually report it.
    """
    assertion = device_identity.build_assertion({"device_uuid": device_uuid})
    body = {"device_uuid": device_uuid, "assertion": assertion}
    if submit_telemetry is not None:
        body["submit_telemetry"] = submit_telemetry
    response = requests.post(
        f"{BACKEND_BASE_URL}/api/entitlement-check.php",
        json=body,
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def fetch_ntfy_topic(device_uuid: str) -> dict:
    """
    ALERT-7. Same signed-assertion pattern as check_entitlement() --
    proves this call genuinely comes from the device itself. The
    backend derives and returns a deterministic per-device ntfy.sh
    topic (HMAC-SHA256 of device_uuid, keyed by a secret that never
    leaves the webhost); this call is idempotent, always returning the
    same topic for the same device, so it's safe to call again if the
    user just wants to re-fetch/re-display it. Raises on a non-2xx
    response (e.g. 402 if the device isn't entitled) -- caller surfaces
    that as an error rather than silently configuring a broken URL.
    """
    assertion = device_identity.build_assertion({"device_uuid": device_uuid})
    response = requests.post(
        f"{BACKEND_BASE_URL}/api/ntfy-topic.php",
        json={"device_uuid": device_uuid, "assertion": assertion},
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def deregister_device(device_uuid: str) -> dict:
    """
    Unlinks this device from whatever account it's currently registered
    to. Same signed-assertion pattern as check_entitlement() -- the
    backend already holds this device's public key from registration, so
    a valid signature over device_uuid is proof this call is genuinely
    coming from the device itself, not just anyone who knows the UUID.
    Caller (server.py's route) is responsible for clearing IS_REGISTERED
    and entitlement_cache locally once this succeeds.
    """
    assertion = device_identity.build_assertion({"device_uuid": device_uuid})
    response = requests.post(
        f"{BACKEND_BASE_URL}/api/register-deregister.php",
        json={"device_uuid": device_uuid, "assertion": assertion},
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def store_entitlement_cache(conn: sqlite3.Connection, account_linked: bool, entitled: bool, raw_response_json: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO entitlement_cache (id, account_linked, entitled, checked_at, raw_response_json) "
        "VALUES (1, ?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET account_linked = excluded.account_linked, "
        "entitled = excluded.entitled, checked_at = excluded.checked_at, raw_response_json = excluded.raw_response_json",
        (account_linked, entitled, now, raw_response_json),
    )
    conn.commit()


def get_entitlement_cache(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute(
        "SELECT account_linked, entitled, checked_at, raw_response_json FROM entitlement_cache WHERE id = 1"
    ).fetchone()
    if row is None:
        return None
    result = {"account_linked": bool(row[0]), "entitled": bool(row[1]), "checked_at": row[2]}
    # email/plan_type/plan_expires_at ride along in the backend's raw
    # response (added once entitlement-check.php started returning them
    # for the settings page) -- optional so older cached rows without
    # these fields still parse fine.
    if row[3]:
        try:
            raw = json.loads(row[3])
            for key in ("email", "plan_type", "plan_expires_at", "has_passkey"):
                if key in raw:
                    result[key] = raw[key]
        except (json.JSONDecodeError, TypeError):
            pass
    return result
