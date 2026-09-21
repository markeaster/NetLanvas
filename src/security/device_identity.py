"""
device_identity.py

Generates and maintains this install's Ed25519 signing keypair, used to
prove device identity during account registration/relinking (REG-1) and
for ongoing entitlement checks (REG-4). Mirrors cert_manager.py's
file-based-key trust model: the private key is never bundled in the
image or repo, generated once at boot, written into a persisted volume,
and never stored anywhere queryable (e.g. config.db) -- only the public
key is.

Zero-config, idempotent: ensure_device_identity() is safe to call on
every boot. It generates a keypair on first run and is a no-op
thereafter -- unlike cert_manager.py's TLS cert, this key has no
expiry/renewal concept, since it's a long-lived identity, not a
short-lived credential.
"""

import base64
import json
import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("netlanvas.device_identity")

# Same directory as cert_manager.py's TLS keypair -- already a persisted
# volume (see docker-compose.dist.yaml's ./tls:/app/tls mount).
KEY_DIR = Path(os.environ.get("NETLANVAS_TLS_DIR", "/app/tls"))
KEY_PATH = KEY_DIR / os.environ.get("NETLANVAS_DEVICE_KEY_FILENAME", "device_identity.key")


def _generate_keypair() -> Ed25519PrivateKey:
    logger.info("Generating new device identity keypair for registration...")
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    KEY_PATH.chmod(0o600)
    return private_key


def _load_private_key() -> Ed25519PrivateKey | None:
    if not KEY_PATH.exists():
        return None
    try:
        return Ed25519PrivateKey.from_private_bytes(KEY_PATH.read_bytes())
    except ValueError as exc:
        logger.error("Existing device identity key at %s is unreadable/corrupt: %s", KEY_PATH, exc)
        return None


def _public_key_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _upsert_public_key(conn: sqlite3.Connection, public_key_b64: str) -> None:
    conn.execute(
        "INSERT INTO device_identity (id, public_key_b64, created_at) VALUES (1, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET public_key_b64 = excluded.public_key_b64",
        (public_key_b64, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def ensure_device_identity(conn: sqlite3.Connection) -> str:
    """
    Idempotent entry point called at every boot, after config.db's
    registration tables exist (init_registration_db() must run first --
    see main.py boot sequence). Returns the base64-encoded public key.
    """
    private_key = _load_private_key()
    if private_key is None:
        private_key = _generate_keypair()

    public_key_b64 = _public_key_b64(private_key)
    _upsert_public_key(conn, public_key_b64)
    return public_key_b64


def get_private_key() -> Ed25519PrivateKey:
    """
    For signing an assertion (REG-3/REG-4's ongoing entitlement checks).
    Raises if ensure_device_identity() has never run -- callers should
    only reach this after boot has completed.
    """
    private_key = _load_private_key()
    if private_key is None:
        raise FileNotFoundError(
            f"No device identity key at {KEY_PATH} -- ensure_device_identity() must run at boot first."
        )
    return private_key


def get_public_key_b64() -> str:
    """
    For any caller that just needs the base64-encoded public key
    without touching config.db (e.g. the telemetry pipeline's Step 0
    bootstrap ping, which reports it alongside instance_id over HTTP --
    a completely different destination than device_identity, no DB
    write belongs on that path). Raises the same as get_private_key()
    if boot has not completed yet.
    """
    return _public_key_b64(get_private_key())


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_assertion(claims: dict) -> str:
    """
    Minimal EdDSA-signed JWT-shaped assertion (RFC-7523-inspired, not
    literal RFC 7523 -- no JWKS/issuer negotiation needed since the
    backend already holds this device's public key from registration).
    Adds iat/exp automatically; callers supply the rest (device_uuid,
    pubkey, challenge for REG-3, or just device_uuid for ongoing
    entitlement checks). Must match backend/netlanvas-lib/eddsa_assertion.php's
    verify_eddsa_assertion() exactly: header.payload.signature, each
    segment base64url, signed message is "<header>.<payload>" as ASCII.
    """
    now = int(time.time())
    # jti: a random per-call nonce, not derived from anything the
    # caller supplies. Without this, two calls within the same whole
    # second (build_assertion's iat has 1-second resolution, and
    # EdDSA signing is deterministic) produce byte-identical
    # assertions -- confirmed live: dispatch_pending_alerts() sending
    # several alerts in one batch, some landing in the same second,
    # made the LATER ones look like replays of the FIRST to any
    # single-use-assertion check keyed on the raw assertion string
    # (see webhost's alert-relay.php), even though each was a
    # genuinely separate, legitimate call. The verifier
    # (eddsa_assertion.php) is schema-permissive -- it returns
    # whatever claims are present, so adding this needs no change on
    # that side.
    payload = {**claims, "iat": now, "exp": now + 120, "jti": secrets.token_hex(16)}

    header_b64 = _b64url(json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode("ascii"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("ascii"))

    signed_message = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = get_private_key().sign(signed_message)

    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"
