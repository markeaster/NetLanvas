"""
sync_client.py

Multi-Site Inventory Sync's network/caching layer (design doc Sections
6/8/14). Talks to netlanvas.com's push.php/pull.php/sync-key-info.php
using the same signed-assertion pattern as registration.py's
check_entitlement(), and owns local caching of the (non-secret) KDF
salt and the (secret, wrapped-at-rest) derived sync key.

PIE (Pre-Internet Encryption): the Sync Passphrase and the derived key
are never sent anywhere. Only the salt (not secret) and encrypted
blobs (opaque to the server) cross the network.
"""

import base64
import json
import logging
import sqlite3

import requests

from security import device_identity, sync_crypto
from security.credential_vault import encrypt_password, decrypt_password

logger = logging.getLogger("netlanvas.sync_client")

BACKEND_BASE_URL = "https://netlanvas.com"

SETTING_KDF_SALT = "SYNC_KDF_SALT"          # base64, not secret -- Layer 2 local cache, design doc Section 14
SETTING_KEY_WRAPPED = "SYNC_KEY_WRAPPED"    # credential_vault-wrapped, base64 payload inside


class SyncKeySaltMismatchError(Exception):
    """
    Raised when the server hands back a KDF salt that doesn't match
    what this instance already has cached locally for this account.
    Design doc Section 14: this is the disaster signal, not a normal
    first-time-setup case -- account_sync_keys was lost/recreated
    server-side. Callers must NOT silently re-derive and proceed; doing
    so would produce a key that can't decrypt any blob already pushed
    under the old one, compounding data loss with a confusing failure.
    """
    def __init__(self, cached_salt_b64: str, server_salt_b64: str):
        self.cached_salt_b64 = cached_salt_b64
        self.server_salt_b64 = server_salt_b64
        super().__init__(
            "Server's KDF salt does not match this instance's cached salt -- "
            "account_sync_keys may have been lost and recreated server-side."
        )


class SyncPassphraseMismatchError(Exception):
    """
    KEY-CHECK-1: raised when this instance's freshly-derived key fails
    to decrypt the account's existing key-check canary -- the
    passphrase just entered does not match whatever passphrase an
    earlier instance on this account already set up. Callers must
    treat this exactly like SyncKeySaltMismatchError: do NOT cache the
    derived key or mark sync enabled. Distinct from that error, which
    means the account's own sync setup was lost/recreated server-side
    -- this one means a human simply typed the wrong thing, and is
    normal, expected, and immediately fixable by trying again.
    """
    def __init__(self):
        super().__init__(
            "This passphrase does not match the one already set up on "
            "another instance in this account."
        )


def _post_signed(endpoint: str, device_uuid: str, extra_body: dict | None = None) -> dict:
    """Same signed-assertion pattern as registration.check_entitlement()."""
    assertion = device_identity.build_assertion({"device_uuid": device_uuid})
    body = {"device_uuid": device_uuid, "assertion": assertion}
    if extra_body:
        body.update(extra_body)
    response = requests.post(f"{BACKEND_BASE_URL}/api/{endpoint}", json=body, timeout=10)
    response.raise_for_status()
    return response.json()


def _verify_key_against_canary(key: bytes, nonce_b64: str | None, ciphertext_b64: str | None) -> None:
    """
    KEY-CHECK-1: raises SyncPassphraseMismatchError if `key` can't
    decrypt the given canary. A caller passing (None, None) -- nothing
    to verify against yet -- is a no-op, not an error.
    """
    if not nonce_b64 or not ciphertext_b64:
        return
    try:
        sync_crypto.decrypt_payload(key, base64.b64decode(nonce_b64), base64.b64decode(ciphertext_b64))
    except Exception:
        raise SyncPassphraseMismatchError()


def get_or_derive_sync_key(conn: sqlite3.Connection, device_uuid: str, passphrase: str | None = None) -> bytes:
    """
    Returns the 32-byte derived sync key, from local cache if present,
    otherwise deriving it fresh (requires `passphrase`) and caching the
    result. Raises SyncKeySaltMismatchError rather than silently
    re-deriving if the server's salt disagrees with what's already
    cached locally -- see that class's docstring.

    KEY-CHECK-1 (2026-09-26, real user report): a wrong passphrase
    previously derived a key silently, was cached, and only failed
    much later -- invisibly, since every subsequent pull just quietly
    failed to decrypt every peer's blob. Before this function ever
    caches/returns a freshly-derived key, it verifies it against the
    account's key-check canary (see sync_crypto.KEY_CHECK_PLAINTEXT
    and SyncPassphraseMismatchError's own docstring) -- an already-
    cached key (the fast path above) is trusted as-is and skips this
    entirely, since it already proved itself the first time it was
    derived.
    """
    from engine.config_loader import config  # local import: avoids a circular import with server.py's own config wiring

    wrapped_key = config._get_setting(SETTING_KEY_WRAPPED)
    if wrapped_key:
        return base64.b64decode(decrypt_password(wrapped_key))

    if not passphrase:
        raise ValueError("No cached sync key and no passphrase given to derive one.")

    info = _post_signed("sync-key-info.php", device_uuid)
    server_salt_b64 = info["kdf_salt"]

    cached_salt_b64 = config._get_setting(SETTING_KDF_SALT)
    if cached_salt_b64 and cached_salt_b64 != server_salt_b64:
        raise SyncKeySaltMismatchError(cached_salt_b64, server_salt_b64)

    salt = base64.b64decode(server_salt_b64)
    key = sync_crypto.derive_sync_key(passphrase, salt)

    if info.get("key_check_nonce") and info.get("key_check_ciphertext"):
        # Someone on this account already claimed the canary -- this
        # key must decrypt it, or the passphrase just entered is wrong.
        _verify_key_against_canary(key, info["key_check_nonce"], info["key_check_ciphertext"])
    else:
        # Nobody's claimed a canary yet -- this may be the very first
        # instance ever to set up sync on this account (or one that
        # pre-dates this check). Offer a candidate; the server's
        # COALESCE upsert only claims it if the account still has none,
        # so a race against another instance doing the same at the same
        # moment resolves safely to whichever wins -- and verifying
        # against whatever comes back (this instance's own candidate,
        # or someone else's if it lost the race) is the same check
        # either way.
        candidate_nonce, candidate_ciphertext = sync_crypto.encrypt_payload(key, sync_crypto.KEY_CHECK_PLAINTEXT)
        claim_info = _post_signed("sync-key-info.php", device_uuid, {
            "key_check_nonce": base64.b64encode(candidate_nonce).decode("ascii"),
            "key_check_ciphertext": base64.b64encode(candidate_ciphertext).decode("ascii"),
        })
        _verify_key_against_canary(key, claim_info.get("key_check_nonce"), claim_info.get("key_check_ciphertext"))

    # Layer 2 (Section 14): cache the salt locally too, in the clear --
    # it was never secret, and this is what makes THIS instance a
    # backup copy the server's row can be restored from if it's ever
    # lost. The key itself is wrapped via credential_vault before
    # touching disk, same as SNMPv3 credentials.
    config._set_setting(SETTING_KDF_SALT, server_salt_b64)
    config._set_setting(SETTING_KEY_WRAPPED, encrypt_password(base64.b64encode(key).decode("ascii")))

    return key


def push_inventory_blob(device_uuid: str, key: bytes, plaintext: bytes) -> dict:
    """
    Synchronous, blocking -- callers on the async side (server.py's
    request handlers, main.py's stage sequence) must schedule this via
    asyncio.to_thread() inside a detached asyncio.create_task(), never
    call it inline. That's the GAP-9 fix (design doc Section 6/12):
    a slow or failed connection to netlanvas.com here must never stall
    the caller.
    """
    nonce, ciphertext = sync_crypto.encrypt_payload(key, plaintext)
    return _post_signed("push.php", device_uuid, {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    })


def pull_and_decrypt(device_uuid: str, key: bytes, since: dict | None = None) -> list[dict]:
    """
    Fetches every instance's blob on the account (including this
    device's own) and decrypts each with the locally-derived key.
    A blob that fails to decrypt (InvalidTag) is skipped with a
    warning, not raised -- one corrupted or foreign-key blob must not
    block merging every other instance's good data.

    since (2026-09-25, direct bandwidth concern): {instance_id:
    last_known_updated_at}, tracked by the caller (server.py's
    _do_sync_pull) across pull cycles. A periodic pull with no
    filtering re-downloads every other instance's FULL ciphertext blob
    every cycle regardless of whether anything actually changed --
    real, unbounded, entirely avoidable bandwidth on a long-running
    account. pull.php only returns a blob strictly newer than what's
    already known; omitting since (or an empty dict, a first-ever
    pull) returns everything, same as before -- exactly what a newly-
    enabled instance's first catch-up pull needs.
    """
    result = _post_signed("pull.php", device_uuid, {"since": since or {}})
    decrypted = []
    for blob in result.get("blobs", []):
        try:
            nonce = base64.b64decode(blob["nonce"])
            ciphertext = base64.b64decode(blob["ciphertext"])
            plaintext = sync_crypto.decrypt_payload(key, nonce, ciphertext)
            decrypted.append({
                "instance_id": blob["instance_id"],
                "updated_at": blob["updated_at"],
                "data": json.loads(plaintext),
            })
        except Exception as e:
            logger.warning(f"[SYNC] Skipping undecryptable blob from instance {blob.get('instance_id')}: {e}")
    return decrypted
