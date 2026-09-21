"""
credential_vault.py

Encrypts SNMPv3 authentication passwords at rest (see punch list SNMP-5/
SNMP-7 and CWE-312 finding F4). snmp_v3_identities.password previously
held these in cleartext inside config.db -- anyone who obtained that one
SQLite file (a stolen backup, a misconfigured bind mount, etc.) could
read live authentication material for the site's network infrastructure
straight out of it.

Design: a symmetric key (Fernet -- AES-128-CBC + HMAC, from the
`cryptography` package already vendored for cert_manager.py) is
generated on first use and persisted at KEY_PATH, which lives under the
./config bind mount -- a different host directory than ./db, where
config.db itself lives (see docker-compose.yaml). That separation is
the whole point: a copy of config.db alone is no longer enough to
recover the plaintext passwords, matching this finding's recommendation
to use "an application-managed key (not derivable from the same DB
file)". KEY_PATH must never be committed to the repository -- see the
config/*.key entry in .gitignore.

Both netlanvas_core (POLLER, decrypts to authenticate against devices)
and netlanvas_api (API_VIEWER, encrypts on identity creation) mount the
same ./config host directory, so either process can create the key if
it doesn't exist yet and the other will see the same file.
"""

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("Netlanvas.CredentialVault")

CONFIG_DIR = Path(os.environ.get("NETLANVAS_CONFIG_DIR", "/app/config"))
KEY_PATH = CONFIG_DIR / os.environ.get("NETLANVAS_CREDENTIAL_KEY_FILENAME", "secret.key")

_fernet = None


def _get_or_create_key() -> bytes:
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes().strip()

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()

    # Write via a temp file + atomic rename, and re-check for a
    # concurrent winner right before doing so -- netlanvas_core and
    # netlanvas_api are separate processes that could both reach this
    # path on first boot after an identity is configured.
    tmp_path = KEY_PATH.with_suffix(f"{KEY_PATH.suffix}.tmp-{os.getpid()}")
    tmp_path.write_bytes(key)
    tmp_path.chmod(0o600)
    try:
        if KEY_PATH.exists():
            tmp_path.unlink(missing_ok=True)
            return KEY_PATH.read_bytes().strip()
        os.replace(tmp_path, KEY_PATH)
    finally:
        tmp_path.unlink(missing_ok=True)

    logger.info("Generated new credential-encryption key at %s", KEY_PATH)
    return key


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_get_or_create_key())
    return _fernet


def encrypt_password(plaintext: str) -> str:
    """Returns an opaque, ASCII-safe token suitable for storing in a TEXT column."""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_password(stored_value: str) -> str:
    """
    Reverses encrypt_password(). Falls back to returning `stored_value`
    unchanged if it isn't a valid Fernet token -- this keeps rows written
    by a pre-encryption install readable rather than breaking SNMP
    polling outright. Callers that load a credential for real use (see
    engine.snmp_adapter.get_configured_credentials) pair this with
    is_encrypted() below and write the encrypted form straight back on
    the very first read that finds plaintext, rather than only fixing
    it whenever someone happens to re-save it through the UI -- see
    that call site for the actual self-healing logic; this function
    itself stays read-only.
    """
    try:
        return _get_fernet().decrypt(stored_value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError, UnicodeEncodeError):
        logger.warning(
            "Stored SNMPv3 password was not a valid encrypted token; treating as legacy plaintext."
        )
        return stored_value


def is_encrypted(stored_value: str) -> bool:
    """True if `stored_value` is a valid Fernet token (already encrypted at rest), False if it looks like legacy plaintext."""
    try:
        _get_fernet().decrypt(stored_value.encode("ascii"))
        return True
    except (InvalidToken, ValueError, UnicodeDecodeError, UnicodeEncodeError):
        return False
