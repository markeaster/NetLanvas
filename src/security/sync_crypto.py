"""
sync_crypto.py

Client-side crypto for Multi-Site Inventory Sync (design doc Sections
4/5). Implements PIE (Pre-Internet Encryption) for this feature: the
Sync Passphrase and every key derived from it never leave this
process, and the webserver only ever receives ciphertext + a
non-secret salt/nonce it cannot use to decrypt anything.

Deliberately NOT derived from login credentials (rejected design,
Section 4) -- a passkey account has no reusable secret to derive from,
so this uses a separate passphrase the user sets once and re-enters on
each new instance.
"""

import os

import argon2.low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KDF_SALT_BYTES = 16
KDF_MEMORY_KIB = 32 * 1024  # 32 MiB
KDF_TIME_COST = 3
KDF_PARALLELISM = 1
KDF_ALGORITHM = "argon2id"
AES_KEY_BYTES = 32   # AES-256
AES_NONCE_BYTES = 12  # standard GCM nonce length

# KEY-CHECK-1 (2026-09-26, real user report): a wrong Sync Passphrase
# entered on a later instance was silently accepted and only failed
# much later -- invisibly, since every pull from then on quietly
# failed to decrypt every peer's blob (InvalidTag, caught and logged
# in pull_and_decrypt(), never surfaced anywhere the user would see
# it). This fixed, versioned plaintext is encrypted by whichever
# instance sets up sync FIRST on an account and stored server-side
# (account_sync_keys.key_check_ciphertext) -- every later instance
# decrypts it locally with its own freshly-derived key before
# accepting a passphrase, entirely offline; the server still never
# sees the passphrase or the derived key, only this ciphertext, same
# as every real inventory blob. Versioned (the trailing "-v1") so a
# future change to this mechanism can't collide with values already
# stored under the old one.
KEY_CHECK_PLAINTEXT = b"netlanvas-sync-key-check-v1"


def generate_kdf_salt() -> bytes:
    """16 random bytes, generated once per account and stored server-side
    (account_sync_keys.kdf_salt) -- not secret, same role as a password
    hash's salt."""
    return os.urandom(KDF_SALT_BYTES)


def derive_sync_key(passphrase: str, salt: bytes) -> bytes:
    """
    Argon2id, 32 MiB / t=3 / p=1 (Section 5) -- deliberately memory-hard
    so a stolen salt (never secret, but returned by /pull) doesn't make
    offline passphrase-guessing cheap. Returns a raw 32-byte key
    suitable directly as an AES-256-GCM key.
    """
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("passphrase must be a non-empty string")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != KDF_SALT_BYTES:
        raise ValueError(f"salt must be exactly {KDF_SALT_BYTES} bytes")

    return argon2.low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=bytes(salt),
        time_cost=KDF_TIME_COST,
        memory_cost=KDF_MEMORY_KIB,
        parallelism=KDF_PARALLELISM,
        hash_len=AES_KEY_BYTES,
        type=argon2.low_level.Type.ID,
    )


def encrypt_payload(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    AES-256-GCM with a fresh random nonce per call -- never reuse a
    nonce under the same key, which is why this always generates its
    own rather than accepting one. Returns (nonce, ciphertext); the
    GCM tag rides inside ciphertext (AESGCM's own convention).
    """
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"key must be exactly {AES_KEY_BYTES} bytes")
    nonce = os.urandom(AES_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Raises cryptography.exceptions.InvalidTag on any tampering or wrong
    key/passphrase -- callers must not swallow this silently, since a
    wrong Sync Passphrase and a corrupted/tampered blob look identical
    from here and both must fail loudly rather than return garbage.
    """
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"key must be exactly {AES_KEY_BYTES} bytes")
    if len(nonce) != AES_NONCE_BYTES:
        raise ValueError(f"nonce must be exactly {AES_NONCE_BYTES} bytes")
    return AESGCM(key).decrypt(nonce, ciphertext, None)
