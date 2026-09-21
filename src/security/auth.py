"""
auth.py

Password hashing and session management for the NetLanvas web UI/API.

Design constraints:
  - Passwords are hashed with argon2id, never stored plaintext or
    reversibly encrypted.
  - Sessions are server-side (a row in SQLite), not a stateless signed
    cookie -- this makes them individually revocable (logout actually
    invalidates the session rather than just deleting a client-side
    cookie).
  - Session lifetime, cookie name, and token length are config-driven.
"""

import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

SESSION_LIFETIME_HOURS = int(os.environ.get("NETLANVAS_SESSION_LIFETIME_HOURS", "12"))
SESSION_TOKEN_BYTES = int(os.environ.get("NETLANVAS_SESSION_TOKEN_BYTES", "32"))
SESSION_COOKIE_NAME = os.environ.get("NETLANVAS_SESSION_COOKIE_NAME", "netlanvas_session")

_hasher = PasswordHasher()


def hash_password(plaintext: str) -> str:
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, stored_hash: str) -> bool:
    try:
        _hasher.verify(stored_hash, plaintext)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def credentials_exist(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    return row is not None and row[0] > 0


def create_initial_user(conn: sqlite3.Connection, username: str, plaintext_password: str) -> None:
    """
    Called exactly once, from the first-run setup route. Callers must
    enforce that this cannot run again once a user row exists -- this
    function itself does not gate that, the route does.
    """
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, hash_password(plaintext_password), datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def verify_login(conn: sqlite3.Connection, username: str, plaintext_password: str) -> int | None:
    """Returns the user_id on success, None on failure."""
    row = conn.execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    if row is None:
        # Run a hash verification against a throwaway hash so a login
        # attempt for a nonexistent username takes roughly the same time
        # as a wrong-password attempt on a real one (reduces username
        # enumeration via a response-time side channel).
        try:
            _hasher.verify(_hasher.hash(secrets.token_hex(16)), plaintext_password)
        except (VerifyMismatchError, InvalidHashError):
            pass
        return None

    user_id, stored_hash = row
    if not verify_password(plaintext_password, stored_hash):
        return None

    if needs_rehash(stored_hash):
        new_hash = hash_password(plaintext_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()

    return user_id


def create_session(conn: sqlite3.Connection, user_id: int) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    token_hash = _hasher.hash(token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_LIFETIME_HOURS)

    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token_hash, user_id, datetime.now(timezone.utc).isoformat(), expires_at.isoformat()),
    )
    conn.commit()
    return token, expires_at


def validate_session(conn: sqlite3.Connection, token: str) -> int | None:
    """Returns user_id if the session token is valid and unexpired, else None."""
    if not token:
        return None

    now = datetime.now(timezone.utc).isoformat()
    rows = conn.execute(
        "SELECT id, token_hash, user_id FROM sessions WHERE expires_at > ?", (now,)
    ).fetchall()

    for session_id, token_hash, user_id in rows:
        try:
            if _hasher.verify(token_hash, token):
                return user_id
        except (VerifyMismatchError, InvalidHashError):
            continue

    return None


def revoke_session(conn: sqlite3.Connection, token: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    rows = conn.execute(
        "SELECT id, token_hash FROM sessions WHERE expires_at > ?", (now,)
    ).fetchall()

    for session_id, token_hash in rows:
        try:
            if _hasher.verify(token_hash, token):
                conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
                conn.commit()
                return
        except (VerifyMismatchError, InvalidHashError):
            continue


def purge_expired_sessions(conn: sqlite3.Connection) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    conn.commit()


# --- First-run setup token (see security/welcome.py) ---
#
# Closes the setup-claim race: /api/setup/password is unauthenticated by
# necessity (no account exists yet), so without this, whoever reaches
# the appliance first over the network wins the admin account. This
# token is generated at boot, its PLAINTEXT is only ever written to the
# welcome file (console/host access required to read it), and only its
# argon2 hash is stored here -- identical trust model to a real
# password, just single-use and short-lived.

def generate_setup_token() -> str:
    return secrets.token_urlsafe(16)


def store_setup_token(conn: sqlite3.Connection, plaintext: str) -> None:
    token_hash = hash_password(plaintext)
    conn.execute(
        "INSERT INTO setup_token (id, token_hash, created_at) VALUES (1, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET token_hash = excluded.token_hash, created_at = excluded.created_at",
        (token_hash, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def verify_setup_token(conn: sqlite3.Connection, plaintext: str) -> bool:
    row = conn.execute("SELECT token_hash FROM setup_token WHERE id = 1").fetchone()
    if row is None:
        return False
    return verify_password(plaintext, row[0])


def clear_setup_token(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM setup_token WHERE id = 1")
    conn.commit()
