"""
api_tokens.py

Long-lived API tokens for programmatic/non-browser access to NetLanvas's
own REST API (e.g. an MCP server) -- a separate credential from the
session cookie, with its own lifecycle and scope.

Design constraints, same trust model as security/auth.py's sessions
(never credential_vault.py's reversible encryption -- an API token
authenticates INBOUND like a password, it is never something NetLanvas
must decrypt and present outward to a third party):
  - Tokens are generated with secrets.token_urlsafe, never stored or
    logged in plaintext -- only an argon2id hash (via auth.hash_password/
    verify_password, the same primitives sessions already use).
  - The plaintext is shown to the caller exactly once, at creation time,
    and never again -- same single-reveal discipline as the setup/
    recovery tokens in auth.py.
  - Each token is independently labeled and revocable (a DELETE removes
    the row outright, same as revoke_session) -- revoking one integration
    never affects another's token.
  - Scope is a single is_read_only flag, enforced by security/middleware.py
    against the request method (GET only for a read-only token) -- not a
    per-route allowlist. Deliberately the simpler of the two designs
    discussed: the only real consumer today is a read-only MCP server,
    and a per-route scope model can be added later if a second consumer
    actually needs something narrower.
"""

import secrets
import sqlite3
from datetime import datetime, timezone

from security.auth import hash_password, verify_password

# Purely a recognizability prefix (e.g. so a token accidentally committed
# or logged is greppable/revokable on sight) -- doesn't reduce entropy,
# the random part is still secrets.token_urlsafe(32) after it.
TOKEN_PREFIX = "nlvt_"


def generate_api_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def create_api_token(conn: sqlite3.Connection, label: str, is_read_only: bool = True) -> tuple[int, str]:
    """Returns (token_id, plaintext). The plaintext is never stored -- capture it now, it's gone after this call returns."""
    plaintext = generate_api_token()
    token_hash = hash_password(plaintext)
    cursor = conn.execute(
        "INSERT INTO api_tokens (label, token_hash, is_read_only, created_at) VALUES (?, ?, ?, ?)",
        (label, token_hash, is_read_only, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return cursor.lastrowid, plaintext


def list_api_tokens(conn: sqlite3.Connection) -> list[dict]:
    """Never includes the hash, let alone the plaintext -- same convention as /api/snmp/v3-identities."""
    rows = conn.execute(
        "SELECT id, label, is_read_only, created_at, last_used_at FROM api_tokens ORDER BY created_at"
    ).fetchall()
    return [
        {
            "id": r["id"],
            "label": r["label"],
            "is_read_only": bool(r["is_read_only"]),
            "created_at": r["created_at"],
            "last_used_at": r["last_used_at"],
        }
        for r in rows
    ]


def revoke_api_token(conn: sqlite3.Connection, token_id: int) -> bool:
    """Returns True if a row was actually deleted (caller can distinguish 'already gone' from 'removed')."""
    cursor = conn.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
    conn.commit()
    return cursor.rowcount > 0


def revoke_all_api_tokens(conn: sqlite3.Connection) -> int:
    """
    Returns the number of tokens revoked. Tokens are appliance-wide (no
    user_id column -- this appliance has exactly one admin, see
    auth.get_sole_user_id), so there's no per-user filter here, unlike
    auth.revoke_all_sessions_for_user.

    Finding from the 2026-11-03 security review of this feature: unlike
    sessions, API tokens were never invalidated by a credential reset --
    a token minted during a transient session compromise (stolen cookie,
    unattended browser) survived both a password change AND
    revoke_all_sessions_for_user, since neither touches this table.
    Called from server.py's recovery_reset, right alongside
    revoke_all_sessions_for_user, to close that gap: the same "credentials
    may now be known to someone else" threat model recovery_reset already
    defends sessions against now covers tokens too.
    """
    cursor = conn.execute("DELETE FROM api_tokens")
    conn.commit()
    return cursor.rowcount


def validate_api_token(conn: sqlite3.Connection, plaintext: str) -> dict | None:
    """
    Returns {"id", "label", "is_read_only"} on success, else None.
    Same iterate-and-verify-each-row scan as auth.validate_session --
    tokens are hashed, so there's no indexed lookup. Fine at this
    appliance's scale (a handful of tokens, ever); see rate_limit.py's
    is_rate_limited, which middleware.py checks BEFORE calling this, to
    cap the cost of a flood of guesses rather than relying on this scan
    being cheap on its own.
    """
    if not plaintext:
        return None
    rows = conn.execute("SELECT id, label, token_hash, is_read_only FROM api_tokens").fetchall()
    for row in rows:
        if verify_password(plaintext, row["token_hash"]):
            conn.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), row["id"]),
            )
            conn.commit()
            return {"id": row["id"], "label": row["label"], "is_read_only": bool(row["is_read_only"])}
    return None
