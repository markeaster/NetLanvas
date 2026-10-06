"""
recovery.py

Writes and reads the one-time credential-recovery file -- the "I
forgot my username/password" equivalent of welcome.py's first-run
setup token, for after setup has already completed.

The PLAINTEXT recovery token exists ONLY in this file. The database
only ever stores its argon2 hash (see security/auth.py's
store_recovery_token). This file is deleted the moment a reset
completes (see api/server.py's /api/recovery/reset route) or a fresh
request overwrites it -- there is no way to recover a stale plaintext
token once either happens, by design.
"""

import os
import re
from pathlib import Path

# Same directory as welcome.py's WELCOME_PATH -- already the
# established "mutable data a host-access owner can read" location on
# every platform (see packaging/windows/netlanvas-service.xml and
# packaging/macos/com.netlanvas.daemon.plist's NETLANVAS_TLS_DIR).
RECOVERY_DIR = Path(os.environ.get("NETLANVAS_TLS_DIR", "/app/tls"))
RECOVERY_PATH = RECOVERY_DIR / "recovery.txt"


def write_recovery_file(token: str, url: str) -> None:
    RECOVERY_DIR.mkdir(parents=True, exist_ok=True)
    content = (
        "=" * 70 + "\n"
        " NETLANVAS -- CREDENTIAL RECOVERY\n"
        + "=" * 70 + "\n\n"
        " A credential reset was requested for this NetLanvas install.\n"
        " If this wasn't you, ignore this file -- it expires the moment a\n"
        " new one is requested, and does nothing on its own without also\n"
        " submitting it through the recovery form below.\n\n"
        " 1. Browse to:\n"
        f"      {url}\n\n"
        " 2. Enter this one-time recovery token, along with a new\n"
        "    username and password:\n"
        f"      {token}\n\n"
        f" (This file lives at: {RECOVERY_PATH})\n\n"
        + "=" * 70 + "\n"
    )
    RECOVERY_PATH.write_text(content)
    RECOVERY_PATH.chmod(0o600)


def print_recovery_file() -> None:
    """
    welcome.py's print_welcome_file() exists so a fresh setup only needs
    `docker logs` to get everything needed -- this is the same thing for
    a recovery request, since otherwise the only hint a container-mode
    admin has that recovery.txt even exists (let alone where) is this
    stdout dump. api/server.py calls this right after write_recovery_file()
    on every /api/recovery/request. Native mode doesn't need it (no
    attached console either way -- see NATIVE-9 in welcome.py -- and the
    recovery page fetches the token directly there), but it's harmless
    to call unconditionally since this is a no-op without a console
    consuming container logs.
    """
    if RECOVERY_PATH.exists():
        # flush=True: stdout inside a container is block-buffered, not
        # line-buffered (see print_welcome_file()'s identical comment).
        # BEGIN/END sentinel distinct from NETLANVAS-SETUP-CARD so a
        # grep for one never risks matching the other.
        print("##### NETLANVAS-RECOVERY-CARD-BEGIN #####", flush=True)
        print(RECOVERY_PATH.read_text(), flush=True)
        print("##### NETLANVAS-RECOVERY-CARD-END #####", flush=True)


def delete_recovery_file() -> None:
    if RECOVERY_PATH.exists():
        RECOVERY_PATH.unlink()


_TOKEN_LINE_RE = re.compile(r"recovery token, along with a new\s*\n\s*username and password:\s*\n\s*(\S+)")


def get_recovery_token() -> str | None:
    """
    Mirrors welcome.py's get_setup_token() -- only meaningful (and only
    ever called) under NETLANVAS_MODE=native, for the exact same reason:
    native mode binds 127.0.0.1 exclusively by construction, so reaching
    this endpoint at all already means you're a process on this same
    machine, the same trust level as reading recovery.txt off disk
    directly. Never wire this into the container path, where the
    equivalent route can be LAN-reachable via Caddy.
    """
    if not RECOVERY_PATH.exists():
        return None
    match = _TOKEN_LINE_RE.search(RECOVERY_PATH.read_text())
    return match.group(1) if match else None
