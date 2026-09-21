"""
welcome.py

Writes and displays the first-run "welcome card" -- URL, TLS
fingerprint, and one-time setup token -- combined into a single file
so a fresh install only needs one glance (docker logs, or
`docker exec netlanvas_api cat /app/tls/welcome.txt` to re-view it
later) to get everything needed to complete setup.

The PLAINTEXT setup token exists ONLY in this file. The database only
ever stores its argon2 hash (see security/auth.py's store_setup_token).
This file is deleted the moment setup completes (see server.py's
/api/setup/password route) -- there is no way to recover the plaintext
token once that happens, by design.
"""

import os
import re
from pathlib import Path

# Same persisted volume as the TLS keypair -- both need to survive
# container restarts before setup completes, no new compose mount needed.
WELCOME_DIR = Path(os.environ.get("NETLANVAS_TLS_DIR", "/app/tls"))
WELCOME_PATH = WELCOME_DIR / "welcome.txt"


def write_welcome_file(fingerprint: str, token: str, url: str) -> None:
    WELCOME_DIR.mkdir(parents=True, exist_ok=True)
    content = (
        "=" * 70 + "\n"
        " NETLANVAS -- FIRST-RUN SETUP\n"
        + "=" * 70 + "\n\n"
        " 1. Browse to:\n"
        f"      {url}\n\n"
        " 2. Before accepting the browser's certificate warning, verify this\n"
        "    fingerprint matches what the browser shows:\n"
        f"      {fingerprint}\n\n"
        " 3. Enter this one-time setup token when creating the admin account:\n"
        f"      {token}\n\n"
        + "=" * 70 + "\n"
    )
    WELCOME_PATH.write_text(content)
    WELCOME_PATH.chmod(0o600)


def print_welcome_file() -> None:
    if WELCOME_PATH.exists():
        # flush=True is required: stdout inside a container is block-
        # buffered (not line-buffered, since it's not a real terminal),
        # so without this the output can sit unflushed indefinitely --
        # unlike logger.info() calls, which flush on every emit by
        # default via logging.StreamHandler.
        #
        # BEGIN/END sentinels wrap the STDOUT copy only (never written
        # into welcome.txt itself, which stays plain/human-readable for
        # `docker exec ... cat`). These exist so the public install
        # script can reliably locate this exact block in `docker compose
        # logs` output -- cert_manager.py's own fingerprint box uses the
        # same "====" border characters, so a naive grep would risk
        # matching the wrong one.
        print("##### NETLANVAS-SETUP-CARD-BEGIN #####", flush=True)
        print(WELCOME_PATH.read_text(), flush=True)
        print("##### NETLANVAS-SETUP-CARD-END #####", flush=True)


def delete_welcome_file() -> None:
    if WELCOME_PATH.exists():
        WELCOME_PATH.unlink()


_TOKEN_LINE_RE = re.compile(r"setup token when creating the admin account:\s*\n\s*(\S+)")


def get_setup_token() -> str | None:
    """
    NATIVE-9: `print_welcome_file()` above prints to stdout for
    `docker logs` visibility -- but a Windows/macOS Service has no
    attached console, so that stdout lands in a service log file
    (netlanvas-service.out.log on Windows) a fresh-install user has no
    reason to know exists, let alone go read. This lets the setup page
    itself fetch and display the plaintext token directly instead,
    closing that gap.

    Only meaningful (and only ever called) under NETLANVAS_MODE=native
    -- see api/server.py's /api/setup/status. Safe to expose over HTTP
    there specifically because native mode binds 127.0.0.1 exclusively
    by construction (see the localhost/remote-access design
    requirement); reaching this endpoint at all already means you're a
    process on this same machine, the same trust level as reading
    welcome.txt off disk directly. Never wire this into the container
    path -- there /api/setup/status can be LAN-reachable via Caddy,
    where returning the plaintext token over the network would be a
    real regression, not a convenience.
    """
    if not WELCOME_PATH.exists():
        return None
    match = _TOKEN_LINE_RE.search(WELCOME_PATH.read_text())
    return match.group(1) if match else None
