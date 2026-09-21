#!/usr/bin/env python3
"""
readiness_check.py

Standalone diagnostic tool -- NOT part of the main NetLanvas application.
Validates whether the mechanisms a Windows/macOS port would actually
depend on (see PUNCH_LIST v10, WIN-1 through WIN-5) really work, BEFORE
any time is spent refactoring the real poller code to use them.

This container never touches network.db/config.db and never runs any
real NetLanvas code -- it only proves or disproves the underlying
plumbing: can this container reach back out to its own host via SSH
(host.docker.internal), authenticate, and run a real command that shows
the REAL physical LAN rather than Docker Desktop's own isolated VM
network -- and are the native tools NetLanvas would need present on
that host.

Meant to be run by hand, once, whenever someone wants to check readiness
-- not a long-running service. Same "run it, read the report, fix what
it flags, run it again" shape as tools like `brew doctor`/`flutter
doctor`, deliberately not an interactive prompt loop (simpler, more
robust than managing stdin/tty inside a container across two very
different host shells).

Written and unit-tested (the local-mechanism parts) on the Linux dev
machine this shipped from -- there is no Windows or Mac box in that
environment, so the actual cross-platform SSH-to-host behavior this
exists to validate has NOT been verified end-to-end here. That
verification is the whole point of handing this to Mark (Windows) and
Chris (Mac) to run for real.
"""

import asyncio
import logging
import os
import platform
import re
import socket
import sys

logging.basicConfig(
    level=logging.DEBUG if os.getenv("READINESS_VERBOSE") else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("readiness")

# asyncssh's own logger is extremely chatty at INFO (every channel open/
# close, every command dispatched) -- confirmed live, it drowns out the
# actual stage-by-stage report below. Quiet unless verbose was asked for.
if not os.getenv("READINESS_VERBOSE"):
    logging.getLogger("asyncssh").setLevel(logging.WARNING)

SSH_HOST = os.getenv("READINESS_SSH_HOST", "host.docker.internal")
# `or`, not a plain default arg -- docker-compose's `${VAR:-}` syntax
# resolves an unset host variable to an EMPTY STRING inside the
# container, not "omit the variable entirely" (confirmed live: crashed
# on int("") because os.getenv only falls back on a genuinely absent
# key, not a present-but-empty one). `or` treats both the same.
SSH_PORT = int(os.getenv("READINESS_SSH_PORT") or "22")
SSH_USER = os.getenv("READINESS_SSH_USER", "")
SSH_KEY_PATH = os.getenv("READINESS_SSH_KEY_PATH", "/run/readiness/id_ed25519")

# Colors only when actually attached to a real terminal -- otherwise the
# raw escape codes just show up as garbled noise (confirmed live: `docker
# compose run` without a TTY, or output redirected to a log file, prints
# literal "[33mWARN[0m" rather than either color or clean text).
_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


PASS = _c("32", "PASS")
FAIL = _c("31", "FAIL")
WARN = _c("33", "WARN")
INFO = _c("36", "INFO")


def _print_header(title: str) -> None:
    print(f"\n{'=' * 70}\n {title}\n{'=' * 70}")


def _print_result(status: str, label: str, detail: str = "") -> None:
    print(f"  [{status}] {label}" + (f" -- {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Stage 1: platform detection
#
# The container itself can NEVER correctly answer "what OS is the real
# host?" -- Docker Desktop runs real Linux containers inside a Linux VM
# even on Windows/Mac, so platform.system() in here always says "Linux"
# regardless of the physical machine underneath. That's not a bug to
# work around, it's why this whole architecture routes native commands
# out to the host via SSH instead of trying to run them locally. This
# stage exists to make that fact visible, not to defeat it.
# ---------------------------------------------------------------------------

def check_container_platform() -> None:
    _print_header("Stage 1: Platform Detection")
    print(f"  Container's own platform.system(): {platform.system()}")
    print(
        "  This will ALWAYS say Linux, on Windows and Mac too -- Docker Desktop\n"
        "  runs real Linux containers inside a VM. This is not what tells us\n"
        "  what the real host is; see the explicit/inferred checks below."
    )

    explicit = os.getenv("NETLANVAS_HOST_OS")
    if explicit:
        _print_result(INFO, "NETLANVAS_HOST_OS explicitly set", explicit)
    else:
        _print_result(
            WARN,
            "NETLANVAS_HOST_OS not set",
            "no install-script-provided platform hint -- falling back to inference below",
        )

    try:
        socket.gethostbyname("host.docker.internal")
        _print_result(
            PASS,
            "host.docker.internal resolves",
            "characteristic of Docker Desktop (Windows/Mac) -- native Linux Docker Engine usually does not resolve this without extra_hosts config",
        )
        inferred_desktop = True
    except socket.gaierror:
        _print_result(
            INFO,
            "host.docker.internal does not resolve",
            "consistent with native Linux Docker Engine, or Docker Desktop with an older version that needs extra_hosts configured",
        )
        inferred_desktop = False

    if explicit:
        print(f"\n  Verdict: {explicit} (explicit)")
    elif inferred_desktop:
        print("\n  Verdict: likely Windows or Mac via Docker Desktop (inferred, low confidence -- see Stage 3 for a real remote probe)")
    else:
        print("\n  Verdict: likely native Linux Docker Engine (inferred, low confidence)")


# ---------------------------------------------------------------------------
# Stage 2: native tool availability, LOCAL (this container)
#
# Sanity check only -- confirms this diagnostic image itself has the
# tools it needs to run its own checks. Not a proxy for whether the
# REAL host has them; that's Stage 4, over SSH.
# ---------------------------------------------------------------------------

async def _run(cmd: list) -> tuple:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except FileNotFoundError:
        return None, "", "command not found"
    except asyncio.TimeoutError:
        return None, "", "timed out"


async def check_local_tools() -> None:
    _print_header("Stage 2: This Container's Own Tooling (sanity check)")
    for tool in ("ssh", "python3"):
        rc, _, _ = await _run(["which", tool])
        _print_result(PASS if rc == 0 else FAIL, f"'{tool}' present in this image")


# ---------------------------------------------------------------------------
# Stage 3: SSH connectivity to the real host
# ---------------------------------------------------------------------------

async def check_ssh_reachability():
    """
    Returns a live, open asyncssh connection on success (which the caller
    is responsible for closing), or None on any failure. Stage 4 reuses
    this same connection rather than reconnecting -- opening two separate
    SSH sessions for one diagnostic run was wasteful and, worse, doubled
    the chance of a transient failure being blamed on the wrong stage.
    """
    _print_header("Stage 3: SSH Reachability to the Host")
    print(f"  Target: {SSH_USER or '<no user configured>'}@{SSH_HOST}:{SSH_PORT}")

    try:
        fut = asyncio.open_connection(SSH_HOST, SSH_PORT)
        reader, writer = await asyncio.wait_for(fut, timeout=5)
        banner = await asyncio.wait_for(reader.readline(), timeout=5)
        writer.close()
        banner_text = banner.decode(errors="replace").strip()
        _print_result(PASS, f"TCP connect to {SSH_HOST}:{SSH_PORT}", f"banner: {banner_text or '(none)'}")
        if "windows" in banner_text.lower():
            print("  Remote banner suggests Windows OpenSSH Server.")
        elif banner_text:
            print("  Remote banner suggests a Unix-like SSH server (OpenSSH on Mac/Linux typically looks like this too).")
    except (OSError, asyncio.TimeoutError) as e:
        _print_result(
            FAIL,
            f"TCP connect to {SSH_HOST}:{SSH_PORT}",
            f"{e} -- is the host's SSH server enabled? (Mac: System Settings > Sharing > Remote Login. "
            "Windows: Settings > Optional Features > OpenSSH Server, then Start-Service sshd)",
        )
        return None

    if not SSH_USER or not os.path.exists(SSH_KEY_PATH):
        _print_result(
            WARN,
            "Skipping authenticated SSH test",
            f"READINESS_SSH_USER and/or a key at {SSH_KEY_PATH} not provided -- see README for how to supply them",
        )
        return None

    try:
        import asyncssh
    except ImportError:
        _print_result(FAIL, "asyncssh not installed in this image", "this is a packaging bug, not a host problem")
        return None

    try:
        conn = await asyncssh.connect(
            SSH_HOST, port=SSH_PORT, username=SSH_USER,
            client_keys=[SSH_KEY_PATH], known_hosts=None, connect_timeout=8,
        )
        _print_result(PASS, "SSH authentication succeeded")
        return conn
    except Exception as e:
        _print_result(FAIL, "SSH authentication failed", str(e))
        return None


# ---------------------------------------------------------------------------
# Stage 4: real remote command execution -- the actual point of all this.
# Proves (or disproves) that a command run via this SSH connection sees
# the REAL physical LAN, not Docker Desktop's own isolated VM network.
# ---------------------------------------------------------------------------

REMOTE_PROBES_UNIX = {
    "remote OS identity": ["uname", "-a"],
    "default gateway (macOS/BSD style)": ["route", "-n", "get", "default"],
    "default gateway (Linux style, fallback)": ["ip", "route", "show", "default"],
    "ARP/neighbor table": ["arp", "-a"],
    "fping present?": ["which", "fping"],
    "nmap present?": ["which", "nmap"],
    "snmpget present?": ["which", "snmpget"],
    "snmpwalk present?": ["which", "snmpwalk"],
}

REMOTE_PROBES_WINDOWS = {
    "remote OS identity": ["cmd.exe", "/c", "ver"],
    "default gateway": ["cmd.exe", "/c", "route", "print", "0.0.0.0"],
    "ARP/neighbor table": ["cmd.exe", "/c", "arp", "-a"],
    "fping present?": ["where", "fping"],
    "nmap present?": ["where", "nmap"],
    "snmpget present?": ["where", "snmpget"],
}


_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _extract_gateway_ip(family: str, line: str) -> str | None:
    """
    Best-effort pull of the actual gateway address out of whichever
    preview line check_remote_execution already picked for the gateway
    probe. Positional and a little fragile by nature (a human is meant
    to eyeball Stage 4's raw output too) but good enough to drive Stage
    6's subnet derivation without asking the user to type their own
    subnet in.
    """
    ips = _IP_RE.findall(line)
    if not ips:
        return None
    if family == "windows":
        # Windows `route print` data row: Destination Netmask Gateway
        # Interface Metric -- gateway is the 3rd IP-shaped column.
        return ips[2] if len(ips) >= 3 else None
    # macOS `route -n get default`'s "gateway: x.x.x.x" line has exactly
    # one IP on it.
    return ips[0]


async def check_remote_execution(conn):
    """
    Returns (family, gateway_ip, tools) where family is "unix"/"windows"
    (or None if Stage 3 already failed), gateway_ip is a best-effort
    parse of the real default gateway (or None if it couldn't be
    determined), and tools is a dict of which optional CLI tools were
    found present on the host -- both feed Stages 6/7/8 below.
    """
    _print_header("Stage 4: Real Command Execution on the Host")

    if conn is None:
        _print_result(WARN, "Skipped", "no authenticated SSH connection available from Stage 3")
        return None, None, {}

    # Try the Unix-style probe set first; a clean failure on the very
    # first command (remote OS identity) is itself a signal this is
    # actually a Windows host, so fall back automatically rather than
    # requiring the caller to already know.
    probes = REMOTE_PROBES_UNIX
    family = "unix"
    result = await conn.run(" ".join(probes["remote OS identity"]), check=False)
    if result.exit_status != 0:
        print("  Unix-style probe failed -- retrying with Windows-style commands.")
        probes = REMOTE_PROBES_WINDOWS
        family = "windows"

    gateway_ip = None
    tools = {}
    for label, cmd in probes.items():
        result = await conn.run(" ".join(cmd), check=False)
        ok = result.exit_status == 0
        output = (result.stdout or result.stderr or "").strip().splitlines()
        # For gateway probes specifically, the interesting value usually
        # isn't line 0 -- macOS's `route -n get default` puts it on its own
        # "gateway: x.x.x.x" line several lines down, and Windows' `route
        # print` puts it in a table row, not the header. Confirmed live:
        # the naive output[0] silently showed "route to: default" instead
        # of the actual address on a real Mac run. Search for a line that
        # looks like it, fall back to line 0 for every other probe.
        preview = output[0] if output else "(no output)"
        if output and label.startswith("default gateway"):
            # Two passes, not one: Windows' `route print` header row itself
            # contains the word "gateway" (column heading) and appears
            # BEFORE the real data row, so a single "gateway" search would
            # wrongly stop on the header. The real Windows data row has
            # "0.0.0.0" (the destination column) but not the word
            # "gateway"; macOS's `route -n get default` has the opposite
            # shape ("gateway: x.x.x.x", no "0.0.0.0" anywhere) -- so try
            # the Windows shape first, then the macOS shape.
            for line in output:
                if "0.0.0.0" in line:
                    preview = line.strip()
                    break
            else:
                for line in output:
                    if "gateway" in line.lower():
                        preview = line.strip()
                        break
            if ok:
                gateway_ip = _extract_gateway_ip(family, preview)
        if label.endswith("present?"):
            tool_name = label.split()[0]
            tools[tool_name] = ok
        _print_result(PASS if ok else FAIL, label, preview[:100])
        if ok and label.startswith("default gateway") and output:
            print(
                "    ^ If this looks like a real LAN address (e.g. 192.168.x.1 or "
                "10.x.x.1 matching your actual router), the mechanism works. If it "
                "looks like a Docker-internal address, something is still routing "
                "through the VM rather than the real host."
            )

    return family, gateway_ip, tools


# ---------------------------------------------------------------------------
# Stage 5: what source address did this SSH connection actually arrive
# from, and which local interface accepted it?
#
# Directly relevant to how tightly sshd can be scoped on each platform.
# Rather than guess a CIDR to lock the host's firewall/sshd to, this
# reads SSH_CONNECTION on the host itself (set by sshd for every session,
# format "client_ip client_port server_ip server_port") so the actual
# answer is observed, not assumed:
#   - client_ip == 127.0.0.1 usually means Docker Desktop proxied this
#     connection through loopback (confirmed common on Mac, via vpnkit)
#     -- if so, binding sshd to ListenAddress 127.0.0.1 would still work
#     for this mechanism and removes LAN exposure entirely.
#   - client_ip is some other private address (e.g. a 172.x Docker/WSL2
#     virtual subnet) -- loopback-only would break this, and a firewall
#     rule would need to allow that specific range instead.
# ---------------------------------------------------------------------------

async def check_ssh_connection_info(conn, family):
    """Returns the client_ip string (or None if unavailable/skipped)."""
    _print_header("Stage 5: SSH Connection Source (for firewall scoping)")

    if conn is None:
        _print_result(WARN, "Skipped", "no authenticated SSH connection available from Stage 3")
        return None

    if family == "windows":
        cmd = "cmd.exe /c echo %SSH_CONNECTION%"
    else:
        cmd = "echo $SSH_CONNECTION"

    result = await conn.run(cmd, check=False)
    raw = (result.stdout or "").strip()

    if not raw or raw == "%SSH_CONNECTION%":
        _print_result(WARN, "SSH_CONNECTION not available", "host's sshd didn't expose it -- can't infer source scope automatically")
        return None

    parts = raw.split()
    if len(parts) != 4:
        _print_result(WARN, "Unexpected SSH_CONNECTION format", raw[:100])
        return None

    client_ip, client_port, server_ip, server_port = parts
    _print_result(INFO, "Client (this container) appeared to the host as", f"{client_ip}:{client_port}")
    _print_result(INFO, "Host accepted the connection on", f"{server_ip}:{server_port}")

    if client_ip in ("127.0.0.1", "::1"):
        print(
            "    ^ Arrived via loopback. IMPORTANT, confirmed live on Windows: this does NOT\n"
            "      mean binding sshd's own ListenAddress to 127.0.0.1 is safe -- that broke the\n"
            "      mechanism on real Windows hardware despite this exact finding, because Docker\n"
            "      Desktop's internal proxy apparently doesn't arrive via the literal loopback\n"
            "      *interface* at the socket-bind level, even though the packet's *source\n"
            "      address* genuinely is 127.0.0.1 by the time sshd sees it. Filtering by source\n"
            "      address at the firewall layer (Stage 10 on Windows) is the tested-safe\n"
            "      approach instead -- see Stage 10 below."
        )
    else:
        print(
            f"    ^ Arrived from a real (non-loopback) address, {client_ip}. A loopback-only\n"
            "      restriction of any kind would break this mechanism on this platform."
        )
    return client_ip


# ---------------------------------------------------------------------------
# Stage 6: subnet-wide reachability sweep.
#
# Everything up to here proves the SSH-to-host mechanism works. This is
# the first stage that exercises what the real poller actually needs to
# DO with it: sweep an entire subnet without knowing in advance what's
# on it -- deliberately agnostic, not a single hardcoded target. The
# subnet is derived from Stage 4's own gateway finding (assumes a /24,
# the common case; override with READINESS_SUBNET_CIDR_SUFFIX if your
# LAN isn't one) rather than asking the user to type it in.
# ---------------------------------------------------------------------------

SUBNET_CIDR_SUFFIX = os.getenv("READINESS_SUBNET_CIDR_SUFFIX") or "24"
_NMAP_HOST_RE = re.compile(r"Nmap scan report for (?:\S+ \()?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)?")


async def check_subnet_sweep(conn, family, gateway_ip, tools) -> list:
    """Returns a list of IPs that answered -- empty list on any skip/failure."""
    _print_header("Stage 6: Subnet-Wide Reachability Sweep")

    if conn is None:
        _print_result(WARN, "Skipped", "no authenticated SSH connection available from Stage 3")
        return []
    if not gateway_ip:
        _print_result(WARN, "Skipped", "couldn't determine a gateway IP from Stage 4 to derive the subnet from")
        return []

    subnet_base = ".".join(gateway_ip.split(".")[:3])
    cidr = f"{subnet_base}.0/{SUBNET_CIDR_SUFFIX}"
    print(f"  Sweeping {cidr} (derived from gateway {gateway_ip} -- assumes a /24; override with")
    print("  READINESS_SUBNET_CIDR_SUFFIX if your LAN uses a different size)")

    use_fping = tools.get("fping")
    use_nmap = not use_fping and tools.get("nmap")
    if not use_fping and not use_nmap:
        _print_result(
            WARN, "Skipped",
            "neither fping nor nmap present on the host (see Stage 4 and WIN-4 in the punch list -- "
            "the real install script needs to bootstrap these via winget/Homebrew)",
        )
        return []

    cmd = f"fping -a -g {cidr} -r 1 -t 200" if use_fping else f"nmap -sn {cidr} -T4"
    try:
        result = await conn.run(cmd, check=False, timeout=90)
    except asyncio.TimeoutError:
        _print_result(FAIL, f"Sweep via {'fping' if use_fping else 'nmap'} timed out", "90s -- unusually slow network, or the CIDR guess is wrong")
        return []

    output = (result.stdout or "").strip()
    if use_fping:
        alive = [l.strip() for l in output.splitlines() if _IP_RE.fullmatch(l.strip())]
    else:
        alive = _NMAP_HOST_RE.findall(output)

    _print_result(
        PASS if alive else WARN, f"Swept {cidr} via {'fping' if use_fping else 'nmap'}",
        f"{len(alive)} host(s) replied",
    )
    if alive:
        preview = ", ".join(alive[:10]) + (f", +{len(alive) - 10} more" if len(alive) > 10 else "")
        print(f"    {preview}")
        print(
            "    ^ This is what a production scan cycle would actually be discovering on a"
            " real LAN, sight unseen -- eyeball that the count/addresses look plausible for"
            " your network, not suspiciously empty or suspiciously huge."
        )
    return alive


# ---------------------------------------------------------------------------
# Stage 7: SNMP reachability probe against whatever Stage 6 found alive.
#
# Exercises the actual SNMP path end-to-end -- not just "is snmpget
# present" (Stage 4 already checked that), but "does a real device on
# this LAN answer through the relay, and does the reply parse." Capped
# to a small sample so this stays lightweight regardless of how large
# the subnet turns out to be; uses the numeric sysDescr OID (no MIB
# name resolution needed) and the 'public' community, matching what
# NetLanvas's own default-community detector already tries.
# ---------------------------------------------------------------------------

SNMP_PROBE_LIMIT = int(os.getenv("READINESS_SNMP_PROBE_LIMIT") or "15")


async def check_snmp_probe(conn, alive_hosts, tools) -> None:
    _print_header("Stage 7: SNMP Reachability Probe")

    if conn is None:
        _print_result(WARN, "Skipped", "no authenticated SSH connection available from Stage 3")
        return
    if not tools.get("snmpget"):
        _print_result(WARN, "Skipped", "snmpget not present on the host (see Stage 4 and WIN-4)")
        return
    if not alive_hosts:
        _print_result(WARN, "Skipped", "no hosts from Stage 6 to probe (subnet sweep found nothing or was skipped)")
        return

    sample = alive_hosts[:SNMP_PROBE_LIMIT]
    print(f"  Probing {len(sample)} of {len(alive_hosts)} discovered host(s) (capped via READINESS_SNMP_PROBE_LIMIT, default 15)")

    replied = 0
    for host in sample:
        result = await conn.run(f"snmpget -v2c -c public -t 1 -r 0 {host} 1.3.6.1.2.1.1.1.0", check=False)
        if result.exit_status == 0 and result.stdout and "No Such" not in result.stdout:
            replied += 1
            sysdescr = result.stdout.strip().split("=", 1)[-1].strip()[:80]
            _print_result(PASS, f"{host} answered SNMP (public)", sysdescr)

    if replied:
        print(
            f"\n    {replied}/{len(sample)} sampled host(s) answered plain 'public' -- these are"
            " real findings the eventual FIND-3 detector would flag, not test noise."
        )
    else:
        _print_result(INFO, f"0/{len(sample)} sampled host(s) answered SNMP on 'public'", "expected on most networks -- not a failure of this tool")


# ---------------------------------------------------------------------------
# Stage 8: nmap smoke test -- only runs if Stage 6 used fping instead of
# nmap for the sweep (so nmap itself hasn't actually been exercised
# yet). A single fast scan of just the gateway, not a full subnet port
# scan -- proves nmap invocation + output parsing works without adding
# real runtime.
# ---------------------------------------------------------------------------

async def check_nmap_smoketest(conn, gateway_ip, tools, sweep_used_nmap: bool) -> None:
    _print_header("Stage 8: nmap Smoke Test")

    if conn is None:
        _print_result(WARN, "Skipped", "no authenticated SSH connection available from Stage 3")
        return
    if sweep_used_nmap:
        _print_result(INFO, "Skipped", "nmap was already exercised directly by Stage 6's sweep")
        return
    if not tools.get("nmap"):
        _print_result(WARN, "Skipped", "nmap not present on the host (see Stage 4 and WIN-4)")
        return
    if not gateway_ip:
        _print_result(WARN, "Skipped", "no gateway IP from Stage 4 to scan")
        return

    result = await conn.run(f"nmap -F {gateway_ip}", check=False, timeout=30)
    ok = result.exit_status == 0 and "Nmap scan report" in (result.stdout or "")
    open_ports = len(re.findall(r"^\d+/tcp\s+open", result.stdout or "", re.MULTILINE))
    _print_result(PASS if ok else FAIL, f"nmap -F {gateway_ip}", f"{open_ports} open port(s) found" if ok else "scan didn't complete as expected")


# ---------------------------------------------------------------------------
# Stage 9: bundled SNMP helper -- proof of concept for WIN-9 in the punch
# list (Windows has no clean, trustworthy install path for snmpget/
# snmpwalk; confirmed via research, not assumed). Rather than ask the
# user to install anything, this pushes a small pre-built Go binary
# (netlanvas_snmp_helper, thin wrapper around gosnmp, cross-compiled
# into this image at build time -- see the Dockerfile) to the host over
# the SAME SSH connection via SFTP, runs it there, and cleans up after.
#
# Currently Windows-only, deliberately: Mac already has a clean answer
# (Homebrew's net-snmp, see Step 2), so this only needs to prove itself
# where the real gap is. Functionally verified locally against a real
# router before ever being tested against a user's machine -- see the
# v14/v15 punch list changelog.
# ---------------------------------------------------------------------------

SNMP_HELPER_LOCAL_PATH = "/app/bin/netlanvas_snmp_helper.exe"
SNMP_HELPER_REMOTE_PATH = r"C:\Windows\Temp\netlanvas_snmp_helper.exe"


async def check_bundled_snmp_helper(conn, family, alive_hosts, tools) -> None:
    _print_header("Stage 9: Bundled SNMP Helper (WIN-9 proof of concept)")

    if conn is None:
        _print_result(WARN, "Skipped", "no authenticated SSH connection available from Stage 3")
        return
    if family != "windows":
        _print_result(INFO, "Skipped", "this proof of concept currently only targets the confirmed Windows gap (WIN-9) -- Mac already has a clean path via Homebrew")
        return
    if tools.get("snmpget"):
        _print_result(INFO, "Skipped", "snmpget is already present on the host -- no need for the bundled helper")
        return
    if not alive_hosts:
        _print_result(WARN, "Skipped", "no hosts from Stage 6 to test against")
        return
    if not os.path.exists(SNMP_HELPER_LOCAL_PATH):
        _print_result(FAIL, "Bundled helper binary missing from this image", "packaging bug, not a host problem")
        return

    try:
        async with conn.start_sftp_client() as sftp:
            await sftp.put(SNMP_HELPER_LOCAL_PATH, SNMP_HELPER_REMOTE_PATH)
        _print_result(PASS, "Pushed bundled SNMP helper to host via SFTP", SNMP_HELPER_REMOTE_PATH)
    except Exception as e:
        _print_result(FAIL, "SFTP push failed", str(e))
        return

    try:
        target = alive_hosts[0]
        result = await conn.run(
            f'"{SNMP_HELPER_REMOTE_PATH}" {target} public 1.3.6.1.2.1.1.1.0', check=False, timeout=10,
        )
        output = (result.stdout or result.stderr or "").strip()
        ok = result.exit_status == 0 and output.startswith("OK:")
        _print_result(
            PASS if ok else INFO, f"Bundled helper SNMP GET against {target}",
            output[:150] or "(no output)",
        )
        if ok:
            print(
                "    ^ Real SNMP reply, pulled via a binary that was never installed on this machine --\n"
                "      it was pushed over the same SSH connection and run directly. This is the proposed\n"
                "      real fix for WIN-9, not just a theory."
            )
        elif "GET_ERROR: request timeout" in output:
            print("    ^ Not a mechanism failure -- this host just didn't answer SNMP on 'public', same as Stage 7 would report.")
    finally:
        cleanup = await conn.run(f'cmd.exe /c del "{SNMP_HELPER_REMOTE_PATH}"', check=False)
        _print_result(
            PASS if cleanup.exit_status == 0 else WARN,
            "Removed the pushed binary from the host",
        )


# ---------------------------------------------------------------------------
# Stage 10: SSH exposure lock-down, applied and tested for real -- not left
# as an untested suggestion. Windows-only: Windows Firewall's rule model is
# safe to automate (additive, scoped, cleanly reversible with one command).
# macOS's equivalent (pf) is a shared, global packet-filter config other
# tools/apps can already be managing -- automating an unattended rewrite of
# it here risks clobbering something already in place, so that stays a
# manual, backed-up step on the page/README instead.
#
# Confirmed live and corrected the hard way: an earlier version of this
# tool suggested sshd's own ListenAddress 127.0.0.1 as "likely safe" based
# on Stage 5 showing a loopback source -- that broke real SSH access on
# Windows, because Docker Desktop's internal proxy doesn't arrive via the
# literal loopback *interface* at the socket-bind level, even though the
# packet's *source address* genuinely is 127.0.0.1 by the time sshd sees
# it. Filtering by source address at the firewall layer, instead of
# restricting which interface sshd binds to, is the fix that respects that
# distinction.
#
# Safety design: applies the restriction over the ALREADY-OPEN connection
# from Stage 3 (which stays alive -- firewall rule changes don't drop
# already-established connections, only affect new ones), then opens a
# genuinely NEW connection to test whether the restriction blocks fresh SSH
# sessions. If it does, rolls back automatically using the still-open
# original connection -- never depends on the connection that might be
# broken to fix itself. Opt-in only (READINESS_APPLY_LOCKDOWN=1) since this
# is the one stage that changes real security configuration on the host,
# not just reads from it.
# ---------------------------------------------------------------------------

# Deliberately two simple sequential commands, controlled from here in
# Python, rather than one line with nested braces/quotes going through two
# shell layers (Windows OpenSSH's default cmd.exe wrapper, then
# powershell.exe's own tokenizer) -- that kind of thing is exactly what
# silently misbehaves in ways that are hard to notice without a real
# Windows box to test on, which is the same trap the ListenAddress mistake
# fell into. Each step here is simple enough to eyeball.
FIREWALL_RULE_EXISTS_CMD_WINDOWS = 'powershell -Command "[bool](Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)"'
FIREWALL_SET_CMD_WINDOWS = 'powershell -Command "Set-NetFirewallRule -Name sshd -RemoteAddress 127.0.0.1"'
FIREWALL_NEW_CMD_WINDOWS = (
    "netsh advfirewall firewall add rule name=sshd dir=in action=allow protocol=TCP "
    "localport=22 remoteip=127.0.0.1"
)
FIREWALL_ROLLBACK_CMD_WINDOWS = 'powershell -Command "Set-NetFirewallRule -Name sshd -RemoteAddress Any"'


async def check_sshd_lockdown(conn, family, client_ip) -> None:
    _print_header("Stage 10: SSH Exposure Lock-Down (tested, self-rolling-back)")

    if not os.getenv("READINESS_APPLY_LOCKDOWN"):
        _print_result(
            INFO, "Skipped",
            "opt-in only -- set READINESS_APPLY_LOCKDOWN=1 to have this stage apply and test a real firewall restriction",
        )
        return
    if conn is None:
        _print_result(WARN, "Skipped", "no authenticated SSH connection available from Stage 3")
        return
    if family != "windows":
        _print_result(INFO, "Skipped", "Windows-only for now -- see README for the manual, backed-up macOS (pf) equivalent")
        return
    if client_ip not in ("127.0.0.1", "::1"):
        _print_result(WARN, "Skipped", "Stage 5 didn't show a loopback source -- this lock-down would break the mechanism, not protect it")
        return

    exists_result = await conn.run(FIREWALL_RULE_EXISTS_CMD_WINDOWS, check=False, timeout=10)
    rule_exists = (exists_result.stdout or "").strip().lower() == "true"

    if rule_exists:
        apply_result = await conn.run(FIREWALL_SET_CMD_WINDOWS, check=False, timeout=15)
    else:
        apply_result = await conn.run(FIREWALL_NEW_CMD_WINDOWS, check=False, timeout=15)
    if apply_result.exit_status != 0:
        _print_result(FAIL, "Failed to apply the firewall restriction", (apply_result.stderr or apply_result.stdout or "").strip()[:150])
        return
    _print_result(
        PASS, "Applied Windows Firewall restriction",
        f"{'scoped existing' if rule_exists else 'created new'} sshd rule, RemoteAddress 127.0.0.1",
    )

    # Deliberately a NEW connection, not the one just used to apply the
    # rule -- that one is already established, and firewall rule changes
    # don't retroactively drop existing connections, so testing on it
    # would prove nothing about whether NEW connections still work.
    test_conn = None
    try:
        import asyncssh
        test_conn = await asyncssh.connect(
            SSH_HOST, port=SSH_PORT, username=SSH_USER,
            client_keys=[SSH_KEY_PATH], known_hosts=None, connect_timeout=8,
        )
        await test_conn.run("echo ok", check=True, timeout=5)
        _print_result(PASS, "Fresh SSH connection succeeded with the restriction in place", "safe to leave applied")
    except Exception as e:
        _print_result(FAIL, "Fresh SSH connection failed with the restriction in place", str(e)[:150])
        print("    ^ Rolling back automatically via the original (still-open) connection...")
        rollback_result = await conn.run(FIREWALL_ROLLBACK_CMD_WINDOWS, check=False, timeout=15)
        _print_result(
            PASS if rollback_result.exit_status == 0 else FAIL,
            "Rollback",
            "restriction removed, back to normal" if rollback_result.exit_status == 0
            else "ROLLBACK FAILED -- fix manually: Set-NetFirewallRule -Name sshd -RemoteAddress Any",
        )
    finally:
        if test_conn is not None:
            test_conn.close()
            await test_conn.wait_closed()


async def main() -> None:
    print("NetLanvas Windows/Mac Platform Readiness Check")
    print("Read PUNCH_LIST v10+ (WIN-1 through WIN-5) for the design this validates.")
    print("Remember to turn SSH back off on this machine once you're done -- see Stage 5.\n")

    check_container_platform()
    await check_local_tools()
    conn = await check_ssh_reachability()
    ssh_ok = conn is not None
    alive_hosts = []
    try:
        family, gateway_ip, tools = await check_remote_execution(conn)
        client_ip = await check_ssh_connection_info(conn, family)
        alive_hosts = await check_subnet_sweep(conn, family, gateway_ip, tools)
        await check_snmp_probe(conn, alive_hosts, tools)
        await check_nmap_smoketest(conn, gateway_ip, tools, sweep_used_nmap=not tools.get("fping") and bool(tools.get("nmap")))
        await check_bundled_snmp_helper(conn, family, alive_hosts, tools)
        await check_sshd_lockdown(conn, family, client_ip)
    finally:
        if conn is not None:
            conn.close()
            await conn.wait_closed()

    _print_header("Summary")
    if ssh_ok:
        print("  SSH mechanism looks viable. Review Stage 4's output above by eye --")
        print("  this script can't judge for you whether the gateway/ARP output shown")
        print("  is really your physical LAN, only that commands executed and returned something.")
        print("  See Stage 5 above for whether sshd can safely be scoped to loopback-only.")
        print(f"  Stage 6 found {len(alive_hosts)} live host(s) on the subnet -- see Stages 6-8 for")
        print("  how the actual sweep/SNMP/nmap functions the real poller needs behaved.")
        print("  Once you're done: turn Remote Login (Mac) / OpenSSH Server (Windows) back off --")
        print("  it doesn't need to stay on between test runs.")
    else:
        print("  SSH mechanism not yet working -- see Stage 3 for what to fix, then re-run.")
        print("  (Same pattern as `brew doctor`/`flutter doctor`: fix what's flagged, run again.)")


if __name__ == "__main__":
    asyncio.run(main())
