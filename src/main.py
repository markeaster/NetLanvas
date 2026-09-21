import asyncio
import logging
import sqlite3
import socket
import ipaddress
import json
import platform
import subprocess
import uvicorn
import os
import time
import threading
import urllib.request
import urllib.parse
import datetime
import shutil
import uuid
import requests
import redis.asyncio as aioredis
from contextlib import contextmanager
from engine.database import init_db, init_auth_db, init_registration_db, init_alerting_db, init_inventory_db
from engine.agnostic_filters import apply_db_hardening
from engine.auto_discovery import detect_default_gateway, discover_active_subnets, enumerate_host_network_interfaces
from pollers.ping_sweeper import run_ping_sweeper
from pollers.lldp_scraper import run_lldp_scraper
from pollers.mac_table_scraper import run_mac_table_scraper
from pollers.fingerprinter import run_fingerprinter, resolve_own_mac
from pollers.wifi_scraper import poll_wifi_clients
from pollers.os_fingerprinter import run_os_fingerprinter
from pollers.web_probe import run_web_probe
from pollers.hostname_discovery import run_hostname_discovery_sweep
from pollers.dhcp_sniffer import start_dhcp_sniffer
from pollers.vlan_registry import run_vlan_registry_scan
from pollers.device_state_tracker import run_device_state_tracker
from pollers.snmp_default_community_detector import run_snmp_default_community_detector, run_snmp_public_security_scan
from pollers.snmp_v3_available_detector import run_snmp_v3_available_detector
from engine.alert_dispatcher import dispatch_pending_alerts
from engine.alerting import prune_alerting_history
from engine.unification import run_unification_engine, run_verified_switch_consolidation_pass, run_inventory_overlay_pass, run_inventory_snapshot_sync
from engine.inference_engine import run_inference_cycle
from engine.smart_switch_pipeline import run_smart_switch_pipeline
from engine.config_loader import config
from engine.oui_manager import parse_and_import_oui, parse_and_import_extended_oui, parse_and_import_enterprise_numbers
from engine.snmp_pipeline import run_snmp_pipeline
from engine.snmp_adapter import get_working_credential, CREDENTIAL_CACHE, V3_CAPABLE_IPS, set_current_tick, check_due_v3_upgrades
from engine.polling_targets import get_representative_targets
from security.cert_manager import ensure_certificate, detect_own_lan_ip, CERT_PATH, KEY_PATH
from security.auth import credentials_exist, create_initial_user, generate_setup_token, store_setup_token
from security import device_identity
from security.welcome import write_welcome_file, print_welcome_file, WELCOME_PATH
from telemetry import log_sampler as telemetry_log_sampler
from telemetry import scheduler as telemetry_scheduler

# ==============================================================================
# 1. CORE SETUP & LOGGING
# ==============================================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("Netlanvas.Core")

runtime_context = {"detected_gateway": None, "discovered_subnets": []}

# NATIVE-1: "container" (default) is the existing Docker deployment --
# POLLER and API_VIEWER are separate OS processes, so redis_client has
# to be a real Redis connection, the only thing both processes can see.
# "native" merges the two roles into this one process (see the NATIVE
# branch in main() below), so the reason Redis exists at all goes away
# -- api/server.py imports the exact same engine.runtime_state.shared_state
# singleton object (Python caches the module, so both call sites get the
# same in-memory store within one process), no server to install or run.
NETLANVAS_MODE = os.getenv("NETLANVAS_MODE", "container").lower()

# CAPS-3 (2026-09-09): the discovery pipeline's SNMP concurrency
# (Semaphore(25) in fingerprinter.py, POLL-3) was tuned and verified
# live only against the Docker build, whose base image ships a
# generous default RLIMIT_NOFILE. Confirmed live on a real native
# macOS install that its default (`launchctl limit maxfiles` -> 256)
# is nowhere near enough: 25 concurrent SNMP subprocesses (each
# holding several fds for their own stdin/stdout/stderr pipes) plus
# the app's own sockets/SQLite connections blew straight through it,
# raising "[Errno 24] Too many open files" mid-fingerprint every
# single tick -- which the tick loop's own top-level exception
# handler quietly swallowed and retried, so the failure repeated
# forever instead of surfacing as a crash. The UI's tick-lock overlay
# just showed a climbing elapsed timer with no way to tell it was
# actually stuck, not slow. Raise the soft limit as high as the OS
# hard limit allows at boot -- harmless on Docker (already high,
# this just confirms/no-ops) and the actual fix on native macOS/Linux.
# Windows has no POSIX rlimit concept (its own handle limits work
# differently and weren't implicated here), so this is skipped there.
if platform.system() != "Windows":
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = hard if hard != resource.RLIM_INFINITY else 65536
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ValueError, OSError):
        # Some restricted environments refuse to raise this even
        # within the reported hard limit -- fall through rather than
        # crash the whole process over a defensive best-effort call.
        pass

if NETLANVAS_MODE == "native":
    from engine.runtime_state import shared_state as redis_client
else:
    REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    # The Redis password is generated once per install (redis_secrets_init
    # in docker-compose.yaml, the same generate-once-persist-to-a-file
    # pattern already used for the TLS cert and device identity key) and
    # written to the same ./config host mount this process already has
    # mounted, rather than a fixed literal shared across every install.
    #
    # Some deployments of this same code path never run a real Redis
    # service at all (a minimal API-only build with no queue behind it,
    # for instance) and never write this file. Redis absence there is
    # meant to be tolerated gracefully at the point of an actual get/set
    # call -- never at import time -- so a missing file falls back to a
    # random, never-persisted, this-process-only password instead of
    # crashing the process outright. Authentication to a real Redis will
    # still correctly fail (there's nothing on either side to match), but
    # a deployment with no Redis at all can still start.
    try:
        with open("/app/config/redis.key") as _f:
            REDIS_PASSWORD = _f.read().strip()
    except FileNotFoundError:
        import secrets as _secrets
        REDIS_PASSWORD = _secrets.token_hex(32)
        logging.getLogger("Netlanvas").warning(
            "[!] /app/config/redis.key not found -- generating an ephemeral, "
            "process-local Redis password instead. Expected on deployments "
            "with no real Redis service; if this appliance DOES have one, "
            "something is wrong with the mount."
        )
    redis_client = aioredis.from_url(f"redis://{REDIS_HOST}:{REDIS_PORT}", password=REDIS_PASSWORD, decode_responses=True, socket_timeout=2.0)

# ==============================================================================
# 1b. INITIAL-SCAN PROGRESS ESTIMATION (locked-UI modal, ticks 0 & 1)
# ==============================================================================
# Ticks 0 and 1 both run the exact same full stage pipeline (see the
# tick_counter <= 1 condition in background_polling_engine below), so
# tick 0's REAL measured per-stage durations are a much better ETA for
# tick 1 than any static guess -- same devices, same stage list. Seed
# values below are only a rough starting point used before a stage has
# ever completed on this boot; every stage overwrites its own entry the
# instant it finishes, so the estimate keeps self-correcting as the
# first tick progresses instead of staying static.
PROGRESS_STAGES = [
    ("gateway_discovery", "Detecting default gateway"),
    ("active_ping_sweeps", "Sweeping subnets for live hosts"),
    ("arp_scrape", "Reading router ARP caches"),
    ("mac_table_scraper", "Reading switch MAC/FDB tables"),
    ("wifi_scrape", "Polling wireless client associations"),
    ("os_profiler", "Fingerprinting operating systems"),
    ("oui_maintenance", "Updating vendor OUI database"),
    ("physical_lldp", "Crawling LLDP topology"),
    ("device_fingerprinting", "Profiling discovered devices"),
    ("unification_engine", "Unifying multi-interface nodes"),
    ("inference_engine", "Inferring network relationships"),
    ("vlan_registry", "Reading VLAN registry"),
    ("purge_router_noise", "Clearing stale router-local noise"),
]
DEFAULT_STAGE_SECONDS = {
    "gateway_discovery": 1, "active_ping_sweeps": 15, "arp_scrape": 3,
    "mac_table_scraper": 5, "wifi_scrape": 3, "os_profiler": 10,
    "oui_maintenance": 2, "physical_lldp": 30, "device_fingerprinting": 30,
    "unification_engine": 2, "inference_engine": 2, "vlan_registry": 5,
    "purge_router_noise": 2,
}
_stage_durations = {}
_discovery_start_mono = None
_max_progress_percent = 0.0

def _current_endpoint_count():
    try:
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(DISTINCT ip_address) FROM l3_bindings")
        n = cursor.fetchone()[0]
        conn.close()
        return n
    except Exception:
        return None

async def _publish_progress(tick, stage_index, stage_key, stage_label):
    global _max_progress_percent
    per_tick_estimate = sum(_stage_durations.get(k, DEFAULT_STAGE_SECONDS[k]) for k, _ in PROGRESS_STAGES)
    total_estimate = max(per_tick_estimate * 2, 1)  # ticks 0 + 1
    elapsed = time.monotonic() - _discovery_start_mono if _discovery_start_mono else 0

    # Clamped to 99% (only the "Discovery complete" transition hits 100)
    # and never allowed to move backwards -- a slow stage finishing
    # partway through tick 0 can raise total_estimate enough that the
    # raw ratio would otherwise dip below where the bar already was.
    raw_percent = (elapsed / total_estimate) * 100
    percent = max(_max_progress_percent, min(99, raw_percent))
    _max_progress_percent = percent

    payload = {
        "tick": tick,
        "stage_index": stage_index,
        "stage_count": len(PROGRESS_STAGES),
        "stage_label": stage_label,
        "endpoint_count": _current_endpoint_count(),
        "percent": round(percent, 1),
        "elapsed_seconds": round(elapsed),
        "eta_seconds": max(0, round(total_estimate - elapsed)),
    }
    try:
        await redis_client.set("ENGINE_PROGRESS", json.dumps(payload))
    except Exception as e:
        logger.debug(f"[!] Failed to publish discovery progress: {e}")

async def _run_progress_stage(tick, stage_index, stage_key, stage_label, coro):
    global _discovery_start_mono
    if _discovery_start_mono is None:
        _discovery_start_mono = time.monotonic()
    await _publish_progress(tick, stage_index, stage_key, stage_label)

    # A stage can legitimately run for many minutes (fingerprinting 100+
    # nodes is the dominant cost by far) -- without this heartbeat,
    # elapsed/ETA only ever update at stage BOUNDARIES, so the modal
    # looks frozen for the entire duration of the slowest stage even
    # though real work is happening. Republishing every 5s keeps the
    # numbers visibly live throughout.
    async def _heartbeat():
        while True:
            await asyncio.sleep(5)
            await _publish_progress(tick, stage_index, stage_key, stage_label)

    start = time.monotonic()
    heartbeat_task = asyncio.create_task(_heartbeat())
    try:
        result = await coro
    finally:
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
    _stage_durations[stage_key] = time.monotonic() - start
    return result

# ==============================================================================
# 2. BACKGROUND TASKS & UTILITIES
# ==============================================================================
def send_first_boot_telemetry(config_loader):
    """
    Unconditional install-count ping -- see punch list TELEM-4. Generates
    (once) and reports an anonymous INSTANCE_ID regardless of
    SUBMIT_TELEMETRY. Only that random ID is ever sent, no other data --
    this is disclosed in the setup wizard and in Settings (see
    settings.html). SUBMIT_TELEMETRY no longer gates this base count; it
    is reserved for any future, richer telemetry only.
    """
    instance_id = config_loader._get_setting("INSTANCE_ID")
    if not instance_id:
        instance_id = str(uuid.uuid4())
        config_loader._set_setting("INSTANCE_ID", instance_id, description="Unique UUID for this installation.")
        logger.info(f"[*] Telemetry: Generated new Instance ID -> {instance_id}")

    payload = {"instance_id": instance_id}
    try:
        requests.post("https://netlanvas.com/telemetry.php", json=payload, timeout=3)
    except Exception as e:
        logger.warning(f"[*] Telemetry: Boot reporting failed (Offline?): {e}")

HEARTBEAT_INTERVAL_SECONDS = 24 * 3600
NETLANVAS_VERSION = os.getenv("NETLANVAS_VERSION", "unknown")
_last_heartbeat_sent_at = 0.0

def maybe_send_telemetry_heartbeat(config_loader):
    """
    Richer, periodic (~daily) heartbeat -- this is the future point
    send_first_boot_telemetry's docstring refers to. Unlike that
    unconditional one-time ping, this is strictly opt-in (SUBMIT_TELEMETRY)
    and sends one more field (version) alongside instance_id, so it must
    never fire unless the setting is explicitly enabled -- that's the
    whole point of the distinction between the two functions. Called once
    per polling-loop tick (cheap check); actually sends at most once per
    HEARTBEAT_INTERVAL_SECONDS.
    """
    global _last_heartbeat_sent_at

    submit_telemetry = config_loader._get_setting("SUBMIT_TELEMETRY", "false")
    if str(submit_telemetry).lower() not in ("true", "1", "yes"):
        return

    now = time.time()
    if now - _last_heartbeat_sent_at < HEARTBEAT_INTERVAL_SECONDS:
        return

    instance_id = config_loader._get_setting("INSTANCE_ID")
    if not instance_id:
        return  # first-boot telemetry hasn't run yet this cycle -- try again next tick

    payload = {"instance_id": instance_id, "netlanvas_version": NETLANVAS_VERSION}
    try:
        requests.post("https://netlanvas.com/api/telemetry-heartbeat.php", json=payload, timeout=5)
        _last_heartbeat_sent_at = now
        logger.info("[*] Telemetry: Sent periodic heartbeat (SUBMIT_TELEMETRY enabled).")
    except Exception as e:
        logger.warning(f"[*] Telemetry: Heartbeat failed (Offline?): {e}")

UPDATE_CHECK_INTERVAL_SECONDS = 3600
_last_update_check_at = 0.0

PRUNE_INTERVAL_SECONDS = 24 * 3600
_last_prune_at = 0.0

def maybe_prune_alerting_history(db_path: str):
    """
    Bounds device_state_transitions/alerts/device_findings growth --
    see engine/alerting.py's prune_alerting_history() for retention
    periods. Same cheap-check-every-tick, run-at-most-once-per-interval
    shape as maybe_send_telemetry_heartbeat/maybe_check_for_update above.
    """
    global _last_prune_at
    now = time.time()
    if now - _last_prune_at < PRUNE_INTERVAL_SECONDS:
        return
    prune_alerting_history(db_path)
    _last_prune_at = now

def _parse_version(v: str):
    """
    Same parsing/comparison shape as server.py's _parse_version (kept
    duplicated rather than shared -- two independent processes, one
    small self-contained helper). Returns None for anything that
    doesn't parse as "vX.Y[.Z]".
    """
    if not v:
        return None
    v = v.strip()
    if v.startswith("v"):
        v = v[1:]
    try:
        parts = tuple(int(p) for p in v.split("."))
    except ValueError:
        return None
    return parts + (0,) * max(0, 3 - len(parts))

def maybe_check_for_update(config_loader):
    """
    Hourly check against a small public version marker published by
    build_multiarch.sh alongside every release (latest-version.txt on
    netlanvas.com). Unlike the entitlement check, this needs no device
    identity/signing -- it's just a public GET -- so it runs directly in
    the poller loop rather than check-on-read in the API container.
    Result is cached in app_settings so the API container (which serves
    /api/version/check to the dashboard) doesn't need its own network
    round trip on every page load. Same "cheap check every tick, actually
    runs at most once per interval" shape as maybe_send_telemetry_heartbeat.

    If AUTO_UPDATE_APP is enabled, a detected newer version also
    triggers Watchtower to actually pull and apply it -- see
    trigger_watchtower_update(). Default is off: a user has to opt in
    to unattended updates of NetLanvas's own release (as opposed to
    redis/caddy, which always auto-update regardless -- see
    maybe_update_infra_images()). The Settings page's "Update Now"
    button hits the same trigger on demand either way.
    """
    global _last_update_check_at

    now = time.time()
    if now - _last_update_check_at < UPDATE_CHECK_INTERVAL_SECONDS:
        return

    try:
        response = requests.get("https://netlanvas.com/latest-version.txt", timeout=5)
        response.raise_for_status()
        latest_version = response.text.strip()
        if latest_version:
            config_loader._set_setting("_LATEST_VERSION_SEEN", latest_version)
            _last_update_check_at = now
            current_parsed = _parse_version(NETLANVAS_VERSION)
            latest_parsed = _parse_version(latest_version)
            if current_parsed is not None and latest_parsed is not None and latest_parsed > current_parsed:
                logger.info(f"[*] Update check: newer version available ({NETLANVAS_VERSION} -> {latest_version}).")
                auto_update = str(config_loader._get_setting("AUTO_UPDATE_APP", "false")).lower() in ("true", "1", "yes")
                if auto_update:
                    logger.info("[*] AUTO_UPDATE_APP enabled -- triggering NetLanvas app update now.")
                    result = trigger_watchtower_update("netlanvas.com/netlanvas")
                    if result:
                        logger.info(f"[*] App auto-update triggered: {result.get('summary')}")
    except Exception as e:
        logger.warning(f"[*] Update check failed (offline?): {e}")

WATCHTOWER_INTERNAL_IP = os.getenv("WATCHTOWER_INTERNAL_IP", "172.28.1.11")
WATCHTOWER_API_TOKEN = os.getenv("WATCHTOWER_API_TOKEN", "")
INFRA_UPDATE_INTERVAL_SECONDS = 3600
_last_infra_update_check_at = 0.0

def trigger_watchtower_update(image_filter: str) -> dict | None:
    """
    POSTs to Watchtower's HTTP API (see docker-compose.dist.yaml's
    watchtower service -- HTTP-trigger-only mode, WATCHTOWER_HTTP_API_UPDATE
    with no periodic polling of its own, so nothing updates on
    Watchtower's own schedule; this function and its callers are the
    only thing that ever actually triggers an update). image_filter is
    comma-separated image name(s), no tag = match regardless of tag
    (e.g. "redis,caddy" or "netlanvas.com/netlanvas"). Returns
    Watchtower's own JSON summary on success, None on any failure --
    callers treat "nothing to update" and "couldn't reach Watchtower"
    the same way (nothing to report), just logged differently.
    """
    if not WATCHTOWER_API_TOKEN:
        return None
    try:
        response = requests.post(
            f"http://{WATCHTOWER_INTERNAL_IP}:8080/v1/update",
            params={"image": image_filter},
            headers={"Authorization": f"Bearer {WATCHTOWER_API_TOKEN}"},
            timeout=300,  # a real image pull + container recreate, not a cheap check
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.warning(f"[*] Watchtower update trigger failed for {image_filter!r}: {e}")
        return None

def maybe_update_infra_images(config_loader):
    """
    Base infrastructure (redis/caddy) always auto-updates, unconditionally
    -- no opt-in needed, unlike the NetLanvas app image itself (see
    maybe_check_for_update's AUTO_UPDATE_APP branch above). These are
    stable, widely-used upstream images with low behavior-change risk;
    a patched CVE there is close to pure upside, with none of the
    "did a new NetLanvas release regress something" risk a forced app
    update would carry.
    """
    global _last_infra_update_check_at
    now = time.time()
    if now - _last_infra_update_check_at < INFRA_UPDATE_INTERVAL_SECONDS:
        return
    _last_infra_update_check_at = now
    result = trigger_watchtower_update("redis,caddy")
    if result and result.get("summary", {}).get("updated"):
        logger.info(f"[*] Infra auto-update: {result['summary']}")

def _is_safe_public_ip(ip_str: str) -> bool:
    """
    Rejects any address that isn't a legitimate public internet address
    -- private, loopback, link-local, reserved, multicast, and
    unspecified ranges are all blocked. Checking the RESOLVED IP (via
    Python's ipaddress module, not a hand-maintained substring list) is
    what actually closes what a hostname-string blocklist can't: DNS
    can return anything for a name that merely "looks" external.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified
    )

def _resolve_and_validate_host(hostname: str):
    """
    Resolves hostname to its TCP-capable (SOCK_STREAM) addresses and
    validates every candidate IP. Restricting the lookup to SOCK_STREAM
    matches what requests/urllib3 actually connects with, so the
    returned list is free of the UDP/RAW duplicate entries an
    unfiltered getaddrinfo() call would otherwise include for the same
    IP -- entries that a downstream consumer filtering only on family
    could hand back for a TCP connection attempt.
    Returns the validated addrinfo list on success, or None if
    resolution fails or any candidate address is disallowed.
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        logger.error(f"SSRF Protection: Could not resolve hostname -> {hostname}")
        return None

    for _family, _type, _proto, _canon, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        if not _is_safe_public_ip(ip_str):
            logger.error(f"SSRF Protection: Hostname '{hostname}' resolved to a disallowed address -> {ip_str}")
            return None
    return addrinfo

_dns_pin_lock = threading.Lock()
_real_getaddrinfo = socket.getaddrinfo

@contextmanager
def _pinned_dns(hostname: str, validated_addrinfo):
    """
    Pins socket-level DNS resolution to the already-validated address
    list for the duration of a connection attempt. Without this,
    requests.get() would re-resolve the hostname itself at connect
    time, and a DNS-rebinding attacker could return a different
    (internal) address for that second lookup than the one just
    validated -- a classic TOCTOU. The monkeypatch is process-global,
    so it's guarded by a lock and restricted to the exact hostname/type
    being pinned; any other lookup falls through to the real resolver.
    """
    def _pinned_getaddrinfo(host, port=None, family=0, type=0, proto=0, flags=0):
        if host != hostname:
            return _real_getaddrinfo(host, port, family, type, proto, flags)
        matches = [
            (fam, typ, prot, canon, (sockaddr[0], port) + tuple(sockaddr[2:]))
            for fam, typ, prot, canon, sockaddr in validated_addrinfo
            if family in (0, fam) and type in (0, typ)
        ]
        if not matches:
            raise socket.gaierror(f"No pinned address matches the requested family/type for {host}")
        return matches

    with _dns_pin_lock:
        socket.getaddrinfo = _pinned_getaddrinfo
        try:
            yield
        finally:
            socket.getaddrinfo = _real_getaddrinfo

def download_oui_payload(url, dest_path, max_redirects=3):
    """
    Fetches the OUI database with SSRF protection applied to every hop,
    not just the initial URL: urllib/requests follow redirects by
    default with no re-validation, which would otherwise let a single
    validated-safe URL redirect straight to an internal address. Each
    hop here is independently scheme-checked and resolved-IP-validated
    before being followed, and the validated address is pinned for the
    connection itself so a second, connect-time DNS lookup can't be
    used to slip past validation (DNS rebinding).
    """
    try:
        current_url = url
        for _hop in range(max_redirects + 1):
            parsed = urllib.parse.urlparse(current_url)
            if parsed.scheme != "https":
                logger.error(f"SSRF Protection: Rejected insecure protocol in URL -> {current_url}")
                return False

            hostname = parsed.hostname or ""
            validated_addrinfo = hostname and _resolve_and_validate_host(hostname)
            if not hostname or not validated_addrinfo:
                return False

            logger.info(f"Downloading upstream OUI database from {current_url}...")
            with _pinned_dns(hostname, validated_addrinfo):
                response = requests.get(
                    current_url,
                    headers={'User-Agent': config.HTTP_USER_AGENT},
                    timeout=10,
                    allow_redirects=False,
                )

            if response.status_code in (301, 302, 303, 307, 308):
                redirect_target = response.headers.get("Location")
                if not redirect_target:
                    logger.error("SSRF Protection: Redirect response with no Location header -- aborting.")
                    return False
                current_url = urllib.parse.urljoin(current_url, redirect_target)
                logger.warning(f"OUI fetch redirected -- re-validating new target: {current_url}")
                continue

            response.raise_for_status()
            with open(dest_path, 'wb') as out_file:
                out_file.write(response.content)
            logger.info("OUI database payload successfully retrieved to local storage.")
            return True

        logger.error(f"SSRF Protection: Exceeded {max_redirects} redirects -- aborting.")
        return False
    except Exception as e:
        logger.error(f"Failed to fetch external OUI database: {e}")
        return False

async def _refresh_oui_file(file_path, url, label, parser):
    if not os.path.exists(file_path):
        logger.warning(f"Local {label} OUI database missing. Flagging for forced external download...")
        needs_update = True
    else:
        needs_update = (time.time() - os.path.getmtime(file_path)) > (30 * 86400)
        if needs_update:
            logger.info(f"Local {label} OUI database expired (>30 days). Flagging for forced update...")
    if needs_update and url:
        success = await asyncio.to_thread(download_oui_payload, url, file_path)
        if success: await asyncio.to_thread(lambda: parser(file_path, label) if label in ("MA-M", "MA-S") else parser(file_path))

async def stage_oui_maintenance():
    # NATIVE-1: derive from config.DB_PATH's own directory rather than
    # a separate hardcoded /app literal -- keeps this in step with
    # engine/oui_manager.py's OUI_FILE, which already made this switch.
    oui_dir = os.path.dirname(config.DB_PATH)
    await _refresh_oui_file(os.path.join(oui_dir, "oui.txt"), config.OUI_URL, "MA-L", parse_and_import_oui)
    # OUI-1 (2026-09-06): same 30-day maintenance cycle now also covers
    # IEEE's MA-M (28-bit) and MA-S (36-bit) registries -- see
    # engine/oui_manager.py's own module note for why these matter (the
    # classic MA-L-only source leaves any device in a newer, smaller
    # IEEE block permanently "Unknown Hardware"). truncate=True here
    # since each file's own refresh should only replace ITS OWN prior
    # rows, not the sibling file's -- unlike ensure_oui_index()'s
    # first-boot build (truncate=False), which builds both files into
    # an already-empty table in the same pass.
    await _refresh_oui_file(os.path.join(oui_dir, "oui28.txt"), config.OUI28_URL, "MA-M", parse_and_import_extended_oui)
    await _refresh_oui_file(os.path.join(oui_dir, "oui36.txt"), config.OUI36_URL, "MA-S", parse_and_import_extended_oui)
    # ENT-1 (2026-09-07): same maintenance cycle for IANA's enterprise-
    # number registry -- resolves SNMP sysObjectID to a vendor name,
    # independent of MAC, so it's the one vendor signal that still
    # works on a privacy-randomized MAC. Single source, so this uses
    # _refresh_oui_file's default (non MA-M/MA-S) branch, which calls
    # parser(file_path) with no label arg -- matches
    # parse_and_import_enterprise_numbers's signature exactly.
    await _refresh_oui_file(os.path.join(oui_dir, "enterprise-numbers.txt"), config.ENTERPRISE_NUMBERS_URL, "IANA-ENT", parse_and_import_enterprise_numbers)

CADDY_DIR = "/app/caddy"
CADDYFILE_PATH = os.path.join(CADDY_DIR, "Caddyfile")

CADDYFILE_CONTENT = """# TLS-only. No plaintext HTTP listener -- see project notes: a redirect
# listener would still be a live plaintext socket, which defeats the
# point of this migration. Users must connect via https:// explicitly.
{
	auto_https off
}

:8899 {
	tls /etc/netlanvas-tls/server.crt /etc/netlanvas-tls/server.key

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "SAMEORIGIN"
	}

	reverse_proxy netlanvas_api:8000 {
		header_up X-Forwarded-Proto https
	}

	log {
		output stdout
		format json
	}
}
"""

def ensure_caddyfile():
    try:
        os.makedirs(CADDY_DIR, exist_ok=True)
        if os.path.isdir(CADDYFILE_PATH):
            os.rmdir(CADDYFILE_PATH)
            logger.warning(f"[!] Found an empty directory at {CADDYFILE_PATH} -- removed it.")
        if not os.path.isfile(CADDYFILE_PATH):
            with open(CADDYFILE_PATH, "w") as f:
                f.write(CADDYFILE_CONTENT)
            logger.info(f"[*] Generated default Caddyfile at {CADDYFILE_PATH}.")
        else:
            logger.info(f"[*] Existing Caddyfile found at {CADDYFILE_PATH} -- leaving untouched.")
    except Exception as e:
        logger.error(f"[!] Failed to provision Caddyfile: {e}")

def detect_host_public_ips() -> list:
    """
    Runs inside netlanvas_core, which is network_mode: host -- so this
    genuinely sees the Pi's real LAN-facing IP(s), unlike netlanvas_api,
    which is sandboxed on the internal bridge network and can only ever
    see its own container IP. Published to Redis so the API's TLS cert
    generation (see security/cert_manager.py) can include the actual
    address a browser will use, with zero manual configuration -- this
    is the mechanism that makes the appliance's install flow genuinely
    zero-config end to end.
    """
    ips = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.add(ip)
    except socket.gaierror:
        pass
    return sorted(ips)

async def stage_publish_host_identity():
    ips = detect_host_public_ips()
    if not ips:
        logger.warning("[!] Could not detect any host-facing IP address to publish.")
        return
    try:
        await redis_client.set("HOST_TLS_SANS", ",".join(ips))
        logger.info(f"[*] Published host address(es) for TLS cert generation: {', '.join(ips)}")
    except Exception as e:
        logger.warning(f"[!] Failed to publish host identity to Redis: {e}")

async def stage_gateway_discovery():
    gw = detect_default_gateway()
    if gw: runtime_context["detected_gateway"] = gw

async def stage_publish_network_interfaces():
    """
    Every tick, not just once at boot (unlike stage_publish_host_identity
    just above) -- unlike the TLS SAN list, this feeds a live Settings
    page dropdown (Polling Source), and interfaces can gain/lose an
    address at any time (a cable plugged in, a DHCP lease renewing).
    See enumerate_host_network_interfaces()'s own docstring for why this
    has to be netlanvas_core doing the publishing, not netlanvas_api
    reading it directly.
    """
    try:
        interfaces = enumerate_host_network_interfaces()
        await redis_client.set("HOST_NETWORK_INTERFACES", json.dumps(interfaces))
    except Exception as e:
        logger.debug(f"Failed to publish host network interfaces to Redis: {e}")

async def stage_arp_scrape(is_deep_scan_tick=False):
    # POLL-1: one representative IP per node instead of every IP that
    # node happens to have -- ARP cache content is identical regardless
    # of which of a device's own IPs is used to query it, confirmed via
    # TOPO-1 (a single router can genuinely have 6+ interface IPs).
    targets = set(get_representative_targets(
        ['Router', 'Switch', 'Switch / WAP', 'Docker Host'],
        credential_cache=CREDENTIAL_CACHE,
    ))
    gw = runtime_context.get("detected_gateway")
    if gw: targets.add(gw)

    if not targets: return

    logger.info(f"Initiating distributed ARP cache scrape across {len(targets)} L3 targets...")

    async def scrape_target(ip):
        # Renamed from "community" -- get_working_credential() now
        # returns an SNMPCredential (v2c or v3), not a bare string.
        # No behavior change, just no longer a misleading name.
        credential = await get_working_credential(ip)
        _, results = await run_snmp_pipeline(ip, credential, is_deep_scan_tick=is_deep_scan_tick)
        arp_result = results.get(35)

        # ROUTER-1: this target's OWN IP/MAC binding can never appear
        # in its own ARP cache (a device doesn't ARP for itself) --
        # confirmed live, this left a fully, successfully SNMP-polled
        # router entirely absent from the topology, since nothing else
        # in the pipeline ever creates an l3_bindings row for a device
        # discoverable only as a scrape TARGET, never as an ARP-table
        # ENTRY. Feeds the same "Centralized atomic ingestion" block
        # below that every other ARP-discovered device already goes
        # through, rather than needing separate ingestion logic.
        own_mac = await resolve_own_mac(ip)
        if own_mac:
            if not arp_result:
                arp_result = {"valid": {}, "stale": set()}
            arp_result.setdefault("valid", {})[own_mac] = ip

        return arp_result

    tasks = [scrape_target(ip) for ip in targets]
    results_list = await asyncio.gather(*tasks, return_exceptions=True)
    
    global_arp_data = {}
    global_stale_ips = set()
    for res in results_list:
        if isinstance(res, dict):
            global_arp_data.update(res.get("valid") or {})
            global_stale_ips.update(res.get("stale") or set())

    # 2. Centralized atomic ingestion
    # ARP-1 (2026-09-20): always enters now, not gated on this cycle
    # actually returning fresh data -- the age-based purge below needs
    # to run every cycle regardless of what this cycle's walk found, so
    # a cycle with zero new/stale entries (a transient scrape failure,
    # or simply nothing changed) doesn't also skip retiring rows that
    # have aged past ARP_CACHE_PURGE_AGE_SECONDS.
    if True:
        conn = sqlite3.connect(config.DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.cursor()

        # NET-2: a router's own ARP cache can legitimately include
        # entries for address space it never actually routes on the
        # monitored LAN -- most commonly its own local Docker bridge
        # networks (each docker-compose project on the router gets an
        # auto-allocated 172.x.0.0/16, and a router that also hosts
        # containers exposes ALL of them in its ARP table alongside
        # real neighbors). Only router_subnets (the router's own
        # CONFIRMED VLAN interfaces, from vlan_registry.py's SNMP walk)
        # represents address space this appliance actually monitors --
        # anything outside every known subnet is discarded here rather
        # than ingested as a "new device". Falls through unfiltered if
        # router_subnets is empty (nothing confirmed yet, e.g. before
        # the first deep-scan) -- same conservative default already
        # used by auto_discovery.py's own NET-1.
        known_subnets = []
        for (subnet_text,) in cursor.execute("SELECT subnet FROM router_subnets"):
            try:
                known_subnets.append(ipaddress.ip_network(subnet_text, strict=False))
            except ValueError:
                continue

        if known_subnets:
            filtered = {}
            for mac, ip in global_arp_data.items():
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if any(addr in net for net in known_subnets):
                    filtered[mac] = ip
            skipped = len(global_arp_data) - len(filtered)
            if skipped:
                logger.info(f"Discarded {skipped} ARP cache entr{'y' if skipped == 1 else 'ies'} outside every confirmed router subnet (router-local noise, e.g. Docker bridges).")
            global_arp_data = filtered

        upsert_count = 0

        for mac, ip in global_arp_data.items():
            # ROUTER-2 (2026-09-09): defense-in-depth -- every actual
            # producer feeding global_arp_data already guards this exact
            # sentinel (an incomplete ARP entry, or, as found live, a
            # VLAN/bridge ifindex with no real L2 hardware reported via
            # resolve_own_mac()'s self-report path), but this is the one
            # place ALL of them converge before writing, so a gap in any
            # future producer is caught here too instead of writing a
            # bogus l3_bindings row for a real IP (confirmed live: this
            # produced a permanently-orphaned SNMPv3 finding keyed to
            # 00:00:00:00:00:00 for the router's own gateway IP).
            if mac == "00:00:00:00:00:00":
                continue
            cursor.execute('INSERT INTO l2_interfaces (mac_address) VALUES (?) ON CONFLICT(mac_address) DO NOTHING', (mac,))
            cursor.execute('''
                INSERT INTO l3_bindings (ip_address, mac_address, discovery_source, last_seen)
                VALUES (?, ?, 'ROUTER_ARP_CACHE', CURRENT_TIMESTAMP)
                ON CONFLICT(ip_address) DO UPDATE SET
                    mac_address=excluded.mac_address,
                    discovery_source=excluded.discovery_source,
                    last_seen=CURRENT_TIMESTAMP
            ''', (ip, mac))
            upsert_count += 1

        # NET-3 follow-up, ARP-1 (2026-09-20): retire immediately rather
        # than waiting for some other event to trigger cleanup (e.g. the
        # same MAC reappearing at a new IP elsewhere) -- a device that
        # goes offline for good, or moves subnets, would otherwise leave
        # its old l3_bindings row (and any "Multihomed" tag it produces)
        # sitting in the DB forever, since l3_bindings is keyed by
        # ip_address and nothing else ever touches the old row once the
        # router stops confirming it. Scoped to ROUTER_ARP_CACHE only --
        # bindings from other discovery sources (fingerprinting, the
        # ALERT-4 presence fallback) aren't this router's to judge.
        #
        # ARP-1: originally gated on ip_address IN global_stale_ips (an
        # entry the SNMP walk still saw but flagged with a non-valid
        # ipNetToMediaType). Confirmed live this essentially never fires
        # in practice: once a router's own ARP timeout (as short as 30s
        # on ours) actually expires a dead entry, it doesn't get flagged
        # invalid -- it just stops appearing in the walk's output at
        # all, so it can never land in global_stale_ips either (that set
        # is built as ip_seen - ip_has_valid_entry, and an IP absent
        # from the whole walk was never in ip_seen to begin with). Real
        # case: a device offline for days sat in l3_bindings indefinitely,
        # last_seen frozen at its final real sighting, still rendering as
        # a live device everywhere the UI reads l3_bindings, since
        # nothing ever purged it. Pure age-based retirement instead --
        # last_seen already freezes correctly the moment a device stops
        # being reconfirmed (that part was always working), so purging
        # on its age directly closes the gap without depending on a
        # router-reported signal that real hardware rarely produces.
        # Runs every cycle regardless of what this cycle's walk returned
        # (a transient scrape failure shouldn't pause aging of already-
        # known rows). 3 hours, not OFFLINE_GRACE_TICKS's 3 ticks --
        # deliberately much more generous than the tick-based offline
        # alert timer (a different, faster-firing concern in
        # device_state_tracker.py) so a real network blip or a brief
        # router reboot can't cause a false purge.
        ARP_CACHE_PURGE_AGE_SECONDS = 3 * 60 * 60
        cursor.execute(
            "DELETE FROM l3_bindings "
            "WHERE discovery_source = 'ROUTER_ARP_CACHE' "
            "AND last_seen <= datetime('now', ?)",
            (f"-{ARP_CACHE_PURGE_AGE_SECONDS} seconds",)
        )
        purged_count = cursor.rowcount

        conn.commit()
        conn.close()
        if upsert_count > 0:
            logger.info(f"Database sync complete: {upsert_count} global L3 bindings logged via Pipeline Step 35.")
        if purged_count > 0:
            logger.info(f"[*] Stale ARP Purge: Removed {purged_count} l3_bindings row(s) no longer confirmed dynamic/static by their source router.")

async def stage_physical_lldp():
    await run_lldp_scraper(override_router_ip=runtime_context.get("detected_gateway"))

async def stage_vlan_registry():
    await run_vlan_registry_scan()

async def stage_purge_router_arp_cache_noise():
    """
    NET-2 follow-up: retroactively removes fake "devices" created before
    stage_arp_scrape()'s router_subnets filter existed. Scoped
    identically to that filter, so it can never remove anything the
    filter would now let through -- only l3_bindings rows sourced from
    ROUTER_ARP_CACHE that fall outside every currently-confirmed
    router_subnets range, and only for nodes NOT already classified
    Router (belt-and-braces; a real router's interfaces already live
    inside router_subnets by definition, so this should never fire for
    one). Deliberately does NOT touch SNMP_IP_TABLE rows -- those are a
    device's own self-reported interfaces (fingerprinter.py), which is
    exactly what unification.py's Docker Host classification depends on
    seeing; only ROUTER_ARP_CACHE represents another device's presence,
    which is the only case a Docker-bridge address is never legitimate.
    Runs once per deep-scan cycle (see the tick loop) -- cheap and a
    safe no-op once nothing matches, same pattern as
    prune_alerting_history().
    """
    conn = sqlite3.connect(config.DB_PATH)
    try:
        known_subnets = []
        for (subnet_text,) in conn.execute("SELECT subnet FROM router_subnets"):
            try:
                known_subnets.append(ipaddress.ip_network(subnet_text, strict=False))
            except ValueError:
                continue
        if not known_subnets:
            return  # nothing confirmed yet -- can't safely judge anything as noise

        rows = conn.execute(
            """SELECT b.ip_address, b.mac_address, l2.node_id FROM l3_bindings b
               LEFT JOIN l2_interfaces l2 ON b.mac_address = l2.mac_address
               LEFT JOIN logical_nodes n ON l2.node_id = n.id
               WHERE b.discovery_source = 'ROUTER_ARP_CACHE'
               AND (n.device_type IS NULL OR n.device_type != 'Router')"""
        ).fetchall()

        noise_macs = set()
        noise_node_ids = set()
        for ip_text, mac, node_id in rows:
            try:
                addr = ipaddress.ip_address(ip_text)
            except ValueError:
                continue
            if not any(addr in net for net in known_subnets):
                noise_macs.add(mac)
                if node_id is not None:
                    noise_node_ids.add(node_id)

        if not noise_macs:
            return

        for mac in noise_macs:
            conn.execute("DELETE FROM alerts WHERE mac_address = ?", (mac,))
            conn.execute("DELETE FROM device_state_transitions WHERE mac_address = ?", (mac,))
            conn.execute("DELETE FROM device_state WHERE mac_address = ?", (mac,))
            conn.execute("DELETE FROM l3_bindings WHERE mac_address = ?", (mac,))
            conn.execute("DELETE FROM l2_interfaces WHERE mac_address = ?", (mac,))
        for node_id in noise_node_ids:
            conn.execute(
                "DELETE FROM logical_nodes WHERE id = ? AND NOT EXISTS (SELECT 1 FROM l2_interfaces WHERE node_id = ?)",
                (node_id, node_id),
            )
        conn.commit()
        logger.info(f"[NET-2] Purged {len(noise_macs)} stale router-local noise device(s) predating the ARP-cache subnet filter.")
    except Exception as e:
        logger.error(f"[NET-2] stage_purge_router_arp_cache_noise failed: {e}")
        conn.rollback()
    finally:
        conn.close()

async def stage_active_ping_sweeps():
    discovered = discover_active_subnets()
    runtime_context["discovered_subnets"] = discovered
    await run_ping_sweeper(override_subnets=discovered)

async def stage_wifi_scrape(is_deep_scan_tick=False):
    # POLL-1: one representative IP per node instead of every IP that
    # node happens to have -- an AP's client association table is
    # identical regardless of which of its own IPs is used to query it.
    aps = get_representative_targets(['Access Point'], credential_cache=CREDENTIAL_CACHE)
    for ap_ip in aps:
        # poll_wifi_clients no longer takes a credential parameter --
        # it resolves its own via get_working_credential() internally
        # (SNMP-8). This also retires the old config.SNMP_COMMUNITY
        # (singular, unparsed) call here, which bypassed the credential
        # list/cache entirely.
        status = await poll_wifi_clients(ap_ip, is_deep_scan_tick=is_deep_scan_tick)
        logger.info(f"Wi-Fi Scrape for {ap_ip}: {status}")

async def stage_device_fingerprinting():
    await run_fingerprinter()

async def stage_web_probe():
    await run_web_probe()

async def stage_os_profiler():
    await run_os_fingerprinter()

async def stage_hostname_discovery():
    # HOSTNAME-1: reverse-mDNS + NetBIOS NBSTAT sweep, every fast tick
    # (cheap best-effort UDP probes, not SNMP) -- see
    # pollers/hostname_discovery.py's module docstring.
    await run_hostname_discovery_sweep()

async def stage_smart_switch_discovery():
    # SMARTSW-1 (2026-09-04, ported from main): NSDP (Netgear) / ESCP
    # (TP-Link) / SSDP (universal) smart-switch discovery -- see
    # engine/smart_switch_pipeline.py's module docstring for why this is
    # its own broadcast-based pipeline rather than a step in
    # engine/snmp_pipeline.py. Runs BEFORE stage_unification_engine() so
    # this cycle's classification pass (specifically
    # run_smart_switch_candidate_pass()) sees fresh results, not last
    # cycle's. Writes into network.db's smart_switch_candidates table --
    # ephemeral, refreshed every cycle, never itself the source of truth
    # (that's inventory.db, written only once self-identifying (SSDP) or
    # a human confirms via /api/node/update or /api/promote_node).
    found = await run_smart_switch_pipeline()
    if not found:
        return
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS smart_switch_candidates (
            mac_address TEXT PRIMARY KEY,
            vendor TEXT,
            model TEXT,
            protocol TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    for mac, entry in found.items():
        conn.execute(
            "INSERT INTO smart_switch_candidates (mac_address, vendor, model, protocol, last_seen) "
            "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(mac_address) DO UPDATE SET vendor=excluded.vendor, model=excluded.model, "
            "protocol=excluded.protocol, last_seen=CURRENT_TIMESTAMP",
            (mac, entry.get("vendor"), entry.get("model"), entry.get("protocol")),
        )
    conn.commit()
    conn.close()

async def stage_unification_engine():
    run_unification_engine()

async def stage_inference_engine():
    await asyncio.to_thread(run_inference_cycle)

async def stage_smart_switch_consolidation():
    # SMARTSW-1: must run AFTER stage_inference_engine() -- it collapses
    # dark-matter's synthetic pseudo-switch nodes into a user-verified
    # real device, and the pseudo nodes it looks for are exactly what
    # run_dark_matter_detection() (called by stage_inference_engine, just
    # above) creates each cycle.
    await asyncio.to_thread(run_verified_switch_consolidation_pass)

async def stage_inventory_reoverlay():
    # INVENTORY-3 (2026-09-09): dark-matter's pseudo-switch nodes are
    # created by stage_inference_engine(), which runs AFTER this same
    # tick's stage_unification_engine() -- whose own inventory-overlay
    # pass (run_inventory_overlay_pass(), called last inside
    # run_unification_engine()) has therefore already run and missed
    # them. Nothing re-runs unification again until the NEXT deep-scan
    # tick -- this whole block only executes on tick 0/1, never on a
    # "structural scan bypassed" tick -- so a saved name for a
    # newly-created pseudo switch had no guaranteed future pass to
    # apply it. Root-caused live: 3+ hours of continuous bypassed-tick
    # operation across many deep-scan cycles never once re-applied it.
    # Re-running the (idempotent, cheap -- one small verified_devices
    # table, one indexed lookup per row) overlay pass here, after
    # consolidation has had its say, closes the gap the same tick the
    # node is born instead of depending on some future pass that may
    # never come.
    reapplied = await asyncio.to_thread(run_inventory_overlay_pass)
    if reapplied:
        logger.info(f"Inventory re-overlay complete. Verified overrides applied: {reapplied}")

async def stage_inventory_snapshot_sync():
    # INVENTORY-4 (2026-09-09): every discovered device gets a
    # last-known snapshot in inventory.db now, not just ones a human
    # has explicitly confirmed -- see run_inventory_snapshot_sync()'s
    # own docstring for the full reasoning and exactly which columns
    # this does (and, just as importantly, does not) touch. Runs right
    # after stage_inventory_reoverlay() so the snapshot reflects
    # whatever name that pass just applied, not a stale pre-overlay one.
    synced = await asyncio.to_thread(run_inventory_snapshot_sync)
    if synced:
        logger.info(f"Inventory snapshot sync complete. Devices synced: {synced}")

_alert_dispatch_task = None


async def background_polling_engine():
    logger.info("Netlanvas Polling Engine initializing...")
    await asyncio.sleep(5)
    SLOW_CYCLE_INTERVAL = 15
    tick_counter = 0

    try:
        await redis_client.set("ENGINE_TICK", "0")
        logger.info("[*] Redis IPC bridge established. Engine Tick reset to 0.")
    except Exception as e:
        logger.error(f"[!] Failed to connect to Redis IPC broker: {e}")

    await stage_publish_host_identity()
    # LICENSE-1 follow-up: the NATIVE-3 Windows skip below was written
    # when this used scapy's raw packet capture (needs Npcap, not
    # bundled). Now a plain bound UDP socket -- no capture driver of
    # any kind, confirmed working natively on Windows -- so there's no
    # longer a reason to skip it there.
    start_dhcp_sniffer()

    # Community Telemetry Pipeline (netlanvas-telemetry-pipeline-v6 S3/
    # S11): captured once per process boot, before tick 1 -- marks
    # where "this restart's log content" begins, so the tick-10
    # finalize below doesn't re-capture a previous run's tail. Cherry-
    # picked from main -- this whole function is shared verbatim
    # between container POLLER mode and native mode (both call
    # background_polling_engine() directly), so this single insertion
    # covers both.
    telemetry_log_capture_start_offset = telemetry_log_sampler.start_capture(config)
    telemetry_tick10_fired = False

    while True:
        # STATE-4: captured before any stage runs, so it marks "this
        # tick began here" in the same UTC text format SQLite's own
        # CURRENT_TIMESTAMP writes (YYYY-MM-DD HH:MM:SS) -- passed to
        # device_state_tracker.py so its l3_bindings presence fallback
        # can compare against actual tick boundaries instead of a fixed
        # wall-clock offset. See that file's own comment for why.
        tick_started_at = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
        # RETRY-1: lets engine.snmp_adapter's UNRESPONSIVE-device retry
        # logic reason in ticks instead of wall-clock time -- see that
        # module's own comment for why. Set as early as possible in the
        # tick, same as tick_started_at above.
        set_current_tick(tick_counter)
        # PLAN-1 follow-up: proactively fire any deferred v3-credential
        # upgrade that's come due, rather than waiting on some other
        # poller to incidentally touch that device first -- see
        # check_due_v3_upgrades()'s own docstring. Every tick,
        # unconditionally, including fast ones -- that's the whole
        # point, a device LLDP/VLAN registry have stopped actively
        # re-querying must not have to wait for the next deep-scan.
        check_due_v3_upgrades()
        try:
            cmd = await redis_client.get("ENGINE_COMMAND")
            if cmd == "RESTART":
                logger.warning("--- RESTART SIGNAL RECEIVED VIA REDIS. INITIATING GRACEFUL EXIT ---")
                await redis_client.delete("ENGINE_COMMAND")
                break
        except Exception: pass

        # --- ADMIN FORCED TOPOLOGY REBUILD LISTENER ---
        try:
            config_conn = sqlite3.connect(config.CONFIG_DB_PATH)
            config_cursor = config_conn.cursor()
            config_cursor.execute("SELECT setting_value FROM app_settings WHERE setting_key = 'FORCE_TOPOLOGY_REBUILD'")
            row = config_cursor.fetchone()

            if row and str(row[0]).lower() in ("true", "1", "yes"):
                logger.warning("--- [ADMIN OVERRIDE] FORCED TOPOLOGY REBUILD INITIATED. Aging out all infrastructure locks... ---")

                # Execute topology age-out on ephemeral network database
                net_conn = sqlite3.connect(config.DB_PATH)
                net_cursor = net_conn.cursor()
                net_cursor.execute("UPDATE infrastructure_links SET last_mapped = '1970-01-01 00:00:00'")
                net_cursor.execute("UPDATE l3_bindings SET last_seen = '1970-01-01 00:00:00' WHERE mac_address LIKE '02:ff:%'")
                net_conn.commit()
                net_conn.close()

                # Acknowledge and reset the control plane flag
                config_cursor.execute("UPDATE app_settings SET setting_value = 'false' WHERE setting_key = 'FORCE_TOPOLOGY_REBUILD'")
                config_conn.commit()
                tick_counter = 0  # Immediately force deep scan alignment

            config_conn.close()
        except Exception as e:
            logger.error(f"Failed to check topology rebuild flag: {e}")

        maybe_send_telemetry_heartbeat(config)
        telemetry_scheduler.maybe_send_daily(config, config.DB_PATH)
        maybe_check_for_update(config)
        await asyncio.to_thread(maybe_update_infra_images, config)
        await asyncio.to_thread(maybe_prune_alerting_history, config.DB_PATH)

        setup_complete = config._get_setting("SETUP_COMPLETE", "false")
        if str(setup_complete).lower() not in ("true", "1", "yes"):
            logger.info("--- Polling Suspended: Awaiting initial UI configuration (SETUP_COMPLETE=false) ---")
            await asyncio.sleep(10)
            continue

        # --- TIME-LIMITED POLLING SCHEDULE ---
        # Continuous mode (default off, see defaults.json) skips this
        # entirely. Time-limited mode runs for POLLING_DURATION_HOURS from
        # _POLLING_STARTED_AT, then flips _POLLING_ACTIVE off and idles --
        # UI/dashboard/alerts/inventory stay fully browsable against
        # last-known state, only this tick loop pauses. Resume is manual
        # only, via the Settings page "Start Now" button (POST
        # /api/polling/start), which sets _POLLING_ACTIVE=true and clears
        # _POLLING_STARTED_AT so it gets re-stamped fresh below.
        polling_mode = str(config._get_setting("POLLING_MODE", "continuous")).lower()
        if polling_mode == "time_limited":
            polling_active = str(config._get_setting("_POLLING_ACTIVE", "true")).lower() in ("true", "1", "yes")
            if not polling_active:
                # No recurring log line here (unlike the SETUP_COMPLETE
                # gate above) -- Settings page's Live Logs window renders
                # its own live "Polling paused at HH:MM:SS for HH:MM:SS"
                # status line client-side from _POLLING_PAUSED_AT via
                # /api/polling/status, so a real backend log entry every
                # 10s would just be redundant noise in the persisted logs.
                await asyncio.sleep(10)
                continue

            started_at_raw = config._get_setting("_POLLING_STARTED_AT", "")
            if not started_at_raw:
                started_at = datetime.datetime.now(datetime.UTC)
                config._set_setting("_POLLING_STARTED_AT", started_at.strftime("%Y-%m-%d %H:%M:%S"))
                logger.info(f"--- Time-Limited Polling: run started, duration {config._get_setting('POLLING_DURATION_HOURS', '4')}h ---")
                # Realigns the deep-scan cadence to start fresh from this
                # moment -- same precedent as the existing "Rebuild
                # Topology" admin action, which does this same reset for
                # the same reason ("Immediately force deep scan
                # alignment"). Safe: _INITIAL_DISCOVERY_COMPLETE is a
                # separate sticky flag (already true from before this
                # run), so this does NOT re-lock the dashboard's tick-lock
                # overlay -- and telemetry_tick10_fired is its own local
                # guard, unaffected by tick_counter, so tick-10 telemetry
                # can't double-fire either. Covers both a genuine resume
                # from paused and a manual "Restart Now" mid-run, since
                # both clear _POLLING_STARTED_AT the same way.
                tick_counter = 0
            else:
                try:
                    started_at = datetime.datetime.strptime(started_at_raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.UTC)
                except ValueError:
                    started_at = datetime.datetime.now(datetime.UTC)
                    config._set_setting("_POLLING_STARTED_AT", started_at.strftime("%Y-%m-%d %H:%M:%S"))

                try:
                    duration_hours = float(config._get_setting("POLLING_DURATION_HOURS", "4"))
                except ValueError:
                    duration_hours = 4.0

                elapsed_hours = (datetime.datetime.now(datetime.UTC) - started_at).total_seconds() / 3600.0
                if elapsed_hours >= duration_hours:
                    config._set_setting("_POLLING_ACTIVE", "false")
                    config._set_setting("_POLLING_PAUSED_AT", datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S"))
                    # Splash banner, not a single log line -- this is the
                    # one moment someone watching the log window needs a
                    # clear explanation of what just happened and how to
                    # undo it, mirroring the visual weight of a real
                    # startup banner rather than blending into the
                    # scrolling tick-by-tick noise above it.
                    logger.info("=" * 70)
                    logger.info(f"TIME-LIMITED POLLING RUN COMPLETE ({duration_hours}h elapsed)")
                    logger.info("Polling is now PAUSED. Dashboard, Alerts, Inventory, and the Graph")
                    logger.info("UI remain fully browsable against the last-known state.")
                    logger.info("To resume: Settings > Polling Schedule > Start Now")
                    logger.info("=" * 70)
                    await asyncio.sleep(10)
                    continue

        try:
            # Progress is only worth tracking/publishing while the UI is
            # actually locked on it (ticks 0 & 1, see index.html's
            # tick-lock-overlay) -- steady-state ticks skip the wrapper
            # entirely and call stages directly, exactly as before.
            track_progress = tick_counter <= 1
            stage_idx = 0
            # CAPS-1: hoisted above the structural-deep-scan `if` block
            # below (which still gates unification/inference/LLDP etc.)
            # because arp_scrape/mac_table_scraper/wifi_scrape run every
            # tick, not just deep-scan ones -- but the SNMP pipeline's
            # own per-step capability re-check (run_snmp_pipeline's
            # is_deep_scan_tick) needs to fire on the SAME cadence as
            # every other structural check, not its own separate timer.
            is_deep_scan_tick = tick_counter <= 1 or tick_counter % SLOW_CYCLE_INTERVAL == 0

            async def _step(key, label, coro):
                nonlocal stage_idx
                stage_idx += 1
                if track_progress:
                    return await _run_progress_stage(tick_counter, stage_idx, key, label, coro)
                return await coro

            await _step("gateway_discovery", "Detecting default gateway", stage_gateway_discovery())
            await stage_publish_network_interfaces()
            logger.info("--- Initiating Real-Time State Scan (L3 IP Discovery) ---")
            # Inverted Order: ICMP Blast first to populate downstream caches, then extract globally
            await _step("active_ping_sweeps", "Sweeping subnets for live hosts", stage_active_ping_sweeps())
            await _step("arp_scrape", "Reading router ARP caches", stage_arp_scrape(is_deep_scan_tick=is_deep_scan_tick))
            await _step("mac_table_scraper", "Reading switch MAC/FDB tables", run_mac_table_scraper(is_deep_scan_tick=is_deep_scan_tick))
            await _step("wifi_scrape", "Polling wireless client associations", stage_wifi_scrape(is_deep_scan_tick=is_deep_scan_tick))
            # Must run after mac_table_scraper/wifi_scrape -- both just
            # upserted endpoint_locations, so this tick's presence data
            # is as fresh as it'll ever be. See device_state_tracker.py.
            await _step("device_state_tracker", "Tracking device online/offline state", run_device_state_tracker(config.DB_PATH, tick_counter, tick_started_at))
            await _step("os_profiler", "Fingerprinting operating systems", stage_os_profiler())
            await _step("hostname_discovery", "Sweeping for device hostnames (mDNS/NetBIOS)", stage_hostname_discovery())
            # No SNMP traffic of its own -- just inspects whatever
            # CREDENTIAL_CACHE this tick's SNMP-driven stages above
            # (arp_scrape, os_profiler) already populated.
            await _step("snmp_default_community_check", "Checking for default SNMP community strings",
                        asyncio.to_thread(run_snmp_default_community_detector, config.DB_PATH, CREDENTIAL_CACHE))
            # ALERT-6: also no SNMP traffic of its own -- V3_CAPABLE_IPS
            # is populated as a side effect of PLAN-1's engineID probe,
            # which already runs as part of normal credential discovery.
            await _step("snmp_v3_available_check", "Checking for SNMPv3-capable devices still on v2c",
                        asyncio.to_thread(run_snmp_v3_available_detector, config.DB_PATH, CREDENTIAL_CACHE, V3_CAPABLE_IPS))
            # Network I/O (webhook POST, SMTP send). to_thread alone only
            # keeps this off the event loop -- it was still awaited
            # inline in this sequential pipeline, so a slow/unreachable
            # delivery target delayed every stage after it, every tick.
            # During the initial setup-progress window (ticks 0-1) keep
            # the original blocking behavior -- there's nothing pending
            # to deliver yet and the UI's progress bar expects each
            # stage to genuinely complete in order. From then on, fire
            # it as a background task instead: guarded against overlap
            # (skip firing a new one if the previous tick's dispatch
            # hasn't finished, rather than run two deliveries
            # concurrently against the same webhook/SMTP target) and
            # logged if it failed.
            global _alert_dispatch_task
            if track_progress:
                await _step("alert_dispatch", "Delivering pending alerts",
                            asyncio.to_thread(dispatch_pending_alerts, config.DB_PATH, config.CONFIG_DB_PATH))
            else:
                stage_idx += 1
                if _alert_dispatch_task is None or _alert_dispatch_task.done():
                    if _alert_dispatch_task is not None and _alert_dispatch_task.exception():
                        logger.error(f"[!] Alert dispatch failed: {_alert_dispatch_task.exception()}")
                    _alert_dispatch_task = asyncio.create_task(
                        asyncio.to_thread(dispatch_pending_alerts, config.DB_PATH, config.CONFIG_DB_PATH)
                    )
                else:
                    logger.debug("[*] Alert dispatch: previous run still in progress, skipping this tick.")

            if is_deep_scan_tick:
                logger.info(f"--- [Tick {tick_counter}] Initiating Structural Deep-Scan ---")
                await _step("oui_maintenance", "Updating vendor OUI database", stage_oui_maintenance())
                await _step("physical_lldp", "Crawling LLDP topology", stage_physical_lldp())
                await _step("device_fingerprinting", "Profiling discovered devices", stage_device_fingerprinting())
                await _step("web_probe", "Checking for web servers on known devices", stage_web_probe())
                # Runs on the same deep-scan cadence, not just the first
                # few ticks -- a device's SNMP config can regress (or a
                # new device can join) at any point, not just during
                # initial setup, so this stays an ongoing check like
                # every other finding detector. Independent toggle from
                # SNMP_TRY_PUBLIC_COMMUNITY -- see snmp_default_community_
                # detector.py's module docstring for why.
                if str(config._get_setting("SNMP_SECURITY_SCAN_PUBLIC", "true")).lower() in ("true", "1", "yes"):
                    await _step("snmp_public_security_scan", "Checking for additional default SNMP exposure",
                                run_snmp_public_security_scan(config.DB_PATH, CREDENTIAL_CACHE))
                await _step("smart_switch_discovery", "Discovering smart switches (SSDP/NSDP/TP-Link)", stage_smart_switch_discovery())
                await _step("unification_engine", "Unifying multi-interface nodes", stage_unification_engine())
                await _step("inference_engine", "Inferring network relationships", stage_inference_engine())
                await _step("smart_switch_consolidation", "Applying verified switch identities", stage_smart_switch_consolidation())
                await _step("inventory_reoverlay", "Reapplying saved names to newly discovered devices", stage_inventory_reoverlay())
                await _step("inventory_snapshot_sync", "Syncing device inventory records", stage_inventory_snapshot_sync())
                await _step("vlan_registry", "Reading VLAN registry", stage_vlan_registry())
                # Must run after vlan_registry -- needs a freshly
                # confirmed router_subnets to safely judge anything as
                # noise. See NET-2.
                await _step("purge_router_noise", "Clearing stale router-local noise", stage_purge_router_arp_cache_noise())
            else:
                mins_left = SLOW_CYCLE_INTERVAL - (tick_counter % SLOW_CYCLE_INTERVAL)
                logger.info(f"--- [Tick {tick_counter}] Structural scan bypassed (Next deep-scan in {mins_left}m) ---")

            tick_counter += 1
            try:
                await redis_client.set("ENGINE_TICK", str(tick_counter))
            except Exception as e:
                logger.error(f"[!] Redis IPC transmission fault: {e}")

            # NATIVE-15 follow-up: tick 0 and tick 1 are two back-to-back
            # structural deep-scans (see the tick_counter==1 branch just
            # below -- tick 1 runs immediately, no sleep, precisely
            # because it's really "Phase 2/2" of one logical first-run
            # scan, not a separate cycle) -- confirmed live (2026-09-02,
            # v3.8.4 real-user testing) that the UI's tick-lock overlay
            # was unlocking mid-way through tick 1, before this second
            # phase had actually finished, because is_populated (a live
            # "does more than 1 node exist right now" query) could
            # already be true partway through tick 1's own unification/
            # inference steps. Persisting a one-time flag exactly when
            # tick_counter first reaches 2 -- both phases now genuinely
            # complete -- and having /api/status read THAT instead of
            # re-querying node counts live, cleanly covers both cases
            # the live-query approach conflated: a fresh install (this
            # flag is unset, so is_populated stays false and the UI
            # correctly stays locked until tick 2, no matter how many
            # nodes transiently exist before then) and a restart of an
            # already-configured appliance (this flag was already set
            # from before the restart, so is_populated is true
            # immediately even though tick_counter itself resets to 0/1
            # again -- the UI never re-locks over data that already
            # exists).
            if tick_counter == 2 and str(config._get_setting("_INITIAL_DISCOVERY_COMPLETE", "false")).lower() != "true":
                config._set_setting("_INITIAL_DISCOVERY_COMPLETE", "true")

            # Community Telemetry Pipeline (design doc S11): fires once
            # per process boot, when the tick-10 log-sample capture
            # window closes. Wrapped in to_thread -- this does a
            # network.db query, a log-file read + regex scrub, and up
            # to 3 blocking HTTP calls (the handshake), heavier than
            # the simple maybe_send_telemetry_heartbeat call above and
            # not worth blocking the event loop for. Cherry-picked from
            # main -- see that commit for why the guard flag exists
            # (not just tick_counter == 10, since FORCE_TOPOLOGY_REBUILD
            # resetting tick_counter to 0 could otherwise re-fire it).
            if tick_counter == 10 and not telemetry_tick10_fired:
                telemetry_tick10_fired = True
                await asyncio.to_thread(
                    telemetry_scheduler.on_tick_10, config, config.DB_PATH, telemetry_log_capture_start_offset
                )

            if tick_counter == 1:
                logger.info("--- Tick 0 Complete. Immediately launching Tick 1 to finalize initialization... ---")
            else:
                logger.info("--- Discovery Cycle Complete. Sleeping for 60s ---")
                await asyncio.sleep(60)
        except asyncio.CancelledError: break
        except Exception as e:
            logger.error(f"Error in polling engine: {e}")
            await asyncio.sleep(10)

def rotate_database():
    if not config.DB_ARCHIVE_ON_BOOT:
        logger.info("[*] Persistent Mode Active: Retaining existing network artifact database.")
        return

    db_path = config.DB_PATH
    if os.path.exists(db_path):
        archive_dir = os.path.join(os.path.dirname(db_path), "archives")
        os.makedirs(archive_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_path = os.path.join(archive_dir, f"network_{timestamp}.db")
        try:
            for ext in ['', '-wal', '-shm']:
                target = db_path + ext
                if os.path.exists(target):
                    shutil.copy2(target, archive_path + ext)
                    os.remove(target)
            logger.info(f"[*] Clean Slate: Artifact database safely archived to {archive_path} and purged.")
            # NATIVE-15's own comment (server.py's is_populated block)
            # already documented this as the design -- "resets it
            # whenever Clean Slate purges network.db" -- but the actual
            # reset call was never present in this function. Found live
            # 2026-09-08: _INITIAL_DISCOVERY_COMPLETE lives in config.db,
            # a completely different file this function never otherwise
            # touches, so once ANY boot ever completed initial discovery
            # once, the flag survived every later purge forever --
            # including a version-bump boot that just wiped ALL real
            # topology, unlocking the dashboard at tick 0 over empty
            # data. Only reset on a CONFIRMED successful purge (inside
            # this try, after the archive succeeded) -- a failed/partial
            # purge leaves the flag matching whatever data might still
            # actually be there, not a guess.
            config._set_setting("_INITIAL_DISCOVERY_COMPLETE", "false")
        except Exception as e:
            logger.error(f"Failed to rotate database: {e}")

_WINDOWS_FIREWALL_RULE_NAME = "NetLanvas Remote Web Viewing"


def _install_windows_proactor_exception_filter() -> None:
    """
    NATIVE-14: filters a well-known, purely cosmetic Windows asyncio
    noise pattern out of the logs users actually see -- confirmed live
    via the Settings page's own "Live System Logs" stream, which surfaces
    backend log output directly to the user, not just a file nobody
    reads. A client connection resetting abruptly (a browser tab
    closing, a keep-alive timing out -- completely normal, happens on
    every platform) makes Windows' ProactorEventLoop internals raise an
    unhandled ConnectionResetError ([WinError 10054]) from its own
    _call_connection_lost cleanup callback, BEFORE the close callback
    it was about to invoke ever runs -- asyncio's default handler then
    logs this as a scary "Exception in callback" ERROR, even though the
    connection genuinely was just closing normally, not failing. This
    is a documented CPython/asyncio-on-Windows quirk (multiple upstream
    bug reports for the same root cause), not specific to anything in
    this codebase.

    Deliberately NOT switching to WindowsSelectorEventLoopPolicy, the
    other commonly-suggested workaround: that policy doesn't support
    `asyncio.create_subprocess_exec` on Windows at all, which the SNMP
    and ping-sweep helper subprocess calls both depend on -- would trade
    one cosmetic problem for a real functional regression. A scoped
    exception-handler filter is the correct fix for exactly this
    situation, not a full event-loop-policy change.

    Only ever installed on Windows (see call site) -- ProactorEventLoop,
    and this exact bug, are Windows-specific; nothing to filter
    elsewhere. Anything that ISN'T this specific known pattern still
    reaches the loop's default handler unchanged, so a genuinely new
    kind of error is never silently swallowed.

    Rate-limited to one log line per NOISE_LOG_INTERVAL_SECONDS (with a
    count of how many were swallowed in between) rather than one line
    per occurrence -- confirmed live (2026-09-02, real Windows install)
    that with a dashboard tab genuinely open, ordinary browser
    keep-alive cycling triggers this pattern in bursts of 2-4 every
    10-15s, continuously, for as long as the tab stays open. The
    original per-occurrence version already fixed the scary part (a raw
    traceback in Live System Logs), but on its own is still a live-log
    panel that never stops scrolling with the same benign line -- worse
    for actually spotting a real problem, not better. Still logged, not
    dropped outright: the Live System Logs stream is meant to surface
    real backend activity (see this function's own opening comment), so
    silence forever would just trade one kind of user confusion for
    another ("why did it stop logging anything").
    """
    loop = asyncio.get_running_loop()
    default_handler = loop.get_exception_handler()

    NOISE_LOG_INTERVAL_SECONDS = 60
    _noise_state = {"count": 0, "last_logged": 0.0}

    def _filtering_handler(loop, context):
        exc = context.get("exception")
        if (
            isinstance(exc, ConnectionResetError)
            and context.get("handle") is not None
            and "_call_connection_lost" in repr(context.get("handle"))
        ):
            _noise_state["count"] += 1
            now = time.monotonic()
            if now - _noise_state["last_logged"] >= NOISE_LOG_INTERVAL_SECONDS:
                logger.debug(
                    f"[*] Suppressed {_noise_state['count']} benign Windows ProactorEventLoop "
                    f"connection-reset event(s) in the last "
                    f"{'~60s' if _noise_state['last_logged'] else 'moment'} "
                    f"(most recent: {exc})"
                )
                _noise_state["count"] = 0
                _noise_state["last_logged"] = now
            return
        if default_handler is not None:
            default_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_filtering_handler)


def _sync_windows_firewall_rule(enabled: bool, port: int) -> None:
    """
    NATIVE-13 follow-up: binding uvicorn to 0.0.0.0 does nothing on its
    own -- Windows Defender Firewall has no inbound allow rule for this
    app by default, so a LAN client's connection is silently dropped
    even though `netstat` shows the app correctly LISTENING on all
    interfaces (confirmed live: exactly this symptom on a real Windows
    box before this was added -- app up, port bound, still unreachable
    from another machine).

    The installer (packaging/windows/netlanvas.iss) pre-creates this
    same-named rule at install time, disabled (enable=no) -- visible/
    auditable as an explicit install-time action rather than a
    background service silently opening a firewall port with no
    user-facing step. This just flips that rule's enabled state to
    match the Settings toggle on every boot (idempotent, and the port
    is configurable so it needs re-syncing anyway). Falls back to
    creating the rule outright if `set rule` reports it doesn't exist
    -- covers an in-place binary swap over an install predating this
    feature, without depending on the installer having run again.
    """
    if platform.system() != "Windows":
        return  # macOS gets its own mechanism when Phase 6 packaging gets there
    enable_flag = "yes" if enabled else "no"
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "set", "rule",
             f"name={_WINDOWS_FIREWALL_RULE_NAME}", "new", f"enable={enable_flag}"],
            capture_output=True, timeout=5, text=True,
        )
        if result.returncode != 0:
            # Rule doesn't exist yet (e.g. binary swapped in place over
            # a pre-NATIVE-13 install without re-running the installer)
            # -- create it directly in the desired state instead.
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={_WINDOWS_FIREWALL_RULE_NAME}", "dir=in", "action=allow",
                 "protocol=TCP", f"localport={port}", f"enable={enable_flag}"],
                capture_output=True, timeout=5, check=True,
            )
        logger.info(f"[*] Windows Firewall: inbound rule for TCP {port} {'enabled' if enabled else 'disabled'}.")
    except Exception as e:
        logger.warning(f"[!] Could not sync Windows Firewall rule for remote web viewing: {e}")


# ==============================================================================
# 3. ORCHESTRATOR / ROLE ROUTER
# ==============================================================================
async def main():
    # ==========================================================================
    # NATIVE-1: standalone process merge (Windows/macOS native port, Phase 1)
    # ==========================================================================
    # This branch is keyed off NETLANVAS_MODE, not NETLANVAS_ROLE -- native
    # mode ignores the container role split entirely (there's only ever one
    # process), so it's kept as its own top-level branch rather than a third
    # value threaded through the POLLER/API_VIEWER logic below.
    if NETLANVAS_MODE == "native":
        if platform.system() == "Windows":
            _install_windows_proactor_exception_filter()
        logger.info("Booting Netlanvas NATIVE Service (standalone, single process)...")
        rotate_database()
        init_db()
        apply_db_hardening(config.DB_PATH)
        init_alerting_db()
        init_inventory_db()
        init_auth_db()
        init_registration_db()
        send_first_boot_telemetry(config)
        await stage_oui_maintenance()

        # NATIVE-18 (2026-09-16): everything from here down used to run
        # once and then `return` out of main() on a RESTART, relying on
        # WinSW/launchd to notice the process exited and relaunch it.
        # Proven wrong on real hardware, not assumed: Windows' own
        # Application Event Log (source "NetLanvas", written by WinSW
        # directly -- far more reliable than piecing this together from
        # the app's own text log) shows every single RESTART-triggered
        # exit on a real Windows test box -- five for five, including one with a
        # nonzero exit code -- logged only as "Child process finished
        # with N" and NEVER followed by an automatic restart. Windows'
        # System event log confirms SCM never even saw these as
        # failures (zero 7031 "terminated unexpectedly" events across
        # the whole history) -- WinSW's <onfailure> covers WinSW's own
        # process crashing, not its wrapped child exiting cleanly, no
        # matter the exit code. The BUG-25b <resetfailure> change and
        # this function's own older comment below (now corrected) were
        # both built on the wrong theory as a result -- the failure
        # counter was never the blocker, because SCM never attempted
        # recovery in the first place.
        #
        # macOS's launchd has the same practical gap via a different
        # mechanism: per Apple's own launchd.plist documentation,
        # KeepAlive's SuccessfulExit=false (what com.netlanvas.daemon
        # .plist uses) relaunches ONLY on a NONZERO exit -- a clean
        # RESTART return (the common case here, exit code 0) would
        # count as "successful" and would NOT be relaunched either.
        # Not yet confirmed live on real Mac hardware the way the
        # Windows numbers above are, but the documented semantics point
        # the same direction, and there's no reason to assume otherwise
        # untested.
        #
        # Rather than chase either platform's service-supervisor
        # semantics further, RESTART is now handled entirely IN this
        # process: loop back and rebuild the server instead of exiting
        # and hoping something else notices. This makes the OS-level
        # supervisor (WinSW/launchd) irrelevant to RESTART entirely --
        # it's only ever needed again if this process dies for a real
        # reason (an actual crash, or the timeout/os._exit(1) fallback
        # below for a wedged shutdown), which is the scenario those
        # supervisors were always meant to cover.
        while True:
            # NATIVE-13: TLS is now ALWAYS generated and served in native
            # mode, not only when "Enable remote web viewing" is on --
            # netlanvas.com's own device-registration flow (register.php)
            # requires an https:// callback URL unconditionally, including
            # for a plain localhost target (confirmed against its actual
            # source: no localhost/private-IP exemption from the https
            # requirement exists there, only from a SEPARATE later check).
            # A native install stuck on plain HTTP could therefore never
            # complete registration at all, regardless of this toggle --
            # this was the actual bug that surfaced the need for this whole
            # feature. The self-signed cert's browser warning is the same
            # one-time "verify this fingerprint" UX the container path
            # already documents; this doesn't change based on the toggle.
            # The toggle controls ONLY which interface gets bound below
            # (127.0.0.1 vs 0.0.0.0) -- i.e. whether anything other than
            # this machine can reach it, not whether TLS exists.
            remote_access_enabled = False
            try:
                ra_conn = sqlite3.connect(config.CONFIG_DB_PATH)
                row = ra_conn.execute(
                    "SELECT setting_value FROM app_settings WHERE setting_key = 'NATIVE_REMOTE_ACCESS_ENABLED'"
                ).fetchone()
                ra_conn.close()
                remote_access_enabled = bool(row) and str(row[0]).lower() in ("true", "1", "yes")
            except Exception as e:
                logger.warning(f"[!] Could not read remote-access setting, defaulting to localhost-only: {e}")

            lan_ip = detect_own_lan_ip()
            fingerprint = ensure_certificate(extra_sans_csv=lan_ip or "")
            _sync_windows_firewall_rule(remote_access_enabled, int(os.getenv("NETLANVAS_PUBLIC_PORT", "8899")))

            if not config.DEMO_MODE:
                try:
                    identity_conn = sqlite3.connect(config.CONFIG_DB_PATH)
                    device_identity.ensure_device_identity(identity_conn)
                    identity_conn.close()
                except Exception as e:
                    logger.warning(f"[!] Could not prepare device registration identity: {e}")

                try:
                    setup_conn = sqlite3.connect(config.CONFIG_DB_PATH)
                    if not credentials_exist(setup_conn):
                        public_port = os.getenv("NETLANVAS_PUBLIC_PORT", "8899")
                        # NATIVE-13: native always serves TLS now (see above),
                        # so this reuses write_welcome_file() same as the
                        # container path, instead of the plain-HTTP-only
                        # setup card this used to write by hand.
                        setup_url = f"https://127.0.0.1:{public_port}/dashboard/settings.html"
                        if not WELCOME_PATH.exists():
                            token = generate_setup_token()
                            store_setup_token(setup_conn, token)
                            write_welcome_file(fingerprint, token, setup_url)
                        print_welcome_file()
                    setup_conn.close()
                except Exception as e:
                    logger.warning(f"[!] Could not prepare first-run setup token: {e}")

            # NATIVE-13: "Enable remote web viewing" (Settings page) controls
            # ONLY which interface gets bound -- TLS itself was already set
            # up unconditionally above (remote_access_enabled/fingerprint
            # computed earlier in this branch, before the setup-token block,
            # since that needed the fingerprint too). Localhost-only remains
            # the default per the standing design requirement that remote
            # access is always opt-in, never silent (see the punch list's
            # Native Localhost Design Requirement note) -- what changed here
            # is that "opt-in" now means "opt-in to being LAN-reachable",
            # not "opt-in to TLS existing at all".
            public_port = int(os.getenv("NETLANVAS_PUBLIC_PORT", "8899"))
            bind_host = "0.0.0.0" if remote_access_enabled else "127.0.0.1"
            logger.info("=" * 70)
            logger.info("TLS CERTIFICATE FINGERPRINT (SHA-256) -- verify this in your browser")
            logger.info("before accepting the certificate warning:")
            logger.info("  %s", fingerprint)
            if remote_access_enabled:
                logger.info("REMOTE WEB VIEWING ENABLED")
                if lan_ip:
                    logger.info("  Reachable at: https://%s:%s", lan_ip, public_port)
                else:
                    logger.warning("  Could not detect this machine's LAN IP -- check Settings once logged in.")
            else:
                logger.info("Remote web viewing is OFF -- only reachable from this machine.")
            logger.info("=" * 70)
            api_config = uvicorn.Config(
                "api.server:app",
                host=bind_host,
                port=public_port,
                log_level="info",
                ssl_certfile=str(CERT_PATH),
                ssl_keyfile=str(KEY_PATH),
            )
            server = uvicorn.Server(api_config)

            # NATIVE-13 fix: same process, same event loop -- the poll loop
            # runs as a background task, uvicorn as another. The ORIGINAL
            # comment here claimed "either one crashing takes the whole
            # process down (asyncio.gather's default behaviour)" -- true for
            # an actual exception, but asyncio.gather() only ever RETURNS
            # once ALL of its awaitables finish, so a *normal* return (e.g.
            # the RESTART-signal `break` in background_polling_engine()'s
            # own tick loop) left the polling task silently dead while
            # uvicorn kept serving forever on the OLD bind/TLS config --
            # meaning the Settings toggle above could never actually take
            # effect. asyncio.wait(FIRST_COMPLETED) is the correct
            # primitive for "either one ending should stop both": whichever
            # finishes first (normally or via exception) triggers cancelling
            # the other, and now (NATIVE-18, see above) that just ends this
            # loop iteration -- the outer `while True:` rebuilds both tasks
            # fresh on the next pass rather than ending the process.
            polling_task = asyncio.create_task(background_polling_engine())
            server_task = asyncio.create_task(server.serve())

            done, pending = await asyncio.wait(
                {polling_task, server_task}, return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
            # BUG-24: cancelling server_task while a live streaming response
            # (e.g. the Live Logs SSE endpoint) is in flight can wedge
            # Starlette's stacked @app.middleware("http") wrappers -- each one
            # is its own BaseHTTPMiddleware -- in a CancelledError/WouldBlock
            # loop that never actually resolves, confirmed live: without
            # this bound, the process never exits and the error log grows
            # unbounded (52MB in under 10 minutes) until something kills it
            # by hand. Bounding this wait can't regress the normal case
            # (nothing pending finishes near-instantly anyway; confirmed
            # live every real RESTART so far has completed well inside 5s,
            # this TimeoutError branch has never actually fired yet).
            #
            # NATIVE-18 caveat: os._exit(1) here still ends the whole OS
            # process, same as before -- and per NATIVE-18's finding above,
            # an exited process is NOT reliably relaunched by WinSW/launchd
            # either, so this specific fallback path (only the rare wedge
            # case, not a normal RESTART) can still leave the service down
            # same as pre-NATIVE-18. Not solved here: avoiding the exit
            # entirely (abandon the wedged task, try to rebuild the server
            # anyway) risks a bind conflict if the old socket hasn't
            # actually been released yet, which needs real testing against
            # a reproduced wedge before it's worth trusting over a known,
            # if imperfect, hard exit.
            try:
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=5.0)
            except asyncio.TimeoutError:
                logger.error("[!] Shutdown did not complete within 5s (likely a wedged streaming response mid-cancel) -- forcing exit; NOTE this process may not auto-restart, check manually.")
                os._exit(1)
            for t in done:
                exc = t.exception()
                if exc:
                    raise exc
            logger.info("[*] RESTART cycle complete -- rebinding with current settings (same process).")
            continue

    role = os.getenv("NETLANVAS_ROLE", "UNKNOWN").upper()

    if role == "POLLER":
        logger.info("Booting Netlanvas POLLER Service...")
        rotate_database()
        init_db()
        apply_db_hardening(config.DB_PATH)
        # config.db, not network.db -- POLLER needs this to exist before
        # the tick loop can read delivery settings when a new alert
        # fires. Idempotent (CREATE TABLE IF NOT EXISTS), safe to also
        # call from API_VIEWER's boot below -- the two containers don't
        # have a guaranteed start order, so neither can assume the other
        # already created it.
        init_alerting_db()
        init_inventory_db()
        send_first_boot_telemetry(config)
        await stage_oui_maintenance()
        await background_polling_engine()

    elif role == "API_VIEWER":
        logger.info("Booting Netlanvas API_VIEWER Service from server.py...")
        init_auth_db()
        init_registration_db()
        init_alerting_db()
        init_inventory_db()

        if config.DEMO_MODE:
            # Public read-only demo: no netlanvas_core, no Redis, no real
            # TLS cert (Apache/Cloudflare terminate HTTPS in front of
            # this container -- see docker-compose.demo.yaml), and no
            # setup wizard (security/middleware.py's DEMO_MODE check
            # bypasses auth entirely, so this dummy account is never
            # actually used to log in -- it only exists to satisfy
            # credentials_exist() and skip the first-run setup redirect).
            logger.info("[*] DEMO_MODE active -- skipping Caddy/TLS/setup-token bootstrap.")
            try:
                demo_conn = sqlite3.connect(config.CONFIG_DB_PATH)
                if not credentials_exist(demo_conn):
                    create_initial_user(demo_conn, "demo", str(uuid.uuid4()))
                    logger.info("[*] DEMO_MODE: seeded placeholder account (unreachable -- auth is bypassed).")
                demo_conn.close()
            except Exception as e:
                logger.warning(f"[!] DEMO_MODE: failed to seed placeholder account: {e}")
            config._set_setting("SETUP_COMPLETE", "true")

            api_config = uvicorn.Config("api.server:app", host="0.0.0.0", port=8000, log_level="warning")
            server = uvicorn.Server(api_config)
            await server.serve()
            return

        ensure_caddyfile()

        # Wait briefly for netlanvas_core to publish the host's real LAN
        # IP (see stage_publish_host_identity above). Both containers
        # start at roughly the same time -- core typically publishes
        # within a few seconds. If it never arrives, proceed anyway; the
        # cert's SAN-drift check will pick it up on the next restart.
        host_sans = ""
        for _ in range(15):
            try:
                val = await redis_client.get("HOST_TLS_SANS")
                if val:
                    host_sans = val
                    break
            except Exception:
                pass
            await asyncio.sleep(1)

        if not host_sans:
            logger.warning("[!] No host address published yet -- TLS certificate may not match the browser's address until netlanvas_api next restarts.")

        fingerprint = ensure_certificate(extra_sans_csv=host_sans)

        # Device registration identity (REG-1) -- generated eagerly at
        # boot, same convention as the TLS cert above, rather than lazily
        # on first use of /api/register/initiate.
        try:
            identity_conn = sqlite3.connect(config.CONFIG_DB_PATH)
            device_identity.ensure_device_identity(identity_conn)
            identity_conn.close()
        except Exception as e:
            logger.warning(f"[!] Could not prepare device registration identity: {e}")

        # First-run setup token -- see security/auth.py + security/welcome.py.
        # Closes the setup-claim race: whoever POSTs to /api/setup/password
        # first would otherwise win the admin account on a fresh install.
        # Requiring a token only ever displayed via docker logs/exec means
        # winning that race now requires host/console access, not just
        # network reachability.
        try:
            setup_conn = sqlite3.connect(config.CONFIG_DB_PATH)
            if not credentials_exist(setup_conn):
                primary_host = host_sans.split(",")[0].strip() if host_sans else "<this-host-ip>"
                public_port = os.getenv("NETLANVAS_PUBLIC_PORT", "8899")
                setup_url = f"https://{primary_host}:{public_port}/dashboard/settings.html"

                if not WELCOME_PATH.exists():
                    # No displayable token exists yet (first boot, or the
                    # file was lost some other way) -- generate one fresh.
                    # If it DOES exist, reuse it rather than generating a
                    # new one that would invalidate whatever the owner
                    # already copied down.
                    token = generate_setup_token()
                    store_setup_token(setup_conn, token)
                    write_welcome_file(fingerprint, token, setup_url)

                print_welcome_file()
            setup_conn.close()
        except Exception as e:
            logger.warning(f"[!] Could not prepare first-run setup token: {e}")

        # Internal port only -- Caddy is the sole host-published listener
        # (8899, TLS-only, see caddy/Caddyfile). This uvicorn instance is
        # reached solely via the internal netlanvas_internal bridge network.
        api_config = uvicorn.Config("api.server:app", host="0.0.0.0", port=8000, log_level="warning")
        server = uvicorn.Server(api_config)
        await server.serve()

    else:
        logger.error(f"CRITICAL: Invalid or missing NETLANVAS_ROLE detected ('{role}'). System aborting.")
        raise SystemExit(1)

if __name__ == "__main__":
    asyncio.run(main())
