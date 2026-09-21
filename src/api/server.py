import sqlite3
import os
import re
import json
import base64
import random
import uuid
import logging
import asyncio
import time
import ipaddress
import platform
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlencode
import redis.asyncio as aioredis
import requests
from fastapi import FastAPI, Query, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel
from engine.config_loader import config, SENSITIVE_SETTING_KEYS, DEFAULTS_PATH
from security.auth import (
    SESSION_COOKIE_NAME, credentials_exist, create_initial_user,
    verify_login, create_session, revoke_session,
    verify_setup_token, clear_setup_token,
)
from security.middleware import check_session
from security.welcome import delete_welcome_file, get_setup_token
from security.rate_limit import is_rate_limited, record_attempt, clear_attempts, get_client_ip
from security import device_identity, registration
from security.cert_manager import detect_own_lan_ip
from security.credential_vault import encrypt_password
from telemetry import payload_builder as telemetry_payload_builder
from telemetry import log_sampler as telemetry_log_sampler
from telemetry import scheduler as telemetry_scheduler
from telemetry import submitter as telemetry_submitter
from engine.alerting import SEVERITY_LEVELS
from engine.alert_dispatcher import _send_webhook, _send_webhook_ntfy, _send_email_smtp, _send_email_relay
from engine.auto_discovery import enumerate_host_network_interfaces
from engine.migrate_archive import ensure_archive_migrated

logger = logging.getLogger("Netlanvas.API")
app = FastAPI(title="Netlanvas Decoupled API", version="2.0")

# UI-2: Docker's own bridge-network auto-allocation lives in this exact
# range (each compose project on a Docker Host gets its own 172.x.0.0/16
# in sequence, starting at 172.17.0.0/16) -- see NET-2's identically-
# scoped constant in engine/auto_discovery.py. A device's own SNMP-
# reported "owned IPs" here are legitimate and needed for Docker Host
# classification (unification.py), but they're never a real LAN-facing
# address worth surfacing on a device card or, worse, using to decide
# which subnet section a device gets filed under on the dashboard --
# a multihomed Docker Host's real IP can easily lose that arbitrary
# "which IP came back first" contest to one of its own internal bridge
# addresses, making the device effectively unfindable under the subnet
# a user would actually look in. Filtered out of endpoint_ledger here,
# once, rather than in every page that renders it.
DOCKER_BRIDGE_RANGE = ipaddress.ip_network("172.16.0.0/12")


def _is_real_ip(ip: str | None) -> bool:
    """True for a genuinely dialable address -- excludes both Docker-
    bridge noise and a dark-matter inference's synthetic placeholder."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr not in DOCKER_BRIDGE_RANGE


def _filter_display_noise_ips(rows: list[dict]) -> list[dict]:
    """
    Nulls ip_address wherever it's never worth showing a human --
    Docker-bridge noise or a synthetic placeholder like the
    "10.10.10.10033"-style pseudo-address mac_table_scraper's dark-
    matter inference invents for an Unmanaged Switch it's inferred but
    never directly observed (last octet encodes a port number, not a
    real address -- fails ipaddress parsing outright).

    MUST run after _annotate_subnet_and_primary, not before: that
    function still needs the original (pre-null) value to derive which
    real subnet a pseudo-address's device is actually attached to --
    only the human-facing address text gets hidden here, not the
    subnet placement it implies. Nulls the field rather than dropping
    the row: a device whose ONLY binding is a bad address (exactly the
    dark-matter Unmanaged Switch case) would otherwise vanish from the
    ledger entirely instead of just losing an address it should never
    have shown. Row count is preserved either way. Safe regardless of
    order relative to topology edge resolution -- that reads
    infrastructure_links/l3_bindings directly via its own separate
    query in /api/topology, never through this filtered list.
    """
    for row in rows:
        if row.get("ip_address") and not _is_real_ip(row["ip_address"]):
            row["ip_address"] = None
    return rows


def _annotate_subnet_and_primary(rows: list[dict], conn) -> list[dict]:
    """
    UI-3: attaches `subnet` (this row's real subnet, router_subnets-
    confirmed where possible, else a derived /24 guess) and
    `is_primary_ip` to every row -- lets the UI show a multihomed
    device under every real subnet it belongs to, while still marking
    which one address is its main interface. Run BEFORE
    _filter_display_noise_ips -- see that function's docstring.

    Subnet derivation deliberately tolerates a dark-matter inference's
    synthetic pseudo-address (first three octets are the real subnet
    the inferred switch is attached to, only the last is a fake port-
    encoded value) -- an Unmanaged Switch known only by that pseudo-
    address should still be filed under the real subnet it's actually
    on, not hidden in "Layer 2 (No IP)" just because its one address
    fails strict parsing. Docker-bridge noise still gets no subnet at
    all, same as before.

    Primary-IP heuristic, most to least authoritative:
      1. The subnet whose VLAN matches this device's own PHYSICALLY
         observed VLAN (endpoint_locations.vlan_id -- real switch-port
         discovery, not just a self-reported address) wins outright.
      2. Failing that, prefer an untagged/native subnet (no vlan_id in
         router_subnets) over a VLAN-tagged one -- a reasonable default
         when there's no direct physical evidence either way.
      3. Failing that, the most recently seen row wins (today's
         previous behavior, kept as the last-resort tie-breaker).
    Applied uniformly to every device type, infrastructure included --
    a switch's own physically-confirmed VLAN is just as meaningful a
    "primary" address as an endpoint's. Only genuinely real addresses
    (see _is_real_ip) are ever eligible to be marked primary.
    """
    confirmed_networks: list[tuple[ipaddress.IPv4Network, object]] = []
    for subnet_text, vlan_id in conn.execute("SELECT subnet, vlan_id FROM router_subnets"):
        try:
            confirmed_networks.append((ipaddress.ip_network(subnet_text, strict=False), vlan_id))
        except ValueError:
            continue

    physical_vlan_by_mac = dict(
        conn.execute("SELECT mac_address, vlan_id FROM endpoint_locations WHERE vlan_id IS NOT NULL")
    )

    def subnet_and_vlan(ip: str):
        try:
            addr = ipaddress.ip_address(ip)
            if addr in DOCKER_BRIDGE_RANGE:
                return None, None
        except ValueError:
            parts = ip.split(".")
            if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts[:3]):
                return None, None
            addr = ipaddress.ip_address(f"{parts[0]}.{parts[1]}.{parts[2]}.1")
        for net, vlan_id in confirmed_networks:
            if addr in net:
                return str(net), vlan_id
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", None

    by_mac: dict[str, list[dict]] = {}
    for row in rows:
        ip = row.get("ip_address")
        subnet, vlan_id = subnet_and_vlan(ip) if ip else (None, None)
        row["subnet"] = subnet
        row["_vlan_id"] = vlan_id
        by_mac.setdefault(row.get("mac_address"), []).append(row)

    for mac, mac_rows in by_mac.items():
        candidates = [r for r in mac_rows if _is_real_ip(r.get("ip_address"))]
        if not candidates:
            continue
        physical_vlan = physical_vlan_by_mac.get(mac)
        primary_set = [r for r in candidates if physical_vlan is not None and r["_vlan_id"] == physical_vlan]
        if not primary_set:
            primary_set = [r for r in candidates if r["_vlan_id"] is None]
        if not primary_set:
            primary_set = [max(candidates, key=lambda r: r.get("last_seen") or "")]
        primary_ips = {r["ip_address"] for r in primary_set}
        for r in mac_rows:
            r["is_primary_ip"] = r.get("ip_address") in primary_ips

    for row in rows:
        row.pop("_vlan_id", None)
    return rows

@app.middleware("http")
async def no_cache_dashboard(request: Request, call_next):
    # The UI is actively iterated on and served from a single Pi with no
    # CDN in front of it -- there's nothing to gain from letting browsers
    # cache these files, and a stale cached copy of a page with polling
    # logic (e.g. index.html's tick-lock modal) fails silently: it keeps
    # running fine, just against old code, with no visible error to
    # explain why a shipped change doesn't show up.
    response = await call_next(request)
    if request.url.path.startswith("/dashboard"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response

app.mount("/dashboard", StaticFiles(directory=os.getenv("NETLANVAS_UI_DIR", "/app/src/ui"), html=True), name="dashboard")

# NATIVE-1: see the matching block in main.py -- same in-process shared
# store, same singleton object, selected the same way.
NETLANVAS_MODE = os.getenv("NETLANVAS_MODE", "container").lower()

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
    redis_client = aioredis.from_url(f"redis://{REDIS_HOST}:{REDIS_PORT}", password=REDIS_PASSWORD, decode_responses=True, socket_timeout=1.0)
ARCHIVE_DIR = os.path.join(os.path.dirname(config.DB_PATH), "archives")

# --- Public demo visit counter (DEMO_MODE only) ---
# Kept in its own tiny local file, entirely separate from the sanitized
# topology data -- purely an anonymous, cookie-based unique-visitor
# count for gauging demo traffic, nothing tied to any real identity.
DEMO_ANALYTICS_DB = os.path.join(os.path.dirname(config.DB_PATH), "demo_analytics.db")
DEMO_VISITOR_COOKIE = "demo_visitor"

def _init_demo_analytics():
    conn = sqlite3.connect(DEMO_ANALYTICS_DB)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS visits (
            visitor_id TEXT PRIMARY KEY,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            visit_count INTEGER DEFAULT 1
        )
    ''')
    conn.commit()
    conn.close()

if config.DEMO_MODE:
    _init_demo_analytics()

class PromotionRequest(BaseModel): node_id: int; target_type: str
class SettingUpdateRequest(BaseModel): key: str; value: str
class ContextActionRequest(BaseModel): node_id: int
class NodeUpdateRequest(BaseModel): node_id: int; hostname: str = None; device_type: str = None
class InventoryUpdateRequest(BaseModel):
    # DEVICE-1: None (the default, and the only value a field takes
    # when the caller's JSON simply omits the key) means "leave this
    # field alone" -- device.html's asset-details form saves
    # independently from its separate identity form and must not blank
    # out whatever the other one just set. An explicit "" means "clear
    # it", same as before. inventory.html's own combined form still
    # sends every field together every time, so this is invisible to
    # it -- same net effect, just no longer unconditional.
    mac_address: str
    user_given_name: str | None = None
    confirmed_device_type: str | None = None
    notes: str | None = None
    location: str | None = None
    asset_tag: str | None = None
    serial_number: str | None = None
    model: str | None = None
    purchase_date: str | None = None
    warranty_expiry: str | None = None
class BugReportRequest(BaseModel): message: str = ""; screenshot_b64: str
class ArchiveAnnotateRequest(BaseModel): filename: str; location: str = ""; notes: str = ""
class ArchiveDeleteRequest(BaseModel): filename: str
class LoginRequest(BaseModel): username: str; password: str
class SetupPasswordRequest(BaseModel): username: str; password: str; setup_token: str
class RemoteAccessRequest(BaseModel): enabled: bool
class SNMPv3IdentityCreateRequest(BaseModel): username: str; password: str; priv_password: str
class SNMPv3ReorderRequest(BaseModel): ordered_ids: list[int]
class VlanNameUpdateRequest(BaseModel): vlan_id: int; vlan_name: str
class AlertingConfigRequest(BaseModel):
    email_enabled: bool = False
    email_delivery_method: str = "relay"
    email_min_severity: str = "medium"
    email_to_address: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    smtp_from_address: str | None = None
    webhook_enabled: bool = False
    webhook_url: str | None = None
    webhook_min_severity: str = "medium"
    webhook_format: str = "json"

# ALERT-5: user-configurable severity overrides. Deliberately just four
# flat settings (not a generic per-alert-type table) -- these are the
# only severities that were ever hardcoded to begin with (see
# device_state_tracker.py/snmp_default_community_detector.py); every
# other alert type's severity (new_device/device_online/flapping) is
# fixed at info/low by design, not something a user would want to raise.
class SeverityConfigRequest(BaseModel):
    offline_router: str = "critical"
    offline_infrastructure: str = "high"
    offline_endpoint: str = "low"
    snmp_exposure: str = "high"
    snmp_v3_unused: str = "medium"

def get_db_connection(archive_file: str = None):
    db_path = config.DB_PATH
    is_archive = False
    
    if archive_file:
        safe_file = os.path.basename(archive_file)
        db_path = os.path.join(ARCHIVE_DIR, safe_file)
        is_archive = True
        
    if not os.path.exists(db_path): 
        raise HTTPException(status_code=404, detail=f"Database target not found: {db_path}")
        
    if is_archive:
        ensure_archive_migrated(db_path)
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
    else:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        
    conn.row_factory = sqlite3.Row
    return conn

def get_config_db_connection():
    if not hasattr(config, 'CONFIG_DB_PATH') or not os.path.exists(config.CONFIG_DB_PATH):
        raise HTTPException(status_code=404, detail="Config Database not found.")
    conn = sqlite3.connect(config.CONFIG_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def mask_credential(val):
    val_str = str(val)
    if len(val_str) <= 4: return "****"
    return f"{val_str[:2]}********{val_str[-2:]}"

def _load_allowed_setting_keys() -> set:
    keys = set()
    try:
        with open(DEFAULTS_PATH, 'r') as f:
            keys = set(json.load(f).keys())
    except Exception as e:
        logger.error(f"[SETTINGS] Failed to load defaults.json for settings allowlist: {e}")
    # FORCE_TOPOLOGY_REBUILD is a legitimate operational flag written by
    # the "Rebuild Topology" button, but is deliberately never seeded in
    # defaults.json (see main.py's admin-override listener, which only
    # ever reads/clears it) -- it must be explicitly allowed here or
    # that feature breaks.
    keys.add("FORCE_TOPOLOGY_REBUILD")
    return keys

ALLOWED_SETTING_KEYS = _load_allowed_setting_keys()

# Enforced server-side, not just hidden client-side (settings.html's own
# readonlyKeys list was previously the ONLY thing stopping a direct
# curl/API write to these -- see punch list S4). IEEE_OUI_URL is
# deliberately NOT included here: it stays read-only in the current UI
# for now, but the API path is kept open so it can be updated later
# (e.g. pointed at a future alternate OUI source) without a code change.
READONLY_SETTING_KEYS = {
    "LOGIN_COUNT", "INSTANCE_ID", "HTTP_USER_AGENT",
    # Internal polling-schedule state, only ever written by main.py's tick
    # loop or the dedicated /api/polling/start endpoint below -- not a
    # plain user-facing setting.
    "_POLLING_ACTIVE", "_POLLING_STARTED_AT", "_POLLING_PAUSED_AT",
}

@app.middleware("http")
async def demo_visit_counter(request: Request, call_next):
    """
    Counts a "visit" once per top-level SPA shell load (index.html),
    not per request -- the UI polls /api/status every 2s while a tab is
    open, so hooking every request would massively over-count and hit
    this DB constantly for no reason. A long-lived anonymous cookie
    (no login, unrelated to the real session cookie) identifies repeat
    visitors across days without anything tied to a real identity.
    """
    response = await call_next(request)
    if config.DEMO_MODE and request.method == "GET" and request.url.path in ("/dashboard/", "/dashboard/index.html"):
        visitor_id = request.cookies.get(DEMO_VISITOR_COOKIE)
        is_new_visitor = visitor_id is None
        if is_new_visitor:
            visitor_id = str(uuid.uuid4())
            response.set_cookie(DEMO_VISITOR_COOKIE, visitor_id, max_age=5 * 365 * 86400, httponly=True, samesite="lax")
        try:
            conn = sqlite3.connect(DEMO_ANALYTICS_DB)
            conn.execute('''
                INSERT INTO visits (visitor_id) VALUES (?)
                ON CONFLICT(visitor_id) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    visit_count = visit_count + 1
            ''', (visitor_id,))
            conn.commit()
            if is_new_visitor:
                total = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
                logger.info(f"[DEMO] New unique visitor (total unique: {total}).")
            conn.close()
        except Exception as e:
            logger.debug(f"[DEMO] Visit tracking failed: {e}")
    return response

@app.middleware("http")
async def demo_read_only(request: Request, call_next):
    """
    Public read-only demo deployment (see engine/config_loader.py's
    DEMO_MODE docstring): blocks every mutating request under /api/ up
    front, before it ever reaches a route handler -- so this covers any
    write route that exists today AND any added later, with nothing
    per-route to remember. GET/HEAD/OPTIONS pass through untouched.
    """
    if config.DEMO_MODE and request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        return JSONResponse(status_code=403, content={"detail": "This is a live read-only demo -- changes aren't saved."})
    return await call_next(request)

@app.middleware("http")
async def auth_gate(request: Request, call_next):
    """
    Runs for every request, including ones bound for the /dashboard
    static mount above -- ASGI middleware wraps the whole app, mounts
    included. It only actually rejects requests whose path starts with
    /api/ (see path_requires_auth in security/middleware.py); everything
    else, including login.html and auth-guard.js themselves, passes
    through untouched.
    """
    unauthorized = await check_session(request, get_config_db_connection)
    if unauthorized is not None:
        return unauthorized
    return await call_next(request)

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}

@app.get("/api/demo/stats")
async def demo_stats():
    if not config.DEMO_MODE:
        raise HTTPException(status_code=404)
    conn = sqlite3.connect(DEMO_ANALYTICS_DB)
    unique_visitors = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
    total_visits = conn.execute("SELECT COALESCE(SUM(visit_count), 0) FROM visits").fetchone()[0]
    last_7d = conn.execute("SELECT COUNT(*) FROM visits WHERE last_seen >= datetime('now', '-7 days')").fetchone()[0]
    conn.close()
    return {"unique_visitors": unique_visitors, "total_visits": total_visits, "active_last_7_days": last_7d}

@app.get("/api/setup/status")
async def setup_status():
    try:
        conn = get_config_db_connection()
        complete = credentials_exist(conn)
        conn.close()
        response = {"setup_complete": complete}
        # NATIVE-9: native mode has no `docker logs` equivalent for a
        # fresh-install user to find the setup token -- safe to hand it
        # straight to the setup page here since native binds 127.0.0.1
        # only (see security/welcome.py's get_setup_token() docstring).
        # Never do this on the container path, where this route can be
        # LAN-reachable via Caddy.
        if not complete and NETLANVAS_MODE == "native":
            response["setup_token"] = get_setup_token()
        return response
    except Exception as e:
        # Fail toward "not complete" rather than leaking an error state
        # that could strand the frontend's setup gate. Unauthenticated
        # route -- the raw exception text stays server-side only.
        logger.error(f"[SETUP] /api/setup/status failed: {e}")
        return {"setup_complete": False}

SETUP_TOKEN_MAX_ATTEMPTS = 10
SETUP_TOKEN_WINDOW_SECONDS = 15 * 60

@app.post("/api/setup/password")
async def setup_password(req: SetupPasswordRequest, request: Request):
    client_ip = get_client_ip(request)
    conn = get_config_db_connection()
    try:
        if credentials_exist(conn):
            raise HTTPException(status_code=403, detail="Setup already complete.")

        if is_rate_limited(client_ip, "setup_token", SETUP_TOKEN_MAX_ATTEMPTS, SETUP_TOKEN_WINDOW_SECONDS):
            logger.warning(f"[SETUP] Rate limit exceeded for setup-token attempts from {client_ip}.")
            raise HTTPException(
                status_code=429,
                detail="Too many attempts. Try again later.",
                headers={"Retry-After": str(SETUP_TOKEN_WINDOW_SECONDS)},
            )

        if not verify_setup_token(conn, req.setup_token):
            # Deliberately distinct from "already complete" above -- a
            # wrong/missing token is very likely a typo by the legitimate
            # owner, not someone else winning a race, and conflating the
            # two messages would be actively misleading for that common
            # case. The token's entropy (not message ambiguity) is what
            # actually prevents guessing it.
            record_attempt(client_ip, "setup_token", SETUP_TOKEN_WINDOW_SECONDS)
            logger.warning(f"[SETUP] Failed setup-token attempt from {client_ip}.")
            if NETLANVAS_MODE == "native":
                token_hint = "It should already be filled in above -- reload this page to fetch it again."
            else:
                token_hint = ("Check `docker logs netlanvas_api` or "
                               "`docker exec netlanvas_api cat /app/tls/welcome.txt`.")
            raise HTTPException(
                status_code=403,
                detail=f"Invalid setup token. {token_hint}",
            )
        username = req.username.strip()
        if not username:
            raise HTTPException(status_code=400, detail="Username cannot be blank.")
        if len(req.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
        create_initial_user(conn, username, req.password)
        clear_setup_token(conn)
        delete_welcome_file()
        clear_attempts(client_ip, "setup_token")
        logger.info(f"[SETUP] Initial admin account '{username}' created from {client_ip}.")
        return {"success": True}
    finally:
        conn.close()

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60

def _log_safe(value: str) -> str:
    """Strip C0 control characters (including CR/LF) from a value before it is
    interpolated into a log message, preventing log-injection/forgery via
    unauthenticated user input."""
    return "".join(ch for ch in value if ord(ch) >= 0x20)

@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    client_ip = get_client_ip(request)
    username = req.username.strip()

    if is_rate_limited(client_ip, "login", LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS):
        logger.warning(f"[AUTH] Rate limit exceeded for login from {client_ip}.")
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(LOGIN_WINDOW_SECONDS)},
        )

    conn = get_config_db_connection()
    try:
        user_id = verify_login(conn, username, req.password)
        if user_id is None:
            record_attempt(client_ip, "login", LOGIN_WINDOW_SECONDS)
            logger.warning(f"[AUTH] Failed login attempt for username '{_log_safe(username)}' from {client_ip}.")
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        clear_attempts(client_ip, "login")
        logger.info(f"[AUTH] Successful login for username '{_log_safe(username)}' from {client_ip}.")

        token, expires_at = create_session(conn, user_id)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            httponly=True,
            # NATIVE-5, superseded by NATIVE-13: container mode is
            # always HTTPS externally (Caddy terminates TLS in front of
            # it -- uvicorn itself only ever sees plain HTTP from Caddy
            # over the internal bridge network, so checking the
            # request's own scheme here would be wrong for that path
            # too). Native mode ALSO now always serves real TLS
            # unconditionally (NATIVE-13 -- see main.py's NATIVE branch;
            # netlanvas.com's own device-registration flow requires an
            # https:// callback regardless of the remote-access toggle,
            # so plain HTTP was never actually viable here even for the
            # localhost-only default). Both paths are HTTPS-terminated
            # now, so this is unconditionally True -- no mode check
            # needed. (Originally NATIVE-5 set this False for native
            # when that mode really was plain-HTTP-only; a Secure cookie
            # over plain HTTP is a real bug -- browsers silently refuse
            # to send it back -- but that premise no longer holds.)
            secure=True,
            # BUG, found live 2026-09-17: "strict" silently dropped this
            # cookie on exactly the navigation patterns this app relies
            # on -- auth-guard.js's own client-side window.location.href
            # reframe of a directly-hit subpage back into
            # index.html?page=..., and the post-login redirect into the
            # app itself, are the kind of same-site-but-not-a-direct-
            # link navigation Strict is designed to be stricter about
            # than Lax. Real symptom: GET /api/settings came back 401
            # on an otherwise fully successful, seconds-old login,
            # which then hung bootstrapApp() forever (auth-guard.js's
            # own 401 handler redirects and returns a promise that
            # never resolves), silently skipping everything after that
            # fetch on every single page load. DEMO_VISITOR_COOKIE
            # above already uses "lax" -- this is the one outlier, not
            # a deliberate stricter choice for session auth specifically.
            samesite="lax",
            max_age=int((expires_at - datetime.now(timezone.utc)).total_seconds()),
        )
        return {"success": True}
    finally:
        conn.close()

@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    client_ip = get_client_ip(request)
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        conn = get_config_db_connection()
        try:
            revoke_session(conn, token)
        finally:
            conn.close()
    logger.info(f"[AUTH] Logout from {client_ip}.")
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"success": True}

# --- Device registration / entitlement (see punch list REG-1..4, ACCT-3/4/7) ---
#
# REG-2 (initiate) sits behind the normal session gate -- only a logged-in
# admin may start this. REG-3 (callback) is unauthenticated by necessity
# (see middleware.py's UNAUTHENTICATED_API_PATHS comment) -- its real
# authorization is the single-use local_state token, not a cookie.

REGISTER_INITIATE_MAX_ATTEMPTS = 10
REGISTER_INITIATE_WINDOW_SECONDS = 15 * 60
REGISTER_CALLBACK_MAX_ATTEMPTS = 20
REGISTER_CALLBACK_WINDOW_SECONDS = 15 * 60

@app.post("/api/register/initiate")
async def register_initiate(request: Request):
    client_ip = get_client_ip(request)
    if is_rate_limited(client_ip, "register_initiate", REGISTER_INITIATE_MAX_ATTEMPTS, REGISTER_INITIATE_WINDOW_SECONDS):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.",
                             headers={"Retry-After": str(REGISTER_INITIATE_WINDOW_SECONDS)})

    conn = get_config_db_connection()
    try:
        public_key_b64 = device_identity.ensure_device_identity(conn)
        device_uuid = config._get_setting("INSTANCE_ID")
        if not device_uuid:
            raise HTTPException(status_code=500, detail="INSTANCE_ID not yet generated -- try again shortly.")

        local_state = registration.generate_state_token(conn)

        primary_host = os.getenv("NETLANVAS_PUBLIC_HOST", request.url.hostname or "")
        public_port = os.getenv("NETLANVAS_PUBLIC_PORT", "8899")
        # https unconditionally -- this was briefly made conditional on
        # NETLANVAS_MODE (NATIVE-11) after a native-only ERR_SSL_PROTOCOL_ERROR
        # was traced here, but that fix was wrong: netlanvas.com's own
        # register.php REQUIRES an https:// redirect_uri unconditionally
        # (no localhost/private-IP exemption from that check exists,
        # confirmed against its actual source), so a plain-http callback
        # would have been rejected server-side even after "fixing" it
        # here. The real fix is NATIVE-13: native mode now always serves
        # real TLS too (not only when remote access is toggled on), so
        # https is correct unconditionally for both paths -- see
        # main.py's NATIVE branch and NATIVE-5's cookie fix, which had
        # the same premise corrected for the same reason.
        callback_url = f"https://{primary_host}:{public_port}/api/register/callback"

        params = {
            "device_uuid": device_uuid,
            "pubkey": public_key_b64,
            "local_state": local_state,
            "redirect_uri": callback_url,
        }
        redirect_url = f"{registration.BACKEND_BASE_URL}/register.php?{urlencode(params)}"
        return {"redirect_url": redirect_url}
    finally:
        conn.close()

@app.get("/api/register/callback")
async def register_callback(request: Request, challenge: str = "", local_state: str = ""):
    client_ip = get_client_ip(request)
    if is_rate_limited(client_ip, "register_callback", REGISTER_CALLBACK_MAX_ATTEMPTS, REGISTER_CALLBACK_WINDOW_SECONDS):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.",
                             headers={"Retry-After": str(REGISTER_CALLBACK_WINDOW_SECONDS)})

    if not challenge or not local_state:
        record_attempt(client_ip, "register_callback", REGISTER_CALLBACK_WINDOW_SECONDS)
        raise HTTPException(status_code=400, detail="Missing challenge or local_state.")

    conn = get_config_db_connection()
    try:
        if not registration.verify_and_consume_state_token(conn, local_state):
            record_attempt(client_ip, "register_callback", REGISTER_CALLBACK_WINDOW_SECONDS)
            logger.warning(f"[REGISTER] Invalid/expired local_state presented from {client_ip}.")
            raise HTTPException(status_code=401, detail="This registration attempt has expired. Please start again.")

        device_uuid = config._get_setting("INSTANCE_ID")
        public_key_b64 = device_identity.ensure_device_identity(conn)

        try:
            result = registration.complete_registration(device_uuid, public_key_b64, challenge)
        except Exception as e:
            logger.warning(f"[REGISTER] Backend registration call failed: {e}")
            raise HTTPException(status_code=502, detail="Could not reach the registration backend. Please try again.")

        registration.store_entitlement_cache(
            conn,
            account_linked=bool(result.get("success")),
            entitled=bool(result.get("entitled", False)),
            raw_response_json=json.dumps(result),
        )
        if result.get("success"):
            # Existing settings.html UI already renders a Registered
            # badge vs. a Register button off this flag (predates this
            # feature -- was a placeholder toggle, see punch list ACCT-4).
            # Keep it working rather than adding a second status source.
            config._set_setting("IS_REGISTERED", "true")
        if result.get("telemetry_preference") is True:
            # register-complete.php only ever sends this key for a
            # brand-new device_uuid, and only when true (the account has
            # an already-expressed "yes" on another device) -- never
            # false/absent, so there's nothing to do in those cases. A
            # relink, or an account with no/negative preference, leaves
            # whatever this install's setup flow already chose alone.
            config._set_setting("SUBMIT_TELEMETRY", "true")
        clear_attempts(client_ip, "register_callback")
        logger.info(f"[REGISTER] Device registration completed for {device_uuid}.")
        return RedirectResponse(url="/dashboard/settings.html?registered=1", status_code=303)
    finally:
        conn.close()

ENTITLEMENT_REFRESH_THRESHOLD_SECONDS = 6 * 3600

@app.get("/api/register/entitlement")
async def register_entitlement_status(request: Request):
    """
    Returns the cached entitlement snapshot, refreshing it first if it's
    stale (or missing) and the device is registered. Check-on-read rather
    than a periodic background job in main.py's poller loop, because that
    loop runs in netlanvas_core, which has no ./tls volume mount (only
    this API container does) -- the poller has no way to read the device
    identity key that signs the assertion check_entitlement() needs. A
    failed live check just falls back to whatever's cached rather than
    surfacing an error to the settings page.
    """
    conn = get_config_db_connection()
    try:
        is_registered = config._get_setting("IS_REGISTERED", "false")
        if str(is_registered).lower() in ("true", "1", "yes"):
            cached = registration.get_entitlement_cache(conn)
            stale = True
            if cached and cached.get("checked_at"):
                try:
                    checked_at = datetime.fromisoformat(cached["checked_at"])
                    stale = (datetime.now(timezone.utc) - checked_at).total_seconds() > ENTITLEMENT_REFRESH_THRESHOLD_SECONDS
                except ValueError:
                    stale = True

            if stale:
                instance_id = config._get_setting("INSTANCE_ID")
                if instance_id:
                    try:
                        submit_telemetry = config._get_setting("SUBMIT_TELEMETRY", "false")
                        result = registration.check_entitlement(
                            instance_id, submit_telemetry=str(submit_telemetry).lower() in ("true", "1", "yes")
                        )
                        registration.store_entitlement_cache(
                            conn, True, bool(result.get("entitled", False)), json.dumps(result)
                        )
                    except Exception as e:
                        logger.warning(f"[*] Entitlement: Live refresh failed, serving cached value: {e}")

        cached = registration.get_entitlement_cache(conn)
        return cached or {"account_linked": False, "entitled": False, "checked_at": None}
    finally:
        conn.close()

def _force_refresh_entitlement(instance_id: str) -> None:
    """
    Bypasses register_entitlement_status()'s normal 6h staleness window
    and re-checks entitlement right now. Used (a) right after a
    telemetry submission succeeds -- the one moment most likely to have
    just changed entitlement, e.g. a beta-promo grant triggered by that
    exact submission -- and (b) by the periodic background sync below.
    Real user report, 2026-09-17: a fresh registration followed minutes
    later by a promo-granting telemetry submission left Settings still
    showing "Free Plan" for up to 6h, since nothing re-checked in
    between. Never raises -- best-effort, same as the check-on-read
    path it complements; a failure here just leaves the existing cache
    in place for that path to retry later.
    """
    is_registered = config._get_setting("IS_REGISTERED", "false")
    if str(is_registered).lower() not in ("true", "1", "yes"):
        return
    conn = get_config_db_connection()
    try:
        submit_telemetry = config._get_setting("SUBMIT_TELEMETRY", "false")
        result = registration.check_entitlement(
            instance_id, submit_telemetry=str(submit_telemetry).lower() in ("true", "1", "yes")
        )
        registration.store_entitlement_cache(
            conn, True, bool(result.get("entitled", False)), json.dumps(result)
        )
    except Exception as e:
        logger.warning(f"[*] Entitlement: forced refresh failed: {e}")
    finally:
        conn.close()

ENTITLEMENT_BACKGROUND_INITIAL_DELAY_SECONDS = 30
ENTITLEMENT_BACKGROUND_FAST_INTERVAL_SECONDS = 2 * 60
ENTITLEMENT_BACKGROUND_FAST_WINDOW_SECONDS = 30 * 60
ENTITLEMENT_BACKGROUND_SLOW_INTERVAL_SECONDS = 30 * 60

async def _entitlement_background_loop():
    """
    Periodic account-data sync, independent of any particular request --
    per user ask 2026-09-17: entitlement/plan data should stay
    reasonably fresh on its own, not only refresh when someone happens
    to load Settings and trips the 6h staleness check in
    register_entitlement_status(). Short initial delay so a
    freshly-registered appliance picks up a change (e.g. a promo grant
    from earlier in the same boot) well inside its first few minutes,
    not after however much of the old 6h window happened to already be
    spent. Lives here (netlanvas_api), not main.py's poller loop
    (netlanvas_core) -- see register_entitlement_status()'s own comment
    for why: only this container has the ./tls mount check_entitlement()
    needs to sign its assertion.

    Follow-up, same day: 30 minutes between checks was still too slow
    for a real fresh-install test -- registration, a telemetry
    submission, and a resulting promo grant can all happen within a
    couple of minutes of first boot, and the old fixed interval left
    that window mostly uncovered even with the "right after a
    submission" refresh in _force_refresh_entitlement()'s other call
    sites, since not every state-changing event on the account side is
    tied to a submission on this device. Per direct user request:
    every 2 minutes for the first 30 minutes since THIS process
    started (i.e. every boot re-arms the fast window, not just a
    literal first-ever install -- the same tight checking is exactly
    as useful after any restart), then back to the original 30-minute
    cadence once that window passes, so a long-running appliance isn't
    polling needlessly forever.
    """
    await asyncio.sleep(ENTITLEMENT_BACKGROUND_INITIAL_DELAY_SECONDS)
    loop_started_at = time.monotonic()
    while True:
        try:
            instance_id = config._get_setting("INSTANCE_ID")
            if instance_id:
                _force_refresh_entitlement(instance_id)
        except Exception as e:
            logger.warning(f"[*] Entitlement: background sync loop error: {e}")
        elapsed = time.monotonic() - loop_started_at
        interval = (
            ENTITLEMENT_BACKGROUND_FAST_INTERVAL_SECONDS
            if elapsed < ENTITLEMENT_BACKGROUND_FAST_WINDOW_SECONDS
            else ENTITLEMENT_BACKGROUND_SLOW_INTERVAL_SECONDS
        )
        await asyncio.sleep(interval)

@app.on_event("startup")
async def _start_entitlement_background_sync():
    asyncio.create_task(_entitlement_background_loop())

@app.post("/api/register/deregister")
async def register_deregister(request: Request):
    """
    Unlinks this device from its account, from the appliance's own
    settings page. Requires an active admin session (same global gate
    as /api/register/entitlement -- this path isn't in
    UNAUTHENTICATED_API_PATHS) since it's a destructive local action,
    on top of the signed-assertion proof-of-possession the backend
    itself checks.
    """
    conn = get_config_db_connection()
    try:
        instance_id = config._get_setting("INSTANCE_ID")
        if not instance_id:
            raise HTTPException(status_code=400, detail="Device has no identity yet.")

        try:
            result = registration.deregister_device(instance_id)
        except Exception as e:
            logger.warning(f"[*] Deregister: backend call failed: {e}")
            raise HTTPException(status_code=502, detail="Could not reach the registration backend. Please try again.")

        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Deregistration failed."))

        config._set_setting("IS_REGISTERED", "false")
        registration.store_entitlement_cache(conn, False, False, json.dumps({"deregistered": True}))
        logger.info(f"[*] Deregister: device {instance_id} unlinked from its account.")
        return {"success": True}
    finally:
        conn.close()

def _parse_version(v: str):
    """
    Parses a "vX.Y" / "vX.Y.Z"-style version string into a comparable
    tuple of ints, e.g. "v3.10" -> (3, 10). Returns None for anything
    that doesn't parse -- an unparseable version should never be
    treated as "newer", it should just suppress the update notice.
    Padded to at least 3 segments so "v3.2" and "v3.2.0" compare equal
    rather than "v3.2" reading as older than "v3.2.0".
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

NETLANVAS_VERSION = os.getenv("NETLANVAS_VERSION", "unknown")

# Detected once per API_VIEWER boot, not per request -- if the version
# running right now differs from the last version this same appliance
# recorded as running, an update just happened (whether via "Update
# Now", AUTO_UPDATE_APP, or a manual docker compose pull). A fresh
# install has no prior recorded version, so that case is explicitly
# excluded -- there's nothing to announce "updated from" on first boot.
# init_auth_db()/init_registration_db()/init_alerting_db() have already
# run by the time uvicorn imports this module (see main.py's API_VIEWER
# boot sequence), so config.db is guaranteed to exist here.
try:
    _prev_version = config._get_setting("_LAST_KNOWN_VERSION")
    if _prev_version and _prev_version != NETLANVAS_VERSION:
        config._set_setting("_JUST_UPDATED_FROM", _prev_version)
        logger.info(f"[*] Detected version change since last boot: {_prev_version} -> {NETLANVAS_VERSION}")
    config._set_setting("_LAST_KNOWN_VERSION", NETLANVAS_VERSION)
except Exception as e:
    logger.warning(f"[*] Could not record boot version: {e}")

@app.get("/api/version/check")
async def version_check():
    """
    Backs the dashboard's "new version available" notice. Reads the
    cache main.py's poller loop writes hourly (maybe_check_for_update) --
    this route itself does no network call, just compares two version
    strings, so it's cheap enough to hit on every pane load.

    Deliberately a real version comparison, not a string inequality --
    a dev/pre-release build running ahead of the last published
    latest-version.txt (e.g. v3.3 running against a still-v3.2 publish)
    must NOT show "an update is available" just because the strings
    differ. Only latest > current counts.

    just_updated_from is non-null exactly once per actual version
    change (see the module-load-time check above) -- cleared by POST
    /api/version/acknowledge-update once the UI has shown it, so it
    doesn't keep resurfacing on every subsequent pane load.
    """
    latest_version = config._get_setting("_LATEST_VERSION_SEEN")
    current_parsed = _parse_version(NETLANVAS_VERSION)
    latest_parsed = _parse_version(latest_version)
    update_available = (
        current_parsed is not None
        and latest_parsed is not None
        and latest_parsed > current_parsed
    )
    return {
        "current_version": NETLANVAS_VERSION,
        "latest_version": latest_version,
        "update_available": update_available,
        "just_updated_from": config._get_setting("_JUST_UPDATED_FROM"),
    }

@app.post("/api/version/acknowledge-update")
async def acknowledge_update():
    try:
        conn = get_config_db_connection()
        conn.execute("DELETE FROM app_settings WHERE setting_key = '_JUST_UPDATED_FROM'")
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[VERSION] acknowledge_update failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

WATCHTOWER_INTERNAL_IP = os.getenv("WATCHTOWER_INTERNAL_IP", "172.28.1.11")
WATCHTOWER_API_TOKEN = os.getenv("WATCHTOWER_API_TOKEN", "")

@app.post("/api/system/update-now")
async def update_now():
    """
    Manual trigger for the Settings page's "Update Now" button --
    works regardless of AUTO_UPDATE_APP, since clicking it is itself
    explicit consent. Same Watchtower HTTP API main.py's
    maybe_check_for_update() uses for the opt-in automatic path (see
    docker-compose.dist.yaml's watchtower service -- HTTP-trigger-only
    mode, nothing updates on its own schedule).
    """
    if not WATCHTOWER_API_TOKEN:
        return {"error": "Update automation isn't configured on this install."}
    try:
        response = await asyncio.to_thread(
            requests.post,
            f"http://{WATCHTOWER_INTERNAL_IP}:8080/v1/update",
            params={"image": "netlanvas.com/netlanvas"},
            headers={"Authorization": f"Bearer {WATCHTOWER_API_TOKEN}"},
            timeout=300,
        )
        response.raise_for_status()
        result = response.json()
        updated = result.get("summary", {}).get("updated", 0)
        if updated:
            return {"success": True, "message": "Update applied -- the appliance will restart momentarily."}
        return {"success": True, "message": "Already running the latest version."}
    except Exception as e:
        logger.error(f"[UPDATE] update_now failed: {e}")
        return {"error": "Could not reach the update service. See server logs for details."}

@app.get("/")
async def root(): return RedirectResponse(url="/dashboard/index.html", status_code=307)

@app.get("/api/settings/remote-access")
async def get_remote_access_status():
    """
    NATIVE-13: Docker/container installs are already LAN-reachable by
    construction (network_mode: host + Caddy) -- this toggle only
    exists for native mode, where localhost-only is the deliberate
    default. `applicable: false` lets the Settings page hide the whole
    control on a container install rather than showing a toggle that
    would do nothing there.
    """
    if NETLANVAS_MODE != "native":
        return {"applicable": False}
    try:
        conn = get_config_db_connection()
        row = conn.execute(
            "SELECT setting_value FROM app_settings WHERE setting_key = 'NATIVE_REMOTE_ACCESS_ENABLED'"
        ).fetchone()
        conn.close()
        enabled = bool(row) and str(row["setting_value"]).lower() in ("true", "1", "yes")
        url = None
        if enabled:
            lan_ip = detect_own_lan_ip()
            if lan_ip:
                url = f"https://{lan_ip}:{os.getenv('NETLANVAS_PUBLIC_PORT', '8899')}"
        return {"applicable": True, "enabled": enabled, "url": url}
    except Exception as e:
        logger.error(f"[SETTINGS] get_remote_access_status failed: {e}")
        return {"applicable": True, "enabled": False, "url": None}

@app.post("/api/settings/remote-access")
async def set_remote_access(req: RemoteAccessRequest):
    if NETLANVAS_MODE != "native":
        raise HTTPException(status_code=400, detail="Remote web viewing only applies to a native (non-Docker) install.")
    config._set_setting("NATIVE_REMOTE_ACCESS_ENABLED", "true" if req.enabled else "false")
    logger.info(f"[SETTINGS] Remote web viewing {'enabled' if req.enabled else 'disabled'} -- restarting to apply.")
    # Binding a new interface (or dropping back to 127.0.0.1) and
    # generating/loading the TLS cert both happen once at process boot
    # (main.py's native branch) -- there's no live-rebind path for an
    # already-listening uvicorn server, so this has to take a real
    # restart to apply, same mechanism the existing "Restart" button
    # already uses.
    try:
        await redis_client.set("ENGINE_COMMAND", "RESTART")
    except Exception as e:
        logger.error(f"[SETTINGS] Failed to dispatch restart after remote-access change: {e}")
        return {"success": True, "message": "Setting saved, but the automatic restart failed -- restart the appliance manually to apply it."}
    return {"success": True, "message": "Setting saved. The appliance is restarting to apply it."}

@app.get("/api/settings/network-interfaces")
async def get_network_interfaces():
    """
    Powers the Polling Source dropdown in Settings
    (SCAN_INTERFACE_OVERRIDE) -- Linux only so far, matching the same
    platform scope as the override itself (see auto_discovery.py's
    detect_default_gateway()). `supported: false` lets the UI hide the
    control entirely on Windows/macOS rather than show a dropdown that
    would always come back empty.

    Bug caught live 2026-09-11: this endpoint originally called
    enumerate_host_network_interfaces() directly here, which is only
    correct in native mode. In the Docker deployment, THIS container
    (netlanvas_api) sits on the isolated netlanvas_internal bridge, not
    network_mode: host -- it would only ever see its own container-
    internal veth interface (a 172.28.x.x bridge address), never the
    host's real NICs. netlanvas_core (network_mode: host) is the only
    thing that can see those, and publishes them to Redis every tick
    for exactly this reason -- read that instead of ever calling this
    function directly except in native mode, where there's no container
    isolation to worry about in the first place.
    """
    if platform.system() != "Linux":
        return {"supported": False, "interfaces": []}
    try:
        if NETLANVAS_MODE == "native":
            interfaces = enumerate_host_network_interfaces()
        else:
            raw = await redis_client.get("HOST_NETWORK_INTERFACES")
            interfaces = json.loads(raw) if raw else []
        return {"supported": True, "interfaces": interfaces}
    except Exception as e:
        logger.error(f"[API] Failed to fetch network interfaces: {e}")
        return {"supported": True, "interfaces": []}

@app.get("/api/polling/status")
async def get_polling_status():
    """
    Drives Settings page's polling-schedule card. In continuous mode
    (the pre-existing behavior) polling is always active by definition,
    so this just reports that without touching _POLLING_ACTIVE/
    _POLLING_STARTED_AT at all -- those two only mean anything in
    time_limited mode.
    """
    mode = str(config._get_setting("POLLING_MODE", "continuous")).lower()
    duration_hours = float(config._get_setting("POLLING_DURATION_HOURS", "4") or 4)
    if mode != "time_limited":
        return {"mode": mode, "active": True, "duration_hours": duration_hours, "remaining_hours": None, "paused_at": None}

    active = str(config._get_setting("_POLLING_ACTIVE", "true")).lower() in ("true", "1", "yes")
    remaining_hours = None
    paused_at_iso = None
    if active:
        started_at_raw = config._get_setting("_POLLING_STARTED_AT", "")
        if started_at_raw:
            try:
                started_at = datetime.strptime(started_at_raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                elapsed_hours = (datetime.now(timezone.utc) - started_at).total_seconds() / 3600.0
                remaining_hours = max(0.0, duration_hours - elapsed_hours)
            except ValueError:
                pass
        else:
            remaining_hours = duration_hours
    else:
        # Drives the Settings page's persistent (non-scrolling) "Paused
        # for HH:MM:SS" banner above the Live Logs window -- sent as
        # explicit ISO 8601 UTC (trailing Z) so the frontend's `new
        # Date(...)` parses it unambiguously regardless of browser locale.
        paused_at_raw = config._get_setting("_POLLING_PAUSED_AT", "")
        if paused_at_raw:
            try:
                paused_at = datetime.strptime(paused_at_raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                paused_at_iso = paused_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                pass

    return {"mode": mode, "active": active, "duration_hours": duration_hours, "remaining_hours": remaining_hours, "paused_at": paused_at_iso}

@app.post("/api/polling/start")
async def start_polling_now():
    """
    The Settings page's single "Start Now" button -- doubles as both the
    initial kick-off and any later manual resume after a time-limited run
    elapses, since the settled design deliberately has no auto-resume.
    Clearing _POLLING_STARTED_AT (rather than setting it here) lets
    main.py's tick loop re-stamp it fresh on its own next pass, so the
    timer always starts from the tick that actually resumes work, not
    this HTTP request.
    """
    config._set_setting("_POLLING_ACTIVE", "true")
    config._set_setting("_POLLING_STARTED_AT", "")
    config._set_setting("_POLLING_PAUSED_AT", "")
    logger.info("[SETTINGS] Polling started/resumed via Start Now.")
    return {"status": "ok"}

@app.post("/api/system/restart")
async def restart_system():
    logger.info("[*] System Restart Requested via API. Dispatching IPC flag.")
    try:
        await redis_client.set("ENGINE_COMMAND", "RESTART")
        return {"success": True, "message": "Restart signal published to engine supervisor."}
    except Exception as e: return {"error": f"Redis IPC fault: {str(e)}"}

def _get_sensitive_raw_values() -> list:
    """
    Fetched once when a log stream connection opens (not re-checked
    live -- if a sensitive setting changes mid-stream, that specific
    already-open connection keeps redacting the old value until it
    reconnects, which happens routinely anyway). SNMP_COMMUNITY_STRING
    may itself be a comma-separated list, so each individual value is
    redacted, not just the whole joined string.
    """
    if not SENSITIVE_SETTING_KEYS:
        return []
    try:
        conn = get_config_db_connection()
        placeholders = ",".join("?" for _ in SENSITIVE_SETTING_KEYS)
        cursor = conn.execute(
            f"SELECT setting_value FROM app_settings WHERE setting_key IN ({placeholders})",
            list(SENSITIVE_SETTING_KEYS),
        )
        raw_values = []
        for (val,) in cursor.fetchall():
            if not val: continue
            raw_values.extend(v.strip() for v in str(val).split(",") if v.strip())
        conn.close()
        return raw_values
    except Exception:
        return []

def _redact_line(line: str, sensitive_values: list) -> str:
    for raw in sensitive_values:
        if raw and raw in line:
            line = line.replace(raw, mask_credential(raw))
    return line

# Public read-only demo (see DEMO_MODE): there's no real poller writing
# engine.log, so the live-tail behavior below is replaced with a looping
# script of plausible-looking lines instead. Deliberately built from the
# same logger names/format/style as the real product, but with
# documentation-range IPs (RFC 5737, never routable) rather than any
# data from a real network -- it should look and feel like watching the
# real thing without being an actual capture of anyone's network.
DEMO_LOG_SCRIPT = [
    ("Netlanvas.Core", "INFO", "--- Initiating Real-Time State Scan (L3 IP Discovery) ---"),
    ("Netlanvas.Core", "INFO", "Initiating distributed ARP cache scrape across 9 L3 targets..."),
    ("Netlanvas.Core", "INFO", "Database sync complete: 41 global L3 bindings logged via Pipeline Step 35."),
    ("Netlanvas.FDB", "INFO", "[*] FDB Scraper: Initializing distributed concurrent scrape across 5 chassis..."),
    ("Netlanvas.SNMP", "INFO", "[*] SNMP Auth Locked: 203.0.113.12 verified with v2c:pu*** (Added to Cache)"),
    ("Netlanvas.LLDP", "INFO", "[Layer 1] Scrutinizing batch nodes: ['203.0.113.2', '203.0.113.5']"),
    ("Netlanvas.LLDP", "INFO", "[*] Success: Switch 203.0.113.5 mapped 3 LLDP links with speed verification."),
    ("Netlanvas.LLDP", "INFO", "[Layer 2] Scrutinizing batch nodes: ['203.0.113.9', '203.0.113.14']"),
    ("Netlanvas.Fingerprint", "INFO", "Stage 5: Profiling 58 nodes..."),
    ("Netlanvas.Fingerprint", "INFO", "[*] SNMP ALIVE [203.0.113.9]: Processing profiles..."),
    ("Netlanvas.Fingerprint", "INFO", "[*] WAP MATCH [203.0.113.9]: Found physical radio -> .1.3.6.1.2.1.2.2.1.2.5 \"wifi0\""),
    ("Netlanvas.Fingerprint", "INFO", "[*] Node Identified [203.0.113.9]: Access Point (Radio Interface Confirmed)"),
    ("Netlanvas.VLAN", "INFO", "[*] VLAN Registry: parsed 6 static VLAN names across 3 switches."),
    ("Netlanvas.Core", "INFO", "--- Discovery Cycle Complete. Sleeping for 60s ---"),
]

async def _demo_log_generator():
    while True:
        for logger_name, level, message in DEMO_LOG_SCRIPT:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            yield f"data: {ts} [{level}] {logger_name}: {message}\n\n"
            await asyncio.sleep(random.uniform(0.8, 2.5))
        await asyncio.sleep(6)

@app.get("/api/logs/stream")
async def stream_logs():
    if config.DEMO_MODE:
        return StreamingResponse(_demo_log_generator(), media_type="text/event-stream")

    async def log_generator():
        log_file = config.LOG_FILE_PATH
        sensitive_values = _get_sensitive_raw_values()
        if not os.path.exists(log_file):
            yield "data: [WAITING FOR LOG FILE]\n\n"
            while not os.path.exists(log_file): await asyncio.sleep(1)
        try:
            with open(log_file, "r") as f:
                lines = f.readlines()
                for line in lines[-100:]: yield f"data: {_redact_line(line.strip(), sensitive_values)}\n\n"
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        await asyncio.sleep(0.5)
                        continue
                    yield f"data: {_redact_line(line.strip(), sensitive_values)}\n\n"
        except asyncio.CancelledError: pass
        except Exception as e: yield f"data: [STREAM ERROR] An internal error occurred.\n\n"
    return StreamingResponse(log_generator(), media_type="text/event-stream")

@app.get("/api/archives")
async def get_archives():
    try:
        if not os.path.exists(ARCHIVE_DIR): return {"archives": []}
        files = os.listdir(ARCHIVE_DIR)
        db_files = [f for f in files if f.endswith(".db") and f.startswith("network_")]
        
        conn = get_config_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT filename, location, notes FROM archive_metadata")
        meta_rows = {row["filename"]: dict(row) for row in cursor.fetchall()}
        conn.close()
        
        archives = []
        for f in db_files:
            match = re.match(r'^network_(\d{8})_(\d{6})\.db$', f)
            if match:
                date_str, time_str = match.groups()
                dt_formatted = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:]} {time_str[:2]}:{time_str[2:4]}:{time_str[4:]}"
            else: dt_formatted = "Unknown"
            
            meta = meta_rows.get(f, {"location": "", "notes": ""})
            archives.append({
                "filename": f,
                "timestamp": dt_formatted,
                "location": meta["location"],
                "notes": meta["notes"],
                "size_mb": round(os.path.getsize(os.path.join(ARCHIVE_DIR, f)) / (1024*1024), 2)
            })
        
        archives.sort(key=lambda x: x["filename"], reverse=True)
        return {"archives": archives}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/archives/annotate")
async def annotate_archive(req: ArchiveAnnotateRequest):
    if not re.match(r'^network_\d{8}_\d{6}\.db$', req.filename):
        return {"error": "Invalid filename format."}
    try:
        conn = get_config_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO archive_metadata (filename, location, notes)
            VALUES (?, ?, ?)
            ON CONFLICT(filename) DO UPDATE SET location = excluded.location, notes = excluded.notes
        ''', (req.filename, req.location, req.notes))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/archives/delete")
async def delete_archive(req: ArchiveDeleteRequest):
    if not re.match(r'^network_\d{8}_\d{6}\.db$', req.filename):
        return {"error": "Invalid filename format."}
        
    target_path = os.path.abspath(os.path.join(ARCHIVE_DIR, req.filename))
    if os.path.commonpath([os.path.abspath(ARCHIVE_DIR), target_path]) != os.path.abspath(ARCHIVE_DIR):
        return {"error": "Path traversal detected."}
        
    try:
        for ext in ["", "-wal", "-shm"]:
            fp = target_path + ext
            if os.path.exists(fp): os.remove(fp)
                
        conn = get_config_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM archive_metadata WHERE filename = ?", (req.filename,))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/settings")
async def get_settings():
    try:
        conn = get_config_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT setting_key, setting_value, description FROM app_settings")
        settings = [dict(row) for row in cursor.fetchall()]
        conn.close()
        for s in settings:
            if s["setting_key"] in SENSITIVE_SETTING_KEYS: s["setting_value"] = mask_credential(s["setting_value"])
        return {"settings": settings}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/settings")
async def update_setting(req: SettingUpdateRequest):
    try:
        if req.key not in ALLOWED_SETTING_KEYS:
            return {"error": f"Unknown setting key: {req.key}"}
        if req.key in READONLY_SETTING_KEYS:
            return {"error": f"Setting '{req.key}' is read-only and cannot be modified via the API."}
        if req.key in SENSITIVE_SETTING_KEYS and "********" in req.value: return {"success": True, "message": "Ignored masked credential update."}
        config._set_setting(req.key, req.value)
        return {"success": True, "message": f"Setting {req.key} updated successfully."}
    except Exception as e:
        logger.error(f"[SETTINGS] update_setting failed for key '{req.key}': {e}")
        return {"error": "An internal error occurred. See server logs for details."}

# --- Community Telemetry Pipeline (netlanvas-telemetry-pipeline-v6) ---
# Sits behind the same session-auth middleware as every other /api/*
# route -- deliberately NOT added to middleware.py's
# UNAUTHENTICATED_API_PATHS. This class of endpoint (a new route
# missing from or mishandled by that allowlist) has bitten this
# project three times already; the fix here is the opposite direction
# -- simply never touching that list for these routes at all, so they
# inherit the default-authenticated behavior with nothing to get wrong.

@app.get("/api/telemetry/preview")
async def telemetry_preview():
    """
    Backs the Preview page's two panes. Calls the EXACT SAME
    payload_builder.build_payload() used for the real daily/tick-10
    send -- no separate preview-only code path, so there is zero drift
    between what a user previews and what would actually be sent.
    """
    try:
        payload = telemetry_payload_builder.build_payload(config, config.DB_PATH)
        # Falls back to a live, on-demand tail-of-the-log preview if
        # tick 10 hasn't completed yet this restart -- confirmed
        # 2026-09-03: a user checking this page early (exactly the
        # behavior it's meant to encourage) would otherwise see nothing
        # in the log pane for however long that takes.
        log_sample = telemetry_log_sampler.get_stored_sample(config)
        if not log_sample:
            log_sample = telemetry_log_sampler.get_preview_sample(config, config.DB_PATH)
        return {"payload": payload, "log_sample": log_sample}
    except Exception as e:
        logger.error(f"[TELEMETRY] preview failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/telemetry/submit-now")
async def telemetry_submit_now():
    """
    The Preview page's "Submit Now" button -- a manual, out-of-cycle
    submission of the current payload through the exact same handshake
    (submitter.submit) as every automatic send. Requires SUBMIT_TELEMETRY
    to already be enabled -- this button doesn't itself opt someone in,
    it only sends once they already have.
    """
    submit_telemetry = str(config._get_setting("SUBMIT_TELEMETRY", "false")).lower() in ("true", "1", "yes")
    if not submit_telemetry:
        return {"error": "Community telemetry is not enabled. Turn on the toggle above before submitting."}

    instance_id = config._get_setting("INSTANCE_ID")
    if not instance_id:
        return {"error": "No instance ID yet -- try again after the appliance has fully started."}

    try:
        payload = telemetry_payload_builder.build_payload(config, config.DB_PATH)
        # Same fallback as maybe_send_daily -- every submission should
        # carry a log sample, not just the once-per-restart tick-10
        # one. Found live 2026-09-03 that this endpoint had the exact
        # same gap maybe_send_daily did before that fix.
        log_sample = telemetry_log_sampler.get_stored_sample(config)
        if not log_sample:
            log_sample = telemetry_log_sampler.get_preview_sample(config, config.DB_PATH)
        payload["log_sample"] = log_sample
        ok = telemetry_submitter.submit(instance_id, payload)
        if ok:
            _force_refresh_entitlement(instance_id)
            return {"success": True}
        return {"error": "Submission failed -- see server logs for details."}
    except Exception as e:
        logger.error(f"[TELEMETRY] manual submit failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

# CAPS-4 (2026-09-10): reuses the exact same submission mechanism as
# submit-now above (same payload builder, same log sample, same
# Ed25519-signed handshake to telemetry-submit.php) -- a bug report is
# just a regular telemetry submission with two extra fields riding
# along, not a parallel code path. Hard-requires SUBMIT_TELEMETRY,
# same as submit-now: a screenshot has none of the sanitization
# guarantees the rest of the payload does (real hostnames/IPs are
# whatever happened to be on screen), so this is deliberately NOT a
# lighter-weight opt-in than telemetry itself -- see the bug-report.js
# frontend's inline enable-prompt, which this is the backstop for.
_MAX_BUG_REPORT_MESSAGE = 5000
_MAX_BUG_REPORT_SCREENSHOT_BYTES = 8 * 1024 * 1024

@app.post("/api/telemetry/submit-bug-report")
async def telemetry_submit_bug_report(req: BugReportRequest):
    submit_telemetry = str(config._get_setting("SUBMIT_TELEMETRY", "false")).lower() in ("true", "1", "yes")
    if not submit_telemetry:
        return {"error": "Community telemetry must be enabled before submitting a bug report."}

    instance_id = config._get_setting("INSTANCE_ID")
    if not instance_id:
        return {"error": "No instance ID yet -- try again after the appliance has fully started."}

    message = req.message.strip()[:_MAX_BUG_REPORT_MESSAGE]
    try:
        screenshot_bytes = base64.b64decode(req.screenshot_b64, validate=True)
    except Exception:
        return {"error": "Screenshot data was not valid."}
    # PNG magic bytes -- webhost-side (telemetry-submit.php) re-validates
    # this independently before ever writing anything to disk; this
    # check is just a fast client-friendly rejection, not the real gate.
    if screenshot_bytes[:8] != b"\x89PNG\r\n\x1a\n":
        return {"error": "Screenshot must be a PNG image."}
    if len(screenshot_bytes) > _MAX_BUG_REPORT_SCREENSHOT_BYTES:
        return {"error": "Screenshot is too large."}

    try:
        payload = telemetry_payload_builder.build_payload(config, config.DB_PATH)
        log_sample = telemetry_log_sampler.get_stored_sample(config)
        if not log_sample:
            log_sample = telemetry_log_sampler.get_preview_sample(config, config.DB_PATH)
        payload["log_sample"] = log_sample
        payload["bug_report"] = {"message": message, "screenshot_b64": req.screenshot_b64}
        ok = telemetry_submitter.submit(instance_id, payload)
        if ok:
            _force_refresh_entitlement(instance_id)
            return {"success": True}
        return {"error": "Submission failed -- see server logs for details."}
    except Exception as e:
        logger.error(f"[TELEMETRY] bug report submit failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/telemetry/nag-status")
async def telemetry_nag_status():
    """
    Whether the global nag banner's telemetry section should show right
    now (design doc S11), plus the two individual ask states -- the
    frontend needs is_registered/submit_telemetry separately so it can
    decide which section(s) of the shared banner to reveal, not just a
    single yes/no.
    """
    try:
        # Public read-only demo: there's no real appliance behind this to
        # submit telemetry from, and demo_read_only middleware blocks the
        # POST this nag's own "enable telemetry" button would need to
        # make anyway. Report both asks as already satisfied, same as
        # the fail-closed error path below.
        if config.DEMO_MODE:
            return {"should_nag": False, "is_registered": True, "submit_telemetry": True}

        is_registered = str(config._get_setting("IS_REGISTERED", "false")).lower() in ("true", "1", "yes")
        submit_telemetry = str(config._get_setting("SUBMIT_TELEMETRY", "false")).lower() in ("true", "1", "yes")
        should_nag = telemetry_scheduler.should_nag_now(config, is_registered)
        return {"should_nag": should_nag, "is_registered": is_registered, "submit_telemetry": submit_telemetry}
    except Exception as e:
        logger.error(f"[TELEMETRY] nag-status failed: {e}")
        # Fail closed -- on error, report both asks as already satisfied
        # so nothing shows, rather than risk nagging incorrectly.
        return {"should_nag": False, "is_registered": True, "submit_telemetry": True}

@app.post("/api/telemetry/nag-shown")
async def telemetry_nag_shown():
    """Called by the frontend once it actually displays the nag modal -- caps it at once per calendar day."""
    try:
        telemetry_scheduler.mark_nagged(config)
        return {"success": True}
    except Exception as e:
        logger.error(f"[TELEMETRY] nag-shown failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

# --- SNMPv3 identities (see punch list SNMP-5/SNMP-7) ---
# Backend-only until now -- these routes are what the Settings UI and
# setup wizard both call. Deliberately stronger than mask_credential()'s
# partial-reveal pattern used for the v2c community string: a v3
# password is a real authentication credential, so it is NEVER returned
# by any of these routes, not even masked -- same principle as this
# app's own login system never returning a user's password. Sits behind
# the same session-auth middleware as every other /api/* route; no
# separate rate limiting added since this is a low-frequency admin
# action, not an unauthenticated attack surface.

@app.get("/api/snmp/v3-identities")
async def list_snmp_v3_identities():
    try:
        conn = get_config_db_connection()
        rows = conn.execute(
            "SELECT id, username, sort_order FROM snmp_v3_identities ORDER BY sort_order"
        ).fetchall()
        conn.close()
        return {"identities": [{"id": r["id"], "username": r["username"], "sort_order": r["sort_order"]} for r in rows]}
    except Exception as e:
        logger.error(f"[SNMP] list_snmp_v3_identities failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/snmp/v3-identities")
async def add_snmp_v3_identity(req: SNMPv3IdentityCreateRequest):
    try:
        username = req.username.strip()
        if not username:
            return {"error": "Username cannot be blank."}
        if not req.password:
            return {"error": "Password cannot be blank."}
        # F14: auth password and privacy password must be independent
        # secrets (RFC 3414 USM) -- accepting only one and reusing it for
        # both authKey and privKey removes that independence. Both are
        # now required per identity.
        if not req.priv_password:
            return {"error": "Privacy password cannot be blank."}
        conn = get_config_db_connection()
        next_order_row = conn.execute("SELECT COALESCE(MAX(sort_order), -1) + 1 FROM snmp_v3_identities").fetchone()
        next_order = next_order_row[0]
        conn.execute(
            "INSERT INTO snmp_v3_identities (username, password, priv_password, sort_order, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
            (username, encrypt_password(req.password), encrypt_password(req.priv_password), next_order),
        )
        conn.commit()
        conn.close()
        logger.info(f"[SNMP] Added v3 identity: username={username}")
        return {"success": True}
    except Exception as e:
        logger.error(f"[SNMP] add_snmp_v3_identity failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.delete("/api/snmp/v3-identities/{identity_id}")
async def delete_snmp_v3_identity(identity_id: int):
    try:
        conn = get_config_db_connection()
        row = conn.execute("SELECT username FROM snmp_v3_identities WHERE id = ?", (identity_id,)).fetchone()
        if row is None:
            conn.close()
            return {"error": "No such identity."}
        conn.execute("DELETE FROM snmp_v3_identities WHERE id = ?", (identity_id,))
        conn.commit()
        conn.close()
        logger.info(f"[SNMP] Removed v3 identity: username={row['username']}")
        return {"success": True}
    except Exception as e:
        logger.error(f"[SNMP] delete_snmp_v3_identity failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/snmp/v3-identities/reorder")
async def reorder_snmp_v3_identities(req: SNMPv3ReorderRequest):
    try:
        conn = get_config_db_connection()
        for new_order, identity_id in enumerate(req.ordered_ids):
            conn.execute("UPDATE snmp_v3_identities SET sort_order = ? WHERE id = ?", (new_order, identity_id))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[SNMP] reorder_snmp_v3_identities failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

# --- Alerting (Priority 3) ---
# alerts/device_findings/device_state live in network.db (get_db_connection,
# same file the topology/discovery data lives in -- alerts are generated
# from that data). alerting_config lives in config.db (get_config_db_
# connection), alongside every other appliance-identity/credential table.

def _alert_filter_clauses(status: str, severity: str, alert_type: str) -> tuple[list, list]:
    """
    Shared WHERE-clause builder for every endpoint that filters the
    inbox by the Inbox tab's three dropdowns (status/severity/type) --
    list_alerts and delete_alerts both need the exact same filter
    semantics, and duplicating this by hand is how mark-all-read's
    earlier filter-scope bug happened in the first place.
    """
    clauses = []
    params: list = []
    # "new"/"acknowledged" map onto read_at, same underlying signal
    # mark-read already uses -- no new column needed for this filter.
    if status == "new":
        clauses.append("read_at IS NULL")
    elif status == "acknowledged":
        clauses.append("read_at IS NOT NULL")
    if severity != "all":
        clauses.append("severity = ?")
        params.append(severity)
    if alert_type != "all":
        clauses.append("alert_type = ?")
        params.append(alert_type)
    return clauses, params


@app.get("/api/alerts")
async def list_alerts(limit: int = Query(50, le=200), status: str = "all", severity: str = "all", alert_type: str = "all"):
    try:
        if status not in ("all", "new", "acknowledged"):
            return {"error": "status must be one of: all, new, acknowledged."}
        if severity != "all" and severity not in SEVERITY_LEVELS:
            return {"error": f"severity must be 'all' or one of {SEVERITY_LEVELS}."}

        conn = get_db_connection()
        clauses, params = _alert_filter_clauses(status, severity, alert_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        rows = conn.execute(
            f"SELECT id, alert_type, severity, mac_address, title, detail, created_at, read_at, is_resolution "
            f"FROM alerts {where} ORDER BY created_at DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        # Deliberately always the TRUE unread count across all alerts,
        # not scoped to the current filter -- this drives the sidebar
        # badge (see index.html), which must reflect real unread state
        # regardless of what the Inbox happens to be filtered to right
        # now.
        unread_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE read_at IS NULL").fetchone()[0]
        conn.close()
        has_new = config._get_setting("ALERTS_HAS_NEW", "false").lower() == "true"
        return {
            "alerts": [dict(r) for r in rows],
            "unread_count": unread_count,
            "has_new": has_new,
        }
    except Exception as e:
        logger.error(f"[ALERTS] list_alerts failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/alerts/{alert_id}/read")
async def mark_alert_read(alert_id: int):
    try:
        conn = get_db_connection()
        conn.execute("UPDATE alerts SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND read_at IS NULL", (alert_id,))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[ALERTS] mark_alert_read failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: int):
    """
    User-driven cleanup, distinct from prune_alerting_history()'s
    automatic 1-year retention -- this is for dismissing something
    irrelevant (a one-off test alert, a device you've since removed)
    right now, not waiting a year for it to age out on its own.
    """
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[ALERTS] delete_alert failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.delete("/api/alerts")
async def delete_alerts(status: str = "all", severity: str = "all", alert_type: str = "all"):
    """
    Bulk counterpart to delete_alert() above, scoped to whatever the
    Inbox's three filter dropdowns are currently showing -- same
    filter-scope discipline as mark_all_alerts_read (never delete rows
    the user can't currently see), but deliberately requires at least
    one filter set rather than defaulting to "delete everything" on a
    bare call with no query params, since this is destructive and
    unlike mark-as-read can't be undone.
    """
    try:
        if status not in ("all", "new", "acknowledged"):
            return {"error": "status must be one of: all, new, acknowledged."}
        if severity != "all" and severity not in SEVERITY_LEVELS:
            return {"error": f"severity must be 'all' or one of {SEVERITY_LEVELS}."}
        if status == "all" and severity == "all" and alert_type == "all":
            return {"error": "Refusing to delete the entire inbox unfiltered -- set at least one filter first."}

        conn = get_db_connection()
        clauses, params = _alert_filter_clauses(status, severity, alert_type)
        where = "WHERE " + " AND ".join(clauses)
        deleted = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
        conn.execute(f"DELETE FROM alerts {where}", params)
        remaining_unread = conn.execute("SELECT COUNT(*) FROM alerts WHERE read_at IS NULL").fetchone()[0]
        conn.commit()
        conn.close()
        if remaining_unread == 0:
            config._set_setting("ALERTS_HAS_NEW", "false")
        return {"success": True, "deleted": deleted}
    except Exception as e:
        logger.error(f"[ALERTS] delete_alerts failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/alerts/mark-all-read")
async def mark_all_alerts_read(severity: str = "all"):
    try:
        if severity != "all" and severity not in SEVERITY_LEVELS:
            return {"error": f"severity must be 'all' or one of {SEVERITY_LEVELS}."}

        conn = get_db_connection()
        # Scoped to whatever the Inbox's Level filter is currently
        # showing -- previously this always marked EVERY unread alert
        # in the whole table, regardless of what was actually visible
        # (a real bug once the filter dropdowns existed: "mark all as
        # read" while filtered to e.g. severity=high silently read-
        # marked low/medium/info alerts the user never even looked at).
        clauses = ["read_at IS NULL"]
        params: list = []
        if severity != "all":
            clauses.append("severity = ?")
            params.append(severity)
        conn.execute(f"UPDATE alerts SET read_at = CURRENT_TIMESTAMP WHERE {' AND '.join(clauses)}", params)

        # Only clear the sidebar badge if NOTHING unread remains across
        # the whole inbox, not just the filtered subset just marked --
        # marking only severity=high read must not hide the badge while
        # unread low/medium/info alerts still genuinely exist.
        remaining_unread = conn.execute("SELECT COUNT(*) FROM alerts WHERE read_at IS NULL").fetchone()[0]
        conn.commit()
        conn.close()
        if remaining_unread == 0:
            config._set_setting("ALERTS_HAS_NEW", "false")
        return {"success": True}
    except Exception as e:
        logger.error(f"[ALERTS] mark_all_alerts_read failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/alerts/acknowledge")
async def acknowledge_alerts():
    """
    Clears just the sidebar's has_new badge -- called when the Alerts
    page itself loads. Deliberately separate from mark-all-read: opening
    the page dismisses "something happened, go look", but doesn't
    presume every individual alert has actually been read yet -- that's
    still the explicit "Mark all as read" button's job.
    """
    try:
        config._set_setting("ALERTS_HAS_NEW", "false")
        return {"success": True}
    except Exception as e:
        logger.error(f"[ALERTS] acknowledge_alerts failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/alerting/config")
async def get_alerting_config():
    try:
        conn = get_config_db_connection()
        row = conn.execute("SELECT * FROM alerting_config WHERE id = 1").fetchone()
        conn.close()
        if row is None:
            return {"config": None}
        result = dict(row)
        # Never returned, not even masked -- same principle as SNMPv3
        # passwords above. The UI shows a "configured" indicator instead
        # (smtp_password_set), driven off whether the column is non-empty.
        result["smtp_password_set"] = bool(result.get("smtp_password"))
        result.pop("smtp_password", None)
        return {"config": result}
    except Exception as e:
        logger.error(f"[ALERTING] get_alerting_config failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/alerting/config")
async def update_alerting_config(req: AlertingConfigRequest):
    try:
        if req.email_min_severity not in SEVERITY_LEVELS or req.webhook_min_severity not in SEVERITY_LEVELS:
            return {"error": f"Severity must be one of {SEVERITY_LEVELS}."}
        if req.email_delivery_method not in ("relay", "smtp"):
            return {"error": "email_delivery_method must be 'relay' or 'smtp'."}
        if req.webhook_format not in ("json", "ntfy"):
            return {"error": "webhook_format must be 'json' or 'ntfy'."}

        conn = get_config_db_connection()
        # A blank password in the request means "leave it as-is" (the
        # UI never round-trips the real value back to us to change) --
        # only overwrite it when a real, non-empty value was submitted.
        if req.smtp_password:
            conn.execute(
                """INSERT INTO alerting_config (
                    id, email_enabled, email_delivery_method, email_min_severity, email_to_address,
                    smtp_host, smtp_port, smtp_username, smtp_password, smtp_use_tls, smtp_from_address,
                    webhook_enabled, webhook_url, webhook_min_severity, webhook_format, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                    email_enabled=excluded.email_enabled, email_delivery_method=excluded.email_delivery_method,
                    email_min_severity=excluded.email_min_severity, email_to_address=excluded.email_to_address,
                    smtp_host=excluded.smtp_host, smtp_port=excluded.smtp_port, smtp_username=excluded.smtp_username,
                    smtp_password=excluded.smtp_password, smtp_use_tls=excluded.smtp_use_tls,
                    smtp_from_address=excluded.smtp_from_address, webhook_enabled=excluded.webhook_enabled,
                    webhook_url=excluded.webhook_url, webhook_min_severity=excluded.webhook_min_severity,
                    webhook_format=excluded.webhook_format, updated_at=CURRENT_TIMESTAMP""",
                (req.email_enabled, req.email_delivery_method, req.email_min_severity, req.email_to_address,
                 req.smtp_host, req.smtp_port, req.smtp_username, req.smtp_password, req.smtp_use_tls,
                 req.smtp_from_address, req.webhook_enabled, req.webhook_url, req.webhook_min_severity, req.webhook_format),
            )
        else:
            conn.execute(
                """INSERT INTO alerting_config (
                    id, email_enabled, email_delivery_method, email_min_severity, email_to_address,
                    smtp_host, smtp_port, smtp_username, smtp_use_tls, smtp_from_address,
                    webhook_enabled, webhook_url, webhook_min_severity, webhook_format, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                    email_enabled=excluded.email_enabled, email_delivery_method=excluded.email_delivery_method,
                    email_min_severity=excluded.email_min_severity, email_to_address=excluded.email_to_address,
                    smtp_host=excluded.smtp_host, smtp_port=excluded.smtp_port, smtp_username=excluded.smtp_username,
                    smtp_use_tls=excluded.smtp_use_tls, smtp_from_address=excluded.smtp_from_address,
                    webhook_enabled=excluded.webhook_enabled, webhook_url=excluded.webhook_url,
                    webhook_min_severity=excluded.webhook_min_severity, webhook_format=excluded.webhook_format,
                    updated_at=CURRENT_TIMESTAMP""",
                (req.email_enabled, req.email_delivery_method, req.email_min_severity, req.email_to_address,
                 req.smtp_host, req.smtp_port, req.smtp_username, req.smtp_use_tls,
                 req.smtp_from_address, req.webhook_enabled, req.webhook_url, req.webhook_min_severity, req.webhook_format),
            )
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[ALERTING] update_alerting_config failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/alerting/severity-config")
async def get_severity_config():
    try:
        return {"config": {
            "offline_router": config._get_setting("SEVERITY_OFFLINE_ROUTER", "critical"),
            "offline_infrastructure": config._get_setting("SEVERITY_OFFLINE_INFRASTRUCTURE", "high"),
            "offline_endpoint": config._get_setting("SEVERITY_OFFLINE_ENDPOINT", "low"),
            "snmp_exposure": config._get_setting("SEVERITY_SNMP_EXPOSURE", "high"),
            "snmp_v3_unused": config._get_setting("SEVERITY_SNMP_V3_UNUSED", "medium"),
        }}
    except Exception as e:
        logger.error(f"[ALERTING] get_severity_config failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/alerting/severity-config")
async def update_severity_config(req: SeverityConfigRequest):
    try:
        values = req.dict()
        for value in values.values():
            if value not in SEVERITY_LEVELS:
                return {"error": f"Severity must be one of {SEVERITY_LEVELS}."}
        config._set_setting("SEVERITY_OFFLINE_ROUTER", values["offline_router"])
        config._set_setting("SEVERITY_OFFLINE_INFRASTRUCTURE", values["offline_infrastructure"])
        config._set_setting("SEVERITY_OFFLINE_ENDPOINT", values["offline_endpoint"])
        config._set_setting("SEVERITY_SNMP_EXPOSURE", values["snmp_exposure"])
        config._set_setting("SEVERITY_SNMP_V3_UNUSED", values["snmp_v3_unused"])
        return {"success": True}
    except Exception as e:
        logger.error(f"[ALERTING] update_severity_config failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

def _synthetic_test_alert() -> dict:
    return {
        "id": 0, "alert_type": "test", "severity": "info", "mac_address": None,
        "title": "NetLanvas test alert",
        "detail": "This is a test alert sent from your NetLanvas appliance's Settings page to confirm delivery is configured correctly.",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/api/alerting/setup-ntfy")
async def setup_ntfy():
    """
    ALERT-7. One click in Notification Settings: fetches this device's
    ntfy.sh topic from the webhost (deterministic -- same topic every
    time, see registration.fetch_ntfy_topic()'s docstring) and saves it
    straight into alerting_config as webhook_url, with webhook_format
    switched to 'ntfy'. Overwrites whatever webhook_url/webhook_format
    was there before -- this button IS the "use ntfy" action, not a
    preview; a user who wants to keep a custom JSON webhook shouldn't
    click it.
    """
    try:
        is_registered = str(config._get_setting("IS_REGISTERED", "false")).lower() in ("true", "1", "yes")
        instance_id = config._get_setting("INSTANCE_ID")
        if not is_registered or not instance_id:
            return {"error": "This device isn't registered yet. Register it from the Settings page first."}

        try:
            result = await asyncio.to_thread(registration.fetch_ntfy_topic, instance_id)
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 402:
                return {"error": "ntfy alerts are a premium feature. Register and subscribe to use them."}
            raise
        topic = result.get("topic")
        if not topic:
            return {"error": "The registration backend didn't return a topic. Please try again."}

        webhook_url = f"https://ntfy.sh/{topic}"
        conn = get_config_db_connection()
        conn.execute(
            """INSERT INTO alerting_config (id, webhook_url, webhook_format, updated_at)
               VALUES (1, ?, 'ntfy', CURRENT_TIMESTAMP)
               ON CONFLICT(id) DO UPDATE SET
                   webhook_url = excluded.webhook_url, webhook_format = excluded.webhook_format,
                   updated_at = CURRENT_TIMESTAMP""",
            (webhook_url,),
        )
        conn.commit()
        conn.close()
        return {"success": True, "webhook_url": webhook_url}
    except Exception as e:
        logger.error(f"[ALERTING] setup_ntfy failed: {e}")
        return {"error": "Could not reach the registration backend. Please try again."}

@app.post("/api/alerting/test-webhook")
async def test_webhook():
    try:
        conn = get_config_db_connection()
        cfg = conn.execute("SELECT webhook_url, webhook_format FROM alerting_config WHERE id = 1").fetchone()
        pubkey_row = conn.execute("SELECT public_key_b64 FROM device_identity WHERE id = 1").fetchone()
        entitlement_row = conn.execute("SELECT entitled FROM entitlement_cache WHERE id = 1").fetchone()
        conn.close()
        if cfg is None or not cfg["webhook_url"]:
            return {"error": "No webhook URL is configured yet."}
        # Webhooks (both formats) are a premium feature -- gated the
        # same way delivery itself is gated in alert_dispatcher.py, so
        # a test that "works" never misleads someone into thinking real
        # alerts will too.
        if not (entitlement_row and entitlement_row["entitled"]):
            return {"error": "Webhook alerts are a premium feature. Register and subscribe to use them."}
        if cfg["webhook_format"] == "ntfy":
            ok = await asyncio.to_thread(_send_webhook_ntfy, cfg["webhook_url"], _synthetic_test_alert())
        else:
            ok = await asyncio.to_thread(
                _send_webhook, cfg["webhook_url"], _synthetic_test_alert(),
                pubkey_row[0] if pubkey_row else None,
            )
        return {"success": ok} if ok else {"error": "Webhook delivery failed -- check the URL and see server logs for details."}
    except Exception as e:
        logger.error(f"[ALERTING] test_webhook failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/alerting/test-email")
async def test_email():
    try:
        conn = get_config_db_connection()
        cfg = conn.execute("SELECT * FROM alerting_config WHERE id = 1").fetchone()
        conn.close()
        if cfg is None:
            return {"error": "Email alerting hasn't been configured yet."}

        if cfg["email_delivery_method"] == "relay":
            device_uuid = config._get_setting("INSTANCE_ID")
            is_registered = str(config._get_setting("IS_REGISTERED")).lower() == "true"
            if not device_uuid or not is_registered:
                return {"error": "This appliance must be registered to use zero-setup email relay -- register it, or switch to your own SMTP server instead."}
            ok = await asyncio.to_thread(_send_email_relay, device_uuid, _synthetic_test_alert())
        else:
            if not cfg["email_to_address"]:
                return {"error": "Set a destination email address first."}
            ok = await asyncio.to_thread(_send_email_smtp, cfg, _synthetic_test_alert())

        return {"success": ok} if ok else {"error": "Email delivery failed -- check your settings and see server logs for details."}
    except Exception as e:
        logger.error(f"[ALERTING] test_email failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

# --- VLAN naming (see punch list VLAN-3) ---
# Admin overrides here are protected from being overwritten by the next
# SNMP deep-scan via the is_admin_named flag -- see
# pollers/vlan_registry.py's upsert (conditional ON CONFLICT ... WHERE)
# for the other half of this mechanism.

@app.get("/api/vlans")
async def list_vlans(archive: str = Query(None)):
    try:
        conn = get_db_connection(archive)
        cursor = conn.cursor()
        cursor.execute("SELECT vlan_id, vlan_name, is_admin_named FROM network_vlans ORDER BY vlan_id")
        vlans = [dict(row) for row in cursor.fetchall()]

        # Per-switch source telemetry (see VLAN-3 follow-up: "show the
        # source(s) of the VLAN information") -- joined against the
        # switch's own logical_nodes hostname where known, since a raw
        # IP alone isn't very readable in the UI.
        cursor.execute('''
            SELECT vs.vlan_id, vs.switch_ip, vs.reported_name, vs.last_seen, n.hostname
            FROM vlan_sources vs
            LEFT JOIN l3_bindings b ON vs.switch_ip = b.ip_address
            LEFT JOIN l2_interfaces i ON b.mac_address = i.mac_address
            LEFT JOIN logical_nodes n ON i.node_id = n.id
            ORDER BY vs.vlan_id, vs.switch_ip
        ''')
        sources_by_vlan = {}
        for row in cursor.fetchall():
            sources_by_vlan.setdefault(row["vlan_id"], []).append({
                "switch_ip": row["switch_ip"],
                "hostname": row["hostname"],
                "reported_name": row["reported_name"],
                "last_seen": row["last_seen"],
            })

        # Authoritative router-confirmed subnet<->VLAN bindings (see
        # pollers/vlan_registry.py's discover_router_vlan_subnets --
        # read straight off the router's own interface table, e.g. an
        # interface literally named "bridge-VLAN50"). Used two ways
        # below: shown directly (confirmed=True) under the VLAN that
        # owns them, and used to SUPPRESS that subnet from showing under
        # any OTHER VLAN's FDB-inferred list. Verified live
        # (2026-08-18): a switch reporting a stray vlan=1 for one device
        # on an otherwise-confirmed VLAN 20 subnet is noise -- not
        # evidence that subnet is "also VLAN 1". VLAN 1 in particular
        # was found to not really be one VLAN at all in this network:
        # several genuinely separate, physically-distinct interfaces
        # (a fibre uplink, the base bridge, a plain Ethernet port) just
        # all lack an 802.1Q tag, and switches report untagged traffic
        # as "vlan 1" regardless of which physical segment it's on.
        cursor.execute("SELECT vlan_id, subnet, router_ip, interface_name FROM vlan_subnets")
        confirmed_by_vlan = {}
        subnet_owner = {}
        for vlan_id, subnet, router_ip, interface_name in cursor.fetchall():
            confirmed_by_vlan.setdefault(vlan_id, {})[subnet] = {
                "router_ip": router_ip, "interface_name": interface_name,
            }
            subnet_owner[subnet] = vlan_id

        # Subnet(s) associated with each VLAN, derived from the /24
        # prefix of every endpoint already known to be on it
        # (endpoint_locations.vlan_id, set by the FDB/Wi-Fi scrapers) --
        # no new SNMP queries needed. Shown as a ranked list, not a
        # single "the" answer: an unconfirmed VLAN can legitimately
        # still be ambiguous, and forcing one answer would misrepresent
        # that rather than reveal it. Link-local/loopback addresses are
        # excluded (same filtering already used elsewhere in this app,
        # e.g. auto_discovery.py's discover_active_subnets()), and any
        # subnet already confirmed as belonging to a DIFFERENT VLAN
        # above is excluded too, rather than counted as noise here.
        cursor.execute('''
            SELECT el.vlan_id, b.ip_address
            FROM endpoint_locations el
            JOIN l3_bindings b ON el.mac_address = b.mac_address
            WHERE el.vlan_id IS NOT NULL AND b.ip_address IS NOT NULL
        ''')
        subnet_counters = {}
        for vlan_id, ip in cursor.fetchall():
            try:
                ip_obj = ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            if ip_obj.is_link_local or ip_obj.is_loopback:
                continue
            parts = ip.split(".")
            if len(parts) != 4:
                continue
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            owner = subnet_owner.get(subnet)
            if owner is not None and owner != vlan_id:
                continue
            subnet_counters.setdefault(vlan_id, Counter())[subnet] += 1

        conn.close()

        for v in vlans:
            vid = v["vlan_id"]
            entries = {}
            for subnet, info in confirmed_by_vlan.get(vid, {}).items():
                entries[subnet] = {"subnet": subnet, "count": None, "confirmed": True, **info}
            counter = subnet_counters.get(vid)
            if counter:
                for subnet, count in counter.most_common(5):
                    if subnet in entries:
                        entries[subnet]["count"] = count
                    else:
                        entries[subnet] = {"subnet": subnet, "count": count, "confirmed": False}
            v["subnets"] = sorted(entries.values(), key=lambda e: (not e["confirmed"], -(e["count"] or 0)))[:5]
            v["sources"] = sources_by_vlan.get(vid, [])

        return {"vlans": vlans}
    except Exception as e:
        logger.error(f"[VLAN] list_vlans failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

# --- Confirmed subnets (see NET-1) ---
# General-purpose version of the VLAN-scoped subnet confirmation above:
# every router interface's real subnet (vlan_id NULL for untagged ones),
# populated by the same discover_router_vlan_subnets() SNMP walk.
# Consumed by the dashboard to label subnet columns with their real
# prefix length instead of a hardcoded /24.

@app.get("/api/subnets")
async def list_subnets(archive: str = Query(None)):
    try:
        conn = get_db_connection(archive)
        cursor = conn.cursor()
        cursor.execute("SELECT subnet, router_ip, interface_name, vlan_id FROM router_subnets ORDER BY subnet")
        subnets = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return {"subnets": subnets}
    except Exception as e:
        logger.error(f"[SUBNETS] list_subnets failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/vlans")
async def set_vlan_name(req: VlanNameUpdateRequest):
    try:
        name = req.vlan_name.strip()
        if not name:
            return {"error": "VLAN name cannot be blank."}
        conn = get_db_connection(None)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO network_vlans (vlan_id, vlan_name, is_admin_named)
            VALUES (?, ?, 1)
            ON CONFLICT(vlan_id) DO UPDATE SET vlan_name = excluded.vlan_name, is_admin_named = 1
        ''', (req.vlan_id, name))
        conn.commit()
        conn.close()
        logger.info(f"[VLAN] Admin-named VLAN {req.vlan_id}: '{name}'")
        return {"success": True}
    except Exception as e:
        logger.error(f"[VLAN] set_vlan_name failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/vlans/{vlan_id}/reset")
async def reset_vlan_name(vlan_id: int):
    try:
        conn = get_db_connection(None)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM network_vlans WHERE vlan_id = ?", (vlan_id,))
        if not cursor.fetchone():
            conn.close()
            return {"error": "No such VLAN."}
        cursor.execute("UPDATE network_vlans SET is_admin_named = 0 WHERE vlan_id = ?", (vlan_id,))
        conn.commit()
        conn.close()
        logger.info(f"[VLAN] Reverted VLAN {vlan_id} to SNMP-sourced naming.")
        return {"success": True}
    except Exception as e:
        logger.error(f"[VLAN] reset_vlan_name failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/status")
async def api_status(archive: str = Query(None)):
    try:
        conn = get_db_connection(archive)
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM l3_bindings b JOIN l2_interfaces i ON b.mac_address = i.mac_address JOIN logical_nodes n ON i.node_id = n.id WHERE n.device_type = 'Router' LIMIT 1")
        gw_row = cursor.fetchone()
        conn.close()

        # NATIVE-15, ported to main (2026-09-04): is_populated used to be
        # a live "does a Router node exist right now" query -- confirmed
        # live this stopped reflecting meaningful discovery progress once
        # ROUTER-1 shipped (v3.8.0): gateway self-discovery reads this
        # host's own ARP table (or an SNMP self-query) at the very start
        # of auto_discover_network(), independent of any other device
        # reporting it, so gw_row can appear within the first tick --
        # unlocking the dashboard's tick-lock overlay almost immediately,
        # including right after a Clean Slate purge wiped everything
        # seconds earlier. native-port already solved this exact problem
        # with a one-time persisted flag (main.py sets it the first time
        # tick_counter reaches 2, and resets it whenever Clean Slate
        # purges network.db) instead of a live query; reading that flag
        # here instead of re-deriving "populated enough" from gw_row's
        # current existence is not just simpler, it's the only version of
        # this check that can't be racy: a fresh/just-purged DB has it
        # unset, so is_populated is false no matter how fast the gateway
        # reappears; a restart of an already-discovered appliance has it
        # set from before, so is_populated is true immediately even
        # though tick_counter itself resets to 0/1 again.
        is_populated = str(config._get_setting("_INITIAL_DISCOVERY_COMPLETE", "false")).lower() == "true"

        tick = 0
        try:
            raw_tick = await redis_client.get("ENGINE_TICK")
            if raw_tick is not None: tick = int(raw_tick)
        except Exception: pass

        progress = None
        try:
            raw_progress = await redis_client.get("ENGINE_PROGRESS")
            if raw_progress: progress = json.loads(raw_progress)
        except Exception: pass

        # Restart Engine only checks ENGINE_COMMAND once per tick, at the
        # very top of the loop (see background_polling_engine()) -- it
        # does NOT interrupt a cycle already in progress, despite what
        # the Settings page's own button copy used to imply. Surfacing
        # whether the command is still sitting unconsumed in Redis lets
        # the UI show "scheduled, not yet actioned" instead of looking
        # like nothing happened.
        restart_pending = False
        try:
            restart_pending = await redis_client.get("ENGINE_COMMAND") == "RESTART"
        except Exception: pass

        # Piggybacked on the same 2s poll every page already runs (via
        # index.html's pollEngineTick()) rather than a separate polling
        # cycle -- index.html uses this to force-navigate to Settings and
        # show the "Scanning Paused" modal, the same way it already
        # force-navigates there during the initial tick-lock.
        polling_mode = str(config._get_setting("POLLING_MODE", "continuous")).lower()
        polling_active = str(config._get_setting("_POLLING_ACTIVE", "true")).lower() in ("true", "1", "yes")

        # LOCK-2 (2026-09-16): the frontend's tick-lock overlay (index.html's
        # pollEngineTick()) had no way to tell "actively scanning, not done
        # yet" apart from "setup wizard never even started" -- both look
        # identical from tick/is_populated alone (tick stays 0 forever in
        # the second case, since main.py's background_polling_engine()
        # deliberately suspends polling until SETUP_COMPLETE is true). That
        # made the lock permanent on a genuinely fresh install: it force-
        # navigated to settings.html AND locked it in the same breath,
        # trapping the user behind the exact "Start Now" button they needed
        # to click to ever leave that state. Surfacing the same flag
        # main.py itself gates on lets the frontend tell the two states
        # apart.
        setup_complete = str(config._get_setting("SETUP_COMPLETE", "false")).lower() == "true"

        return {
            "resolved_gateway": gw_row["ip_address"] if gw_row else "Detecting...",
            "monitored_subnets": ["Dynamic Resolution Active"],
            "engine_tick": tick,
            "is_populated": is_populated,
            "progress": progress,
            "restart_pending": restart_pending,
            "polling_mode": polling_mode,
            "polling_active": polling_active,
            "setup_complete": setup_complete
        }
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/topology")
async def api_topology(archive: str = Query(None)):
    try:
        conn = get_db_connection(archive)
        cursor = conn.cursor()
        cursor.execute("SELECT id, hostname, device_type, os_family, weld_confidence FROM logical_nodes")
        nodes = [dict(row) for row in cursor.fetchall()]

        cursor.execute('''
            SELECT l.local_switch_ip, l.remote_system_name, l.local_port, l.local_port_name, l.link_speed, l.is_ambiguous,
                   src_i.node_id AS source_node_id, dst_i.node_id AS target_node_id
            FROM infrastructure_links l
            LEFT JOIN l3_bindings src_b ON l.local_switch_ip = src_b.ip_address
            LEFT JOIN l2_interfaces src_i ON src_b.mac_address = src_i.mac_address
            LEFT JOIN l3_bindings dst_b ON l.remote_system_name = dst_b.ip_address
            LEFT JOIN l2_interfaces dst_i ON dst_b.mac_address = dst_i.mac_address
            WHERE src_i.node_id IS NOT NULL AND dst_i.node_id IS NOT NULL AND src_i.node_id != dst_i.node_id
        ''')
        raw_edges = [dict(row) for row in cursor.fetchall()]
        
        unique_edges = {}
        for edge in raw_edges:
            src, tgt = str(edge["source_node_id"]), str(edge["target_node_id"])
            pair_key = tuple(sorted([src, tgt]))
            if pair_key not in unique_edges:
                unique_edges[pair_key] = {"source_node_id": src, "target_node_id": tgt, "ports": [], "port_names": [], "speeds": [], "is_ambiguous": bool(edge.get("is_ambiguous"))}
            
            port_id = str(edge["local_port"])
            port_name = edge.get("local_port_name") if edge.get("local_port_name") else port_id
            speed = edge.get("link_speed") if edge.get("link_speed") else "Unknown"
            
            if port_id not in unique_edges[pair_key]["ports"]:
                unique_edges[pair_key]["ports"].append(port_id)
                unique_edges[pair_key]["port_names"].append(port_name)
                unique_edges[pair_key]["speeds"].append(speed)
                
            if edge.get("is_ambiguous"): unique_edges[pair_key]["is_ambiguous"] = True

        edges = list(unique_edges.values())

        cursor.execute('''
            SELECT i.mac_address, b.ip_address, el.vlan_id, b.last_seen, b.discovery_source, b.is_ghost, b.http_header, i.vendor, i.category, i.market_segment, i.node_id, i.wireless_ssid, i.is_virtual, n.hostname, n.device_type, n.os_family, n.weld_confidence, df.snmp_sysdescr, ds.status AS device_status
            FROM l2_interfaces i
            LEFT JOIN l3_bindings b ON i.mac_address = b.mac_address
            LEFT JOIN logical_nodes n ON i.node_id = n.id
            LEFT JOIN device_fingerprints df ON i.mac_address = df.mac_address
            LEFT JOIN endpoint_locations el ON i.mac_address = el.mac_address
            LEFT JOIN device_state ds ON i.mac_address = ds.mac_address
            WHERE (b.ip_address IS NOT NULL AND (COALESCE(b.is_public, 0) = 0 OR b.discovery_source = 'ROUTER_INTERFACE')) OR n.device_type IN ('Unmanaged Switch', 'Access Point', 'Switch / WAP')
        ''')
        interfaces = _annotate_subnet_and_primary([dict(row) for row in cursor.fetchall()], conn)
        interfaces = _filter_display_noise_ips(interfaces)

        cursor.execute("SELECT b.ip_address, i.node_id FROM l3_bindings b JOIN l2_interfaces i ON b.mac_address = i.mac_address WHERE b.ip_address IS NOT NULL")
        ip_to_node = {row["ip_address"]: str(row["node_id"]) for row in cursor.fetchall()}

        cursor.execute('''
            SELECT il.local_switch_ip, il.local_port, il.remote_system_name 
            FROM infrastructure_links il
            JOIN l3_bindings b ON il.remote_system_name = b.ip_address
            JOIN l2_interfaces i ON b.mac_address = i.mac_address
            JOIN logical_nodes n ON i.node_id = n.id
            WHERE n.device_type IN ('Unmanaged Switch', 'Smart Switch', 'Smart Switch (Unverified)')
        ''')
        um_links = {(str(row[0]), str(row[1])): row[2] for row in cursor.fetchall()}

        # CLIENTFANOUT-1 (2026-09-21): found live -- a multi-homed
        # client (a Docker host with more than one owned IP, e.g. its
        # real LAN address plus its own Docker bridge gateway
        # addresses) was being counted and rendered as multiple
        # separate "clients" of whatever switch port it's actually on.
        # endpoint_locations has exactly one row per MAC (its own
        # primary key), but l3_bindings has one row per owned IP --
        # the previous query JOINed the two directly, so any device
        # with N owned IPs fanned out into N result rows here, each
        # incrementing client_counts and producing its own duplicate
        # box in the FBD view. Confirmed live: a real appliance host (one
        # real MAC, three owned IPs -- LAN + two Docker bridge gateways)
        # showed as 3 identical clients behind the same switch, which
        # showed "Clients: 8" with only 3 distinct devices actually drawn.
        # b.ip_address IS NOT NULL was only ever meant as an EXISTENCE
        # check ("this device has some known IP, worth counting at
        # all") -- EXISTS preserves that filter without multiplying
        # rows, since endpoint_locations' natural one-row-per-MAC
        # cardinality is no longer joined against a one-row-per-IP
        # table.
        cursor.execute('''
            SELECT el.mac_address, el.local_port, el.local_port_name, el.link_speed, el.switch_ip
            FROM endpoint_locations el
            LEFT JOIN l2_interfaces l2 ON el.mac_address = l2.mac_address
            LEFT JOIN logical_nodes ln ON l2.node_id = ln.id
            WHERE (ln.device_type IN ('Endpoint', 'Server', 'Docker Host', 'Printer') OR ln.device_type IS NULL)
            AND EXISTS (
                SELECT 1 FROM l3_bindings b
                WHERE b.mac_address = el.mac_address AND b.ip_address IS NOT NULL
            )
        ''')

        client_counts = {}
        client_mapping = {}

        for row in cursor.fetchall():
            switch_ip = row["switch_ip"]
            local_port = str(row["local_port"])
            parent_ident = um_links.get((switch_ip, local_port), switch_ip)
            parent_node_id = ip_to_node.get(parent_ident)

            if parent_node_id:
                nid_str = str(parent_node_id)
                client_counts[nid_str] = client_counts.get(nid_str, 0) + 1

                if local_port == 'WLAN':
                    # CAPS-2 (2026-09-09): wifi_scraper.py's WLAN migration
                    # (both the heuristic upstream-inference path and the
                    # Enterprise-MIB path) only ever updates switch_ip/
                    # local_port -- local_port_name/link_speed are left as
                    # whatever they were from this MAC's last WIRED FDB
                    # sighting (typically the AP's own uplink port, since
                    # that's the port a bridged wifi client's traffic
                    # actually appears on in the switch's FDB). Confirmed
                    # live: this made every wireless client display the
                    # AP's wired uplink speed/port instead of "WiFi".
                    display_port, link_speed = "WiFi", "WiFi"
                elif parent_ident != switch_ip:
                    # Reparented via um_links: this client's real FDB
                    # sighting is on the Unmanaged/Smart Switch's own
                    # uplink port into switch_ip -- that port/speed
                    # describes the INTERMEDIATE switch's link, not this
                    # client's (unknowable, smart switches don't expose
                    # their own port tables -- see PLAN-1/session notes)
                    # connection to it. Confirmed live: this made every
                    # device behind a smart switch display the upstream
                    # switch's own port as if it were its own.
                    display_port, link_speed = "Unknown", "Unknown"
                else:
                    display_port = row["local_port_name"] if row["local_port_name"] else local_port
                    link_speed = row["link_speed"] if row["link_speed"] else "Unknown"
                client_mapping[row["mac_address"].lower()] = {"parent_node_id": nid_str, "port": local_port, "port_name": display_port, "link_speed": link_speed}

        # SPARSE-2 (2026-09-05): a device discovered only via NOARP-1's
        # local-ARP fallback (no SNMP anywhere, no FDB/endpoint_locations
        # row) never showed up here -- confirmed live, telemetry showed 3
        # real devices but the graph's router node showed Clients: 0. On
        # a flat network with no visible switch layer, the router IS
        # every such device's only real parent. Only fills in a MAC not
        # already mapped by a stronger source (FDB placement) above.
        cursor.execute("SELECT id FROM logical_nodes WHERE device_type = 'Router' LIMIT 1")
        router_row = cursor.fetchone()
        if router_row:
            router_nid = str(router_row["id"])
            cursor.execute("SELECT b.mac_address FROM l3_bindings b LEFT JOIN l2_interfaces l2 ON b.mac_address = l2.mac_address LEFT JOIN logical_nodes ln ON l2.node_id = ln.id WHERE b.discovery_source = 'LOCAL_ARP_ICMP' AND (ln.device_type = 'Endpoint' OR ln.device_type IS NULL)")
            for row in cursor.fetchall():
                mac_lower = row["mac_address"].lower()
                if mac_lower not in client_mapping:
                    client_counts[router_nid] = client_counts.get(router_nid, 0) + 1
                    client_mapping[mac_lower] = {"parent_node_id": router_nid, "port": "Local ARP", "port_name": "Local ARP", "link_speed": "Unknown"}

        conn.close()
        return {"network_overview": {"total_unified_nodes": len(nodes), "total_active_endpoints": len(interfaces), "total_mapped_links": len(edges)}, "nodes": nodes, "topology_edges": edges, "endpoint_ledger": interfaces, "client_counts": client_counts, "client_mapping": client_mapping}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/dashboard_data")
async def api_dashboard_data(archive: str = Query(None)):
    try:
        conn = get_db_connection(archive)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT i.mac_address, b.ip_address, el.vlan_id, b.last_seen, b.discovery_source, b.is_ghost, b.http_header, i.vendor, i.category, i.market_segment, i.node_id, i.wireless_ssid, i.is_virtual, n.hostname, n.device_type, n.os_family, n.weld_confidence, df.snmp_sysdescr, ds.status AS device_status
            FROM l2_interfaces i
            LEFT JOIN l3_bindings b ON i.mac_address = b.mac_address
            LEFT JOIN logical_nodes n ON i.node_id = n.id
            LEFT JOIN device_fingerprints df ON i.mac_address = df.mac_address
            LEFT JOIN endpoint_locations el ON i.mac_address = el.mac_address
            LEFT JOIN device_state ds ON i.mac_address = ds.mac_address
            WHERE (b.ip_address IS NOT NULL AND (COALESCE(b.is_public, 0) = 0 OR b.discovery_source = 'ROUTER_INTERFACE')) OR n.device_type IN ('Unmanaged Switch', 'Access Point', 'Switch / WAP')
        ''')
        endpoint_ledger = _annotate_subnet_and_primary([dict(row) for row in cursor.fetchall()], conn)
        endpoint_ledger = _filter_display_noise_ips(endpoint_ledger)
        cursor.execute('SELECT COUNT(DISTINCT l.local_switch_ip) FROM infrastructure_links l')
        total_switches = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM infrastructure_links')
        total_links = cursor.fetchone()[0]
        conn.close()
        return {"endpoint_ledger": endpoint_ledger, "network_overview": {"total_mapped_links": total_links, "infrastructure_switches": ["dummy"] * total_switches}}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/inventory")
async def api_inventory_list():
    """
    Lists every device inventory.db knows about -- as of INVENTORY-4,
    that's EVERY device the engine has ever discovered (see
    engine/unification.py's run_inventory_snapshot_sync(), which keeps
    last_known_*/category/market_segment current every deep-scan tick),
    not just ones a human has explicitly confirmed. The human-entered
    fields (user_given_name, confirmed_device_type, notes, and the
    asset-management fields) come straight from this table too --
    they're never touched by the automatic sync, only by
    /api/inventory/update below.

    currently_seen/node_id still need a live network.db check -- the
    stored last_known_* fields reflect the last successful sync, which
    could be stale for a device that's dropped off the network since.
    """
    try:
        inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
        inv_conn.row_factory = sqlite3.Row
        devices = [dict(r) for r in inv_conn.execute(
            """SELECT mac_address, user_given_name, confirmed_device_type, notes,
                      location, asset_tag, serial_number, model, purchase_date, warranty_expiry,
                      last_known_hostname, last_known_vendor, last_known_device_type, last_known_ip,
                      last_known_os_family, last_known_http_header, category, market_segment,
                      first_discovered, last_synced, created_at, updated_at
               FROM verified_devices ORDER BY COALESCE(last_synced, updated_at) DESC"""
        ).fetchall()]
        inv_conn.close()

        conn = get_db_connection(None)
        cursor = conn.cursor()
        live_node_by_mac = {}
        macs = [d["mac_address"] for d in devices]
        if macs:
            placeholders = ",".join("?" * len(macs))
            cursor.execute(f"SELECT mac_address, node_id FROM l2_interfaces WHERE mac_address IN ({placeholders})", macs)
            for row in cursor.fetchall():
                live_node_by_mac[row["mac_address"]] = row["node_id"]
        conn.close()

        for d in devices:
            d["node_id"] = live_node_by_mac.get(d["mac_address"])
            d["currently_seen"] = d["mac_address"] in live_node_by_mac
            # A dark-matter pseudo-switch's ip_address is a synthetic
            # port-encoded placeholder, not a real dialable address --
            # see _is_real_ip's own docstring. Same filtering the rest
            # of the UI already applies via _filter_display_noise_ips,
            # so this page doesn't show "10.10.10.10033" as if it were
            # a real IP. run_inventory_snapshot_sync() stores it raw
            # (that's the storage layer's job to stay simple); this is
            # the presentation layer, same as everywhere else it's used.
            if not _is_real_ip(d["last_known_ip"]):
                d["last_known_ip"] = None

        return {"devices": devices}
    except Exception as e:
        logger.error(f"[API] inventory list failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/inventory/update")
async def api_inventory_update(req: InventoryUpdateRequest):
    try:
        mac = req.mac_address.strip().lower()
        if not mac:
            return {"error": "MAC address is required."}

        # None (field omitted from the JSON entirely) -> leave it alone.
        # "" (field explicitly sent blank) -> clear it (NULL). See the
        # request model's own docstring for why this distinction exists.
        raw_fields = {
            "user_given_name": req.user_given_name, "confirmed_device_type": req.confirmed_device_type,
            "notes": req.notes, "location": req.location, "asset_tag": req.asset_tag,
            "serial_number": req.serial_number, "model": req.model,
            "purchase_date": req.purchase_date, "warranty_expiry": req.warranty_expiry,
        }
        provided = {k: (v.strip() or None) for k, v in raw_fields.items() if v is not None}

        inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
        inv_conn.execute("INSERT OR IGNORE INTO verified_devices (mac_address) VALUES (?)", (mac,))
        if provided:
            set_clause = ", ".join(f"{k} = ?" for k in provided) + ", updated_at = CURRENT_TIMESTAMP"
            inv_conn.execute(f"UPDATE verified_devices SET {set_clause} WHERE mac_address = ?", (*provided.values(), mac))
        inv_conn.commit()
        inv_conn.close()

        # Mirror onto the live node immediately if one currently exists
        # for this MAC -- same dual-write discipline as
        # _persist_inventory_override's counterpart direction
        # (/api/node/update goes node_id -> mac -> inventory.db; this
        # goes mac -> node_id -> network.db), so an edit made here
        # shows up on the Graph UI/Devices page right away instead of
        # waiting for the next deep-scan tick's overlay pass. Only
        # user_given_name/confirmed_device_type have a live counterpart
        # to mirror onto -- the asset-management fields have no
        # equivalent in network.db.
        name = provided.get("user_given_name")
        dtype = provided.get("confirmed_device_type")
        if name is not None or dtype is not None:
            conn = get_db_connection(None)
            cursor = conn.cursor()
            cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (mac,))
            row = cursor.fetchone()
            if row and row["node_id"] is not None:
                updates, params = [], []
                if name is not None:
                    updates.append("hostname = ?"); params.append(name)
                if dtype is not None:
                    updates.append("device_type = ?"); params.append(dtype)
                updates.append("weld_confidence = 100")
                params.append(row["node_id"])
                cursor.execute(f"UPDATE logical_nodes SET {', '.join(updates)} WHERE id = ?", params)
                conn.commit()
            conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[API] inventory update failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.delete("/api/inventory/{mac_address}")
async def api_inventory_delete(mac_address: str):
    try:
        inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
        inv_conn.execute("DELETE FROM verified_devices WHERE mac_address = ?", (mac_address.strip().lower(),))
        inv_conn.commit()
        inv_conn.close()
        return {"success": True}
    except Exception as e:
        logger.error(f"[API] inventory delete failed: {e}")
        return {"error": "An internal error occurred. See server logs for details."}

def _persist_inventory_override(node_id: int, user_given_name: str = None, confirmed_device_type: str = None) -> None:
    """
    INVENTORY-1 (2026-09-04): /api/node/update and /api/promote_node
    both write a user's correction directly into network.db's
    logical_nodes -- which main.py's rotate_database() Clean Slate
    purge wipes on the very next version-bump reboot, and which gets a
    brand new autoincrement id on every ordinary re-discovery cycle
    regardless. Confirmed live: this was already true for every manual
    correction a user has ever made through either endpoint, not just
    the smart-switch case that surfaced it -- neither endpoint had ever
    persisted anything past the next purge.

    Looks up the node's MAC (the one identifier that survives a purge)
    and upserts into inventory.db's verified_devices, a separate file
    main.py's Clean Slate purge never touches. engine/unification.py's
    run_inventory_overlay_pass() re-applies this onto whatever
    logical_nodes row that MAC ends up with every deep-scan cycle from
    now on, so the correction sticks for good. A node with no resolved
    MAC yet (shouldn't normally happen for anything a user can already
    see to correct) is a silent no-op -- the network.db-side update
    the caller already made still took effect for this session, just
    won't survive a purge.
    """
    if not user_given_name and not confirmed_device_type:
        return
    try:
        conn = get_db_connection(None)
        cursor = conn.cursor()
        cursor.execute("SELECT mac_address FROM l2_interfaces WHERE node_id = ? LIMIT 1", (node_id,))
        row = cursor.fetchone()
        conn.close()
        if not row or not row["mac_address"]:
            return
        mac = row["mac_address"]

        inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
        inv_conn.execute("""
            INSERT INTO verified_devices (mac_address, user_given_name, confirmed_device_type, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(mac_address) DO UPDATE SET
                user_given_name = COALESCE(excluded.user_given_name, verified_devices.user_given_name),
                confirmed_device_type = COALESCE(excluded.confirmed_device_type, verified_devices.confirmed_device_type),
                updated_at = CURRENT_TIMESTAMP
        """, (mac, user_given_name, confirmed_device_type))
        inv_conn.commit()
        inv_conn.close()
    except Exception as e:
        logger.warning(f"[API] Failed to persist inventory override for node {node_id}: {e}")


@app.post("/api/promote_node")
async def api_promote_node(req: PromotionRequest):
    if req.target_type not in ["Switch", "Access Point", "Smart Switch"]: return {"error": "Invalid target type."}
    try:
        conn = get_db_connection(None)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM logical_nodes WHERE id = ?", (req.node_id,))
        if not cursor.fetchone(): return {"error": "Node not found."}
        cursor.execute("UPDATE logical_nodes SET device_type = ?, weld_confidence = 100 WHERE id = ?", (req.target_type, req.node_id))
        conn.commit()
        conn.close()
        _persist_inventory_override(req.node_id, confirmed_device_type=req.target_type)
        return {"success": True, "message": "Node promoted."}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/node/verify")
async def api_verify_node(req: ContextActionRequest):
    try:
        conn = get_db_connection(None)
        cursor = conn.cursor()
        cursor.execute("UPDATE logical_nodes SET weld_confidence = 100 WHERE id = ?", (req.node_id,))
        cursor.execute('''
            SELECT b.ip_address FROM l3_bindings b 
            JOIN l2_interfaces i ON b.mac_address = i.mac_address 
            WHERE i.node_id = ?
        ''', (req.node_id,))
        row = cursor.fetchone()
        if row:
            ip = row["ip_address"]
            cursor.execute("UPDATE infrastructure_links SET is_ambiguous = 0 WHERE remote_system_name = ?", (ip,))
            cursor.execute("UPDATE endpoint_locations SET is_ambiguous = 0 WHERE switch_ip = ?", (ip,))
        conn.commit()
        conn.close()
        return {"success": True, "message": "Node fully verified."}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/node/remove")
async def api_remove_node(req: ContextActionRequest):
    try:
        conn = get_db_connection(None)
        cursor = conn.cursor()
        cursor.execute("UPDATE logical_nodes SET device_type = 'False Positive', weld_confidence = -1 WHERE id = ?", (req.node_id,))
        cursor.execute('''
            SELECT b.ip_address, b.mac_address FROM l3_bindings b 
            JOIN l2_interfaces i ON b.mac_address = i.mac_address 
            WHERE i.node_id = ?
        ''', (req.node_id,))
        row = cursor.fetchone()
        if row:
            ip = row["ip_address"]
            mac = row["mac_address"]
            cursor.execute("DELETE FROM infrastructure_links WHERE remote_system_name = ?", (ip,))
            cursor.execute("UPDATE endpoint_locations SET is_ambiguous = 0 WHERE mac_address = ?", (mac,))
        conn.commit()
        conn.close()
        return {"success": True, "message": "False positive destroyed."}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.get("/api/node/{node_id}")
async def get_node_details(node_id: int):
    """
    DEVICE-1 (2026-09-09): expanded to actually return everything this
    query was already fetching (wireless_ssid, is_ghost,
    snmp_sysobjectid, banner, fp_last_updated were all selected and
    silently discarded before reaching the interface dict below -- same
    discard-after-select shape as OUI-4), plus join in device_state
    (online/offline), inventory.db's per-MAC record (asset fields +
    last-known snapshot + human notes -- see engine/unification.py's
    run_inventory_snapshot_sync()), and any currently-active
    device_findings across every MAC on this node.
    """
    try:
        conn = get_db_connection(None)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT
                n.id as node_id, n.hostname, n.device_type, n.os_family, n.weld_confidence,
                i.mac_address, i.vendor, i.category, i.market_segment, i.is_virtual, i.wireless_ssid,
                b.ip_address, b.vlan_id, b.discovery_source, b.is_public, b.is_ghost, b.last_seen, b.http_header,
                df.snmp_sysdescr, df.snmp_sysobjectid, df.banner, df.last_updated as fp_last_updated,
                ds.status AS device_status
            FROM logical_nodes n
            LEFT JOIN l2_interfaces i ON n.id = i.node_id
            LEFT JOIN l3_bindings b ON i.mac_address = b.mac_address
            LEFT JOIN device_fingerprints df ON i.mac_address = df.mac_address
            LEFT JOIN device_state ds ON i.mac_address = ds.mac_address
            WHERE n.id = ?
        ''', (node_id,))
        rows = cursor.fetchall()

        if not rows:
            conn.close()
            return {"error": "Node not found."}

        node_profile = {
            "node_id": rows[0]["node_id"], "hostname": rows[0]["hostname"], "device_type": rows[0]["device_type"],
            "os_family": rows[0]["os_family"], "weld_confidence": rows[0]["weld_confidence"], "interfaces": []
        }

        macs = []
        for row in rows:
            if row["mac_address"]:
                macs.append(row["mac_address"])
                node_profile["interfaces"].append({
                    "mac_address": row["mac_address"], "ip_address": row["ip_address"], "vendor": row["vendor"],
                    "category": row["category"], "market_segment": row["market_segment"],
                    "vlan_id": row["vlan_id"], "discovery_source": row["discovery_source"], "is_public": bool(row["is_public"]),
                    "is_ghost": bool(row["is_ghost"]), "is_virtual": bool(row["is_virtual"]),
                    "wireless_ssid": row["wireless_ssid"], "last_seen": row["last_seen"],
                    "device_status": row["device_status"], "snmp_sysdescr": row["snmp_sysdescr"],
                    "snmp_sysobjectid": row["snmp_sysobjectid"], "banner": row["banner"],
                    "fp_last_updated": row["fp_last_updated"], "http_header": row["http_header"],
                })

        # _persist_inventory_override's own "which MAC represents this
        # node in inventory.db" convention -- first l2_interfaces row,
        # same tie-break SQLite's own unordered LIMIT 1 would give.
        primary_mac = macs[0] if macs else None
        node_profile["primary_mac"] = primary_mac

        node_profile["findings"] = []
        if macs:
            placeholders = ",".join("?" * len(macs))
            cursor.execute(f'''
                SELECT mac_address, finding_type, severity, detail, first_detected, last_confirmed
                FROM device_findings
                WHERE mac_address IN ({placeholders}) AND resolved_at IS NULL
                ORDER BY CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
            ''', macs)
            node_profile["findings"] = [dict(r) for r in cursor.fetchall()]
        conn.close()

        node_profile["inventory"] = None
        if primary_mac:
            inv_conn = sqlite3.connect(config.INVENTORY_DB_PATH)
            inv_conn.row_factory = sqlite3.Row
            inv_row = inv_conn.execute(
                """SELECT notes, location, asset_tag, serial_number, model, purchase_date, warranty_expiry,
                          last_known_hostname, last_known_vendor, last_known_device_type, last_known_ip,
                          last_known_os_family, first_discovered, last_synced, created_at, updated_at
                   FROM verified_devices WHERE mac_address = ?""",
                (primary_mac,)
            ).fetchone()
            inv_conn.close()
            if inv_row:
                node_profile["inventory"] = dict(inv_row)

        return {"success": True, "data": node_profile}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}

@app.post("/api/node/update")
async def update_node_details(req: NodeUpdateRequest):
    try:
        conn = get_db_connection(None)
        cursor = conn.cursor()
        updates = []
        params = []
        if req.hostname is not None:
            updates.append("hostname = ?")
            params.append(req.hostname)
        if req.device_type is not None:
            updates.append("device_type = ?")
            params.append(req.device_type)
        if not updates: return {"error": "No fields to update."}
        params.append(req.node_id)
        query = f"UPDATE logical_nodes SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()
        conn.close()
        _persist_inventory_override(req.node_id, user_given_name=req.hostname, confirmed_device_type=req.device_type)
        return {"success": True, "message": "Node updated successfully."}
    except Exception as e:
        logger.error(f"[API] {e}")
        return {"error": "An internal error occurred. See server logs for details."}
