import asyncio
import json
import re
import logging
import ipaddress
import os
import platform
import sqlite3
import tempfile
import time
from engine.config_loader import config
from engine.snmp_credential import (
    SNMPCredential, SNMPVersion,
    AUTH_PROTOCOLS_BY_STRENGTH, PRIV_PROTOCOLS_BY_STRENGTH,
    NET_SNMP_AUTH_FLAG, NET_SNMP_PRIV_FLAG,
)
from security.credential_vault import decrypt_password, encrypt_password, is_encrypted

logger = logging.getLogger("Netlanvas.SNMP")

# NATIVE-3: no net-snmp CLI exists for Windows (see tools/snmp_helper's
# own header comment for the research behind this) -- this Go binary
# wraps gosnmp with the same GET/WALK/v2c/v3-authPriv contract, and the
# same argv-secret-avoidance discipline as the Linux path below (see
# run_snmp_command's own comment on that): credentials are never argv
# here either, they go over the subprocess's stdin as JSON. Verified
# live against a real snmpd (v2c and v3 authPriv, correct AND wrong
# credentials) and against the real lab router from real Windows
# hardware before this was wired in. Default path mirrors
# PING_SWEEP_HELPER_PATH's own repo-relative fallback -- see that
# constant's comment in pollers/ping_sweeper.py; Phase 3 packaging
# should set the env var rather than rely on this default.
SNMP_HELPER_PATH = os.getenv(
    "NETLANVAS_SNMP_HELPER",
    os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "tools", "snmp_helper",
        "netlanvas_snmp_helper.exe" if platform.system() == "Windows" else "netlanvas_snmp_helper",
    )),
)

def clean_snmp_string(raw_val):
    if not raw_val: return raw_val
    raw_str = str(raw_val)
    match = re.search(r'"([^"]*)"', raw_str)
    if match: return match.group(1).strip()
    return re.sub(r'^\.\d+(?:\.\d+)+\s+', '', raw_str).strip()

def format_port_name(raw_name):
    if not raw_name: return raw_name
    name_str = str(raw_name).strip()
    if len(name_str) <= 13: return name_str
    name_str = re.sub(r'(?i)TenGigabitEthernet', '10GbE', name_str)
    name_str = re.sub(r'(?i)GigabitEthernet', 'GbE', name_str)
    name_str = re.sub(r'(?i)FastEthernet', 'FE', name_str)
    name_str = re.sub(r'(?i)\bGigabit\b', 'Gb', name_str)
    name_str = re.sub(r'(?i)Slot:\s*(\d+)', r'S\1', name_str)
    name_str = re.sub(r'(?i)Port:\s*(\d+)', r'P\1', name_str)
    name_str = re.sub(r'(?i)\bLevel\b', '', name_str)
    return re.sub(r'\s+', ' ', name_str).strip()

CREDENTIAL_CACHE = {}

# username -> (auth_protocol, priv_protocol) that last actually worked
# for this SNMPv3 identity, ANYWHERE on the network (2026-09-08). A
# real fleet almost always uses one consistent auth/priv pairing across
# every device for a given identity -- once the full strength-
# descending search (6 auth x 4 priv = 24 combinations) finds the
# right one for the FIRST device, every OTHER device using that same
# identity can try that remembered combo first instead of repeating
# the full 24-combination search. Pure optimization, not correctness:
# if the remembered combo is wrong for some device (mixed
# configurations do exist), adaptive_snmp_query() just falls through
# to the rest of the strength-descending list exactly as before. In-
# memory only, same as CREDENTIAL_CACHE -- resets on restart, which is
# fine since it costs at most one extra failed attempt to rebuild.
LAST_WORKING_V3_PROTOCOLS = {}

# ip_address -> (streak_count, last_increment_timestamp) for the
# CACHED credential specifically. MIN_SECONDS_BETWEEN_STREAK_INCREMENTS
# exists because a single "logical" polling attempt can generate
# MULTIPLE concurrent adaptive_snmp_query calls against the same
# device (e.g. mac_table_scraper.py fires 7 concurrent OID walks per
# switch via asyncio.gather). Without this guard, a device that's
# simply busy handling that burst can fail all 7 nearly simultaneously,
# blowing through CACHE_RETRY_THRESHOLD in under a second instead of
# across genuinely separate ~60s polling cycles as intended.
CREDENTIAL_FAILURE_STREAK = {}
CACHE_RETRY_THRESHOLD = 3
MIN_SECONDS_BETWEEN_STREAK_INCREMENTS = 30

# RETRY-1: CREDENTIAL_CACHE[ip] used to store the bare string
# "UNRESPONSIVE" -- a device that failed a full strength-descending
# credential probe (every configured v2c/v3 identity, every auth/priv
# protocol pairing) was permanently blacklisted for the rest of the
# process's life, with no expiry and no retry mechanism at all.
# Confirmed live: a real UniFi/TP-Link AP that was genuinely
# unreachable for a period (device-side, unrelated to NetLanvas) got
# marked UNRESPONSIVE, came back online minutes later (confirmed
# reachable via a completely independent test tool), and stayed stuck
# misclassified for the rest of that process's lifetime regardless --
# fingerprinter.py's own worker() never even attempted it again,
# because get_working_credential()/adaptive_snmp_query() both
# short-circuited to the cached UNRESPONSIVE marker before ever
# touching the network. Devices that never hit this state (never
# actually went unresponsive) were entirely unaffected -- confirmed,
# an Aruba AP on the same network fingerprinted correctly the whole
# time, simply because it never triggered this code path.
#
# Now a (marker, tick) tuple instead of a bare string, so a device
# gets one retry attempt every few ticks instead of being permanently
# written off. Tick-based, not wall-clock -- tick duration varies
# wildly in this codebase (observed anywhere from ~15s to 20+ minutes
# depending on how many devices need deep SNMP discovery that cycle --
# the exact same reason STATE-3/STATE-4 moved device_state_tracker.py's
# own offline-detection off wall-clock timing entirely), so a fixed
# wall-clock retry interval would be meaningless: too eager during a
# fast/quiet tick, needlessly slow during a device-heavy one.
#
# _current_tick is updated once per tick by main.py's own tick loop
# (set_current_tick()) rather than threading a tick parameter through
# every poller's own call chain into this module -- adaptive_snmp_query/
# get_working_credential are called from half a dozen different files
# many layers deep (fingerprinter, mac_table_scraper, ping_sweeper,
# wifi_scraper, vlan_registry, snmp_pipeline), so a shared module-level
# value read from anywhere is far less invasive than a parameter
# threaded through all of them -- the same pattern CREDENTIAL_CACHE
# itself already uses. Naturally resets to 0 on every process restart,
# in lockstep with CREDENTIAL_CACHE itself also being wiped on restart
# (pure in-memory state, nothing persisted to disk) -- no baseline-
# reset logic needed the way device_state.last_seen_tick required,
# since there's no stale on-disk value to reconcile against.
UNRESPONSIVE_RETRY_TICKS = 5
_current_tick = 0


def set_current_tick(tick: int) -> None:
    global _current_tick
    _current_tick = tick


def _is_unresponsive_marker(cached) -> bool:
    return isinstance(cached, tuple) and len(cached) == 2 and cached[0] == "UNRESPONSIVE"


def _unresponsive_due_for_retry(cached) -> bool:
    _, marked_at_tick = cached
    return (_current_tick - marked_at_tick) >= UNRESPONSIVE_RETRY_TICKS


# PLAN-1 (2026-09-09): SNMP-FRAMEWORK-MIB's snmpEngineID -- populated
# only on an agent that has a real SNMPv3/USM stack compiled in, and
# (like any MIB object) readable over an ordinary v2c GET regardless of
# which security model is actually asking. A device that answers this
# has a v3 stack worth eventually trying; one that returns "No Such
# Object" doesn't, full stop -- no amount of credential guessing would
# ever have found anything.
_ENGINE_ID_OID = "1.3.6.1.6.3.10.2.1.1.0"

# Relative, not absolute -- matches UNRESPONSIVE_RETRY_TICKS's own
# _current_tick + N convention just above. An absolute "tick 3" would
# be meaningless for a device first discovered on, say, tick 250 of a
# long-running appliance.
V3_UPGRADE_DEFER_TICKS = 3

# ip -> tick its deferred v3-credential discovery becomes due. Only
# ever populated for a device that (a) already answers v2c -- so
# there's no urgency, tick 0/1 already gets real data from it -- and
# (b) confirmed via the engineID probe above to have a v3 stack worth
# eventually trying. Removed the moment the deferred check actually
# runs (success or failure), so it fires at most once per device.
DEFERRED_V3_UPGRADE = {}

# ip's whose deferred upgrade check is currently running in the
# background -- guards against firing it twice if two callers both
# land on the same device on/after its due tick.
_V3_UPGRADE_IN_FLIGHT = set()

# ip's whose deferred upgrade check has run to COMPLETION, success or
# not -- checked by a sibling IP (same logical node) before it pays
# its own cascade cost, so a negative result is shared just as much as
# a positive one. Separate from CREDENTIAL_CACHE, which only ever
# records positive outcomes.
V3_UPGRADE_ATTEMPTED = set()

# ALERT-6 (2026-09-09): every ip whose snmpEngineID has ever answered,
# i.e. confirmed to have a real v3 stack -- regardless of whether we
# ever found a configured credential that works against it. Read by
# pollers/snmp_v3_available_detector.py to flag a device that's
# capable of the stronger, encrypted/authenticated protocol but is
# currently being managed over plaintext v2c instead -- a real,
# actionable hardening gap this same engineID probe already surfaces
# for free, no extra scanning needed. Grows, never shrinks -- "this
# device has a v3 stack" doesn't stop being true if a later poll
# doesn't happen to re-confirm it.
V3_CAPABLE_IPS = set()


async def _try_v3_cascade(ip, oid, walk, timeout, retries, v3_credentials, search_start=None):
    """
    The strength-descending SNMPv3 auth/priv cascade, extracted out of
    adaptive_snmp_query() so PLAN-1's deferred background upgrade check
    (_run_deferred_v3_upgrade below) can reuse the exact same logic
    used for a device's real-time fallback probe, rather than
    duplicating it. Same caching/LAST_WORKING_V3_PROTOCOLS side effects
    as before this was extracted -- callers just get back the query
    result (or None), the cache updates happen here either way.
    """
    for base_credential in v3_credentials:
        remembered = LAST_WORKING_V3_PROTOCOLS.get(base_credential.username)
        proto_order = ([remembered] if remembered else []) + [
            (a, p) for a in AUTH_PROTOCOLS_BY_STRENGTH for p in PRIV_PROTOCOLS_BY_STRENGTH
            if (a, p) != remembered
        ]
        for auth_proto, priv_proto in proto_order:
            trial = base_credential.resolved_with(auth_proto, priv_proto)
            result = await run_snmp_command(ip, oid, trial, walk, timeout, retries)
            if result is not None:
                elapsed = f"{time.monotonic() - search_start:.1f}s search" if search_start is not None else "background upgrade"
                if CREDENTIAL_CACHE.get(ip) != trial:
                    CREDENTIAL_CACHE[ip] = trial
                    logger.info(f"[*] SNMP Auth Locked: {ip} verified with {trial.display_label()} ({auth_proto}/{priv_proto}) (Added to Cache, {elapsed})")
                LAST_WORKING_V3_PROTOCOLS[base_credential.username] = (auth_proto, priv_proto)
                CREDENTIAL_FAILURE_STREAK.pop(ip, None)
                return result
    return None


async def _probe_and_schedule_v3_upgrade(ip: str, v2c_credential) -> None:
    """
    PLAN-1: called right after a device is found to answer v2c. v2c
    already serves every real tick 0/1 query for it, so there's no
    urgency to also find its v3 credentials right now -- but v3 is the
    stronger, encrypted protocol, worth switching to eventually if the
    device supports it. One cheap extra v2c GET (the engineID OID
    above) decides whether that's even worth attempting; if so, the
    real 24-combination cascade is scheduled for a later, non-critical
    tick instead of paying its cost during the current one. No-op if
    this device already has a scheduled or completed check.
    """
    if ip in DEFERRED_V3_UPGRADE or ip in _V3_UPGRADE_IN_FLIGHT:
        return
    engine_id = await run_snmp_command(ip, _ENGINE_ID_OID, v2c_credential, walk=False, timeout=1, retries=1)
    if not engine_id:
        return  # no v3 stack detected -- never worth trying, nothing to schedule
    V3_CAPABLE_IPS.add(ip)
    target_tick = _current_tick + V3_UPGRADE_DEFER_TICKS
    DEFERRED_V3_UPGRADE[ip] = target_tick
    logger.info(f"[*] SNMP: {ip} answers v2c and has a v3 engine ({engine_id}) -- deferring v3 credential discovery to tick {target_tick}, using v2c meanwhile.")


def _maybe_trigger_deferred_v3_upgrade(ip: str) -> None:
    """
    Fire-and-forget: if this IP's deferred v3 upgrade is due, run it in
    the background. Deliberately not awaited by the caller -- whoever
    triggered this already has their own (v2c-served) answer in hand,
    and the upgrade attempt can genuinely cost up to the full ~100s
    cascade if the remembered combo doesn't match this device.
    """
    target_tick = DEFERRED_V3_UPGRADE.get(ip)
    if target_tick is None or _current_tick < target_tick or ip in _V3_UPGRADE_IN_FLIGHT:
        return
    _V3_UPGRADE_IN_FLIGHT.add(ip)
    asyncio.create_task(_run_deferred_v3_upgrade(ip))


def check_due_v3_upgrades() -> None:
    """
    PLAN-1 follow-up (2026-09-09): _maybe_trigger_deferred_v3_upgrade()
    only ever fires as a side effect of some OTHER caller happening to
    touch that same IP via get_working_credential()/adaptive_snmp_query()
    on or after its due tick. Confirmed live: a device LLDP/VLAN
    registry have already "certified" stops getting actively
    re-queried every tick (they just carry it forward in a summary list
    instead) -- so a device that's gone fully quiet can sit with its
    upgrade due but never triggered until the next full device sweep
    (a deep-scan tick, ~11-13 min apart), even though nothing about the
    mechanism itself is broken. Call this once per tick, unconditionally,
    so "due" actually means "runs this tick" regardless of whether
    anything else happens to touch the device. No SNMP traffic of its
    own -- iterates the same DEFERRED_V3_UPGRADE dict
    _maybe_trigger_deferred_v3_upgrade already reads, just proactively
    instead of opportunistically. list(...) copies the keys before
    iterating since _run_deferred_v3_upgrade mutates this same dict
    (pops itself out on completion) from a concurrently-scheduled task.
    """
    for ip in list(DEFERRED_V3_UPGRADE.keys()):
        _maybe_trigger_deferred_v3_upgrade(ip)


def _sibling_ips_same_node(ip: str) -> list:
    """
    Every OTHER IP address currently welded to the same logical_nodes
    row as `ip`, via l3_bindings -> l2_interfaces -> node_id. By the
    time a deferred v3 upgrade actually fires (tick 3+), a multihomed
    device's several VLAN-interface IPs (a router being the clearest
    case) have normally already been welded into one node by
    unification.run_unification_engine(), which runs every tick between
    when this was scheduled and when it comes due. Deliberately DB-
    driven, not an assumption like "every gateway-looking IP is the
    same router" -- that doesn't hold in general (independent
    routers/VRRP pairs are real topologies); this only ever treats two
    IPs as the same device once the unification engine has actually
    said so.
    """
    try:
        conn = sqlite3.connect(config.DB_PATH)
        rows = conn.execute(
            """
            SELECT DISTINCT l3b2.ip_address
            FROM l3_bindings l3b1
            JOIN l2_interfaces l2i1 ON l3b1.mac_address = l2i1.mac_address
            JOIN l2_interfaces l2i2 ON l2i2.node_id = l2i1.node_id
            JOIN l3_bindings l3b2 ON l3b2.mac_address = l2i2.mac_address
            WHERE l3b1.ip_address = ? AND l3b2.ip_address != ?
            """,
            (ip, ip),
        ).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except sqlite3.OperationalError:
        return []


def _node_lock_key_for_ip(ip: str) -> str:
    """
    A stable key shared by every IP welded to the same logical_nodes
    row, for _NODE_V3_UPGRADE_LOCKS below. Falls back to the bare IP
    (a lock nothing else will ever contend for) when it isn't welded
    to anything yet -- same "no assumption, DB says so or it doesn't"
    discipline as _sibling_ips_same_node.
    """
    try:
        conn = sqlite3.connect(config.DB_PATH)
        row = conn.execute(
            "SELECT l2i.node_id FROM l3_bindings l3b JOIN l2_interfaces l2i ON l3b.mac_address = l2i.mac_address WHERE l3b.ip_address = ?",
            (ip,),
        ).fetchone()
        conn.close()
        if row and row[0] is not None:
            return f"node:{row[0]}"
    except sqlite3.OperationalError:
        pass
    return f"ip:{ip}"


# node-key -> asyncio.Lock. check_due_v3_upgrades() fires every due IP
# via create_task() in one tight loop -- confirmed live 2026-09-09:
# without this, a multihomed device's several sibling IPs all start
# their deferred check in the SAME instant, so each one's sibling-
# already-attempted check sees nothing yet (none of them have finished)
# and all of them redundantly run the real ~100s cascade anyway. This
# serializes concurrent siblings onto one real cascade attempt -- the
# first one through actually runs it, the rest block on this lock and
# then find its now-recorded result waiting for them.
_NODE_V3_UPGRADE_LOCKS = {}


def _get_node_v3_lock(node_key: str) -> asyncio.Lock:
    if node_key not in _NODE_V3_UPGRADE_LOCKS:
        _NODE_V3_UPGRADE_LOCKS[node_key] = asyncio.Lock()
    return _NODE_V3_UPGRADE_LOCKS[node_key]


async def _run_deferred_v3_upgrade(ip: str) -> None:
    node_key = _node_lock_key_for_ip(ip)
    async with _get_node_v3_lock(node_key):
        try:
            # Check whether a sibling IP's deferred check has ALREADY
            # run -- reuse its outcome either way, not just a positive
            # one. Confirmed live (2026-09-09): a router that genuinely
            # doesn't accept any configured v3 identity on one
            # interface won't accept it on any other interface either
            # (same SNMP engine, same configured users) -- without
            # this, every one of its VLAN-interface IPs independently
            # re-paid the full ~100s cascade just to independently
            # re-fail it. The node-keyed lock above is what makes this
            # check meaningful when check_due_v3_upgrades() fires every
            # sibling in the same instant: without it, none of them
            # would have finished yet when the others check, and this
            # loop would find nothing to reuse either way -- confirmed
            # live the same day, all 4 of a router's IPs independently
            # ran the full cascade concurrently before this lock was
            # added.
            for sibling_ip in _sibling_ips_same_node(ip):
                sibling_cred = CREDENTIAL_CACHE.get(sibling_ip)
                if sibling_cred is not None and not _is_unresponsive_marker(sibling_cred) and sibling_cred.version != SNMPVersion.V2C:
                    CREDENTIAL_CACHE[ip] = sibling_cred
                    logger.info(f"[*] SNMP: {ip}'s deferred v3 upgrade skipped -- sibling {sibling_ip} (same logical node) already has a working v3 credential, reusing it.")
                    return
                if sibling_ip in V3_UPGRADE_ATTEMPTED:
                    logger.info(f"[*] SNMP: {ip}'s deferred v3 upgrade skipped -- sibling {sibling_ip} (same logical node) already tried and found nothing, staying on v2c.")
                    return

            v3_credentials = [c for c in get_configured_credentials() if c.version != SNMPVersion.V2C]
            result = await _try_v3_cascade(ip, "1.3.6.1.2.1.1.2", True, 1, 1, v3_credentials)
            if result is None:
                logger.info(f"[*] SNMP: {ip}'s deferred v3 upgrade check found no working v3 credential -- staying on v2c.")
        except Exception as e:
            logger.warning(f"[*] SNMP: {ip}'s deferred v3 upgrade check failed: {e}")
        finally:
            V3_UPGRADE_ATTEMPTED.add(ip)
            DEFERRED_V3_UPGRADE.pop(ip, None)
            _V3_UPGRADE_IN_FLIGHT.discard(ip)


# ip_address -> asyncio.Lock. Ensures only ONE full credential re-probe
# runs at a time per device, even when several concurrent callers all
# need one at once -- mac_table_scraper.py's process_switch_fdb is the
# clearest example, firing 7 concurrent adaptive_snmp_query calls per
# switch via asyncio.gather. Without this, each of those 7 discovers
# independently that a re-probe is needed and each launches its own
# full walk through every configured credential -- confirmed live: one
# device produced 7 identical "re-probing full list" log lines and 7
# redundant full walks in the same burst. Callers that find the lock
# already held simply wait for the in-flight probe and reuse whatever
# credential it lands on, instead of repeating the work.
IP_PROBE_LOCKS = {}

def _get_probe_lock(ip):
    if ip not in IP_PROBE_LOCKS:
        IP_PROBE_LOCKS[ip] = asyncio.Lock()
    return IP_PROBE_LOCKS[ip]


def _find_sibling_credential(ip: str):
    """
    POLL-2: looks up other IPs bound to the SAME logical node as `ip`
    and returns the first one that already has a working credential
    cached, or None. A multi-homed device (confirmed live via TOPO-1: a
    single router can genuinely have 6+ interface IPs) shares one SNMP
    agent regardless of which of its own IPs you reach it on -- SNMP
    talks to the device, not the interface -- so a credential discovered
    via any one of its IPs is a high-confidence candidate for the
    others. Only ever used as a candidate to VERIFY (see
    get_working_credential), never trusted blindly, in case unification
    ever groups two IPs under one node incorrectly.
    """
    try:
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT b2.ip_address
            FROM l3_bindings b1
            JOIN l2_interfaces i1 ON b1.mac_address = i1.mac_address
            JOIN l2_interfaces i2 ON i1.node_id = i2.node_id
            JOIN l3_bindings b2 ON i2.mac_address = b2.mac_address
            WHERE b1.ip_address = ? AND b2.ip_address != ? AND i1.node_id IS NOT NULL
        ''', (ip, ip))
        sibling_ips = [row[0] for row in cursor.fetchall()]
        conn.close()
    except Exception:
        return None

    for sibling_ip in sibling_ips:
        cached = CREDENTIAL_CACHE.get(sibling_ip)
        if cached and not _is_unresponsive_marker(cached):
            return cached
    return None


def get_configured_credentials() -> list:
    v3_identities = []
    try:
        conn = sqlite3.connect(config.CONFIG_DB_PATH)
        rows = conn.execute(
            "SELECT id, username, password, priv_password FROM snmp_v3_identities ORDER BY sort_order"
        ).fetchall()

        for row_id, u, p, pp in rows:
            password = decrypt_password(p)
            priv_password = decrypt_password(pp) if pp else None

            # Self-heal: this identity is still stored as legacy
            # plaintext (predates credential_vault's encryption, or
            # was never re-saved through Settings since). Rather than
            # only encrypting it whenever someone happens to re-save
            # it via the UI -- which may never happen -- encrypt it
            # right now that it's already been loaded, and write it
            # straight back. Confirmed live 2026-09-03: the previous
            # behavior left credentials plaintext indefinitely and
            # re-logged decrypt_password's warning on every single
            # read (every device x every identity during a cold
            # CREDENTIAL_CACHE rebuild). This now fires at most once
            # per identity, ever.
            updates = {}
            if not is_encrypted(p):
                updates["password"] = encrypt_password(password)
            if pp and not is_encrypted(pp):
                updates["priv_password"] = encrypt_password(priv_password)
            if updates:
                set_clause = ", ".join(f"{col} = ?" for col in updates)
                conn.execute(f"UPDATE snmp_v3_identities SET {set_clause} WHERE id = ?", (*updates.values(), row_id))
                conn.commit()
                logger.info(f"[SNMP] Encrypted at-rest credential for identity '{u}' (was legacy plaintext) -- done, won't warn again.")

            v3_identities.append(
                SNMPCredential(version=SNMPVersion.V3, username=u, password=password, priv_password=priv_password)
            )
        conn.close()
    except sqlite3.OperationalError as e:
        logger.warning(f"[SNMP] Could not read snmp_v3_identities (table may not exist yet): {e}")

    v2c_credentials = [
        SNMPCredential(version=SNMPVersion.V2C, community=c)
        for c in config.SNMP_COMMUNITIES
    ]

    return v3_identities + v2c_credentials


async def get_working_credential(ip) -> SNMPCredential:
    v2c_credentials = [c for c in get_configured_credentials() if c.version == SNMPVersion.V2C]
    safe_fallback = v2c_credentials[-1] if v2c_credentials else None

    if is_virtual_subnet(ip):
        return safe_fallback

    if ip in CREDENTIAL_CACHE:
        cached = CREDENTIAL_CACHE[ip]
        if _is_unresponsive_marker(cached):
            if not _unresponsive_due_for_retry(cached):
                return safe_fallback
            # Retry window elapsed -- fall through to the normal probe
            # below exactly as if this ip had never been cached.
        else:
            # PLAN-1: get_working_credential() is the fast path most
            # regular per-tick pollers actually use (vlan_registry.py,
            # mac_table_scraper.py, LLDP) -- adaptive_snmp_query()'s own
            # equivalent cached-path is only reached by a narrower set
            # of callers (fingerprinter.py's reachability/profile
            # queries). Confirmed live 2026-09-09: without this same
            # trigger here too, a device that's ONLY ever touched via
            # get_working_credential() (a router's non-primary VLAN
            # gateway IPs, in practice) never got its deferred check
            # fired at all -- it just sat in DEFERRED_V3_UPGRADE forever,
            # regardless of how many ticks passed.
            _maybe_trigger_deferred_v3_upgrade(ip)
            return cached

    # POLL-2: try a sibling interface's already-known-working credential
    # FIRST -- genuinely verified against THIS specific IP with a single
    # quick request, not assumed -- before falling through to the full
    # strength-descending probe below. Succeeds almost always for a
    # multi-homed device, collapsing what used to be a full per-
    # credential/per-protocol probe on every one of its interface IPs
    # into one verification call after the first IP pays the real cost.
    sibling_credential = _find_sibling_credential(ip)
    if sibling_credential:
        result = await run_snmp_command(ip, "1.3.6.1.2.1.1.2.0", sibling_credential, timeout=1, retries=1)
        if result is not None:
            CREDENTIAL_CACHE[ip] = sibling_credential
            logger.info(f"[*] SNMP: {ip} verified sibling credential {sibling_credential.display_label()} from same node -- skipped full re-probe (POLL-2).")
            return sibling_credential

    await adaptive_snmp_query(ip, "1.3.6.1.2.1.1.2.0", timeout=1, retries=1)
    resolved = CREDENTIAL_CACHE.get(ip)
    if resolved is None or _is_unresponsive_marker(resolved):
        return safe_fallback
    return resolved


def is_virtual_subnet(ip_str):
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
        if ip_obj in ipaddress.IPv4Network('172.16.0.0/12') or ip_obj.is_link_local:
            return True
    except Exception:
        pass
    return False


async def _run_snmp_command_helper(ip, oid, credential: SNMPCredential, walk, timeout, retries):
    """
    NATIVE-3 (Windows) / NATIVE-10 (macOS): tools/snmp_helper takes the
    same role IcmpSendEcho plays for ping_sweeper.py's Windows branch --
    no net-snmp CLI to shell out to on either platform, so a
    purpose-built Go binary stands in for it (the same gosnmp-wrapping
    source, just cross-compiled per OS -- confirmed live on both real
    Windows hardware and a real Mac before either was wired in). This
    function itself has no OS-specific logic at all -- renamed from
    _run_snmp_command_windows once macOS needed the identical path too
    and "windows" stopped being accurate. Same filtering/return
    contract as the tail of run_snmp_command() below, kept identical on
    purpose so adaptive_snmp_query() and everything above it needs zero
    changes for any OS.
    """
    if credential.version == SNMPVersion.V2C:
        cred_json = {"version": "v2c", "community": credential.community}
    else:
        if not credential.is_resolved:
            logger.error(f"[SNMP] Internal error: unresolved v3 credential passed to run_snmp_command for {ip}.")
            return None
        # Strength-named protocol strings (SHA-256, AES-192, ...), not
        # net-snmp's own CLI flag spellings -- NET_SNMP_AUTH_FLAG/
        # NET_SNMP_PRIV_FLAG below are specific to invoking the net-snmp
        # CLI, which this path doesn't do. tools/snmp_helper maps these
        # strength names to gosnmp's own constants itself.
        cred_json = {
            "version": "v3",
            "username": credential.username,
            "auth_protocol": credential.auth_protocol,
            "auth_password": credential.password,
            "priv_protocol": credential.priv_protocol,
            "priv_password": credential.effective_priv_password,
        }

    # Same reasoning as the Linux path's private snmp.conf file below --
    # secrets go over stdin, never argv, where any co-resident local
    # process/user could otherwise read them for the call's lifetime.
    stdin_payload = json.dumps(cred_json).encode()
    cmd = [SNMP_HELPER_PATH, ip, oid, "walk" if walk else "get", str(timeout), str(retries)]

    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await proc.communicate(input=stdin_payload)
    if proc.returncode != 0: return None
    lines = stdout.decode().splitlines()
    valid_lines = [line.strip() for line in lines if line.strip() and "No Such" not in line and "No more variables" not in line]
    if not valid_lines: return None
    return valid_lines if walk else valid_lines[0].strip('"')


async def run_snmp_command(ip, oid, credential: SNMPCredential, walk=False, timeout=1, retries=1):
    if is_virtual_subnet(ip): return None
    if credential is None: return None

    if platform.system() in ("Windows", "Darwin"):
        return await _run_snmp_command_helper(ip, oid, credential, walk, timeout, retries)

    cmd_name = "snmpwalk" if walk else "snmpget"

    # Secrets (v2c community / v3 username+password) are handed to
    # net-snmp via a private, mode-0600 snmp.conf (pointed to with
    # SNMPCONFPATH) instead of as -c/-u/-A/-X CLI arguments -- argv is
    # readable by any co-resident local process/user for the lifetime of
    # the call via /proc/<pid>/cmdline or `ps -ef`, while this file is
    # only readable by this process's own user and is removed as soon as
    # the subprocess exits. "-m ''" reproduces this container's own
    # default /etc/snmp/snmp.conf ("mibs :") so overriding SNMPCONFPATH
    # doesn't change MIB-loading behavior. See CWE-214 finding F10.
    if credential.version == SNMPVersion.V2C:
        secret_directives = {"defCommunity": credential.community}
        cmd = [cmd_name, "-v", "2c", "-m", "",
               "-On", "-Oq", "-t", str(timeout), "-r", str(retries), ip, oid]
    else:
        if not credential.is_resolved:
            logger.error(f"[SNMP] Internal error: unresolved v3 credential passed to run_snmp_command for {ip}.")
            return None
        auth_flag = NET_SNMP_AUTH_FLAG.get(credential.auth_protocol, credential.auth_protocol)
        priv_flag = NET_SNMP_PRIV_FLAG.get(credential.priv_protocol, credential.priv_protocol)
        # F14: -A (authKey) and -X (privKey) / defAuthPassphrase and
        # defPrivPassphrase must come from independent secrets (RFC 3414
        # USM) -- previously both used the same stored password.
        # effective_priv_password is the dedicated privacy passphrase,
        # falling back to the auth password only for identities that
        # predate that field.
        secret_directives = {
            "defSecurityName": credential.username,
            "defAuthPassphrase": credential.password,
            "defPrivPassphrase": credential.effective_priv_password,
        }
        cmd = [cmd_name, "-v3", "-l", "authPriv", "-a", auth_flag, "-x", priv_flag, "-m", "",
               "-On", "-Oq", "-t", str(timeout), "-r", str(retries), ip, oid]

    if any(v is not None and ("\n" in v or "\r" in v) for v in secret_directives.values()):
        logger.error(f"[SNMP] Internal error: credential for {ip} contains a newline; refusing to build snmp.conf.")
        return None

    with tempfile.TemporaryDirectory(prefix="netlanvas-snmp-") as conf_dir:
        conf_fd = os.open(os.path.join(conf_dir, "snmp.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(conf_fd, "w") as conf_file:
            for directive, value in secret_directives.items():
                conf_file.write(f"{directive} {value}\n")

        env = dict(os.environ, SNMPCONFPATH=conf_dir)
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
        )
        stdout, stderr = await proc.communicate()
    if proc.returncode != 0: return None
    lines = stdout.decode().splitlines()
    valid_lines = [line.strip() for line in lines if line.strip() and "No Such" not in line and "No more variables" not in line]
    if not valid_lines: return None
    return valid_lines if walk else valid_lines[0].strip('"')


async def adaptive_snmp_query(ip, oid, walk=False, timeout=1, retries=1):
    if is_virtual_subnet(ip): return None

    was_previously_cached = ip in CREDENTIAL_CACHE
    if was_previously_cached:
        cached = CREDENTIAL_CACHE[ip]
        if _is_unresponsive_marker(cached):
            if not _unresponsive_due_for_retry(cached):
                return None
            # Retry window elapsed -- fall through to the full probe
            # below exactly as if this ip had never been cached,
            # rather than reusing the (now stale) UNRESPONSIVE marker.
            was_previously_cached = False
        else:
            result = await run_snmp_command(ip, oid, cached, walk, timeout, retries)
            if result is not None:
                CREDENTIAL_FAILURE_STREAK.pop(ip, None)
                # PLAN-1: this is where a deferred v3 upgrade actually
                # fires in practice, most of the time -- the full
                # credential search below only ever runs once per
                # device, but this fast cached-credential path runs on
                # every single query after that, tick after tick, so
                # it's the natural place to notice "this device's
                # deferred check has come due."
                _maybe_trigger_deferred_v3_upgrade(ip)
                return result

            prev_streak, last_increment = CREDENTIAL_FAILURE_STREAK.get(ip, (0, 0.0))
            now = time.time()
            if now - last_increment >= MIN_SECONDS_BETWEEN_STREAK_INCREMENTS:
                streak = prev_streak + 1
                CREDENTIAL_FAILURE_STREAK[ip] = (streak, now)
            else:
                streak = prev_streak
            if streak < CACHE_RETRY_THRESHOLD:
                logger.debug(f"[SNMP-TRANSIENT] {ip} failed (streak {streak}/{CACHE_RETRY_THRESHOLD}). Preserving cache, deferring full re-probe.")
                return None

    lock = _get_probe_lock(ip)
    if lock.locked():
        async with lock:
            pass  # wait for the in-flight probe to finish
        cached = CREDENTIAL_CACHE.get(ip)
        if cached and not _is_unresponsive_marker(cached):
            return await run_snmp_command(ip, oid, cached, walk, timeout, retries)
        return None

    async with lock:
        # PERF-2 (2026-09-08): no log line existed for the START of a
        # full credential search, and no attempt anywhere measured how
        # long the search itself took -- confirmed live this made the
        # single biggest remaining tick 0/1 cost (a straggler device
        # stuck in this exact loop, gating fingerprinter.py's
        # asyncio.gather() and therefore the whole downstream pipeline)
        # invisible in the logs: a multi-minute gap with nothing in it
        # to explain which device or why. search_start/elapsed below
        # turn that into a directly attributable, per-device number.
        search_start = time.monotonic()
        all_credentials = get_configured_credentials()
        v2c_credentials = [c for c in all_credentials if c.version == SNMPVersion.V2C]
        v3_credentials = [c for c in all_credentials if c.version != SNMPVersion.V2C]
        logger.info(
            f"[*] SNMP: Starting full credential search for {ip} "
            f"({len(v3_credentials)} v3 identit{'y' if len(v3_credentials) == 1 else 'ies'} x up to "
            f"{len(AUTH_PROTOCOLS_BY_STRENGTH) * len(PRIV_PROTOCOLS_BY_STRENGTH)} combos, "
            f"{len(v2c_credentials)} v2c communit{'y' if len(v2c_credentials) == 1 else 'ies'}) -- "
            f"{'re-probe, cache was stale' if was_previously_cached else 'first time seen'}."
        )

        # PLAN-1 (2026-09-09): v2c FIRST, not v3. Two reasons, both
        # confirmed live: (1) SNMPv3's USM security model deliberately
        # doesn't send an informative reply to a wrong auth/priv combo
        # (that itself would be an information leak) -- it just drops
        # the packet, so a device that speaks v2c but not v3 was paying
        # the FULL 24-combination-per-identity timeout cost, every
        # time, before ever reaching the protocol that actually works.
        # (2) real data from this network showed v2c is the dominant
        # answer anyway. A device that answers NEITHER v2c nor v3 pays
        # the same total cost either order -- this only helps the
        # common case, never hurts the worst case.
        for base_credential in v2c_credentials:
            result = await run_snmp_command(ip, oid, base_credential, walk, timeout, retries)
            if result is not None:
                elapsed = time.monotonic() - search_start
                if CREDENTIAL_CACHE.get(ip) != base_credential:
                    CREDENTIAL_CACHE[ip] = base_credential
                    logger.info(f"[*] SNMP Auth Locked: {ip} verified with {base_credential.display_label()} (Added to Cache, {elapsed:.1f}s search)")
                CREDENTIAL_FAILURE_STREAK.pop(ip, None)
                # Don't block this call on it -- see
                # _probe_and_schedule_v3_upgrade's own docstring.
                asyncio.create_task(_probe_and_schedule_v3_upgrade(ip, base_credential))
                return result

        # v2c came back empty -- fall through to the real v3 cascade,
        # same as always (a device that answers nothing on v2c might
        # still be legitimately v3-only).
        result = await _try_v3_cascade(ip, oid, walk, timeout, retries, v3_credentials, search_start)
        if result is not None:
            return result

        elapsed = time.monotonic() - search_start
        if was_previously_cached:
            logger.info(f"[SNMP-TRANSIENT] {ip} failed full re-probe after {elapsed:.1f}s. Preserving cache.")
        else:
            CREDENTIAL_CACHE[ip] = ("UNRESPONSIVE", _current_tick)
            logger.info(f"[SNMP-AUTH] {ip} exhausted full credential search in {elapsed:.1f}s, no response. Added to Do-Not-Call list (retry after tick {_current_tick + UNRESPONSIVE_RETRY_TICKS}).")
        return None
