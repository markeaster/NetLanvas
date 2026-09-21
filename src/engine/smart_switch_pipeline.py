"""
engine/smart_switch_pipeline.py

Discovers "smart" (web-managed, no SNMP) switches via their own
vendor-proprietary broadcast discovery protocols. engine/snmp_pipeline.py
can never reach these devices -- by definition they don't speak SNMP at
all, and (separately) run_snmp_pipeline() is only ever invoked against
devices ALREADY classified as infrastructure via get_representative_targets(),
which a no-SNMP switch can never earn in the first place (it needs SNMP-based
classification to enter that list, but has no SNMP -- a real chicken-and-egg
gate, confirmed live 2026-09-04).

Each vendor gets ONE UDP broadcast, once per deep-scan cycle, that every
compatible switch on the local segment answers at once -- regardless of
IP, connection state, or whether NetLanvas has discovered it via any
other path yet. This is what lets it find a switch with nothing plugged
into it, not just one dark-matter detection has already flagged as an
ambiguous port. Reuses the same lightweight step-registry pattern as
engine/snmp_pipeline.py (PipelineEngine/@engine.register/StepResult),
kept as a SEPARATE registry/module rather than added to that one --
its steps take no ip/credential (one broadcast covers the whole
segment), a different enough shape to warrant its own file.

Results are NOT written directly into logical_nodes -- they're stored
in network.db's smart_switch_candidates table (ephemeral, refreshed
every cycle) as unverified auto-suggestions. unification.py's
inventory-overlay pass checks engine.INVENTORY_DB_PATH's verified_devices
table FIRST (a human's 100%-confirmed identification, which survives a
Clean Slate purge -- these candidates don't); only once a candidate is
missing from there does the dark-matter pass fall back to suggesting
this module's own findings as a lower-confidence hint for the user to
confirm via the existing /api/node/update or /api/promote_node
endpoints (which persist the confirmation back into inventory.db,
closing the loop for good).

PROTOCOL SOURCES AND CONFIDENCE (2026-09-04, updated same day after live
testing against real hardware -- one Netgear GS308Ev4 and one TP-Link
TL-SG105E, both on the user's own network):

- SSDP/UPnP (step 5, all vendors): standard, well-documented protocol
  (RFC-adjacent, not reverse-engineered) -- a plain M-SEARCH multicast
  to 239.255.255.250:1900. CONFIRMED WORKING live against the real
  GS308Ev4: it answers with `SERVER: Netgear_Switch UPnP/1.1
  GS308Ev4/V1.0.1.3`, a clean vendor+exact-model+firmware string, and
  a `USN: uuid:...-28940175fae9` whose trailing 12 hex chars ARE the
  device's real MAC (28:94:01:75:fa:e9, cross-checked against
  l3_bindings). This is by far the highest-confidence signal in this
  file -- a real device volunteering its own identity over a standard
  protocol, not a guessed byte layout. Root cause for why NSDP (below)
  gets no reply from this specific hardware generation: the switch's
  own web UI (Settings > Switch Discovery) has exactly one relevant
  toggle, labeled "UPnP: The protocol for device discovery" -- this
  firmware line uses UPnP, not NSDP, confirmed directly from the
  device's own settings page. TESTED LIVE AND CONFIRMED NOT TO COVER
  TP-Link: the same M-SEARCH sweep produces zero reply from the real
  TL-SG105E (78 total replies network-wide, none from it) -- TP-Link's
  Easy Smart line doesn't speak SSDP, so ESCP (step 20) remains the
  only path there. _SSDP_SWITCH_VENDOR_PATTERNS below is a small,
  deliberately extensible substring table (currently just Netgear) --
  any other vendor whose smart switches turn out to answer SSDP needs
  only a new entry here, no new broadcast code.
- NSDP (Netgear, step 10): cross-validated across two independent
  sources that agree on the core structure -- the "Netgear Switch
  Discovery Protocol" Wikipedia article and AlbanBedel/libnsdp's
  actual C source (nsdp_packet.c). Reasonable confidence in the
  32-byte header layout, TLV field codes, and ports (63321 client /
  63322 switch) as a byte-level construction -- and confirmed BY
  PACKET CAPTURE to be sent correctly (right length, no kernel drops).
  But CONFIRMED LIVE to get ZERO replies from the user's real GS308Ev4
  -- see the SSDP note above for why (this firmware generation doesn't
  implement NSDP at all). Kept in the pipeline anyway (not every
  Netgear smart-switch generation necessarily behaves the same way,
  and a step that finds nothing on this one network is still free
  insurance for other users' older/different Netgear hardware) as a
  fallback that runs after SSDP, never overwriting an SSDP-sourced
  identification for the same MAC (see run_smart_switch_pipeline()'s
  merge logic). The two sources DISAGREED on TLV type/length byte
  order (Wikipedia said little-endian, libnsdp's code implied
  big-endian) -- implemented here as big-endian; still unverified,
  since no real NSDP reply has ever been captured to check against.
- TP-Link Easy Smart (ESCP, step 20): solid confidence in the framing
  (32-byte header, ports 29809 client / 29808 switch, packet type
  0x00=probe / 0x02=response, FFFF0000 terminator) from Chris Moore's
  Easy Smart switch vulnerability writeup (chrisdcmoore.co.uk), and
  the probe was confirmed sent correctly. But, like NSDP, CONFIRMED
  LIVE to get ZERO replies from the user's real TL-SG105E. Cause
  unconfirmed -- could be this specific model/firmware not
  implementing ESCP, discovery disabled by default, or a detail of
  this probe's construction being wrong; unlike the NSDP case there
  was no switch-side settings page to directly confirm which. Kept in
  the pipeline as-is (no better-understood alternative exists for
  TP-Link -- SSDP is confirmed NOT to cover it) pending either a
  packet capture of a genuine ESCP exchange (e.g. from TP-Link's own
  Easy Smart Configuration Utility talking to the same switch) or
  community-contributed hardware that does respond.
- D-Link (SmartConsole/DDP, UDP port 62976) and Zyxel (ZON/ZDP,
  multicast MAC 01:A0:C5:11:11:11): confirmed port/MAC only, no
  confirmed request/response payload format found anywhere searched.
  Deliberately NOT implemented -- a prober guessing at unconfirmed
  bytes would either never get a real reply (a false negative dressed
  up as a real check) or misparse garbage, which is worse than not
  having the feature. Left as documented stubs at the bottom of this
  file, ready for a step_30/step_40 once someone (ideally the
  community, since this project has neither brand's hardware to test
  against) can supply real capture data.
"""

import asyncio
import logging
import socket
import sqlite3
import struct
import time
import requests
from typing import NamedTuple, Optional, Any, Dict, Callable, Tuple, List

from engine.auto_discovery import bind_socket_to_scan_interface
from engine.config_loader import config

logger = logging.getLogger("Netlanvas.SmartSwitch")

_BROADCAST_TIMEOUT = 3.0  # seconds to collect replies after each broadcast


class StepResult(NamedTuple):
    should_continue: bool
    data: Optional[List[dict]]


class SmartSwitchPipeline:
    def __init__(self):
        self.registry: Dict[int, Tuple[str, Callable]] = {}

    def register(self, step_id: int, name: str):
        def decorator(func: Callable):
            self.registry[step_id] = (name, func)
            return func
        return decorator


engine = SmartSwitchPipeline()


def _get_local_mac() -> bytes:
    """Best-effort local MAC for the request header's client-MAC field --
    both protocols expect a real-looking requester MAC, not zeros. Falls
    back to a synthetic locally-administered MAC if uuid.getnode() can't
    determine a real one (still valid framing either way, discovery
    itself doesn't depend on this being the appliance's true NIC MAC)."""
    try:
        import uuid
        node = uuid.getnode()
        if (node >> 40) % 2 == 0:  # low bit of the first octet: 0 = believed genuine, not the random fallback
            return node.to_bytes(6, "big")
    except Exception:
        pass
    return b"\x02\x00\x00\x00\x00\x01"  # locally-administered fallback, valid but not a real NIC address


def _udp_broadcast_probe(client_port: int, switch_port: int, payload: bytes, timeout: float) -> List[Tuple[bytes, str]]:
    """Blocking (run via asyncio.to_thread) -- binds a UDP socket to
    client_port, broadcasts `payload` to 255.255.255.255:switch_port,
    then collects every reply arriving within `timeout` seconds. Both
    protocols reply FROM switch_port TO client_port, so a single bound
    socket sees its own replies without needing a separate listener.
    An empty return is the normal case on a network with no matching
    switches, not an error."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    replies: List[Tuple[bytes, str]] = []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        bind_socket_to_scan_interface(sock)
        sock.bind(("0.0.0.0", client_port))
        sock.sendto(payload, ("255.255.255.255", switch_port))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(2048)
                replies.append((data, addr[0]))
            except socket.timeout:
                break
    except OSError as e:
        # Port already in use, no broadcast-capable interface, etc. --
        # log once at debug and return whatever we got (possibly
        # nothing); never let a probe failure affect the rest of the
        # deep-scan cycle.
        logger.debug(f"[SmartSwitch] Broadcast probe on port {client_port} failed: {e}")
    finally:
        sock.close()
    return replies


# ==============================================================================
# STEP 5: UNIVERSAL UPNP/SSDP SWITCH DISCOVERY
# ==============================================================================
_SSDP_MULTICAST_ADDR = "239.255.255.250"
_SSDP_MULTICAST_PORT = 1900
_SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")

# Substring (lowercased) -> vendor name. Matched against the SSDP SERVER
# header. Deliberately small and easy to extend -- add a line here for
# any other vendor whose smart switches turn out to answer SSDP; no
# other code changes needed. See module docstring for what's confirmed
# vs. not.
_SSDP_SWITCH_VENDOR_PATTERNS = {
    "netgear_switch": "Netgear",
}


def _ssdp_sweep_blocking(timeout: float) -> List[Tuple[str, bytes]]:
    """Blocking (run via asyncio.to_thread). One multicast M-SEARCH,
    collects every raw HTTP-over-UDP reply for `timeout` seconds. An
    empty return is the normal case, not an error -- most replies on a
    real network are unrelated devices (media servers, routers, etc.),
    filtered out later in _parse_ssdp_response by vendor pattern."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    replies: List[Tuple[str, bytes]] = []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_socket_to_scan_interface(sock)
        sock.settimeout(timeout)
        sock.sendto(_SSDP_REQUEST, (_SSDP_MULTICAST_ADDR, _SSDP_MULTICAST_PORT))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(4096)
                replies.append((addr[0], data))
            except socket.timeout:
                break
    except OSError as e:
        logger.debug(f"[SmartSwitch] SSDP sweep failed: {e}")
    finally:
        sock.close()
    return replies


def _parse_ssdp_response(src_ip: str, data: bytes) -> Optional[dict]:
    text = data.decode("utf-8", errors="replace")
    headers: Dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().upper()] = value.strip()

    server = headers.get("SERVER", "")
    vendor = None
    for pattern, name in _SSDP_SWITCH_VENDOR_PATTERNS.items():
        if pattern in server.lower():
            vendor = name
            break
    if not vendor:
        return None  # a real device, just not a switch we recognize -- not an error

    # SERVER header is conventionally "OS/ver UPnP/ver Product/ver" --
    # the last token is the most specific (e.g. "GS308Ev4/V1.0.1.3").
    model, firmware = None, None
    last_token = server.split()[-1] if server.split() else ""
    if "/" in last_token:
        model, firmware = last_token.split("/", 1)

    # USN embeds a UUID (uuid:XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX) whose
    # trailing 12 hex chars are, at least on the confirmed Netgear
    # hardware, the device's real MAC -- confirmed by cross-checking
    # against l3_bindings for the same IP. Falls back to None (not the
    # broadcasting host's own IP-derived guess) if the pattern doesn't
    # hold for some other vendor's UUID scheme.
    mac = None
    usn = headers.get("USN", "")
    if "uuid:" in usn:
        uuid_part = usn.split("uuid:", 1)[1].split(":", 1)[0]
        candidate = uuid_part.split("-")[-1]
        if len(candidate) == 12 and all(c in "0123456789abcdefABCDEF" for c in candidate):
            mac = ":".join(candidate[i:i + 2] for i in range(0, 12, 2)).lower()

    if not mac:
        return None  # can't key results by MAC without one

    return {
        "mac": mac,
        "vendor": vendor,
        "model": model,
        "name": None,
        "ip": src_ip,
        "protocol": "SSDP",
        "firmware": firmware,
        "location": headers.get("LOCATION"),
        "source_ip": src_ip,
    }


@engine.register(5, "Universal UPnP/SSDP Switch Discovery")
async def step_05_ssdp() -> StepResult:
    replies = await asyncio.to_thread(_ssdp_sweep_blocking, _BROADCAST_TIMEOUT)
    devices = []
    seen_macs = set()
    for src_ip, data in replies:
        parsed = _parse_ssdp_response(src_ip, data)
        if parsed and parsed["mac"] not in seen_macs:
            seen_macs.add(parsed["mac"])
            devices.append(parsed)
            logger.info(f"[SmartSwitch] SSDP: found {parsed['vendor']} {parsed.get('model') or 'switch'} at {src_ip} (MAC {parsed['mac']})")
    return StepResult(should_continue=True, data=devices or None)


# ==============================================================================
# STEP 10: NETGEAR NSDP DISCOVERY (fallback -- see module docstring, SSDP
# above is the confirmed-working path for the hardware tested so far)
# ==============================================================================
_NSDP_CLIENT_PORT = 63321
_NSDP_SWITCH_PORT = 63322
_NSDP_SIGNATURE = b"NSDP"
_NSDP_FIELD_TYPES = {
    0x0001: "model",
    0x0003: "name",
    0x0004: "mac",
    0x0006: "ip",
    0x0007: "netmask",
    0x0008: "gateway",
    0x000d: "firmware",
}


def _build_nsdp_request(client_mac: bytes) -> bytes:
    header = struct.pack(
        ">BBHI6s6sHH",
        0x01,        # protocol version
        0x01,        # opcode: read request
        0x0000,      # operation result
        0x00000000,  # unknown
        client_mac,  # host (requester) MAC
        b"\x00" * 6,  # target device MAC -- zero/unknown = broadcast to every switch
        0x0000,      # unknown
        0x0000,      # sequence number
    )
    header += _NSDP_SIGNATURE
    header += b"\x00" * 4  # unknown trailer, completes the 32-byte header
    body = b"".join(struct.pack(">HH", field_type, 0) for field_type in _NSDP_FIELD_TYPES)
    body += struct.pack(">HH", 0xFFFF, 0x0000)  # terminator
    return header + body


def _parse_nsdp_response(data: bytes) -> Optional[dict]:
    if len(data) < 32 or data[24:28] != _NSDP_SIGNATURE:
        return None
    if data[1] != 0x02:  # not a read response
        return None
    device_mac_bytes = data[14:20]
    device_mac = ":".join(f"{b:02x}" for b in device_mac_bytes)
    fields: Dict[str, str] = {}
    offset = 32
    while offset + 4 <= len(data):
        field_type, length = struct.unpack(">HH", data[offset:offset + 4])
        if field_type == 0xFFFF:
            break
        value = data[offset + 4:offset + 4 + length]
        name = _NSDP_FIELD_TYPES.get(field_type)
        if name == "mac" and len(value) == 6:
            fields[name] = ":".join(f"{b:02x}" for b in value)
        elif name in ("ip", "netmask", "gateway") and len(value) == 4:
            fields[name] = ".".join(str(b) for b in value)
        elif name in ("model", "name", "firmware"):
            try:
                fields[name] = value.decode("ascii", errors="replace").strip("\x00").strip()
            except Exception:
                pass
        offset += 4 + length
    return {
        "mac": fields.get("mac") or device_mac,
        "vendor": "Netgear",
        "model": fields.get("model"),
        "name": fields.get("name"),
        "ip": fields.get("ip"),
        "protocol": "NSDP",
    }


@engine.register(10, "Netgear NSDP Discovery")
async def step_10_nsdp() -> StepResult:
    request = _build_nsdp_request(_get_local_mac())
    replies = await asyncio.to_thread(_udp_broadcast_probe, _NSDP_CLIENT_PORT, _NSDP_SWITCH_PORT, request, _BROADCAST_TIMEOUT)
    devices = []
    for data, src_ip in replies:
        parsed = _parse_nsdp_response(data)
        if parsed:
            parsed["source_ip"] = src_ip
            devices.append(parsed)
            logger.info(f"[SmartSwitch] NSDP: found {parsed.get('model') or 'a Netgear smart switch'} at {src_ip} (MAC {parsed['mac']})")
    return StepResult(should_continue=True, data=devices or None)


# ==============================================================================
# STEP 20: TP-LINK EASY SMART DISCOVERY (ESCP)
# ==============================================================================
_TPLINK_CLIENT_PORT = 29809
_TPLINK_SWITCH_PORT = 29808


def _build_tplink_probe(client_mac: bytes) -> bytes:
    header = struct.pack(
        ">BB6s6sHIHHHH",
        0x01,          # protocol version
        0x00,          # packet type: discovery probe
        b"\x00" * 6,   # target switch MAC -- zero/unknown = broadcast to every switch
        client_mac,    # client (requester) MAC
        0x0000,        # sequence number
        0x00000000,    # unknown (4 bytes)
        0x0024,        # total packet length incl. header (32) + terminator (4)
        0x0000,        # unknown field
        0x0000,        # reserved
        0x0000,        # unknown
    )
    header += struct.pack(">I", 0x00000000)  # trailing unknown, completes the 32-byte header
    terminator = struct.pack(">HH", 0xFFFF, 0x0000)
    return header + terminator


def _parse_tplink_response(data: bytes) -> Optional[dict]:
    if len(data) < 32 or data[1] != 0x02:  # not a discovery response
        return None
    switch_mac_bytes = data[2:8]
    mac = ":".join(f"{b:02x}" for b in switch_mac_bytes)
    if mac == "00:00:00:00:00:00":
        return None
    # Field-level TLV meanings aren't confirmed (see module docstring) --
    # walk the body generically and surface any printable-ASCII value as
    # a best-effort model/name candidate, rather than pretending to know
    # which TLV type means what.
    strings_found = []
    offset = 32
    while offset + 4 <= len(data):
        field_type, length = struct.unpack(">HH", data[offset:offset + 4])
        if field_type == 0xFFFF:
            break
        value = data[offset + 4:offset + 4 + length]
        if value and all(32 <= b < 127 for b in value):
            strings_found.append(value.decode("ascii"))
        offset += 4 + max(length, 1)
    return {
        "mac": mac,
        "vendor": "TP-Link",
        "model": strings_found[0] if strings_found else None,
        "name": strings_found[1] if len(strings_found) > 1 else None,
        "ip": None,
        "protocol": "ESCP",
        "raw_strings": strings_found,  # best-effort, see module docstring
    }


@engine.register(20, "TP-Link Easy Smart Discovery")
async def step_20_tplink() -> StepResult:
    request = _build_tplink_probe(_get_local_mac())
    replies = await asyncio.to_thread(_udp_broadcast_probe, _TPLINK_CLIENT_PORT, _TPLINK_SWITCH_PORT, request, _BROADCAST_TIMEOUT)
    devices = []
    for data, src_ip in replies:
        parsed = _parse_tplink_response(data)
        if parsed:
            parsed["source_ip"] = src_ip
            devices.append(parsed)
            logger.info(f"[SmartSwitch] ESCP: found {parsed.get('model') or 'a TP-Link Easy Smart switch'} at {src_ip} (MAC {parsed['mac']})")
    return StepResult(should_continue=True, data=devices or None)


# ==============================================================================
# STEP 25: TP-LINK EASY SMART DISCOVERY, PASSIVE HTTP FALLBACK
# ==============================================================================
# TPHTTP-1 (2026-09-11): ESCP (step 20) is confirmed, via live packet
# capture against a real TL-SG105E-class switch, to get ZERO replies --
# not a probe-construction bug, an actual silent target (see module
# docstring's ESCP section and the packet-capture note added the same
# day). But that same real hardware's web UI (port 80, pre-authentication,
# no credentials needed) serves an extremely distinctive, unmistakably
# TP-Link login page: a `logon.cgi`-actioned form, the JS helper
# `doPrintfTableHeadBorder`, and the literal string "TP-Link
# Technologies Co., Ltd." in the footer -- all present in the raw HTML
# BEFORE any login attempt. Confirmed this exact combination is
# TP-Link-specific (not a generic embedded-Linux template): searched
# for prior art of this fingerprint being used elsewhere and found
# none, but the string set is distinctive enough (an exact company
# name plus a uniquely-named non-generic JS function) that a false
# positive from an unrelated vendor is effectively impossible.
#
# Unlike every step above, this one is inherently a per-IP unicast
# check (HTTP has no broadcast equivalent), not one broadcast covering
# the whole segment -- so it works from the CURRENT tick's already-known
# l3_bindings IPs rather than discovering brand new ones the way SSDP/
# NSDP/ESCP can. A switch with literally nothing else plugged into it
# yet (unseen by ARP/ICMP) still won't be found by this step -- that
# gap is real and stays open until this hardware answers SOME broadcast
# protocol, or a future capture nails down ESCP after all.
_TPLINK_HTTP_TIMEOUT = 2.0
_TPLINK_HTTP_SIGNATURE_MARKERS = ("logon.cgi", "doPrintfTableHeadBorder", "TP-Link Technologies Co., Ltd.")
# TPHTTP-2 (investigated, NOT implemented, 2026-09-11): the exact model
# IS visible unauthenticated in principle (SystemInfoRpm.htm's own
# info_ds.descriStr, or the outer frameset's g_title) -- but BOTH only
# ever render once a session is already authenticated. The plain
# login-form page (the one carrying the three markers above, and the
# only state this step will ever actually observe from a real,
# never-logged-in appliance) contains neither. Confirmed live: g_title
# only appeared in earlier testing because of a leftover authenticated
# session from manual credential testing against this same switch, not
# because it's genuinely available pre-auth. Since NetLanvas never
# authenticates to a device it's fingerprinting, this data is
# structurally unreachable here -- model stays None, same as v3.15.23.


def _fetch_l3_binding_ips() -> List[Tuple[str, str]]:
    """Blocking (run via asyncio.to_thread). Returns [(ip, mac), ...]
    for every currently-known l3_binding -- the candidate pool for the
    per-IP HTTP probe below. Read-only, best-effort: an empty return
    (fresh DB, table not yet created) just means this step finds
    nothing this cycle, not an error."""
    try:
        conn = sqlite3.connect(config.DB_PATH)
        try:
            return conn.execute("SELECT ip_address, mac_address FROM l3_bindings WHERE mac_address IS NOT NULL").fetchall()
        finally:
            conn.close()
    except Exception as e:
        logger.debug(f"[SmartSwitch] Could not read l3_bindings for HTTP fallback candidates: {e}")
        return []


def _check_tplink_http_signature(ip: str) -> bool:
    """Blocking (run via asyncio.to_thread). One quick unauthenticated
    GET to port 80 -- see step docstring above for why these particular
    markers are trustworthy. Any failure (closed port, non-HTTP
    service, timeout) is the normal case for the vast majority of
    candidate IPs, not an error."""
    try:
        resp = requests.get(f"http://{ip}/", timeout=_TPLINK_HTTP_TIMEOUT)
        body = resp.text
        return all(marker in body for marker in _TPLINK_HTTP_SIGNATURE_MARKERS)
    except requests.RequestException:
        return False


@engine.register(25, "TP-Link Easy Smart Discovery (HTTP fallback)")
async def step_25_tplink_http() -> StepResult:
    candidates = await asyncio.to_thread(_fetch_l3_binding_ips)
    if not candidates:
        return StepResult(should_continue=True, data=None)
    checks = await asyncio.gather(*(asyncio.to_thread(_check_tplink_http_signature, ip) for ip, _mac in candidates))
    devices = []
    for (ip, mac), matched in zip(candidates, checks):
        if matched:
            devices.append({
                "mac": mac,
                "vendor": "TP-Link",
                "model": None,  # not determinable without authenticating -- see TPHTTP-2 above
                "name": None,
                "ip": ip,
                "protocol": "HTTP",
                "source_ip": ip,
            })
            logger.info(f"[SmartSwitch] HTTP: found a TP-Link Easy Smart switch at {ip} (MAC {mac}, ESCP got no reply from this hardware)")
    return StepResult(should_continue=True, data=devices or None)


# ==============================================================================
# STUBS -- confirmed port/MAC, no confirmed payload format, see module docstring.
# Not registered (a fake no-op step would look like "we checked and found
# nothing" when we were never actually able to check at all).
#
# D-Link SmartConsole / DDP: broadcast destination UDP port 62976.
#   Would be step 30 once someone can supply a real capture.
#
# Zyxel ZON / ZDP: L2 multicast to destination MAC 01:A0:C5:11:11:11
#   (not a UDP broadcast like the others -- needs a raw socket, not just
#   SO_BROADCAST). Would be step 40 once someone can supply a real capture.
# ==============================================================================


async def run_smart_switch_pipeline() -> Dict[str, dict]:
    """Runs every registered step once (each is a single broadcast covering
    the whole local segment, not a per-IP query) and merges results into
    one dict keyed by MAC. Called once per deep-scan cycle from main.py's
    stage_smart_switch_discovery() -- unlike engine/snmp_pipeline.py's
    run_snmp_pipeline(), this never needs a pre-established SNMP
    credential or a device already classified as infrastructure, which
    is exactly the point: it's the only way to find a smart switch with
    nothing plugged into it, or one NetLanvas has never seen via
    ARP/FDB at all yet.
    """
    found: Dict[str, dict] = {}
    for step_id in sorted(engine.registry.keys()):
        name, func = engine.registry[step_id]
        try:
            result = await func()
            if result.data:
                for entry in result.data:
                    mac = entry.get("mac")
                    if not mac:
                        continue
                    # First writer wins: steps run in ascending id order,
                    # deliberately ordered by confidence (5=standard SSDP,
                    # then vendor-specific reverse-engineered fallbacks).
                    # A later, less-trustworthy step finding the same MAC
                    # must never clobber an earlier step's identification.
                    if mac not in found:
                        found[mac] = entry
        except Exception as e:
            logger.warning(f"[SmartSwitch] Step '{name}' ({step_id}) failed: {e}")
    return found
