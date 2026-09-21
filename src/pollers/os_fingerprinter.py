import asyncio
import logging
import sqlite3
import os
import socket
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser, AsyncServiceInfo
from engine.hostname_registry import set_hostname_by_node_id, PRIORITY_MDNS
from engine.auto_discovery import bind_socket_to_scan_interface, scan_interface_ip_for_zeroconf

logger = logging.getLogger("Netlanvas.OS_Profiler")
DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")

# Apple internal model-code -> marketing name. NOT exhaustive by design --
# see punch list MDNS-3. Codes not in this table just display as-is (the
# raw code, e.g. "iPhone16,2") rather than guessing a name, since a wrong
# marketing name would be worse than no translation at all. Extend this
# table over time; never invent an entry for a code you're not sure of.
APPLE_MODEL_NAMES = {
    "iPhone10,3": "iPhone X",
    "iPhone10,6": "iPhone X",
    "iPhone11,2": "iPhone XS",
    "iPhone11,6": "iPhone XS Max",
    "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPad13,1": "iPad Air (4th gen)",
    "iPad13,2": "iPad Air (4th gen)",
    "MacBookPro18,1": "MacBook Pro (16-inch, 2021)",
    "MacBookPro18,3": "MacBook Pro (14-inch, 2021)",
    "MacBookAir10,1": "MacBook Air (M1, 2020)",
}

# Ordered priority list of (TXT key, needs_apple_lookup) checked when
# resolving a device's MODEL -- see punch list MDNS-5/9/10. First match
# wins. Confirmed against a real mDNS survey (not assumed):
#   'model' -- Apple _device-info._tcp AND generic AirPlay receivers
#              (confirmed on a Marantz AV receiver, which is not Apple
#              hardware at all -- AirPlay is an open protocol any
#              compatible device implements the same way). The
#              APPLE_MODEL_NAMES lookup safely falls back to the raw
#              value when the code isn't Apple's, which is exactly why
#              the Marantz case already worked correctly by coincidence.
#   'md'    -- Google Cast. Already a human-readable marketing name
#              ("Chromecast Audio", "Google Nest Hub") -- no lookup
#              table needed, unlike Apple's internal codes.
#   'ty'    -- IPP/AirPrint printers. Already human-readable
#              ("Brother MFC-L3710CW series").
#   'usb_MDL' -- Printers again, via the older _printer._tcp path.
MODEL_TXT_KEYS = [
    ("model", True),
    ("md", False),
    ("ty", False),
    ("usb_MDL", False),
]

# Ordered priority list of TXT keys checked for a device's FRIENDLY
# (user-assigned) NAME, preferred over the raw mDNS service instance
# name when available. Confirmed on real hardware:
#   'fn' -- Google Cast friendly name (e.g. "Workshop Speaker") -- the
#           service instance name itself is an opaque device ID, 'fn'
#           is what a human actually typed in the Google Home app.
#   'n'  -- Amazon _amzn-wplay (Fire TV) friendly name (e.g. "Mark's
#           2nd Fire TV") -- the raw instance name here is an opaque
#           "amzn.dmgr:<hash>:<hash>:<port>" string, useless as a
#           hostname on its own.
FRIENDLY_NAME_TXT_KEYS = ["fn", "n"]


def _normalize_properties(raw_properties) -> dict:
    """
    zeroconf TXT record properties arrive as a dict with bytes keys/values
    (or None for valueless flags). Normalizes to a clean str->str dict
    once, here, so every downstream lookup can just do a plain dict get
    instead of repeating byte-decoding logic everywhere.
    """
    if not raw_properties:
        return {}
    normalized = {}
    for k, v in raw_properties.items():
        key_str = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
        if v is None:
            val_str = None
        elif isinstance(v, bytes):
            try:
                val_str = v.decode("utf-8", errors="ignore")
            except Exception:
                val_str = None
        else:
            val_str = str(v)
        normalized[key_str] = val_str
    return normalized


def _resolve_model(properties: dict) -> str | None:
    """
    Checks MODEL_TXT_KEYS in priority order, first match wins. Apple's
    'model' key gets translated through APPLE_MODEL_NAMES (falling back
    to the raw code/value if unknown -- never a guess); every other key
    is already human-readable and used as-is. Returns None if nothing
    matched, so callers can fall back to a generic tag rather than
    fabricate a value.
    """
    if not properties:
        return None
    for key, needs_apple_lookup in MODEL_TXT_KEYS:
        if key in properties and properties[key]:
            raw_val = properties[key]
            if needs_apple_lookup:
                return APPLE_MODEL_NAMES.get(raw_val, raw_val)
            return raw_val
    return None


def _resolve_friendly_name(properties: dict) -> str | None:
    """Checks FRIENDLY_NAME_TXT_KEYS in priority order, first match wins."""
    if not properties:
        return None
    for key in FRIENDLY_NAME_TXT_KEYS:
        if key in properties and properties[key]:
            return properties[key]
    return None


def _parse_ssdp_server_header(server_string: str) -> str:
    """
    UPnP SERVER headers are conventionally three space-separated tokens
    (OS/version UPnP/version Product/version), but formatting varies
    significantly across vendors -- see punch list MDNS-4. The LAST
    token is usually the actual product identifier, which is more
    useful than the generic OS/UPnP-version prefix a blind truncation
    would show. Falls back to a simple truncation if the string doesn't
    look like the conventional three-token shape.
    """
    if not server_string:
        return server_string
    tokens = server_string.split()
    if len(tokens) >= 2:
        candidate = tokens[-1]
        if "/" in candidate and len(candidate) > 2:
            return candidate[:40]
    return server_string[:22]


# --- 1. mDNS Listener (Multicast DNS) ---
class AsyncMDNSListener:
    def __init__(self):
        self.discovered = {}

    def remove_service(self, zeroconf, type, name):
        pass

    def update_service(self, zeroconf, type, name):
        pass

    def add_service(self, zeroconf, type, name):
        asyncio.create_task(self.async_resolve(zeroconf, type, name))

    async def async_resolve(self, zc, type_, name):
        info = AsyncServiceInfo(type_, name)
        await info.async_request(zc, 3000)
        if info and info.parsed_addresses():
            ip = info.parsed_addresses()[0]
            clean_name = name.split('.')[0]
            self.discovered[ip] = {
                "instance_name": clean_name,
                "properties": _normalize_properties(info.properties),
                "service_type": type_,
            }

async def run_mdns_sweep(duration=3):
    zc_interfaces = scan_interface_ip_for_zeroconf()
    aiozc = AsyncZeroconf(interfaces=zc_interfaces) if zc_interfaces else AsyncZeroconf()
    listener = AsyncMDNSListener()
    # See punch list MDNS-1/8/10 for why each of these was added, and
    # MDNS-6/7 for what was deliberately investigated and NOT added:
    # confirmed via a live mDNS survey that Amazon Echo/Alexa and
    # Ring/Blink advertise nothing locally at all (no service type,
    # zero footprint) -- not a gap in this list, a real limitation of
    # those product lines. Fire TV (_amzn-wplay) is a different Amazon
    # product line and IS self-announcing, hence its inclusion.
    services = [
        "_googlecast._tcp.local.",
        "_http._tcp.local.",
        "_daap._tcp.local.",
        "_spotify-connect._tcp.local.",
        "_device-info._tcp.local.",
        "_companion-link._tcp.local.",
        "_airplay._tcp.local.",
        "_amzn-wplay._tcp.local.",
        "_ipp._tcp.local.",
        "_printer._tcp.local.",
    ]

    browser = AsyncServiceBrowser(aiozc.zeroconf, services, listener)
    await asyncio.sleep(duration)
    
    await browser.async_cancel()
    await aiozc.async_close()
    
    return listener.discovered

# --- 2. SSDP Sweeper (UPnP Discovery) ---
def _ssdp_sweep_blocking():
    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    bind_socket_to_scan_interface(sock)
    sock.settimeout(2)
    discovered = {}

    try:
        sock.sendto(ssdp_request.encode(), ("239.255.255.250", 1900))
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                headers = data.decode('utf-8', errors='ignore').split('\r\n')
                for header in headers:
                    if header.upper().startswith("SERVER:"):
                        server_string = header.split(":", 1)[1].strip()
                        discovered[ip] = server_string
            except socket.timeout:
                break
    except Exception:
        pass
    finally:
        sock.close()
    return discovered

async def run_ssdp_sweep():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _ssdp_sweep_blocking)

async def run_os_fingerprinter():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT b.ip_address, n.id, n.hostname
        FROM l3_bindings b
        JOIN l2_interfaces i ON b.mac_address = i.mac_address
        JOIN logical_nodes n ON i.node_id = n.id
        WHERE b.ip_address IS NOT NULL
    ''')
    targets = {row[0]: (row[1], row[2]) for row in cursor.fetchall()}
    
    if not targets:
        conn.close()
        return

    logger.info("[*] OS Profiler: Launching 3-second mDNS/SSDP Broadcast Sweep...")

    mdns_results, ssdp_results = await asyncio.gather(
        run_mdns_sweep(duration=3),
        run_ssdp_sweep()
    )

    os_updates = []
    hostname_writes = 0

    for ip, (node_id, current_hostname) in targets.items():
        mdns_hostname = None
        new_os = None

        if ip in mdns_results:
            entry = mdns_results[ip]
            props = entry.get("properties")
            friendly_name = _resolve_friendly_name(props)
            mdns_hostname = friendly_name if friendly_name else entry["instance_name"]
            resolved_model = _resolve_model(props)
            new_os = resolved_model if resolved_model else "mDNS Node"
        elif ip in ssdp_results:
            new_os = _parse_ssdp_server_header(ssdp_results[ip])

        # HOSTNAME-1: this used to write hostname directly and
        # unconditionally (new_hostname != current_hostname was the
        # only gate) -- meaning a curated-service-type mDNS instance
        # name could silently clobber an already-known SNMP sysName,
        # since this stage runs every fast tick while sysName only
        # refreshes on the slower deep-scan cadence. Routed through the
        # priority registry instead: a real friendly_name/instance_name
        # only wins if nothing more authoritative is already held.
        if mdns_hostname and set_hostname_by_node_id(cursor, node_id, mdns_hostname, PRIORITY_MDNS):
            hostname_writes += 1

        if new_os:
            os_updates.append((new_os, node_id))

    if os_updates:
        cursor.executemany('''
            UPDATE logical_nodes
            SET os_family = COALESCE(?, os_family)
            WHERE id = ?
        ''', os_updates)

    conn.commit()
    conn.close()
    logger.info(f"[*] OS Profiler: Dynamically mapped {len(os_updates)} IoT/Media endpoints via broadcast protocols ({hostname_writes} hostname updates).")

if __name__ == "__main__":
    asyncio.run(run_os_fingerprinter())
