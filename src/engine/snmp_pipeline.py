import logging
import sqlite3
import time
import re
import ipaddress
from typing import NamedTuple, Optional, Any, Dict, Callable, Tuple
from engine.config_loader import config
from engine.snmp_adapter import run_snmp_command
from engine.snmp_credential import SNMPCredential
logger = logging.getLogger("Netlanvas.Pipeline")
class StepResult(NamedTuple):
    should_continue: bool
    data: Optional[Any]
class SNMPPipeline:
    def __init__(self):
        self.registry: Dict[int, Tuple[str, Callable]] = {}
    def register(self, step_id: int, name: str):
        def decorator(func: Callable):
            self.registry[step_id] = (name, func)
            return func
        return decorator
engine = SNMPPipeline()
# --- STEP 10: REACHABILITY GATE ---
@engine.register(10, "Reachability Gate (sysUpTime)")
async def step_10_reachability(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    if config.VERBOSE_LOGGING: logger.debug(f"[Pipeline-10] Testing reachability for {ip}")
    res = await run_snmp_command(ip, "1.3.6.1.2.1.1.3.0", credential)
    if res: return StepResult(should_continue=True, data=res)
    if config.VERBOSE_LOGGING: logger.debug(f"[Pipeline-10] {ip} is offline. Aborting pipeline.")
    return StepResult(should_continue=False, data=None)
# --- STEP 20: SYSTEM PROFILING ---
@engine.register(20, "System Profiling (sysObjectID)")
async def step_20_sysobjectid(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    if config.VERBOSE_LOGGING: logger.debug(f"[Pipeline-20] Extracting sysObjectID for {ip}")
    res = await run_snmp_command(ip, "1.3.6.1.2.1.1.2.0", credential)
    if res:
        context['sys_object_id'] = res
        return StepResult(should_continue=True, data=res)
    return StepResult(should_continue=True, data=None)
# --- STEP 30: L3 VLAN GATEWAY PARSER ---
@engine.register(30, "L3 VLAN Gateway Parser (ifTable)")
async def step_30_iftable(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    if config.VERBOSE_LOGGING: logger.debug(f"[Pipeline-30] Parsing IF-MIB for {ip}")
    res = await run_snmp_command(ip, "1.3.6.1.2.1.2.2.1.2", credential, walk=True, timeout=3, retries=2)
    vlans = {}
    if res:
        for line in res:
            match = re.search(r'(?:bridge-)?vlan(\d+)', line, re.IGNORECASE)
            if match:
                try:
                    oid_part, _ = line.split(" ", 1)
                    if_idx = int(oid_part.split(".")[-1])
                    vlans[if_idx] = int(match.group(1))
                except Exception: pass
        if vlans: return StepResult(should_continue=True, data=vlans)
    return StepResult(should_continue=True, data=None)
# --- STEP 35: L3 ARP CACHE PARSER ---
@engine.register(35, "L3 ARP Cache Parser (ipNetToMediaPhysAddress)")
async def step_35_arp(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    if config.VERBOSE_LOGGING: logger.debug(f"[Pipeline-35] Querying ARP cache on {ip}")
    res = await run_snmp_command(ip, "1.3.6.1.2.1.4.22.1.2", credential, walk=True, timeout=3, retries=2)
    if not res:
        return StepResult(should_continue=True, data=None)

    # NET-3: ipNetToMediaType (RFC1213 -- standard MIB-II, no vendor-
    # specific extension needed) reports invalid(2) for an ARP entry
    # the router itself has given up trying to re-resolve, but hasn't
    # purged from the table yet -- confirmed live against a real device
    # that had been physically powered off for over a week, whose
    # stale ARP entry (RouterOS's own CLI shows it as status "failed")
    # was still being blindly re-ingested every cycle here, refreshing
    # l3_bindings.last_seen to "now" and making the appliance report it
    # as currently online. Only dynamic(3)/static(4) are trusted as
    # genuine presence; invalid(2)/other(1) are excluded outright.
    # Best-effort: if this second walk fails for any reason, falls back
    # to the old unfiltered behavior rather than losing ARP data
    # entirely over a transient issue with a non-critical extra check.
    # NET-4 (2026-09-03): stale-ness is tracked per (ifIndex,
    # ip) ROW, not per bare ip -- a router can carry both a valid,
    # currently-resolving ARP entry for a device AND a separate stale
    # ghost entry for the SAME ip on a DIFFERENT interface (confirmed
    # live: two identical devices behind an unmanaged switch's uplink
    # port left one of them with a stale, never-resolving entry on the
    # router's software bridge interface, alongside its own real, valid
    # entry on the physical port it actually lives on). Keying the old
    # stale_ips set by bare ip meant that unrelated ghost entry silently
    # poisoned the device's genuinely valid entry too -- it vanished
    # from discovery entirely, despite the router confirming it fine on
    # its real interface. ip_has_valid_entry/stale_ips below now only
    # mark an ip as fully stale (for the caller's l3_bindings-retirement
    # use, see the comment lower down) once EVERY row seen for it is
    # invalid -- one bad interface can no longer hide a good one.
    type_res = await run_snmp_command(ip, "1.3.6.1.2.1.4.22.1.4", credential, walk=True, timeout=3, retries=2)
    stale_entries = set()
    ip_seen = set()
    ip_has_valid_entry = set()
    if type_res:
        for line in type_res:
            try:
                if " " not in line: continue
                oid_part, val_part = line.split(" ", 1)
                oid_suffix = oid_part.split('.')[-5:]
                if len(oid_suffix) != 5: continue
                ifindex, ip_address = oid_suffix[0], ".".join(oid_suffix[1:])
                ip_seen.add(ip_address)
                if val_part.strip(' "') in ("3", "4"):
                    ip_has_valid_entry.add(ip_address)
                else:
                    stale_entries.add((ifindex, ip_address))
            except Exception: pass
    stale_ips = ip_seen - ip_has_valid_entry

    arp_records = {}
    for line in res:
        try:
            if " " not in line: continue
            oid_part, val_part = line.split(" ", 1)
            oid_suffix = oid_part.split('.')[-5:]
            if len(oid_suffix) != 5: continue
            ifindex, ip_address = oid_suffix[0], ".".join(oid_suffix[1:])
            if ip_address.startswith("127."): continue
            if (ifindex, ip_address) in stale_entries: continue
            ip_obj = ipaddress.IPv4Address(ip_address)
            if not (ip_obj.is_private or ip_obj.is_link_local): continue
            raw_mac = val_part.strip(' "').replace(' ', ':').lower()
            parts = raw_mac.split(':')
            if len(parts) == 6:
                mac_address = ':'.join(f'{int(p, 16):02x}' for p in parts)
                if mac_address != "00:00:00:00:00:00":
                    arp_records[mac_address] = ip_address
        except Exception: pass
    # NET-3 follow-up: a MAC that moves to a new IP (DHCP reassignment,
    # VLAN change, physical relocation to a different subnet) leaves its
    # old l3_bindings row behind forever otherwise -- l3_bindings is
    # keyed by ip_address, so the old row is a different primary key
    # from the new one and nothing ever touches it once the router stops
    # confirming it as dynamic/static. Surfacing stale_ips here (instead
    # of only using it to filter this walk's own arp_records) lets the
    # caller actively retire those rows the moment the source router
    # itself gives up on them, rather than waiting on some other event
    # (e.g. the same MAC reappearing elsewhere) that may never happen.
    if arp_records or stale_ips:
        return StepResult(should_continue=True, data={"valid": arp_records, "stale": stale_ips})
    return StepResult(should_continue=True, data=None)
# --- STEP 40: STANDARD Q-BRIDGE MIB ---
@engine.register(40, "Standard Q-BRIDGE MIB")
async def step_40_qbridge(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    if config.VERBOSE_LOGGING: logger.debug(f"[Pipeline-40] Querying Q-BRIDGE-MIB on {ip}")
    res = await run_snmp_command(ip, "1.3.6.1.2.1.17.7.1.2.2.1.2", credential, walk=True, timeout=4, retries=2)
    mac_locations = []
    if res:
        for line in res:
            try:
                if " " not in line: continue
                oid_part, port = line.split(" ", 1)
                parts = oid_part.strip('.').split(".")
                vlan = int(parts[-7])
                mac = ":".join([f"{int(x):02x}" for x in parts[-6:]])
                if port.strip().isdigit() and port.strip() != '0':
                    mac_locations.append((mac, int(port.strip()), vlan))
            except Exception: pass
        if mac_locations: return StepResult(should_continue=True, data=mac_locations)
    return StepResult(should_continue=True, data=None)
# --- STEP 50: STANDARD BRIDGE MIB ---
@engine.register(50, "Standard BRIDGE MIB")
async def step_50_bridge(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    if config.VERBOSE_LOGGING: logger.debug(f"[Pipeline-50] Querying standard BRIDGE-MIB on {ip}")
    res = await run_snmp_command(ip, "1.3.6.1.2.1.17.4.3.1.2", credential, walk=True, timeout=4, retries=2)
    mac_locations = []
    if res:
        for line in res:
            try:
                if " " not in line: continue
                oid_part, port = line.split(" ", 1)
                parts = oid_part.strip('.').split(".")
                mac = ":".join([f"{int(x):02x}" for x in parts[-6:]])
                if port.strip().isdigit() and port.strip() != '0':
                    mac_locations.append((mac, int(port.strip()), 1))
            except Exception: pass
        if mac_locations: return StepResult(should_continue=True, data=mac_locations)
    return StepResult(should_continue=True, data=None)
# --- STEP 60: ARUBA WAP ENTERPRISE ---
@engine.register(60, "Aruba WAP Enterprise")
async def step_60_aruba(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    if not config.WIFI_STRICT_MODE:
        return StepResult(should_continue=True, data=None)
    sys_obj = context.get('sys_object_id', '')
    if "14823" not in sys_obj: return StepResult(should_continue=True, data=None)
    res = await run_snmp_command(ip, "1.3.6.1.4.1.14823.2.3.3.1.2.4.1.1", credential, walk=True)
    macs = []
    if res:
        for line in res:
            try:
                _, raw_val = line.split(" ", 1)
                macs.append(raw_val.replace(" ", ":").lower().strip())
            except Exception: pass
        if macs: return StepResult(should_continue=True, data=macs)
    return StepResult(should_continue=True, data=None)
# --- STEP 70: TP-LINK WAP ENTERPRISE ---
@engine.register(70, "TP-Link WAP Enterprise")
async def step_70_tplink(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    if not config.WIFI_STRICT_MODE:
        return StepResult(should_continue=True, data=None)
    sys_obj = context.get('sys_object_id', '')
    if "11863" not in sys_obj: return StepResult(should_continue=True, data=None)
    res = await run_snmp_command(ip, "1.3.6.1.4.1.11863.10.1.1.2.1.2", credential, walk=True)
    macs = []
    if res:
        for line in res:
            try:
                _, raw_val = line.split(" ", 1)
                if " " in raw_val:
                    ascii_str = "".join([chr(int(h, 16)) for h in raw_val.split()])
                    macs.append(ascii_str.replace('\x00', '').lower().replace('-', ':').strip())
            except Exception: pass
        if macs: return StepResult(should_continue=True, data=macs)
    return StepResult(should_continue=True, data=None)
# --- STEP 80: UBIQUITI CONTROLLER-MANAGED ---
@engine.register(80, "Ubiquiti Controller-Managed")
async def step_80_ubiquiti(ip: str, credential: SNMPCredential, context: dict) -> StepResult:
    sys_obj = context.get('sys_object_id', '')
    if "41112" not in sys_obj: return StepResult(should_continue=True, data=None)
    return StepResult(should_continue=True, data="CONTROLLER_MANAGED")
# ==============================================================================
# PIPELINE RUNNER & CACHE CONTROLLER
# ==============================================================================
async def run_snmp_pipeline(ip: str, credential: SNMPCredential, is_deep_scan_tick: bool = False) -> Tuple[str, Dict[int, Any]]:
    # CAPS-1 (2026-09-09): force_deep used to be gated by a hardcoded
    # 12h wall-clock timer (next_deep_discovery) -- a step that returned
    # None on just ONE poll (a transient SNMP timeout, a switch busy
    # elsewhere) got silently excluded from working_functions and thus
    # from every FAST poll for up to 12 hours, even if the device would
    # have answered fine on the very next tick. Confirmed live: this is
    # what dropped the GS748 switch's Q-BRIDGE-MIB FDB walk (step 40)
    # for one test host's connection. Replaced with is_deep_scan_tick,
    # threaded down from main.py's own tick loop -- every step gets
    # re-checked on the SAME cadence as every other structural deep-scan
    # (unification, inference, LLDP, etc.), so a bad poll self-heals at
    # most one deep-scan cycle later instead of up to 12 hours later.
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT working_functions FROM device_capabilities WHERE ip_address = ?", (ip,))
    row = cursor.fetchone()
    cached_steps = []
    force_deep = False
    current_time = time.time()
    if row:
        working_str = row[0]
        if working_str:
            cached_steps = [int(x) for x in working_str.split(',') if x.isdigit()]
        force_deep = is_deep_scan_tick
    else:
        force_deep = True
    if config.VERBOSE_LOGGING:
        mode = "DEEP DISCOVERY" if force_deep else f"FAST POLL ({cached_steps})"
        logger.debug(f"[*] Pipeline Execution Mode for {ip}: {mode}")
    steps_to_run = sorted(engine.registry.keys()) if force_deep else sorted(cached_steps)
    if not force_deep:
        if 10 not in steps_to_run: steps_to_run.insert(0, 10)
        if 20 not in steps_to_run: steps_to_run.insert(1, 20)
        steps_to_run = sorted(list(set(steps_to_run)))
    results_payload = {}
    working_steps = []
    shared_context = {}
    for step_id in steps_to_run:
        name, func = engine.registry.get(step_id)
        result = await func(ip, credential, shared_context)
        if result.data is not None:
            working_steps.append(step_id)
            results_payload[step_id] = result.data
        if not result.should_continue:
            break
    new_working_string = ",".join(map(str, sorted(working_steps)))
    # next_deep_discovery is no longer read anywhere (deep-scan cadence
    # is now driven by is_deep_scan_tick, not a stored timestamp) --
    # column kept for schema/backward-compat, stamped with this poll's
    # time purely as a diagnostic "last checked" marker.
    cursor.execute('''
        INSERT INTO device_capabilities (ip_address, sys_object_id, working_functions, last_successful_poll, next_deep_discovery)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            sys_object_id=excluded.sys_object_id,
            working_functions=excluded.working_functions,
            last_successful_poll=excluded.last_successful_poll,
            next_deep_discovery=excluded.next_deep_discovery
    ''', (ip, shared_context.get('sys_object_id', ''), new_working_string, current_time, current_time))
    conn.commit()
    conn.close()
    return new_working_string, results_payload
