import asyncio
import logging
import sqlite3
import os
import re
import ipaddress
from pysnmp.hlapi.v3arch.asyncio import *
from engine.config_loader import config
from engine.snmp_adapter import get_working_credential, run_snmp_command, format_port_name, get_configured_credentials
from engine.snmp_credential import SNMPVersion, AUTH_PROTOCOLS_BY_STRENGTH, PRIV_PROTOCOLS_BY_STRENGTH
from engine.pysnmp_credential_adapter import to_pysnmp_auth_data
from engine.hostname_registry import set_hostname_by_mac, is_usable_hostname, PRIORITY_LLDP_SYSNAME
logger = logging.getLogger("Netlanvas.LLDP")
DB_PATH = config.DB_PATH
IEEE_LLDP_MAN_ADDR_OID = "1.0.8802.1.1.2.1.4.2"
IEEE_LLDP_CHASSIS_OID = "1.0.8802.1.1.2.1.4.1.1.5"
MIKROTIK_NEIGHBOR_IP_OID = "1.3.6.1.4.1.14988.1.1.11.1.1.2"
IEEE_LLDP_REMOTE_BRANCH_OID = "1.0.8802.1.1.2.1.4.1.1"
Q_BRIDGE_PVID_OID = "1.3.6.1.2.1.17.7.1.4.3.1.1"
IFTYPE_OID = "1.3.6.1.2.1.2.2.1.3"
IFDESCR_OID = "1.3.6.1.2.1.2.2.1.2"
snmp_engine = SnmpEngine()
# SSRF (F2/F6): LLDP-neighbor-supplied IPs (management address,
# OID-embedded IP, MikroTik neighbor table) are attacker-influenced --
# a rogue/compromised neighbor can advertise an arbitrary IP and turn
# this crawler into an unrestricted, credentialed SNMP poll of that
# address. Cap how many newly-discovered targets a single crawl will
# ever queue, on top of restricting which IPs are eligible at all
# (see is_allowed_neighbor_ip below).
MAX_DISCOVERED_TARGETS_PER_CRAWL = 500

# to_pysnmp_auth_data() moved to engine/pysnmp_credential_adapter.py --
# ping_sweeper.py needs the exact same translation, so this is now
# shared rather than duplicated (see punch list SNMP-3).

def is_valid_ipv4(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ValueError:
        return False
def is_allowed_neighbor_ip(ip_str):
    """
    SSRF guard (F2/F6): restrict LLDP/MikroTik-neighbor-supplied IPs to
    RFC1918 private and link-local ranges before they're ever queued as
    a credentialed SNMP poll target -- same restriction convention as
    ping_sweeper.py's auto_discover_network() (is_private/is_link_local).
    Loopback is rejected explicitly first: Python's ipaddress stdlib
    classifies 127.0.0.0/8 as is_private == True, so relying on
    is_private alone would let a neighbor advertise "127.0.0.1" (or any
    other loopback address) straight through as an allowed poll target.
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    if ip_obj.is_loopback:
        return False
    return ip_obj.is_private or ip_obj.is_link_local
def resolve_mac_to_ip(mac_address):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    mac_clean = mac_address.lower().replace('-', ':').strip()
    cursor.execute("SELECT ip_address FROM l3_bindings WHERE mac_address = ?", (mac_clean,))
    result = cursor.fetchone()
    if result and result[0] and is_valid_ipv4(result[0]):
        conn.close()
        return result[0]
    if len(mac_clean) >= 14:
        mac_prefix = mac_clean[:14] + "%"
        cursor.execute("SELECT ip_address FROM l3_bindings WHERE mac_address LIKE ? ORDER BY last_seen DESC LIMIT 1", (mac_prefix,))
        result = cursor.fetchone()
        if result and result[0] and is_valid_ipv4(result[0]):
            conn.close()
            return result[0]
    conn.close()
    return None
def save_link_to_db(switch_ip, local_port, remote_name, vlan_id=None, local_port_name=None, link_speed=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS infrastructure_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            local_switch_ip TEXT NOT NULL,
            local_port INTEGER NOT NULL,
            local_port_name TEXT,
            link_speed TEXT,
            remote_system_name TEXT,
            vlan_id INTEGER,
            is_ambiguous BOOLEAN DEFAULT 0,
            last_mapped DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(local_switch_ip, local_port)
        )
    ''')
    cursor.execute('''
        INSERT INTO infrastructure_links (local_switch_ip, local_port, local_port_name, link_speed, remote_system_name, vlan_id, last_mapped)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(local_switch_ip, local_port) DO UPDATE SET
            local_port_name=COALESCE(excluded.local_port_name, infrastructure_links.local_port_name),
            link_speed=COALESCE(excluded.link_speed, infrastructure_links.link_speed),
            remote_system_name=excluded.remote_system_name,
            vlan_id=COALESCE(excluded.vlan_id, infrastructure_links.vlan_id),
            last_mapped=CURRENT_TIMESTAMP
    ''', (switch_ip, local_port, local_port_name, link_speed, remote_name, vlan_id))
    conn.commit()
    conn.close()

def save_neighbor_hostname(mac_address, sys_name):
    # HOSTNAME-1: lldpRemSysName (leaf_type 9 above, already crawled for
    # every neighbor) was previously only ever used as a topology LABEL
    # (neighbor_label / infrastructure_links.remote_system_name) --
    # never fed into the neighbor's OWN logical_nodes.hostname. It's a
    # genuinely strong signal (the same admin-configured name a direct
    # SNMP sysName query would return), useful specifically for a
    # neighbor that shows up via LLDP but doesn't itself answer direct
    # SNMP (wrong/missing credential, ACL, etc.) -- exactly the case
    # fingerprinter.py's own "SNMP DEAD" fallback already flags.
    if not is_usable_hostname(sys_name):
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    set_hostname_by_mac(cursor, mac_address, sys_name, PRIORITY_LLDP_SYSNAME)
    conn.commit()
    conn.close()

async def get_physical_port_telemetry(ip, credential):
    task_type = run_snmp_command(ip, IFTYPE_OID, credential, walk=True)
    task_descr = run_snmp_command(ip, IFDESCR_OID, credential, walk=True)
    task_oper = run_snmp_command(ip, "1.3.6.1.2.1.2.2.1.8", credential, walk=True)
    task_hspeed = run_snmp_command(ip, "1.3.6.1.2.1.31.1.1.1.15", credential, walk=True)
    task_speed = run_snmp_command(ip, "1.3.6.1.2.1.2.2.1.5", credential, walk=True)
    iftype_res, ifdescr_res, oper_res, hspeed_res, speed_res = await asyncio.gather(
        task_type, task_descr, task_oper, task_hspeed, task_speed
    )
    valid_ports = {}
    allowed_types = {6, 71, 117, 161, 188}
    allowed_indices = set()
    if iftype_res:
        for line in iftype_res:
            try:
                if " " not in line: continue
                oid_part, val_part = line.split(" ", 1)
                port_idx = int(oid_part.split(".")[-1])
                if_type = int(val_part.split()[-1])
                if if_type in allowed_types:
                    allowed_indices.add(port_idx)
                    valid_ports[port_idx] = {"name": f"Port {port_idx}", "speed": "Unknown"}
            except Exception: pass
    if ifdescr_res:
        for line in ifdescr_res:
            try:
                if " " not in line: continue
                oid_part, name_part = line.split(" ", 1)
                port_idx = int(oid_part.split(".")[-1])
                if port_idx in allowed_indices:
                    valid_ports[port_idx]["name"] = format_port_name(name_part.strip(' "'))
            except Exception: pass
    oper_up_ports = set()
    if oper_res:
        for line in oper_res:
            try:
                if " " in line:
                    oid_part, val_part = line.split(" ", 1)
                    if "1" in val_part or "up" in val_part.lower():
                        oper_up_ports.add(int(oid_part.split(".")[-1]))
            except Exception: pass
    port_speeds = {}
    if hspeed_res:
        for line in hspeed_res:
            try:
                if " " in line:
                    oid_part, val_part = line.split(" ", 1)
                    idx = int(oid_part.split(".")[-1])
                    speed_mbps = int(val_part.strip())
                    if speed_mbps > 0 and idx in oper_up_ports:
                        port_speeds[idx] = speed_mbps
            except Exception: pass
    if speed_res:
        for line in speed_res:
            try:
                if " " in line:
                    oid_part, val_part = line.split(" ", 1)
                    idx = int(oid_part.split(".")[-1])
                    if idx not in port_speeds and idx in oper_up_ports:
                        speed_bps = int(val_part.strip())
                        if speed_bps > 0:
                            port_speeds[idx] = speed_bps // 1000000
            except Exception: pass
    def format_speed_str(mbps):
        if mbps >= 1000:
            return f"{mbps // 1000} Gbps" if mbps % 1000 == 0 else f"{mbps / 1000} Gbps"
        return f"{mbps} Mbps"
    for idx, mbps in port_speeds.items():
        if idx in valid_ports:
            valid_ports[idx]["speed"] = format_speed_str(mbps)
    return valid_ports
async def fetch_qbridge_pvids(switch_ip, auth_data, snmp_engine):
    """
    Takes an already-built pysnmp auth_data object (whichever credential
    just succeeded for the LLDP walk in poll_switch_lldp) rather than
    rebuilding one from raw community+mpModel params -- reuses exactly
    what worked instead of re-deriving it, and naturally supports v3
    since auth_data can now be a UsmUserData just as easily as a
    CommunityData.
    """
    port_vlans = {}
    try:
        target = await UdpTransportTarget.create((switch_ip, 161), timeout=1.0, retries=0)
        iterator = walk_cmd(snmp_engine, auth_data, target, ContextData(), ObjectType(ObjectIdentity(Q_BRIDGE_PVID_OID)), lexicographicMode=False)
        async for errorIndication, errorStatus, _, varBinds in iterator:
            if errorIndication or errorStatus: break
            for varBind in varBinds:
                oid_str = varBind[0].prettyPrint()
                if "17.7.1.4.3.1.1" not in oid_str: continue
                try:
                    port_idx = int(oid_str.split('.')[-1])
                    vlan_id = int(varBind[1].prettyPrint())
                    if vlan_id > 0: port_vlans[port_idx] = vlan_id
                except ValueError: continue
    except Exception: pass
    return port_vlans
async def discover_neighbors(device_ip, snmp_engine):
    switches = set()
    seen_oids = set()
    credential = await get_working_credential(device_ip)

    # v2c: keep trying both v2c and v1 message formats for this one
    # community string, exactly as before. v3: no format ambiguity to
    # loop over, just one attempt with the resolved identity.
    if credential is not None and credential.version == SNMPVersion.V2C:
        auth_data_attempts = [to_pysnmp_auth_data(credential, mp_model=1), to_pysnmp_auth_data(credential, mp_model=0)]
    else:
        auth_data_attempts = [to_pysnmp_auth_data(credential)]

    for comm_data in auth_data_attempts:
        if comm_data is None: continue
        try:
            target = await UdpTransportTarget.create((device_ip, 161), timeout=1.0, retries=0)
            iterator = walk_cmd(snmp_engine, comm_data, target, ContextData(), ObjectType(ObjectIdentity(IEEE_LLDP_MAN_ADDR_OID)), lexicographicMode=False)
            async for errorIndication, errorStatus, _, varBinds in iterator:
                if errorIndication or errorStatus: break
                for varBind in varBinds:
                    oid_str = varBind[0].prettyPrint()
                    if oid_str in seen_oids or "8802" not in oid_str: break
                    seen_oids.add(oid_str)
                    val_str = varBind[1].prettyPrint().strip().replace('"', '')
                    if is_valid_ipv4(val_str) and val_str != device_ip and is_allowed_neighbor_ip(val_str):
                        switches.add(val_str)
                    oid_match = re.search(r'\.1\.4\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', oid_str)
                    if oid_match:
                        extracted_ip = oid_match.group(1)
                        if is_valid_ipv4(extracted_ip) and extracted_ip != device_ip and is_allowed_neighbor_ip(extracted_ip): switches.add(extracted_ip)
            iterator = walk_cmd(snmp_engine, comm_data, target, ContextData(), ObjectType(ObjectIdentity(MIKROTIK_NEIGHBOR_IP_OID)), lexicographicMode=False)
            async for errorIndication, errorStatus, _, varBinds in iterator:
                if errorIndication or errorStatus: break
                for varBind in varBinds:
                    oid_str = varBind[0].prettyPrint()
                    if oid_str in seen_oids or "14988" not in oid_str: break
                    seen_oids.add(oid_str)
                    val_str = varBind[1].prettyPrint().strip()
                    if is_valid_ipv4(val_str) and val_str != device_ip and val_str != "0.0.0.0" and is_allowed_neighbor_ip(val_str):
                        switches.add(val_str)
            iterator = walk_cmd(snmp_engine, comm_data, target, ContextData(), ObjectType(ObjectIdentity(IEEE_LLDP_CHASSIS_OID)), lexicographicMode=False)
            async for errorIndication, errorStatus, _, varBinds in iterator:
                if errorIndication or errorStatus: break
                for varBind in varBinds:
                    oid_str = varBind[0].prettyPrint()
                    if oid_str in seen_oids or "8802" not in oid_str: break
                    seen_oids.add(oid_str)
                    raw_val = varBind[1]
                    mac_str = ':'.join(f'{b:02x}' for b in raw_val.asOctets()) if hasattr(raw_val, 'asOctets') else raw_val.prettyPrint()
                    resolved_ip = resolve_mac_to_ip(mac_str.replace('"', '').strip())
                    if resolved_ip and resolved_ip != device_ip: switches.add(resolved_ip)
            if switches: break
        except Exception: continue
    return switches
async def poll_switch_lldp(switch_ip, snmp_engine):
    base_credential = await get_working_credential(switch_ip)
    port_telemetry = await get_physical_port_telemetry(switch_ip, base_credential)

    # Build the pysnmp auth_data trial matrix from the SAME shared,
    # admin-configured credential list used everywhere else
    # (get_configured_credentials), not a locally rebuilt v2c-only
    # list -- this is what actually brings v3 support into this
    # pysnmp-native code path, replacing the old execution_matrix that
    # only ever knew about raw v2c community strings. The
    # currently-cached credential is tried first, matching the
    # original's "move the working one to the front" behavior. v3
    # identities are exhausted through their full strength-descending
    # protocol grid, same sequencing as the CLI-based adapter.
    configured = get_configured_credentials()
    base_key = base_credential.cache_key() if base_credential else None
    ordered_credentials = ([base_credential] if base_credential else []) + \
        [c for c in configured if c.cache_key() != base_key]

    auth_data_matrix = []
    for cred in ordered_credentials:
        if cred is None: continue
        if cred.version == SNMPVersion.V2C:
            for mp in (1, 0):
                ad = to_pysnmp_auth_data(cred, mp_model=mp)
                if ad is not None: auth_data_matrix.append(ad)
        else:
            for auth_proto in AUTH_PROTOCOLS_BY_STRENGTH:
                for priv_proto in PRIV_PROTOCOLS_BY_STRENGTH:
                    trial = cred.resolved_with(auth_proto, priv_proto)
                    ad = to_pysnmp_auth_data(trial)
                    if ad is not None: auth_data_matrix.append(ad)

    links_found = 0
    success = False
    for comm_data in auth_data_matrix:
        seen_oids = set()
        neighbor_profiles = {}
        iterations = 0
        try:
            target = await UdpTransportTarget.create((switch_ip, 161), timeout=1.2, retries=0)
            iterator = walk_cmd(snmp_engine, comm_data, target, ContextData(), ObjectType(ObjectIdentity(IEEE_LLDP_REMOTE_BRANCH_OID)), lexicographicMode=False)
            async for errorIndication, errorStatus, _, varBinds in iterator:
                iterations += 1
                if iterations > 200 or errorIndication or errorStatus: break
                for varBind in varBinds:
                    oid_str = varBind[0].prettyPrint()
                    val_obj = varBind[1]
                    if oid_str in seen_oids or "8802" not in oid_str: break
                    seen_oids.add(oid_str)
                    digits = re.findall(r'\d+', oid_str)
                    try:
                        idx_8802 = digits.index('8802')
                        leaf_type = int(digits[idx_8802 + 8])
                        local_port = int(digits[-2])
                        index_suffix = ".".join(digits[-3:])
                        if leaf_type not in [5, 7, 9, 10]: continue
                        if index_suffix not in neighbor_profiles:
                            neighbor_profiles[index_suffix] = {"port": local_port, "name": "", "mac": "", "port_id": "", "sys_desc": ""}
                        val_str = val_obj.prettyPrint().strip().replace('"', '')
                        if leaf_type == 9: neighbor_profiles[index_suffix]["name"] = val_str
                        elif leaf_type == 10: neighbor_profiles[index_suffix]["sys_desc"] = val_str
                        elif leaf_type == 5:
                            if hasattr(val_obj, 'asOctets'):
                                mac_bytes = val_obj.asOctets()
                                if len(mac_bytes) == 6: val_str = ':'.join(f'{b:02x}' for b in mac_bytes)
                            neighbor_profiles[index_suffix]["mac"] = val_str
                        elif leaf_type == 7: neighbor_profiles[index_suffix]["port_id"] = val_str
                    except (ValueError, IndexError): continue
            if iterations > 0 and not errorIndication and neighbor_profiles:
                success = True
                pvid_map = await fetch_qbridge_pvids(switch_ip, comm_data, snmp_engine)
                for suffix, profile in neighbor_profiles.items():
                    local_port = int(profile["port"])
                    if local_port == 0: continue
                    if port_telemetry and local_port not in port_telemetry: continue
                    local_port_name = port_telemetry[local_port]["name"] if port_telemetry else f"Port {local_port}"
                    link_speed = port_telemetry[local_port]["speed"] if port_telemetry else "Unknown"
                    vlan_id = pvid_map.get(local_port)
                    if not profile["name"] and not profile["sys_desc"]: continue
                    neighbor_label = None
                    if profile["mac"] and profile["mac"].strip():
                        clean_mac = profile["mac"].replace('-', ':').upper()
                        resolved_ip = resolve_mac_to_ip(clean_mac)
                        neighbor_label = resolved_ip if resolved_ip else clean_mac
                        if profile["name"] and profile["name"].strip() and profile["name"] != "None":
                            save_neighbor_hostname(clean_mac.lower(), profile["name"].strip())
                    elif profile["name"] and profile["name"].strip() and profile["name"] != "None":
                        neighbor_label = profile["name"]
                    elif profile["port_id"] and profile["port_id"].strip():
                        neighbor_label = profile["port_id"]
                    else: neighbor_label = "Unknown"
                    save_link_to_db(switch_ip, local_port, neighbor_label, vlan_id, local_port_name, link_speed)
                    links_found += 1
                break
        except Exception: continue
    if success:
        logger.info(f"[*] Success: Switch {switch_ip} mapped {links_found} LLDP links with speed verification.")
        return {"ip": switch_ip, "qualified": True}
    else:
        return {"ip": switch_ip, "qualified": False}
def resolve_ip_to_node_id(ip):
    """
    POLL-1 helper: returns the node_id already bound to this IP, or
    None if it isn't resolved yet (a brand new device just discovered
    via LLDP, not yet through unification). Deliberately conservative --
    only ever used to SKIP a redundant poll when we're confident via
    existing data that another IP for the same node was already
    LLDP-polled this run, never to guess at devices we don't have
    enough information about yet.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT i.node_id FROM l3_bindings b
        JOIN l2_interfaces i ON b.mac_address = i.mac_address
        WHERE b.ip_address = ? AND i.node_id IS NOT NULL
    ''', (ip,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


async def run_lldp_scraper(override_router_ip=None):
    router_ip = override_router_ip or config.GATEWAY_IP
    processed_switches = set()
    # POLL-1: tracks which NODES (not just which IPs) have already been
    # LLDP-polled this run -- confirmed live via TOPO-1 that a single
    # physical device can surface under several different IPs across
    # different neighbors' LLDP tables, each of which would otherwise
    # get independently polled for an identical result.
    processed_node_ids = set()
    switches_to_process = set()
    # SSRF (F2/F6): bound how many distinct targets a single crawl will
    # ever queue, on top of restricting which IPs are eligible at all
    # (is_allowed_neighbor_ip). Without this, a malicious/compromised
    # neighbor advertising many distinct in-range-looking addresses
    # across LLDP tables could make the recursive crawl balloon
    # unboundedly.
    all_targets_seen = set()
    logger.info(f"Phase 1: Running core gateway perimeter discovery on {router_ip}...")
    base_discoveries = await discover_neighbors(router_ip, snmp_engine)
    if not base_discoveries:
        logger.warning(f"No direct IP neighbors found on {router_ip}. Awaiting ARP DB synchronization (SD Card I/O compensation)...")
        await asyncio.sleep(15)
        base_discoveries = await discover_neighbors(router_ip, snmp_engine)
    switches_to_process.update(base_discoveries)
    all_targets_seen.update(base_discoveries)
    if not switches_to_process:
        logger.warning("No initial targets resolvable. Standing down Stage 3.")
        return
    logger.info("Phase 2: Launching recursive qualification crawl...")
    depth_layer = 1
    while switches_to_process:
        if depth_layer > 10: break
        current_batch = list(switches_to_process)
        switches_to_process.clear()

        # Only skip an IP when we're CERTAIN (via an existing node_id)
        # it's the same device as one already polled this run -- an IP
        # with no resolved node_id yet is always polled, since we have
        # no basis to call it redundant.
        poll_batch = []
        for ip in current_batch:
            node_id = resolve_ip_to_node_id(ip)
            if node_id is not None:
                if node_id in processed_node_ids:
                    logger.debug(f"[POLL-1] Skipping {ip} -- node {node_id} already LLDP-polled this run via a different IP.")
                    continue
                processed_node_ids.add(node_id)
            poll_batch.append(ip)

        logger.info(f"[Layer {depth_layer}] Scrutinizing batch nodes: {poll_batch}")
        poll_results = await asyncio.gather(*[
            poll_switch_lldp(switch, snmp_engine) for switch in poll_batch
        ])
        qualified_batch_ips = [r["ip"] for r in poll_results if r["qualified"]]
        # Track the FULL original batch as processed (not just the
        # deduped poll_batch), so a skipped sibling IP is never
        # rediscovered and re-queued in a later layer either.
        processed_switches.update(current_batch)
        if qualified_batch_ips:
            discovery_tasks = [discover_neighbors(switch, snmp_engine) for switch in qualified_batch_ips]
            discovery_results = await asyncio.gather(*discovery_tasks)
            for nested_set in discovery_results:
                for ip in nested_set:
                    if ip in processed_switches or ip in current_batch or ip in switches_to_process:
                        continue
                    if ip not in all_targets_seen and len(all_targets_seen) >= MAX_DISCOVERED_TARGETS_PER_CRAWL:
                        logger.warning(f"[SSRF-cap] MAX_DISCOVERED_TARGETS_PER_CRAWL ({MAX_DISCOVERED_TARGETS_PER_CRAWL}) reached -- ignoring further newly-discovered targets this crawl.")
                        continue
                    switches_to_process.add(ip)
                    all_targets_seen.add(ip)
        depth_layer += 1
    logger.info(f"Crawl complete. Certified infrastructure units mapped: {list(processed_switches)}")
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_lldp_scraper())
