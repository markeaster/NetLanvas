import asyncio
import logging
import sqlite3
from engine.config_loader import config
from engine.snmp_adapter import get_working_credential, adaptive_snmp_query, format_port_name, CREDENTIAL_CACHE
from engine.snmp_pipeline import run_snmp_pipeline
from engine.polling_targets import get_representative_targets

logger = logging.getLogger("Netlanvas.FDB")

async def process_switch_fdb(switch_ip, router_ips, semaphore, is_deep_scan_tick=False):
    async with semaphore:
        logger.info(f"[*] FDB Scraper: Extracting MAC tables, virtual boundaries, and telemetry from {switch_ip}...")
        base_comm = await get_working_credential(switch_ip)
        _, results = await run_snmp_pipeline(switch_ip, base_comm, is_deep_scan_tick=is_deep_scan_tick)

        mac_data = results.get(40) or results.get(50) or []
        
        task_dot1d = adaptive_snmp_query(switch_ip, "1.3.6.1.2.1.17.1.4.1.2", walk=True)
        task_iftype = adaptive_snmp_query(switch_ip, "1.3.6.1.2.1.2.2.1.3", walk=True)
        task_stack = adaptive_snmp_query(switch_ip, "1.3.6.1.2.1.31.1.2.1.3", walk=True)
        task_ifdescr = adaptive_snmp_query(switch_ip, "1.3.6.1.2.1.2.2.1.2", walk=True)
        task_operstatus = adaptive_snmp_query(switch_ip, "1.3.6.1.2.1.2.2.1.8", walk=True)
        task_highspeed = adaptive_snmp_query(switch_ip, "1.3.6.1.2.1.31.1.1.1.15", walk=True)
        task_speed = adaptive_snmp_query(switch_ip, "1.3.6.1.2.1.2.2.1.5", walk=True)
        
        dot1d_res, iftype_res, stack_res, ifDescr_res, oper_res, hspeed_res, speed_res = await asyncio.gather(
            task_dot1d, task_iftype, task_stack, task_ifdescr, task_operstatus, task_highspeed, task_speed, return_exceptions=True
        )

        port_to_ifindex = {}
        if isinstance(dot1d_res, list):
            for line in dot1d_res:
                try:
                    if " " in line:
                        oid_part, val_part = line.split(" ", 1)
                        port_to_ifindex[str(oid_part.strip().split(".")[-1])] = str(val_part.strip())
                except Exception: pass

        iftype_map = {}
        if isinstance(iftype_res, list):
            for line in iftype_res:
                try:
                    if " " in line:
                        oid_part, val_part = line.split(" ", 1)
                        iftype_map[str(oid_part.strip().split(".")[-1])] = int(val_part.strip().split()[-1])
                except Exception: pass
                
        sub_to_physical = {}
        if isinstance(stack_res, list):
            for line in stack_res:
                try:
                    if " " in line:
                        oid_part, _ = line.split(" ", 1)
                        parts = oid_part.strip('.').split(".")
                        if parts[-1] != "0": sub_to_physical[str(parts[-2])] = str(parts[-1])
                except Exception: pass

        def get_base_physical_port(if_idx):
            current = if_idx
            visited = set()
            while current in sub_to_physical and current not in visited:
                visited.add(current)
                current = sub_to_physical[current]
            return current

        # REVERTED VIRTUAL LOGIC: Match known-good exactly
        port_names = {}
        bridge_ports = set()
        if isinstance(ifDescr_res, list):
            for line in ifDescr_res:
                try:
                    if " " not in line: continue
                    oid_part, name_part = line.split(" ", 1)
                    idx = str(oid_part.split(".")[-1])
                    name_raw = name_part.strip(' "')
                    name_clean = name_raw.lower()
                    port_names[idx] = format_port_name(name_raw)
                    if "br0" in name_clean or "bridge" in name_clean:
                        bridge_ports.add(idx)
                except Exception: pass

        oper_up_ports = set()
        if isinstance(oper_res, list):
            for line in oper_res:
                try:
                    if " " in line:
                        oid_part, val_part = line.split(" ", 1)
                        if "1" in val_part or "up" in val_part.lower():
                            oper_up_ports.add(str(oid_part.split(".")[-1]))
                except Exception: pass

        port_speeds = {}
        if isinstance(hspeed_res, list):
            for line in hspeed_res:
                try:
                    if " " in line:
                        oid_part, val_part = line.split(" ", 1)
                        idx = str(oid_part.split(".")[-1])
                        speed_mbps = int(val_part.strip())
                        if speed_mbps > 0 and idx in oper_up_ports:
                            port_speeds[idx] = speed_mbps
                except Exception: pass
                
        if isinstance(speed_res, list):
            for line in speed_res:
                try:
                    if " " in line:
                        oid_part, val_part = line.split(" ", 1)
                        idx = str(oid_part.split(".")[-1])
                        if idx not in port_speeds and idx in oper_up_ports:
                            speed_bps = int(val_part.strip())
                            if speed_bps > 0:
                                port_speeds[idx] = speed_bps // 1000000
                except Exception: pass

        def format_speed_str(mbps):
            if mbps >= 1000:
                return f"{mbps // 1000} Gbps" if mbps % 1000 == 0 else f"{mbps / 1000} Gbps"
            return f"{mbps} Mbps"

        switch_locations = []
        for mac, port, vlan in mac_data:
            port_str = str(port)
            if port_str in port_to_ifindex: port_str = port_to_ifindex[port_str]
            port_str = get_base_physical_port(port_str)

            # REVERTED VIRTUAL ASSIGNMENT
            if port_str in bridge_ports:
                port_str = "Bridge"

            port_name = port_names.get(port_str, f"Port {port_str}") if port_str != "Bridge" else "Bridge"
            speed_str = format_speed_str(port_speeds[port_str]) if port_str in port_speeds else "Unknown"
            if port_str == "Bridge": speed_str = "Virtual"

            mac_lower = mac.lower()
            switch_locations.append((mac_lower, switch_ip, port_str, port_name, speed_str, vlan))

        return switch_locations

async def run_mac_table_scraper(is_deep_scan_tick=False):
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()

    # POLL-1: one representative IP per node instead of every IP that
    # node happens to have -- a switch/router's FDB table is identical
    # regardless of which of its own IPs is used to query it, confirmed
    # via TOPO-1 (a single router can genuinely have 6+ interface IPs).
    switches = get_representative_targets(
        ['Switch', 'Router', 'Switch / WAP'], credential_cache=CREDENTIAL_CACHE,
    )

    cursor.execute('''
        SELECT DISTINCT b.ip_address
        FROM logical_nodes n
        JOIN l2_interfaces i ON n.id = i.node_id
        JOIN l3_bindings b ON i.mac_address = b.mac_address
        WHERE n.device_type = 'Router' AND b.ip_address IS NOT NULL
    ''')
    router_ips = {row[0] for row in cursor.fetchall()}
    
    if not switches:
        conn.close()
        return

    logger.info(f"[*] FDB Scraper: Initializing distributed concurrent scrape across {len(switches)} chassis...")

    semaphore = asyncio.Semaphore(5)
    tasks = [process_switch_fdb(ip, router_ips, semaphore, is_deep_scan_tick=is_deep_scan_tick) for ip in switches]
    results_list = await asyncio.gather(*tasks)

    global_mac_locations = {}
    for batch in results_list:
        for mac_lower, switch_ip, port_str, port_name, speed_str, vlan in batch:
            if mac_lower not in global_mac_locations:
                global_mac_locations[mac_lower] = []
            if not any(loc[0] == switch_ip for loc in global_mac_locations[mac_lower]):
                global_mac_locations[mac_lower].append((switch_ip, port_str, port_name, speed_str, vlan))

    cursor.execute('''
        SELECT l.local_switch_ip, l.local_port, n.device_type
        FROM infrastructure_links l
        LEFT JOIN l3_bindings b ON l.remote_system_name = b.ip_address
        LEFT JOIN l2_interfaces i ON b.mac_address = i.mac_address
        LEFT JOIN logical_nodes n ON i.node_id = n.id
    ''')
    port_penalties = {}
    for src_ip, port, dev_type in cursor.fetchall():
        key = f"{src_ip}:{port}"
        dtype = str(dev_type).lower() if dev_type else "unknown_infrastructure"
        
        # EXPANDED SAFE-ZONE TO INCLUDE UNMANAGED SWITCHES
        if "access point" in dtype or "wap" in dtype or "unmanaged switch" in dtype or "smart switch" in dtype:
            port_penalties[key] = -5000
        else: 
            port_penalties[key] = 10000 

    raw_density = {}
    for mac, locations in global_mac_locations.items():
        for switch_ip, port, _, _, _ in locations:
            port_key = f"{switch_ip}:{port}"
            raw_density[port_key] = raw_density.get(port_key, 0) + 1
            if port_key not in port_penalties and switch_ip in router_ips: port_penalties[port_key] = 10000

    port_weights = {}
    for port_key, count in raw_density.items():
        port_weights[port_key] = count + port_penalties.get(port_key, 0)

    # REMOVED CACHE LOOKUP - WE WANT TRUE DROPS
    final_edge_locations = []
    macs_to_purge = []
    
    for mac, locations in global_mac_locations.items():
        best_location = min(locations, key=lambda loc: port_weights.get(f"{loc[0]}:{loc[1]}", 9999))
        best_weight = port_weights.get(f"{best_location[0]}:{best_location[1]}", 9999)
        
        # UNCONDITIONAL BACKBONE DROP
        if best_weight >= 10000: 
            macs_to_purge.append((mac,))
            continue
            
        final_edge_locations.append((mac, best_location[0], best_location[1], best_location[2], best_location[3], best_location[4]))

    if macs_to_purge:
        cursor.executemany("DELETE FROM endpoint_locations WHERE mac_address = ? AND local_port != 'WLAN'", macs_to_purge)

    for mac, switch_ip, port, port_name, speed_str, vlan in final_edge_locations:
        cursor.execute('''
            INSERT INTO endpoint_locations (mac_address, switch_ip, local_port, local_port_name, link_speed, vlan_id, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(mac_address) DO UPDATE SET switch_ip = excluded.switch_ip, local_port = excluded.local_port, local_port_name = excluded.local_port_name, link_speed = excluded.link_speed, vlan_id = excluded.vlan_id, last_seen = CURRENT_TIMESTAMP
        ''', (mac, switch_ip, port, port_name, speed_str, vlan))

    cursor.execute("DELETE FROM endpoint_locations WHERE local_port != 'WLAN' AND (strftime('%s', 'now') - strftime('%s', last_seen)) > 21600")
    wired_purged = cursor.rowcount
    
    cursor.execute("DELETE FROM endpoint_locations WHERE local_port = 'WLAN' AND (strftime('%s', 'now') - strftime('%s', last_seen)) > 3600")
    wifi_purged = cursor.rowcount

    cursor.execute("DELETE FROM endpoint_locations WHERE local_port = 'Bridge' OR local_port_name = 'Bridge'")
    bridge_purged = cursor.rowcount

    # device_type filter (2026-09-08): was missing 'Switch / WAP',
    # 'Smart Switch', and 'Smart Switch (Unverified)' -- the actual
    # device_type strings a confirmed smart switch (SSDP/NSDP/ESCP)
    # ends up with. A smart switch's uplink port therefore never
    # qualified for promotion at all, even though the exact same
    # local_port_name/link_speed data this query already selects for
    # every OTHER promoted device was sitting right there for it too.
    # Deliberately NOT adding 'Unmanaged Switch' here -- that device
    # type only ever exists BECAUSE a port hosts multiple MACs with no
    # single confirmed device (see inference_engine.py's dark-matter
    # detection), so it could never satisfy this query's single-MAC
    # promotion shape in the first place; that case has its own fix.
    cursor.execute('''
        SELECT el.switch_ip, el.local_port, el.local_port_name, el.link_speed, b.ip_address, el.vlan_id, b.mac_address, src_b.mac_address
        FROM endpoint_locations el
        JOIN l3_bindings b ON el.mac_address = b.mac_address
        JOIN l2_interfaces i ON el.mac_address = i.mac_address
        JOIN logical_nodes ln_tgt ON i.node_id = ln_tgt.id
        LEFT JOIN l3_bindings src_b ON el.switch_ip = src_b.ip_address
        WHERE ln_tgt.device_type IN ('Access Point', 'Switch', 'Router', 'Switch / WAP', 'Smart Switch', 'Smart Switch (Unverified)')
    ''')
    promotions = cursor.fetchall()

    promoted_count = 0
    for switch_ip, port, port_name, speed_str, target_ip, vlan_id, tgt_mac, src_mac in promotions:
        if not target_ip or port == 'Bridge' or (src_mac and tgt_mac and src_mac.lower() == tgt_mac.lower()): continue
        cursor.execute('''
            INSERT INTO infrastructure_links (local_switch_ip, local_port, local_port_name, link_speed, remote_system_name, vlan_id, last_mapped)
            VALUES (?, CAST(? AS INTEGER), ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(local_switch_ip, local_port) DO UPDATE SET local_port_name = excluded.local_port_name, link_speed = excluded.link_speed, remote_system_name = excluded.remote_system_name, vlan_id = excluded.vlan_id, last_mapped = CURRENT_TIMESTAMP
        ''', (switch_ip, port, port_name, speed_str, target_ip, vlan_id))
        promoted_count += 1

    cursor.execute('''
        SELECT l1.local_switch_ip, l1.remote_system_name, b_local.mac_address
        FROM infrastructure_links l1
        LEFT JOIN infrastructure_links l2 
            ON l1.local_switch_ip = l2.remote_system_name 
            AND l1.remote_system_name = l2.local_switch_ip
        JOIN l3_bindings b_local ON l1.local_switch_ip = b_local.ip_address
        WHERE l2.id IS NULL AND l1.remote_system_name IS NOT NULL
    ''')
    unidirectional_links = cursor.fetchall()
    
    backfill_count = 0
    for src_ip, tgt_ip, src_mac in unidirectional_links:
        if not src_mac: continue
        clean_mac = src_mac.lower()
        if clean_mac in global_mac_locations:
            for switch_ip, port, port_name, speed_str, vlan in global_mac_locations[clean_mac]:
                if switch_ip == tgt_ip and port != 'Bridge':
                    cursor.execute('''
                        INSERT INTO infrastructure_links (local_switch_ip, local_port, local_port_name, link_speed, remote_system_name, vlan_id, last_mapped)
                        VALUES (?, CAST(? AS INTEGER), ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(local_switch_ip, local_port) DO UPDATE SET local_port_name = excluded.local_port_name, link_speed = excluded.link_speed, remote_system_name = excluded.remote_system_name, vlan_id = excluded.vlan_id, last_mapped = CURRENT_TIMESTAMP
                    ''', (tgt_ip, port, port_name, speed_str, src_ip, vlan))
                    backfill_count += 1
                    break

    conn.commit()
    conn.close()

    logger.info(f"FDB Scrape Complete. Density-Based Edge Resolution applied across {len(switches)} chassis.")
    if len(macs_to_purge) > 0: logger.info(f"[*] Artifact Sanitization: Actively purged {len(macs_to_purge)} stale backbone clamps.")
    if wired_purged > 0: logger.info(f"[*] Hysteresis Timeout: Purged {wired_purged} stale WIRED locations aged > 6 hours.")
    if wifi_purged > 0: logger.info(f"[*] Hysteresis Timeout: Purged {wifi_purged} stale WLAN locations aged > 1 hour.")
    if bridge_purged > 0: logger.info(f"[*] Artifact Sanitization: Permanently destroyed {bridge_purged} virtual Bridge assignments.")
    if promoted_count > 0: logger.info(f"[*] FDB Promotion: Elevated {promoted_count} opaque infrastructure nodes.")
    if backfill_count > 0: logger.info(f"[*] Bidirectional Back-Fill: Synthesized {backfill_count} reverse infrastructure links using FDB data.")

if __name__ == "__main__":
    asyncio.run(run_mac_table_scraper())
