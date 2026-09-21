import asyncio
import sqlite3
import sys
import os
from datetime import datetime
from engine.config_loader import config
from engine.snmp_adapter import get_working_credential, run_snmp_command

# Deliberately broader than production discovery needs -- see punch
# list SNMP-11. Includes sysDescr, which NOTHING in production
# discovery actually queries (the pipeline only ever fetches the
# numeric sysObjectID, step_20 in snmp_pipeline.py) but is often the
# single most human-readable "what is this device" field a vendor
# exposes -- genuinely useful for a device NetLanvas isn't classifying
# correctly.
DIAGNOSTIC_OIDS = {
    "sysDescr": {"oid": "1.3.6.1.2.1.1.1.0", "walk": False},
    "sysObjectID": {"oid": "1.3.6.1.2.1.1.2.0", "walk": False},
    "sysName": {"oid": "1.3.6.1.2.1.1.5.0", "walk": False},
    "ifTable (Interfaces)": {"oid": "1.3.6.1.2.1.2.2.1.3", "walk": True},
    "ifDescr (Interface Names)": {"oid": "1.3.6.1.2.1.2.2.1.2", "walk": True},
    "IEEE 802.11 MIB (Wi-Fi)": {"oid": "1.2.840.10036.1.1.1.1", "walk": True},
    "Q-BRIDGE FDB": {"oid": "1.3.6.1.2.1.17.7.1.2.2.1.2", "walk": True},
    "BRIDGE FDB (legacy)": {"oid": "1.3.6.1.2.1.17.4.3.1.1", "walk": True},
    "ARP Cache": {"oid": "1.3.6.1.2.1.4.22.1.2", "walk": True},
    "LLDP Remote Table": {"oid": "1.0.8802.1.1.2.1.4.1.1", "walk": True},
}


async def dump_target(ip, hostname, dev_type, credential, output_lines):
    def emit(line=""):
        print(line)
        output_lines.append(line)

    label_parts = [ip]
    if hostname: label_parts.append(hostname)
    if dev_type: label_parts.append(dev_type)

    emit("==========================================================")
    emit(f" TARGET: {' | '.join(label_parts)}")
    # display_label() never reveals the actual community string or
    # v3 password -- same masking principle as everywhere else this
    # gets logged (see punch list SNMP-4). This file may end up
    # attached to a bug report, so it's held to the same bar as a
    # normal log line, not treated as a private debugging exception.
    emit(f" CREDENTIAL USED: {credential.display_label() if credential else 'NONE RESOLVED'}")
    emit("==========================================================")

    if credential is None:
        emit("[!] No working credential could be resolved for this target -- skipping.")
        emit("")
        return

    for name, params in DIAGNOSTIC_OIDS.items():
        emit(f"\n--- Querying {name} [{params['oid']}] ---")
        result = await run_snmp_command(ip, params["oid"], credential, walk=params["walk"], timeout=2, retries=2)
        if result is None:
            emit("[ NO RESPONSE / EMPTY ]")
            continue
        if params["walk"]:
            for line in result:
                emit(line)
        else:
            emit(str(result))
    emit("")


async def main():
    # Optional: `python3 snmp_dump.py 10.10.10.50` dumps just that one
    # IP, regardless of whether it's already correctly classified in
    # the DB -- this is the case SNMP-11 actually exists for: a device
    # NetLanvas isn't identifying right. No argument falls back to the
    # original behavior (every currently-known non-endpoint device).
    target_arg = sys.argv[1] if len(sys.argv) > 1 else None

    if target_arg:
        targets = [(target_arg, None, None)]
    else:
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT b.ip_address, n.hostname, n.device_type
            FROM l3_bindings b
            JOIN l2_interfaces i ON b.mac_address = i.mac_address
            JOIN logical_nodes n ON i.node_id = n.id
            WHERE n.device_type != 'Endpoint' AND b.ip_address IS NOT NULL
        """)
        targets = cursor.fetchall()
        conn.close()

    output_lines = []
    def emit_top(line):
        print(line)
        output_lines.append(line)

    emit_top(f"NetLanvas SNMP Diagnostic Dump -- {datetime.now().isoformat()}")
    emit_top(f"Found {len(targets)} target(s) for analysis.\n")

    for ip, hostname, dev_type in targets:
        # Same shared mechanism as every other SNMP call site in the
        # app -- v3-first, cache-first, full v2c fallback list. This
        # tool never hardcodes or bypasses it (that was the original
        # bug this rework closes -- see punch list SNMP-11).
        credential = await get_working_credential(ip)
        await dump_target(ip, hostname, dev_type, credential, output_lines)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.dirname(config.DB_PATH)
    out_path = os.path.join(out_dir, f"snmp_dump_{timestamp}.txt")
    with open(out_path, "w") as f:
        f.write("\n".join(output_lines))

    print(f"\n[*] Full dump written to: {out_path}")
    print("[*] Attach this file to a bug report for hardware NetLanvas doesn't classify correctly.")


if __name__ == "__main__":
    asyncio.run(main())
