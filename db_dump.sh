#!/bin/bash

# Define the database path
DB_PATH="/app/db/network.db"
CONTAINER_NAME="netlanvas_core"

# Check if the container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: Container '${CONTAINER_NAME}' is not running."
    echo "Please start the stack first using: docker compose up -d"
    exit 1
fi

# Function to execute a query using Python inside the container
print_table() {
    local table_name=$1
    local query=$2

    echo "===================================================================================================="
    echo " TABLE: ${table_name}"
    echo "===================================================================================================="

    docker exec -i ${CONTAINER_NAME} python -c "
import sqlite3
try:
    conn = sqlite3.connect('${DB_PATH}')
    cursor = conn.cursor()
    cursor.execute(\"\"\"${query}\"\"\")
    rows = cursor.fetchall()

    if not rows:
        print('  [ No data found ]')
    else:
        headers = [desc[0] for desc in cursor.description]
        widths = [len(h) for h in headers]
        for row in rows:
            for i, val in enumerate(row):
                widths[i] = max(widths[i], len(str(val) if val is not None else 'NULL'))

        row_format = ' | '.join(['{:<' + str(w) + '}' for w in widths])
        print(row_format.format(*headers))
        print('-' * (sum(widths) + 3 * (len(headers) - 1)))
        for row in rows:
            print(row_format.format(*[str(val) if val is not None else 'NULL' for val in row]))
except Exception as e:
    print(f'Error executing query: {e}')
"
    echo -e "\n"
}

clear
echo "===================================================================================================="
echo "                            NETLANVAS DIAGNOSTIC DATABASE DUMP"
echo "===================================================================================================="
echo -e "\n"

# 1. Logical Nodes (Restored to show weld_confidence and os_family)
print_table "logical_nodes (Unified Entities)" \
"SELECT id, substr(hostname, 1, 40) as hostname, device_type, substr(os_family, 1, 22) as os_family, weld_confidence FROM logical_nodes;"

# 2. Device Fingerprints
print_table "device_fingerprints (Hardware/OS Signatures)" \
"SELECT substr(mac_address, 1, 20) as mac, substr(snmp_sysdescr, 1, 60) as sysDescr, substr(banner, 1, 30) as banner FROM device_fingerprints;"

# 3. Layer 2 Interfaces
print_table "l2_interfaces (Hardware MACs & Wi-Fi Tags)" \
"SELECT substr(mac_address, 1, 17) as mac, node_id, substr(vendor, 1, 25) as vendor, substr(wireless_ssid, 1, 20) as ssid FROM l2_interfaces;"

# 4. Layer 3 Bindings (Now includes 'is_public' flag)
print_table "l3_bindings (IP Assignments & State)" \
"SELECT ip_address, substr(mac_address, 1, 17) as mac, discovery_source, is_public, is_ghost FROM l3_bindings;"

# 5. Infrastructure Links (Includes is_ambiguous flag)
print_table "infrastructure_links (LLDP / CDP Verified Topology)" \
"SELECT id, local_switch_ip as switch_ip, local_port as port, substr(remote_system_name, 1, 25) as remote_target, is_ambiguous FROM infrastructure_links;"

# 6. Endpoint Locations (Includes is_ambiguous flag)
print_table "endpoint_locations (FDB / MAC Scraper Results)" \
"SELECT substr(mac_address, 1, 17) as mac, switch_ip, local_port as port, vlan_id, is_ambiguous, datetime(last_seen, 'localtime') as last_seen FROM endpoint_locations ORDER BY switch_ip, CAST(local_port as INTEGER);"

echo "Dump Complete."
