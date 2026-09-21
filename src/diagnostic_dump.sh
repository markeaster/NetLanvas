#!/bin/bash
set -e

# Dynamically resolve script execution directory and map local tmp
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
TMP_DIR="${SCRIPT_DIR}/tmp"

# Evaluate positional arguments or trigger interactive prompts
if [ -n "$1" ]; then
    TARGET_IP="$1"
else
    read -p "Enter Target IP Address: " TARGET_IP
fi

if [ -n "$2" ]; then
    SNMP_COMMUNITY="$2"
else
    read -s -p "Enter SNMP Community String: " SNMP_COMMUNITY
    echo ""
fi

# Failsafe validation
if [ -z "$TARGET_IP" ] || [ -z "$SNMP_COMMUNITY" ]; then
    echo "CRITICAL: Both Target IP and Community String must be provided."
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CLEAN_FILE="${TMP_DIR}/diag_${TARGET_IP}_${TIMESTAMP}.txt"

# Ensure relative tmp directory exists alongside the script before executing payload
mkdir -p "${TMP_DIR}"

TARGET_OIDS=(
    "1.3.6.1.2.1.1"       # System Information
    "1.3.6.1.2.1.2"       # Interfaces
    "1.3.6.1.2.1.3"       # Address Translation (ARP)
    "1.3.6.1.2.1.4"       # IP Routing & Addressing
    "1.3.6.1.2.1.17"      # Bridge MIB (MAC Forwarding Tables, STP)
    "1.3.6.1.2.1.25"      # Host Resources
    "1.3.6.1.2.1.31"      # ifMIB (64-bit interface counters)
    "1.3.6.1.2.1.47"      # Entity MIB (Hardware chassis components)
    "1.3.6.1.2.1.55"      # IPv6 Metrics
    "1.3.6.1.2.1.9999"    # Non-standard assignments (e.g., RouterOS DHCP)
    "1.3.6.1.4.1"         # Enterprises (All vendor-proprietary hardware/APIs)
    "1.2.840.10036"       # IEEE 802.11 (Wi-Fi Associations)
)

echo "[*] Executing segmented bulk MIB walk against ${TARGET_IP}..."
echo "[*] Outputting directly to: ${CLEAN_FILE}"

> "${CLEAN_FILE}"

for OID in "${TARGET_OIDS[@]}"; do
    echo " -> Traversing branch: ${OID}"
    snmpbulkwalk -v2c -Cc -c "${SNMP_COMMUNITY}" "${TARGET_IP}" "${OID}" >> "${CLEAN_FILE}" 2>&1 || \
    snmpwalk -v2c -Cc -c "${SNMP_COMMUNITY}" "${TARGET_IP}" "${OID}" >> "${CLEAN_FILE}" 2>&1 || true
done

echo "[*] Segmented diagnostic dump complete."
