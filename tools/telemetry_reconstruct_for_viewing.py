#!/usr/bin/env python3
"""
telemetry_reconstruct_for_viewing.py

Converts a stored Community Telemetry submission's db.json (the format
telemetry-submit.php writes to /var/netlanvas-telemetry/ on the
webhost, or a quarantined rejection under its quarantine/ subdir) into
a real network_YYYYMMDD_HHMMSS.db that the Time Machine UI can open.

Why this exists: the telemetry payload's mac/ip fields are
DELIBERATELY not valid addresses -- sanitizer.py masks them with
literal asterisks (e.g. "192.168.**1.1", "AA:BB:CC:DD:**:*E") so a
fuzzed value is never mistaken for a real one. That's correct for the
pipeline's actual purpose, but it means the raw payload can't be
loaded into the app's own UI as-is: anything that validates, sorts, or
links on IP/MAC syntax chokes on the literal '*' characters. This
script reverses JUST that masking -- not the anonymization itself --
so the result is syntactically valid and browsable while still never
exposing anything the fuzzing was meant to hide.

Transform (deterministic, same input -> same output every run):
  - MAC "AA:BB:CC:DD:**:*E" -> "AA:BB:CC:DD:00:0E"
    The 4 kept octets and the 1 real nibble are untouched (already
    real device/vendor-identifying data per the design); the masked
    positions become literal zeros. Fixed-width by construction (the
    mask is always exactly "**:*X"), so zero-fill is always valid
    hex -- no edge case here.
  - IP "192.168.**N.X" -> "192.168.N.X"
    "10.**A.**B.X" / "172.**A.**B.X" -> "10.A.B.X" / "172.A.B.X"
    The asterisks are STRIPPED, not zero-replaced -- N/A/B are
    already plain small integers once the '*' prefix is gone.
    Zero-replacing instead (e.g. "**1" -> "001") would produce a
    leading-zero octet, which Python's own ipaddress module (and
    plenty of other strict parsers) rejects outright as an
    octal-ambiguity hazard, and breaks structurally the moment an
    index reaches two digits ("**12" -> "0012", a malformed 4-char
    octet). Stripping has neither problem.
  - "pub.lic.ip.N" -> "203.0.113.N % 256"
    Mapped into 203.0.113.0/24 (RFC 5737 TEST-NET-3) -- reserved
    for documentation/example use, guaranteed to never be a real
    routable address, so a public IP (the one field the pipeline
    never transmits at all) stays genuinely un-exposed while still
    rendering as a normal-looking address.
  - hostname -> "{vendor} {device_type}" (e.g. "Sonos, Inc. Endpoint")
    The real hostname isn't recoverable from its scrambled form, and
    inventing a plausible-looking name would be actively misleading.
    vendor/device_type are the two fields the pipeline does NOT
    fuzz, so this labels each device from data that's actually real,
    instead of either gibberish or a fabrication.

Anything that doesn't match one of the above shapes (null, already
a plain value, or an unrecognized format) passes through unchanged
rather than erroring -- this script is a display aid, not a validator;
a submission that failed cross-validation for carrying genuinely
malformed data should still convert without crashing.

Usage:
    python3 telemetry_reconstruct_for_viewing.py <input_db.json> <output_network.db>

Schema matches engine/database.py's init_db() + apply_migrations() for
the tables payload_builder.py's own device query touches
(logical_nodes/l2_interfaces/l3_bindings/network_vlans) plus the other
core tables as empty-but-present, so the app's other usual queries
against an archive don't hit a missing-table error.
"""
import json
import re
import sqlite3
import sys

_MAC_RE = re.compile(r'^([0-9A-F]{2}):([0-9A-F]{2}):([0-9A-F]{2}):([0-9A-F]{2}):\*\*:\*([0-9A-F])$', re.I)
_IP_192_RE = re.compile(r'^192\.168\.\*\*(\d+)\.(\d+)$')
_IP_10_172_RE = re.compile(r'^(10|172)\.\*\*(\d+)\.\*\*(\d+)\.(\d+)$')
_IP_PUBLIC_RE = re.compile(r'^pub\.lic\.ip\.(\d+)$')


def reconstruct_mac(mac):
    if not mac:
        return mac
    m = _MAC_RE.match(mac.strip())
    if not m:
        return mac
    g1, g2, g3, g4, nibble = m.groups()
    return f"{g1}:{g2}:{g3}:{g4}:00:0{nibble}".upper()


def reconstruct_ip(ip):
    if not ip:
        return ip
    ip = ip.strip()

    m = _IP_192_RE.match(ip)
    if m:
        idx, last = m.groups()
        return f"192.168.{int(idx) % 256}.{last}"

    m = _IP_10_172_RE.match(ip)
    if m:
        prefix, idx2, idx3, last = m.groups()
        return f"{prefix}.{int(idx2) % 256}.{int(idx3) % 256}.{last}"

    m = _IP_PUBLIC_RE.match(ip)
    if m:
        (idx,) = m.groups()
        return f"203.0.113.{int(idx) % 256}"

    return ip


def build(src_json_path, out_db_path):
    with open(src_json_path) as f:
        data = json.load(f)

    conn = sqlite3.connect(out_db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA foreign_keys = ON;")

    cur.execute('''CREATE TABLE IF NOT EXISTS logical_nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT, device_type TEXT, weld_confidence INTEGER DEFAULT 0, site_id TEXT, os_family TEXT, hostname_source_priority INTEGER NOT NULL DEFAULT 0)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS l2_interfaces (mac_address TEXT PRIMARY KEY, node_id INTEGER, vendor TEXT, chassis_mac BOOLEAN DEFAULT 0, is_virtual BOOLEAN DEFAULT 0, wireless_ssid TEXT, FOREIGN KEY(node_id) REFERENCES logical_nodes(id) ON DELETE CASCADE)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS l3_bindings (ip_address TEXT PRIMARY KEY, mac_address TEXT, vlan_id INTEGER, discovery_source TEXT, is_public BOOLEAN DEFAULT 0, is_ghost BOOLEAN DEFAULT 0, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, http_header TEXT, FOREIGN KEY(mac_address) REFERENCES l2_interfaces(mac_address) ON DELETE CASCADE)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS endpoint_locations (mac_address TEXT PRIMARY KEY, switch_ip TEXT, local_port TEXT, local_port_name TEXT, link_speed TEXT, vlan_id INTEGER, is_ambiguous BOOLEAN DEFAULT 0, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS network_vlans (vlan_id INTEGER PRIMARY KEY, vlan_name TEXT, ui_color TEXT, is_admin_named BOOLEAN DEFAULT 0)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS infrastructure_links (id INTEGER PRIMARY KEY AUTOINCREMENT, local_switch_ip TEXT NOT NULL, local_port INTEGER NOT NULL, local_port_name TEXT, link_speed TEXT, remote_system_name TEXT, vlan_id INTEGER, is_ambiguous BOOLEAN DEFAULT 0, last_mapped DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(local_switch_ip, local_port))''')
    cur.execute('''CREATE TABLE IF NOT EXISTS device_fingerprints (mac_address TEXT PRIMARY KEY, snmp_sysdescr TEXT, snmp_sysobjectid TEXT, banner TEXT, last_updated DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(mac_address) REFERENCES l2_interfaces(mac_address) ON DELETE CASCADE)''')
    cur.execute('''CREATE TABLE IF NOT EXISTS device_capabilities (ip_address TEXT PRIMARY KEY, sys_object_id TEXT, working_functions TEXT DEFAULT '', last_successful_poll DATETIME, next_deep_discovery DATETIME)''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_l2_node_id ON l2_interfaces(node_id)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_l3_mac_address ON l3_bindings(mac_address)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_l3_discovery_source ON l3_bindings(discovery_source)')

    received_at = data.get("received_at") or data.get("generated_at")

    seen_macs = set()
    inserted = 0
    for device in data.get("devices", []):
        vendor = device.get("vendor") or "Unknown Vendor"
        device_type = device.get("device_type") or "Device"
        display_hostname = f"{vendor} {device_type}"

        mac = reconstruct_mac(device.get("mac"))
        ip = reconstruct_ip(device.get("ip"))

        cur.execute(
            "INSERT INTO logical_nodes (hostname, device_type, weld_confidence, site_id, os_family) VALUES (?, ?, ?, ?, ?)",
            (display_hostname, device_type, 100, None, device.get("os_family")),
        )
        node_id = cur.lastrowid

        if mac:
            if mac in seen_macs:
                # Rare collision (see module docstring) -- two devices
                # resolved to the same synthetic MAC. Disambiguate by
                # appending the node_id into the last octet's upper
                # nibble rather than silently overwriting one device
                # via INSERT OR REPLACE's PRIMARY KEY semantics.
                mac = mac[:-1] + format(node_id % 16, 'X')
            seen_macs.add(mac)
            cur.execute(
                "INSERT OR REPLACE INTO l2_interfaces (mac_address, node_id, vendor, chassis_mac, is_virtual, wireless_ssid) VALUES (?, ?, ?, ?, ?, ?)",
                (mac, node_id, vendor, 0, int(bool(device.get("is_virtual"))), None),
            )
        if ip:
            # discovery_source MUST be 'LOCAL_ARP_ICMP', not a custom
            # provenance label -- api/server.py's /api/topology handler
            # (SPARSE-2, 2026-09-05) string-matches exactly this value
            # to decide "no FDB/SNMP data exists for this device, wire
            # it straight to the router as its only known parent" --
            # the one real fallback the live app has for a flat,
            # switch-less home network. An earlier version of this
            # script used a custom label here for provenance tracking,
            # which silently failed that match and left every
            # reconstructed archive showing zero graph edges (not a
            # faithful "no topology known" rendering -- genuinely wrong,
            # since the live app WOULD draw these edges for this exact
            # kind of network). Provenance instead lives in the
            # archive_metadata notes set when this archive is
            # registered, not in a field the app reads functionally.
            cur.execute(
                "INSERT OR REPLACE INTO l3_bindings (ip_address, mac_address, vlan_id, discovery_source, is_public, is_ghost, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ip, mac, device.get("vlan_id"), "LOCAL_ARP_ICMP", 0, 0, received_at),
            )
        inserted += 1

    conn.commit()
    conn.close()
    print(f"wrote {out_db_path}: {inserted} devices from instance_id={data.get('instance_id')} generated_at={data.get('generated_at')}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input_db.json> <output_network.db>", file=sys.stderr)
        sys.exit(1)
    build(sys.argv[1], sys.argv[2])
