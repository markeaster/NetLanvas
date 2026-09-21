"""
engine/hostname_registry.py

HOSTNAME-1: a single, priority-aware writer for logical_nodes.hostname,
shared by every discovery mechanism that can produce a device's actual
name (as opposed to a generic description or vendor guess). Before this,
each poller wrote hostname independently and unconditionally -- e.g.
os_fingerprinter.py's mDNS sweep could silently overwrite a hostname
that fingerprinter.py had just set from SNMP sysDescr, with no concept
of which signal was more trustworthy. That's still true for device_type/
weld_confidence (a separate, existing anti-clobber mechanism in
fingerprinter.py's update_device_fingerprint -- not touched here), but
hostname needed its own protection.

Priority order (highest wins, ties keep the existing value untouched
rather than re-write it): SNMP sysName is an admin-configured name on
the device itself, LLDP sysName is the same signal relayed by a
neighboring switch, mDNS/NetBIOS are self-announced names via a
discovery protocol, and passive DHCP hostname sniffing is the weakest
authoritative signal (a client-supplied hint, not necessarily even
validated by the DHCP server) but still meaningfully better than no
name at all -- hence still ranked above the FALLBACK tier used for the
old "sysDescr or vendor or Unknown Device" guesswork.
"""
import sqlite3

PRIORITY_SNMP_SYSNAME = 50
PRIORITY_LLDP_SYSNAME = 40
PRIORITY_MDNS = 30
PRIORITY_NETBIOS = 20
PRIORITY_DHCP = 10
PRIORITY_FALLBACK = 0

# Values that come back from real devices/protocols but carry no actual
# identifying information -- never worth writing, and never worth
# raising a device's hostname_source_priority floor over, since a
# later, genuinely-empty response from a WEAKER mechanism shouldn't
# block a stronger mechanism from ever overwriting this junk.
_JUNK_VALUES = {"", "unknown device", "unknown", "n/a", "none", "localhost"}

# DNS full-name limit -- generous for what's really just a display
# label, but bounds how much a hostile/malformed response (DHCP option
# 12/81 is client-supplied and never validated by anything upstream of
# this) can shove into the DB or UI.
_MAX_HOSTNAME_LENGTH = 253


def is_usable_hostname(value) -> bool:
    if not value:
        return False
    v = value.strip()
    if not v or v.lower() in _JUNK_VALUES:
        return False
    if len(v) > _MAX_HOSTNAME_LENGTH:
        return False
    # Reject control characters (incl. \n/\r/\t) -- every caller of this
    # gate eventually f-string-interpolates the hostname into a log
    # line, and a client-supplied value (DHCP hostname, NetBIOS/mDNS
    # response) is otherwise a direct log-injection vector.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in v):
        return False
    return True


def set_hostname_by_node_id(cursor: sqlite3.Cursor, node_id: int, hostname: str, priority: int) -> bool:
    """
    Writes hostname to a specific logical_nodes row IF this priority is
    >= whatever priority currently holds that field (higher or equal
    tiers may refresh/confirm; lower tiers are silently ignored -- not
    an error, just deference to a better-known name). Returns True if
    the write happened.
    """
    if not is_usable_hostname(hostname):
        return False
    cursor.execute("SELECT hostname_source_priority FROM logical_nodes WHERE id = ?", (node_id,))
    row = cursor.fetchone()
    if row is None:
        return False
    current_priority = row[0] or 0
    if priority < current_priority:
        return False
    cursor.execute(
        "UPDATE logical_nodes SET hostname = ?, hostname_source_priority = ? WHERE id = ?",
        (hostname.strip(), priority, node_id),
    )
    return True


def set_hostname_by_mac(cursor: sqlite3.Cursor, mac_address: str, hostname: str, priority: int) -> bool:
    """Same as set_hostname_by_node_id, resolved via a MAC's current node_id. False if the MAC isn't unified to a node yet."""
    if not is_usable_hostname(hostname):
        return False
    cursor.execute("SELECT node_id FROM l2_interfaces WHERE mac_address = ?", (mac_address,))
    row = cursor.fetchone()
    if row is None or row[0] is None:
        return False
    return set_hostname_by_node_id(cursor, row[0], hostname, priority)


def set_hostname_by_ip(cursor: sqlite3.Cursor, ip_address: str, hostname: str, priority: int) -> bool:
    """Same again, resolved via an IP's current l3_bindings -> l2_interfaces -> node_id chain."""
    if not is_usable_hostname(hostname):
        return False
    cursor.execute('''
        SELECT i.node_id FROM l3_bindings b
        JOIN l2_interfaces i ON b.mac_address = i.mac_address
        WHERE b.ip_address = ? AND i.node_id IS NOT NULL
    ''', (ip_address,))
    row = cursor.fetchone()
    if row is None:
        return False
    return set_hostname_by_node_id(cursor, row[0], hostname, priority)
