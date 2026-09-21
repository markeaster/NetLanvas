"""
pollers/hostname_discovery.py

HOSTNAME-1: two active, protocol-generic hostname-discovery mechanisms
that don't depend on a device advertising anything beyond baseline
mDNS/NetBIOS responder compliance -- unlike os_fingerprinter.py's
existing mDNS sweep, which only catches devices publishing one of a
curated list of IoT/media service types.

1. Reverse mDNS PTR lookup (<reversed-ip>.in-addr.arpa over
   224.0.0.251:5353) -- confirmed live against a test lab's own
   containers: works against stock avahi-daemon with NO special config
   (publish-workstation left at its default "no"), since answering a
   PTR-for-my-own-address query is baseline mDNS responder behavior,
   not a service announcement. A host running no mDNS responder at all
   stays correctly silent -- confirmed too (umgd-ep2, no avahi
   installed, produces no response, not a false name).

2. NetBIOS Name Service NBSTAT query (UDP 137) -- the standard
   "wildcard" node-status query, catches Windows/SMB devices that
   register a NetBIOS name regardless of DNS/router configuration.
   Filters to unique (non-group) names with the workstation suffix
   (0x00), since a raw response can also include the device's Windows
   Workgroup/Domain name as a group entry -- that's not a hostname.

Both are cheap, best-effort UDP probes (short timeout, no retries) --
run every fast tick alongside the existing mDNS/SSDP sweep, not gated
behind the deep-scan cadence like SNMP-based fingerprinting.
"""
import asyncio
import logging
import os
import socket
import sqlite3
import struct

from engine.hostname_registry import set_hostname_by_ip, PRIORITY_MDNS, PRIORITY_NETBIOS
from engine.auto_discovery import bind_socket_to_scan_interface

logger = logging.getLogger("Netlanvas.HostnameDiscovery")
DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")


def _mdns_reverse_lookup_one(ip: str, timeout: float = 1.5) -> str | None:
    try:
        parts = ip.split(".")[::-1]
        qname = ".".join(parts) + ".in-addr.arpa"
        labels = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
        header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
        question = labels + struct.pack(">HH", 12, 1)  # QTYPE=PTR, QCLASS=IN
        pkt = header + question

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_socket_to_scan_interface(s)
        # Critical: without this, this socket receives its OWN
        # multicast query back as if it were a response (confirmed live
        # -- every lookup was silently matching on the loopback copy
        # first, and since that never equals the target IP the whole
        # probe just fell through to nothing). Disabling loopback means
        # the only thing that can arrive is a genuine reply.
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        try:
            s.bind(("", 5353))
        except OSError:
            s.bind(("", 0))
        mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.sendto(pkt, ("224.0.0.251", 5353))

        import time
        deadline_at = time.monotonic() + timeout
        while True:
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                return None
            s.settimeout(remaining)
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                return None
            if addr[0] != ip:
                continue
            name = _parse_ptr_hostname(data)
            if name:
                return name
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _parse_ptr_hostname(data: bytes) -> str | None:
    """
    Minimal DNS-message PTR-answer parser -- pulls the first label
    sequence out of the answer's RDATA and returns it as "name.local"
    (stripped of the trailing empty label / root). Deliberately doesn't
    attempt full message parsing (compression pointers into the
    question section, multiple answers) -- one PTR answer is all this
    query ever expects back.
    """
    try:
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount < 1:
            return None
        # These responses come back with QDCOUNT=0 (confirmed live --
        # no echoed question section), so the answer starts right after
        # the 12-byte header, not after a question that isn't there.
        pos = 12
        # Answer: NAME (may be a compression pointer, 2 bytes with top bits 11)
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
        pos += 2 + 2 + 4  # TYPE + CLASS + TTL
        rdlength = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        rdata_end = pos + rdlength
        labels = []
        while pos < rdata_end and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:
                ptr = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
                labels.extend(_read_labels_at(data, ptr))
                break
            length = data[pos]
            pos += 1
            labels.append(data[pos:pos + length].decode("utf-8", errors="ignore"))
            pos += length
        if not labels:
            return None
        full = ".".join(labels)
        # Only the first label is the actual hostname (the rest is the
        # "local" domain suffix) -- return just that, matching how the
        # rest of the codebase already treats short hostnames elsewhere.
        return labels[0] if labels[0] else None
    except Exception:
        return None


def _read_labels_at(data: bytes, pos: int) -> list[str]:
    labels = []
    seen = 0
    while pos < len(data) and data[pos] != 0 and seen < 20:
        if data[pos] & 0xC0 == 0xC0:
            pos = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
            seen += 1
            continue
        length = data[pos]
        pos += 1
        labels.append(data[pos:pos + length].decode("utf-8", errors="ignore"))
        pos += length
        seen += 1
    return labels


_NBSTAT_WILDCARD_NAME = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"


def _netbios_lookup_one(ip: str, timeout: float = 1.0) -> str | None:
    try:
        header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
        question = _NBSTAT_WILDCARD_NAME + struct.pack(">HH", 0x0021, 0x0001)  # QTYPE=NBSTAT, QCLASS=IN
        pkt = header + question

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 137))
        # Same spoofing concern as the mDNS lookup above: this socket
        # isn't connect()-ed, so any host on the segment can race a
        # forged reply to our ephemeral port. Verify the sender is
        # actually the IP we queried before trusting the name in it.
        import time
        deadline_at = time.monotonic() + timeout
        while True:
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                return None
            s.settimeout(remaining)
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                return None
            if addr[0] != ip:
                continue
            return _parse_nbstat_name(data)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def _parse_nbstat_name(data: bytes) -> str | None:
    try:
        # NBSTAT responses come back with QDCOUNT=0 (confirmed live --
        # no echoed question section at all, unlike a normal DNS
        # response), so the answer starts immediately after the
        # 12-byte header, not after a question we never see repeated.
        pos = 12
        # Answer: NAME (full encoded wildcard here, could in principle
        # be a compression pointer) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            pos += len(_NBSTAT_WILDCARD_NAME)
        pos += 2 + 2 + 4
        rdlength = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        num_names = data[pos]
        pos += 1
        for _ in range(num_names):
            raw_name = data[pos:pos + 15]
            suffix = data[pos + 15]
            flags = struct.unpack(">H", data[pos + 16:pos + 18])[0]
            pos += 18
            is_group = bool(flags & 0x8000)
            if is_group or suffix != 0x00:
                continue
            name = raw_name.decode("ascii", errors="ignore").strip()
            if name:
                return name
        return None
    except Exception:
        return None


async def run_hostname_discovery_sweep():
    """
    Every fast tick: for every currently-known IP, try both mechanisms
    (bounded concurrency, short per-probe timeout) and write any usable
    result through the shared priority-aware hostname writer -- never
    directly UPDATEs logical_nodes itself.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT ip_address FROM l3_bindings WHERE ip_address IS NOT NULL")
    ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    if not ips:
        return

    semaphore = asyncio.Semaphore(20)
    loop = asyncio.get_running_loop()

    async def probe(ip):
        async with semaphore:
            mdns_name, nb_name = await asyncio.gather(
                loop.run_in_executor(None, _mdns_reverse_lookup_one, ip),
                loop.run_in_executor(None, _netbios_lookup_one, ip),
            )
            return ip, mdns_name, nb_name

    results = await asyncio.gather(*(probe(ip) for ip in ips), return_exceptions=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    mdns_hits = 0
    nb_hits = 0
    for r in results:
        if isinstance(r, Exception):
            continue
        ip, mdns_name, nb_name = r
        if mdns_name and set_hostname_by_ip(cursor, ip, mdns_name, PRIORITY_MDNS):
            mdns_hits += 1
        if nb_name and set_hostname_by_ip(cursor, ip, nb_name, PRIORITY_NETBIOS):
            nb_hits += 1
    conn.commit()
    conn.close()

    if mdns_hits or nb_hits:
        logger.info(f"[*] Hostname Discovery: {mdns_hits} via reverse-mDNS, {nb_hits} via NetBIOS NBSTAT.")
