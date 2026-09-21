"""
pollers/dhcp_sniffer.py

HOSTNAME-1: passive capture of DHCPDISCOVER/DHCPREQUEST broadcasts,
parsing Option 12 (Host Name) and Option 81 (Client FQDN) for the
client-supplied hostname. The most "agnostic" of all five mechanisms --
depends on nothing but the DHCP client's own broadcast traffic, not any
router/DNS/NetBIOS/mDNS support on either end. Inherently limited to
whatever L2 segment(s) netlanvas_core is actually attached to
(network_mode: host) -- the same reach limitation the existing
ARP-based discovery already has, not a new one introduced here.

LICENSE-1: previously used scapy's AsyncSniffer, which pulls in scapy
(GPL v2) -- incompatible with this project's Apache 2.0 license once
open-sourced. DHCP is itself UDP broadcast traffic, so no packet-capture
library is actually needed: a plain SOCK_DGRAM socket bound to port 67
with SO_BROADCAST receives DHCPDISCOVER/REQUEST directly. Confirmed
working against real, generated DHCP traffic on both Linux and Windows
before this replaced the scapy version -- same capture coverage, zero
third-party dependency, zero libpcap/Npcap requirement (scapy's own
capture backend was already logging "No libpcap provider available!"
on macOS PyInstaller builds, so this is also a fix for a real gap
there, not purely a license-driven substitution).

Runs as a long-lived background listener (its own daemon thread)
started once at POLLER boot, not tied to the tick loop -- DHCP
broadcasts are inherently event-driven (a lease request/renewal), not
something worth polling for.
"""
import logging
import os
import socket
import sqlite3
import threading

from engine.hostname_registry import set_hostname_by_mac, is_usable_hostname, PRIORITY_DHCP
from security.rate_limit import is_rate_limited, record_attempt

logger = logging.getLogger("Netlanvas.DHCPSniffer")
# NATIVE-1: same DB_PATH env var config_loader.py already honors, so a
# native/standalone boot (no /app) doesn't need this file at all -- was
# a bare literal before, now consistent with the rest of the codebase.
DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")

_listener_thread = None
_DHCP_MAGIC_COOKIE = bytes([99, 130, 83, 99])

# Every accepted packet opens a fresh SQLite connection and commits on
# this capture thread -- fine for legitimate DHCP traffic (lease
# events are inherently rare), not fine against a flood: any
# unauthenticated device on the L2 segment can emit DHCPDISCOVER
# broadcasts at line rate with no cost to itself. Two independent caps,
# reusing the same primitive the HTTP-facing rate limiter uses: a
# per-MAC cap (legitimate renewals are minutes-to-hours apart, so this
# only ever throttles a repeat/flood from one source) and a global cap
# (bounds worst case even if the flood spoofs a different MAC every
# packet).
_RATE_BUCKET = "dhcp_sniffer"
_PER_MAC_WINDOW_SECONDS = 30
_GLOBAL_WINDOW_SECONDS = 10
_GLOBAL_MAX_PER_WINDOW = 50


def _parse_bootp_dhcp(data: bytes):
    """Manual BOOTP header + DHCP option TLV parse. Same semantics as
    the previous scapy-based version: chaddr for the MAC, Option 12/81
    for the hostname. Returns (mac, hostname) or None if not a usable
    DHCP packet."""
    if len(data) < 240:
        return None
    hlen = data[2]
    chaddr_full = data[28:44]
    chaddr = chaddr_full[: hlen if 0 < hlen <= 16 else 6]
    if not chaddr or chaddr == b"\x00" * len(chaddr):
        return None
    mac = ":".join(f"{b:02x}" for b in chaddr[:6])

    if data[236:240] != _DHCP_MAGIC_COOKIE:
        return None

    options = {}
    i = 240
    while i < len(data):
        opt_type = data[i]
        if opt_type == 255:  # End
            break
        if opt_type == 0:  # Pad
            i += 1
            continue
        if i + 1 >= len(data):
            break
        opt_len = data[i + 1]
        options[opt_type] = data[i + 2 : i + 2 + opt_len]
        i += 2 + opt_len

    hostname = None
    if 12 in options and options[12]:
        hostname = options[12].decode("utf-8", errors="ignore").strip() or None
    elif 81 in options and options[81]:
        # Option 81: flags(1) + rcode1(1) + rcode2(1) + FQDN. Decoded
        # defensively (strip control bytes, take the first label)
        # rather than assume a fixed byte offset for where the name
        # text starts -- same defensive approach the scapy version used.
        raw = options[81][3:] if len(options[81]) > 3 else options[81]
        text = raw.decode("utf-8", errors="ignore")
        cleaned = "".join(ch for ch in text if ch.isprintable())
        name = cleaned.split(".")[0].strip()
        hostname = name or None

    return mac, hostname


def _handle_packet(data: bytes):
    try:
        parsed = _parse_bootp_dhcp(data)
        if parsed is None:
            return
        mac, hostname = parsed
        if not is_usable_hostname(hostname):
            return

        if is_rate_limited("global", _RATE_BUCKET, _GLOBAL_MAX_PER_WINDOW, _GLOBAL_WINDOW_SECONDS):
            return
        if is_rate_limited(mac, _RATE_BUCKET, 1, _PER_MAC_WINDOW_SECONDS):
            return
        # Routine per-packet volume counting, not a security failure --
        # see rate_limit.record_attempt's log_level docstring. DEBUG,
        # not WARNING: ordinary DHCP broadcast traffic on any real
        # network hits this every cycle and isn't worth an admin's
        # attention unless the cap is actually reached (which is_rate_
        # limited above already gates on, returning before this runs).
        record_attempt("global", _RATE_BUCKET, _GLOBAL_WINDOW_SECONDS, log_level=logging.DEBUG)
        record_attempt(mac, _RATE_BUCKET, _PER_MAC_WINDOW_SECONDS, log_level=logging.DEBUG)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        wrote = set_hostname_by_mac(cursor, mac, hostname, PRIORITY_DHCP)
        conn.commit()
        conn.close()
        if wrote:
            logger.info(f'[*] DHCP Sniffer: {mac} -> "{hostname}" (Option 12/81)')
    except Exception as e:
        logger.debug(f"[!] DHCP Sniffer: packet handling error: {e}")


def _listen_loop(sock: socket.socket):
    while True:
        try:
            data, _addr = sock.recvfrom(4096)
        except OSError as e:
            logger.debug(f"[!] DHCP Sniffer: recv error: {e}")
            continue
        _handle_packet(data)


def start_dhcp_sniffer():
    global _listener_thread
    if _listener_thread is not None:
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", 67))
    except OSError as e:
        logger.error(f"[!] DHCP Sniffer: failed to start -- {e}")
        return

    _listener_thread = threading.Thread(target=_listen_loop, args=(sock,), daemon=True)
    _listener_thread.start()
    logger.info("[*] DHCP Sniffer: passive capture started (udp/67, bound broadcast socket).")
