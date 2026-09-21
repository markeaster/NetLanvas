"""
pollers/web_probe.py

WEB-1 (feature request via Report-a-Bug, 2026-09-15, mark@easters.org):
for every known IP, do a best-effort check for a web server on 443
then 80 and record what it says about itself -- powers the Graph UI's
"Open Web Page" context-menu item (see links.html), which only shows
up for a node once this has actually found something there.

Deliberately best-effort and non-destructive: a single short-timeout
HEAD request per port, no redirect following, no auth. A device that
doesn't answer just stays as it was (NULL, or whatever was last
found) -- a failed probe this tick is not evidence there's no longer a
web server there, it's just as likely a busy device or a dropped
packet, so failures never clear a previously-found header.

Runs on the deep-scan cadence (see main.py's stage_web_probe, alongside
device_fingerprinting) rather than every tick -- this is a real,
if brief, outbound connection per device, not a cheap local check like
the hostname sweep's UDP probes.
"""
import asyncio
import logging
import os
import socket
import sqlite3
import ssl

logger = logging.getLogger("Netlanvas.WebProbe")

DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")

_CONNECT_TIMEOUT = 1.2
_MAX_CONCURRENT = 20
_MAX_HEADER_LEN = 200

_SSL_CONTEXT = ssl.create_default_context()
_SSL_CONTEXT.check_hostname = False
_SSL_CONTEXT.verify_mode = ssl.CERT_NONE


async def _probe_one(ip: str, port: int, use_tls: bool) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=_SSL_CONTEXT if use_tls else None),
            timeout=_CONNECT_TIMEOUT,
        )
    except Exception:
        return None

    try:
        writer.write(
            f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetLanvas\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(2048), timeout=_CONNECT_TIMEOUT)
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if not raw:
        return None
    lines = raw.decode(errors="replace").split("\r\n")
    status_line = lines[0].strip() if lines else ""
    if not status_line.startswith("HTTP/"):
        return None

    server = ""
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break

    scheme = "https" if use_tls else "http"
    summary = f"{scheme} | {status_line}"
    if server:
        summary += f" | Server: {server}"
    return summary[:_MAX_HEADER_LEN]


async def _probe_ip(ip: str, sem: asyncio.Semaphore) -> tuple[str, str | None]:
    async with sem:
        result = await _probe_one(ip, 443, use_tls=True)
        if result is None:
            result = await _probe_one(ip, 80, use_tls=False)
        return ip, result


async def run_web_probe():
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip_address FROM l3_bindings WHERE ip_address IS NOT NULL AND is_ghost = 0"
        )
        ips = [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()

    if not ips:
        return

    sem = asyncio.Semaphore(_MAX_CONCURRENT)
    results = await asyncio.gather(*[_probe_ip(ip, sem) for ip in ips])

    found = [(header, ip) for ip, header in results if header is not None]
    if not found:
        logger.debug("[WebProbe] No web servers found this pass.")
        return

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executemany(
            "UPDATE l3_bindings SET http_header = ? WHERE ip_address = ?", found
        )
        conn.commit()
    finally:
        conn.close()

    logger.info(f"[WebProbe] Found {len(found)} web server(s) out of {len(ips)} known IP(s).")
