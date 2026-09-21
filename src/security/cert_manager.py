"""
cert_manager.py

Generates and maintains a self-signed TLS keypair unique to this install.
No certificate or key is ever bundled in the image or the git repository --
this module is the ONLY place a key is created, and it only runs at
container boot, writing into a persisted volume.

Zero-config design: netlanvas_api runs on the isolated netlanvas_internal
bridge network, so it cannot see the host's real LAN-facing IP on its
own. That address is detected instead by netlanvas_core (which runs on
network_mode: host and genuinely can see it) and published via Redis --
see main.py's detect_host_public_ips()/stage_publish_host_identity() and
the API_VIEWER boot sequence that reads it. This module takes that value
as a plain string parameter (extra_sans_csv) rather than fetching it
itself, keeping this module synchronous and free of a Redis dependency.

NETLANVAS_TLS_EXTRA_SANS remains available as an optional manual
override/addition (e.g. a custom DNS name) for edge cases, but nothing
in the normal boot path requires it to be set.
"""

import ipaddress
import logging
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

logger = logging.getLogger("netlanvas.cert_manager")

# All of these are overridable via environment variables — nothing here
# is a magic number baked into the module.
CERT_DIR = Path(os.environ.get("NETLANVAS_TLS_DIR", "/app/tls"))
KEY_PATH = CERT_DIR / os.environ.get("NETLANVAS_TLS_KEY_FILENAME", "server.key")
CERT_PATH = CERT_DIR / os.environ.get("NETLANVAS_TLS_CERT_FILENAME", "server.crt")
CERT_VALIDITY_DAYS = int(os.environ.get("NETLANVAS_TLS_VALIDITY_DAYS", "825"))
RENEW_WITHIN_DAYS = int(os.environ.get("NETLANVAS_TLS_RENEW_WITHIN_DAYS", "30"))
CERT_COMMON_NAME = os.environ.get("NETLANVAS_TLS_CN", "netlanvas.local")

# Optional manual override/addition, e.g. "netlanvas.local,10.0.0.5".
# Not required for normal operation -- see module docstring.
EXTRA_SANS_ENV = os.environ.get("NETLANVAS_TLS_EXTRA_SANS", "")


def _detect_container_ips() -> list[str]:
    """
    Enumerate this container's own IPv4 addresses. Harmless to include
    but NOT sufficient on its own -- see module docstring for why the
    host's real LAN IP has to arrive via extra_sans_csv instead.
    """
    ips: set[str] = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except socket.gaierror:
        logger.warning("Could not resolve local hostname for SAN detection.")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            ips.add(s.getsockname()[0])
    except OSError:
        pass

    return sorted(ips)


def detect_own_lan_ip() -> str | None:
    """
    NATIVE-12/HOTFIX (2026-09-07): main.py's NETLANVAS_MODE == "native"
    boot branch has imported this since it was merged in, but this
    function was only ever ported to native-port's cert_manager.py --
    main branch's copy never got it, which meant EVERY main.py import
    unconditionally NameErrored at module load (not just when native
    mode actually runs), crashing netlanvas_core/netlanvas_api outright
    the moment this main.py version got deployed. Same UDP-connect
    trick _detect_container_ips() already uses for defense-in-depth SAN
    coverage, exposed as its own function for native mode's remote-
    access toggle. No packet actually leaves the machine (UDP is
    connectionless -- this just asks the OS routing table which local
    interface WOULD be used to reach 1.1.1.1). Returns None if
    genuinely undetectable (e.g. no network connectivity at all).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def _split_ips_and_hostnames(csv: str) -> tuple[set[str], set[str]]:
    """
    Splits a comma-separated string into (ip_strings, hostnames) -- each
    entry is tried as an IP address first, treated as a DNS hostname
    otherwise.
    """
    ip_strings: set[str] = set()
    hostnames: set[str] = set()
    for entry in csv.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            ipaddress.ip_address(entry)
            ip_strings.add(entry)
        except ValueError:
            hostnames.add(entry)
    return ip_strings, hostnames


def _externally_provided_sans(extra_sans_csv: str) -> tuple[set[str], set[str]]:
    """
    SANs that come from OUTSIDE this container's own self-detection --
    the real host address netlanvas_core publishes, plus the optional
    NETLANVAS_TLS_EXTRA_SANS manual override. These are the only ones a
    real browser could ever actually be pointed at (Caddy, the sole TLS
    terminator -- see Caddyfile's `tls` directive -- is always reached
    via the published host address, never via this container's own
    internal bridge-network IP), so they're the only ones worth
    reissuing over when they change. See _sans_have_drifted (CERT-1).
    """
    ips: set[str] = set()
    hostnames: set[str] = set()
    for csv in (EXTRA_SANS_ENV, extra_sans_csv or ""):
        csv_ips, csv_hostnames = _split_ips_and_hostnames(csv)
        ips |= csv_ips
        hostnames |= csv_hostnames
    return ips, hostnames


def _desired_sans(extra_sans_csv: str) -> tuple[set[str], set[str]]:
    """
    Full SAN set actually written into a newly issued certificate --
    auto-detected container IPs plus every externally-provided address
    (see _externally_provided_sans). The self-detected addresses are
    included here for defense-in-depth on any direct-to-container
    access path, but deliberately excluded from the drift check itself.
    """
    ips = set(_detect_container_ips())
    ext_ips, ext_hostnames = _externally_provided_sans(extra_sans_csv)
    ips |= ext_ips
    return ips, set(ext_hostnames)


def _existing_sans(cert: x509.Certificate) -> tuple[set[str], set[str]]:
    """Extracts (ip_set, hostname_set) from an already-issued certificate."""
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return set(), set()

    ips = {str(v) for v in san_ext.value.get_values_for_type(x509.IPAddress)}
    hostnames = set(san_ext.value.get_values_for_type(x509.DNSName))
    return ips, hostnames


def _generate_new_cert(extra_sans_csv: str) -> None:
    logger.info("Generating new self-signed TLS keypair for this install...")

    CERT_DIR.mkdir(parents=True, exist_ok=True)

    private_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CERT_COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetLanvas Self-Hosted Instance"),
    ])

    now = datetime.now(timezone.utc)
    ip_set, hostname_set = _desired_sans(extra_sans_csv)

    san_entries: list[x509.GeneralName] = [x509.DNSName("localhost")]
    san_entries += [x509.DNSName(h) for h in sorted(hostname_set)]
    for ip_str in sorted(ip_set):
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        except ValueError:
            continue

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                key_agreement=True,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    certificate = cert_builder.sign(private_key, hashes.SHA256())

    KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    KEY_PATH.chmod(0o600)

    CERT_PATH.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    CERT_PATH.chmod(0o644)

    logger.info(
        "New certificate written to %s (valid %s days). SAN IPs: %s, hostnames: %s",
        CERT_PATH, CERT_VALIDITY_DAYS, sorted(ip_set), sorted(hostname_set),
    )


def _load_existing_cert() -> x509.Certificate | None:
    if not (KEY_PATH.exists() and CERT_PATH.exists()):
        return None
    try:
        return x509.load_pem_x509_certificate(CERT_PATH.read_bytes())
    except (ValueError, OSError) as exc:
        logger.error("Existing cert at %s is unreadable/corrupt: %s", CERT_PATH, exc)
        return None


def _needs_renewal(cert: x509.Certificate) -> bool:
    expires = cert.not_valid_after_utc
    return (expires - datetime.now(timezone.utc)) < timedelta(days=RENEW_WITHIN_DAYS)


def _sans_have_drifted(cert: x509.Certificate, extra_sans_csv: str) -> bool:
    """
    True if an address a real browser could actually be pointed at is
    no longer covered by the existing cert -- e.g. netlanvas_core has
    now published a host IP that wasn't available yet on a previous
    boot, or the host's IP changed. This is what makes address
    detection self-healing across restarts without ever needing a
    manual step.

    CERT-1: deliberately checks only _externally_provided_sans (never
    this container's own self-detected bridge-network IP, which Docker
    doesn't guarantee stays the same across a container recreation) --
    and checks SUBSET, not equality, since the existing cert legitimately
    also carries whatever self-detected IP _generate_new_cert() added
    last time, which was never part of this comparison to begin with.
    Comparing for exact equality against that larger existing set would
    report "drifted" on every single boot, even when nothing externally
    meaningful changed -- exactly the bug this fixes.
    """
    desired_ips, desired_hostnames = _externally_provided_sans(extra_sans_csv)
    existing_ips, existing_hostnames = _existing_sans(cert)
    return not desired_ips.issubset(existing_ips) or not desired_hostnames.issubset(existing_hostnames)


def fingerprint_sha256(cert: x509.Certificate | None = None) -> str:
    cert = cert or _load_existing_cert()
    if cert is None:
        raise FileNotFoundError("No certificate present to fingerprint.")
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def ensure_certificate(extra_sans_csv: str = "") -> str:
    """
    Idempotent entry point called at every boot. Generates a cert on first
    run, reissues near expiry, and ALSO reissues whenever the desired SAN
    set no longer matches what's already on disk -- see
    _sans_have_drifted. Returns the SHA-256 fingerprint so the caller can
    log/display it.
    """
    existing = _load_existing_cert()

    if existing is None:
        _generate_new_cert(extra_sans_csv)
    elif _needs_renewal(existing):
        logger.info("Existing certificate expires within %s days — reissuing.", RENEW_WITHIN_DAYS)
        _generate_new_cert(extra_sans_csv)
    elif _sans_have_drifted(existing, extra_sans_csv):
        logger.info("Host address(es) have changed since this certificate was issued — reissuing.")
        _generate_new_cert(extra_sans_csv)
    else:
        logger.info("Existing certificate is valid and up to date until %s — no action needed.", existing.not_valid_after_utc)

    fp = fingerprint_sha256()
    logger.info("=" * 70)
    logger.info("TLS CERTIFICATE FINGERPRINT (SHA-256) — verify this in your browser")
    logger.info("before accepting the certificate warning:")
    logger.info("  %s", fp)
    logger.info("=" * 70)
    return fp


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ensure_certificate()
