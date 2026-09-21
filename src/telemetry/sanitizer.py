"""
sanitizer.py

The fuzzing primitives for the Community Telemetry Pipeline (see
netlanvas-telemetry-pipeline-v6, Drive). Single source of truth for
turning real MAC/hostname/IP/VLAN-name values into anonymized-but-
consistent fuzzed equivalents -- called by both payload_builder.py (the
structured per-device payload) and log_sampler.py (the sanitized log
sample), which is what guarantees a given device gets the same fuzzed
identity in both artifacts. That consistency is load-bearing: the
server-side payload/log cross-validation (submission handshake, see the
design doc §6) depends on it to tell a genuine submission from a
fabricated one.

TELEMETRY_SALT is a per-instance secret (random, generated once,
encrypted at rest via security.credential_vault, never transmitted) that
drives every hash-based fuzzing function below. Each field type uses a
distinct HMAC domain-separation prefix so that knowing one instance's
fuzzed output for one field type reveals nothing about how the same
salt fuzzes a different field type (same reasoning as this project's
F14 finding: authKey/privKey must not be derived identically from one
shared secret).

IP fuzzing uses a different mechanism -- a per-instance sequential
mapping table (TELEMETRY_IP_MAPPING), not a hash -- because the design
calls for topology trends to stay visible over time (same real subnet
always gets the same fuzzed index across all of an instance's
submissions), which a stateless hash could give too, but a small
sequential table is simpler to reason about and matches how the user
described the scheme (Subnet_A/Subnet_B-style labels embedded directly
in the fuzzed address).
"""

import hashlib
import hmac
import ipaddress
import json
import re
import secrets

from engine import config_loader
from security import credential_vault

_SALT_SETTING_KEY = "TELEMETRY_SALT"
_IP_MAPPING_SETTING_KEY = "TELEMETRY_IP_MAPPING"

# Domain-separation contexts -- see module docstring. Never reuse one
# context prefix for two different field types.
_CTX_MAC = b"MAC:"
_CTX_HOSTNAME = b"HOSTNAME:"
_CTX_VLAN_NAME = b"VLAN:"

# The only punctuation _structural_fuzz() passes through unchanged --
# an intentionally narrow allowlist (not "anything non-alphanumeric"),
# since the input can be attacker-influenceable raw text (a hostname
# set via DHCP/mDNS/NetBIOS). See _structural_fuzz's else-branch
# comment for the incident this closed.
_SAFE_PASSTHROUGH_CHARS = set("-._ ")


_salt_cache: bytes | None = None


def _get_salt(config: "config_loader.ConfigLoader") -> bytes:
    """
    Returns this instance's TELEMETRY_SALT as raw bytes, generating and
    persisting a fresh one (encrypted at rest, CSPRNG-sourced) on first
    use. Never logged, never included in any outbound payload.

    Cached in-process after first read -- this salt never changes once
    generated, and callers (fuzz_mac/fuzz_hostname/etc.) are invoked
    once per field per device, so an uncached version would mean one
    decrypt-and-DB-read per field on every device in a payload build.
    """
    global _salt_cache
    if _salt_cache is not None:
        return _salt_cache

    stored = config._get_setting(_SALT_SETTING_KEY)
    if stored:
        _salt_cache = _decode_salt(stored)
        return _salt_cache

    raw = secrets.token_bytes(32)
    config._set_setting(
        _SALT_SETTING_KEY,
        _encode_salt(raw),
        description="Per-instance secret salt driving telemetry field fuzzing. Never transmitted.",
    )
    _salt_cache = raw
    return raw


def _encode_salt(raw: bytes) -> str:
    import base64

    return credential_vault.encrypt_password(base64.b64encode(raw).decode("ascii"))


def _decode_salt(stored_value: str) -> bytes:
    import base64

    return base64.b64decode(credential_vault.decrypt_password(stored_value))


def _hmac_token(salt: bytes, context: bytes, value: str, length: int) -> str:
    """Domain-separated HMAC-SHA256, truncated to `length` hex chars."""
    digest = hmac.new(salt, context + value.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:length]


# --------------------------------------------------------------------
# MAC address fuzzing
# --------------------------------------------------------------------

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})$")


def fuzz_mac(config: "config_loader.ConfigLoader", mac: str) -> str:
    """
    Keeps the first 4 octets (vendor/product-line identification,
    32 bits -- more than the standard 3-octet OUI, per the design's
    explicit "least significant bits" fuzzing directive). The last 2
    octets are rendered as "**:*X" -- literal asterisks, not just a
    plain-looking hex pair -- so the value reads as obviously fuzzed at
    a glance rather than looking like it could be a real MAC (confirmed
    2026-09-03: a plain hex-looking replacement "didn't look fuzzed").
    X is a single hex nibble derived from the same per-instance-salted
    hash as before (16 buckets) -- enough to tell two different real
    MACs apart in the fuzzed output without pretending to be a real,
    precise value.
    """
    m = _MAC_RE.match(mac.strip())
    if not m:
        return mac  # not MAC-shaped; caller's problem, not ours to guess at

    salt = _get_salt(config)
    kept = ":".join(m.group(1, 2, 3, 4))
    nibble = _hmac_token(salt, _CTX_MAC, mac.upper(), length=1)
    return f"{kept}:**:*{nibble}".upper()


# --------------------------------------------------------------------
# Hostname / VLAN-name fuzzing -- structurally-similar fuzzed token
# --------------------------------------------------------------------

def _structural_fuzz(salt: bytes, context: bytes, value: str) -> str:
    """
    Replaces `value` with a same-length, same-character-shape token
    derived from a domain-separated HMAC -- preserves naming-convention
    statistics (length, whether it's all-lowercase/has-digits/has-
    dashes) without leaking the real string. Character-by-character:
    each output character is drawn from the same "class" (lowercase
    letter / digit / other) as the corresponding input character,
    keyed off successive bytes of one HMAC digest (re-hashed if the
    value is longer than one digest's worth of bytes).
    """
    if not value:
        return value

    out_chars = []
    digest_bytes = b""
    counter = 0
    for ch in value:
        while len(digest_bytes) <= len(out_chars):
            digest_bytes += hmac.new(salt, context + value.encode("utf-8") + counter.to_bytes(2, "big"), hashlib.sha256).digest()
            counter += 1
        b = digest_bytes[len(out_chars)]

        if ch.isdigit():
            out_chars.append(str(b % 10))
        elif ch.islower():
            out_chars.append(chr(ord("a") + (b % 26)))
        elif ch.isupper():
            out_chars.append(chr(ord("A") + (b % 26)))
        elif ch in _SAFE_PASSTHROUGH_CHARS:
            # Only these carry naming-CONVENTION information (e.g.
            # "kebab-case") that isn't identity-revealing on its own --
            # fuzzing them would just turn "office-printer" into
            # unreadable noise for zero extra privacy benefit.
            out_chars.append(ch)
        else:
            # Everything else -- quotes, angle brackets, semicolons,
            # parens, backslashes, control characters -- is NOT passed
            # through, even though the original "kept as-is" comment
            # said all punctuation was safe. It wasn't: a raw hostname
            # is attacker-influenceable (DHCP option 12, mDNS, NetBIOS
            # all let an untrusted device on the LAN set arbitrary
            # bytes here), so passing exotic punctuation through
            # unfuzzed would let something like <script> or
            # '; DROP TABLE-- survive this "sanitizer" verbatim. Found
            # 2026-09-03 while building the server-side malicious-
            # content scan as a second, independent layer -- fixed
            # here at the source instead of only papering over it
            # downstream. Fuzzed to a lowercase letter, same as the
            # digit/letter branches above, so the output stays
            # readable and hostname-shaped without ever emitting the
            # original byte.
            out_chars.append(chr(ord("a") + (b % 26)))

    return "".join(out_chars)


def fuzz_hostname(config: "config_loader.ConfigLoader", hostname: str) -> str:
    salt = _get_salt(config)
    return _structural_fuzz(salt, _CTX_HOSTNAME, hostname)


def fuzz_vlan_name(config: "config_loader.ConfigLoader", vlan_name: str) -> str:
    salt = _get_salt(config)
    return _structural_fuzz(salt, _CTX_VLAN_NAME, vlan_name)


# --------------------------------------------------------------------
# IP address fuzzing -- per-instance sequential octet mapping
# --------------------------------------------------------------------

_EMPTY_IP_MAPPING = {"octet3_192168": {}, "octet2_10_172": {}, "octet3_10_172": {}, "public": {}}


def _load_ip_mapping(config: "config_loader.ConfigLoader") -> dict:
    stored = config._get_setting(_IP_MAPPING_SETTING_KEY)
    if not stored:
        return dict(_EMPTY_IP_MAPPING)
    try:
        loaded = json.loads(stored)
        # Merge against the empty template so a bucket added in a later
        # version of this module (or missing from an older stored blob)
        # doesn't KeyError -- existing buckets/values are preserved.
        return {**_EMPTY_IP_MAPPING, **loaded}
    except (ValueError, TypeError):
        return dict(_EMPTY_IP_MAPPING)


def _save_ip_mapping(config: "config_loader.ConfigLoader", mapping: dict) -> None:
    config._set_setting(
        _IP_MAPPING_SETTING_KEY,
        json.dumps(mapping),
        description="Per-instance sequential-index mapping for fuzzed subnet octets in telemetry. Not sensitive on its own (no real values), but internal state, not for transmission.",
    )


def _sequential_index(bucket: dict, real_value: str) -> int:
    """
    Returns the existing index for `real_value` in `bucket` (a dict of
    real-value -> int), or allocates the next one (1-based, in
    first-seen order) if this is the first time we've seen it. Mutates
    `bucket` in place; caller is responsible for persisting it.
    """
    if real_value in bucket:
        return bucket[real_value]
    next_index = len(bucket) + 1
    bucket[real_value] = next_index
    return next_index


def fuzz_ip(config: "config_loader.ConfigLoader", ip: str) -> str:
    """
    RFC1918-range-aware fuzzing, per netlanvas-telemetry-pipeline-v6 §3:

    - 192.168.x.x: octets 1,2,4 kept; octet 3 replaced with a
      sequentially-assigned per-instance index.
    - 10.x.x.x and 172.16.0.0-172.31.255.255: octet 1 kept; octets 2
      and 3 each independently replaced with their own
      sequentially-assigned per-instance index; octet 4 kept.
    - Anything else (public/non-RFC1918): replaced entirely with
      pub.lic.ip.N (sequential per-instance index).

    Mapping state is loaded, updated, and saved on every call rather
    than batched -- these calls happen at payload-build time, not in a
    hot per-packet path, so the extra I/O is not a real cost.

    Design judgment call (the source spec gave one example, not enough
    to fully disambiguate this): for 10.x.x.x/172.16-31.x.x, octet 2
    and octet 3 each get their own single sequential counter, keyed by
    the full real prefix up to that octet (so "10.10.50" and "10.20.50"
    are different keys and never collide) -- but the counter itself
    increases globally across the whole instance's octet-3 values, not
    reset back to 1 for each new octet-2 group. E.g. 10.10.50.x gets
    octet3 index 1; 10.20.50.x -- a different real subnet under a
    different octet-2 -- gets octet3 index 2, not 1 again. Every
    distinct real subnet still gets its own unique, stable fuzzed
    index either way; this is simply the simpler of two reasonable
    numbering schemes, not a stricter privacy requirement.
    """
    try:
        addr = ipaddress.IPv4Address(ip.strip())
    except (ValueError, ipaddress.AddressValueError):
        return ip  # not IPv4-shaped; caller's problem, not ours to guess at

    octets = str(addr).split(".")
    mapping = _load_ip_mapping(config)

    if addr in ipaddress.IPv4Network("192.168.0.0/16"):
        # Own bucket (octet3_192168), separate from the 10.x/172.16-31.x
        # bucket below -- these must NOT share a sequential counter, or
        # a subnet's fuzzed index would depend on what OTHER unrelated
        # address family happened to be fuzzed first in this instance's
        # history (confirmed as a real bug via a live test 2026-09-03:
        # sharing one "octet3" bucket across both families made a
        # 10.x.x.x subnet get index 3 just because two 192.168.x.x
        # subnets had already been seen).
        idx = _sequential_index(mapping["octet3_192168"], f"192.168.{octets[2]}")
        _save_ip_mapping(config, mapping)
        # "**N", not a bare number -- confirmed 2026-09-03: a plain
        # digit in the fuzzed octet's place looked like it could be a
        # real IP, defeating the point. The literal asterisks make it
        # unmistakable at a glance while the digit still lets two
        # different real subnets be told apart in the output.
        return f"192.168.**{idx}.{octets[3]}"

    if addr in ipaddress.IPv4Network("10.0.0.0/8") or addr in ipaddress.IPv4Network("172.16.0.0/12"):
        prefix = octets[0]
        idx2 = _sequential_index(mapping["octet2_10_172"], f"{prefix}.{octets[1]}")
        idx3 = _sequential_index(mapping["octet3_10_172"], f"{prefix}.{octets[1]}.{octets[2]}")
        _save_ip_mapping(config, mapping)
        return f"{prefix}.**{idx2}.**{idx3}.{octets[3]}"

    # Public / non-RFC1918 -- device record is kept, IP replaced entirely.
    idx = _sequential_index(mapping["public"], str(addr))
    _save_ip_mapping(config, mapping)
    return f"pub.lic.ip.{idx}"
