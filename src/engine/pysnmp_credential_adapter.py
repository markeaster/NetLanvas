"""
pysnmp_credential_adapter.py

Translates our SNMPCredential (v2c string or v3 identity) into whatever
pysnmp's native hlapi needs for its `authData` parameter. Separate from
snmp_credential.py's NET_SNMP_AUTH_FLAG/NET_SNMP_PRIV_FLAG, which are
net-snmp CLI flag names for the subprocess-based adapter -- pysnmp uses
actual object constants, not plain strings, so this is a genuinely
different mapping, not reusable.

Shared by every module that talks to pysnmp's native async API directly
(as opposed to shelling out to snmpget/snmpwalk via snmp_adapter.py):
currently pollers/lldp_scraper.py and pollers/ping_sweeper.py. Kept in
one place specifically so a second caller (ping_sweeper.py) didn't have
to duplicate this logic -- see punch list SNMP-3.
"""
import pysnmp.hlapi.v3arch.asyncio as _pysnmp_hlapi
from pysnmp.hlapi.v3arch.asyncio import CommunityData, UsmUserData
from engine.snmp_credential import SNMPVersion

# Constant availability depends on the installed pysnmp version (pinned
# to 7.1.28 per S6) -- verified directly against the real installed
# package, all ten entries confirmed present, not assumed. An
# unavailable protocol here still degrades gracefully (returns None,
# not a crash) if this ever runs against a different pysnmp version.
_PYSNMP_AUTH_PROTOCOL_NAMES = {
    "SHA-512": "usmHMAC384SHA512AuthProtocol",
    "SHA-384": "usmHMAC256SHA384AuthProtocol",
    "SHA-256": "usmHMAC192SHA256AuthProtocol",
    "SHA-224": "usmHMAC128SHA224AuthProtocol",
    "SHA": "usmHMACSHAAuthProtocol",
    "MD5": "usmHMACMD5AuthProtocol",
}
_PYSNMP_PRIV_PROTOCOL_NAMES = {
    "AES-256": "usmAesCfb256Protocol",
    "AES-192": "usmAesCfb192Protocol",
    "AES-128": "usmAesCfb128Protocol",
    "DES": "usmDESPrivProtocol",
}


def to_pysnmp_auth_data(credential, mp_model=1):
    """
    Returns CommunityData for v2c/v1, UsmUserData for v3. Returns None
    if credential is None, unresolved, or its protocol pairing isn't
    available on this pysnmp build -- callers should treat None as
    "can't build this one, skip it."
    """
    if credential is None:
        return None
    if credential.version == SNMPVersion.V2C:
        return CommunityData(credential.community, mpModel=mp_model)
    if not credential.is_resolved:
        return None
    auth_proto = getattr(_pysnmp_hlapi, _PYSNMP_AUTH_PROTOCOL_NAMES.get(credential.auth_protocol, ""), None)
    priv_proto = getattr(_pysnmp_hlapi, _PYSNMP_PRIV_PROTOCOL_NAMES.get(credential.priv_protocol, ""), None)
    if auth_proto is None or priv_proto is None:
        return None
    return UsmUserData(
        credential.username,
        # F14: authKey and privKey must come from independent secrets
        # (RFC 3414 USM) -- previously both were the same stored
        # password. effective_priv_password is the dedicated privacy
        # passphrase, falling back to the auth password only for
        # identities that predate that field.
        authKey=credential.password, privKey=credential.effective_priv_password,
        authProtocol=auth_proto, privProtocol=priv_proto,
    )
