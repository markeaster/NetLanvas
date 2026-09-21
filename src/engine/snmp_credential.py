from dataclasses import dataclass
from typing import Optional
from enum import Enum


class SNMPVersion(Enum):
    V2C = "v2c"
    V3 = "v3"


AUTH_PROTOCOLS_BY_STRENGTH = ["SHA-512", "SHA-384", "SHA-256", "SHA-224", "SHA", "MD5"]
PRIV_PROTOCOLS_BY_STRENGTH = ["AES-256", "AES-192", "AES-128", "DES"]

# net-snmp's own CLI flag values for -a/-x. AES-128 is the one naming
# irregularity worth knowing: net-snmp historically shipped only one
# AES variant (128-bit) named simply "AES" -- "AES-192"/"AES-256" were
# added later via the Blumenthal AES patch, which is NOT guaranteed to
# be compiled into every distro's net-snmp package. Attempting an
# unsupported protocol just fails that one probe attempt (non-zero
# exit -> None, same as a wrong password) and the strength-descending
# loop moves on -- graceful by construction, just worth knowing a
# couple of probe attempts may be "doomed" on a build without the
# patch. Worth verifying once, not assumed: `docker exec netlanvas_core
# snmpget --help 2>&1 | grep -A2 "\-x"` shows which -x values this
# specific image's net-snmp actually accepts.
NET_SNMP_AUTH_FLAG = {
    "SHA-512": "SHA-512", "SHA-384": "SHA-384", "SHA-256": "SHA-256",
    "SHA-224": "SHA-224", "SHA": "SHA", "MD5": "MD5",
}
NET_SNMP_PRIV_FLAG = {
    "AES-256": "AES-256", "AES-192": "AES-192", "AES-128": "AES", "DES": "DES",
}


@dataclass(frozen=True)
class SNMPCredential:
    version: SNMPVersion
    community: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    # F14: independent USM privacy passphrase, kept separate from
    # `password` (the auth passphrase) so authKey and privKey are
    # cryptographically independent per RFC 3414, instead of both being
    # derived from the same secret. Falls back to `password` only for
    # v3 identities that predate this field (see config_loader.py's
    # migration, which backfills it from the existing password column).
    priv_password: Optional[str] = None
    auth_protocol: Optional[str] = None
    priv_protocol: Optional[str] = None

    @property
    def is_resolved(self) -> bool:
        if self.version == SNMPVersion.V2C:
            return True
        return self.auth_protocol is not None and self.priv_protocol is not None

    @property
    def effective_priv_password(self) -> Optional[str]:
        """
        The passphrase every caller should actually use for USM privacy
        (privKey/-X). Prefers the independent priv_password; falls back
        to the auth password only for identities loaded from a row that
        predates this field (shouldn't normally occur post-migration,
        but keeps this safe rather than sending a literal "None").
        """
        return self.priv_password if self.priv_password else self.password

    def resolved_with(self, auth_protocol: str, priv_protocol: str) -> "SNMPCredential":
        if self.version == SNMPVersion.V2C:
            return self
        return SNMPCredential(
            version=self.version, username=self.username, password=self.password,
            priv_password=self.priv_password,
            auth_protocol=auth_protocol, priv_protocol=priv_protocol,
        )

    def cache_key(self) -> str:
        if self.version == SNMPVersion.V2C:
            return f"v2c::{self.community}"
        return f"v3::{self.username}"

    def display_label(self) -> str:
        if self.version == SNMPVersion.V2C:
            masked = f"{self.community[:2]}***" if self.community else "?"
            return f"v2c:{masked}"
        return f"v3:{self.username}"
