"""
submitter.py

Client-side implementation of the Community Telemetry Pipeline's
submission handshake (netlanvas-telemetry-pipeline-v6 S6): bootstrap ->
challenge -> verify -> submit. Reuses this install's existing Ed25519
identity (security.device_identity, already generated at boot for
REG-3/REG-4) rather than minting a new one -- see the design doc for
the full threat-model reasoning.

Invoked by main.py's automatic triggers (S11: tick-10 first send, the
daily periodic send) and by the Preview page's "Submit Now" button (S7)
-- all three call submit() directly, so there is exactly one submission
code path to keep correct.
"""

import base64
import hashlib
import logging

import requests

from security import device_identity
from engine import oui_manager

logger = logging.getLogger("Netlanvas.Telemetry.Submitter")

_BASE_URL = "https://netlanvas.com"
_BOOTSTRAP_URL = f"{_BASE_URL}/telemetry.php"
_HANDSHAKE_URL = f"{_BASE_URL}/api/telemetry-handshake.php"
_VERIFY_URL = f"{_BASE_URL}/api/telemetry-verify.php"
_SUBMIT_URL = f"{_BASE_URL}/api/telemetry-submit.php"


def _ensure_bootstrapped(instance_id: str, public_key_b64: str, timeout: float) -> None:
    """
    Idempotent -- safe to call before every handshake. The server does
    INSERT OR IGNORE plus a backfill UPDATE (telemetry.php), so
    repeating this is cheap and harmless even when already bound.
    """
    requests.post(
        _BOOTSTRAP_URL,
        json={"instance_id": instance_id, "public_key_b64": public_key_b64},
        timeout=timeout,
    )


def _handshake(instance_id: str, timeout: float) -> str:
    resp = requests.post(_HANDSHAKE_URL, json={"instance_id": instance_id}, timeout=timeout)
    resp.raise_for_status()
    nonce = resp.json().get("nonce")
    if not nonce:
        raise RuntimeError("Handshake response missing nonce")
    return nonce


def _verify(instance_id: str, nonce: str, timeout: float) -> bytes:
    """
    Signs the nonce's own hex-string bytes exactly as received (NOT the
    decoded raw bytes) -- must match telemetry-verify.php's
    verification side precisely, or every real signature fails to
    verify. Returns the raw signature bytes, needed to derive
    submission_id.
    """
    signature = device_identity.get_private_key().sign(nonce.encode("ascii"))
    signature_b64 = base64.b64encode(signature).decode("ascii")

    resp = requests.post(
        _VERIFY_URL,
        json={"instance_id": instance_id, "nonce": nonce, "signature": signature_b64},
        timeout=timeout,
    )
    resp.raise_for_status()
    return signature


def _submission_id(signature: bytes) -> str:
    """base64url(SHA256(signature)), no padding -- both sides derive this independently, nothing is issued/transmitted for it."""
    return base64.urlsafe_b64encode(hashlib.sha256(signature).digest()).rstrip(b"=").decode("ascii")


def _save_classifications_if_present(resp_json: dict) -> None:
    """
    OUI-2 (2026-09-08): the ack's "classifications" block (empty {} for
    a non-entitled account, populated for an entitled one -- see
    telemetry-submit.php's OUI-3 side) is the ENTIRE appliance-side
    sync mechanism for Premium vendor classification data -- no
    separate polling/fetch endpoint, it just rides along on telemetry
    the appliance already sends. Deliberately isolated in its own
    try/except: a caching hiccup here must never turn an otherwise-
    successful submission into a reported failure, same principle
    submit()'s own outer try/except already applies to the send itself.
    """
    try:
        classifications = resp_json.get("classifications")
        if classifications:
            oui_manager.save_premium_classifications(classifications)
    except Exception as e:
        logger.warning(f"[*] Telemetry: failed to cache premium classifications from ack: {e}")


def submit(instance_id: str, payload: dict, timeout: float = 15.0) -> bool:
    """
    Full handshake + submit for one payload. Returns True on success,
    False on any failure (logged, never raised -- a telemetry
    submission failing must never affect the appliance's own
    operation, same principle as send_first_boot_telemetry/
    maybe_send_telemetry_heartbeat in main.py).
    """
    try:
        public_key_b64 = device_identity.get_public_key_b64()
        _ensure_bootstrapped(instance_id, public_key_b64, timeout)

        nonce = _handshake(instance_id, timeout)
        signature = _verify(instance_id, nonce, timeout)
        submission_id = _submission_id(signature)

        resp = requests.post(f"{_SUBMIT_URL}/{submission_id}", json=payload, timeout=timeout)
        resp.raise_for_status()

        logger.info(
            "[*] Telemetry: Community submission accepted (%d devices).",
            len(payload.get("devices", [])),
        )

        try:
            _save_classifications_if_present(resp.json())
        except ValueError:
            pass  # non-JSON body -- shouldn't happen given raise_for_status() passed, not worth failing the submission over

        return True
    except Exception as e:
        logger.warning(f"[*] Telemetry: Community submission failed: {e}")
        return False
