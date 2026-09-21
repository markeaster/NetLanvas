"""
rate_limit.py

Lightweight in-memory rate limiter. No external dependency, no
persistence -- appropriate for this appliance's scale (single admin
user, single process, tolerant of resetting on restart). Buckets are
keyed by (identifier, bucket_name) so different endpoints/checks don't
share a counter -- a flood against one doesn't lock out another.

Not suitable as-is for a multi-worker/multi-process deployment (state
is process-local); this appliance runs a single uvicorn process, so
that's not a constraint here.
"""

import logging
import time
from collections import defaultdict
from threading import Lock

logger = logging.getLogger("Netlanvas.RateLimit")

_attempts: dict[tuple[str, str], list[float]] = defaultdict(list)
_lock = Lock()


def _prune_locked(key: tuple[str, str], window_seconds: int, now: float) -> list[float]:
    """Caller must hold _lock."""
    cutoff = now - window_seconds
    pruned = [t for t in _attempts[key] if t > cutoff]
    _attempts[key] = pruned
    return pruned


def is_rate_limited(identifier: str, bucket: str, max_attempts: int, window_seconds: int) -> bool:
    """
    Returns True if `identifier` has already hit max_attempts within the
    window for this bucket. Callers should check this BEFORE doing any
    expensive work (e.g. an argon2 verify) -- that's the actual point:
    capping cost per identifier, not just capping success/failure counts.
    """
    key = (identifier, bucket)
    now = time.time()
    with _lock:
        timestamps = _prune_locked(key, window_seconds, now)
        return len(timestamps) >= max_attempts


def record_attempt(identifier: str, bucket: str, window_seconds: int, log_level: int = logging.WARNING) -> None:
    """
    Records a failed attempt. Call only on the failure path -- see
    clear_attempts for success.

    log_level defaults to WARNING because most callers (login,
    setup_token, register_callback, session_check) are tracking a
    genuine auth/security failure -- exactly the kind of thing an
    admin reviewing logs should see. A caller tracking routine,
    expected volume instead of an actual failure (e.g. dhcp_sniffer.py
    rate-limiting ordinary broadcast traffic, not a security event)
    should pass a quieter level -- reusing this shared bucket/window
    bookkeeping doesn't mean every caller's normal operation deserves
    WARNING severity.
    """
    key = (identifier, bucket)
    now = time.time()
    with _lock:
        _prune_locked(key, window_seconds, now)
        _attempts[key].append(now)
        count = len(_attempts[key])
    logger.log(log_level, f"[RATE-LIMIT] Attempt {count} recorded for '{identifier}' on bucket '{bucket}'.")


def clear_attempts(identifier: str, bucket: str) -> None:
    """Call on success -- a legitimate user who eventually gets it right shouldn't stay flagged."""
    key = (identifier, bucket)
    with _lock:
        _attempts.pop(key, None)


def get_client_ip(request) -> str:
    """
    Extracts the real client IP via X-Forwarded-For, set automatically
    by Caddy's reverse_proxy (see caddy/Caddyfile). Caddy's default
    behavior is to APPEND its own upstream IP to any existing
    X-Forwarded-For value rather than replace it -- so the trustworthy
    entry is always the LAST one, not the first. A client can freely
    set X-Forwarded-For to anything on the initial request; taking the
    first entry (as this used to) let that value flow straight through
    as the rate-limit bucket key, letting an attacker rotate a fake
    header per request to bypass brute-force protection on login/setup.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else "unknown"
