"""
middleware.py

HTTP-level auth gate, registered in server.py as @app.middleware("http").
Runs for every request (ASGI middleware wraps the whole app, including
the /dashboard static mount) but only actually rejects requests whose
path starts with /api/ -- see path_requires_auth below. The static
/dashboard/ mount (HTML/JS/CSS) is never gated here: the UI shell isn't
sensitive, and login.html/auth-guard.js themselves must be loadable
before any session exists. Only the JSON data behind /api/* needs
gating.
"""

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from security.auth import SESSION_COOKIE_NAME, validate_session
from security.rate_limit import is_rate_limited, record_attempt, get_client_ip
from engine.config_loader import config

logger = logging.getLogger("Netlanvas.Auth")

# Routes reachable with no session. Keep this list as short as possible --
# anything else under /api/ requires a valid session cookie.
UNAUTHENTICATED_API_PATHS = {
    "/api/auth/login",
    "/api/setup/status",
    "/api/setup/password",
    # REG-3's local callback: arrives via a cross-site 302 from
    # netlanvas.com, so netlanvas_session (samesite=strict) is never
    # sent here regardless of whether the admin is logged in. Its real
    # authorization is registration_state's single-use local_state
    # token, verified inside the handler itself -- see
    # security/registration.py's verify_and_consume_state_token.
    "/api/register/callback",
    # index.html's checkForUpdate() fires unconditionally from
    # DOMContentLoaded, before handleLifecycleEvent() has any chance to
    # confirm setup is complete -- on a fresh install with no session,
    # gating this would 401 and auth-guard.js would bounce straight to
    # login.html before the setup wizard ever had a chance to show.
    # Response is just two version strings + a bool, nothing sensitive.
    "/api/version/check",
    # NATIVE-16: exact same bug as /api/version/check above, just missed
    # the first time -- index.html's pollEngineTick() also starts
    # unconditionally on load (it drives the tick-lock overlay, which
    # has to work correctly BEFORE setup completes, so it can't wait for
    # a session either) and hits this every ~2s. Confirmed live as real
    # user feedback (2026-09-02, first macOS .pkg test): a fresh install
    # with no session went straight to the login page instead of the
    # setup wizard -- the very first unauthenticated poll 401'd and
    # auth-guard.js's wrapped fetch bounced the top-level window to
    # login.html before settings.html's own bootstrapSettingsPage() ever
    # got a chance to show the setup modal, on either platform (this is
    # shared UI code, not macOS-specific -- Windows has the identical
    # race, just apparently never lost it in testing there). Response is
    # engine tick/progress state, nothing sensitive.
    "/api/status",
    # NATIVE-16: the actual, confirmed root cause of "fresh install goes
    # straight to login instead of the setup wizard" -- found via a real
    # Chrome DevTools Protocol network trace (2026-09-02), not
    # speculation, after /api/status's own fix (above) turned out not to
    # be the whole story. checkForUpdate()'s just_updated_from branch
    # fires this POST unconditionally, completely independent of setup
    # state, whenever _LAST_KNOWN_VERSION in the (persisted-across-
    # reinstalls) database differs from the currently-running
    # NETLANVAS_VERSION -- which is exactly what happens on every
    # version-over-version reinstall test against the same retained
    # data directory (by design: ProgramData/Application Support data
    # survives an upgrade). /api/version/check (the GET right next to
    # this call, same function) was already exempted for the identical
    # reason; this POST sibling was simply missed the first time.
    # Response is just {"success": true}, nothing sensitive.
    "/api/version/acknowledge-update",
}

# A request presenting a cookie that doesn't match any valid session
# still costs an argon2 verify per stored session row (see
# security/auth.py's validate_session -- tokens are hashed, so there's
# no indexed lookup, only a verify-against-each-row scan). At this
# appliance's scale (0-2 sessions ever) that scan itself is cheap; the
# actual risk is an attacker sending garbage cookies with no cap on how
# often. This threshold is deliberately generous: the UI's own pollers
# (index.html + settings.html, both hitting /api/status every ~2s while
# mounted) will throw a few failed requests in the brief window after a
# session expires, before auth-guard.js redirects away -- that's normal
# behavior, not an attack, and shouldn't lock the legitimate owner out
# of their own login page.
SESSION_CHECK_MAX_ATTEMPTS = 30
SESSION_CHECK_WINDOW_SECONDS = 5 * 60


def path_requires_auth(path: str) -> bool:
    if not path.startswith("/api/"):
        return False
    return path not in UNAUTHENTICATED_API_PATHS


async def check_session(request: Request, get_conn_fn) -> JSONResponse | None:
    """
    Returns a 401/429 JSONResponse if the request needs (and lacks) a
    valid session; returns None if the request may proceed. get_conn_fn
    is the caller's own DB connection factory (server.py's
    get_config_db_connection), passed in rather than imported here to
    avoid a circular import between this module and server.py.
    """
    if not path_requires_auth(request.url.path):
        return None

    # Public read-only demo deployment: no real accounts exist, and
    # there's nothing to protect (all mutating calls are separately
    # blocked in server.py's demo_read_only middleware regardless of
    # session state). See engine/config_loader.py's DEMO_MODE docstring.
    if config.DEMO_MODE:
        return None

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        # No cookie at all costs nothing (no DB call, no argon2 verify)
        # -- not rate-limited, since there's no expensive work to cap.
        return JSONResponse(status_code=401, content={"detail": "Authentication required."})

    client_ip = get_client_ip(request)
    if is_rate_limited(client_ip, "session_check", SESSION_CHECK_MAX_ATTEMPTS, SESSION_CHECK_WINDOW_SECONDS):
        logger.warning(f"[AUTH] Rate limit exceeded for session checks from {client_ip}.")
        return JSONResponse(status_code=429, content={"detail": "Too many requests. Try again later."})

    # Custom @app.middleware("http") functions run OUTSIDE FastAPI's
    # normal exception-handler layer -- an uncaught exception here (e.g.
    # get_conn_fn() raising because config.db is temporarily missing)
    # would otherwise surface as a raw, unhandled 500 rather than a
    # clean response. Fail closed: any DB/lookup error is treated the
    # same as "no valid session" rather than propagating.
    try:
        conn = get_conn_fn()
        try:
            user_id = validate_session(conn, token)
        finally:
            conn.close()
    except Exception:
        return JSONResponse(status_code=401, content={"detail": "Authentication required."})

    if user_id is None:
        record_attempt(client_ip, "session_check", SESSION_CHECK_WINDOW_SECONDS)
        logger.warning(f"[AUTH] Invalid/expired session cookie presented from {client_ip}.")
        return JSONResponse(status_code=401, content={"detail": "Session expired or invalid."})

    return None
