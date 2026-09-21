"""
engine/runtime_state.py

NATIVE-1: drop-in async replacement for the subset of redis.asyncio's
client interface main.py/server.py actually use (get/set/delete on
plain string values -- see redis.asyncio usage sites: ENGINE_TICK,
ENGINE_PROGRESS, ENGINE_COMMAND, HOST_TLS_SANS, all plain GET/SET, no
pub/sub, no persistence relied on -- confirmed by the native-port
scope research before this was written).

Only used when NETLANVAS_MODE=native (see main.py's role router) --
the Docker/container deployment is completely unaffected, still
connects to a real Redis server exactly as before. This exists
because native "standalone" mode merges POLLER and API_VIEWER into
one process (see main.py's NATIVE branch), so the whole reason
Redis exists today -- letting two separate OS processes see the same
four values -- doesn't apply. A real Redis server would be a genuine
unnecessary dependency to bundle/install on a user's machine for
this.

Not used for native "server" mode (the opt-in two-process mode) --
that needs real cross-process IPC, which is a separate, not-yet-built
backend (see the native-port plan's open items). This store only
works within a single process's own memory.
"""

import asyncio


class InProcessStateStore:
    def __init__(self):
        self._store: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> str | None:
        async with self._lock:
            return self._store.get(key)

    async def set(self, key: str, value: str) -> None:
        async with self._lock:
            self._store[key] = value

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)


# Module-level singleton -- both main.py and api/server.py import this
# exact object when NETLANVAS_MODE=native, so they share one store
# (Python only executes a module body once per process, caching the
# result in sys.modules; every subsequent `from engine.runtime_state
# import shared_state` gets the same instance, not a fresh copy).
shared_state = InProcessStateStore()
