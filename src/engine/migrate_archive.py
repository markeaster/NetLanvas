"""
engine/migrate_archive.py

Time Machine archives are frozen network.db/inventory.db snapshots,
opened READ-ONLY for actual queries (see api/server.py's
get_db_connection, which uses `file:{path}?mode=ro`) so nothing ever
accidentally rewrites historical data. But an archive taken before a
schema change (a new nullable column, e.g. l3_bindings.http_header --
see WEB-1) predates that column entirely: a SELECT naming it throws
"no such column", breaking the ENTIRE Time Machine view of that
archive rather than just omitting the new field. Found live 2026-09-15
while building WEB-1, flagged rather than shipped silently broken --
this is the fix.

This is the one place that gap gets closed: right before the real
read-only connection to an archive is opened, a brief, separate
READ-WRITE connection applies the exact same additive-only migrations
already used for the live databases (reusing engine.database's own
apply_migrations()/apply_inventory_migrations(), not duplicating their
column lists), then closes. Purely additive -- ADD COLUMN and CREATE
TABLE IF NOT EXISTS throughout, never touches an existing row, never
drops anything -- so this doesn't compromise an archive's value as a
historical record. An archive gains empty (NULL) columns for features
that didn't exist when it was taken, exactly as if that archive's
device had simply never been probed for that field, which is the
truthful state: it never was.

Usage: call ensure_archive_migrated(path, kind) once, right before
opening the real read-only connection to that same path (see
api/server.py's get_db_connection). Going forward: any new column
added to apply_migrations()/apply_inventory_migrations() in
engine/database.py is automatically picked up here too on the next
archive access -- there is no second column list to keep in sync when
adding a future field. This is the one place to do it.
"""
import logging
import os
import sqlite3

from engine.database import apply_migrations, apply_inventory_migrations

logger = logging.getLogger("Netlanvas.ArchiveMigration")

# An archive file's content and schema are both frozen the moment
# Time Machine writes it -- unlike the live databases, it never
# changes again out from under a running process. So a per-process,
# in-memory "already handled" set is sufficient; there is no need to
# re-check (let alone re-migrate) the same path on every request for
# the life of this process, and no risk of that cache going stale.
_migrated_paths = set()


def ensure_archive_migrated(db_path: str, kind: str = "network") -> None:
    """
    kind: "network" (network.db-shaped archive -- apply_migrations) or
    "inventory" (inventory.db-shaped archive -- apply_inventory_migrations).
    Most Time Machine archives are network.db snapshots; inventory.db
    is not currently archived by name in the same rotation, but this
    takes a kind param now rather than hardcoding one migration path,
    so a future inventory-archive feature doesn't need this file
    touched again.
    """
    if not os.path.exists(db_path):
        return

    real_path = os.path.realpath(db_path)
    if real_path in _migrated_paths:
        return

    migrate_fn = apply_inventory_migrations if kind == "inventory" else apply_migrations

    try:
        conn = sqlite3.connect(db_path)
        migrate_fn(conn)
        conn.commit()
        conn.close()
    except Exception as e:
        # Best-effort: a migration failure here shouldn't take down the
        # whole archive view -- callers still just get "no such column"
        # for whatever field this pass couldn't add, exactly the
        # pre-existing behavior, nothing new to break on.
        logger.error(f"[ArchiveMigration] Failed to migrate {db_path}: {e}")
        return

    _migrated_paths.add(real_path)
    logger.info(f"[ArchiveMigration] Migrated archive schema ({kind}): {db_path}")
