import sqlite3
import logging
import os
from engine.config_loader import config

logger = logging.getLogger("Netlanvas.DB")

def apply_migrations(conn):
    cursor = conn.cursor()
    
    def column_exists(table, column):
        cursor.execute(f"PRAGMA table_info({table})")
        return any(row[1] == column for row in cursor.fetchall())

    if not column_exists("logical_nodes", "os_family"):
        cursor.execute("ALTER TABLE logical_nodes ADD COLUMN os_family TEXT")

    # HOSTNAME-1: tracks which discovery mechanism last set hostname and
    # at what priority tier (see engine/hostname_registry.py), so a
    # later-arriving lower-priority signal (e.g. mDNS instance name)
    # never clobbers an already-known higher-priority one (e.g. SNMP
    # sysName, an admin-assigned name). Separate from weld_confidence,
    # which governs device_type classification stability, a different
    # concern entirely.
    if not column_exists("logical_nodes", "hostname_source_priority"):
        cursor.execute("ALTER TABLE logical_nodes ADD COLUMN hostname_source_priority INTEGER NOT NULL DEFAULT 0")
        
    if not column_exists("l3_bindings", "is_public"):
        cursor.execute("ALTER TABLE l3_bindings ADD COLUMN is_public BOOLEAN DEFAULT 0")

    # WEB-1 (2026-09-15): a short summary of whatever pollers/web_probe.py
    # found on 443/80 for this IP (scheme, status line, Server header if
    # present) -- NULL means either nothing's there or it hasn't been
    # probed yet, not a confirmed absence. Powers the Graph UI's
    # "Open Web Page" context-menu item.
    if not column_exists("l3_bindings", "http_header"):
        cursor.execute("ALTER TABLE l3_bindings ADD COLUMN http_header TEXT")
        
    if not column_exists("infrastructure_links", "is_ambiguous"):
        cursor.execute("ALTER TABLE infrastructure_links ADD COLUMN is_ambiguous BOOLEAN DEFAULT 0")
        
    if not column_exists("endpoint_locations", "is_ambiguous"):
        cursor.execute("ALTER TABLE endpoint_locations ADD COLUMN is_ambiguous BOOLEAN DEFAULT 0")

    if not column_exists("infrastructure_links", "local_port_name"):
        cursor.execute("ALTER TABLE infrastructure_links ADD COLUMN local_port_name TEXT")

    if not column_exists("endpoint_locations", "local_port_name"):
        cursor.execute("ALTER TABLE endpoint_locations ADD COLUMN local_port_name TEXT")

    # Link Speed Migrations
    if not column_exists("infrastructure_links", "link_speed"):
        cursor.execute("ALTER TABLE infrastructure_links ADD COLUMN link_speed TEXT")

    if not column_exists("endpoint_locations", "link_speed"):
        cursor.execute("ALTER TABLE endpoint_locations ADD COLUMN link_speed TEXT")

    # VLAN-3: admin-set VLAN names must survive the next SNMP deep-scan
    # rather than being silently overwritten -- see pollers/vlan_registry.py's
    # upsert, which now checks this flag via an UPSERT ... WHERE clause.
    if not column_exists("network_vlans", "is_admin_named"):
        cursor.execute("ALTER TABLE network_vlans ADD COLUMN is_admin_named BOOLEAN DEFAULT 0")

    # Per-switch VLAN name reports -- lets the UI show WHERE a name came
    # from (a switch can disagree with itself over time, or two switches
    # can report slightly different names for the same vlan_id, e.g.
    # "Guest-VLAN" vs "Guest" -- seen live on this network). Deliberately
    # separate from network_vlans.vlan_name (the single displayed name,
    # protected by is_admin_named): this table is raw per-source
    # telemetry and is always overwritten on every scan, never protected.
    cursor.execute('''CREATE TABLE IF NOT EXISTS vlan_sources (
        vlan_id INTEGER NOT NULL,
        switch_ip TEXT NOT NULL,
        reported_name TEXT,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (vlan_id, switch_ip)
    )''')

    # Authoritative subnet<->VLAN bindings confirmed directly from a
    # router's own interface table (ifDescr name matched against
    # ipAdEntAddr/ipAdEntIfIndex) -- see pollers/vlan_registry.py's
    # discover_router_vlan_subnets(). Distinct from (and more
    # trustworthy than) inferring a VLAN's subnet from switch FDB data:
    # confirmed live that a switch reporting vlan=1 for a device often
    # just means "no 802.1Q tag was present" on that link, not that the
    # device is genuinely on some single logical "VLAN 1" network.
    cursor.execute('''CREATE TABLE IF NOT EXISTS vlan_subnets (
        vlan_id INTEGER NOT NULL,
        subnet TEXT NOT NULL,
        router_ip TEXT,
        interface_name TEXT,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (vlan_id, subnet)
    )''')

    # NET-1: general-purpose version of the same confirmed-subnet data
    # above, but covering EVERY router interface (untagged included),
    # not just VLAN-tagged ones -- vlan_subnets deliberately only
    # records interfaces whose name matched a VLAN pattern. This table
    # is what lets auto_discovery.py's discover_active_subnets() (ping-
    # sweep targeting) and the dashboard use the router's real
    # advertised netmask instead of assuming /24, for ANY subnet a
    # router interface confirms -- tagged or not. Populated by the same
    # SNMP walk discover_router_vlan_subnets() already does, no extra
    # queries needed.
    cursor.execute('''CREATE TABLE IF NOT EXISTS router_subnets (
        subnet TEXT PRIMARY KEY,
        router_ip TEXT,
        interface_name TEXT,
        vlan_id INTEGER,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    # Priority 3 (Free-Tier Alerting), STATE-1/2. Nothing before this
    # tracked device presence as anything other than last_seen +
    # staleness purge (see mac_table_scraper.py) -- this is the first
    # real "new/online/offline" state machine, one row per device.
    # device_state_transitions is the append-only history STATE-2 needs
    # for flapping detection (device cycling status repeatedly in a
    # short window) -- device_state alone only ever shows the CURRENT
    # status, not how often it's been changing.
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_state (
        mac_address TEXT PRIMARY KEY,
        status TEXT NOT NULL DEFAULT 'new',
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_status_change DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(mac_address) REFERENCES l2_interfaces(mac_address) ON DELETE CASCADE
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_state_transitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT NOT NULL,
        from_status TEXT,
        to_status TEXT NOT NULL,
        transitioned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(mac_address) REFERENCES l2_interfaces(mac_address) ON DELETE CASCADE
    )''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_state_transitions_mac_time ON device_state_transitions(mac_address, transitioned_at)')

    # FIND-1/2. One row per (device, finding type) currently active --
    # UNIQUE constraint below lets pollers upsert (re-detecting the same
    # issue on the same device just bumps last_confirmed, same idiom as
    # mac_table_scraper's ON CONFLICT upserts) rather than accumulating
    # duplicate rows every tick the condition is still true.
    # resolved_at is set once a finding stops being observed, so history
    # survives instead of being deleted -- mirrors device_findings'
    # sibling tables' "never delete, mark done" shape elsewhere in this
    # schema (is_admin_named, etc.).
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_address TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        detail TEXT,
        first_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_confirmed DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME,
        FOREIGN KEY(mac_address) REFERENCES l2_interfaces(mac_address) ON DELETE CASCADE,
        UNIQUE(mac_address, finding_type)
    )''')

    # ALERT-1. Deliberately denormalized (title/detail copied in at
    # creation time, not joined back to device_state_transitions/
    # device_findings on every read) -- the inbox needs to stay fast and
    # simple to paginate, and an alert should keep reading sensibly even
    # if the underlying finding is later resolved/the device is removed
    # (mac_address is nullable and has no FK for exactly this reason --
    # same "survive the thing it's about going away" reasoning as
    # account_events on the webhost side).
    cursor.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        mac_address TEXT,
        title TEXT NOT NULL,
        detail TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        read_at DATETIME,
        email_dispatched_at DATETIME,
        webhook_dispatched_at DATETIME
    )''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_read_at ON alerts(read_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)')
    # *_dispatched_at is set once delivery has been ATTEMPTED (success or
    # a non-retryable failure -- see engine/alert_dispatcher.py), not
    # necessarily delivered -- this is what stops the dispatcher from
    # retrying the same alert forever. NULL means "not yet attempted",
    # for both a never-touched alert and one whose channel was disabled
    # at creation time and only later got enabled.
    if not column_exists("alerts", "email_dispatched_at"):
        cursor.execute("ALTER TABLE alerts ADD COLUMN email_dispatched_at DATETIME")
    if not column_exists("alerts", "webhook_dispatched_at"):
        cursor.execute("ALTER TABLE alerts ADD COLUMN webhook_dispatched_at DATETIME")
    # Distinguishes a recovery/good-news event (device back online, a
    # finding resolved) from a problem report -- purely a UI-treatment
    # flag (see alerting.html), NOT a severity level. Severity stays
    # about urgency/threshold-filtering only; conflating "resolved"
    # into that scale would put a non-problem on the same ordinal axis
    # as how bad a problem is, which doesn't make sense and would have
    # broken email/webhook min-severity threshold semantics.
    if not column_exists("alerts", "is_resolution"):
        cursor.execute("ALTER TABLE alerts ADD COLUMN is_resolution BOOLEAN NOT NULL DEFAULT 0")

    # STATE-3: offline detection moved from a wall-clock window
    # (OFFLINE_GRACE_SECONDS) to a tick-count window (OFFLINE_GRACE_TICKS,
    # see device_state_tracker.py) -- a fixed number of seconds races
    # against how long a tick actually takes, which varies (confirmed
    # live: 95s under normal load, 275-330s under memory pressure), so a
    # slow tick alone could cross a wall-clock threshold with nothing
    # actually wrong. Tick count tracks real polling progress instead.
    if not column_exists("device_state", "last_seen_tick"):
        cursor.execute("ALTER TABLE device_state ADD COLUMN last_seen_tick INTEGER")

    # OUI-4: the Premium-tier category/market_segment enrichment
    # (engine/oui_manager.py's get_vendor_info(), fed by
    # save_premium_classifications() from the telemetry ack) was being
    # computed correctly but discarded on every real call site --
    # fingerprinter.py only ever used get_vendor(), the plain-string
    # wrapper. Persisted here so it's queryable the same way vendor
    # already is, instead of being recomputed (and re-discarded) on
    # every single fingerprint pass with nowhere to land.
    if not column_exists("l2_interfaces", "category"):
        cursor.execute("ALTER TABLE l2_interfaces ADD COLUMN category TEXT")
    if not column_exists("l2_interfaces", "market_segment"):
        cursor.execute("ALTER TABLE l2_interfaces ADD COLUMN market_segment TEXT")

def init_db():
    db_path = config.DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    logger.info("Initializing Netlanvas SQLite Database Schema...")
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys = ON;")

    cursor.execute('''CREATE TABLE IF NOT EXISTS logical_nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT, device_type TEXT, weld_confidence INTEGER DEFAULT 0, site_id TEXT, os_family TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS l2_interfaces (mac_address TEXT PRIMARY KEY, node_id INTEGER, vendor TEXT, chassis_mac BOOLEAN DEFAULT 0, is_virtual BOOLEAN DEFAULT 0, wireless_ssid TEXT, FOREIGN KEY(node_id) REFERENCES logical_nodes(id) ON DELETE CASCADE)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS l3_bindings (ip_address TEXT PRIMARY KEY, mac_address TEXT, vlan_id INTEGER, discovery_source TEXT, is_public BOOLEAN DEFAULT 0, is_ghost BOOLEAN DEFAULT 0, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(mac_address) REFERENCES l2_interfaces(mac_address) ON DELETE CASCADE)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS endpoint_locations (mac_address TEXT PRIMARY KEY, switch_ip TEXT, local_port TEXT, local_port_name TEXT, link_speed TEXT, vlan_id INTEGER, is_ambiguous BOOLEAN DEFAULT 0, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS network_vlans (vlan_id INTEGER PRIMARY KEY, vlan_name TEXT, ui_color TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS infrastructure_links (id INTEGER PRIMARY KEY AUTOINCREMENT, local_switch_ip TEXT NOT NULL, local_port INTEGER NOT NULL, local_port_name TEXT, link_speed TEXT, remote_system_name TEXT, vlan_id INTEGER, is_ambiguous BOOLEAN DEFAULT 0, last_mapped DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(local_switch_ip, local_port))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_fingerprints (mac_address TEXT PRIMARY KEY, snmp_sysdescr TEXT, snmp_sysobjectid TEXT, banner TEXT, last_updated DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(mac_address) REFERENCES l2_interfaces(mac_address) ON DELETE CASCADE)''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_capabilities (
        ip_address TEXT PRIMARY KEY,
        sys_object_id TEXT,
        working_functions TEXT DEFAULT '',
        last_successful_poll DATETIME,
        next_deep_discovery DATETIME
    )''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_l2_node_id ON l2_interfaces(node_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_l3_mac_address ON l3_bindings(mac_address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_l3_discovery_source ON l3_bindings(discovery_source)')

    apply_migrations(conn)
    conn.commit()
    conn.close()
    logger.info("Database schema initialized successfully.")

def apply_auth_migrations(conn):
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT NOT NULL,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)')
    cursor.execute('''CREATE TABLE IF NOT EXISTS setup_token (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        token_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')

def apply_registration_migrations(conn):
    """
    Tables backing device registration/entitlement (REG-1..4, ACCT-3).
    Private signing key never touches this table -- see
    security/device_identity.py, which mirrors cert_manager.py's
    file-based-key trust model.
    """
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_identity (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        public_key_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS registration_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        state_token_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS entitlement_cache (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        account_linked BOOLEAN NOT NULL DEFAULT 0,
        entitled BOOLEAN NOT NULL DEFAULT 0,
        checked_at TEXT NOT NULL,
        raw_response_json TEXT
    )''')

def apply_alerting_migrations(conn):
    """
    Alerting config (ALERT-4/5/6). Singleton row (id=1), same shape as
    entitlement_cache/device_identity above -- one appliance, one config,
    no need for a keyed table. Plaintext SMTP password column, matching
    snmp_v3_identities' existing convention (config_loader.py) for this
    same local-trust-boundary database -- this is the device's own
    SQLite file, not a shared multi-tenant store, so it's held to the
    same bar as every other credential already living here.

    Two independent email delivery paths, per explicit product decision:
    email_delivery_method='relay' calls the webhost's Resend-backed relay
    (gated on the device being REGISTERED to some account, not on paid
    entitlement -- ALERT-4 is a free-tier feature, the zero-setup relay
    is the incentive to register, not a paywall) or 'smtp' sends directly
    via the user's own server, no registration required either way.
    Webhooks (webhook_*) stay premium/entitlement-gated, checked at
    delivery time against entitlement_cache, not stored here.
    """
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS alerting_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        email_enabled BOOLEAN NOT NULL DEFAULT 0,
        email_delivery_method TEXT NOT NULL DEFAULT 'relay',
        email_min_severity TEXT NOT NULL DEFAULT 'medium',
        email_to_address TEXT,
        smtp_host TEXT,
        smtp_port INTEGER DEFAULT 587,
        smtp_username TEXT,
        smtp_password TEXT,
        smtp_use_tls BOOLEAN DEFAULT 1,
        smtp_from_address TEXT,
        webhook_enabled BOOLEAN NOT NULL DEFAULT 0,
        webhook_url TEXT,
        webhook_min_severity TEXT NOT NULL DEFAULT 'medium',
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )''')

    # ALERT-7: 'json' (default) is the original raw-signed-payload
    # webhook body, unchanged; 'ntfy' formats the same alert as an
    # ntfy.sh publish request instead (human-readable title/priority/
    # tags, no signing -- see alert_dispatcher.py's _send_webhook_ntfy).
    # A column, not a second table, since exactly one format applies to
    # whatever's already in webhook_url -- same singleton-row shape as
    # everything else here.
    def _column_exists(table, column):
        cursor.execute(f"PRAGMA table_info({table})")
        return any(row[1] == column for row in cursor.fetchall())

    if not _column_exists("alerting_config", "webhook_format"):
        cursor.execute("ALTER TABLE alerting_config ADD COLUMN webhook_format TEXT NOT NULL DEFAULT 'json'")

def init_alerting_db():
    """
    Creates alerting_config in config.db. Called once at API_VIEWER boot,
    same phase as init_registration_db()/init_auth_db() -- see main.py
    boot sequence.
    """
    db_path = config.CONFIG_DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    apply_alerting_migrations(conn)
    conn.commit()
    conn.close()
    logger.info("Alerting schema (alerting_config) initialized in config.db.")

def init_inventory_db():
    """
    INVENTORY-1 (2026-09-04): creates verified_devices in its own
    separate file (config.INVENTORY_DB_PATH), never in network.db or
    config.db. Called from BOTH POLLER and API_VIEWER boot -- POLLER's
    unification.py reads this every deep-scan cycle to re-apply
    confirmed names/types onto freshly-(re)discovered nodes; API_VIEWER
    writes to it whenever a user corrects a device via /api/node/update
    or /api/promote_node. Neither container has a guaranteed start
    order (same reasoning as init_alerting_db() above), so both call
    this idempotently (CREATE TABLE IF NOT EXISTS) rather than assuming
    the other already has.

    Deliberately its own file, not a table in config.db: this is the
    one thing in the whole schema that must survive main.py's
    rotate_database() Clean Slate purge, which only ever touches
    config.DB_PATH (network.db) -- keeping it in a separate file makes
    "never purged" a structural guarantee, not a rule someone has to
    remember to keep respecting inside a shared file. mac_address is
    the primary key because it's the one identifier that survives a
    purge and re-discovery cycle intact; network.db's logical_nodes.id
    is an autoincrement PK that gets regenerated from scratch every
    time, so nothing there could ever be a stable foreign key into this
    table.
    """
    db_path = config.INVENTORY_DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS verified_devices (
            mac_address TEXT PRIMARY KEY,
            user_given_name TEXT,
            confirmed_device_type TEXT,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    apply_inventory_migrations(conn)
    conn.commit()
    conn.close()
    logger.info("Inventory schema (verified_devices) initialized in inventory.db.")

def apply_inventory_migrations(conn):
    """
    INVENTORY-4 (2026-09-09): two genuinely different kinds of data now
    share this row, and it's important the sync logic below (see
    engine/unification.py's run_inventory_snapshot_sync()) never
    confuses them:

    1. Asset-management fields (location, asset_tag, serial_number,
       model, purchase_date, warranty_expiry) -- pure human input, the
       network can never discover a serial number. Only ever written
       by a person via /api/inventory/update, same as user_given_name/
       confirmed_device_type/notes always have been.

    2. last_known_* + category/market_segment + first_discovered/
       last_synced -- an automatic snapshot of the CURRENT network.db
       state for every device the engine has ever seen, refreshed every
       deep-scan tick regardless of whether anyone has ever looked at
       this device, let alone confirmed anything about it. This is what
       makes "every device gets an inventory record automatically" (not
       just ones a human explicitly confirmed) actually work -- before
       this, verified_devices only ever gained a row when a human acted.

    created_at/updated_at keep their existing meaning (a human edit),
    untouched by the automatic snapshot sync -- only first_discovered/
    last_synced track the automatic side, so the UI can tell "when did
    someone last confirm this" apart from "when did the network last
    actually see it."
    """
    cursor = conn.cursor()

    def column_exists(column):
        cursor.execute("PRAGMA table_info(verified_devices)")
        return any(row[1] == column for row in cursor.fetchall())

    for column, ddl in [
        ("location", "TEXT"),
        ("asset_tag", "TEXT"),
        ("serial_number", "TEXT"),
        ("model", "TEXT"),
        ("purchase_date", "TEXT"),
        ("warranty_expiry", "TEXT"),
        ("last_known_hostname", "TEXT"),
        ("last_known_vendor", "TEXT"),
        ("last_known_device_type", "TEXT"),
        ("last_known_ip", "TEXT"),
        ("last_known_os_family", "TEXT"),
        ("last_known_http_header", "TEXT"),
        ("category", "TEXT"),
        ("market_segment", "TEXT"),
        ("first_discovered", "DATETIME"),
        ("last_synced", "DATETIME"),
    ]:
        if not column_exists(column):
            cursor.execute(f"ALTER TABLE verified_devices ADD COLUMN {column} {ddl}")

def init_registration_db():
    """
    Creates the registration/entitlement tables in config.db. Called once
    at API_VIEWER boot, before device_identity.ensure_device_identity()
    (which writes into device_identity) -- see main.py boot sequence.
    """
    db_path = config.CONFIG_DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    apply_registration_migrations(conn)
    conn.commit()
    conn.close()
    logger.info("Registration schema (device_identity/registration_state/entitlement_cache) initialized in config.db.")

def init_auth_db():
    """
    Creates the users/sessions tables in config.db (the same database
    app_settings already lives in -- see config_loader.py's
    CONFIG_DB_PATH). Called once at API_VIEWER boot, before uvicorn
    starts accepting requests, so /api/auth/* and /api/setup/* routes
    always have a schema to query against.
    """
    db_path = config.CONFIG_DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    apply_auth_migrations(conn)
    conn.commit()
    conn.close()
    logger.info("Auth schema (users/sessions) initialized in config.db.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    init_auth_db()
