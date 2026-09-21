import os
import json
import sqlite3
import sys
import logging
import logging.handlers
import time
from dotenv import load_dotenv

root_logger = logging.getLogger("Netlanvas")
logger = logging.getLogger("Netlanvas.Config")

_DEBUG_VALUE_MAX_LEN = 200


def _debug_value_repr(value):
    """
    Found live 2026-09-08: a real customer's Community Telemetry
    submissions were being rejected with corrupted-looking, deeply
    nested-escaped log_sample content. Root cause -- with verbose
    logging on, _get_setting()/_set_setting() echoed a setting's FULL
    value into the debug log unconditionally, including
    _TELEMETRY_LOG_SAMPLE itself (telemetry/log_sampler.py), whose
    value IS the entire JSON-serialized log sample. That debug line
    then got captured into a LATER log-sample window (the very
    mechanism this logging was itself part of), embedding a full
    serialized copy of one sample inside the next -- and repeating
    across restarts/reads compounds it further, matching the several
    levels of escaping actually observed. Truncating any long value
    before it reaches the debug log breaks this self-referential loop
    at the source, for _TELEMETRY_LOG_SAMPLE and any other large
    stored value, not just a specific key exclusion.
    """
    text = str(value)
    if len(text) <= _DEBUG_VALUE_MAX_LEN:
        return text
    return f"{text[:_DEBUG_VALUE_MAX_LEN]}... ({len(text)} chars total)"

# NATIVE-6: '../../' from this file's own directory is correct for the
# source tree (src/engine/config_loader.py -> up two levels -> repo
# root, where defaults.json actually lives) but wrong under a frozen
# PyInstaller onefile build -- there's no extra src/ wrapper inside the
# bundle, sys._MEIPASS itself IS the bundle root, so '../../' from
# _MEIPASS/engine overshoots by one level and lands on _MEIPASS's OWN
# parent (the bare system Temp directory) instead. Confirmed live: this
# silently broke defaults.json seeding (config_loader.py's own
# _bootstrap_config_db_once() has a graceful `if os.path.exists(...)`
# check, so it never raised -- every setting was just falling back to
# each individual caller's own hardcoded default the whole time,
# nothing was ever actually seeded) and, loudly, broke
# server.py's ALLOWED_SETTING_KEYS allowlist (which does log its
# failure), which in turn made every POST /api/settings call fail with
# "Unknown setting key" -- the setup wizard's own settings couldn't be
# saved at all in a frozen build. sys._MEIPASS is the standard,
# PyInstaller-documented way to find bundled data files at runtime.
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
ENV_PATH = os.path.join(BASE_DIR, '.env')
DEFAULTS_PATH = os.path.join(BASE_DIR, 'defaults.json')

# Setting keys whose VALUE must never be sent to a browser, even within
# the live log stream (see server.py's /api/logs/stream redaction).
# The raw value is DELIBERATELY still written to the on-disk log file
# (and therefore visible via `docker logs`) by _get_setting/_set_setting
# below -- reading that requires host/console access, an accepted trust
# boundary distinct from anything reachable over the network.
SENSITIVE_SETTING_KEYS = {"SNMP_COMMUNITY_STRING"}

load_dotenv(dotenv_path=ENV_PATH, override=True)

class RuntimeConfig:
    def __init__(self):
        self._verbose_mode = False
        # Deployment-time only -- deliberately an env var, not a DB-backed
        # app_setting, so it can never appear as a toggle in the real
        # Settings UI. Set on the read-only public demo deployment only
        # (see docker-compose.demo.yaml): disables auth, blocks all
        # mutating API calls, and swaps the live log stream for a
        # simulated one, since there's no real poller/session data there.
        self.DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")
        self.DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")
        self.CONFIG_DB_PATH = os.path.join(os.path.dirname(self.DB_PATH), "config.db")
        # SMARTSW-1: separate, NEVER purged by rotate_database()'s Clean
        # Slate (which only ever touches self.DB_PATH) -- holds user- and
        # system-confirmed device identities (e.g. a no-SNMP smart switch
        # positively identified via SSDP) that must survive a purge, since
        # logical_nodes.id is an autoincrement PK regenerated from scratch
        # on every one.
        self.INVENTORY_DB_PATH = os.path.join(os.path.dirname(self.DB_PATH), "inventory.db")
        self.LOG_FILE_PATH = os.path.join(os.path.dirname(self.DB_PATH), "engine.log")
        os.makedirs(os.path.dirname(self.DB_PATH), exist_ok=True)
        verbose = self._bootstrap_config_db()
        self._initialize_logging(verbose)

    def _bootstrap_config_db(self) -> bool:
        # RELIABILITY-1: every early-boot touch of config.db (WAL mode,
        # snmp_v3_identities, app_settings/archive_metadata, defaults.json
        # seeding, the VERBOSE_LOGGING read) used to be split across TWO
        # connections opened moments apart (_initialize_logging, then a
        # separate _bootstrap_settings) -- a self-inflicted race with no
        # real reason to exist: confirmed live that the second connection
        # could hit "database is locked" against the first, and with zero
        # retry that permanently skipped app_settings/archive_metadata
        # creation for the rest of the process's life (every _set_setting
        # call afterward then failed with "no such table"). One shared
        # connection removes that self-inflicted window entirely.
        #
        # The retry loop below still matters for genuinely external
        # contention: confirmed live on Windows that an unsigned, freshly
        # -built .exe's first disk write here can sit behind Windows
        # Defender's real-time scan for a long time (up to ~90s observed
        # across separate builds) -- far past what a single connect()
        # timeout alone could ride out. A real installed build only ever
        # pays this once (Defender caches a file's clean verdict and
        # doesn't rescan an unchanged binary on later launches); the
        # structural fix for that piece is code signing (Phase 5,
        # tracked separately), this retry is just the safety net for a
        # one-time slow first boot. In the container topology this
        # whole race effectively never fires at all -- POLLER and
        # API_VIEWER are separate OS processes, each with their own
        # RuntimeConfig() instantiation, never this close together.
        last_error = None
        for attempt in range(8):
            if attempt > 0:
                time.sleep(0.1 * attempt)
            try:
                return self._bootstrap_config_db_once()
            except sqlite3.OperationalError as e:
                last_error = e
                if "locked" not in str(e).lower():
                    break  # not the transient race this retry targets -- fail fast below
        logger.error(f"Failed to bootstrap config.db: {last_error}")
        return True  # can't confirm VERBOSE_LOGGING's stored value -- default verbose, safer for a first boot that never fully bootstrapped

    def _bootstrap_config_db_once(self) -> bool:
        conn = sqlite3.connect(self.CONFIG_DB_PATH, timeout=10.0)
        # WAL mode is set here deliberately -- this is the earliest
        # point config.db is ever touched, in EITHER process (POLLER
        # or API_VIEWER both instantiate RuntimeConfig() at import
        # time). Without this, config.db used SQLite's default
        # rollback-journal locking, which takes an exclusive lock on
        # the WHOLE file during any write -- a real contention risk
        # between netlanvas_core and netlanvas_api sharing this file,
        # worse on slower storage (SD cards) than NVMe. WAL is a
        # persistent, file-level setting once applied here, so no
        # other connection site needs to repeat it -- same pattern
        # database.py's init_db() already uses for network.db.
        conn.execute("PRAGMA journal_mode=WAL;")
        # snmp_v3_identities is created here too, for the identical
        # reason WAL mode is set here: this is the earliest point
        # EITHER process (POLLER or API_VIEWER) ever touches
        # config.db. netlanvas_core is the process that actually
        # queries this table (via snmp_adapter.py's
        # get_configured_credentials) -- creating it only in
        # database.py's init_auth_db() (API_VIEWER-only) would risk
        # POLLER racing ahead and querying a table that doesn't
        # exist yet, depending on which container finishes booting
        # first. See punch list SNMP-7.
        # `password` is TEXT here but is never written or read as
        # cleartext -- server.py's add_snmp_v3_identity() encrypts it
        # via security/credential_vault.py (Fernet, keyed from a file
        # outside config.db) before the INSERT, and snmp_adapter.py's
        # get_configured_credentials() decrypts it after the SELECT.
        # The column stays TEXT because the stored value is an
        # opaque, ASCII-safe encrypted token, not raw bytes.
        conn.execute("CREATE TABLE IF NOT EXISTS snmp_v3_identities (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, password TEXT NOT NULL, sort_order INTEGER NOT NULL, created_at TEXT NOT NULL)")
        # F14: `password` was being reused as BOTH the USM authKey and
        # privKey (see pysnmp_credential_adapter.py/snmp_adapter.py),
        # which removes the intended cryptographic independence RFC
        # 3414 assumes between the two. priv_password is the
        # independent privacy passphrase (encrypted at rest the same
        # way `password` is, per F4/credential_vault.py); existing
        # identities are backfilled from their current (already
        # encrypted) password so already-configured devices keep
        # authenticating without interruption -- an operator can then
        # give them a distinct privacy passphrase via Settings. New
        # identities are required (see server.py's
        # add_snmp_v3_identity) to supply both independently.
        existing_v3_cols = {row[1] for row in conn.execute("PRAGMA table_info(snmp_v3_identities)").fetchall()}
        if "priv_password" not in existing_v3_cols:
            conn.execute("ALTER TABLE snmp_v3_identities ADD COLUMN priv_password TEXT")
            conn.execute("UPDATE snmp_v3_identities SET priv_password = password WHERE priv_password IS NULL")

        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL,
                description TEXT,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # TIME MACHINE METADATA
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS archive_metadata (
                filename TEXT PRIMARY KEY,
                location TEXT,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        if os.path.exists(DEFAULTS_PATH):
            with open(DEFAULTS_PATH, 'r') as f:
                defaults = json.load(f)

            for key, data in defaults.items():
                cursor.execute("SELECT setting_value FROM app_settings WHERE setting_key = ?", (key,))
                row = cursor.fetchone()
                if not row:
                    default_val = str(data.get("value", ""))
                    # INSERT OR IGNORE, not a plain INSERT -- netlanvas_core
                    # and netlanvas_api are separate processes that both
                    # run this bootstrap independently at startup, racing
                    # against the same config.db. The SELECT above and
                    # this INSERT are not atomic together, so another
                    # process can insert this exact key in the gap
                    # between them. A plain INSERT would then hit the
                    # UNIQUE constraint on setting_key and abort the
                    # entire remaining loop (the caller's retry wrapper
                    # would otherwise just re-run this same race). OR
                    # IGNORE makes losing that race a harmless no-op
                    # instead.
                    cursor.execute('INSERT OR IGNORE INTO app_settings (setting_key, setting_value, description) VALUES (?, ?, ?)',
                                   (key, default_val, data.get("description", "")))

        cursor.execute("SELECT setting_value FROM app_settings WHERE setting_key = 'VERBOSE_LOGGING'")
        res = cursor.fetchone()
        verbose = res[0].lower() in ('true', '1', 'yes') if res else True

        conn.commit()
        conn.close()
        return verbose

    def _initialize_logging(self, verbose: bool):
        self._verbose_mode = verbose

        console_handler = logging.StreamHandler()
        file_handler = logging.handlers.TimedRotatingFileHandler(self.LOG_FILE_PATH, when="D", interval=1, backupCount=2)
        
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S", 
            force=True,
            handlers=[console_handler, file_handler]
        )
        
        root_logger.info("==================================================================")
        root_logger.info("                NETLANVAS APPLIANCE INITIALIZING                  ")
        root_logger.info("==================================================================")
        if self._verbose_mode:
            logger.debug(f"[*] Verbose logging verified. DB_PATH: {self.DB_PATH}")
            logger.debug(f"[*] Configuration Control Plane: {self.CONFIG_DB_PATH}")

    def _get_setting(self, key, fallback=None):
        try:
            conn = sqlite3.connect(self.CONFIG_DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT setting_value FROM app_settings WHERE setting_key = ?", (key,))
            result = cursor.fetchone()
            conn.close()
            value = result[0] if result else fallback

            if self._verbose_mode and key != "VERBOSE_LOGGING":
                logger.debug(f"[CONFIG READ] Key: {key} -> Value: {_debug_value_repr(value)}")
            return value
        except:
            if self._verbose_mode and key != "VERBOSE_LOGGING":
                logger.debug(f"[CONFIG READ FAULT] Key: {key} -> Resorting to fallback: {fallback}")
            return fallback

    def _set_setting(self, key, value, description=None):
        if self._verbose_mode: logger.debug(f"[CONFIG WRITE] Modifying Key: {key} -> New Value: {_debug_value_repr(value)}")
        try:
            conn = sqlite3.connect(self.CONFIG_DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO app_settings (setting_key, setting_value, description, last_updated)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, last_updated=CURRENT_TIMESTAMP
            ''', (key, str(value), description))
            conn.commit()
            conn.close()
            
            if key == 'VERBOSE_LOGGING':
                self._verbose_mode = str(value).lower() in ('true', '1', 'yes')
                logger.debug(f"[CONFIG STATE] Runtime verbosity dynamically updated to: {self._verbose_mode}")
        except Exception as e: logger.error(f"Failed to update setting {key}: {e}")

    @property
    def VERBOSE_LOGGING(self): return self._get_setting("VERBOSE_LOGGING", "true").lower() in ('true', '1', 'yes')
    @property
    def SNMP_COMMUNITY(self): return self._get_setting("SNMP_COMMUNITY_STRING", "public")
    @property
    def SNMP_TRY_PUBLIC(self): return self._get_setting("SNMP_TRY_PUBLIC_COMMUNITY", "true").lower() in ('true', '1', 'yes')
    @property
    def SNMP_COMMUNITIES(self):
        raw = self.SNMP_COMMUNITY
        comms = [c.strip() for c in raw.split(',') if c.strip()]
        if self.SNMP_TRY_PUBLIC and "public" not in comms: comms.append("public")
        if self._verbose_mode:
            # Match snmp_credential.py's display_label() masking convention
            # -- these are live SNMP credentials, not safe to log in full.
            masked = [f"{c[:2]}***" if c else "?" for c in comms]
            logger.debug(f"[CONFIG ARRAY] Assembled SNMP Community Chain: {masked}")
        return comms
    @property
    def HTTP_USER_AGENT(self): return self._get_setting("HTTP_USER_AGENT", "Mozilla/5.0")
    @property
    def OUI_URL(self): return self._get_setting("IEEE_OUI_URL", "")
    @property
    def OUI28_URL(self): return self._get_setting("IEEE_OUI28_URL", "")
    @property
    def OUI36_URL(self): return self._get_setting("IEEE_OUI36_URL", "")
    @property
    def ENTERPRISE_NUMBERS_URL(self): return self._get_setting("IANA_ENTERPRISE_NUMBERS_URL", "")
    @property
    def WIFI_STRICT_MODE(self): return self._get_setting("WIFI_STRICT_MODE", "false").lower() in ('true', '1', 'yes')
    @property
    def DB_ARCHIVE_ON_BOOT(self): return self._get_setting("DB_ARCHIVE_ON_BOOT", "false").lower() in ('true', '1', 'yes')

config = RuntimeConfig()
