import sqlite3
import re
import os
import logging
import datetime

logger = logging.getLogger("Netlanvas.OUI")
DB_PATH = os.getenv("DB_PATH", "/app/db/network.db")
OUI_FILE = os.path.join(os.path.dirname(DB_PATH), "oui.txt")
# OUI-1 (2026-09-06): IEEE's classic MA-L registry (oui.txt, 24-bit
# assignments) is only one of three registries it publishes -- MA-M
# (oui28/mam.txt, 28-bit) and MA-S (oui36/oui36.txt, 36-bit) exist
# because IEEE ran out of MA-L space years ago and now issues smaller
# blocks to newer/lower-volume registrants, exactly the kind of budget
# IoT/consumer hardware turning up in real telemetry. A MAC in one of
# these blocks was previously "Unknown Hardware" forever, independent
# of how fresh oui.txt was kept -- a missing data source, not a
# staleness bug. Confirmed live against IEEE's real files: the SAME
# 3-byte OUI prefix is shared by multiple DIFFERENT vendors in both
# files, each owning a specific sub-range of the remaining bytes (e.g.
# "C8-5C-E2 (hex)" appears twice, once for a 700000-7FFFFF range and
# once for A00000-AFFFFF) -- so unlike MA-L, matching these needs a
# range containment check, not a flat OUI lookup.
OUI28_FILE = os.path.join(os.path.dirname(DB_PATH), "oui28.txt")
OUI36_FILE = os.path.join(os.path.dirname(DB_PATH), "oui36.txt")
# ENT-1 (2026-09-07): every MAC-based lookup above (MA-L/M/S, plus the
# locally-administered-bit check) is structurally blind on a privacy-
# randomized MAC -- it was never drawn from any vendor's block, so no
# amount of OUI data helps. SNMP's sysObjectID is a SEPARATE identity
# signal entirely: it's set by firmware under the vendor's own IANA
# Private Enterprise Number (iso.org.dod.internet.private.enterprise,
# 1.3.6.1.4.1.<id>), unrelated to the interface's MAC. snmp_pipeline.py
# already queries it (step 20) and fingerprinter.py already reads it
# per-target (as the SNMP-alive gate) -- it just never got resolved to
# a vendor NAME. Three existing pipeline steps (60/70/80) already
# substring-match specific known IDs (14823 Aruba, 11863 TP-Link,
# 41112 Ubiquiti) for capability detection; this generalizes that same
# fact for vendor display instead of three hardcoded special cases.
ENTERPRISE_FILE = os.path.join(os.path.dirname(DB_PATH), "enterprise-numbers.txt")

def ensure_oui_index():
    """Safety check: Ensures the oui_index tables exist and are populated."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='oui_index'")
    table_exists = cursor.fetchone()[0] == 1

    needs_build = True
    if table_exists:
        cursor.execute("SELECT count(*) FROM oui_index")
        if cursor.fetchone()[0] > 0:
            needs_build = False

    cursor.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='oui_extended_index'")
    ext_table_exists = cursor.fetchone()[0] == 1
    ext_needs_build = True
    if ext_table_exists:
        cursor.execute("SELECT count(*) FROM oui_extended_index")
        if cursor.fetchone()[0] > 0:
            ext_needs_build = False

    conn.close()

    if needs_build:
        if os.path.exists(OUI_FILE):
            logger.info(f"OUI Index is missing or empty. Building from {OUI_FILE}...")
            parse_and_import_oui(OUI_FILE)
        else:
            logger.warning(f"Missing {OUI_FILE}! Creating empty OUI table to prevent crash.")
            conn = sqlite3.connect(DB_PATH)
            conn.execute('CREATE TABLE IF NOT EXISTS oui_index (oui TEXT PRIMARY KEY, vendor_name TEXT)')
            conn.commit()
            conn.close()

    if ext_needs_build:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('CREATE TABLE IF NOT EXISTS oui_extended_index (oui TEXT, range_start INTEGER, range_end INTEGER, vendor_name TEXT, source TEXT)')
        conn.commit()
        conn.close()
        for f, label in ((OUI28_FILE, "MA-M"), (OUI36_FILE, "MA-S")):
            if os.path.exists(f):
                logger.info(f"Extended OUI Index is missing or empty. Building from {f}...")
                parse_and_import_extended_oui(f, label)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='enterprise_index'")
    ent_table_exists = cursor.fetchone()[0] == 1
    ent_needs_build = True
    if ent_table_exists:
        cursor.execute("SELECT count(*) FROM enterprise_index")
        if cursor.fetchone()[0] > 0:
            ent_needs_build = False
    conn.close()

    if ent_needs_build:
        if os.path.exists(ENTERPRISE_FILE):
            logger.info(f"Enterprise-number index is missing or empty. Building from {ENTERPRISE_FILE}...")
            parse_and_import_enterprise_numbers(ENTERPRISE_FILE)
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.execute('CREATE TABLE IF NOT EXISTS enterprise_index (enterprise_id TEXT PRIMARY KEY, org_name TEXT)')
            conn.commit()
            conn.close()

def parse_and_import_oui(file_path):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS oui_index (oui TEXT PRIMARY KEY, vendor_name TEXT)')
    cursor.execute('DELETE FROM oui_index')

    # Matches: 28-6F-B9   (hex)       Nokia Shanghai Bell Co., Ltd.
    pattern = re.compile(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)$')

    count = 0
    try:
        with open(file_path, 'r', encoding='latin-1') as f:
            for line in f:
                match = pattern.match(line)
                if match:
                    oui_raw, vendor = match.groups()
                    oui_normalized = oui_raw.replace('-', '')
                    cursor.execute('INSERT OR IGNORE INTO oui_index VALUES (?, ?)', (oui_normalized, vendor.strip()))
                    count += 1
        conn.commit()
        logger.info(f"Success! Imported {count} OUI records.")
    except Exception as e:
        logger.error(f"Failed to process OUI file: {e}")
    finally:
        conn.close()

def parse_and_import_extended_oui(file_path, source="MA-M"):
    """
    OUI-1: parses IEEE's MA-M/MA-S format -- both files share the same
    shape, just different range widths (MA-M: 0x100000-wide, 20 free
    bits; MA-S: 0x1000-wide, 12 free bits), so one parser handles both,
    distinguished only by the `source` label. Each entry is TWO lines:
    the OUI "(hex)" line (same 3-byte format as MA-L), immediately
    followed by the "(base 16)" range line for that specific vendor's
    slice of the remaining bytes. Deletes only THIS source's prior rows
    before inserting -- refreshing MA-M must never touch MA-S rows (or
    vice versa), whether this is the first-boot build or a periodic
    30-day refresh of just one of the two files.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS oui_extended_index (oui TEXT, range_start INTEGER, range_end INTEGER, vendor_name TEXT, source TEXT)')
    cursor.execute('DELETE FROM oui_extended_index WHERE source = ?', (source,))

    hex_pattern = re.compile(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)$')
    range_pattern = re.compile(r'^([0-9A-F]{6})-([0-9A-F]{6})\s+\(base 16\)')

    count = 0
    try:
        with open(file_path, 'r', encoding='latin-1') as f:
            lines = f.readlines()
        i = 0
        while i < len(lines):
            hex_match = hex_pattern.match(lines[i])
            if hex_match and i + 1 < len(lines):
                range_match = range_pattern.match(lines[i + 1])
                if range_match:
                    oui_raw, vendor = hex_match.groups()
                    oui_normalized = oui_raw.replace('-', '')
                    range_start = int(range_match.group(1), 16)
                    range_end = int(range_match.group(2), 16)
                    cursor.execute(
                        'INSERT INTO oui_extended_index (oui, range_start, range_end, vendor_name, source) VALUES (?, ?, ?, ?, ?)',
                        (oui_normalized, range_start, range_end, vendor.strip(), source),
                    )
                    count += 1
                    i += 2
                    continue
            i += 1
        conn.commit()
        logger.info(f"Success! Imported {count} extended (MA-M/MA-S) OUI records from {file_path}.")
    except Exception as e:
        logger.error(f"Failed to process extended OUI file {file_path}: {e}")
    finally:
        conn.close()

# OUI-1: IEEE reserves an entire MA-L (24-bit) block under this exact
# placeholder name specifically so it can be subdivided into smaller
# MA-M/MA-S assignments -- confirmed live, real OUIs like C8-5C-E2 and
# 8C-1F-64 show this generic string in oui.txt itself, NOT a real
# vendor. Without checking for it, a subdivided block's device would
# always get the placeholder before ever reaching the extended-range
# lookup that actually knows the real vendor.
_RESERVED_FOR_SUBDIVISION = "IEEE Registration Authority"

def is_locally_administered(mac_address):
    """
    OUI-2 (2026-09-06): the locally-administered bit (bit 1 of the
    first octet, 0x02) marks a MAC as either intentionally hand-
    assigned or, increasingly commonly, a per-network PRIVACY-
    RANDOMIZED address (iOS/Android and modern Windows/macOS all
    default to this now for Wi-Fi). Either way, an OUI lookup against
    it is meaningless by construction -- it was never drawn from any
    vendor's registered block. Checked first, before any DB lookup, so
    a coincidental accidental match against a real OUI can't happen.
    """
    try:
        first_octet = int(mac_address.split(':')[0].split('-')[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False

def get_vendor_info(mac_address):
    """
    OUI-3 (2026-09-06): structured counterpart to a plain vendor-string
    lookup -- every OTHER enrichment source in this codebase (SSDP,
    mDNS, NSDP/ESCP) already returns vendor+model+confidence-shaped
    data; plain OUI lookup was the one foundational signal that only
    ever produced a bare string.

    Returns {"vendor": str, "source": str, "confidence": str, and, if a
    Premium classification is cached for this OUI (see
    save_premium_classifications() below), "category": str and
    "market_segment": str}.
    source is one of: "randomized" (locally-administered MAC, no OUI
    lookup attempted), "MA-L" (classic 24-bit exact match), "MA-M"/
    "MA-S" (28/36-bit range match), "reserved" (MA-L says this block is
    subdivided, but no MA-M/MA-S entry in our table covers this
    specific device's range), or "unmatched" (no data anywhere).
    confidence is "high" for a real vendor match, "none" otherwise.

    OUI-4 (2026-09-09): every caller now goes through this function
    directly -- category/market_segment were being computed correctly
    but silently discarded, since the only actual callers all used a
    since-removed get_vendor(mac) wrapper that returned just the bare
    vendor string. See fingerprinter.py's update_device_fingerprint().
    """
    if is_locally_administered(mac_address):
        return {"vendor": "Private (Randomized MAC)", "source": "randomized", "confidence": "none"}

    ensure_oui_index()
    clean_mac = mac_address.upper().replace(':', '').replace('-', '')
    oui = clean_mac[:6]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT vendor_name FROM oui_index WHERE oui = ?', (oui,))
    result = cursor.fetchone()
    if result and result[0] != _RESERVED_FOR_SUBDIVISION:
        base = {"vendor": result[0], "source": "MA-L", "confidence": "high"}
    else:
        base = None

    # MA-L miss, or MA-L only has the generic subdivision placeholder --
    # check the MA-M/MA-S range table for a more specific match.
    # remainder is the device-specific low bits (last 3 bytes), matched
    # against whichever vendor's declared range contains it.
    if base is None and len(clean_mac) >= 12:
        try:
            remainder = int(clean_mac[6:12], 16)
            cursor.execute(
                'SELECT vendor_name, source FROM oui_extended_index WHERE oui = ? AND ? BETWEEN range_start AND range_end',
                (oui, remainder),
            )
            ext_result = cursor.fetchone()
            if ext_result:
                base = {"vendor": ext_result[0], "source": ext_result[1], "confidence": "high"}
        except ValueError:
            pass

    if base is None:
        if result:
            # MA-L confirmed this block IS reserved for subdivision, we
            # just don't have THIS specific sub-range on file -- more
            # honest than silently showing the generic placeholder as
            # if it were real.
            base = {"vendor": "Unknown Hardware", "source": "reserved", "confidence": "none"}
        else:
            base = {"vendor": "Unknown Hardware", "source": "unmatched", "confidence": "none"}

    # OUI-2 (2026-09-08): layer in Premium-tier category/market_segment
    # data if this appliance has ever received any for this OUI (see
    # save_premium_classifications() -- populated from the entitlement-
    # gated block in the telemetry submission ack, OUI-3 webhost-side).
    # Purely additive -- never overrides vendor/source/confidence above,
    # since this is a genuinely different signal (device CATEGORY, not
    # vendor identity) layered on top regardless of which OUI-1/8/18-22
    # source actually resolved the vendor name.
    premium = _get_premium_classification(cursor, oui)
    if premium:
        base["category"] = premium[0]
        base["market_segment"] = premium[1]

    conn.close()
    return base


_PREMIUM_TABLE_READY = False


def _ensure_premium_classifications_table(cursor):
    global _PREMIUM_TABLE_READY
    if _PREMIUM_TABLE_READY:
        return
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS premium_oui_classifications (
            oui TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            market_segment TEXT NOT NULL,
            confidence TEXT NOT NULL,
            cached_at TEXT NOT NULL
        )
    ''')
    _PREMIUM_TABLE_READY = True


def _get_premium_classification(cursor, oui):
    """Returns (category, market_segment) or None. Table may not exist
    yet on a fresh install that's never received any -- checked lazily
    rather than unconditionally creating it on every single vendor
    lookup, since most lookups (the vast majority of installs, which
    aren't entitled to Premium data at all) will never need it."""
    try:
        cursor.execute('SELECT category, market_segment FROM premium_oui_classifications WHERE oui = ?', (oui,))
        return cursor.fetchone()
    except sqlite3.OperationalError:
        return None


def save_premium_classifications(classifications: dict) -> int:
    """
    OUI-2: persists the classification block from a telemetry
    submission's ack response (submitter.py's submit(), OUI-3
    webhost-side) into a local cache get_vendor_info() reads from.
    `classifications` is {oui: {"category": ..., "market_segment": ...,
    "confidence": ...}}, already validated/whitelisted server-side to
    only ever carry the closed-set enum fields -- no raw LLM text ever
    reaches this appliance. Silently no-ops on an empty/missing block
    (the common case: most accounts aren't entitled, and even entitled
    ones often have nothing new resolved yet).

    Returns the number of entries saved.
    """
    if not classifications:
        return 0
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    _ensure_premium_classifications_table(cursor)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    saved = 0
    for oui, data in classifications.items():
        if not isinstance(data, dict) or 'category' not in data or 'market_segment' not in data:
            continue
        cursor.execute(
            '''INSERT INTO premium_oui_classifications (oui, category, market_segment, confidence, cached_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(oui) DO UPDATE SET category=excluded.category, market_segment=excluded.market_segment,
                   confidence=excluded.confidence, cached_at=excluded.cached_at''',
            (oui.upper(), data['category'], data['market_segment'], data.get('confidence', 'high'), now),
        )
        saved += 1
    conn.commit()
    conn.close()
    if saved:
        logger.info(f"[*] OUI-2: cached {saved} Premium vendor classification(s) from telemetry ack.")
    return saved

def parse_and_import_enterprise_numbers(file_path):
    """
    ENT-1: parses IANA's private-enterprise-numbers.txt. Confirmed live
    against the real file (2026-09-07): each entry is a bare numeric ID
    line at column 0, immediately followed by a 2-space-indented
    organization-name line, then two more indented lines (contact name,
    contact email) this parser skips -- e.g. enterprise 9 is followed
    by "  ciscoSystems". ~66k entries, single source, so unlike the
    MA-M/MA-S split this is a full-table replace on every refresh.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS enterprise_index (enterprise_id TEXT PRIMARY KEY, org_name TEXT)')
    cursor.execute('DELETE FROM enterprise_index')

    id_pattern = re.compile(r'^(\d+)$')
    count = 0
    try:
        with open(file_path, 'r', encoding='latin-1') as f:
            lines = f.readlines()
        i = 0
        while i < len(lines):
            id_match = id_pattern.match(lines[i].rstrip('\n'))
            if id_match and i + 1 < len(lines):
                org_line = lines[i + 1]
                if org_line.startswith('  ') and not org_line.startswith('    '):
                    org_name = org_line.strip()
                    if org_name:
                        cursor.execute('INSERT OR IGNORE INTO enterprise_index VALUES (?, ?)', (id_match.group(1), org_name))
                        count += 1
                    i += 2
                    continue
            i += 1
        conn.commit()
        logger.info(f"Success! Imported {count} IANA enterprise-number records.")
    except Exception as e:
        logger.error(f"Failed to process enterprise-numbers file {file_path}: {e}")
    finally:
        conn.close()

_SYSOBJECTID_ENTERPRISE_RE = re.compile(r'1\.3\.6\.1\.4\.1\.(\d+)')

def get_vendor_from_sysobjectid(sys_object_id_raw):
    """
    ENT-1: resolves a raw sysObjectID SNMP response (a walk-result list
    or plain string, e.g. containing "...1.3.6.1.4.1.9.1.516...") to a
    vendor NAME via the IANA enterprise-number registry -- deliberately
    independent of MAC, so it works precisely where get_vendor_info() can't:
    a locally-administered/randomized MAC, or a device in an OUI block
    IEEE hasn't published/we haven't refreshed. Returns None (never a
    placeholder string) on no match or no sysObjectID, so callers can
    cleanly prefer their existing MAC-based vendor over a None instead
    of overwriting a real answer with a lookup miss.
    """
    if not sys_object_id_raw:
        return None
    haystack = sys_object_id_raw if isinstance(sys_object_id_raw, str) else " ".join(sys_object_id_raw)
    match = _SYSOBJECTID_ENTERPRISE_RE.search(haystack)
    if not match:
        return None

    ensure_oui_index()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT org_name FROM enterprise_index WHERE enterprise_id = ?', (match.group(1),))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None
