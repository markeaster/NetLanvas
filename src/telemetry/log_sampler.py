"""
log_sampler.py

Captures and sanitizes the "first 10 ticks after restart" log sample
for the Community Telemetry Pipeline (netlanvas-telemetry-pipeline-v6
§3/§11). Two different scrubbing strategies for two different kinds of
value:

- IP addresses and MAC addresses have strict, well-defined syntax, so
  they're found via regex pattern-matching directly in the log text
  and fuzzed with the *same* sanitizer.py functions payload_builder.py
  uses -- this is what makes the server-side payload/log
  cross-validation (design doc §6) possible: a device that appears in
  the structured payload gets the same fuzzed MAC/IP wherever it also
  shows up in the log sample.

- Hostnames have no reliable universal syntax to pattern-match against
  free text (unlike IPs/MACs), so rather than guessing "this word looks
  like a hostname" with a regex, this module looks for exact,
  whole-word matches of the REAL hostnames already known from this
  same tick's device query (the exact same source payload_builder.py
  uses) and replaces each with its already-fuzzed counterpart. Safer,
  and again exactly what the cross-validation needs.

Usage from main.py's boot/tick sequence:
    start_offset = log_sampler.start_capture(config)          # at boot
    ...
    if tick_counter == 10:
        scrubbed = log_sampler.finalize_capture(config, config.DB_PATH, start_offset)
"""

import json
import re
from pathlib import Path

from telemetry import sanitizer
from telemetry.payload_builder import query_devices

_LOG_SAMPLE_SETTING_KEY = "_TELEMETRY_LOG_SAMPLE"

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")

# TELEM-1 (2026-09-04): engine/snmp_pipeline.py logs one "[Pipeline-N] ..."
# DEBUG line PER CANDIDATE TARGET it attempts (reachability test, sysObjectID
# extraction, ARP/FDB walk, etc.) -- fired for every IP it tries, whether or
# not that IP ever turns into a confirmed device. Found live: a real user
# ("Chris") with a small, sparse home network had his telemetry submission
# rejected by the webhost's cross-validation check every time (up to
# found=867, matched=46) -- root cause traced to this exact pattern. On a
# dense lab network (the appliance's own primary test environment) almost
# every candidate IP the pipeline tries IS a real device, so the noise is
# invisible; on a sparse home network -- the actual common case for most
# real users -- most candidates never resolve into a device, so the fuzzed
# IPs in these lines vastly outnumber the ones that ever appear in the
# structured device payload, and the server's cross-validation ratio
# (expects most log-mentioned IPs to correlate with real devices) fails.
# These lines are pure "I tried this candidate" scan noise, never an
# assertion that a device was confirmed -- excluded from the telemetry log
# sample entirely rather than tuning the server-side ratio to tolerate an
# unbounded amount of it (which would weaken the check's actual purpose,
# catching a fabricated payload, for every other submission too).
_PIPELINE_PROBE_LINE_RE = re.compile(r"Netlanvas\.Pipeline:\s*\[Pipeline-\d+\]")


def _scrub_ips_and_macs(config, line: str) -> str:
    line = _MAC_RE.sub(lambda m: sanitizer.fuzz_mac(config, m.group(0)), line)
    line = _IP_RE.sub(lambda m: sanitizer.fuzz_ip(config, m.group(0)), line)
    return line


def _scrub_hostnames(config, line: str, real_hostnames: set) -> str:
    for real in real_hostnames:
        if not real:
            continue
        pattern = re.compile(r"\b" + re.escape(real) + r"\b")
        if pattern.search(line):
            line = pattern.sub(sanitizer.fuzz_hostname(config, real), line)
    return line


def scrub_log_lines(config, network_db_path: str, raw_lines: list) -> list:
    """
    Sanitizes a batch of raw log lines. Real hostnames are looked up
    fresh from network.db at scrub time (the same source
    payload_builder.py uses), not cached from earlier -- the log
    sample and the structured payload should describe the same real
    state, since the server-side cross-validation compares them
    against each other.
    """
    device_rows = query_devices(network_db_path)
    real_hostnames = {row["hostname"] for row in device_rows if row["hostname"]}

    scrubbed = []
    for line in raw_lines:
        line = _scrub_ips_and_macs(config, line)
        line = _scrub_hostnames(config, line, real_hostnames)
        scrubbed.append(line)
    return scrubbed


def start_capture(config) -> int:
    """
    Call once at boot, before tick 1. Returns the engine log's current
    end-of-file byte offset, so finalize_capture() knows where "since
    this boot" begins -- avoids re-capturing a previous run's tail.
    Returns 0 if the log file doesn't exist yet (nothing to skip).

    TELEM-4 (found 2026-09-16): also clears _TELEMETRY_LOG_SAMPLE right
    here. Confirmed live: a real submission was rejected server-side
    (telemetry-submit.php's cross_validate_payload_and_logs(),
    log_payload_mismatch, found=37 matched=0) because the stored sample
    was FOUR DAYS old -- get_stored_sample() had been faithfully
    returning a real tick-10 capture from a previous boot on every
    restart since, since nothing ever invalidated it. That silently
    defeated scheduler.py's own "if not log_sample: fall back to
    get_preview_sample()" safeguard, which exists for exactly this
    situation (no real sample yet this boot) but never fired, because
    the stale leftover from days ago is never actually falsy. A boot
    that restarts before ever reaching tick 10 -- trivially reproducible
    just by restarting often, not a contrived edge case -- kept
    resubmitting a sample describing a different topology than the
    devices payload sent alongside it, and cross-validation correctly
    (if confusingly, from a user's perspective) rejected the mismatch
    every time. Clearing here restores that fallback's actual intended
    behavior: empty until genuinely re-captured this boot.
    """
    config._set_setting(
        _LOG_SAMPLE_SETTING_KEY,
        "",
        description="Sanitized first-10-ticks-post-restart log sample for Community Telemetry. Cleared at boot, regenerated once tick 10 completes this same boot.",
    )
    log_path = Path(config.LOG_FILE_PATH)
    if not log_path.exists():
        return 0
    return log_path.stat().st_size


def finalize_capture(config, network_db_path: str, start_offset: int) -> list:
    """
    Call once, at tick 10. Reads every log line written since
    start_offset, scrubs it, persists the result for later use (the
    Preview page's left pane, and main.py's tick-10 first-submission
    trigger -- see design doc §11), and returns the scrubbed lines.
    """
    log_path = Path(config.LOG_FILE_PATH)
    if not log_path.exists():
        raw_lines = []
    else:
        with open(log_path, "r") as f:
            f.seek(start_offset)
            raw_lines = [line.rstrip("\n") for line in f.readlines()]

    # TELEM-1: drop per-candidate pipeline probe noise before scrubbing --
    # see _PIPELINE_PROBE_LINE_RE above for why.
    raw_lines = [line for line in raw_lines if not _PIPELINE_PROBE_LINE_RE.search(line)]

    scrubbed = scrub_log_lines(config, network_db_path, raw_lines)
    config._set_setting(
        _LOG_SAMPLE_SETTING_KEY,
        json.dumps(scrubbed),
        description="Sanitized first-10-ticks-post-restart log sample for Community Telemetry. Regenerated every restart.",
    )
    return scrubbed


def get_stored_sample(config) -> list:
    """The official, once-per-restart tick-10 sample (see finalize_capture), or [] if none exists yet."""
    stored = config._get_setting(_LOG_SAMPLE_SETTING_KEY)
    if not stored:
        return []
    try:
        return json.loads(stored)
    except (ValueError, TypeError):
        return []


def get_preview_sample(config, network_db_path: str, tail_lines: int = 150) -> list:
    """
    For the Preview page before tick 10 has ever completed this
    restart, when get_stored_sample() is still empty. Confirmed
    2026-09-03: a user checking the Preview page early (exactly the
    behavior this whole feature wants to encourage -- inspect before
    opting in) would otherwise see nothing for the log pane until tick
    10, which could be many minutes away.

    Reads the tail of the CURRENT log file directly (not "since this
    boot" -- this function has no access to POLLER's own boot-time
    offset; it's called from the API_VIEWER container, a separate
    process, via the log file the two containers already share
    through the same ./db mount) and scrubs it the same way as the
    official capture. Deliberately NOT persisted to
    _TELEMETRY_LOG_SAMPLE -- this is a live look, not the authoritative
    once-per-restart artifact the submission handshake's cross-
    validation relies on.
    """
    log_path = Path(config.LOG_FILE_PATH)
    if not log_path.exists():
        return []
    with open(log_path, "r") as f:
        raw_lines = [line.rstrip("\n") for line in f.readlines()[-tail_lines:]]
    # TELEM-1: keep the preview consistent with what finalize_capture()
    # actually submits.
    raw_lines = [line for line in raw_lines if not _PIPELINE_PROBE_LINE_RE.search(line)]
    return scrub_log_lines(config, network_db_path, raw_lines)
