"""
scheduler.py

Orchestrates WHEN the Community Telemetry Pipeline actually sends data
or asks the user for something, per netlanvas-telemetry-pipeline-v6
S11. Three entry points, all called from main.py's tick loop:

- on_tick_10(): once per process boot, when the tick-10 log-sample
  capture window closes. Fires the first submission immediately if
  already opted in.
- maybe_send_daily(): the periodic (~daily) structured-payload send,
  same "runs every tick, sends at most once per interval" shape as
  main.py's own maybe_send_telemetry_heartbeat().
- should_nag_now() / mark_nagged(): read/write pair for whatever
  new API endpoint the frontend polls to decide whether to show the
  shared registration/telemetry nag modal (design doc S11).
"""

import datetime
import logging
import time

from telemetry import log_sampler, payload_builder, submitter

logger = logging.getLogger("Netlanvas.Telemetry.Scheduler")

_DAILY_INTERVAL_SECONDS = 24 * 3600
_last_daily_sent_at = 0.0

_LAST_NAGGED_SETTING_KEY = "_TELEMETRY_LAST_NAGGED"


def _submit_telemetry_enabled(config) -> bool:
    return str(config._get_setting("SUBMIT_TELEMETRY", "false")).lower() in ("true", "1", "yes")


def on_tick_10(config, network_db_path: str, log_start_offset: int) -> None:
    """
    Call once, when tick_counter reaches 10 for the first time this
    process boot. Finalizes the log sample regardless of opt-in status
    (it's also needed for the Preview page's left pane) -- only the
    SEND is opt-in-gated.
    """
    log_sampler.finalize_capture(config, network_db_path, log_start_offset)

    if not _submit_telemetry_enabled(config):
        return

    instance_id = config._get_setting("INSTANCE_ID")
    if not instance_id:
        return  # first-boot telemetry hasn't run yet this cycle -- nothing to attribute this send to

    payload = payload_builder.build_payload(config, network_db_path)
    if not payload.get("devices"):
        return  # nothing discovered yet this boot -- see maybe_send_daily's identical guard

    payload["log_sample"] = log_sampler.get_stored_sample(config)
    submitter.submit(instance_id, payload)


def maybe_send_daily(config, network_db_path: str) -> None:
    """
    Cheap check every tick (same shape as main.py's own
    maybe_send_telemetry_heartbeat), actually sends at most once per
    _DAILY_INTERVAL_SECONDS.

    Attaches a log sample too -- the official tick-10 one if it exists
    (get_stored_sample), otherwise a fresh on-demand tail-of-the-log
    scrub (get_preview_sample), same fallback the Preview page uses.
    Originally this only rode along with the tick-10 first send; found
    live 2026-09-03 that this left every daily send with nothing to
    cross-validate against on any instance where tick 10 hadn't
    completed yet this restart (confirmed: two real production
    submissions, both from this function, both missing log_sample
    entirely) -- exactly the data the payload/log cross-validation
    needs on every submission, not just the rare tick-10 one.

    _last_daily_sent_at resets to 0.0 on every process restart (it's
    an in-memory global, not persisted), so this fires on the very
    first tick after every boot -- including right after a
    version-bump boot's "Clean Slate" DB purge, before discovery has
    populated anything. Found live 2026-09-03: the v3.10.0 production
    redeploy's first tick sent a payload with an empty devices list,
    which the server correctly rejects (missing_devices) -- wasting a
    handshake and logging a confusing "submission failed" line for a
    send that was never going to have anything to report. Skipping
    when there's nothing to report yet means the very next tick that
    does have devices sends normally (this function doesn't record
    _last_daily_sent_at on skip, so it isn't throttled).

    _last_daily_sent_at is now set as soon as a real attempt is made
    (right before calling submitter.submit()), not only on success
    (2026-09-08 fix -- found live: a real customer's daily send was
    failing server-side cross-validation every time due to a separate
    corrupted-log-sample bug, and because this only throttled on
    success, that failure retried on literally EVERY tick thereafter
    with no backoff at all -- hundreds of attempts a day against the
    public endpoint, not the intended "at most once daily" cadence.
    The empty-devices skip above is unaffected and still doesn't
    throttle, since that's a deliberate "try again next tick" case,
    not a failure.
    """
    global _last_daily_sent_at

    if not _submit_telemetry_enabled(config):
        return

    now = time.time()
    if now - _last_daily_sent_at < _DAILY_INTERVAL_SECONDS:
        return

    instance_id = config._get_setting("INSTANCE_ID")
    if not instance_id:
        return

    payload = payload_builder.build_payload(config, network_db_path)
    if not payload.get("devices"):
        return  # nothing discovered yet this boot -- try again next tick, don't burn a handshake on an empty report

    log_sample = log_sampler.get_stored_sample(config)
    if not log_sample:
        log_sample = log_sampler.get_preview_sample(config, network_db_path)
    payload["log_sample"] = log_sample

    _last_daily_sent_at = now  # throttle on ATTEMPT, not just success -- see docstring above
    submitter.submit(instance_id, payload)


def should_nag_now(config, is_registered: bool) -> bool:
    """
    True if either ask (registration, telemetry opt-in) is still
    outstanding AND the shared nag modal hasn't already been shown
    today. Does not itself record that the nag fired -- call
    mark_nagged() once the caller actually shows it (a page load that
    checks this isn't the same as the modal actually being displayed).
    """
    if is_registered and _submit_telemetry_enabled(config):
        return False  # nothing left to ask

    last_nagged = config._get_setting(_LAST_NAGGED_SETTING_KEY)
    today = datetime.date.today().isoformat()
    return last_nagged != today


def mark_nagged(config) -> None:
    config._set_setting(
        _LAST_NAGGED_SETTING_KEY,
        datetime.date.today().isoformat(),
        description="Date the shared registration/telemetry nag modal was last shown -- caps it at once per calendar day.",
    )
