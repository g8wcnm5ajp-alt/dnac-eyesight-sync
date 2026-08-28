"""
Daily "Automate Switch Sync" scheduler -- a daemon thread polling every
30s, same self-rolled pattern as forescout-lookup's app.py (scheduled
debug jobs / Advanced Trace auto-revert): fewer moving parts to trust
than pulling in APScheduler for what's really just "does the wall-clock
HH:MM match, and haven't we already fired today."
"""
import logging
import threading
import time
from datetime import datetime, timezone

from sync_engine import load_config, run_sync

POLL_SECONDS = 30

_last_fired_date = None
_lock = threading.Lock()


def _scheduler_loop():
    global _last_fired_date
    while True:
        try:
            cfg = load_config()
            sched = cfg.get("schedule", {})
            if sched.get("enabled"):
                now = datetime.now(timezone.utc)
                today = now.date()
                target = sched.get("time", "")
                try:
                    target_h, target_m = (int(p) for p in target.split(":", 1))
                except (ValueError, AttributeError):
                    target_h = target_m = None
                with _lock:
                    already_fired_today = _last_fired_date == today
                if (
                    target_h is not None
                    and not already_fired_today
                    and now.hour == target_h
                    and now.minute == target_m
                ):
                    logging.info("Scheduler: firing daily sync (target %s UTC).", target)
                    with _lock:
                        _last_fired_date = today
                    run_sync(triggered_by="scheduled")
        except Exception:
            logging.exception("Scheduler loop error -- will retry next poll.")
        time.sleep(POLL_SECONDS)


def start_scheduler():
    thread = threading.Thread(target=_scheduler_loop, daemon=True)
    thread.start()
    return thread
