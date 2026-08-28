"""
DNAC -> Eyesight reconciliation engine, plus config/history/log persistence.

Design decisions (confirmed with David during planning, 2026-08-28):

  - Diffs DNAC's *current* device list directly against Eyesight's
    *current* live switch list -- no locally cached "last response"
    snapshot (the original script's approach). Self-healing: a run
    that fails partway, or a switch added/removed by hand in Eyesight
    between runs, can't leave a stale local cache out of sync with
    reality, because there is no local cache of what Eyesight has.

  - Switch-manager (appliance) assignment is a stable hash of the
    switch's IP, not random.randint() per run (the original
    behavior) -- a given switch always lands on the same managing
    appliance once assigned, instead of bouncing across runs.

  - Switch-profile assignment keeps the original regex-rules format
    (newline-separated "regex|profilename", first match wins, matched
    against "<ip>,<hostname>") but makes "nothing matched" an explicit,
    reported condition instead of silently reusing whatever the last
    rule in the list happened to be.
"""
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone

from dnac_client import DnacClient, DnacClientError
from eyesight_client import EyesightClient, EyesightClientError

DATA_DIR = os.environ.get("DNAC_EYESIGHT_DATA_DIR", "/data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
HISTORY_PATH = os.path.join(DATA_DIR, "history.json")
LOG_DIR = os.path.join(DATA_DIR, "logs")

DEFAULT_CONFIG = {
    "dnac": {
        "url": "", "username": "", "password": "", "family_filter": ".*Switches.*",
        "page_limit": 400, "ssl_verify": False,
    },
    "eyesight": {
        "url": "", "username": "", "password": "", "ssl_verify": False, "trim_or_delete": "Trim",
    },
    "switch_managers": [],
    "switch_profiles": "",
    "proxy": {"enable": False, "ip": "", "port": "", "username": "", "password": ""},
    "general": {"log_level": "INFO", "retention_days": 30},
    "schedule": {"enabled": False, "time": "02:00"},
}


class SyncEngineError(Exception):
    pass


def _ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)


def load_config():
    _ensure_dirs()
    if not os.path.isfile(CONFIG_PATH):
        save_config(DEFAULT_CONFIG)
        return json.loads(json.dumps(DEFAULT_CONFIG))
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    # Merge in any keys added to DEFAULT_CONFIG since this file was last saved --
    # keeps older config.json files (from before a new section was added) working
    # without a manual migration step.
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    for section, defaults in DEFAULT_CONFIG.items():
        if section in cfg:
            if isinstance(defaults, dict):
                merged[section] = {**defaults, **cfg[section]}
            else:
                merged[section] = cfg[section]
    return merged


def save_config(cfg):
    _ensure_dirs()
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


def _load_history():
    if not os.path.isfile(HISTORY_PATH):
        return []
    try:
        with open(HISTORY_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _save_history(entries):
    tmp = HISTORY_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(entries, f, indent=2)
    os.replace(tmp, HISTORY_PATH)


def get_history():
    return sorted(_load_history(), key=lambda e: e["timestamp"], reverse=True)


def _prune_old_logs(retention_days):
    """Deletes log files (and their history entries) older than retention_days --
    David's ask: avoid filling up disk space with old run logs."""
    cutoff = time.time() - retention_days * 86400
    entries = _load_history()
    kept = []
    for e in entries:
        if e["timestamp"] < cutoff:
            log_path = os.path.join(LOG_DIR, e.get("log_file", ""))
            if e.get("log_file") and os.path.isfile(log_path):
                try:
                    os.remove(log_path)
                except OSError:
                    pass
            continue
        kept.append(e)
    if len(kept) != len(entries):
        _save_history(kept)


def _stable_manager_for_ip(ip, managers):
    """Deterministic pick from the manager list -- same IP always maps to the same
    manager as long as the manager list itself doesn't change (a stable hash, not
    Python's own hash() which is randomized per-process for strings)."""
    if not managers:
        return None
    digest = hashlib.md5(ip.encode("utf-8")).hexdigest()
    idx = int(digest, 16) % len(managers)
    return managers[idx]


def _profile_for(ip, hostname, switch_profiles_text):
    """Returns (profile_name, matched_rule) or (None, None) if nothing matched --
    the "nothing matched" case is now explicit (the original script silently fell
    through to whatever the last-tried rule's name was)."""
    subject = f"{ip},{hostname or ''}"
    for line in (switch_profiles_text or "").splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        pattern, _, profile_name = line.partition("|")
        try:
            if re.search(pattern, subject):
                return profile_name, line
        except re.error:
            continue  # malformed pattern in this rule -- skip it, don't abort the whole run
    return None, None


def run_sync(triggered_by="manual", dry_run=False):
    """Runs one full reconcile pass. Always writes a history entry + log file, even
    on failure, so a broken config/credential shows up in History rather than just
    vanishing. Returns the history entry dict."""
    _ensure_dirs()
    cfg = load_config()
    started_at = time.time()
    log_lines = []

    def log(msg):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        log_lines.append(f"{ts}  {msg}")
        logging.info(msg)

    summary = {
        "dnac_count": 0, "eyesight_count": 0, "added": 0, "removed": 0,
        "unchanged": 0, "profile_unmatched": [], "success": False, "error": None,
    }

    try:
        log(f"Sync started (triggered_by={triggered_by}, dry_run={dry_run})")

        dnac = DnacClient(
            cfg["dnac"]["url"], cfg["dnac"]["username"], cfg["dnac"]["password"],
            ssl_verify=cfg["dnac"]["ssl_verify"], proxy_cfg=cfg["proxy"],
        )
        eyesight = EyesightClient(
            cfg["eyesight"]["url"], cfg["eyesight"]["username"], cfg["eyesight"]["password"],
            verify_ssl=cfg["eyesight"]["ssl_verify"],
        )

        log("Authenticating to DNAC...")
        dnac.authenticate()
        log("Authenticating to Eyesight...")
        eyesight.authenticate()

        log(f"Pulling device list from DNAC (family={cfg['dnac']['family_filter']!r})...")
        dnac_devices = dnac.list_devices(
            family_filter=cfg["dnac"]["family_filter"], page_limit=cfg["dnac"]["page_limit"],
        )
        summary["dnac_count"] = len(dnac_devices)
        log(f"DNAC returned {len(dnac_devices)} device(s).")

        log("Pulling current switch list from Eyesight...")
        eyesight_switches = eyesight.get_switch_summary()
        summary["eyesight_count"] = len(eyesight_switches)
        eyesight_ips = {s["managementAddress"] for s in eyesight_switches if s.get("managementAddress")}
        log(f"Eyesight currently has {len(eyesight_switches)} switch(es).")

        dnac_ips = set()
        to_add = []
        managers = cfg["switch_managers"]
        for dev in dnac_devices:
            ip = dev.get("managementIpAddress")
            if not ip:
                continue
            dnac_ips.add(ip)
            if ip in eyesight_ips:
                summary["unchanged"] += 1
                continue  # already present -- exact-equality check (fixed from the original's substring `in` bug)
            profile_name, matched_rule = _profile_for(ip, dev.get("hostname"), cfg["switch_profiles"])
            if profile_name is None:
                summary["profile_unmatched"].append(ip)
                log(f"  SKIP {ip}: no switch-profile rule matched, not adding.")
                continue
            manager = _stable_manager_for_ip(ip, managers)
            if manager is None:
                summary["profile_unmatched"].append(ip)
                log(f"  SKIP {ip}: no switch managers configured, not adding.")
                continue
            to_add.append({
                "comment": dev.get("hostname", ""),
                "connectingAppliance": manager,
                "managementAddress": ip,
                "profileName": profile_name,
            })
            log(f"  ADD {ip} (hostname={dev.get('hostname')!r}, profile={profile_name!r}, manager={manager})")

        # Anything in Eyesight that DNAC no longer reports gets removed in both
        # modes -- "Delete" additionally removes anything DNAC still reports that
        # was ALREADY in Eyesight too (so it gets deleted then re-added fresh with
        # the current manager/profile assignment); "Trim" leaves those alone
        # (to_add already excludes them via the `if ip in eyesight_ips: continue` above).
        gone_from_dnac = eyesight_ips - dnac_ips
        to_delete = list(gone_from_dnac)
        if cfg["eyesight"]["trim_or_delete"] == "Delete":
            already_present_and_still_in_dnac = eyesight_ips & dnac_ips
            to_delete.extend(already_present_and_still_in_dnac)
            for ip in already_present_and_still_in_dnac:
                dev = next((d for d in dnac_devices if d.get("managementIpAddress") == ip), None)
                if dev is None:
                    continue
                profile_name, _ = _profile_for(ip, dev.get("hostname"), cfg["switch_profiles"])
                manager = _stable_manager_for_ip(ip, managers)
                if profile_name and manager:
                    to_add.append({
                        "comment": dev.get("hostname", ""), "connectingAppliance": manager,
                        "managementAddress": ip, "profileName": profile_name,
                    })
                    log(f"  RE-ADD {ip} (Delete mode: removed then re-added with current profile/manager)")

        for ip in gone_from_dnac:
            log(f"  REMOVE {ip}: no longer reported by DNAC.")

        summary["removed"] = len(to_delete)
        summary["added"] = len([a for a in to_add if a not in []])  # count after de-dup below

        # De-dup to_add by managementAddress -- Delete-mode re-adds could otherwise
        # duplicate an entry that was also freshly discovered in the same pass
        # (shouldn't normally happen since eyesight_ips/dnac_ips are disjoint sets
        # per branch, but cheap to guard against).
        seen_ips = set()
        deduped_add = []
        for a in to_add:
            if a["managementAddress"] in seen_ips:
                continue
            seen_ips.add(a["managementAddress"])
            deduped_add.append(a)
        to_add = deduped_add
        summary["added"] = len(to_add)

        if dry_run:
            log(f"Dry run -- would delete {len(to_delete)}, add {len(to_add)}. Not calling Eyesight.")
        else:
            if to_delete:
                log(f"Deleting {len(to_delete)} switch(es) from Eyesight...")
                eyesight.delete_switches(to_delete)
            if to_add:
                log(f"Adding {len(to_add)} switch(es) to Eyesight...")
                eyesight.add_switches(to_add)

        summary["success"] = True
        log("Sync completed successfully.")

    except (DnacClientError, EyesightClientError, SyncEngineError) as e:
        summary["error"] = str(e)
        log(f"ERROR: {e}")
    except Exception as e:
        summary["error"] = f"Unexpected error: {e}"
        log(f"ERROR: {e}")

    finished_at = time.time()
    log_filename = f"run_{int(started_at)}.log"
    with open(os.path.join(LOG_DIR, log_filename), "w") as f:
        f.write("\n".join(log_lines) + "\n")

    entry = {
        "id": f"{int(started_at)}",
        "timestamp": started_at,
        "duration_seconds": round(finished_at - started_at, 1),
        "triggered_by": triggered_by,
        "dry_run": dry_run,
        "log_file": log_filename,
        **summary,
    }
    entries = _load_history()
    entries.append(entry)
    _save_history(entries)
    _prune_old_logs(cfg["general"]["retention_days"])
    return entry


# ---------------------------------------------------------------------
# Manual Manage tab -- David's ask: ad-hoc add/view/remove against the
# live Eyesight REST API without waiting for a scheduled/full sync.
# Each call builds its own short-lived EyesightClient from current
# config, same as run_sync does.
# ---------------------------------------------------------------------
def _eyesight_client_from_config(cfg=None):
    cfg = cfg or load_config()
    return EyesightClient(
        cfg["eyesight"]["url"], cfg["eyesight"]["username"], cfg["eyesight"]["password"],
        verify_ssl=cfg["eyesight"]["ssl_verify"],
    )


def manual_list_switches():
    return _eyesight_client_from_config().get_switch_summary()


def manual_add_switch(ip, profile_name, manager, comment=""):
    if not profile_name:
        raise SyncEngineError("Profile name is required.")
    if not manager:
        raise SyncEngineError("Connecting appliance is required.")
    _eyesight_client_from_config().add_switches([{
        "comment": comment, "connectingAppliance": manager,
        "managementAddress": ip, "profileName": profile_name,
    }])


def manual_remove_switch(ip):
    _eyesight_client_from_config().delete_switches([ip])


def get_log_text(log_file):
    """Reads back one run's log file by name -- validated against the stored
    history entries first, so this can't be used to read an arbitrary path."""
    entries = _load_history()
    if not any(e.get("log_file") == log_file for e in entries):
        raise SyncEngineError("Unknown log file.")
    path = os.path.join(LOG_DIR, log_file)
    if not os.path.isfile(path):
        raise SyncEngineError("Log file no longer exists (pruned).")
    with open(path) as f:
        return f.read()
