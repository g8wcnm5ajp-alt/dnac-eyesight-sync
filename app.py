"""
DNAC-to-Eyesight Switch Sync -- web app.

Pulls the switch inventory from Cisco DNAC and reconciles it into
Forescout Eyesight (add/remove switches so Eyesight's bulk-add never
hits a "already exists" failure). Rebuilt from a CRON-fired script
(ciscodnacapp_library.py) into a Dockerized web app, following the
same pattern as the sibling forescout-lookup Tech Support Collector:
Flask + Docker, Deploy.sh/Remove.sh with a docker bridge network,
login-gated HTTPS. See sync_engine.py for the reconcile logic itself.
"""
import json
import logging
import os
import secrets
import ssl
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from dnac_client import DnacClient, DnacClientError
from eyesight_client import EyesightClient, EyesightClientError
from scheduler import start_scheduler
from sync_engine import (
    DATA_DIR, SyncEngineError, get_history, get_log_text, load_config, manual_add_switch,
    manual_list_switches, manual_remove_switch, run_sync, save_config,
)

app = Flask(__name__)

APP_VERSION = "1.0.0"
DEPLOYED_AT = datetime.now(timezone.utc)

os.makedirs(DATA_DIR, exist_ok=True)

# ---------------------------------------------------------------------
# Login -- identical pattern to forescout-lookup/app.py's Phase D login:
# one Admin account, default password forced to change on first login,
# session-gated via one before_request hook. Ported directly rather
# than reinvented, since this app also stores/uses real DNAC and
# Eyesight credentials via its Config tab and deserves the same bar.
# ---------------------------------------------------------------------
AUTH_PATH = os.path.join(DATA_DIR, "auth.json")
DEFAULT_ADMIN_PASSWORD = "DnacEyesightSync123"

_SECRET_KEY_PATH = os.path.join(DATA_DIR, "secret_key")
if os.path.isfile(_SECRET_KEY_PATH):
    with open(_SECRET_KEY_PATH) as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(_SECRET_KEY_PATH, "w") as f:
        f.write(app.secret_key)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("DNAC_EYESIGHT_SSL_CERT"))


def _load_auth():
    if not os.path.isfile(AUTH_PATH):
        auth = {
            "username": "admin",
            "password_hash": generate_password_hash(DEFAULT_ADMIN_PASSWORD),
            "must_change_password": True,
        }
        _save_auth(auth)
        return auth
    with open(AUTH_PATH) as f:
        return json.load(f)


def _save_auth(auth):
    tmp = AUTH_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(auth, f)
    os.replace(tmp, AUTH_PATH)


def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def _check_csrf():
    token = request.form.get("csrf_token", "")
    return bool(token) and secrets.compare_digest(token, session.get("csrf_token", ""))


_PUBLIC_PATHS = {"/login"}


@app.before_request
def _require_login():
    if request.path.startswith("/static/"):
        return
    if request.path in _PUBLIC_PATHS:
        return
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    if _load_auth().get("must_change_password") and request.path != "/change-password":
        return redirect(url_for("change_password_route"))


ACTIVITY_LOG_PATH = os.path.join(DATA_DIR, "activity_log.jsonl")


def _log_activity(action, **details):
    try:
        entry = {
            "logged_at": int(time.time()), "action": action,
            "remote_addr": request.remote_addr,
            **details,
        }
        with open(ACTIVITY_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


@app.route("/login", methods=["GET", "POST"])
def login_route():
    error = None
    if request.method == "POST":
        auth = _load_auth()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == auth["username"] and check_password_hash(auth["password_hash"], password):
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            _log_activity("login", username=username)
            if auth.get("must_change_password"):
                return redirect(url_for("change_password_route"))
            return redirect(url_for("index"))
        error = "Invalid username or password."
        _log_activity("login_failed", username=username)
    return render_template("login.html", error=error, csrf_token=_csrf_token())


@app.route("/logout", methods=["POST"])
def logout_route():
    _log_activity("logout", username=session.get("username"))
    session.clear()
    return redirect(url_for("login_route"))


@app.route("/change-password", methods=["GET", "POST"])
def change_password_route():
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    error = None
    if request.method == "POST":
        if not _check_csrf():
            error = "Session expired -- please try again."
        else:
            auth = _load_auth()
            old_password = request.form.get("old_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if not check_password_hash(auth["password_hash"], old_password):
                error = "Current password is incorrect."
            elif len(new_password) < 8:
                error = "New password must be at least 8 characters."
            elif new_password != confirm_password:
                error = "New password and confirmation do not match."
            elif new_password == DEFAULT_ADMIN_PASSWORD:
                error = "Choose a password different from the default."
            else:
                auth["password_hash"] = generate_password_hash(new_password)
                auth["must_change_password"] = False
                _save_auth(auth)
                _log_activity("password_changed", username=session.get("username"))
                return redirect(url_for("index"))
    return render_template(
        "change_password.html", error=error, csrf_token=_csrf_token(),
        forced=_load_auth().get("must_change_password", False),
    )


# ---------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------
def _with_display_time(entries):
    out = []
    for e in entries:
        e = dict(e)
        e["timestamp_display"] = datetime.fromtimestamp(e["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        out.append(e)
    return out


@app.route("/")
def index():
    return render_template(
        "index.html", config=load_config(), history=_with_display_time(get_history()[:50]),
        version=APP_VERSION, deployed_at=DEPLOYED_AT.strftime("%Y-%m-%d %H:%M UTC"),
    )


@app.route("/api/config", methods=["GET"])
def api_config_get():
    return jsonify(load_config())


@app.route("/api/config", methods=["POST"])
def api_config_save():
    """Whole-section replace, one section per call (dnac / eyesight / switch_managers /
    switch_profiles / proxy / general / schedule) -- the Config tab's three panels and
    the Automate Switch Sync tab each save their own section independently."""
    section = request.json.get("section") if request.is_json else None
    values = request.json.get("values") if request.is_json else None
    if not section or values is None:
        return jsonify({"error": "Missing section/values."}), 400
    cfg = load_config()
    if section not in cfg:
        return jsonify({"error": f"Unknown config section {section!r}."}), 400
    cfg[section] = values
    save_config(cfg)
    _log_activity("config_saved", section=section)
    return jsonify({"ok": True})


@app.route("/api/test/dnac", methods=["POST"])
def api_test_dnac():
    """Tests the DNAC panel's *currently entered* (not necessarily saved) form values --
    David's ask: validate a token is received and there's no HTTP error, before committing
    credentials via Save. Proxy settings come from the already-saved config (proxy lives in
    the General panel, not this form)."""
    data = request.get_json(silent=True) or {}
    cfg = load_config()
    try:
        client = DnacClient(
            data.get("url", ""), data.get("username", ""), data.get("password", ""),
            ssl_verify=bool(data.get("ssl_verify")), proxy_cfg=cfg["proxy"],
        )
        token = client.authenticate()
    except DnacClientError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": f"Unexpected error: {e}"}), 400
    if not token:
        return jsonify({"ok": False, "error": "Authenticated but no token was returned."}), 400
    return jsonify({"ok": True})


@app.route("/api/test/eyesight", methods=["POST"])
def api_test_eyesight():
    """Same as api_test_dnac, but for the Eyesight panel's currently entered form values."""
    data = request.get_json(silent=True) or {}
    try:
        client = EyesightClient(
            data.get("url", ""), data.get("username", ""), data.get("password", ""),
            verify_ssl=bool(data.get("ssl_verify")),
        )
        token = client.authenticate()
    except EyesightClientError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": f"Unexpected error: {e}"}), 400
    if not token:
        return jsonify({"ok": False, "error": "Authenticated but no token was returned."}), 400
    return jsonify({"ok": True})


@app.route("/api/sync/run", methods=["POST"])
def api_sync_run():
    dry_run = request.form.get("dry_run") == "1"
    entry = run_sync(triggered_by="manual", dry_run=dry_run)
    _log_activity("sync_run", triggered_by="manual", dry_run=dry_run, success=entry["success"])
    return jsonify(entry)


@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify(get_history())


@app.route("/api/history/<log_file>/log", methods=["GET"])
def api_history_log(log_file):
    try:
        return get_log_text(log_file), 200, {"Content-Type": "text/plain; charset=utf-8"}
    except SyncEngineError as e:
        return str(e), 404


# ---------------------------------------------------------------------
# Manual Manage tab
# ---------------------------------------------------------------------
@app.route("/api/manual/switches", methods=["GET"])
def api_manual_switches():
    try:
        return jsonify(manual_list_switches())
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/manual/add", methods=["POST"])
def api_manual_add():
    ip = request.form.get("ip", "").strip()
    profile = request.form.get("profile", "").strip()
    manager = request.form.get("manager", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        manual_add_switch(ip, profile, manager, comment)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    _log_activity("manual_add", ip=ip, profile=profile, manager=manager)
    return jsonify({"ok": True})


@app.route("/api/manual/remove", methods=["POST"])
def api_manual_remove():
    ip = request.form.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP is required."}), 400
    try:
        manual_remove_switch(ip)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    _log_activity("manual_remove", ip=ip)
    return jsonify({"ok": True})


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    start_scheduler()

    _ssl_cert = os.environ.get("DNAC_EYESIGHT_SSL_CERT")
    _ssl_key = os.environ.get("DNAC_EYESIGHT_SSL_KEY")
    if _ssl_cert and _ssl_key:
        _ssl_key_password = None
        _ssl_key_password_file = os.environ.get("DNAC_EYESIGHT_SSL_KEY_PASSWORD_FILE")
        if _ssl_key_password_file and os.path.isfile(_ssl_key_password_file):
            with open(_ssl_key_password_file) as f:
                _ssl_key_password = f.read().strip()
        _ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        _ssl_ctx.load_cert_chain(_ssl_cert, _ssl_key, password=_ssl_key_password or None)
        app.run(host="0.0.0.0", port=5000, ssl_context=_ssl_ctx)
    else:
        app.run(host="0.0.0.0", port=5000)
