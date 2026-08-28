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
import io
import json
import logging
import os
import secrets
import shutil
import ssl
import subprocess
import threading
import time
import zipfile
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from dnac_client import DnacClient, DnacClientError
from eyesight_client import EyesightClient, EyesightClientError
from scheduler import start_scheduler
from sync_engine import (
    DATA_DIR, SyncEngineError, get_history, get_log_text, load_config, manual_add_switch,
    manual_get_profile_credentials, manual_get_switch, manual_get_switch_credentials,
    manual_health_check, manual_list_switches, manual_remove_switch, manual_update_profile_credentials,
    manual_update_switch, manual_update_switch_credentials, run_sync, save_config,
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
# HTTPS certificate management -- ported directly from the sibling
# forescout-lookup app (David's ask, 2026-08-28: same section here as
# there). Only meaningful once Deploy.sh mounts /certs (read-write)
# and /host-apache-certs (read-only, this EM's own Apache SSL dir) --
# both added to this app's Deploy.sh alongside this feature.
# ---------------------------------------------------------------------
CERT_DIR = "/certs"
APACHE_CERT_MOUNT = "/host-apache-certs"


def _cert_info(cert_path):
    if not os.path.isfile(cert_path):
        return None
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-enddate", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=5,
        )
    except OSError as exc:
        return {"error": str(exc)}
    if proc.returncode != 0:
        return {"error": proc.stderr.strip() or "openssl could not read this file."}
    info = {}
    for line in proc.stdout.splitlines():
        if line.startswith("subject="):
            info["subject"] = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line[len("issuer="):].strip()
        elif line.startswith("notAfter="):
            info["expires"] = line[len("notAfter="):].strip()
        elif line.startswith("sha256 Fingerprint="):
            info["fingerprint"] = line[len("sha256 Fingerprint="):].strip()
    return info


def _key_is_encrypted(key_path):
    try:
        with open(key_path) as f:
            return "ENCRYPTED" in f.read()
    except OSError:
        return False


def _verify_cert_key(cert_path, key_path, password):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path, password=password or None)
        return True, None
    except (ssl.SSLError, OSError) as exc:
        return False, str(exc)


def _render_certs_page(error=None, message=None):
    apache_cert_path = os.path.join(APACHE_CERT_MOUNT, "cert.pem")
    apache_key_path = os.path.join(APACHE_CERT_MOUNT, "private.key")
    apache = _cert_info(apache_cert_path) if os.path.isfile(apache_cert_path) else None
    return render_template(
        "certs.html",
        current=_cert_info(os.path.join(CERT_DIR, "cert.pem")),
        apache=apache,
        apache_key_encrypted=_key_is_encrypted(apache_key_path) if apache else False,
        certs_dir_available=os.path.isdir(CERT_DIR),
        csrf_token=_csrf_token(),
        error=error,
        message=message,
    )


@app.route("/admin/certs", methods=["GET"])
def certs_route():
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    return _render_certs_page()


@app.route("/admin/certs/apply", methods=["POST"])
def certs_apply_route():
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    if not _check_csrf():
        return _render_certs_page(error="Session expired -- please try again.")
    if not os.path.isdir(CERT_DIR):
        return _render_certs_page(error="No writable certificate directory on this deployment.")

    source = request.form.get("source")
    password = request.form.get("password", "")
    tmp_cert = os.path.join(CERT_DIR, "cert.pem.new")
    tmp_key = os.path.join(CERT_DIR, "private.key.new")

    try:
        if source == "apache":
            src_cert = os.path.join(APACHE_CERT_MOUNT, "cert.pem")
            src_key = os.path.join(APACHE_CERT_MOUNT, "private.key")
            if not os.path.isfile(src_cert) or not os.path.isfile(src_key):
                raise ValueError("This EM's Apache cert/key could not be found.")
            shutil.copyfile(src_cert, tmp_cert)
            shutil.copyfile(src_key, tmp_key)
        elif source == "upload":
            cert_file = request.files.get("cert_file")
            key_file = request.files.get("key_file")
            if not cert_file or not key_file or not cert_file.filename or not key_file.filename:
                raise ValueError("Both a certificate file and a private key file are required.")
            cert_file.save(tmp_cert)
            key_file.save(tmp_key)
        else:
            raise ValueError("Unknown certificate source.")

        ok, err = _verify_cert_key(tmp_cert, tmp_key, password)
        if not ok:
            raise ValueError(f"That cert/key could not be loaded: {err}")

        os.replace(tmp_cert, os.path.join(CERT_DIR, "cert.pem"))
        os.replace(tmp_key, os.path.join(CERT_DIR, "private.key"))
        os.chmod(os.path.join(CERT_DIR, "private.key"), 0o600)
        pw_path = os.path.join(CERT_DIR, "key_password.txt")
        if password:
            with open(pw_path, "w") as f:
                f.write(password)
            os.chmod(pw_path, 0o600)
        elif os.path.isfile(pw_path):
            os.remove(pw_path)
    except ValueError as exc:
        for p in (tmp_cert, tmp_key):
            if os.path.isfile(p):
                os.remove(p)
        return _render_certs_page(error=str(exc))

    _log_activity("cert_updated", username=session.get("username"), source=source)
    # Werkzeug's dev server can't hot-swap a TLS cert mid-process -- the
    # container's --restart unless-stopped policy (Deploy.sh) is what
    # actually applies this, by bringing the process back up with the
    # new file already in place.
    threading.Timer(1.0, lambda: os._exit(0)).start()
    return _render_certs_page(
        message="New certificate saved. Restarting the service now to apply it -- this page will be unreachable for a few seconds."
    )


@app.route("/admin/certs/export-apache", methods=["GET"])
def certs_export_apache_route():
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    src_cert = os.path.join(APACHE_CERT_MOUNT, "cert.pem")
    src_key = os.path.join(APACHE_CERT_MOUNT, "private.key")
    if not os.path.isfile(src_cert) or not os.path.isfile(src_key):
        return redirect(url_for("certs_route"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.write(src_cert, "cert.pem")
        zf.write(src_key, "private.key")
    buf.seek(0)
    _log_activity("cert_exported", username=session.get("username"))
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name="apache-cert.zip")


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


# Credential fields shared by both the switch- and profile-credentials update forms --
# matches CredentialsSwitchToUpdate/CredentialsProfileToUpdate in the real API's own spec
# (/switch/api/v2/api-docs, confirmed live 2026-08-28). Only fields actually present in the
# submitted form are sent, matching the real API's own partial-update semantics -- an admin
# changing just the SNMP community string shouldn't blank out the CLI password.
_CREDENTIAL_FIELD_NAMES = (
    "cliType", "cliPassword", "cliPrivilegedPassword", "snmpCommunity",
    "snmpAuthPassword", "snmpPrivacyPassword", "dot1xRadiusSecret", "comment",
)


def _credential_fields_from_form():
    return {k: v for k in _CREDENTIAL_FIELD_NAMES if (v := request.form.get(k, "").strip())}


@app.route("/api/manual/healthcheck", methods=["GET"])
def api_manual_healthcheck():
    try:
        return jsonify({"ok": True, "result": manual_health_check()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/manual/switch", methods=["GET"])
def api_manual_get_switch():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP is required."}), 400
    try:
        return jsonify(manual_get_switch(ip))
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/manual/update", methods=["POST"])
def api_manual_update():
    ip = request.form.get("ip", "").strip()
    profile = request.form.get("profile", "").strip()
    manager = request.form.get("manager", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        manual_update_switch(ip, profile, manager, comment)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    _log_activity("manual_update", ip=ip, profile=profile, manager=manager)
    return jsonify({"ok": True})


@app.route("/api/manual/switch_credentials", methods=["GET"])
def api_manual_get_switch_credentials():
    """Returns real device secrets (CLI/SNMP/802.1X) straight from Eyesight -- rendered on the
    live page only, never written to any log file (see _log_activity calls below, which log
    the action and IP, deliberately never the credential values themselves)."""
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP is required."}), 400
    try:
        result = manual_get_switch_credentials(ip)
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    _log_activity("manual_get_switch_credentials", ip=ip)
    return jsonify(result)


@app.route("/api/manual/switch_credentials", methods=["POST"])
def api_manual_update_switch_credentials():
    ip = request.form.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP is required."}), 400
    try:
        manual_update_switch_credentials(ip, _credential_fields_from_form())
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    _log_activity("manual_update_switch_credentials", ip=ip)
    return jsonify({"ok": True})


@app.route("/api/manual/profile_credentials", methods=["GET"])
def api_manual_get_profile_credentials():
    profile = request.args.get("profile", "").strip()
    if not profile:
        return jsonify({"error": "Profile name is required."}), 400
    try:
        result = manual_get_profile_credentials(profile)
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    _log_activity("manual_get_profile_credentials", profile=profile)
    return jsonify(result)


@app.route("/api/manual/profile_credentials", methods=["POST"])
def api_manual_update_profile_credentials():
    profile = request.form.get("profile", "").strip()
    if not profile:
        return jsonify({"error": "Profile name is required."}), 400
    try:
        manual_update_profile_credentials(profile, _credential_fields_from_form())
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    _log_activity("manual_update_profile_credentials", profile=profile)
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
