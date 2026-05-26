import json
import hashlib
import hmac
import os
import sqlite3
import time
from functools import wraps

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)

# ======= Config / Credentials =======
IS_RENDER = bool(os.environ.get("RENDER") or os.environ.get("PORT"))
ALLOW_INSECURE_DEFAULTS = os.environ.get("ALLOW_INSECURE_DEFAULTS", "").lower() in {"1", "true", "yes"}


def required_config(name, dev_default=None):
    value = os.environ.get(name)
    if value:
        return value
    if IS_RENDER and not ALLOW_INSECURE_DEFAULTS:
        raise RuntimeError(f"{name} environment variable is required")
    return dev_default or ""


ADMIN_USERNAME = required_config("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = required_config("ADMIN_PASSWORD", "dev-admin-password")
ADMIN_SECRET = required_config("ADMIN_SECRET", "dev-admin-secret")
CLIENT_SHARED_SECRET = os.environ.get("CLIENT_SHARED_SECRET", "")
REQUIRE_CLIENT_AUTH = os.environ.get("REQUIRE_CLIENT_AUTH", "1" if IS_RENDER else "0").lower() not in {"0", "false", "no"}
CLIENT_SIGNATURE_WINDOW_SECONDS = int(os.environ.get("CLIENT_SIGNATURE_WINDOW_SECONDS", "300"))
CLIENT_POLL_SECONDS = int(os.environ.get("CLIENT_POLL_SECONDS", "15"))
ALLOW_REMOTE_BARTENDER_EXE = os.environ.get("ALLOW_REMOTE_BARTENDER_EXE", "").lower() in {"1", "true", "yes"}

if REQUIRE_CLIENT_AUTH and not CLIENT_SHARED_SECRET:
    raise RuntimeError("CLIENT_SHARED_SECRET environment variable is required when REQUIRE_CLIENT_AUTH is enabled")

# Flask session secret
app.secret_key = required_config("FLASK_SECRET_KEY", "dev-flask-session-secret")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1" if IS_RENDER else "0").lower() not in {"0", "false", "no"},
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")
BASE_ALLOWED_REMOTE_SETTINGS = {
    "active_bom",
    "btw_file",
    "templates",
    "printer",
    "last_mode",
    "column_mapping",
    "minda_column_mapping",
}
ALLOWED_REMOTE_SETTINGS = set(BASE_ALLOWED_REMOTE_SETTINGS)
if ALLOW_REMOTE_BARTENDER_EXE:
    ALLOWED_REMOTE_SETTINGS.add("bartender_exe")
ALLOWED_TEMPLATE_KEYS = {"polaris", "minda", "solder"}


def valid_admin_secret(secret):
    return bool(ADMIN_SECRET) and hmac.compare_digest(str(secret or ""), ADMIN_SECRET)


def canonical_json(data):
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def valid_heartbeat_signature(data):
    if not REQUIRE_CLIENT_AUTH:
        return True

    timestamp = request.headers.get("X-Client-Timestamp", "")
    signature = request.headers.get("X-Client-Signature", "")
    client_id = request.headers.get("X-Client-Id", "")
    software_id = str(data.get("software_id", "")).strip()

    if client_id and client_id != software_id:
        return False

    try:
        timestamp_int = int(timestamp)
    except (TypeError, ValueError):
        return False

    if abs(time.time() - timestamp_int) > CLIENT_SIGNATURE_WINDOW_SECONDS:
        return False

    body = canonical_json(data)
    signed = f"{timestamp}.{body}".encode("utf-8")
    expected = hmac.new(CLIENT_SHARED_SECRET.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def validate_remote_settings(settings):
    if settings is None:
        return None
    if not isinstance(settings, dict):
        raise ValueError("settings must be an object")

    cleaned = {}
    for key, value in settings.items():
        if key not in ALLOWED_REMOTE_SETTINGS:
            raise ValueError(f"Remote setting not allowed: {key}")
        if key == "templates":
            if not isinstance(value, dict):
                raise ValueError("templates must be an object")
            cleaned["templates"] = {
                str(tk): str(tv)
                for tk, tv in value.items()
                if str(tk) in ALLOWED_TEMPLATE_KEYS
            }
        else:
            cleaned[key] = value
    return cleaned


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS softwares (
                software_id TEXT PRIMARY KEY,
                machine_name TEXT,
                version TEXT,
                os_name TEXT,
                ip_address TEXT,
                last_seen REAL,
                status TEXT,
                kill_reason TEXT,
                update_url TEXT,
                notes TEXT
            )
        """)
        for col_name, col_type in [
            ("current_settings", "TEXT"),
            ("pending_settings", "TEXT"),
            ("locked_settings", "TEXT"),
            ("pause_until", "REAL"),
            ("pause_reason", "TEXT"),
            ("last_command_at", "REAL"),
        ]:
            try:
                conn.execute(f"ALTER TABLE softwares ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass
        conn.commit()


def get_all_softwares():
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM softwares")
        rows = cursor.fetchall()
        return {row["software_id"]: dict(row) for row in rows}


def get_software(software_id):
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM softwares WHERE software_id = ?", (software_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def expire_pause_if_needed(obj):
    if not obj or obj.get("status") != "paused":
        return obj
    pause_until = obj.get("pause_until")
    if pause_until and float(pause_until) <= time.time():
        set_software_status(obj["software_id"], "active")
        return get_software(obj["software_id"])
    return obj


def safe_json_loads(value, fallback):
    try:
        return json.loads(value) if value else fallback
    except (TypeError, json.JSONDecodeError):
        return fallback


def save_software_heartbeat(software_id, machine_name, version, os_name, ip_address, current_settings=None):
    init_db()
    now = time.time()
    settings_json = json.dumps(current_settings) if current_settings else None
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status, kill_reason, update_url FROM softwares WHERE software_id = ?", (software_id,))
        row = cursor.fetchone()
        if row is None:
            cursor.execute("""
                INSERT INTO softwares (software_id, machine_name, version, os_name, ip_address, last_seen, status, kill_reason, update_url, notes, current_settings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (software_id, machine_name, version, os_name, ip_address, now, "active", None, None, "", settings_json))
        else:
            cursor.execute("""
                UPDATE softwares
                SET machine_name = COALESCE(?, machine_name),
                    version = COALESCE(?, version),
                    os_name = COALESCE(?, os_name),
                    ip_address = COALESCE(?, ip_address),
                    last_seen = ?,
                    current_settings = ?
                WHERE software_id = ?
            """, (machine_name or None, version or None, os_name or None, ip_address or None, now, settings_json, software_id))
        conn.commit()


def set_software_status(software_id, status, kill_reason=None, update_url=None, pause_until=None, pause_reason=None):
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM softwares WHERE software_id = ?", (software_id,))
        exists = cursor.fetchone()
        if not exists:
            cursor.execute("""
                INSERT INTO softwares (
                    software_id, machine_name, version, os_name, ip_address, last_seen,
                    status, kill_reason, update_url, notes, pause_until, pause_reason, last_command_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                software_id, None, None, None, None, time.time(),
                status, kill_reason, update_url, "", pause_until, pause_reason, time.time()
            ))
        else:
            if status == "killed":
                cursor.execute("""
                    UPDATE softwares
                    SET status = ?, kill_reason = ?, pause_until = NULL, pause_reason = NULL, last_command_at = ?
                    WHERE software_id = ?
                """, (status, kill_reason, time.time(), software_id))
            elif status == "active":
                cursor.execute("""
                    UPDATE softwares
                    SET status = ?, kill_reason = NULL, update_url = NULL, pause_until = NULL, pause_reason = NULL, last_command_at = ?
                    WHERE software_id = ?
                """, (status, time.time(), software_id))
            elif status == "paused":
                cursor.execute("""
                    UPDATE softwares
                    SET status = ?, pause_until = ?, pause_reason = ?, kill_reason = NULL, last_command_at = ?
                    WHERE software_id = ?
                """, (status, pause_until, pause_reason, time.time(), software_id))
            elif status == "update_available":
                cursor.execute("""
                    UPDATE softwares
                    SET status = ?, update_url = ?, last_command_at = ?
                    WHERE software_id = ?
                """, (status, update_url, time.time(), software_id))
        conn.commit()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


@app.route("/", methods=["GET"])
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def do_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["logged_in"] = True
        session["username"] = username
        return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error="Invalid username or password",
    ), 401


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    all_softwares = get_all_softwares()
    serialized = {sid: _serialize_software(sid, obj) for sid, obj in all_softwares.items()}
    return render_template("dashboard.html", now=int(time.time()), softwares=serialized)


def _serialize_software(software_id, obj):
    obj = expire_pause_if_needed({"software_id": software_id, **obj}) or obj
    heartbeat_age = max(0, int(time.time() - float(obj.get("last_seen") or 0))) if obj.get("last_seen") else None
    current_settings = safe_json_loads(obj.get("current_settings"), None)
    pending_settings = safe_json_loads(obj.get("pending_settings"), None)
    locked_settings = safe_json_loads(obj.get("locked_settings"), [])
    return {
        "software_id": software_id,
        "machine_name": obj.get("machine_name"),
        "version": obj.get("version"),
        "os_name": obj.get("os_name"),
        "ip_address": obj.get("ip_address"),
        "last_seen": obj.get("last_seen"),
        "heartbeat_age_seconds": heartbeat_age,
        "online": heartbeat_age is not None and heartbeat_age <= max(CLIENT_POLL_SECONDS * 3, 60),
        "status": obj.get("status", "active"),
        "kill_reason": obj.get("kill_reason"),
        "update_url": obj.get("update_url"),
        "pause_until": obj.get("pause_until"),
        "pause_reason": obj.get("pause_reason"),
        "last_command_at": obj.get("last_command_at"),
        "notes": obj.get("notes", ""),
        "current_settings": current_settings,
        "pending_settings": pending_settings,
        "locked_settings": locked_settings,
        "pending_count": len(pending_settings or {}),
        "locked_count": len(locked_settings or []),
    }


@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    data = request.get_json(force=True, silent=True) or {}

    if not valid_heartbeat_signature(data):
        return jsonify({"error": "Unauthorized heartbeat"}), 401

    software_id = str(data.get("software_id", "")).strip()
    version = str(data.get("version", "")).strip()
    machine_name = str(data.get("machine_name", "")).strip()
    os_name = str(data.get("os_name", "")).strip()
    ip_address = str(data.get("ip_address", "")).strip()
    current_settings = data.get("current_settings")

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    save_software_heartbeat(software_id, machine_name, version, os_name, ip_address, current_settings=current_settings)

    obj = expire_pause_if_needed(get_software(software_id) or {}) or {}

    # Auto-clear pending_settings if Sticker has applied them
    pending = safe_json_loads(obj.get("pending_settings"), None)
    if pending and current_settings:
        all_applied = True
        for k, v in pending.items():
            if k == "templates" and isinstance(v, dict):
                curr_templates = current_settings.get("templates", {})
                for tk, tv in v.items():
                    if curr_templates.get(tk) != tv:
                        all_applied = False
                        break
            elif current_settings.get(k) != v:
                all_applied = False
                break
        if all_applied:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("UPDATE softwares SET pending_settings = NULL WHERE software_id = ?", (software_id,))
                conn.commit()
            obj["pending_settings"] = None

    resp = {
        "software_id": software_id,
        "status": obj.get("status", "active"),
        "kill_reason": obj.get("kill_reason"),
        "update_url": obj.get("update_url"),
        "pause_until": obj.get("pause_until"),
        "pause_reason": obj.get("pause_reason"),
        "pending_settings": safe_json_loads(obj.get("pending_settings"), None),
        "locked_settings": safe_json_loads(obj.get("locked_settings"), []),
        "next_poll_seconds": CLIENT_POLL_SECONDS,
    }

    return jsonify(resp), 200


@app.route("/api/admin/kill", methods=["POST"])
def api_admin_kill():
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if not valid_admin_secret(secret):
            return jsonify({"error": "Unauthorized"}), 401
    else:
        data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()
    reason = str(data.get("reason", "")).strip()

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    set_software_status(software_id, "killed", kill_reason=reason or "Killed by admin")
    return jsonify({"ok": True, "software_id": software_id, "status": "killed"}), 200


@app.route("/api/admin/activate", methods=["POST"])
def api_admin_activate():
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if not valid_admin_secret(secret):
            return jsonify({"error": "Unauthorized"}), 401
    else:
        data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    set_software_status(software_id, "active")
    return jsonify({"ok": True, "software_id": software_id, "status": "active"}), 200


@app.route("/api/admin/pause", methods=["POST"])
def api_admin_pause():
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if not valid_admin_secret(secret):
            return jsonify({"error": "Unauthorized"}), 401
    else:
        data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()
    reason = str(data.get("reason", "")).strip() or "Paused by admin"
    try:
        pause_minutes = int(data.get("pause_minutes") or 0)
    except (TypeError, ValueError):
        pause_minutes = 0

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    pause_until = time.time() + (pause_minutes * 60) if pause_minutes > 0 else None
    set_software_status(software_id, "paused", pause_until=pause_until, pause_reason=reason)
    return jsonify({
        "ok": True,
        "software_id": software_id,
        "status": "paused",
        "pause_until": pause_until,
    }), 200


@app.route("/api/admin/update", methods=["POST"])
def api_admin_update():
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if not valid_admin_secret(secret):
            return jsonify({"error": "Unauthorized"}), 401
    else:
        data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()
    update_url = str(data.get("update_url", "")).strip()

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400
    if not update_url:
        return jsonify({"error": "update_url is required"}), 400

    set_software_status(software_id, "update_available", update_url=update_url)
    return (
        jsonify(
            {
                "ok": True,
                "software_id": software_id,
                "status": "update_available",
                "update_url": update_url,
            }
        ),
        200,
    )


@app.route("/api/admin/list", methods=["GET"])
def api_admin_list():
    if not session.get("logged_in"):
        secret = request.headers.get("X-Admin-Secret") or request.headers.get("x-admin-secret")
        if not valid_admin_secret(secret):
            return jsonify({"error": "Unauthorized"}), 401

    all_softwares = get_all_softwares()
    serialized = {sid: _serialize_software(sid, obj) for sid, obj in all_softwares.items()}
    return jsonify({"softwares": serialized}), 200


@app.route("/api/admin/save_notes", methods=["POST"])
def api_admin_save_notes():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    software_id = str(data.get("software_id", "")).strip()
    notes = str(data.get("notes", ""))

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE softwares SET notes = ? WHERE software_id = ?", (notes, software_id))
        conn.commit()

    return jsonify({"ok": True}), 200


@app.route("/api/admin/clear_pending", methods=["POST"])
def api_admin_clear_pending():
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if not valid_admin_secret(secret):
            return jsonify({"error": "Unauthorized"}), 401
    else:
        data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()
    clear_locks = bool(data.get("clear_locks"))

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    updates = ["pending_settings = NULL", "last_command_at = ?"]
    params = [time.time()]
    if clear_locks:
        updates.append("locked_settings = ?")
        params.append("[]")
    params.append(software_id)

    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(f"UPDATE softwares SET {', '.join(updates)} WHERE software_id = ?", params)
        conn.commit()

    return jsonify({"ok": True, "software_id": software_id}), 200


@app.route("/api/admin/settings/<software_id>", methods=["GET"])
def api_admin_get_settings(software_id):
    if not session.get("logged_in"):
        secret = request.headers.get("X-Admin-Secret") or request.headers.get("x-admin-secret")
        if not valid_admin_secret(secret):
            return jsonify({"error": "Unauthorized"}), 401

    obj = expire_pause_if_needed(get_software(software_id))
    if not obj:
        return jsonify({"error": "Software not found"}), 404

    return jsonify({
        "software_id": software_id,
        "current_settings": safe_json_loads(obj.get("current_settings"), None),
        "pending_settings": safe_json_loads(obj.get("pending_settings"), None),
        "locked_settings": safe_json_loads(obj.get("locked_settings"), []),
    }), 200


@app.route("/api/admin/settings", methods=["POST"])
def api_admin_push_settings():
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if not valid_admin_secret(secret):
            return jsonify({"error": "Unauthorized"}), 401
    else:
        data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()
    try:
        settings = validate_remote_settings(data.get("settings"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    locked = data.get("locked_settings")

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT pending_settings FROM softwares WHERE software_id = ?", (software_id,))
        row = cursor.fetchone()

        if row is None:
            # Create entry if not exists
            cursor.execute("""
                INSERT INTO softwares (software_id, last_seen, status, pending_settings, locked_settings)
                VALUES (?, ?, ?, ?, ?)
            """, (software_id, time.time(), "active",
                  json.dumps(settings) if settings else None,
                  json.dumps(locked) if locked is not None else "[]"))
        else:
            # Merge pending settings
            existing_pending = json.loads(row[0] or "{}")
            if settings:
                # Handle nested templates merge
                if "templates" in settings and "templates" in existing_pending:
                    existing_pending["templates"].update(settings["templates"])
                    settings_copy = dict(settings)
                    del settings_copy["templates"]
                    existing_pending.update(settings_copy)
                else:
                    existing_pending.update(settings)

            updates = []
            params = []
            if settings:
                updates.append("pending_settings = ?")
                params.append(json.dumps(existing_pending))
            if locked is not None:
                updates.append("locked_settings = ?")
                params.append(json.dumps(locked))

            if updates:
                params.append(software_id)
                cursor.execute(f"UPDATE softwares SET {', '.join(updates)} WHERE software_id = ?", params)

        conn.commit()

    return jsonify({"ok": True, "software_id": software_id}), 200


if __name__ == "__main__":
    init_db()
    debug_enabled = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", port=5000, debug=debug_enabled)
