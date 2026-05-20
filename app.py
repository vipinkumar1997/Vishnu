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
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "vipin@123")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "MY_SECRET_KEY_123")

# Flask session secret
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "flask_session_secret_xyz")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")


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
                notes TEXT,
                pause_until REAL,
                pause_reason TEXT
            )
        """)
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


def save_software_heartbeat(software_id, machine_name, version, os_name, ip_address):
    init_db()
    now = time.time()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status, kill_reason, update_url FROM softwares WHERE software_id = ?", (software_id,))
        row = cursor.fetchone()
        if row is None:
            cursor.execute("""
                INSERT INTO softwares (software_id, machine_name, version, os_name, ip_address, last_seen, status, kill_reason, update_url, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (software_id, machine_name, version, os_name, ip_address, now, "active", None, None, ""))
        else:
            cursor.execute("""
                UPDATE softwares
                SET machine_name = COALESCE(?, machine_name),
                    version = COALESCE(?, version),
                    os_name = COALESCE(?, os_name),
                    ip_address = COALESCE(?, ip_address),
                    last_seen = ?
                WHERE software_id = ?
            """, (machine_name or None, version or None, os_name or None, ip_address or None, now, software_id))
        conn.commit()


def set_software_status(software_id, status, kill_reason=None, update_url=None):
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM softwares WHERE software_id = ?", (software_id,))
        exists = cursor.fetchone()
        if not exists:
            cursor.execute("""
                INSERT INTO softwares (software_id, machine_name, version, os_name, ip_address, last_seen, status, kill_reason, update_url, notes, pause_until, pause_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            """, (software_id, None, None, None, None, time.time(), status, kill_reason, update_url, ""))
        else:
            if status == "killed":
                cursor.execute("""
                    UPDATE softwares
                    SET status = ?, kill_reason = ?
                    WHERE software_id = ?
                """, (status, kill_reason, software_id))
            elif status == "active":
                cursor.execute("""
                    UPDATE softwares
                    SET status = ?, kill_reason = NULL
                    WHERE software_id = ?
                """, (status, software_id))
            elif status == "update_available":
                cursor.execute("""
                    UPDATE softwares
                    SET status = ?, update_url = ?
                    WHERE software_id = ?
                """, (status, update_url, software_id))
        conn.commit()


def set_software_pause(software_id, pause_minutes, pause_reason=""):
    """Set software to pause for specified minutes. 0 means immediate pause."""
    init_db()
    now = time.time()
    pause_until = now + (pause_minutes * 60) if pause_minutes > 0 else now
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM softwares WHERE software_id = ?", (software_id,))
        exists = cursor.fetchone()
        if not exists:
            cursor.execute("""
                INSERT INTO softwares (software_id, machine_name, version, os_name, ip_address, last_seen, status, kill_reason, update_url, notes, pause_until, pause_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (software_id, None, None, None, None, now, "paused", None, None, "", pause_until, pause_reason))
        else:
            cursor.execute("""
                UPDATE softwares
                SET status = ?, pause_until = ?, pause_reason = ?, kill_reason = NULL
                WHERE software_id = ?
            """, ("paused", pause_until, pause_reason, software_id))
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
    return {
        "software_id": software_id,
        "machine_name": obj.get("machine_name"),
        "version": obj.get("version"),
        "os_name": obj.get("os_name"),
        "ip_address": obj.get("ip_address"),
        "last_seen": obj.get("last_seen"),
        "status": obj.get("status", "active"),
        "kill_reason": obj.get("kill_reason"),
        "update_url": obj.get("update_url"),
        "notes": obj.get("notes", ""),
        "pause_until": obj.get("pause_until"),
        "pause_reason": obj.get("pause_reason", ""),
    }


@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()
    version = str(data.get("version", "")).strip()
    machine_name = str(data.get("machine_name", "")).strip()
    os_name = str(data.get("os_name", "")).strip()
    ip_address = str(data.get("ip_address", "")).strip()

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    save_software_heartbeat(software_id, machine_name, version, os_name, ip_address)

    obj = get_software(software_id) or {}

    resp = {
        "software_id": software_id,
        "status": obj.get("status", "active"),
        "kill_reason": obj.get("kill_reason"),
        "update_url": obj.get("update_url"),
        "pause_until": obj.get("pause_until"),
        "pause_reason": obj.get("pause_reason"),
    }

    return jsonify(resp), 200


@app.route("/api/admin/kill", methods=["POST"])
def api_admin_kill():
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if secret != ADMIN_SECRET:
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
        if secret != ADMIN_SECRET:
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
    """Pause software for specified minutes with optional auto-restart."""
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if secret != ADMIN_SECRET:
            return jsonify({"error": "Unauthorized"}), 401
    else:
        data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()
    pause_minutes = int(data.get("pause_minutes", 0) or 0)  # 0 = immediate close
    reason = str(data.get("reason", "Manual pause")).strip()

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400
    
    if pause_minutes < 0:
        pause_minutes = 0

    set_software_pause(software_id, pause_minutes, reason)
    
    pause_until = time.time() + (pause_minutes * 60) if pause_minutes > 0 else time.time()
    return jsonify({
        "ok": True,
        "software_id": software_id,
        "status": "paused",
        "pause_minutes": pause_minutes,
        "pause_until": pause_until,
    }), 200


@app.route("/api/admin/update", methods=["POST"])
def api_admin_update():
    if not session.get("logged_in"):
        data = request.get_json(force=True, silent=True) or {}
        secret = str(data.get("secret", "")).strip()
        if secret != ADMIN_SECRET:
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
        if secret != ADMIN_SECRET:
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


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
