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

# ======= Config / Credentials (as requested) =======
pythonADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "vipin@123"
ADMIN_SECRET = "MY_SECRET_KEY_123"

# Flask session secret
app.secret_key = "flask_session_secret_xyz"

# ======= In-memory storage (no DB / no files) =======
# softwares[software_id] = {
#   "software_id": str,
#   "machine_name": str,
#   "version": str,
#   "last_seen": float,
#   "status": "active"|"killed"|"update_available",
#   "kill_reason": str|None,
#   "update_url": str|None,
# }
softwares = {}


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

    if username == pythonADMIN_USERNAME and password == ADMIN_PASSWORD:
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
    # UI will call API periodically; this page can render initial state.
    return render_template("dashboard.html", now=int(time.time()), softwares=softwares)


def _serialize_software(software_id, obj):
    status = obj.get("status", "active")
    return {
        "software_id": software_id,
        "machine_name": obj.get("machine_name"),
        "version": obj.get("version"),
        "last_seen": obj.get("last_seen"),
        "status": status,
        "kill_reason": obj.get("kill_reason"),
        "update_url": obj.get("update_url"),
    }


@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    data = request.get_json(force=True, silent=True) or {}

    software_id = str(data.get("software_id", "")).strip()
    version = str(data.get("version", "")).strip()
    machine_name = str(data.get("machine_name", "")).strip()

    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    now = time.time()

    if software_id not in softwares:
        softwares[software_id] = {
            "software_id": software_id,
            "machine_name": machine_name,
            "version": version,
            "last_seen": now,
            "status": "active",
            "kill_reason": None,
            "update_url": None,
        }
    else:
        softwares[software_id]["machine_name"] = machine_name or softwares[software_id].get(
            "machine_name"
        )
        softwares[software_id]["version"] = version or softwares[software_id].get("version")
        softwares[software_id]["last_seen"] = now

    obj = softwares[software_id]

    # Response should include: status, kill_reason, update_url
    resp = {
        "software_id": software_id,
        "status": obj.get("status", "active"),
        "kill_reason": obj.get("kill_reason"),
        "update_url": obj.get("update_url"),
    }

    return jsonify(resp), 200


def _verify_admin_secret(req):
    secret = req.headers.get("X-Admin-Secret") or req.headers.get("x-admin-secret")
    # Some endpoints pass it in JSON body as "secret".
    if secret:
        return secret == ADMIN_SECRET
    return False


@app.route("/api/admin/kill", methods=["POST"])
def api_admin_kill():
    data = request.get_json(force=True, silent=True) or {}
    secret = str(data.get("secret", "")).strip()
    software_id = str(data.get("software_id", "")).strip()
    reason = str(data.get("reason", "")).strip()

    if secret != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    if software_id in softwares:
        softwares[software_id].update(
            {
                "status": "killed",
                "kill_reason": reason or "Killed by admin",
                "update_url": softwares[software_id].get("update_url"),
            }
        )
    else:
        softwares[software_id] = {
            "software_id": software_id,
            "machine_name": None,
            "version": None,
            "last_seen": time.time(),
            "status": "killed",
            "kill_reason": reason or "Killed by admin",
            "update_url": None,
        }

    return jsonify({"ok": True, "software_id": software_id, "status": "killed"}), 200


@app.route("/api/admin/activate", methods=["POST"])
def api_admin_activate():
    data = request.get_json(force=True, silent=True) or {}
    secret = str(data.get("secret", "")).strip()
    software_id = str(data.get("software_id", "")).strip()

    if secret != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    if not software_id:
        return jsonify({"error": "software_id is required"}), 400

    if software_id in softwares:
        softwares[software_id].update(
            {
                "status": "active",
                "kill_reason": None,
            }
        )
    else:
        softwares[software_id] = {
            "software_id": software_id,
            "machine_name": None,
            "version": None,
            "last_seen": time.time(),
            "status": "active",
            "kill_reason": None,
            "update_url": None,
        }

    return jsonify({"ok": True, "software_id": software_id, "status": "active"}), 200


@app.route("/api/admin/update", methods=["POST"])
def api_admin_update():
    data = request.get_json(force=True, silent=True) or {}
    secret = str(data.get("secret", "")).strip()
    software_id = str(data.get("software_id", "")).strip()
    update_url = str(data.get("update_url", "")).strip()

    if secret != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    if not software_id:
        return jsonify({"error": "software_id is required"}), 400
    if not update_url:
        return jsonify({"error": "update_url is required"}), 400

    if software_id in softwares:
        softwares[software_id].update(
            {
                "status": "update_available",
                "update_url": update_url,
                # keep kill_reason as-is
            }
        )
    else:
        softwares[software_id] = {
            "software_id": software_id,
            "machine_name": None,
            "version": None,
            "last_seen": time.time(),
            "status": "update_available",
            "kill_reason": None,
            "update_url": update_url,
        }

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
    # Requirement: header X-Admin-Secret verify
    if request.headers.get("X-Admin-Secret") != ADMIN_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"softwares": {sid: _serialize_software(sid, obj) for sid, obj in softwares.items()}}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

