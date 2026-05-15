import threading
import time

from flask import Blueprint, current_app, jsonify, redirect, render_template, request
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import User

bp = Blueprint("auth", __name__)

_login_attempts: dict[str, list[float]] = {}
_lock = threading.Lock()
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 60


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with _lock:
        attempts = [t for t in _login_attempts.get(ip, []) if now - t < _WINDOW_SECONDS]
        _login_attempts[ip] = attempts
        if len(attempts) >= _MAX_ATTEMPTS:
            return True
        attempts.append(now)
        _login_attempts[ip] = attempts
        return False


@bp.post("/auth/login")
def auth_login():
    ip = request.remote_addr or "unknown"
    if _is_rate_limited(ip):
        return jsonify({"error": "Too many login attempts. Try again in a minute."}), 429

    admin_password = current_app.extensions["config"].admin_password
    data = request.get_json(silent=True) or {}
    password = data.get("password")
    if password == admin_password:
        with _lock:
            _login_attempts.pop(ip, None)
        user = User(1)
        login_user(user, remember=True)
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid password"}), 401


@bp.post("/auth/logout")
@login_required
def auth_logout():
    logout_user()
    return jsonify({"status": "ok"})


@bp.get("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect("/")
    return render_template("login.html")
