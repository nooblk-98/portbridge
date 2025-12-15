
from flask import Blueprint, jsonify, request, redirect, render_template
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import User
from app.core.config import ADMIN_PASSWORD

bp = Blueprint('auth', __name__)

@bp.post("/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    password = data.get("password")
    if password == ADMIN_PASSWORD:
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
