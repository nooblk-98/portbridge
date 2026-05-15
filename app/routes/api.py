import io

import segno
from flask import Blueprint, abort, current_app, jsonify, request, send_file
from flask_login import login_required

bp = Blueprint("api", __name__)


def _cm():
    return current_app.extensions["client_manager"]


def _fm():
    return current_app.extensions["forwarding_manager"]


def _cfg():
    return current_app.extensions["config"]


@bp.get("/api/state")
@login_required
def api_state():
    config = _cfg()
    clients = _cm().list_clients()
    forwardings = _fm().list_rules()
    return jsonify(
        {
            "endpoint": f"{config.wg_host}:{config.wg_port}",
            "interface": config.wg_interface,
            "address": str(config.wg_address),
            "network": str(config.wg_network),
            "clients": len(clients.get("items", [])),
            "forwardings": len(forwardings),
        }
    )


@bp.get("/api/clients")
@login_required
def api_clients():
    return jsonify(_cm().list_clients())


@bp.post("/api/clients")
@login_required
def api_create_client():
    body = request.get_json(force=True, silent=True) or {}
    name = body.get("name") or f"client-{int(__import__('time').time())}"
    raw_address = body.get("address")
    try:
        result = _cm().create_client(name, raw_address)
        return jsonify(result)
    except ValueError as e:
        abort(400, description=str(e))


@bp.patch("/api/clients/<name>")
@login_required
def api_rename_client(name):
    body = request.get_json(force=True, silent=True) or {}
    new_name = (body.get("name") or "").strip()
    if not new_name:
        abort(400, description="New name is required.")
    try:
        result = _cm().rename_client(name, new_name)
        return jsonify(result)
    except ValueError as e:
        abort(400, description=str(e))
    except LookupError:
        abort(404)


@bp.delete("/api/clients/<name>")
@login_required
def api_delete_client(name):
    try:
        result = _cm().delete_client(name)
        return jsonify(result)
    except LookupError:
        abort(404)


@bp.get("/clients/<name>.conf")
@login_required
def api_download_client(name):
    try:
        path = _cm().download_config_path(name)
        return send_file(str(path), mimetype="text/plain", download_name=f"{name}.conf", as_attachment=True)
    except LookupError:
        abort(404)


@bp.get("/clients/<name>.png")
@login_required
def api_qr_client(name):
    try:
        content = _cm().read_config(name)
    except LookupError:
        abort(404)
    qr = segno.make(content)
    buffer = io.BytesIO()
    qr.save(buffer, kind="png", scale=5, dark="black", light=None)
    buffer.seek(0)
    return send_file(buffer, mimetype="image/png", download_name=f"{name}.png")


@bp.get("/api/forwardings")
@login_required
def api_forwardings():
    rules = _fm().list_rules()
    return jsonify({"items": rules})


@bp.post("/api/forwardings")
@login_required
def api_add_forwarding():
    body = request.get_json(force=True, silent=True) or {}
    try:
        result = _fm().add_rule(body)
        return jsonify(result)
    except ValueError as e:
        abort(400, description=str(e))


@bp.delete("/api/forwardings/<path:port>/<proto>")
@login_required
def api_delete_forwarding(port, proto):
    try:
        result = _fm().remove_rule(port, proto)
        return jsonify(result)
    except LookupError:
        abort(404)


@bp.get("/api/wg/status")
@login_required
def api_wg_status():
    from app.core.providers import SubprocessRunner

    runner = SubprocessRunner()
    status = runner.run(["wg", "show"], check=False)
    return jsonify({"output": (status.stdout or status.stderr or "").splitlines()})
