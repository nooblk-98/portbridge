
import io
import time
import ipaddress
import segno
import os
from flask import Blueprint, jsonify, request, abort, send_file
from flask_login import login_required
from app.core.config import (
    WG_HOST, WG_PORT, WG_INTERFACE, WG_ADDRESS, WG_NETWORK, 
    CLIENTS_FILE, FORWARD_FILE, CLIENTS_DIR, APP_PORT
)
from app.core.utils import save_json, run
from app.core.wireguard import (
    load_clients, ensure_server_keys, peer_status_map, 
    next_available_ip, generate_keypair, write_client_config, 
    refresh_wireguard
)
from app.core.iptables import (
    load_forwardings, apply_forwardings, protocols_overlap
)

bp = Blueprint('api', __name__)

@bp.get("/api/state")
@login_required
def api_state():
    clients = load_clients()
    forwardings = load_forwardings()
    return jsonify(
        {
            "endpoint": f"{WG_HOST}:{WG_PORT}",
            "interface": WG_INTERFACE,
            "address": str(WG_ADDRESS),
            "network": str(WG_NETWORK),
            "clients": len(clients),
            "forwardings": len(forwardings),
        }
    )

@bp.get("/api/clients")
@login_required
def api_clients():
    server_public = ensure_server_keys()[1]
    clients = load_clients()
    fwd = load_forwardings()
    status = peer_status_map()
    payload = []
    for client in clients:
        forwards = [r for r in fwd if str(r.get("client_ip")) == client["address"]]
        peer_state = status.get(client["public_key"], {})
        payload.append(
            {
                "name": client["name"],
                "address": f"{client['address']}/{WG_NETWORK.prefixlen}",
                "public_key": client["public_key"],
                "config": f"/clients/{client['name']}.conf",
                "online": bool(peer_state.get("online")),
                "last_handshake": peer_state.get("handshake"),
                "rx_bytes": peer_state.get("rx_bytes", 0),
                "tx_bytes": peer_state.get("tx_bytes", 0),
                "forwardings": forwards,
            }
        )
    return jsonify({"server_public_key": server_public, "items": payload})


@bp.post("/api/clients")
@login_required
def api_create_client():
    body = request.get_json(force=True, silent=True) or {}
    name = body.get("name") or f"client-{int(time.time())}"
    raw_address = body.get("address")

    clients = load_clients()
    if any(c["name"] == name for c in clients):
        abort(400, description="Client name already exists.")

    if raw_address:
        try:
            address_ip = ipaddress.ip_address(raw_address)
        except ValueError:
            abort(400, description="Invalid client IP.")
        if address_ip not in WG_NETWORK:
            abort(400, description="Client IP outside WireGuard network.")
        if address_ip == WG_ADDRESS.ip or any(ipaddress.ip_address(c["address"]) == address_ip for c in clients):
            abort(400, description="Client IP already in use.")
    else:
        address_ip = next_available_ip(clients)

    private, public = generate_keypair()
    client = {
        "name": name,
        "address": str(address_ip),
        "private_key": private,
        "public_key": public,
        "created_at": int(time.time()),
    }
    clients.append(client)
    save_json(CLIENTS_FILE, clients)

    server_public = ensure_server_keys()[1]
    write_client_config(client, server_public)
    refresh_wireguard(clients)
    apply_forwardings(load_forwardings())

    return jsonify({"name": name, "config": f"/clients/{name}.conf"})


@bp.delete("/api/clients/<name>")
@login_required
def api_delete_client(name):
    clients = load_clients()
    updated = [c for c in clients if c["name"] != name]
    if len(updated) == len(clients):
        abort(404)
    save_json(CLIENTS_FILE, updated)

    cfg = CLIENTS_DIR / f"{name}.conf"
    if cfg.exists():
        cfg.unlink()

    refresh_wireguard(updated)
    apply_forwardings(load_forwardings())
    return jsonify({"removed": name})


@bp.get("/clients/<name>.conf")
@login_required
def api_download_client(name):
    path = CLIENTS_DIR / f"{name}.conf"
    if not path.exists():
        abort(404)
    return send_file(path, mimetype="text/plain", download_name=f"{name}.conf", as_attachment=True)


@bp.get("/clients/<name>.png")
@login_required
def api_qr_client(name):
    path = CLIENTS_DIR / f"{name}.conf"
    if not path.exists():
        abort(404)
    content = path.read_text()
    qr = segno.make(content)
    buffer = io.BytesIO()
    qr.save(buffer, kind="png", scale=5, dark="black", light=None)
    buffer.seek(0)
    return send_file(buffer, mimetype="image/png", download_name=f"{name}.png")


@bp.get("/api/forwardings")
@login_required
def api_forwardings():
    rules = load_forwardings()
    return jsonify({"items": rules})


@bp.post("/api/forwardings")
@login_required
def api_add_forwarding():
    body = request.get_json(force=True, silent=True) or {}
    try:
        # Port can be int or string (range)
        port_raw = body.get("port")
        if "-" in str(port_raw):
            # Validate range
            s, e = map(int, str(port_raw).split("-"))
            if s >= e:
                abort(400, description="Invalid port range.")
            port = str(port_raw)
        else:
            port = int(port_raw)
    except Exception:
        abort(400, description="Port must be numeric or range (e.g. 8000-8100).")

    proto = (body.get("protocol") or "both").lower()
    if proto not in ("tcp", "udp", "both"):
        abort(400, description="Protocol must be tcp, udp, or both.")

    client_ip_raw = body.get("client_ip")
    if not client_ip_raw:
        abort(400, description="client_ip is required.")
    try:
        client_ip = ipaddress.ip_address(client_ip_raw)
    except ValueError:
        abort(400, description="Invalid client_ip.")

    source_ip = body.get("source_ip")
    if source_ip:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            try:
                ipaddress.ip_network(source_ip)
            except ValueError:
                 abort(400, description="Invalid source IP/CIDR.")

    target_port_raw = body.get("target_port") or port
    try:
        target_port = int(target_port_raw)
    except Exception:
        abort(400, description="target_port must be numeric.")

    if client_ip not in WG_NETWORK:
        abort(400, description="client_ip outside WireGuard network.")

    # Security: Prevent forwarding critical ports
    reserved_ports = [
        int(os.environ.get("WG_PORT", 51820)),
        APP_PORT
    ]
    
    # Check for conflict
    conflict = False
    if "-" in str(port):
        s, e = map(int, str(port).split("-"))
        for rp in reserved_ports:
            if s <= rp <= e:
                conflict = True
                break
    else:
        if int(port) in reserved_ports:
            conflict = True

    if conflict:
        abort(400, description=f"Cannot forward reserved system ports ({', '.join(map(str, reserved_ports))}).")

    rules = load_forwardings()
    for rule in rules:
        existing_proto = rule.get("protocol", "both")
        existing_port = int(rule.get("port", -1))
        if existing_port == port and protocols_overlap(existing_proto, proto):
            if str(rule.get("client_ip")) != str(client_ip):
                abort(400, description="Port is already in use by another client.")

    rules = [
        r
        for r in rules
        if not (
            str(r.get("port", -1)) == str(port)
            and r.get("protocol", "both") == proto
        )
    ]
    rules.append({
        "port": port, 
        "protocol": proto, 
        "client_ip": str(client_ip), 
        "target_port": target_port,
        "source_ip": source_ip
    })

    save_json(FORWARD_FILE, rules)
    apply_forwardings(rules)
    return jsonify({"port": port, "protocol": proto, "client_ip": str(client_ip), "target_port": target_port})


@bp.delete("/api/forwardings/<path:port>/<proto>")
@login_required
def api_delete_forwarding(port, proto):
    proto = proto.lower()
    rules = load_forwardings()
    updated = [r for r in rules if not (str(r.get("port", -1)) == str(port) and r.get("protocol", "both") == proto)]
    if len(updated) == len(rules):
        abort(404)
    save_json(FORWARD_FILE, updated)
    apply_forwardings(updated)
    return jsonify({"removed": {"port": port, "protocol": proto}})


@bp.get("/api/wg/status")
@login_required
def api_wg_status():
    status = run(["wg", "show"], check=False)
    return jsonify({"output": (status.stdout or status.stderr or "").splitlines()})
