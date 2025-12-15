#!/usr/bin/env python3
import ipaddress
import io
import json
import logging
import os
import subprocess
import time
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file, redirect, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import segno

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CLIENTS_DIR = DATA_DIR / "clients"
CLIENTS_FILE = DATA_DIR / "clients.json"
FORWARD_FILE = Path(os.environ.get("FORWARD_CONFIG", DATA_DIR / "forwardings.json"))
DEFAULT_FORWARD_FILE = Path("/app/config/forwarding-ports.conf")
WG_CONFIG_PATH = Path(os.environ.get("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf"))
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_PORT = int(os.environ.get("WG_PORT", "51820"))
WG_HOST = os.environ.get("WG_HOST", "127.0.0.1")
APP_PORT = int(os.environ.get("APP_PORT", "3000"))
WG_NETWORK = ipaddress.ip_network(os.environ.get("WG_NETWORK", "10.8.0.0/24"))
_hosts = WG_NETWORK.hosts()
_default_address = next(_hosts)
_default_forward_target = next(_hosts, _default_address)
WG_ADDRESS = ipaddress.ip_interface(os.environ.get("WG_ADDRESS", f"{_default_address}/{WG_NETWORK.prefixlen}"))
DEFAULT_FORWARD_TARGET = os.environ.get("DEFAULT_FORWARD_TARGET", str(_default_forward_target))
DEFAULT_CLIENT_NAME = os.environ.get("DEFAULT_CLIENT_NAME", "default")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")  # Default password

# Simple User class
class User(UserMixin):
    def __init__(self, id):
        self.id = id

NAT_CHAIN = "WG_FORWARDER"
FILTER_CHAIN = "WG_FORWARDER_FWD"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

login_manager = LoginManager()
login_manager.login_view = "login_page"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


def run(cmd, check=True, input_data=None):
    logging.info("exec: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        logging.info(result.stdout.strip())
    if result.stderr.strip():
        logging.warning(result.stderr.strip())
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nstdout: {result.stdout}\nstderr: {result.stderr}")
    return result


def ensure_directories():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    WG_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)


def load_json(path, default):
    try:
        with path.open() as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        return default


def save_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        json.dump(payload, handle, indent=2)


def ensure_server_keys():
    priv_path = DATA_DIR / "server.privatekey"
    pub_path = DATA_DIR / "server.publickey"
    if not priv_path.exists():
        priv = run(["wg", "genkey"]).stdout.strip()
        pub = run(["wg", "pubkey"], input_data=f"{priv}\n").stdout.strip()
        priv_path.write_text(priv + "\n")
        pub_path.write_text(pub + "\n")
        os.chmod(priv_path, 0o600)
        os.chmod(pub_path, 0o600)
    return priv_path.read_text().strip(), pub_path.read_text().strip()


def detect_primary_interface():
    try:
        result = run(["sh", "-c", "ip route show default | awk '{print $5; exit}'"], check=False)
        iface = result.stdout.strip()
        if iface:
            return iface
    except Exception:
        return "eth0"
    return "eth0"


def generate_keypair():
    priv = run(["wg", "genkey"]).stdout.strip()
    pub = run(["wg", "pubkey"], input_data=f"{priv}\n").stdout.strip()
    return priv, pub


def load_clients():
    raw = load_json(CLIENTS_FILE, [])
    clients = []
    for entry in raw:
        try:
            ipaddress.ip_address(entry["address"])
            clients.append(entry)
        except Exception:
            continue
    return clients


def write_client_config(client, server_public):
    cfg = "\n".join(
        [
            "[Interface]",
            f"PrivateKey = {client['private_key']}",
            f"Address = {client['address']}/{WG_NETWORK.prefixlen}",
            "DNS = 1.1.1.1",
            "",
            "[Peer]",
            f"PublicKey = {server_public}",
            f"Endpoint = {WG_HOST}:{WG_PORT}",
            "AllowedIPs = 0.0.0.0/0",
            "PersistentKeepalive = 25",
            "",
        ]
    )
    path = CLIENTS_DIR / f"{client['name']}.conf"
    path.write_text(cfg)
    os.chmod(path, 0o600)
    return path


def next_available_ip(clients):
    used = {WG_ADDRESS.ip}
    used.update(ipaddress.ip_address(c["address"]) for c in clients)
    for host in WG_NETWORK.hosts():
        if host not in used:
            return host
    raise RuntimeError("No free client addresses remain in the configured network.")


def render_wireguard_config(clients, server_private):
    lines = [
        "[Interface]",
        f"Address = {WG_ADDRESS}",
        f"ListenPort = {WG_PORT}",
        f"PrivateKey = {server_private}",
        "SaveConfig = false",
        "",
    ]
    for client in clients:
        lines.extend(
            [
                "[Peer]",
                f"PublicKey = {client['public_key']}",
                f"AllowedIPs = {client['address']}/32",
                "",
            ]
        )
    WG_CONFIG_PATH.write_text("\n".join(lines))
    os.chmod(WG_CONFIG_PATH, 0o600)


def bounce_interface():
    run(["wg-quick", "down", WG_INTERFACE], check=False)
    run(["wg-quick", "up", WG_INTERFACE])
    log_wireguard_status()


def log_wireguard_status():
    status = run(["wg", "show"], check=False)
    payload = status.stdout or status.stderr
    if payload:
        logging.info("WireGuard status:\n%s", payload.strip())


def ensure_masquerade(ext_iface):
    check = run(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", ext_iface, "-j", "MASQUERADE"],
        check=False,
    )
    if check.returncode != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ext_iface, "-j", "MASQUERADE"])


def ensure_chain(table, chain, parent_chain=None):
    run(["iptables", "-t", table, "-N", chain], check=False)
    if parent_chain:
        present = run(["iptables", "-t", table, "-C", parent_chain, "-j", chain], check=False)
        if present.returncode != 0:
            run(["iptables", "-t", table, "-A", parent_chain, "-j", chain])


def apply_forwardings(rules):
    ext_iface = detect_primary_interface()
    ensure_chain("nat", NAT_CHAIN, "PREROUTING")
    ensure_chain("filter", FILTER_CHAIN, "FORWARD")
    run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
    run(["iptables", "-t", "filter", "-F", FILTER_CHAIN])

    for rule in rules:
        try:
            # Handle Port Ranges (e.g., "8000-8100" or just "8000")
            port_input = str(rule["port"])
            is_range = "-" in port_input
            
            if is_range:
                start_port, end_port = map(int, port_input.split("-"))
                dport_arg = f"{start_port}:{end_port}"
                validation_port = start_port
            else:
                port = int(port_input)
                dport_arg = str(port)
                validation_port = port

            proto = rule.get("protocol", "both").lower()
            client_ip = str(ipaddress.ip_address(rule["client_ip"]))
            
            # Target port logic handling for ranges is complex. 
            # For ranges, we usually map 1:1, so target_port is ignored or must match start.
            # For single ports, we use target_port.
            if is_range:
                to_dest = f"{client_ip}:{start_port}-{end_port}"
                dest_port_arg = dport_arg
            else:
                target_port = int(rule.get("target_port", port))
                to_dest = f"{client_ip}:{target_port}"
                dest_port_arg = str(target_port)

            source_ip = rule.get("source_ip", "").strip()

        except Exception as e:
            logging.error(f"Skipping invalid rule {rule}: {e}")
            continue

        protocols = ["tcp", "udp"] if proto == "both" else [proto]
        for name in protocols:
            # DNAT Rule
            dnat_cmd = [
                "iptables", "-t", "nat", "-A", NAT_CHAIN,
                "-i", ext_iface,
                "-p", name,
                "--dport", dport_arg,
                "-j", "DNAT",
                "--to-destination", to_dest
            ]
            if source_ip:
                dnat_cmd.extend(["-s", source_ip])
            
            run(dnat_cmd)

            # Filter Rule (FORWARD)
            filter_cmd = [
                "iptables", "-t", "filter", "-A", FILTER_CHAIN,
                "-p", name,
                "-d", client_ip,
                "--dport", dest_port_arg,
                "-j", "ACCEPT"
            ]
            if source_ip:
                filter_cmd.extend(["-s", source_ip])
                
            run(filter_cmd)

    ensure_masquerade(ext_iface)
    logging.info("Applied %s forwarding rules", len(rules))


def protocols_overlap(existing_proto, new_proto):
    existing = existing_proto.lower()
    new = new_proto.lower()
    if existing == "both" or new == "both":
        return True
    return existing == new


def peer_status_map():
    status = {}
    now = int(time.time())
    
    # Get Transfer stats
    transfer = {}
    res_transfer = run(["wg", "show", WG_INTERFACE, "transfer"], check=False)
    if res_transfer.returncode == 0 and res_transfer.stdout:
        for line in res_transfer.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                # pubkey: rx tx
                transfer[parts[0]] = {"rx": int(parts[1]), "tx": int(parts[2])}

    res = run(["wg", "show", WG_INTERFACE, "latest-handshakes"], check=False)
    if res.returncode != 0 or not res.stdout:
        return status

    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        pubkey = parts[0]
        ts_raw = parts[1]
        try:
            ts = int(ts_raw)
        except ValueError:
            ts = 0
        online = ts > 0 and (now - ts) < 180
        
        t_stats = transfer.get(pubkey, {"rx": 0, "tx": 0})
        
        status[pubkey] = {
            "handshake": ts, 
            "online": online, 
            "age": now - ts if ts else None,
            "rx_bytes": t_stats["rx"],
            "tx_bytes": t_stats["tx"]
        }
    return status


def load_forwardings(default_client_ip=None):
    payload = load_json(FORWARD_FILE, None)
    if isinstance(payload, list):
        return payload

    # If no persisted rules, seed a single TCP+UDP forward for port 20000 to the default client.
    if default_client_ip:
        seed = [{"port": 30000, "protocol": "both", "client_ip": str(default_client_ip), "target_port": 8080}]
        save_json(FORWARD_FILE, seed)
        return seed

    save_json(FORWARD_FILE, [])
    return []


def seamless_reload():
    try:
        # Generate raw wg config using wg-quick strip
        stripped = run(["wg-quick", "strip", str(WG_CONFIG_PATH)]).stdout
        
        # Sync the configuration without down/up
        run(["wg", "syncconf", WG_INTERFACE, "/dev/stdin"], input_data=stripped)
        log_wireguard_status()
    except Exception as e:
        logging.warning("Seamless reload failed (%s), falling back to bounce", e)
        bounce_interface()


def refresh_wireguard(clients):
    server_private, _ = ensure_server_keys()
    render_wireguard_config(clients, server_private)
    seamless_reload()
    logging.info("Reloaded WireGuard with %s clients", len(clients))


def bootstrap():
    ensure_directories()
    server_private, server_public = ensure_server_keys()
    clients = load_clients()

    if not clients:
        # Seed a default client if none exist.
        default_ip = next_available_ip([])
        priv, pub = generate_keypair()
        default_client = {
            "name": DEFAULT_CLIENT_NAME,
            "address": str(default_ip),
            "private_key": priv,
            "public_key": pub,
            "created_at": int(time.time()),
        }
        clients.append(default_client)
        save_json(CLIENTS_FILE, clients)
        write_client_config(default_client, server_public)

    forwardings = load_forwardings(default_client_ip=clients[0]["address"])

    for client in clients:
        write_client_config(client, server_public)

    render_wireguard_config(clients, server_private)
    bounce_interface()
    apply_forwardings(forwardings)
    logging.info("Bootstrap complete: %s clients, %s forwarding rules", len(clients), len(forwardings))


@app.get("/api/state")
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


@app.get("/api/clients")
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


@app.post("/api/clients")
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


@app.delete("/api/clients/<name>")
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


@app.get("/clients/<name>.conf")
@login_required
def api_download_client(name):
    path = CLIENTS_DIR / f"{name}.conf"
    if not path.exists():
        abort(404)
    return send_file(path, mimetype="text/plain", download_name=f"{name}.conf", as_attachment=True)


@app.get("/clients/<name>.png")
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


@app.get("/api/forwardings")
@login_required
def api_forwardings():
    rules = load_forwardings()
    return jsonify({"items": rules})


@app.post("/api/forwardings")
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
        int(os.environ.get("APP_PORT", 3000))
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


@app.delete("/api/forwardings/<path:port>/<proto>")
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


@app.get("/api/wg/status")
@login_required
def api_wg_status():
    status = run(["wg", "show"], check=False)
    return jsonify({"output": (status.stdout or status.stderr or "").splitlines()})


@app.post("/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    password = data.get("password")
    if password == ADMIN_PASSWORD:
        user = User(1)
        login_user(user, remember=True)
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid password"}), 401

@app.post("/auth/logout")
@login_required
def auth_logout():
    logout_user()
    return jsonify({"status": "ok"})

@app.get("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect("/")
    return app.send_static_file("login.html")

@app.get("/")
@login_required
def index():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    bootstrap()
    app.run(host="0.0.0.0", port=APP_PORT)
