
import os
import time
import ipaddress
import logging
from app.core.config import (
    DATA_DIR, CLIENTS_DIR, CLIENTS_FILE, WG_CONFIG_PATH, WG_INTERFACE,
    WG_PORT, WG_HOST, WG_NETWORK, WG_ADDRESS, DEFAULT_CLIENT_NAME
)
from app.core.utils import run, load_json, save_json

def ensure_directories():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    WG_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

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

def log_wireguard_status():
    status = run(["wg", "show"], check=False)
    payload = status.stdout or status.stderr
    if payload:
        logging.info("WireGuard status:\n%s", payload.strip())

def bounce_interface():
    run(["wg-quick", "down", WG_INTERFACE], check=False)
    run(["wg-quick", "up", WG_INTERFACE])
    log_wireguard_status()

def seamless_reload():
    try:
        stripped = run(["wg-quick", "strip", str(WG_CONFIG_PATH)]).stdout
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

def peer_status_map():
    status = {}
    now = int(time.time())
    
    transfer = {}
    res_transfer = run(["wg", "show", WG_INTERFACE, "transfer"], check=False)
    if res_transfer.returncode == 0 and res_transfer.stdout:
        for line in res_transfer.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
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
