
import time
import logging
from app.core.config import (
    CLIENTS_FILE, DEFAULT_CLIENT_NAME
)
from app.core.utils import save_json
from app.core.wireguard import (
    ensure_directories, ensure_server_keys, load_clients, 
    next_available_ip, generate_keypair, write_client_config, 
    render_wireguard_config, bounce_interface
)
from app.core.iptables import (
    load_forwardings, apply_forwardings
)

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

    # Use client address for default forwarding seed if needed
    default_client_ip = clients[0]["address"] if clients else None
    forwardings = load_forwardings(default_client_ip=default_client_ip)

    for client in clients:
        write_client_config(client, server_public)

    render_wireguard_config(clients, server_private)
    bounce_interface()
    apply_forwardings(forwardings)
    logging.info("Bootstrap complete: %s clients, %s forwarding rules", len(clients), len(forwardings))
