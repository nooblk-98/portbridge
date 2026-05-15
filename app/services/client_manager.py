import ipaddress
import logging
import time

from app.core.providers import ConfigProvider, StorageBackend
from app.core.wireguard import WireGuardService
from app.services.forwarding_manager import ForwardingManager


class ClientManager:
    def __init__(self, wg: WireGuardService, storage: StorageBackend, config: ConfigProvider, fwd: ForwardingManager):
        self._wg = wg
        self._storage = storage
        self._config = config
        self._fwd = fwd

    def list_clients(self) -> dict:
        server_public = self._wg.ensure_server_keys()[1]
        clients = self._wg.load_clients()
        fwd = self._fwd.list_rules()
        status = self._wg.peer_status_map()
        payload = []
        for client in clients:
            forwards = [r for r in fwd if str(r.get("client_ip")) == client["address"]]
            peer_state = status.get(client["public_key"], {})
            payload.append(
                {
                    "name": client["name"],
                    "address": f"{client['address']}/{self._config.wg_network.prefixlen}",
                    "public_key": client["public_key"],
                    "config": f"/clients/{client['name']}.conf",
                    "online": bool(peer_state.get("online")),
                    "last_handshake": peer_state.get("handshake"),
                    "rx_bytes": peer_state.get("rx_bytes", 0),
                    "tx_bytes": peer_state.get("tx_bytes", 0),
                    "forwardings": forwards,
                }
            )
        return {"server_public_key": server_public, "items": payload}

    def create_client(self, name: str, address: str | None = None) -> dict:
        clients = self._wg.load_clients()
        if any(c["name"] == name for c in clients):
            raise ValueError("Client name already exists.")

        if address:
            try:
                address_ip = ipaddress.ip_address(address)
            except ValueError:
                raise ValueError("Invalid client IP.") from None
            if address_ip not in self._config.wg_network:
                raise ValueError("Client IP outside WireGuard network.")
            if address_ip == self._config.wg_address.ip or any(
                ipaddress.ip_address(c["address"]) == address_ip for c in clients
            ):
                raise ValueError("Client IP already in use.")
        else:
            address_ip = self._wg.next_available_ip(clients)

        private, public = self._wg.generate_keypair()
        client = {
            "name": name,
            "address": str(address_ip),
            "private_key": private,
            "public_key": public,
            "created_at": int(time.time()),
        }
        clients.append(client)
        self._storage.save_json(str(self._config.clients_file), clients)

        server_public = self._wg.ensure_server_keys()[1]
        self._wg.write_client_config(client, server_public)
        self._wg.refresh_wireguard(clients)
        self._fwd.apply_all()

        return {"name": name, "config": f"/clients/{name}.conf"}

    def rename_client(self, old_name: str, new_name: str) -> dict:
        clients = self._wg.load_clients()
        target = next((c for c in clients if c["name"] == old_name), None)
        if not target:
            raise LookupError("Client not found.")
        if any(c["name"] == new_name for c in clients if c["name"] != old_name):
            raise ValueError("Client name already exists.")

        old_conf = self._config.clients_dir / f"{old_name}.conf"
        new_conf = self._config.clients_dir / f"{new_name}.conf"
        if old_conf.exists():
            old_conf.rename(new_conf)

        target["name"] = new_name
        self._storage.save_json(str(self._config.clients_file), clients)
        server_public = self._wg.ensure_server_keys()[1]
        self._wg.write_client_config(target, server_public)
        self._wg.refresh_wireguard(clients)

        return {"name": new_name}

    def delete_client(self, name: str) -> dict:
        clients = self._wg.load_clients()
        updated = [c for c in clients if c["name"] != name]
        if len(updated) == len(clients):
            raise LookupError("Client not found.")
        self._storage.save_json(str(self._config.clients_file), updated)

        cfg = self._config.clients_dir / f"{name}.conf"
        if cfg.exists():
            cfg.unlink()

        self._wg.refresh_wireguard(updated)
        self._fwd.apply_all()

        return {"removed": name}

    def download_config_path(self, name: str):
        path = self._config.clients_dir / f"{name}.conf"
        if not path.exists():
            raise LookupError("Config not found.")
        return path

    def read_config(self, name: str) -> str:
        path = self.download_config_path(name)
        return path.read_text()

    def bootstrap(self) -> None:
        self._wg.ensure_dirs()
        server_private, server_public = self._wg.ensure_server_keys()
        clients = self._wg.load_clients()

        if not clients:
            import time as _time

            default_ip = self._wg.next_available_ip([])
            priv, pub = self._wg.generate_keypair()
            default_client = {
                "name": self._config.default_client_name,
                "address": str(default_ip),
                "private_key": priv,
                "public_key": pub,
                "created_at": int(_time.time()),
            }
            clients.append(default_client)
            self._storage.save_json(str(self._config.clients_file), clients)
            self._wg.write_client_config(default_client, server_public)

        for client in clients:
            self._wg.write_client_config(client, server_public)

        self._wg.render_wireguard_config(clients, server_private)
        self._wg.bounce_interface()

        default_client_ip = clients[0]["address"] if clients else None
        if default_client_ip:
            self._fwd.seed_if_empty(default_client_ip)
        logging.info("Bootstrap: %s clients loaded", len(clients))
