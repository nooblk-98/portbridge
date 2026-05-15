import ipaddress
import logging
import os
import time

from app.core.providers import CommandRunner, ConfigProvider, StorageBackend


class WireGuardService:
    def __init__(self, config: ConfigProvider, storage: StorageBackend, runner: CommandRunner):
        self._config = config
        self._storage = storage
        self._runner = runner

    def ensure_dirs(self):
        self._config.data_dir.mkdir(parents=True, exist_ok=True)
        self._config.clients_dir.mkdir(parents=True, exist_ok=True)
        self._config.wg_config_path.parent.mkdir(parents=True, exist_ok=True)

    def ensure_server_keys(self) -> tuple[str, str]:
        priv_path = str(self._config.data_dir / "server.privatekey")
        pub_path = str(self._config.data_dir / "server.publickey")
        if not self._storage.exists(priv_path):
            priv = self._runner.run(["wg", "genkey"]).stdout.strip()
            pub = self._runner.run(["wg", "pubkey"], input_data=f"{priv}\n").stdout.strip()
            self._storage.write_text(priv_path, priv + "\n")
            self._storage.write_text(pub_path, pub + "\n")
            try:
                os.chmod(priv_path, 0o600)
                os.chmod(pub_path, 0o600)
            except OSError:
                pass
        priv_content = self._storage.read_text(priv_path) or ""
        pub_content = self._storage.read_text(pub_path) or ""
        return priv_content.strip(), pub_content.strip()

    def generate_keypair(self) -> tuple[str, str]:
        priv = self._runner.run(["wg", "genkey"]).stdout.strip()
        pub = self._runner.run(["wg", "pubkey"], input_data=f"{priv}\n").stdout.strip()
        return priv, pub

    def load_clients(self) -> list[dict]:
        raw = self._storage.load_json(str(self._config.clients_file), [])
        clients = []
        for entry in raw:
            try:
                ipaddress.ip_address(entry["address"])
                clients.append(entry)
            except Exception:
                continue
        return clients

    def write_client_config(self, client: dict, server_public: str):
        cfg = "\n".join(
            [
                "[Interface]",
                f"PrivateKey = {client['private_key']}",
                f"Address = {client['address']}/{self._config.wg_network.prefixlen}",
                "DNS = 1.1.1.1",
                "",
                "[Peer]",
                f"PublicKey = {server_public}",
                f"Endpoint = {self._config.wg_host}:{self._config.wg_port}",
                "AllowedIPs = 0.0.0.0/0",
                "PersistentKeepalive = 25",
                "",
            ]
        )
        path = str(self._config.clients_dir / f"{client['name']}.conf")
        self._storage.write_text(path, cfg)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def next_available_ip(self, clients: list[dict]) -> ipaddress.IPv4Address:
        used = {self._config.wg_address.ip}
        used.update(ipaddress.ip_address(c["address"]) for c in clients)
        for host in self._config.wg_network.hosts():
            if host not in used:
                return host
        raise RuntimeError("No free client addresses remain in the configured network.")

    def render_wireguard_config(self, clients: list[dict], server_private: str):
        lines = [
            "[Interface]",
            f"Address = {self._config.wg_address}",
            f"ListenPort = {self._config.wg_port}",
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
        path = str(self._config.wg_config_path)
        self._storage.write_text(path, "\n".join(lines))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def log_wireguard_status(self):
        status = self._runner.run(["wg", "show"], check=False)
        payload = status.stdout or status.stderr
        if payload:
            logging.info("WireGuard status:\n%s", payload.strip())

    def bounce_interface(self):
        self._runner.run(["wg-quick", "down", self._config.wg_interface], check=False)
        self._runner.run(["wg-quick", "up", self._config.wg_interface])
        self.log_wireguard_status()

    def seamless_reload(self):
        try:
            stripped = self._runner.run(["wg-quick", "strip", str(self._config.wg_config_path)]).stdout
            self._runner.run(["wg", "syncconf", self._config.wg_interface, "/dev/stdin"], input_data=stripped)
            self.log_wireguard_status()
        except Exception as e:
            logging.warning("Seamless reload failed (%s), falling back to bounce", e)
            self.bounce_interface()

    def refresh_wireguard(self, clients: list[dict]):
        server_private, _ = self.ensure_server_keys()
        self.render_wireguard_config(clients, server_private)
        self.seamless_reload()
        logging.info("Reloaded WireGuard with %s clients", len(clients))

    def peer_status_map(self) -> dict:
        status = {}
        now = int(time.time())

        transfer = {}
        res_transfer = self._runner.run(["wg", "show", self._config.wg_interface, "transfer"], check=False)
        if res_transfer.returncode == 0 and res_transfer.stdout:
            for line in res_transfer.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    transfer[parts[0]] = {"rx": int(parts[1]), "tx": int(parts[2])}

        res = self._runner.run(["wg", "show", self._config.wg_interface, "latest-handshakes"], check=False)
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
                "tx_bytes": t_stats["tx"],
            }
        return status
