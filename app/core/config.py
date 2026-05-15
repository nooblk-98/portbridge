import ipaddress
import logging
import os
from pathlib import Path

from app.core.providers import ConfigProvider


class EnvConfigProvider(ConfigProvider):
    def __init__(self):
        data_dir = os.environ.get("DATA_DIR", "/data")
        self._data_dir = Path(data_dir)
        self._clients_dir = self._data_dir / "clients"
        self._clients_file = self._data_dir / "clients.json"
        self._forward_file = Path(os.environ.get("FORWARD_CONFIG", str(self._data_dir / "forwardings.json")))
        self._wg_config_path = Path(os.environ.get("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf"))
        self._wg_interface = os.environ.get("WG_INTERFACE", "wg0")
        self._wg_port = int(os.environ.get("WG_PORT", "51820"))
        self._wg_host = os.environ.get("WG_HOST", "127.0.0.1")
        self._app_port = int(os.environ.get("APP_PORT", "3000"))
        network_str = os.environ.get("WG_NETWORK", "10.8.0.0/24")
        self._wg_network = ipaddress.ip_network(network_str)
        self._admin_password = os.environ.get("ADMIN_PASSWORD", "admin")
        self._default_client_name = os.environ.get("DEFAULT_CLIENT_NAME", "default")
        self._nat_chain = "WG_FORWARDER"
        self._filter_chain = "WG_FORWARDER_FWD"

        _hosts = self._wg_network.hosts()
        default_address = next(_hosts)
        try:
            _default_forward_target = next(_hosts)
        except StopIteration:
            _default_forward_target = default_address

        self._wg_address = ipaddress.ip_interface(
            os.environ.get("WG_ADDRESS", f"{default_address}/{self._wg_network.prefixlen}")
        )
        self._default_forward_target = os.environ.get("DEFAULT_FORWARD_TARGET", str(_default_forward_target))
        self._secret_key: bytes | None = None
        self._warn()

    def _warn(self):
        if self._admin_password == "admin":
            logging.warning(
                "SECURITY: ADMIN_PASSWORD is set to the default 'admin'. "
                "Set the ADMIN_PASSWORD environment variable to a strong password."
            )
        if self._wg_host == "127.0.0.1":
            logging.warning(
                "CONFIG: WG_HOST is '127.0.0.1' (default). "
                "Clients will receive an unusable config. Set WG_HOST to your server's public IP or hostname."
            )

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def clients_dir(self) -> Path:
        return self._clients_dir

    @property
    def clients_file(self) -> Path:
        return self._clients_file

    @property
    def forward_file(self) -> Path:
        return self._forward_file

    @property
    def wg_config_path(self) -> Path:
        return self._wg_config_path

    @property
    def wg_interface(self) -> str:
        return self._wg_interface

    @property
    def wg_port(self) -> int:
        return self._wg_port

    @property
    def wg_host(self) -> str:
        return self._wg_host

    @property
    def app_port(self) -> int:
        return self._app_port

    @property
    def wg_network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return self._wg_network

    @property
    def wg_address(self) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface:
        return self._wg_address

    @property
    def admin_password(self) -> str:
        return self._admin_password

    @property
    def default_client_name(self) -> str:
        return self._default_client_name

    @property
    def default_forward_target(self) -> str:
        return self._default_forward_target

    @property
    def nat_chain(self) -> str:
        return self._nat_chain

    @property
    def filter_chain(self) -> str:
        return self._filter_chain

    @property
    def secret_key(self) -> bytes:
        if self._secret_key is None:
            self._secret_key = self._load_or_create_secret_key()
        return self._secret_key

    def _load_or_create_secret_key(self) -> bytes:
        key_file = self._data_dir / ".secret_key"
        try:
            key_file.parent.mkdir(parents=True, exist_ok=True)
            if key_file.exists():
                key = key_file.read_bytes()
                if len(key) >= 24:
                    return key
            key = os.urandom(32)
            key_file.write_bytes(key)
            key_file.chmod(0o600)
            return key
        except Exception:
            return os.urandom(32)

    SECRET_KEY = property(lambda self: self.secret_key)
