
import os
import ipaddress
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CLIENTS_DIR = DATA_DIR / "clients"
CLIENTS_FILE = DATA_DIR / "clients.json"
FORWARD_FILE = Path(os.environ.get("FORWARD_CONFIG", DATA_DIR / "forwardings.json"))
WG_CONFIG_PATH = Path(os.environ.get("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf"))
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_PORT = int(os.environ.get("WG_PORT", "51820"))
WG_HOST = os.environ.get("WG_HOST", "127.0.0.1")
APP_PORT = int(os.environ.get("APP_PORT", "3000"))
WG_NETWORK = ipaddress.ip_network(os.environ.get("WG_NETWORK", "10.8.0.0/24"))

_hosts = WG_NETWORK.hosts()
_default_address = next(_hosts)
# Advance to the second host for default forward target if possible
try:
    _default_forward_target = next(_hosts)
except StopIteration:
    _default_forward_target = _default_address

WG_ADDRESS = ipaddress.ip_interface(os.environ.get("WG_ADDRESS", f"{_default_address}/{WG_NETWORK.prefixlen}"))
DEFAULT_FORWARD_TARGET = os.environ.get("DEFAULT_FORWARD_TARGET", str(_default_forward_target))
DEFAULT_CLIENT_NAME = os.environ.get("DEFAULT_CLIENT_NAME", "default")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24))

NAT_CHAIN = "WG_FORWARDER"
FILTER_CHAIN = "WG_FORWARDER_FWD"
