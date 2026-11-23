#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${EUID} -ne 0 || $# -ne 1 ]]; then
    echo "Usage: sudo bash install.sh <public WireGuard hostname or IP>" >&2
    exit 1
fi

endpoint=$1

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
app_dir=/opt/portbridge
config_dir=/etc/portbridge
state_dir=/var/lib/portbridge
unit=/etc/systemd/system/portbridge.service

for path in "$app_dir" "$config_dir" "$state_dir" "$unit"; do
    if [[ -e $path || -L $path ]]; then
        echo "Existing path: $path. This installer is for fresh installations." >&2
        exit 1
    fi
done
if ! command -v apt-get >/dev/null || ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    echo "This installer requires Debian or Ubuntu with systemd." >&2
    exit 1
fi
read -rsp "Dashboard password (at least 16 letters or numbers): " password
echo
if [[ ! $password =~ ^[A-Za-z0-9]{16,128}$ ]]; then
    echo "Choose a password of 16 to 128 letters or numbers." >&2
    exit 1
fi

apt-get update
apt-get install -y python3 python3-venv wireguard-tools iproute2 iptables procps
if ! python3 - "$endpoint" <<'PYVALIDATE'
import ipaddress
import re
import sys

host = sys.argv[1]
try:
    ipaddress.ip_address(host)
    if "%" in host:
        sys.exit(1)
except ValueError:
    labels = host.removesuffix(".").split(".")
    if len(host) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ) or all(label.isdecimal() for label in labels):
        sys.exit(1)
PYVALIDATE
then
    echo "Supply a hostname or bare IP address, without a URL or port." >&2
    exit 1
fi
if [[ -e /etc/wireguard/pb0.conf ]] || ip link show dev pb0 >/dev/null 2>&1; then
    echo "The pb0 WireGuard interface is already in use." >&2
    exit 1
fi
install -d -m 0700 "$app_dir" "$config_dir" "$state_dir"
install -d -m 0750 "$app_dir/app"
cp -R "$source_dir/app/." "$app_dir/app/"
install -m 0600 "$source_dir/run.py" "$source_dir/requirements.txt" "$app_dir/"
python3 -m venv "$app_dir/venv"
"$app_dir/venv/bin/python" -m pip install -r "$app_dir/requirements.txt" waitress==3.0.2

cat > "$config_dir/portbridge.env" <<ENV
WG_HOST=$endpoint
WG_INTERFACE=pb0
WG_CONFIG_PATH=$config_dir/pb0.conf
DATA_DIR=$state_dir
ADMIN_PASSWORD=$password
SEED_FORWARDING=0
ENABLE_IPV4_FORWARDING=1
ENV
unset password

cat > "$unit" <<'UNIT'
[Unit]
Description=PortBridge WireGuard dashboard
Wants=network-online.target
After=network-online.target

[Service]
WorkingDirectory=/opt/portbridge
EnvironmentFile=/etc/portbridge/portbridge.env
ExecStart=/opt/portbridge/venv/bin/waitress-serve --listen=127.0.0.1:3000 run:app
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/portbridge /var/lib/portbridge
ExecStopPost=-/usr/bin/wg-quick down /etc/portbridge/pb0.conf
UMask=0077
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"
systemctl daemon-reload
systemctl enable --now portbridge.service
systemctl is-active --quiet portbridge.service
echo "PortBridge is running on 127.0.0.1:3000. Allow UDP 51820 in your server firewall."
