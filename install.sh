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

# Full IPv6 literal check (RFC 4291), including an embedded IPv4 address.
ipv6_re='^(([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:)|([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:)|([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:)|([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)|([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)|([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))$'

die() {
    echo "$*" >&2
    exit 1
}

is_ipv4() {
    local host=$1 octet
    [[ $host =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    for octet in $host; do
        [[ $octet =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        ((octet <= 255)) || return 1
    done
}

is_ipv6() {
    [[ $1 =~ $ipv6_re ]]
}

is_hostname() {
    local host=${1%.} label
    [[ -n $host && ${#host} -le 253 ]] || return 1
    local IFS=.
    for label in $host; do
        [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
        [[ $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
        # Reject labels that are only digits so malformed IPv4 addresses fail here.
        [[ ! $label =~ ^[0-9]+$ ]] || return 1
    done
}

if ! is_ipv4 "$endpoint" && ! is_ipv6 "$endpoint" && ! is_hostname "$endpoint"; then
    die "Supply a hostname or bare IP address, without a URL, port or zone."
fi

for path in "$app_dir" "$config_dir" "$state_dir" "$unit"; do
    if [[ -e $path || -L $path ]]; then
        die "Existing path: $path. This installer is for fresh installations."
    fi
done
if ! command -v apt-get >/dev/null || ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    die "This installer requires Debian or Ubuntu with systemd."
fi
if [[ -e /etc/wireguard/pb0.conf ]] || ip link show dev pb0 >/dev/null 2>&1; then
    die "The pb0 WireGuard interface is already in use."
fi

read -rsp "Dashboard password (at least 16 letters or numbers): " password
echo
if [[ ! $password =~ ^[A-Za-z0-9]{16,128}$ ]]; then
    die "Choose a password of 16 to 128 letters or numbers."
fi

portbridge_bin=${PORTBRIDGE_BINARY:-}
if [[ -z $portbridge_bin || ! -f $portbridge_bin || ! -x $portbridge_bin ]]; then
    die "Set PORTBRIDGE_BINARY to an executable from a trusted PortBridge build. See the README for build steps."
fi

apt-get update
apt-get install -y ca-certificates iproute2 iptables procps wireguard-tools

install -d -m 0700 "$app_dir" "$config_dir" "$state_dir"
install -d -m 0750 "$app_dir/app"
cp -R "$source_dir/app/." "$app_dir/app/"
install -m 0755 "$portbridge_bin" "$app_dir/portbridge"

cat > "$config_dir/portbridge.env" <<ENV
WG_HOST=$endpoint
WG_INTERFACE=pb0
WG_CONFIG_PATH=$config_dir/pb0.conf
DATA_DIR=$state_dir
ADMIN_PASSWORD=$password
SEED_FORWARDING=0
ENABLE_IPV4_FORWARDING=1
APP_HOST=127.0.0.1
APP_PORT=3000
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
# Keep the shared iptables lock usable inside the read-only mount namespace.
ExecStartPre=+/usr/bin/touch /run/xtables.lock
ExecStart=/opt/portbridge/portbridge
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/portbridge /var/lib/portbridge -/run/xtables.lock
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
