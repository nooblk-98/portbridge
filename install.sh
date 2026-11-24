#!/usr/bin/env bash
set -euo pipefail
umask 077


usage() {
    cat >&2 <<'USAGE'
Usage:
  sudo bash install.sh <public WireGuard hostname or IP>   Install PortBridge
  sudo bash install.sh --upgrade                           Upgrade to the latest release
  sudo bash install.sh --uninstall [--purge]               Remove PortBridge (--purge also deletes peers and keys)
USAGE
    exit 1
}

mode=install
purge=0
endpoint=
case ${1:-} in
    --upgrade) mode=upgrade; shift ;;
    --uninstall)
        mode=uninstall
        shift
        if [[ ${1:-} == --purge ]]; then purge=1; shift; fi
        ;;
    -h | --help) usage ;;
esac
if [[ ${EUID} -ne 0 ]]; then
    echo "Run the installer as root, for example with sudo." >&2
    usage
fi
if [[ $mode == install ]]; then
    [[ $# -eq 1 ]] || usage
    endpoint=$1
else
    [[ $# -eq 0 ]] || usage
fi

# When piped from curl or wget there is no script file, so there is no local
# release archive and the latest release is downloaded instead.
script_path=${BASH_SOURCE[0]:-}
source_dir=
if [[ -n $script_path && -f $script_path ]]; then
    source_dir=$(cd -- "$(dirname -- "$script_path")" && pwd)
fi
release_repo=nooblk-98/portbridge
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

download() {
    local url=$1 out=$2
    if command -v curl >/dev/null; then
        # Time out and retry instead of hanging on a stalled connection.
        curl -fsSL --connect-timeout 15 --max-time 300 --retry 3 --retry-delay 3 -o "$out" "$url"
    elif command -v wget >/dev/null; then
        wget -q -T 30 -t 3 -O "$out" "$url"
    else
        die "curl or wget is required to download PortBridge. Install one with: apt-get install -y curl"
    fi
}

# Download the latest release (or PORTBRIDGE_VERSION, for example v1.0.1),
# verify its SHA-256 checksum, and use it as the install source.
fetch_release() {
    local arch base archive expected
    case "$(uname -m)" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) die "Unsupported architecture: $(uname -m)" ;;
    esac
    if [[ -n ${PORTBRIDGE_VERSION:-} ]]; then
        [[ $PORTBRIDGE_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] ||
            die "PORTBRIDGE_VERSION must look like v1.2.3."
        base="https://github.com/$release_repo/releases/download/$PORTBRIDGE_VERSION"
    else
        base="https://github.com/$release_repo/releases/latest/download"
    fi
    archive=portbridge-linux-$arch.tar.gz
    work_dir=$(mktemp -d)
    trap 'rm -rf "$work_dir"' EXIT
    echo "Downloading $archive from $base"
    download "$base/$archive" "$work_dir/$archive"
    download "$base/SHA256SUMS" "$work_dir/SHA256SUMS"
    expected=$(awk -v file="$archive" '$2 == file {print $1}' "$work_dir/SHA256SUMS")
    [[ -n $expected ]] || die "No checksum published for $archive."
    printf '%s  %s\n' "$expected" "$archive" | (cd "$work_dir" && sha256sum -c -) ||
        die "Checksum verification failed for $archive."
    tar -xzf "$work_dir/$archive" -C "$work_dir"
    source_dir=$work_dir/${archive%.tar.gz}
    portbridge_bin=$source_dir/portbridge
}

if [[ $mode == uninstall ]]; then
    systemctl disable --now portbridge.service </dev/null 2>/dev/null || true
    rm -f "$unit"
    systemctl daemon-reload </dev/null 2>/dev/null || true
    rm -rf "$app_dir" "$config_dir"
    if [[ $purge -eq 1 ]]; then
        rm -rf "$state_dir"
        echo "PortBridge was removed, including its peers and keys."
    else
        echo "PortBridge was removed. Peers and keys remain in $state_dir (use --uninstall --purge to delete them)."
    fi
    exit 0
fi

if ! command -v apt-get >/dev/null || ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
    die "This installer requires Debian or Ubuntu with systemd."
fi

if [[ $mode == install ]]; then
    if ! is_ipv4 "$endpoint" && ! is_ipv6 "$endpoint" && ! is_hostname "$endpoint"; then
        die "Supply a hostname or bare IP address, without a URL, port or zone."
    fi
    for path in "$app_dir" "$config_dir" "$unit"; do
        if [[ -e $path || -L $path ]]; then
            die "Existing path: $path. Use --upgrade to update, or --uninstall first."
        fi
    done
    if [[ -e /etc/wireguard/pb0.conf ]] || ip link show dev pb0 >/dev/null 2>&1; then
        die "The pb0 WireGuard interface is already in use."
    fi
    if [[ -e $state_dir ]]; then
        echo "Reusing existing PortBridge data in $state_dir."
    fi
else
    if [[ ! -x $app_dir/portbridge || ! -f $unit ]]; then
        die "PortBridge is not installed. Run the installer with your hostname or IP first."
    fi
fi

# A release archive keeps the binary next to install.sh; a source checkout
# passes PORTBRIDGE_BINARY explicitly; otherwise the latest release is fetched.
work_dir=
portbridge_bin=${PORTBRIDGE_BINARY:-}
if [[ -z $portbridge_bin ]]; then
    if [[ -n $source_dir && -x $source_dir/portbridge ]]; then
        portbridge_bin=$source_dir/portbridge
    else
        fetch_release
    fi
fi
if [[ ! -f $portbridge_bin || ! -x $portbridge_bin ]]; then
    die "PortBridge binary not found at $portbridge_bin. Use a complete release archive or set PORTBRIDGE_BINARY to a trusted build."
fi
if [[ -z $source_dir || ! -f $source_dir/app/templates/login.html || ! -f $source_dir/app/static/js/app.js ]]; then
    die "The installer is missing the dashboard files (app/templates and app/static). Use a complete release archive or repository checkout."
fi

write_unit() {
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
PrivateTmp=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
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
}

if [[ $mode == upgrade ]]; then
    # Replace the program and dashboard files; settings, peers and keys stay.
    stage=$app_dir/.upgrade.$$
    install -d -m 0750 "$stage" "$stage/app"
    cp -R "$source_dir/app/." "$stage/app/"
    install -m 0755 "$portbridge_bin" "$stage/portbridge"
    mv -f "$stage/portbridge" "$app_dir/portbridge"
    rm -rf "$app_dir/app.old"
    mv "$app_dir/app" "$app_dir/app.old"
    mv "$stage/app" "$app_dir/app"
    rm -rf "$stage" "$app_dir/app.old"
    write_unit
    systemctl daemon-reload </dev/null
    systemctl restart portbridge.service </dev/null
    systemctl is-active --quiet portbridge.service </dev/null
    echo "PortBridge was upgraded to $("$app_dir/portbridge" --version </dev/null) and restarted."
    exit 0
fi

# Unattended installs can supply PORTBRIDGE_ADMIN_PASSWORD. Otherwise read from
# the terminal so the prompt also works when the script is piped in.
if [[ -n ${PORTBRIDGE_ADMIN_PASSWORD:-} ]]; then
    password=$PORTBRIDGE_ADMIN_PASSWORD
else
    if ! read -rsp "Dashboard password (at least 16 letters or numbers): " password </dev/tty; then
        echo
        die "The dashboard password prompt needs an interactive terminal."
    fi
    echo
fi
if [[ ! $password =~ ^[A-Za-z0-9]{16,128}$ ]]; then
    die "Choose a password of 16 to 128 letters or numbers."
fi

# Store a salted hash instead of the password. Older releases cannot hash, so
# fall back to the plaintext setting for them.
password_setting=
password_hash=$("$portbridge_bin" hash-password <<<"$password" 2>/dev/null || true)
if [[ $password_hash =~ ^pbkdf2-sha256\$[0-9]+\$[0-9a-f]+\$[0-9a-f]{64}$ ]]; then
    password_setting="ADMIN_PASSWORD_HASH=$password_hash"
else
    echo "This release cannot hash passwords; storing the password in $config_dir/portbridge.env." >&2
    password_setting="ADMIN_PASSWORD=$password"
fi
unset password

# Child commands read /dev/null so they cannot consume a script piped on stdin.
apt-get update </dev/null
apt-get install -y ca-certificates iproute2 iptables procps wireguard-tools </dev/null

install -d -m 0700 "$app_dir" "$config_dir" "$state_dir"
install -d -m 0750 "$app_dir/app"
cp -R "$source_dir/app/." "$app_dir/app/"
install -m 0755 "$portbridge_bin" "$app_dir/portbridge"

cat > "$config_dir/portbridge.env" <<ENV
WG_HOST=$endpoint
WG_INTERFACE=pb0
WG_CONFIG_PATH=$config_dir/pb0.conf
DATA_DIR=$state_dir
$password_setting
SEED_FORWARDING=0
ENABLE_IPV4_FORWARDING=1
APP_HOST=0.0.0.0
APP_PORT=3000
ENV

write_unit
systemctl daemon-reload
systemctl enable --now portbridge.service
systemctl is-active --quiet portbridge.service
echo "PortBridge is running. Allow UDP 51820 (WireGuard) and TCP 3000 (dashboard) in your server firewall."
echo "The dashboard is served over plain HTTP at http://$endpoint:3000; put it behind HTTPS before exposing it widely."
