<div align="center">
  <img src="images/banner.png" alt="PortBridge: reach devices behind NAT or CGNAT through a WireGuard server you control" width="100%">

  [![Release](https://img.shields.io/github/v/release/nooblk-98/portbridge)](https://github.com/nooblk-98/portbridge/releases)
  [![Docker image](https://img.shields.io/docker/pulls/lahiru98s/portbridge)](https://hub.docker.com/r/lahiru98s/portbridge)
  [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

PortBridge is a single Rust binary that pairs a WireGuard VPN server with iptables port forwarding, managed from a web dashboard. Run it on a public VPS to expose services from home labs, Starlink or other connections that cannot accept inbound traffic.

- **Private access**: share a host or subnet with other peers over WireGuard, with per-route access control.
- **Public forwarding**: publish a TCP or UDP port on the server and send it to a service on a peer, with optional source IP restrictions.
- **Easy onboarding**: create peers in the UI, then download the config or scan a QR code.
- **Safe defaults**: passwords are stored as salted hashes, logins are rate limited, and peers can only reach each other through routes you approve.

## Screenshots

<p align="center">
  <img src="images/screenshots/dashboard.png" alt="PortBridge dashboard" width="100%">
</p>

<table>
  <tr>
    <td width="50%"><img src="images/screenshots/clients.png" alt="Clients: connected peers with handshake and data usage"><br><sub><b>Clients</b>: peers, handshakes and data usage</sub></td>
    <td width="50%"><img src="images/screenshots/routes.png" alt="Routes: who may use each advertised route"><br><sub><b>Routes</b>: advertised routes and who can reach them</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="images/screenshots/forwarding.png" alt="Forwarding: public port rules"><br><sub><b>Forwarding</b>: publish a service on a public port</sub></td>
    <td width="50%"><img src="images/screenshots/dashboard-dark.png" alt="Dashboard in dark mode"><br><sub><b>Dark mode</b>: follows your system or your choice</sub></td>
  </tr>
</table>

## Quick start

You need a server with a public IP or DNS name, and UDP 51820 allowed through its firewall and your provider's.

### Docker Compose

Create a `.env` file with your server's address and a strong dashboard password:

```ini
WG_HOST=vpn.example.com
ADMIN_PASSWORD=change-me-to-a-long-password
```

Then start the [published image](docker-compose-live.yml):

```sh
docker compose -f docker-compose-live.yml up -d
```

To build from a local checkout instead, run `docker compose up -d --build`.


The dashboard is then available at `http://vpn.example.com:3000`. Allow TCP 3000 through your server and provider firewalls.

> [!WARNING]
> The dashboard is served over plain HTTP, so your password is sent unencrypted. Put it behind an HTTPS reverse proxy, restrict port 3000 to trusted addresses in your firewall, or bind it to localhost (`APP_HOST=127.0.0.1`, or `"127.0.0.1:3000:3000/tcp"` in Compose) and use an SSH tunnel: `ssh -N -L 3000:127.0.0.1:3000 user@vpn.example.com`.

### Debian or Ubuntu (no Docker)

Requires systemd and sudo. Run the installer with your server's public hostname or IP in place of `vpn.example.com`. It downloads the latest release for your architecture (`x86_64` or `arm64`), verifies its SHA-256 checksum, and prompts for a dashboard password. No Rust toolchain is needed.

```sh
curl -fsSL https://raw.githubusercontent.com/nooblk-98/portbridge/main/install.sh | sudo bash -s -- vpn.example.com
```

With `wget`:

```sh
wget -qO- https://raw.githubusercontent.com/nooblk-98/portbridge/main/install.sh | sudo bash -s -- vpn.example.com
```

To pin a version, set `PORTBRIDGE_VERSION` on the `sudo` side, for example `| sudo PORTBRIDGE_VERSION=v1.0.0 bash -s -- vpn.example.com`.

The installer prompts for a dashboard password (16–128 letters or numbers) and stores only a salted hash of it. It creates the `pb0` WireGuard interface, stores data in `/var/lib/portbridge`, and starts the `portbridge` service. The dashboard listens on port 3000 (allow TCP 3000 in your firewall). See the warning above about HTTP.

```sh
sudo systemctl status portbridge
sudo journalctl -u portbridge -e
```

To upgrade to the latest release or remove PortBridge, run the same script with a flag:

```sh
curl -fsSL https://raw.githubusercontent.com/nooblk-98/portbridge/main/install.sh | sudo bash -s -- --upgrade
curl -fsSL https://raw.githubusercontent.com/nooblk-98/portbridge/main/install.sh | sudo bash -s -- --uninstall
```

An upgrade keeps your settings, peers and keys. An uninstall keeps peers and keys in `/var/lib/portbridge` unless you add `--purge`.

<details>
<summary>Build from source</summary>

Install `build-essential` and Rust 1.85 or newer, then:

```sh
git clone https://github.com/nooblk-98/portbridge.git
cd portbridge
cargo build --release --locked --bin portbridge
sudo PORTBRIDGE_BINARY="$PWD/target/release/portbridge" bash install.sh vpn.example.com
```

</details>

## Usage

### Connect a device

1. Sign in and create a peer under **Clients**.
2. Download its WireGuard configuration or scan the QR code with the [WireGuard app](https://www.wireguard.com/install/).
3. Activate the tunnel and check **Clients** for a recent handshake.

### Share a host or subnet privately

1. Open **Clients → Peer settings** for the device that owns or can reach the host.
2. Enter an IPv4 address (`192.168.50.10`) or CIDR (`192.168.50.0/24`) and save.
3. If the destination sits behind that device, enable IP forwarding on it, allow forwarding in its firewall, and add a return route to the WireGuard subnet (or use source NAT).
4. Peers using **Split tunnel** must re-import their updated profile. They can then connect to the destination IP directly.

You can advertise private IPv4 ranges and `100.64.0.0/10`. Routes must be distinct and cannot overlap the VPN subnet or existing server routes. DNS, MTU and keepalive can also be set per peer.

Open **Routes** and select **Edit access** to choose which peers may use a route. An empty selection blocks every other peer.

### Publish a service to the internet

Open **Forwarding**, create a rule, and choose a public port, protocol, target peer and service port. Optionally restrict it to a source IP or CIDR.

The service sees the original client address, so its replies must return through WireGuard. With a split-tunnel profile, add a return route for the permitted sources, or use a full-tunnel profile. Allow the public port through your firewalls, and for Docker add the port to the Compose `ports` list, for example `"30000:30000/tcp"`.

### Internet access through the VPN

Peers can reach the internet through the server by default. Devices with full-tunnel profiles send their IPv4 internet traffic through it. To block this, set `ALLOW_INTERNET_EGRESS=0` in `/etc/portbridge/portbridge.env` (or the Compose service environment) and restart. Devices on split-tunnel profiles only send VPN traffic through the tunnel either way.

## Configuration

PortBridge is configured through environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `ADMIN_PASSWORD` | required unless a hash is set | Dashboard password |
| `ADMIN_PASSWORD_HASH` | unset | Salted PBKDF2 hash used instead of `ADMIN_PASSWORD`. Create one with `echo -n 'your-password' \| portbridge hash-password` |
| `WG_HOST` | `127.0.0.1` | Public hostname or IP written into peer configs |
| `WG_PORT` | `51820` | WireGuard UDP port |
| `WG_NETWORK` | `10.8.0.0/24` | VPN subnet |
| `WG_INTERFACE` | `wg0` | WireGuard interface name |
| `APP_HOST` / `APP_PORT` | `0.0.0.0` / `3000` | Dashboard bind address |
| `DATA_DIR` | `/data` | Where keys and state are stored |
| `ALLOW_INTERNET_EGRESS` | allowed | Set to `0` to block peer internet access through the server |

## Upgrading

On Debian or Ubuntu, use `--upgrade` as shown above. With Docker, pull the new image and recreate the container. Keep the same Compose project name and data volume. If you are upgrading from the earlier Python version, sign in again and recreate legacy public forwards for the intended peers.

## Development

```sh
cargo build
cargo test
```

See [CONTEXT.md](CONTEXT.md) for the domain language and module overview.
