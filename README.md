<div align="center">
  <img src="images/banner.png" alt="PortBridge: reach devices behind NAT or CGNAT through a WireGuard server you control" width="100%">

  [![Release](https://img.shields.io/github/v/release/nooblk-98/portbridge?style=flat-square&logo=github&color=0ea5e9)](https://github.com/nooblk-98/portbridge/releases)
  [![Build](https://github.com/nooblk-98/portbridge/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/nooblk-98/portbridge/actions/workflows/release.yml)
  [![Docker pulls](https://img.shields.io/docker/pulls/lahiru98s/portbridge?style=flat-square&logo=docker&logoColor=white&color=2496ed)](https://hub.docker.com/r/lahiru98s/portbridge)
  [![Rust](https://img.shields.io/badge/Rust-1.85%2B-dea584?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
  [![WireGuard](https://img.shields.io/badge/WireGuard-powered-88171a?style=flat-square&logo=wireguard&logoColor=white)](https://www.wireguard.com/)
  [![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
</div>

PortBridge is a single Rust binary that pairs a WireGuard VPN server with iptables port forwarding, managed from a web dashboard. Run it on a public VPS to expose services from home labs, Starlink or other connections that cannot accept inbound traffic. Think of it as a **self-hosted alternative to Tailscale and Headscale**, with public port forwarding built in, that also works as a **bastion (jump) host**.

- **Private access**: share a host or subnet with other peers over WireGuard, with per-route access control.
- **Public forwarding**: publish a TCP or UDP port on the server and send it to a service on a peer, with optional source IP restrictions.
- **Live dashboard**: peers online, traffic over time, top talkers, connection health checks, and CPU, memory and disk gauges.
- **Easy onboarding**: create peers in the UI, then download the config or scan a QR code. Each peer gets its own cartoon avatar.
- **Split tunnel by default**: devices keep their own internet connection and IP. Switch a peer to full tunnel from its card when you want its traffic to leave through the server.
- **Safe defaults**: passwords are stored as salted hashes, logins are rate limited, and peers can only reach each other through routes you approve.

## Where PortBridge fits

PortBridge is a **self-hosted alternative to Tailscale and Headscale** for a common setup: you have a VPS with a public IP, and you want devices behind NAT or CGNAT, such as home labs, Starlink and mobile networks, to reach each other and be reachable, without a third-party account or hosted control plane.

It covers the same ground as, and can replace, tools such as:

- **VPN and mesh tools**: Tailscale, Headscale, NetBird, Netmaker, ZeroTier, Nebula, and WireGuard managers such as wg-easy.
- **Tunnels that publish a port**: frp, rathole, ngrok, Cloudflare Tunnel and Pangolin.

PortBridge is a **hub and spoke**, not a mesh: every peer connects to your server and traffic between peers passes through it. That keeps it simple, with plain WireGuard configs, one public UDP port and one binary. It also lets PortBridge do something most VPN tools do not: **publish a public TCP or UDP port** on the server and send it into a peer.

| Choose PortBridge when you want | Choose a mesh tool when you need |
| --- | --- |
| One server you control, with no external account or hosted coordination service | Direct peer-to-peer connections and NAT traversal between peers |
| To publish a service from behind CGNAT on a public port | Sign-in with your identity provider and per-user or per-group policies |
| Plain WireGuard profiles and QR codes that work with any client | Large teams or hundreds of devices |

### Use it as a bastion host

Every peer can reach the server, and any peer can share a subnet, so the VPS also works as a **bastion (jump) host** for machines that have no public address.

1. Add your laptop as a peer, and add a machine on the target network (for example a home server) as another.
2. In the home server's **Peer settings**, advertise its network, such as `192.168.1.0/24`, and use **Routes → Edit access** to choose who may use it.
3. With the laptop's tunnel up, reach the network directly, for example `ssh user@192.168.1.20`.

You can also jump through the server's public address with no VPN client on the laptop, because the server can reach every peer's tunnel address:

```sh
ssh -J ubuntu@vpn.example.com user@10.10.0.2
```

> [!TIP]
> Harden the bastion itself: allow SSH with keys only, restrict its firewall, and put the dashboard behind HTTPS or limit port 3000 to trusted addresses.

## Screenshots

<p align="center">
  <img src="images/screenshots/dashboard.png" alt="PortBridge dashboard with peers online, traffic, connection health, a traffic chart, top talkers and server gauges" width="100%">
</p>

<table>
  <tr>
    <td width="50%"><img src="images/screenshots/clients.png" alt="Clients: peer cards with avatars, a split tunnel switch, advertised routes and data usage"><br><sub><b>Clients</b>: avatars, a split tunnel switch, routes and data usage</sub></td>
    <td width="50%"><img src="images/screenshots/routes.png" alt="Routes: who may use each advertised route and which profiles need a fresh export"><br><sub><b>Routes</b>: who can use each route and which profiles need exporting</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="images/screenshots/forwarding.png" alt="Forwarding: public port rules"><br><sub><b>Forwarding</b>: publish a service on a public port</sub></td>
    <td width="50%"><img src="images/screenshots/peer-settings.png" alt="Peer settings: advertised routes, access per route, split tunnel, DNS, MTU and keepalive"><br><sub><b>Peer settings</b>: routes, access, split tunnel and network options</sub></td>
  </tr>
</table>

<p align="center">
  <img src="images/screenshots/dashboard-dark.png" alt="The dashboard in dark mode" width="100%"><br>
  <sub><b>Dark mode</b>: follows your system or your choice</sub>
</p>

## Architecture

<p align="center">
  <img src="images/architecture.png" alt="PortBridge architecture: a browser manages PortBridge on a public VPS, which configures WireGuard and iptables; peers behind NAT dial out over the tunnel and public traffic reaches their services through DNAT." width="100%">
</p>

- **Peers dial out.** Devices behind NAT or CGNAT connect to the server's WireGuard port and keep the tunnel alive, so they need no open inbound port.
- **The server is the hub.** PortBridge generates the WireGuard config and the iptables rules, and applies them with `wg`, `wg-quick` and `iptables-restore`.
- **Private routes and public ports.** Peers reach each other and shared subnets over the hub according to each route's access rules. A forwarding rule sends a public port into the tunnel to a service on a peer.
- **One binary.** An `axum` web server serves the dashboard and JSON API. State lives in JSON files under `DATA_DIR`, and the code behind the `Storage` and `Runner` seams is replaced by fakes in tests.

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

Peers use split tunneling by default: only VPN and advertised-route traffic goes through the tunnel, so a device keeps its own internet connection and public IP. To send all of a device's traffic through the server, turn off **Split tunnel** in that peer's settings and re-import its profile. The server allows this by default. To block this, set `ALLOW_INTERNET_EGRESS=0` in `/etc/portbridge/portbridge.env` (or the Compose service environment) and restart.

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

See [CHANGELOG.md](CHANGELOG.md) for what changed in each release. On Debian or Ubuntu, use `--upgrade` as shown above. With Docker, pull the new image and recreate the container. Keep the same Compose project name and data volume. If you are upgrading from the earlier Python version, sign in again and recreate legacy public forwards for the intended peers.

## Development

```sh
cargo build
cargo test
```

See [CONTEXT.md](CONTEXT.md) for the domain language and module overview.
