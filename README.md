# PortBridge

PortBridge connects devices behind NAT or CGNAT to a WireGuard server you control. Use **Peer settings** to reach a host or subnet privately over WireGuard. Use **Forwarding** when a service needs to be reachable from the internet on a public TCP or UDP port.

## Install on Debian or Ubuntu without Docker

Use a dedicated server with systemd, sudo access, and a public IP address or DNS name. Allow inbound UDP 51820 in your server and provider firewalls.

```sh
git clone https://github.com/nooblk-98/portbridge.git
cd portbridge
sudo bash install.sh vpn.example.com
```

The installer prompts for the dashboard password and starts the `portbridge` service. It uses the `pb0` WireGuard interface and keeps peer data in `/var/lib/portbridge`. The dashboard listens on localhost. Open an SSH tunnel from your computer, then visit <http://localhost:3000>.

```sh
ssh -N -L 3000:127.0.0.1:3000 user@vpn.example.com
```

For service status, run `sudo systemctl status portbridge`. For logs, run `sudo journalctl -u portbridge -e`.

## Connect a device

1. Sign in to the dashboard and create a peer under **Clients**.
2. Download its WireGuard configuration or scan the QR code with the [WireGuard app](https://www.wireguard.com/install/).
3. Activate the tunnel. Under **Clients**, check for a recent handshake.

A device can offer services on its own WireGuard IP. Make sure those services listen on the tunnel address and the device firewall allows traffic from the VPN.

## Share a host or subnet privately

1. Open **Clients → Peer settings** for the device that owns or can reach the host.
2. Enter an IPv4 address such as `192.168.50.10` to share one host or a CIDR such as `192.168.50.0/24` to share a subnet. Save the settings.
3. If the destination is behind the advertising device, enable IP forwarding on that device, allow forwarding in its firewall, and add a return route to the WireGuard subnet through that device (or configure source NAT there).
4. For receiving peers using **Split tunnel**, re-import their updated configuration so the new destination is routed over WireGuard. Then connect to the destination IP and its normal service port.

Advertised routes must be distinct and must not overlap the VPN subnet. Clearing the route list withdraws the advertisement. Route changes briefly reconnect the server tunnel. PortBridge distributes route changes through updated WireGuard profiles. You can also set DNS, MTU and persistent keepalive per peer. Re-import the relevant profile after changing those options.

## Publish a specific service

Open **Forwarding**, create a rule, and select a public port, protocol, target peer and service port. Set a source IP or CIDR to restrict access when needed. Allow the public port through the server and provider firewalls. For Docker, publish the same port and protocol in Compose.

## Existing Docker installations

The [Compose example](docker-compose-live.yml) uses the published image. Set `WG_HOST` and a strong `ADMIN_PASSWORD` before starting it. Existing Docker volumes contain your peer keys and rules. Keep the volume when upgrading. Features documented here require an image built from a version that includes them.
