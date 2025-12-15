<div align="center">
  <img src="https://raw.githubusercontent.com/nooblk-98/portbridge/main/images/logo/logo.png" width="360" alt="PortBridge logo" />

  # PortBridge
  
A professional, lightweight, and user-friendly solution for managing WireGuard peers and port forwarding rules. Designed to easily expose services running behind NAT (like home routers or private networks) through a public VPS, without needing a public IP at the source.

  <div>
    <a href="https://hub.docker.com/r/lahiru98s/portbridge"><img src="https://img.shields.io/docker/pulls/lahiru98s/portbridge.svg" alt="Docker UI pulls" /></a>
    <a href="https://github.com/nooblk-98/portbridge/releases"><img src="https://img.shields.io/github/v/release/nooblk-98/portbridge?logo=github" alt="Latest release" /></a>
     <a href="https://creativecommons.org/licenses/by-nc/2.0/">
    <img src="https://img.shields.io/badge/License-CC%20BY--NC%202.0-blue.svg" alt="License: CC BY-NC 2.0" />
  </div>
</div>

---

## 🚀 Key Features

*   **Easy Peer Management**: Create, delete, and manage WireGuard clients with a few clicks.
*   **QR Code Support**: Instantly generate QR codes for mobile client configuration.
*   **Dynamic Port Forwarding**: Forward TCP/UDP ports from your public server to any connected client.
*   **Port Range Support**: Forward entire ranges of ports (e.g., `8000-8100`) for games and complex apps.
*   **Source IP Whitelisting**: Restrict access to forwarded ports to specific IP addresses for enhanced security.
*   **Real-time Monitoring**: View client online status, handshake times, and **bandwidth usage (RX/TX)**.
*   **Secure Dashboard**: Built-in authentication to protect your management UI.
*   **Dark Mode**: Fully supported dark theme for comfortable viewing.
*   **Dockerized**: Runs in a lightweight Alpine container with minimal dependencies.

---

## 🏗️ Architecture & How It Works

This application solves the problem of accessing services hosted on networks without a public IP (e.g., Starlink, CGNAT, or dynamic residential IPs).

### The Concept
You run this application on a **VPS** (Virtual Private Server) that has a Public IP. Your home devices (Clients) connect to this VPS via a WireGuard tunnel. The VPS then acts as a gateway, forwarding traffic from specific public ports through the tunnel to your home devices.

---

## 🛠️ Deployment Guide

### Prerequisites
*   A VPS with a Public IP (Ubuntu/Debian recommended).
*   Docker and Docker Compose installed.
*   Root access (required for managing network interfaces).

### Quick Start

Create a `docker-compose.yml`:

```yaml
version: "3"
services:
  app:
    image: lahiru98s/portbridge:latest
    cap_add:
      - NET_ADMIN
    network_mode: host  # Required for manipulating host interfaces
    environment:
      - WG_HOST=your.public.ip.address  # IMPORTANT: Your VPS Public IP
      - ADMIN_PASSWORD=secure_password
      # Optional:
      # - WG_PORT=51820
      # - APP_PORT=3000
      # - WG_INTERFACE=wg0
    volumes:
      - ./data:/data
    restart: unless-stopped
```

Run the container:
```bash
docker-compose up -d
```

---

## 💻 Client Connection Guide

1.  Open the Web UI (`http://<your-vps-ip>:3000`).
2.  Go to the **Clients** tab -> **"New Client"**.
3.  Name it (e.g., `Home-Server`) and Create.
4.  Download the Config or Scan QR Code on your device.

---

## 🔗 Port Forwarding (The Magic)

Let's expose a service (e.g., a Web App on port 80) running on your home machine.

1.  **Open a Port** in the **Forwarding** tab.
    *   **Public Port**: `20000`
    *   **Internal Port**: `80`
    *   **Target Client**: Select `Home-Server`
2.  **Access**: `http://<VPS-Public-IP>:20000` -> now routes to your Home Server's port 80!

---

## 🛡️ Security Notes

*   **Firewall**: Ensure your VPS firewall allows the ports you expose.
*   **Web UI**: Defaults to port `3000` with Basic Auth (or configured password).
