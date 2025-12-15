# PortBridge

A professional, lightweight WireGuard manager and port forwarding solution. Easily expose services running behind NAT (like home routers) through a public VPS.

**[🌐 View Full Project & Documentation on GitHub](https://github.com/nooblk-98/portbridge)**

---

## 🚀 Quick Start

**One-Line Deployment:**
```bash
wget -O docker-compose.yml https://raw.githubusercontent.com/nooblk-98/lighthouse/refs/heads/main/docker-compose.live.yml && docker compose up -d
```

**Manual Configuration:**

```yaml
version: "3.8"

services:
  wg-forwarder:
    image: lahiru98s/portbridge:latest
    container_name: portbridge

    environment:
      WG_HOST: 80.225.221.245
      WG_PORT: 51820
      WG_NETWORK: 10.8.0.0/24
      WG_ADDRESS: 10.8.0.1/24
      APP_PORT: 3000
      ADMIN_PASSWORD: admin

    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    ports:
      - "51820:51820/udp"
      - "3000:3000/tcp"
      - "30000-30100:30000-30100/tcp"

    volumes:
      - wg-data:/data
      - /lib/modules:/lib/modules:ro

    restart: unless-stopped

volumes:
  wg-data:
```

## ✨ Key Features
*   **WireGuard Management**: Easy Web UI for peers.
*   **Port Forwarding**: Expose local ports via VPS.
*   **No Public IP Needed**: Works behind CGNAT/Starlink.
*   **Zero Config**: Docker-ready.

Visit the [GitHub Repository](https://github.com/nooblk-98/portbridge) for the full guide.
