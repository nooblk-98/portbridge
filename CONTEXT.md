# PortBridge Domain Language

## Domain

PortBridge exposes services running on devices behind NAT/CGNAT/Starlink through a public VPS by combining a WireGuard VPN server with iptables-based port forwarding, all managed through a web UI.

## Core Concepts

**WireGuard tunnel** — an encrypted VPN link between the VPS (server) and a remote device (client). The tunnel uses a virtual subnet (default `10.8.0.0/24`).

**Peer / Client** — a remote device that connects to PortBridge over WireGuard. Each peer gets a unique IP in the tunnel subnet, a keypair, and a config file. Peers are managed through the UI.

**Port forward** — a rule that maps a public port on the VPS to a target port on a connected peer's device. Forwarding is implemented with iptables DNAT and FORWARD rules.

**Forwarding rule** — a single port forward entry with protocol (TCP/UDP/both), public port (or range), target peer, internal target port, and optional source IP whitelist.

**Advertised route** — a private or shared IPv4 range owned by a peer and routed over the tunnel. Another peer can reach it only when route access permits it.

**Route access** — per advertised route, the set of recipient peer public keys allowed to reach it. A missing entry means every connected peer (legacy behaviour); an empty list denies every recipient. The advertising peer can always use its own route.

**Bootstrap** — the initialization sequence run at startup: ensure directories, generate server keys, seed a default peer, write WireGuard config, bounce the interface, apply iptables rules.

## Technical Structure

**Config** — reads its settings from environment variables and paths (`DATA_DIR`, `WG_*`, `APP_HOST`, `APP_PORT`, `ADMIN_PASSWORD`). `APP_HOST` defaults to `0.0.0.0`, `APP_PORT` to `3000`.

**Storage** — a seam that persists JSON state and text files. `JsonFileStorage` reads/writes the real filesystem; `InMemoryStorage` supports tests.

**Runner** — a seam that wraps subprocess execution. `SystemRunner` runs real commands; `FakeRunner` records commands and returns canned output.

**RuleRenderer** — a pure module that translates forwarding rule data into structured iptables rule descriptors. No I/O, no subprocess.

**WireGuardService** — manages key generation, peer configuration, interface control, route overlap checks and status queries. Depends on `Runner`, `Storage` and `Config`.

**IPTablesService** — renders and applies the managed chains with `iptables-restore`, including route access and the default-DROP policy. Depends on `Runner`, `Storage` and `Config`.

**ClientManager** — orchestrates peer lifecycle (create, rename, options, delete), profile revisions, route-access rollback and bootstrap by coordinating `WireGuardService`, `ForwardingManager` and `Storage`.

**ForwardingManager** — orchestrates port forwarding rule lifecycle (add, remove) by coordinating `IPTablesService`, `Storage` and `RuleRenderer`.

**Auth** — bounded-expiry server-side sessions with random opaque tokens, password-bound session and remember cookies, constant-time password comparison and the per-IP login rate limit. Sessions from the earlier Python version are not accepted, so upgrading from it needs one login.

**Web** — the axum router, JSON API, Jinja-compatible templates and static assets. Templates live under `app/templates` and static assets under `app/static`; the stylesheet is built from `frontend/` (see `frontend/README.md`).
