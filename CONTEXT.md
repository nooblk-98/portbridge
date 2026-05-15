# PortBridge Domain Language

## Domain

PortBridge exposes services running on devices behind NAT/CGNAT/Starlink through a public VPS by combining a WireGuard VPN server with iptables-based port forwarding, all managed through a web UI.

## Core Concepts

**WireGuard tunnel** — an encrypted VPN link between the VPS (server) and a remote device (client). The tunnel uses a virtual subnet (default `10.8.0.0/24`).

**Peer / Client** — a remote device that connects to PortBridge over WireGuard. Each peer gets a unique IP in the tunnel subnet, a keypair, and a config file. Peers are managed through the UI.

**Port forward** — a rule that maps a public port on the VPS to a target port on a connected peer's device. Forwarding is implemented with iptables DNAT and FORWARD rules.

**Forwarding rule** — a single port forward entry with protocol (TCP/UDP/both), public port (or range), target peer, internal target port, and optional source IP whitelist.

**Bootstrap** — the initialization sequence run at container startup: ensures directories, generates server keys, seeds a default peer, writes WireGuard config, bounces the WireGuard interface, applies iptables rules.

## Technical Structure

**ConfigProvider** — a seam that supplies all configuration values (env vars, paths, secrets). Callers depend on the interface, not module-level globals.

**CommandRunner** — a seam that wraps subprocess execution. One adapter runs real commands (`SubprocessRunner`); a fake adapter records commands for tests.

**StorageBackend** — a seam that persists JSON state and files. One adapter reads/writes the real filesystem (`JsonFileStorage`); an in-memory adapter supports tests.

**RuleRenderer** — a pure module that translates forwarding rule data into structured iptables rule descriptors. No I/O, no subprocess.

**WireGuardService** — the module behind the WireGuard seam. Manages key generation, peer configuration, interface control, and status queries. Depends on `CommandRunner`, `StorageBackend`, and `ConfigProvider`.

**IPTablesService** — the module behind the iptables seam. Applies and removes port forwarding rules. Depends on `CommandRunner`, `StorageBackend`, and `ConfigProvider`.

**ClientManager** — a service that orchestrates peer lifecycle (create, rename, delete) by coordinating `WireGuardService`, `IPTablesService`, and `StorageBackend`.

**ForwardingManager** — a service that orchestrates port forwarding rule lifecycle (add, remove) by coordinating `IPTablesService`, `StorageBackend`, and `RuleRenderer`.
