import ipaddress
import json
import logging
import os
import re
from threading import RLock

from app.core.peer_options import PRIVATE_ROUTES, allowed_recipient_addresses, peer_options, validated_peers
from app.core.providers import CommandRunner, ConfigProvider, StorageBackend
from app.core.rule_renderer import protocols_overlap, render_rule

EGRESS_BLOCKS = (
    *PRIVATE_ROUTES,
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "168.63.129.16/32",
    "192.0.0.0/24",
    "224.0.0.0/3",
)


class IPTablesService:
    def __init__(self, config: ConfigProvider, storage: StorageBackend, runner: CommandRunner):
        self._config = config
        self._storage = storage
        self._runner = runner
        self._lock = RLock()

    def detect_primary_interface(self) -> str:
        try:
            result = self._runner.run(["sh", "-c", "ip route show default | awk '{print $5; exit}'"], check=False)
            iface = result.stdout.strip()
            if iface:
                return iface
        except Exception:
            return "eth0"
        return "eth0"

    def _install_chain(self, table, chain, parent, rules):
        command = ["iptables", "-w", "-t", table]
        # Restore replaces the entire managed chain in one table transaction.
        entries = [f"*{table}", f":{chain} - [0:0]", f"-F {chain}"]
        if any(not re.fullmatch(r"[A-Za-z0-9_.:/,-]+", arg) for rule in rules for arg in rule):
            raise ValueError("Invalid firewall rule argument.")
        entries.extend(f"-A {chain} " + " ".join(rule) for rule in rules)
        jump = f"-j {chain}"
        present = self._runner.run(command + ["-C", parent, "-j", chain], check=False).returncode == 0
        if present and table == "filter":
            entries.append(f"-D {parent} {jump}")
        if not present or table == "filter":
            entries.append(f"-I {parent} 1 {jump}")
        self._runner.run(["iptables-restore", "-w", "--noflush"], input_data="\n".join([*entries, "COMMIT", ""]))

    def _routing_rules(self, ext_iface):
        interface = self._config.wg_interface
        network = str(self._config.wg_network)
        same_tunnel = ["-i", interface, "-o", interface]
        established = ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"]
        rules = [same_tunnel + ["-s", network, "-d", network, "-j", "ACCEPT"]]
        clients = validated_peers(self._storage.load_json(str(self._config.clients_file), []))
        for peer in clients:
            for route in peer_options(peer)["advertised_routes"]:
                if not isinstance(route, str):
                    continue
                for address in allowed_recipient_addresses(peer, route, clients):
                    rules.append(same_tunnel + ["-s", f"{address}/32", "-d", route, "-j", "ACCEPT"])
                    rules.append(same_tunnel + ["-s", route, "-d", f"{address}/32", *established, "-j", "ACCEPT"])
        if os.environ.get("ALLOW_INTERNET_EGRESS") == "1":
            for destination in (*EGRESS_BLOCKS, *self._external_connected_routes(ext_iface)):
                rules.append(["-i", interface, "-o", ext_iface, "-d", str(destination), "-j", "DROP"])
            rules.append(["-i", interface, "-o", ext_iface, "-s", network, "-j", "ACCEPT"])
            rules.append(["-i", ext_iface, "-o", interface, "-d", network, *established, "-j", "ACCEPT"])
        return rules

    def _external_connected_routes(self, interface):
        result = self._runner.run(["ip", "-j", "-4", "route", "show", "dev", interface])
        return [
            ipaddress.IPv4Network(entry["dst"])
            for entry in json.loads(result.stdout)
            if entry.get("dst") not in (None, "default")
        ]

    def apply_forwardings(self, rules: list[dict]):
        with self._lock:
            ext_iface = self.detect_primary_interface()
            interface = self._config.wg_interface
            network = str(self._config.wg_network)
            clients = self._storage.load_json(str(self._config.clients_file), [])
            owners = {peer["address"]: peer["public_key"] for peer in clients}
            active = [
                rule
                for rule in rules
                if rule.get("peer_public_key") and owners.get(str(rule.get("client_ip"))) == rule["peer_public_key"]
            ]
            commands = [command for rule in active for command in render_rule(rule, ext_iface)]
            dnat = [command.args for command in commands if command.table == "nat"]
            public = [
                ["-i", ext_iface, "-o", interface, "-m", "conntrack", "--ctstate", "DNAT", *command.args]
                for command in commands
                if command.table == "filter"
            ]
            if public:
                public.append(
                    [
                        "-i",
                        interface,
                        "-o",
                        ext_iface,
                        "-s",
                        network,
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "DNAT",
                        "--ctdir",
                        "REPLY",
                        "-j",
                        "ACCEPT",
                    ]
                )
            policy = [
                *public,
                *self._routing_rules(ext_iface),
                ["-i", interface, "-j", "DROP"],
                ["-o", interface, "-j", "DROP"],
            ]
            # Move an existing unconditional hook to the front atomically on upgrade.
            chain = self._config.filter_chain
            parent = "FORWARD"
            self._install_chain("filter", chain, parent, policy)
            self._install_chain("nat", self._config.nat_chain, "PREROUTING", dnat)
            masquerade = []
            if os.environ.get("ALLOW_INTERNET_EGRESS") == "1":
                masquerade.append(["-s", network, "-o", ext_iface, "-j", "MASQUERADE"])
            self._install_chain("nat", self._config.nat_chain + "_POST", "POSTROUTING", masquerade)
            logging.info("Applied %s forwarding rules", len(rules))

    def load_forwardings(self, default_client_ip: str | None = None) -> list[dict]:
        payload = self._storage.load_json(str(self._config.forward_file), None)
        if isinstance(payload, list):
            return payload

        if default_client_ip:
            seed = [{"port": 30000, "protocol": "both", "client_ip": str(default_client_ip), "target_port": 8080}]
            self._storage.save_json(str(self._config.forward_file), seed)
            return seed

        self._storage.save_json(str(self._config.forward_file), [])
        return []

    @staticmethod
    def protocols_overlap(existing_proto: str, new_proto: str) -> bool:
        return protocols_overlap(existing_proto, new_proto)
