import ipaddress

from app.core.iptables import IPTablesService
from app.core.providers import ConfigProvider, StorageBackend
from app.core.rule_renderer import protocols_overlap


class ForwardingManager:
    def __init__(self, ipt: IPTablesService, storage: StorageBackend, config: ConfigProvider):
        self._ipt = ipt
        self._storage = storage
        self._config = config

    def list_rules(self) -> list[dict]:
        return self._ipt.load_forwardings()

    def add_rule(self, data: dict) -> dict:
        try:
            port_raw = data.get("port")
            if port_raw is None:
                raise TypeError
            if "-" in str(port_raw):
                s, e = map(int, str(port_raw).split("-"))
                if s >= e:
                    raise ValueError("Invalid port range.")
                port: int | str = str(port_raw)
            else:
                port = int(port_raw)
        except ValueError as exc:
            if "Invalid port range" in str(exc):
                raise
            raise ValueError("Port must be numeric or range (e.g. 8000-8100).") from None
        except (TypeError, AttributeError):
            raise ValueError("Port must be numeric or range (e.g. 8000-8100).") from None

        proto = (data.get("protocol") or "both").lower()
        if proto not in ("tcp", "udp", "both"):
            raise ValueError("Protocol must be tcp, udp, or both.")

        client_ip_raw = data.get("client_ip")
        if not client_ip_raw:
            raise ValueError("client_ip is required.")
        try:
            client_ip = ipaddress.ip_address(client_ip_raw)
        except ValueError:
            raise ValueError("Invalid client_ip.") from None

        source_ip = data.get("source_ip")
        if source_ip:
            try:
                ipaddress.ip_address(source_ip)
            except ValueError:
                try:
                    ipaddress.ip_network(source_ip)
                except ValueError:
                    raise ValueError("Invalid source IP/CIDR.") from None

        target_port_raw = data.get("target_port") or port
        try:
            target_port = int(target_port_raw)
        except Exception:
            raise ValueError("target_port must be numeric.") from None

        if client_ip not in self._config.wg_network:
            raise ValueError("client_ip outside WireGuard network.")

        reserved_ports = [self._config.wg_port, self._config.app_port]
        conflict = False
        if "-" in str(port):
            s, e = map(int, str(port).split("-"))
            for rp in reserved_ports:
                if s <= rp <= e:
                    conflict = True
                    break
        else:
            if int(port) in reserved_ports:
                conflict = True
        if conflict:
            raise ValueError(f"Cannot forward reserved system ports ({', '.join(map(str, reserved_ports))}).")

        rules = self._ipt.load_forwardings()
        for rule in rules:
            existing_proto = rule.get("protocol", "both")
            existing_port = str(rule.get("port", -1))
            if existing_port == str(port) and protocols_overlap(existing_proto, proto):
                if str(rule.get("client_ip")) != str(client_ip):
                    raise ValueError("Port is already in use by another client.")

        rules = [r for r in rules if not (str(r.get("port", -1)) == str(port) and r.get("protocol", "both") == proto)]
        rules.append(
            {
                "port": port,
                "protocol": proto,
                "client_ip": str(client_ip),
                "target_port": target_port,
                "source_ip": source_ip,
            }
        )

        self._storage.save_json(str(self._config.forward_file), rules)
        self._ipt.apply_forwardings(rules)
        return {"port": port, "protocol": proto, "client_ip": str(client_ip), "target_port": target_port}

    def remove_rule(self, port: str, proto: str) -> dict:
        proto = proto.lower()
        rules = self._ipt.load_forwardings()
        updated = [r for r in rules if not (str(r.get("port", -1)) == str(port) and r.get("protocol", "both") == proto)]
        if len(updated) == len(rules):
            raise LookupError("Forwarding rule not found.")
        self._storage.save_json(str(self._config.forward_file), updated)
        self._ipt.apply_forwardings(updated)
        return {"removed": {"port": port, "protocol": proto}}

    def seed_if_empty(self, default_client_ip: str) -> None:
        rules = self._ipt.load_forwardings()
        if not rules:
            seed = [{"port": 30000, "protocol": "both", "client_ip": str(default_client_ip), "target_port": 8080}]
            self._storage.save_json(str(self._config.forward_file), seed)

    def apply_all(self):
        rules = self._ipt.load_forwardings()
        self._ipt.apply_forwardings(rules)
