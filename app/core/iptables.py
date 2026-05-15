import logging

from app.core.providers import CommandRunner, ConfigProvider, StorageBackend
from app.core.rule_renderer import protocols_overlap, render_rule


class IPTablesService:
    def __init__(self, config: ConfigProvider, storage: StorageBackend, runner: CommandRunner):
        self._config = config
        self._storage = storage
        self._runner = runner
        self._nat_tmp = config.nat_chain + "_TMP"
        self._filter_tmp = config.filter_chain + "_TMP"

    def detect_primary_interface(self) -> str:
        try:
            result = self._runner.run(["sh", "-c", "ip route show default | awk '{print $5; exit}'"], check=False)
            iface = result.stdout.strip()
            if iface:
                return iface
        except Exception:
            return "eth0"
        return "eth0"

    def _ensure_masquerade(self, ext_iface: str):
        check = self._runner.run(
            ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", ext_iface, "-j", "MASQUERADE"],
            check=False,
        )
        if check.returncode != 0:
            self._runner.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ext_iface, "-j", "MASQUERADE"])

    def _ensure_chain(self, table: str, chain: str):
        self._runner.run(["iptables", "-t", table, "-N", chain], check=False)

    def _chain_args(self, action: str, chain: str, cmd: list) -> list:
        args = [action, chain] + cmd[1:]
        return args

    def _build_rules_into_tmp(self, rules: list[dict], ext_iface: str):
        self._ensure_chain("nat", self._nat_tmp)
        self._ensure_chain("filter", self._filter_tmp)
        self._runner.run(["iptables", "-t", "nat", "-F", self._nat_tmp])
        self._runner.run(["iptables", "-t", "filter", "-F", self._filter_tmp])

        for rule in rules:
            commands = render_rule(rule, ext_iface)
            for cmd in commands:
                chain = self._nat_tmp if cmd.table == "nat" else self._filter_tmp
                self._runner.run(["iptables", "-t", cmd.table, "-A", chain] + cmd.args)

    def _swap_chain(self, table: str, live_chain: str, tmp_chain: str, parent_chain: str):
        self._ensure_chain(table, live_chain)
        present = self._runner.run(["iptables", "-t", table, "-C", parent_chain, "-j", live_chain], check=False)
        if present.returncode != 0:
            self._runner.run(["iptables", "-t", table, "-A", parent_chain, "-j", live_chain])

        self._runner.run(["iptables", "-t", table, "-F", live_chain])

        res = self._runner.run(["iptables", "-t", table, "-S", tmp_chain], check=False)
        for line in (res.stdout or "").splitlines():
            if line.startswith(f"-A {tmp_chain}"):
                new_rule = line.replace(f"-A {tmp_chain}", f"-A {live_chain}", 1)
                self._runner.run(["iptables", "-t", table] + new_rule.split()[1:])

        self._runner.run(["iptables", "-t", table, "-F", tmp_chain], check=False)
        self._runner.run(["iptables", "-t", table, "-X", tmp_chain], check=False)

    def apply_forwardings(self, rules: list[dict]):
        ext_iface = self.detect_primary_interface()
        self._build_rules_into_tmp(rules, ext_iface)
        self._swap_chain("nat", self._config.nat_chain, self._nat_tmp, "PREROUTING")
        self._swap_chain("filter", self._config.filter_chain, self._filter_tmp, "FORWARD")
        self._ensure_masquerade(ext_iface)
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
