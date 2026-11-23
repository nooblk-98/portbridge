import ipaddress
import json
import unittest
from unittest.mock import MagicMock, patch

from app.core.config import EnvConfigProvider
from app.core.iptables import IPTablesService
from app.core.peer_options import validate_options
from app.core.providers import CommandResult, FakeRunner, InMemoryStorage
from app.core.wireguard import WireGuardService
from app.services.client_manager import ClientManager

OWNER = {"name": "owner", "address": "10.8.0.2", "private_key": "owner-private", "public_key": "owner-public"}
READER = {"name": "reader", "address": "10.8.0.3", "private_key": "reader-private", "public_key": "reader-public"}
ROUTE = "192.168.50.10/32"


class PeerRoutingTests(unittest.TestCase):
    def setUp(self):
        self.config = EnvConfigProvider()
        self.storage = InMemoryStorage()
        self.runner = FakeRunner()
        self.wg = WireGuardService(self.config, self.storage, self.runner)

    def test_legacy_profile_keeps_defaults(self):
        path = self.wg.write_client_config(OWNER, "server-public")
        config = self.storage.read_text(path)
        self.assertIn("AllowedIPs = 0.0.0.0/0", config)
        self.assertIn("DNS = 1.1.1.1", config)
        self.assertIn("PersistentKeepalive = 25", config)
        self.assertNotIn("MTU =", config)

    def test_owner_and_receiving_peer_get_distinct_routes(self):
        owner = OWNER | {"advertised_routes": [ROUTE], "split_tunnel": True}
        reader = READER | {"split_tunnel": True, "dns": "", "mtu": 1380, "keepalive": 0}
        peers = [owner, reader]
        owner_config = self.storage.read_text(self.wg.write_client_config(owner, "server", peers))
        reader_config = self.storage.read_text(self.wg.write_client_config(reader, "server", peers))
        self.wg.render_wireguard_config(peers, "server-private")
        server_config = self.storage.read_text(str(self.config.wg_config_path))
        self.assertNotIn(ROUTE, owner_config)
        self.assertIn(f"AllowedIPs = 10.8.0.0/24, {ROUTE}", reader_config)
        self.assertIn("MTU = 1380", reader_config)
        self.assertIn("PersistentKeepalive = 0", reader_config)
        self.assertNotIn("DNS =", reader_config)
        self.assertIn(f"AllowedIPs = 10.8.0.2/32, {ROUTE}", server_config)
        self.assertIn("AllowedIPs = 10.8.0.3/32", server_config)

    def test_route_validation(self):
        network = ipaddress.IPv4Network("10.8.0.0/24")
        peers = [OWNER, READER | {"advertised_routes": ["192.168.60.0/24"]}]
        settings = validate_options({"advertised_routes": ["192.168.50.10"]}, OWNER, peers, network)
        self.assertEqual(settings["advertised_routes"], [ROUTE])
        for value in ["192.168.60.9", "10.8.0.50", "0.0.0.0/0", "127.0.0.1", "::1", "1.2.3.4\nDNS=x"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_options({"advertised_routes": [value]}, OWNER, peers, network)

    def test_server_route_overlap_is_rejected(self):
        command = "ip -j -4 route show table all"
        self.runner.responses[command] = CommandResult(
            0, json.dumps([{"dst": "192.168.50.0/24", "dev": "eth0"}, {"dst": "default", "dev": "eth0"}]), ""
        )
        with self.assertRaisesRegex(ValueError, "overlaps a server route"):
            self.wg.check_local_routes([ROUTE])
        self.wg.check_local_routes(["192.168.60.10/32"])

    def test_firewall_advertisements_and_peer_replies_stay_in_tunnel(self):
        self.storage.save_json(str(self.config.clients_file), [OWNER | {"advertised_routes": [ROUTE]}])
        firewall = IPTablesService(self.config, self.storage, self.runner)
        routes = firewall._routing_rules("eth0")
        interface = self.config.wg_interface
        self.assertEqual(len(routes), 3)
        for rule in routes:
            self.assertEqual(rule[:4], ["-i", interface, "-o", interface])
        self.assertIn(
            ["-i", interface, "-o", interface, "-s", "10.8.0.0/24", "-d", "10.8.0.0/24", "-j", "ACCEPT"], routes
        )
        self.assertEqual(sum(ROUTE in rule for rule in routes), 2)

    def test_firewall_replaces_rules_and_installs_final_drops_atomically(self):
        class RecordingRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.transactions = []

            def run(self, cmd, *, check=True, input_data=None):
                if input_data:
                    self.transactions.append(input_data)
                return super().run(cmd, check=check, input_data=input_data)

        runner = RecordingRunner()
        firewall = IPTablesService(self.config, self.storage, runner)
        firewall.apply_forwardings([])
        policy = runner.transactions[0]
        chain = self.config.filter_chain
        interface = self.config.wg_interface
        self.assertIn(f"-F {chain}\n", policy)
        self.assertIn(f"-I FORWARD 1 -j {chain}\n", policy)
        self.assertIn(f"-A {chain} -i {interface} -j DROP\n", policy)
        self.assertIn(f"-A {chain} -o {interface} -j DROP\n", policy)
        self.assertTrue(policy.endswith("COMMIT\n"))

    def test_options_rollback_restores_profiles_and_preserves_original_error(self):
        previous = [OWNER, READER]
        self.storage.save_json(str(self.config.clients_file), previous)
        wg = MagicMock()
        wg.load_clients.return_value = previous
        wg.ensure_server_keys.return_value = ("private", "public")
        forwarding = MagicMock()
        forwarding.apply_all.side_effect = [RuntimeError("firewall failure"), None]
        manager = ClientManager(wg, self.storage, self.config, forwarding)
        with self.assertRaisesRegex(RuntimeError, "firewall failure"):
            manager.update_options("owner", {"advertised_routes": [ROUTE]})
        self.assertEqual(self.storage.load_json(str(self.config.clients_file)), previous)
        updated = wg.replace_routes.call_args_list[0].args[1]
        self.assertEqual(wg.replace_routes.call_args_list[1].args, (updated, previous))
        self.assertEqual(wg.write_client_config.call_args.args, (READER, "public", previous))

    def test_deleted_advertiser_withdraws_route_and_updates_other_profiles(self):
        owner = OWNER | {"advertised_routes": [ROUTE]}
        wg = MagicMock()
        wg.load_clients.return_value = [owner, READER]
        wg.ensure_server_keys.return_value = ("private", "public")
        manager = ClientManager(wg, self.storage, self.config, MagicMock())
        with patch("pathlib.Path.unlink"):
            self.assertEqual(manager.delete_client("owner"), {"removed": "owner"})
        wg.replace_routes.assert_called_once_with([owner, READER], [READER])
        wg.write_client_config.assert_called_once_with(READER, "public", [READER])

    def test_failed_route_install_restores_prior_wireguard_config(self):
        class FailingRunner(FakeRunner):
            def run(self, cmd, **kwargs):
                result = super().run(cmd, **kwargs)
                if cmd[:2] == ["wg-quick", "up"] and self.commands.count(cmd) == 1:
                    raise RuntimeError("route conflict")
                return result

        runner = FailingRunner()
        wg = WireGuardService(self.config, self.storage, runner)
        key_path = self.config.data_dir
        self.storage.write_text(str(key_path / "server.privatekey"), "private")
        self.storage.write_text(str(key_path / "server.publickey"), "public")
        with self.assertRaisesRegex(RuntimeError, "route conflict"):
            wg.replace_routes([OWNER], [OWNER | {"advertised_routes": [ROUTE]}])
        self.assertNotIn(ROUTE, self.storage.read_text(str(self.config.wg_config_path)))
        self.assertEqual(sum(command[:2] == ["wg-quick", "up"] for command in runner.commands), 2)


if __name__ == "__main__":
    unittest.main()
