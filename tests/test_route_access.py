import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from flask import Flask

from app.core.config import EnvConfigProvider
from app.core.iptables import IPTablesService
from app.core.peer_options import validate_options
from app.core.providers import CommandResult, FakeRunner, InMemoryStorage, JsonFileStorage
from app.core.wireguard import WireGuardService
from app.routes import api as api_routes
from app.services.client_manager import ClientManager
from app.services.forwarding_manager import ForwardingManager

OWNER = {"name": "owner", "address": "10.8.0.2", "private_key": "owner-private", "public_key": "owner-public"}
READER = {"name": "reader", "address": "10.8.0.3", "private_key": "reader-private", "public_key": "reader-public"}
THIRD = {"name": "third", "address": "10.8.0.4", "private_key": "third-private", "public_key": "third-public"}
ROUTE = "192.168.50.10/32"
ROUTE_TWO = "192.168.60.0/24"


def packet_verdict(rules, source, destination, established=False):
    """Return the first jumping target that matches a forwarded tunnel packet."""
    for rule in rules:
        if "--ctstate" in rule:
            states = rule[rule.index("--ctstate") + 1].split(",")
            if not (established and ("ESTABLISHED" in states or "RELATED" in states)):
                continue
        if "-s" in rule and ipaddress.ip_address(source) not in ipaddress.ip_network(rule[rule.index("-s") + 1]):
            continue
        if "-d" in rule and ipaddress.ip_address(destination) not in ipaddress.ip_network(rule[rule.index("-d") + 1]):
            continue
        return rule[rule.index("-j") + 1]
    return None


class RouteAccessTests(unittest.TestCase):
    def setUp(self):
        self.config = EnvConfigProvider()
        self.storage = InMemoryStorage()
        self.runner = FakeRunner()
        self.runner.responses["ip -j -4 route show table all"] = CommandResult(0, "[]", "")
        self.wg = WireGuardService(self.config, self.storage, self.runner)
        self.storage.write_text(str(self.config.data_dir / "server.privatekey"), "server-private")
        self.storage.write_text(str(self.config.data_dir / "server.publickey"), "server-public")

    def manager(self, forwarding=None):
        firewall = IPTablesService(self.config, self.storage, self.runner)
        return ClientManager(
            self.wg, self.storage, self.config, forwarding or ForwardingManager(firewall, self.storage, self.config)
        )

    def store(self, clients):
        self.storage.save_json(str(self.config.clients_file), clients)

    def routing_rules(self):
        firewall = IPTablesService(self.config, self.storage, self.runner)
        interface = self.config.wg_interface
        return firewall._routing_rules("eth0") + [
            ["-i", interface, "-j", "DROP"],
            ["-o", interface, "-j", "DROP"],
        ]

    def test_legacy_data_without_route_access_allows_every_peer(self):
        owner = OWNER | {"advertised_routes": [ROUTE]}
        reader = READER | {"split_tunnel": True}
        third = THIRD | {"split_tunnel": True}
        self.store([owner, reader, third])

        payload = self.manager().list_clients()
        (route,) = payload["routes"]
        self.assertIsNone(route["allowed_peer_public_keys"])
        self.assertEqual(route["owner_name"], "owner")
        self.assertEqual(route["owner_public_key"], "owner-public")
        self.assertIs(route["owner_online"], False)
        self.assertIsNone(route["owner_last_handshake"])
        self.assertIn(
            f"AllowedIPs = 10.8.0.0/24, {ROUTE}", self.wg.render_client_config(reader, "server", [owner, reader, third])
        )
        self.assertIn(
            f"AllowedIPs = 10.8.0.0/24, {ROUTE}", self.wg.render_client_config(third, "server", [owner, reader, third])
        )

    def test_empty_access_list_denies_every_peer(self):
        owner = OWNER | {"advertised_routes": [ROUTE], "route_access": {ROUTE: []}}
        reader = READER | {"split_tunnel": True}
        third = THIRD | {"split_tunnel": True}
        self.store([owner, reader, third])

        payload = self.manager().list_clients()
        self.assertEqual(payload["routes"][0]["allowed_peer_public_keys"], [])
        for peer in (reader, third):
            profile = self.wg.render_client_config(peer, "server", [owner, reader, third])
            self.assertNotIn(ROUTE, profile)
        rules = self.routing_rules()
        self.assertEqual(packet_verdict(rules, READER["address"], "192.168.50.10"), "DROP")
        self.assertEqual(packet_verdict(rules, THIRD["address"], "192.168.50.10"), "DROP")
        self.assertEqual(packet_verdict(rules, OWNER["address"], "192.168.50.10"), "ACCEPT")

    def test_selected_peer_only_receives_route(self):
        owner = OWNER | {"advertised_routes": [ROUTE], "route_access": {ROUTE: [READER["public_key"]]}}
        reader = READER | {"split_tunnel": True}
        third = THIRD | {"split_tunnel": True}
        self.store([owner, reader, third])

        payload = self.manager().list_clients()
        self.assertEqual(payload["routes"][0]["allowed_peer_public_keys"], [READER["public_key"]])
        self.assertIn(
            f"AllowedIPs = 10.8.0.0/24, {ROUTE}", self.wg.render_client_config(reader, "server", [owner, reader, third])
        )
        self.assertNotIn(ROUTE, self.wg.render_client_config(third, "server", [owner, reader, third]))

        rules = self.routing_rules()
        self.assertEqual(packet_verdict(rules, READER["address"], "192.168.50.10"), "ACCEPT")
        self.assertEqual(packet_verdict(rules, THIRD["address"], "192.168.50.10"), "DROP")
        self.assertEqual(packet_verdict(rules, "192.168.50.10", READER["address"], established=True), "ACCEPT")
        self.assertEqual(packet_verdict(rules, "192.168.50.10", THIRD["address"], established=True), "DROP")

    def test_deleted_recipient_is_denied_and_stale_established_reply_drops(self):
        owner = OWNER | {
            "advertised_routes": [ROUTE],
            "route_access": {ROUTE: [READER["public_key"], "deleted-public"]},
        }
        reader = READER | {"split_tunnel": True}
        third = THIRD | {"split_tunnel": True}
        self.store([owner, reader, third])
        self.assertEqual(self.manager().list_clients()["routes"][0]["allowed_peer_public_keys"], [READER["public_key"]])

        revoked = OWNER | {
            "advertised_routes": [ROUTE],
            "route_access": {ROUTE: ["deleted-public"]},
        }
        self.store([revoked, reader, third])
        payload = self.manager().list_clients()
        self.assertEqual(payload["routes"][0]["allowed_peer_public_keys"], [])
        rules = self.routing_rules()
        self.assertFalse(any(f"{READER['address']}/32" in rule for rule in rules))
        self.assertEqual(packet_verdict(rules, READER["address"], "192.168.50.10"), "DROP")
        self.assertEqual(packet_verdict(rules, "192.168.50.10", READER["address"], established=True), "DROP")

    def test_source_address_follows_the_selected_public_key(self):
        owner = OWNER | {"advertised_routes": [ROUTE], "route_access": {ROUTE: [READER["public_key"]]}}
        moved_reader = READER | {"address": "10.8.0.9", "split_tunnel": True}
        self.store([owner, moved_reader, THIRD])

        rules = self.routing_rules()
        self.assertEqual(packet_verdict(rules, "10.8.0.9", "192.168.50.10"), "ACCEPT")
        self.assertEqual(packet_verdict(rules, READER["address"], "192.168.50.10"), "DROP")

        # Replacing the key at the old address revokes access; the ACL names keys, not addresses.
        replacement = READER | {"public_key": "replacement-public"}
        self.store([owner, replacement, THIRD])
        self.assertEqual(self.manager().list_clients()["routes"][0]["allowed_peer_public_keys"], [])
        rules = self.routing_rules()
        self.assertEqual(packet_verdict(rules, READER["address"], "192.168.50.10"), "DROP")

    def test_each_route_has_its_own_access_list(self):
        owner = OWNER | {
            "advertised_routes": [ROUTE, ROUTE_TWO],
            "route_access": {ROUTE: [READER["public_key"]], ROUTE_TWO: []},
        }
        self.store([owner, READER, THIRD])
        rules = self.routing_rules()
        self.assertEqual(packet_verdict(rules, READER["address"], "192.168.50.10"), "ACCEPT")
        self.assertEqual(packet_verdict(rules, READER["address"], "192.168.60.1"), "DROP")

    def test_route_access_validation_canonicalizes_and_prunes(self):
        clients = [OWNER, READER | {"advertised_routes": []}, THIRD]
        settings = validate_options(
            {
                "advertised_routes": ["192.168.50.10"],
                "route_access": {
                    "192.168.50.10": [READER["public_key"], READER["public_key"]],
                    ROUTE_TWO: [THIRD["public_key"]],
                },
            },
            OWNER,
            clients,
            self.config.wg_network,
        )
        self.assertEqual(settings["advertised_routes"], [ROUTE])
        self.assertEqual(settings["route_access"], {ROUTE: [READER["public_key"]]})

    def test_route_access_rejects_unknown_recipients_and_overlaps(self):
        clients = [OWNER, READER, THIRD]
        with self.assertRaisesRegex(ValueError, "unknown peer"):
            validate_options(
                {"advertised_routes": [ROUTE], "route_access": {ROUTE: ["ghost-public"]}},
                OWNER,
                clients,
                self.config.wg_network,
            )
        with self.assertRaisesRegex(ValueError, "overlaps an advertised route"):
            validate_options(
                {"advertised_routes": [ROUTE], "route_access": {"192.168.50.0/24": [READER["public_key"]]}},
                OWNER,
                clients,
                self.config.wg_network,
            )
        with self.assertRaisesRegex(ValueError, "cannot grant itself"):
            validate_options(
                {"advertised_routes": [ROUTE], "route_access": {ROUTE: [OWNER["public_key"]]}},
                OWNER,
                clients,
                self.config.wg_network,
            )

    def test_access_only_update_skips_wireguard_and_persists(self):
        owner = OWNER | {"advertised_routes": [ROUTE]}
        reader = READER | {"split_tunnel": True}
        third = THIRD | {"split_tunnel": True}
        self.store([owner, reader, third])
        manager = self.manager()
        manager.record_profile_export("reader")
        manager.record_profile_export("third")
        exported = {
            row["name"]: row["profile_refresh_required"] for row in manager.list_clients()["split_tunnel_profiles"]
        }
        self.assertEqual(exported, {"reader": False, "third": False})

        before = len(self.runner.commands)
        result = manager.update_options(
            "owner", {"advertised_routes": [ROUTE], "route_access": {ROUTE: [READER["public_key"]]}}
        )
        self.assertEqual(result["options"]["route_access"], {ROUTE: [READER["public_key"]]})
        commands = self.runner.commands[before:]
        self.assertFalse(any(command[0] in ("wg", "wg-quick") for command in commands))
        self.assertTrue(any(command[0] == "iptables-restore" for command in commands))

        stored = self.storage.load_json(str(self.config.clients_file))
        self.assertEqual(stored[0]["route_access"], {ROUTE: [READER["public_key"]]})
        profiles = {
            row["name"]: row["profile_refresh_required"] for row in manager.list_clients()["split_tunnel_profiles"]
        }
        self.assertIs(profiles["reader"], False)
        self.assertIs(profiles["third"], True)

    def test_access_only_rollback_restores_data_profiles_and_firewall(self):
        previous = [OWNER | {"advertised_routes": [ROUTE]}, READER, THIRD]
        self.store(previous)
        wg = MagicMock()
        wg.load_clients.return_value = previous
        wg.ensure_server_keys.return_value = ("private", "public")
        forwarding = MagicMock()
        forwarding.apply_all.side_effect = [RuntimeError("firewall failure"), None]
        manager = ClientManager(wg, self.storage, self.config, forwarding)

        with self.assertRaisesRegex(RuntimeError, "firewall failure"):
            manager.update_options(
                "owner", {"advertised_routes": [ROUTE], "route_access": {ROUTE: [READER["public_key"]]}}
            )

        self.assertEqual(self.storage.load_json(str(self.config.clients_file)), previous)
        wg.replace_routes.assert_not_called()
        wg.refresh_wireguard.assert_not_called()
        restored = [call.args for call in wg.write_client_config.call_args_list[-3:]]
        self.assertEqual(
            restored,
            [
                (previous[0], "public", previous),
                (previous[1], "public", previous),
                (previous[2], "public", previous),
            ],
        )
        self.assertEqual(forwarding.apply_all.call_count, 2)

    def test_stale_stored_recipient_does_not_block_an_unrelated_edit(self):
        owner = OWNER | {"advertised_routes": [ROUTE], "route_access": {ROUTE: ["deleted-public"]}}
        self.store([owner, READER, THIRD])
        self.manager().update_options("owner", {"dns": "9.9.9.9"})
        stored = self.storage.load_json(str(self.config.clients_file))
        self.assertEqual(stored[0]["route_access"], {ROUTE: []})
        self.assertEqual(stored[0]["dns"], "9.9.9.9")

    def test_removing_an_advertised_route_prunes_its_access_entry(self):
        owner = OWNER | {"advertised_routes": [ROUTE, ROUTE_TWO], "route_access": {ROUTE: [READER["public_key"]]}}
        self.store([owner, READER, THIRD])
        manager = self.manager()
        manager.update_options("owner", {"advertised_routes": [ROUTE_TWO]})
        stored = self.storage.load_json(str(self.config.clients_file))
        self.assertEqual(stored[0]["route_access"], {})

    def test_corrupt_stored_access_denies_instead_of_opening(self):
        owner = OWNER | {"advertised_routes": [ROUTE], "route_access": "not-a-map"}
        self.store([owner, READER, THIRD])
        payload = self.manager().list_clients()
        self.assertEqual(payload["routes"][0]["allowed_peer_public_keys"], [])
        self.assertEqual(packet_verdict(self.routing_rules(), READER["address"], "192.168.50.10"), "DROP")

    def test_corrupt_stored_route_entry_is_denied_and_rewritten_as_empty(self):
        owner = OWNER | {"advertised_routes": [ROUTE], "route_access": {ROUTE: "oops"}}
        self.store([owner, READER, THIRD])
        manager = self.manager()
        self.assertEqual(manager.list_clients()["routes"][0]["allowed_peer_public_keys"], [])
        manager.update_options("owner", {"dns": "9.9.9.9"})
        stored = self.storage.load_json(str(self.config.clients_file))
        self.assertEqual(stored[0]["route_access"], {ROUTE: []})

    def test_unknown_profile_export_is_reported_as_unknown(self):
        owner = OWNER | {"advertised_routes": [ROUTE]}
        reader = READER | {"split_tunnel": True}
        full_tunnel = THIRD | {"split_tunnel": False}
        self.store([owner, reader, full_tunnel])
        manager = self.manager()
        self.assertEqual(
            manager.list_clients()["split_tunnel_profiles"],
            [{"name": "reader", "profile_refresh_required": None}],
        )


class RouteAccessApiTests(unittest.TestCase):
    def setUp(self):
        self.config = EnvConfigProvider()
        self.storage = InMemoryStorage()
        self.runner = FakeRunner()
        self.runner.responses["ip -j -4 route show table all"] = CommandResult(0, "[]", "")
        self.wg = WireGuardService(self.config, self.storage, self.runner)
        self.storage.write_text(str(self.config.data_dir / "server.privatekey"), "server-private")
        self.storage.write_text(str(self.config.data_dir / "server.publickey"), "server-public")

    def store(self, clients):
        self.storage.save_json(str(self.config.clients_file), clients)

    def app(self):
        app = Flask(__name__)
        app.config.update(TESTING=True, LOGIN_DISABLED=True)
        firewall = IPTablesService(self.config, self.storage, self.runner)
        manager = ClientManager(
            self.wg, self.storage, self.config, ForwardingManager(firewall, self.storage, self.config)
        )
        app.extensions["config"] = self.config
        app.extensions["client_manager"] = manager
        app.extensions["forwarding_manager"] = ForwardingManager(firewall, self.storage, self.config)
        app.register_blueprint(api_routes.bp)
        return app

    def test_clients_endpoint_exposes_routes_and_profile_status(self):
        owner = OWNER | {"advertised_routes": [ROUTE], "route_access": {ROUTE: [READER["public_key"]]}}
        reader = READER | {"split_tunnel": True}
        self.store([owner, reader, THIRD])
        client = self.app().test_client()

        payload = client.get("/api/clients").get_json()
        self.assertEqual(
            payload["routes"],
            [
                {
                    "cidr": ROUTE,
                    "owner_name": "owner",
                    "owner_public_key": "owner-public",
                    "owner_online": False,
                    "owner_last_handshake": None,
                    "allowed_peer_public_keys": [READER["public_key"]],
                }
            ],
        )
        self.assertEqual(payload["split_tunnel_profiles"], [{"name": "reader", "profile_refresh_required": None}])

        app = self.app()
        manager = app.extensions["client_manager"]
        manager.record_profile_export("reader")
        payload = app.test_client().get("/api/clients").get_json()
        self.assertIs(payload["split_tunnel_profiles"][0]["profile_refresh_required"], False)

    def test_options_patch_accepts_route_access_and_rejects_bad_recipients(self):
        self.store([OWNER | {"advertised_routes": [ROUTE]}, READER, THIRD])
        client = self.app().test_client()

        response = client.patch(
            "/api/clients/owner/options",
            json={"advertised_routes": [ROUTE], "route_access": {ROUTE: [READER["public_key"]]}},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["options"]["route_access"], {ROUTE: [READER["public_key"]]})

        response = client.patch(
            "/api/clients/owner/options",
            json={"advertised_routes": [ROUTE], "route_access": {ROUTE: ["ghost-public"]}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("unknown peer", response.get_json()["description"])

        response = client.patch(
            "/api/clients/owner/options",
            json={"advertised_routes": [ROUTE], "route_access": {"192.168.50.0/24": []}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("overlaps", response.get_json()["description"])
        stored = self.storage.load_json(str(self.config.clients_file))
        self.assertEqual(stored[0]["route_access"], {ROUTE: [READER["public_key"]]})


class ProfileExportRouteTests(unittest.TestCase):
    def test_downloading_a_profile_records_the_exported_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            environment = {
                "DATA_DIR": tmp,
                "WG_CONFIG_PATH": str(Path(tmp) / "wg0.conf"),
                "ADMIN_PASSWORD": "a-strong-test-password",
            }
            with patch.dict("os.environ", environment):
                config = EnvConfigProvider()
                storage = JsonFileStorage(tmp)
                runner = FakeRunner()
                wg = WireGuardService(config, storage, runner)
                storage.write_text(str(config.data_dir / "server.privatekey"), "server-private")
                storage.write_text(str(config.data_dir / "server.publickey"), "server-public")
                clients = [OWNER | {"advertised_routes": [ROUTE]}, READER | {"split_tunnel": True}]
                storage.save_json(str(config.clients_file), clients)
                config.clients_dir.mkdir(parents=True, exist_ok=True)
                (config.clients_dir / "reader.conf").write_text(
                    wg.render_client_config(clients[1], "server-public", clients)
                )
                firewall = IPTablesService(config, storage, runner)
                manager = ClientManager(wg, storage, config, ForwardingManager(firewall, storage, config))

                app = Flask(__name__)
                app.config.update(TESTING=True, LOGIN_DISABLED=True)
                app.extensions["config"] = config
                app.extensions["client_manager"] = manager
                app.extensions["forwarding_manager"] = ForwardingManager(firewall, storage, config)
                app.register_blueprint(api_routes.bp)
                client = app.test_client()

                self.assertEqual(
                    client.get("/api/clients").get_json()["split_tunnel_profiles"],
                    [{"name": "reader", "profile_refresh_required": None}],
                )
                download = client.get("/clients/reader.conf")
                self.assertEqual(download.status_code, 200)
                download.close()
                self.assertEqual(
                    client.get("/api/clients").get_json()["split_tunnel_profiles"],
                    [{"name": "reader", "profile_refresh_required": False}],
                )

                stored = storage.load_json(str(config.clients_file))
                stored[0]["advertised_routes"].append(ROUTE_TWO)
                storage.save_json(str(config.clients_file), stored)
                self.assertEqual(
                    client.get("/api/clients").get_json()["split_tunnel_profiles"],
                    [{"name": "reader", "profile_refresh_required": True}],
                )


if __name__ == "__main__":
    unittest.main()
