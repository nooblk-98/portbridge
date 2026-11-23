#![allow(dead_code)]

mod common;

use common::{client, with_options, Setup};
use portbridge::storage::Storage;
use serde_json::{json, Map, Value};

const ROUTE: &str = "192.168.50.10/32";

fn options(body: Value) -> Map<String, Value> {
    body.as_object().cloned().expect("object")
}

fn seed_fixture(setup: &Setup) {
    setup.seed_keys();
    let owner = with_options(
        client("owner", "10.8.0.2", "owner-public"),
        json!({"advertised_routes": [ROUTE]}),
    );
    let reader = with_options(
        client("reader", "10.8.0.3", "reader-public"),
        json!({"split_tunnel": true}),
    );
    let third = with_options(
        client("third", "10.8.0.4", "third-public"),
        json!({"split_tunnel": true}),
    );
    setup.store(&[owner, reader, third]);
}

#[test]
fn list_clients_reports_routes_and_profile_status() {
    let setup = Setup::new();
    seed_fixture(&setup);
    let payload = setup.manager.list_clients().expect("list");
    let route = &payload["routes"][0];
    assert_eq!(route["cidr"], ROUTE);
    assert_eq!(route["owner_name"], "owner");
    assert_eq!(route["owner_public_key"], "owner-public");
    assert_eq!(route["owner_online"], false);
    assert_eq!(route["owner_last_handshake"], Value::Null);
    assert_eq!(route["allowed_peer_public_keys"], Value::Null);
    assert_eq!(
        payload["split_tunnel_profiles"],
        json!([
            {"name": "reader", "profile_refresh_required": null},
            {"name": "third", "profile_refresh_required": null}
        ])
    );
    assert_eq!(payload["items"][0]["address"], "10.8.0.2/24");
    assert_eq!(payload["items"][0]["config"], "/clients/owner.conf");
    assert_eq!(payload["items"][0]["options"]["dns"], "1.1.1.1");
}

#[test]
fn download_records_an_export_revision_and_changes_track_it() {
    let setup = Setup::new();
    seed_fixture(&setup);
    setup
        .manager
        .record_profile_export("reader", None)
        .expect("export");
    let payload = setup.manager.list_clients().expect("list");
    assert_eq!(
        payload["split_tunnel_profiles"][0]["profile_refresh_required"],
        false
    );
    let updated = setup
        .manager
        .update_options(
            "owner",
            &options(json!({
                "advertised_routes": [ROUTE],
                "route_access": {ROUTE: ["reader-public"]}
            })),
        )
        .expect("update");
    assert_eq!(
        updated["options"]["route_access"],
        json!({ROUTE: ["reader-public"]})
    );
    let payload = setup.manager.list_clients().expect("list");
    // The reader still receives the route, so its profile did not change.
    assert_eq!(
        payload["split_tunnel_profiles"][0]["profile_refresh_required"],
        false
    );
    // The third peer lost the route and now needs a refresh; without an export
    // its state is unknown rather than false.
    assert_eq!(
        payload["split_tunnel_profiles"][1]["profile_refresh_required"],
        Value::Null
    );
}

#[test]
fn access_only_update_skips_wireguard_and_persists() {
    let setup = Setup::new();
    seed_fixture(&setup);
    let before = setup.runner.commands().len();
    let result = setup
        .manager
        .update_options(
            "owner",
            &options(json!({
                "advertised_routes": [ROUTE],
                "route_access": {ROUTE: ["reader-public"]}
            })),
        )
        .expect("update");
    assert_eq!(
        result["options"]["route_access"],
        json!({ROUTE: ["reader-public"]})
    );
    let commands = &setup.runner.commands()[before..];
    assert!(
        !commands
            .iter()
            .any(|command| command.first().map(String::as_str) == Some("wg")
                || command.first().map(String::as_str) == Some("wg-quick")),
        "access-only updates must not bounce WireGuard: {commands:?}"
    );
    assert!(commands
        .iter()
        .any(|command| command.first().map(String::as_str) == Some("iptables-restore")));
    assert_eq!(
        setup.clients()[0].extra["route_access"],
        json!({ROUTE: ["reader-public"]})
    );
    let reader_conf = setup
        .storage
        .read_text(
            &setup
                .config
                .clients_dir
                .join("reader.conf")
                .to_string_lossy(),
        )
        .expect("reader profile");
    assert!(reader_conf.contains(ROUTE));
}

#[test]
fn access_only_rollback_restores_storage_profiles_and_firewall() {
    let setup = Setup::new();
    seed_fixture(&setup);
    setup
        .manager
        .record_profile_export("reader", None)
        .expect("export");
    let before = setup.clients();
    setup.runner.fail_next("iptables-restore", 1);
    let error = setup
        .manager
        .update_options(
            "owner",
            &options(json!({
                "advertised_routes": [ROUTE],
                "route_access": {ROUTE: []}
            })),
        )
        .expect_err("firewall failure");
    assert!(error.to_string().contains("Command failed"), "{error}");
    assert_eq!(setup.clients(), before);
    let reader_conf = setup
        .storage
        .read_text(
            &setup
                .config
                .clients_dir
                .join("reader.conf")
                .to_string_lossy(),
        )
        .expect("reader profile");
    assert!(reader_conf.contains(ROUTE));
    assert!(!setup
        .runner
        .commands()
        .iter()
        .any(|command| command.first().map(String::as_str) == Some("wg-quick")));
    // The rollback put the previous firewall back.
    let restores = setup
        .runner
        .calls()
        .iter()
        .filter(|(command, _)| command.first().map(String::as_str) == Some("iptables-restore"))
        .count();
    assert!(
        restores >= 2,
        "expected the failed apply and the rollback: {restores}"
    );
}

#[test]
fn deleting_an_advertiser_withdraws_routes_and_profiles() {
    let setup = Setup::new();
    seed_fixture(&setup);
    setup.manager.delete_client("owner").expect("delete owner");
    assert_eq!(setup.clients().len(), 2);
    assert!(!setup.storage.exists(
        &setup
            .config
            .clients_dir
            .join("owner.conf")
            .to_string_lossy()
    ));
    assert!(setup
        .runner
        .commands()
        .iter()
        .any(|command| command.first().map(String::as_str) == Some("wg-quick")));
}

#[test]
fn bootstrap_keeps_existing_data_and_writes_profiles() {
    let setup = Setup::new();
    seed_fixture(&setup);
    setup.manager.bootstrap().expect("bootstrap");
    let clients = setup.clients();
    assert_eq!(clients.len(), 3);
    let wg_config = setup
        .storage
        .read_text(&setup.config.wg_config_path.to_string_lossy())
        .expect("wg config");
    assert!(wg_config.contains("Address = 10.8.0.1/24"));
    assert!(wg_config.contains("AllowedIPs = 10.8.0.2/32, 192.168.50.10/32"));
    let reader_conf = setup
        .storage
        .read_text(
            &setup
                .config
                .clients_dir
                .join("reader.conf")
                .to_string_lossy(),
        )
        .expect("reader profile");
    assert!(reader_conf.contains("AllowedIPs = 10.8.0.0/24, 192.168.50.10/32"));
    let owner_conf = setup
        .storage
        .read_text(
            &setup
                .config
                .clients_dir
                .join("owner.conf")
                .to_string_lossy(),
        )
        .expect("owner profile");
    assert!(!owner_conf.contains(ROUTE));
}

#[test]
fn invalid_access_input_is_rejected_before_any_state_change() {
    let setup = Setup::new();
    seed_fixture(&setup);
    let before = setup.clients();
    for access in [
        json!({ROUTE: ["ghost-public"]}),
        json!({"192.168.50.0/24": []}),
        json!({ROUTE: ["owner-public"]}),
    ] {
        let error = setup
            .manager
            .update_options(
                "owner",
                &options(json!({"advertised_routes": [ROUTE], "route_access": access})),
            )
            .expect_err("invalid access");
        assert!(!error.to_string().is_empty());
        assert_eq!(setup.clients(), before);
    }
}

#[test]
fn failed_create_rolls_back_client_state_and_profile() {
    let setup = Setup::new();
    seed_fixture(&setup);
    let before = setup.clients();
    setup.runner.fail_next("wg syncconf", 1);
    setup.runner.fail_next("wg-quick up", 1);
    let error = setup
        .manager
        .create_client("new-peer", Some("10.8.0.9"))
        .expect_err("refresh failure");
    assert!(error.to_string().contains("Command failed"), "{error}");
    assert_eq!(setup.clients(), before);
    assert!(!setup.storage.exists(
        &setup
            .config
            .clients_dir
            .join("new-peer.conf")
            .to_string_lossy()
    ));
}

#[test]
fn failed_rename_rolls_back_name_profile_and_exports() {
    let setup = Setup::new();
    seed_fixture(&setup);
    setup
        .manager
        .record_profile_export("owner", None)
        .expect("export");
    let before = setup.clients();
    setup.runner.fail_next("wg syncconf", 1);
    setup.runner.fail_next("wg-quick up", 1);
    let error = setup
        .manager
        .rename_client("owner", "owner-renamed")
        .expect_err("refresh failure");
    assert!(error.to_string().contains("Command failed"), "{error}");
    assert_eq!(setup.clients(), before);
    assert!(setup.storage.exists(
        &setup
            .config
            .clients_dir
            .join("owner.conf")
            .to_string_lossy()
    ));
    assert!(!setup.storage.exists(
        &setup
            .config
            .clients_dir
            .join("owner-renamed.conf")
            .to_string_lossy()
    ));
    let exports = setup
        .storage
        .read_text(
            &setup
                .config
                .data_dir
                .join("profile_exports.json")
                .to_string_lossy(),
        )
        .expect("exports");
    assert!(exports.contains("\"owner\""));
    assert!(!exports.contains("owner-renamed"));
}

#[test]
fn corrupt_client_state_fails_visibly_without_overwriting() {
    let setup = Setup::new();
    seed_fixture(&setup);
    let path = setup.config.clients_file.to_string_lossy().into_owned();
    let corrupt = "{\"not\":\"an array\"";
    setup.storage.write_text(&path, corrupt).expect("write");
    assert!(setup.manager.list_clients().is_err());
    assert!(setup.manager.bootstrap().is_err());
    assert_eq!(setup.storage.read_text(&path).as_deref(), Some(corrupt));
}

#[test]
fn partly_invalid_client_state_fails_without_overwriting() {
    let setup = Setup::new();
    seed_fixture(&setup);
    let path = setup.config.clients_file.to_string_lossy().into_owned();
    let original = setup.storage.read_text(&path).expect("client state");
    let mut items: Vec<Value> = serde_json::from_str(&original).expect("clients");
    items.push(json!({"name": "broken"}));
    let partial = serde_json::to_string(&items).expect("json");
    setup.storage.write_text(&path, &partial).expect("write");
    assert!(setup.manager.list_clients().is_err());
    assert_eq!(
        setup.storage.read_text(&path).as_deref(),
        Some(partial.as_str())
    );
}
