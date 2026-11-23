#![allow(dead_code)]

mod common;

use common::{client, Setup};
use portbridge::storage::Storage;
use serde_json::{json, Map, Value};

fn owner() -> portbridge::model::Client {
    client("owner", "10.8.0.2", "owner-public")
}

fn rule(port: Value, target: Value) -> Map<String, Value> {
    json!({
        "port": port,
        "protocol": "tcp",
        "client_ip": "10.8.0.2",
        "target_port": target,
    })
    .as_object()
    .cloned()
    .unwrap()
}

fn stored_rules(setup: &Setup) -> Vec<Value> {
    setup
        .storage
        .load_json(&setup.config.forward_file.to_string_lossy(), json!([]))
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn seed_valid_rule(setup: &Setup) {
    setup
        .storage
        .save_json(
            &setup.config.forward_file.to_string_lossy(),
            &json!([{
                "port": 30000,
                "protocol": "both",
                "client_ip": "10.8.0.2",
                "peer_public_key": "owner-public",
                "target_port": 8080,
                "source_ip": null
            }]),
        )
        .expect("forwardings");
}

#[test]
fn ports_outside_the_valid_range_are_rejected() {
    let setup = Setup::new();
    setup.seed_keys();
    setup.store(&[owner()]);
    for (port, target) in [
        (json!(0), json!(8080)),
        (json!(65536), json!(8080)),
        (json!("0-10"), json!(8080)),
        (json!("10-65536"), json!(8080)),
        (json!("8000-8100"), json!(0)),
        (json!("8000-8100"), json!(65536)),
    ] {
        let error = setup
            .forwarding
            .add_rule(&rule(port.clone(), target.clone()))
            .expect_err("invalid port");
        assert!(
            error.to_string().contains("Port") || error.to_string().contains("target_port"),
            "{port} / {target}: {error}"
        );
        assert!(stored_rules(&setup).is_empty());
    }
}

#[test]
fn old_invalid_forward_records_stay_inert_and_unchanged() {
    let setup = Setup::new();
    setup.seed_keys();
    setup.store(&[owner()]);
    let invalid = json!({
        "port": 0,
        "protocol": "both",
        "client_ip": "10.8.0.2",
        "peer_public_key": "owner-public",
        "target_port": 70000
    });
    let valid = json!({
        "port": 30000,
        "protocol": "both",
        "client_ip": "10.8.0.2",
        "peer_public_key": "owner-public",
        "target_port": 8080
    });
    setup
        .storage
        .save_json(
            &setup.config.forward_file.to_string_lossy(),
            &json!([invalid, valid]),
        )
        .expect("forwardings");

    let listed = setup.forwarding.list_rules().expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["port"], 30000);
    setup.manager.bootstrap().expect("bootstrap");
    assert_eq!(stored_rules(&setup).len(), 2);
    setup
        .iptables
        .apply_forwardings(&stored_rules(&setup))
        .expect("invalid record is skipped");
}

#[test]
fn failed_forward_add_restores_previous_storage_and_policy() {
    let setup = Setup::new();
    setup.seed_keys();
    setup.store(&[owner()]);
    seed_valid_rule(&setup);
    let previous = stored_rules(&setup);
    setup.runner.fail_next("iptables-restore", 1);
    let error = setup
        .forwarding
        .add_rule(&rule(json!(30001), json!(8081)))
        .expect_err("apply failure");
    assert!(error.to_string().contains("Command failed"), "{error}");
    assert_eq!(stored_rules(&setup), previous);
    assert!(
        setup
            .runner
            .calls()
            .iter()
            .filter(|(command, _)| command.first().map(String::as_str) == Some("iptables-restore"))
            .count()
            >= 2
    );
}

#[test]
fn failed_forward_delete_restores_previous_storage_and_policy() {
    let setup = Setup::new();
    setup.seed_keys();
    setup.store(&[owner()]);
    seed_valid_rule(&setup);
    let previous = stored_rules(&setup);
    setup.runner.fail_next("iptables-restore", 1);
    let error = setup
        .forwarding
        .remove_rule("30000", "both")
        .expect_err("apply failure");
    assert!(error.to_string().contains("Command failed"), "{error}");
    assert_eq!(stored_rules(&setup), previous);
}

#[test]
fn failed_add_with_egress_discovery_rolls_back_storage_and_installs_drops() {
    let setup = Setup::new();
    setup.seed_keys();
    setup.store(&[owner()]);
    seed_valid_rule(&setup);
    let previous = stored_rules(&setup);
    setup.runner.set_stdout(
        "sh -c ip route show default | awk '{print $5; exit}'",
        "eth0\n",
    );
    let mut config = (*setup.config).clone();
    config.allow_internet_egress = true;
    let storage: std::sync::Arc<dyn Storage> = setup.storage.clone();
    let iptables = std::sync::Arc::new(portbridge::iptables::IPTablesService::new(
        std::sync::Arc::new(config.clone()),
        storage.clone(),
        setup.runner.clone(),
    ));
    let forwarding = std::sync::Arc::new(portbridge::forwarding_manager::ForwardingManager::new(
        iptables,
        storage,
        std::sync::Arc::new(config),
    ));
    setup.runner.fail_next("ip -j -4 route show dev eth0", 1);
    assert!(forwarding
        .add_rule(&rule(json!(30001), json!(8081)))
        .is_err());
    assert_eq!(stored_rules(&setup), previous);
    let drops = setup
        .runner
        .calls()
        .iter()
        .filter_map(|(_, input)| input.as_deref())
        .filter(|payload| {
            payload.contains("-A WG_FORWARDER_FWD -i wg0 -j DROP")
                && payload.contains("-A WG_FORWARDER_FWD -o wg0 -j DROP")
        })
        .count();
    assert!(
        drops >= 1,
        "discovery failure must install the drop-only policy"
    );
}
