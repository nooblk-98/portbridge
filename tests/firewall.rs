#![allow(dead_code)]

mod common;

use common::{client, packet_verdict, with_options, Setup};
use portbridge::rule_renderer::render_rule;
use serde_json::json;

const ROUTE: &str = "192.168.50.10/32";

fn tunnel_rules(setup: &Setup) -> Vec<Vec<String>> {
    let mut rules = setup.iptables.routing_rules("eth0").expect("rules");
    let interface = setup.config.wg_interface.clone();
    rules.push(vec![
        "-i".into(),
        interface.clone(),
        "-j".into(),
        "DROP".into(),
    ]);
    rules.push(vec!["-o".into(), interface, "-j".into(), "DROP".into()]);
    rules
}

#[test]
fn legacy_route_allows_every_connected_peer() {
    let setup = Setup::new();
    setup.seed_keys();
    let owner = with_options(
        client("owner", "10.8.0.2", "owner-public"),
        json!({"advertised_routes": [ROUTE]}),
    );
    setup.store(&[
        owner,
        client("reader", "10.8.0.3", "reader-public"),
        client("third", "10.8.0.4", "third-public"),
    ]);
    let rules = tunnel_rules(&setup);
    assert_eq!(
        packet_verdict(&rules, "10.8.0.3", "192.168.50.10", false),
        "ACCEPT"
    );
    assert_eq!(
        packet_verdict(&rules, "10.8.0.4", "192.168.50.10", false),
        "ACCEPT"
    );
    assert_eq!(
        packet_verdict(&rules, "192.168.50.10", "10.8.0.3", true),
        "ACCEPT"
    );
}

#[test]
fn selected_peer_only_and_established_replies_are_restricted() {
    let setup = Setup::new();
    setup.seed_keys();
    let owner = with_options(
        client("owner", "10.8.0.2", "owner-public"),
        json!({
            "advertised_routes": [ROUTE],
            "route_access": {ROUTE: ["reader-public"]}
        }),
    );
    setup.store(&[
        owner,
        client("reader", "10.8.0.3", "reader-public"),
        client("third", "10.8.0.4", "third-public"),
    ]);
    let rules = tunnel_rules(&setup);
    assert_eq!(
        packet_verdict(&rules, "10.8.0.3", "192.168.50.10", false),
        "ACCEPT"
    );
    assert_eq!(
        packet_verdict(&rules, "10.8.0.4", "192.168.50.10", false),
        "DROP"
    );
    assert_eq!(
        packet_verdict(&rules, "192.168.50.10", "10.8.0.3", true),
        "ACCEPT"
    );
    assert_eq!(
        packet_verdict(&rules, "192.168.50.10", "10.8.0.4", true),
        "DROP"
    );
}

#[test]
fn empty_access_list_denies_all_recipients_but_not_the_owner() {
    let setup = Setup::new();
    setup.seed_keys();
    let owner = with_options(
        client("owner", "10.8.0.2", "owner-public"),
        json!({
            "advertised_routes": [ROUTE],
            "route_access": {ROUTE: []}
        }),
    );
    setup.store(&[
        owner,
        client("reader", "10.8.0.3", "reader-public"),
        client("third", "10.8.0.4", "third-public"),
    ]);
    let rules = tunnel_rules(&setup);
    assert_eq!(
        packet_verdict(&rules, "10.8.0.3", "192.168.50.10", false),
        "DROP"
    );
    assert_eq!(
        packet_verdict(&rules, "192.168.50.10", "10.8.0.3", true),
        "DROP"
    );
    assert_eq!(
        packet_verdict(&rules, "10.8.0.2", "192.168.50.10", false),
        "ACCEPT"
    );
}

#[test]
fn deleted_recipient_cannot_reuse_an_established_flow() {
    let setup = Setup::new();
    setup.seed_keys();
    let owner = with_options(
        client("owner", "10.8.0.2", "owner-public"),
        json!({
            "advertised_routes": [ROUTE],
            "route_access": {ROUTE: ["deleted-public"]}
        }),
    );
    setup.store(&[
        owner,
        client("reader", "10.8.0.3", "reader-public"),
        client("third", "10.8.0.4", "third-public"),
    ]);
    let rules = tunnel_rules(&setup);
    assert_eq!(
        packet_verdict(&rules, "10.8.0.3", "192.168.50.10", false),
        "DROP"
    );
    assert_eq!(
        packet_verdict(&rules, "192.168.50.10", "10.8.0.3", true),
        "DROP"
    );
    assert!(!rules
        .iter()
        .any(|rule| rule.iter().any(|value| value == "10.8.0.3/32")));
}

#[test]
fn apply_forwardings_installs_atomic_restore_payloads() {
    let setup = Setup::new();
    setup.seed_keys();
    setup.store(&[client("owner", "10.8.0.2", "owner-public")]);
    setup.store_forwarding(json!({
        "port": 30000,
        "protocol": "both",
        "client_ip": "10.8.0.2",
        "peer_public_key": "owner-public",
        "target_port": 8080,
        "source_ip": null
    }));
    let rules = setup.iptables.load_forwardings(None);
    setup.iptables.apply_forwardings(&rules).expect("apply");
    let calls = setup.runner.calls();
    let payloads: Vec<&str> = calls
        .iter()
        .filter(|(command, _)| command.first().map(String::as_str) == Some("iptables-restore"))
        .filter_map(|(_, input)| input.as_deref())
        .collect();
    assert_eq!(payloads.len(), 3);
    let filter = payloads[0];
    assert!(filter.starts_with("*filter\n:WG_FORWARDER_FWD - [0:0]\n-F WG_FORWARDER_FWD\n"));
    assert!(filter.contains("-A WG_FORWARDER_FWD -i eth0 -o wg0 -m conntrack --ctstate DNAT -p tcp -d 10.8.0.2 --dport 8080 -m conntrack --ctorigdstport 30000 -j ACCEPT"));
    assert!(filter.contains("-A WG_FORWARDER_FWD -i wg0 -j DROP\n"));
    assert!(filter.contains("-A WG_FORWARDER_FWD -o wg0 -j DROP\n"));
    assert!(filter.ends_with("COMMIT\n"));
    assert!(payloads[1].contains(
        "-A WG_FORWARDER -i eth0 -p tcp --dport 30000 -j DNAT --to-destination 10.8.0.2:8080"
    ));
}

#[test]
fn render_rule_matches_the_reference_arguments() {
    let rule = json!({
        "port": "8000-8100",
        "protocol": "tcp",
        "client_ip": "10.8.0.2",
        "target_port": 9000,
        "source_ip": "203.0.113.0/24"
    });
    let commands = render_rule(&rule, "eth0");
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].table, "nat");
    assert_eq!(
        commands[0].args,
        vec![
            "-i",
            "eth0",
            "-p",
            "tcp",
            "--dport",
            "8000:8100",
            "-j",
            "DNAT",
            "--to-destination",
            "10.8.0.2:8000-8100",
            "-s",
            "203.0.113.0/24"
        ]
    );
    assert_eq!(commands[1].table, "filter");
    assert_eq!(
        commands[1].args,
        vec![
            "-p",
            "tcp",
            "-d",
            "10.8.0.2",
            "--dport",
            "8000:8100",
            "-m",
            "conntrack",
            "--ctorigdstport",
            "8000:8100",
            "-j",
            "ACCEPT",
            "-s",
            "203.0.113.0/24"
        ]
    );
}

#[test]
fn invalid_rule_is_skipped() {
    assert!(render_rule(
        &json!({"port": "not-a-port", "client_ip": "10.8.0.2"}),
        "eth0"
    )
    .is_empty());
}

fn egress_firewall(setup: &Setup) -> std::sync::Arc<portbridge::iptables::IPTablesService> {
    setup.runner.set_stdout(
        "sh -c ip route show default | awk '{print $5; exit}'",
        "eth0\n",
    );
    let mut config = (*setup.config).clone();
    config.allow_internet_egress = true;
    let storage: std::sync::Arc<dyn portbridge::storage::Storage> = setup.storage.clone();
    std::sync::Arc::new(portbridge::iptables::IPTablesService::new(
        std::sync::Arc::new(config),
        storage,
        setup.runner.clone(),
    ))
}

fn restore_count(setup: &Setup) -> usize {
    setup
        .runner
        .calls()
        .iter()
        .filter(|(command, _)| command.first().map(String::as_str) == Some("iptables-restore"))
        .count()
}

#[test]
fn egress_route_discovery_failure_keeps_the_running_policy() {
    let setup = Setup::new();
    setup.seed_keys();
    setup.store(&[client("owner", "10.8.0.2", "owner-public")]);
    let firewall = egress_firewall(&setup);
    firewall.apply_forwardings(&[]).expect("initial policy");
    let installed = restore_count(&setup);

    setup.runner.fail_next("ip -j -4 route show dev eth0", 1);
    let error = firewall
        .apply_forwardings(&[])
        .expect_err("discovery failure");
    assert!(error.to_string().contains("directly connected"), "{error}");
    assert_eq!(
        restore_count(&setup),
        installed,
        "policy must not be replaced"
    );

    setup
        .runner
        .set_stdout("ip -j -4 route show dev eth0", "{not json");
    let error = firewall
        .apply_forwardings(&[])
        .expect_err("invalid discovery output");
    assert!(error.to_string().contains("directly connected"), "{error}");
    assert_eq!(
        restore_count(&setup),
        installed,
        "policy must not be replaced"
    );
}

#[test]
fn egress_blocks_discovered_direct_routes_before_allowing_internet() {
    let setup = Setup::new();
    setup.seed_keys();
    setup.store(&[client("owner", "10.8.0.2", "owner-public")]);
    setup.runner.set_stdout(
        "ip -j -4 route show dev eth0",
        r#"[{"dst":"192.0.2.0/24","dev":"eth0"},{"dst":"default","dev":"eth0"}]"#,
    );
    let firewall = egress_firewall(&setup);
    let rules = firewall.routing_rules("eth0").expect("rules");
    let direct = vec![
        "-i",
        "wg0",
        "-o",
        "eth0",
        "-d",
        "192.0.2.0/24",
        "-j",
        "DROP",
    ];
    let allow = vec![
        "-i",
        "wg0",
        "-o",
        "eth0",
        "-s",
        "10.8.0.0/24",
        "-j",
        "ACCEPT",
    ];
    let direct_index = rules
        .iter()
        .position(|rule| *rule == direct)
        .expect("direct block");
    let allow_index = rules
        .iter()
        .position(|rule| *rule == allow)
        .expect("internet allow");
    assert!(direct_index < allow_index);
}
