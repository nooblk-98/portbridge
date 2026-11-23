#![allow(dead_code)]

mod common;

use std::net::Ipv4Addr;

use common::{client, with_options};
use portbridge::model::{
    allowed_recipient_addresses, allowed_recipient_keys, may_receive_route, parse_cidr,
    validate_options, validated_peers,
};
use serde_json::{json, Map, Value};

const ROUTE: &str = "192.168.50.10/32";
const ROUTE_TWO: &str = "192.168.60.0/24";

fn network() -> ipnet::Ipv4Net {
    "10.8.0.0/24".parse().unwrap()
}

fn peers() -> Vec<portbridge::model::Client> {
    vec![
        client("owner", "10.8.0.2", "owner-public"),
        client("reader", "10.8.0.3", "reader-public"),
        client("third", "10.8.0.4", "third-public"),
    ]
}

#[test]
fn legacy_route_has_no_access_list() {
    let clients = peers();
    assert!(allowed_recipient_keys(&clients[0], ROUTE, &clients).is_none());
    assert_eq!(
        allowed_recipient_addresses(&clients[0], ROUTE, &clients),
        vec![
            "10.8.0.2".parse::<Ipv4Addr>().unwrap(),
            "10.8.0.3".parse().unwrap(),
            "10.8.0.4".parse().unwrap()
        ]
    );
}

#[test]
fn empty_and_corrupt_access_fail_closed() {
    let mut clients = peers();
    clients[0]
        .extra
        .insert("route_access".into(), json!({ROUTE: []}));
    assert_eq!(
        allowed_recipient_keys(&clients[0], ROUTE, &clients),
        Some(Default::default())
    );
    clients[0]
        .extra
        .insert("route_access".into(), json!("corrupt"));
    assert_eq!(
        allowed_recipient_keys(&clients[0], ROUTE, &clients),
        Some(Default::default())
    );
    clients[0]
        .extra
        .insert("route_access".into(), json!({ROUTE: "corrupt"}));
    assert_eq!(
        allowed_recipient_keys(&clients[0], ROUTE, &clients),
        Some(Default::default())
    );
}

#[test]
fn selected_key_maps_to_its_current_address() {
    let mut clients = peers();
    clients[0]
        .extra
        .insert("route_access".into(), json!({ROUTE: ["reader-public"]}));
    assert_eq!(
        allowed_recipient_addresses(&clients[0], ROUTE, &clients),
        vec![
            "10.8.0.2".parse::<Ipv4Addr>().unwrap(),
            "10.8.0.3".parse().unwrap()
        ]
    );
    // The same key at a new tunnel address follows the key, not the old address.
    clients[1].address = "10.8.0.9".into();
    assert_eq!(
        allowed_recipient_addresses(&clients[0], ROUTE, &clients),
        vec![
            "10.8.0.2".parse::<Ipv4Addr>().unwrap(),
            "10.8.0.9".parse().unwrap()
        ]
    );
    // A replacement key at the old address is not selected.
    clients[1].public_key = "replacement-public".into();
    let allowed = allowed_recipient_keys(&clients[0], ROUTE, &clients).unwrap();
    assert!(allowed.is_empty());
    assert!(!may_receive_route(
        &clients[1],
        &clients[0],
        ROUTE,
        &clients
    ));
}

#[test]
fn validation_canonicalizes_and_prunes_stale_entries() {
    let clients = peers();
    let mut raw = Map::new();
    raw.insert("advertised_routes".into(), json!(["192.168.50.10"]));
    raw.insert(
        "route_access".into(),
        json!({
            "192.168.50.10": ["reader-public", "reader-public"],
            ROUTE_TWO: ["third-public"]
        }),
    );
    let settings = validate_options(&raw, &clients[0], &clients, network()).expect("settings");
    assert_eq!(settings.advertised_routes, vec![ROUTE]);
    assert_eq!(settings.route_access, json!({ROUTE: ["reader-public"]}));
}

#[test]
fn validation_rejects_unknown_recipients_overlaps_and_self() {
    let clients = peers();
    let base = || {
        let mut raw = Map::new();
        raw.insert("advertised_routes".into(), json!([ROUTE]));
        raw
    };
    let mut unknown = base();
    unknown.insert("route_access".into(), json!({ROUTE: ["ghost-public"]}));
    let error = validate_options(&unknown, &clients[0], &clients, network()).unwrap_err();
    assert!(error.contains("unknown peer"), "{error}");

    let mut overlap = base();
    overlap.insert(
        "route_access".into(),
        json!({"192.168.50.0/24": ["reader-public"]}),
    );
    let error = validate_options(&overlap, &clients[0], &clients, network()).unwrap_err();
    assert!(error.contains("overlaps an advertised route"), "{error}");

    let mut own = base();
    own.insert("route_access".into(), json!({ROUTE: ["owner-public"]}));
    let error = validate_options(&own, &clients[0], &clients, network()).unwrap_err();
    assert!(error.contains("cannot grant itself"), "{error}");
}

#[test]
fn removing_a_route_prunes_its_access_entry() {
    let mut clients = peers();
    clients[0]
        .extra
        .insert("advertised_routes".into(), json!([ROUTE, ROUTE_TWO]));
    clients[0]
        .extra
        .insert("route_access".into(), json!({ROUTE: ["reader-public"]}));
    let mut raw = Map::new();
    raw.insert("advertised_routes".into(), json!([ROUTE_TWO]));
    let settings = validate_options(&raw, &clients[0], &clients, network()).expect("settings");
    assert_eq!(settings.route_access, json!({}));
}

#[test]
fn stale_stored_recipient_does_not_block_unrelated_edit() {
    let mut clients = peers();
    clients[0]
        .extra
        .insert("advertised_routes".into(), json!([ROUTE]));
    clients[0]
        .extra
        .insert("route_access".into(), json!({ROUTE: ["deleted-public"]}));
    let mut raw = Map::new();
    raw.insert("dns".into(), json!("9.9.9.9"));
    let settings = validate_options(&raw, &clients[0], &clients, network()).expect("settings");
    assert_eq!(settings.route_access, json!({ROUTE: []}));
    assert_eq!(settings.dns, "9.9.9.9");
}

#[test]
fn route_cidrs_are_strict_and_private() {
    assert_eq!(
        parse_cidr("192.168.1.5").unwrap().to_string(),
        "192.168.1.5/32"
    );
    assert!(parse_cidr("192.168.1.5/24").is_err());
    let clients = peers();
    for value in ["10.8.0.50", "0.0.0.0/0", "127.0.0.1", "::1"] {
        let mut raw = Map::new();
        raw.insert("advertised_routes".into(), json!([value]));
        assert!(
            validate_options(&raw, &clients[0], &clients, network()).is_err(),
            "{value} should be rejected"
        );
    }
}

#[test]
fn duplicate_keys_or_addresses_are_not_validated() {
    let mut clients = peers();
    let clone = client("owner-copy", "10.8.0.2", "owner-public");
    clients.push(clone);
    let valid = validated_peers(&clients);
    assert!(valid
        .iter()
        .all(|peer| peer.name != "owner" && peer.name != "owner-copy"));
}

#[test]
fn options_round_trip_keeps_the_documented_defaults() {
    let client = with_options(client("owner", "10.8.0.2", "owner-public"), Value::Null);
    let options = client.options();
    assert!(!options.split_tunnel);
    assert_eq!(options.dns, "1.1.1.1");
    assert_eq!(options.keepalive, 25);
    assert!(options.mtu.is_none());
}
