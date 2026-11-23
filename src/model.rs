use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::host_addresses;
use crate::error::AppError;
use crate::storage::Storage;

pub const DEFAULT_DNS: &str = "1.1.1.1";
pub const DEFAULT_KEEPALIVE: i64 = 25;

pub fn private_routes() -> Vec<Ipv4Net> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
    ]
    .iter()
    .map(|value| value.parse().expect("private route"))
    .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    pub name: String,
    pub address: String,
    pub private_key: String,
    pub public_key: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Load the persisted client list, refusing to silently discard corrupt or
/// partly invalid records. Callers must not save over this state when it fails.
pub fn load_clients(storage: &dyn Storage, path: &str) -> Result<Vec<Client>, AppError> {
    if !storage.exists(path) {
        return Ok(Vec::new());
    }
    let text = storage
        .read_text(path)
        .ok_or_else(|| AppError::runtime("Unable to read the client state file."))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| AppError::runtime(format!("Invalid client state file: {error}")))?;
    let Value::Array(items) = value else {
        return Err(AppError::runtime(
            "Invalid client state file: expected a JSON array.",
        ));
    };
    let mut clients = Vec::with_capacity(items.len());
    let mut names = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for (index, item) in items.into_iter().enumerate() {
        let client: Client = serde_json::from_value(item).map_err(|error| {
            AppError::runtime(format!("Invalid client record {index}: {error}"))
        })?;
        let address = client.address_ip().ok_or_else(|| {
            AppError::runtime(format!("Invalid client record {index}: invalid address."))
        })?;
        if client.name.is_empty() || client.public_key.is_empty() || client.private_key.is_empty() {
            return Err(AppError::runtime(format!(
                "Invalid client record {index}: missing name or key."
            )));
        }
        if !names.insert(client.name.clone())
            || !addresses.insert(address)
            || !keys.insert(client.public_key.clone())
        {
            return Err(AppError::runtime(format!(
                "Invalid client record {index}: duplicate name, address or public key."
            )));
        }
        clients.push(client);
    }
    Ok(clients)
}

impl Client {
    pub fn address_ip(&self) -> Option<Ipv4Addr> {
        self.address.parse().ok()
    }

    pub fn options(&self) -> PeerOptions {
        PeerOptions::from_extra(&self.extra)
    }

    pub fn set_options(&mut self, settings: &PeerSettings) {
        for (key, value) in settings.as_map() {
            self.extra.insert(key, value);
        }
    }
}

#[derive(Clone, Debug)]
pub enum RouteAccess {
    All,
    Deny,
    Selected(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct PeerOptions {
    pub advertised_routes: Vec<String>,
    pub route_access: Value,
    pub split_tunnel: bool,
    pub dns: String,
    pub mtu: Option<i64>,
    pub keepalive: i64,
}

impl Default for PeerOptions {
    fn default() -> Self {
        Self {
            advertised_routes: Vec::new(),
            route_access: Value::Object(Map::new()),
            split_tunnel: false,
            dns: DEFAULT_DNS.to_string(),
            mtu: None,
            keepalive: DEFAULT_KEEPALIVE,
        }
    }
}

impl PeerOptions {
    pub fn from_extra(extra: &Map<String, Value>) -> Self {
        let advertised_routes = extra
            .get("advertised_routes")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let route_access = extra
            .get("route_access")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        let split_tunnel = extra
            .get("split_tunnel")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let dns = extra
            .get("dns")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_DNS)
            .to_string();
        let mtu = extra.get("mtu").and_then(Value::as_i64);
        let keepalive = extra
            .get("keepalive")
            .and_then(Value::as_i64)
            .unwrap_or(DEFAULT_KEEPALIVE);
        Self {
            advertised_routes,
            route_access,
            split_tunnel,
            dns,
            mtu,
            keepalive,
        }
    }

    pub fn as_map(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert(
            "advertised_routes".to_string(),
            Value::Array(string_array(&self.advertised_routes)),
        );
        map.insert("route_access".to_string(), self.route_access.clone());
        map.insert("split_tunnel".to_string(), Value::Bool(self.split_tunnel));
        map.insert("dns".to_string(), Value::String(self.dns.clone()));
        map.insert(
            "mtu".to_string(),
            self.mtu.map(Value::from).unwrap_or(Value::Null),
        );
        map.insert("keepalive".to_string(), Value::from(self.keepalive));
        map
    }

    pub fn route_access_for(&self, route: &str) -> RouteAccess {
        match &self.route_access {
            Value::Null => RouteAccess::All,
            Value::Object(entries) => match entries.get(route) {
                None => RouteAccess::All,
                Some(Value::Array(items)) => RouteAccess::Selected(
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect(),
                ),
                Some(_) => RouteAccess::Deny,
            },
            _ => RouteAccess::Deny,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerSettings {
    pub advertised_routes: Vec<String>,
    pub route_access: Value,
    pub split_tunnel: bool,
    pub dns: String,
    pub mtu: Option<i64>,
    pub keepalive: i64,
}

impl PeerSettings {
    pub fn as_map(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert(
            "advertised_routes".to_string(),
            Value::Array(string_array(&self.advertised_routes)),
        );
        map.insert("route_access".to_string(), self.route_access.clone());
        map.insert("split_tunnel".to_string(), Value::Bool(self.split_tunnel));
        map.insert("dns".to_string(), Value::String(self.dns.clone()));
        map.insert(
            "mtu".to_string(),
            self.mtu.map(Value::from).unwrap_or(Value::Null),
        );
        map.insert("keepalive".to_string(), Value::from(self.keepalive));
        map
    }

    pub fn as_options(&self) -> PeerOptions {
        let mut extra = Map::new();
        for (key, value) in self.as_map() {
            extra.insert(key, value);
        }
        PeerOptions::from_extra(&extra)
    }
}

pub fn string_array(values: &[String]) -> Vec<Value> {
    values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect()
}

pub fn parse_cidr(value: &str) -> Result<Ipv4Net, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Each advertised route must be an IPv4 address or CIDR.".to_string());
    }
    let text = if trimmed.contains('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/32")
    };
    let parsed: Ipv4Net = text
        .parse()
        .map_err(|_| format!("Invalid IPv4 route: {trimmed}"))?;
    if parsed.network() != parsed.addr() {
        return Err(format!("Invalid IPv4 route: {trimmed}"));
    }
    Ok(parsed)
}

pub fn networks_overlap(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

pub fn is_private(route: Ipv4Net) -> bool {
    private_routes().iter().any(|private| {
        route.prefix_len() >= private.prefix_len() && private.contains(&route.network())
    })
}

/// Peers whose public key and tunnel address are unique and valid.
pub fn validated_peers(clients: &[Client]) -> Vec<Client> {
    let mut candidates: Vec<(String, String, Client)> = Vec::new();
    for client in clients {
        let Some(key) = Some(client.public_key.as_str()).filter(|key| !key.is_empty()) else {
            continue;
        };
        let Some(address) = client.address_ip() else {
            continue;
        };
        candidates.push((key.to_string(), address.to_string(), client.clone()));
    }
    let mut key_counts = BTreeMap::<String, usize>::new();
    let mut address_counts = BTreeMap::<String, usize>::new();
    for (key, address, _) in &candidates {
        *key_counts.entry(key.clone()).or_insert(0) += 1;
        *address_counts.entry(address.clone()).or_insert(0) += 1;
    }
    candidates
        .into_iter()
        .filter(|(key, address, _)| {
            key_counts.get(key) == Some(&1) && address_counts.get(address) == Some(&1)
        })
        .map(|(_, _, client)| client)
        .collect()
}

pub fn allowed_recipient_keys(
    owner: &Client,
    route: &str,
    clients: &[Client],
) -> Option<BTreeSet<String>> {
    let access = owner.options().route_access_for(route);
    match access {
        RouteAccess::All => None,
        RouteAccess::Deny => Some(BTreeSet::new()),
        RouteAccess::Selected(selected) => {
            let connected: BTreeSet<String> = validated_peers(clients)
                .into_iter()
                .filter(|peer| peer.public_key != owner.public_key)
                .map(|peer| peer.public_key)
                .collect();
            Some(
                selected
                    .into_iter()
                    .filter(|key| connected.contains(key))
                    .collect(),
            )
        }
    }
}

pub fn allowed_recipient_addresses(
    owner: &Client,
    route: &str,
    clients: &[Client],
) -> Vec<Ipv4Addr> {
    let peers: Vec<Client> = validated_peers(clients)
        .into_iter()
        .filter(|peer| peer.public_key != owner.public_key && peer.address != owner.address)
        .collect();
    let selected = allowed_recipient_keys(owner, route, clients);
    let mut addresses: BTreeSet<Ipv4Addr> = peers
        .into_iter()
        .filter(|peer| match &selected {
            None => true,
            Some(keys) => keys.contains(&peer.public_key),
        })
        .filter_map(|peer| peer.address_ip())
        .collect();
    if let Some(address) = owner.address_ip() {
        // The advertising peer can always use its own route.
        addresses.insert(address);
    }
    addresses.into_iter().collect()
}

pub fn may_receive_route(client: &Client, owner: &Client, route: &str, clients: &[Client]) -> bool {
    if client.public_key == owner.public_key {
        return false;
    }
    match allowed_recipient_keys(owner, route, clients) {
        None => true,
        Some(keys) => keys.contains(&client.public_key),
    }
}

fn stored_recipient_keys(value: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let mut stored = BTreeMap::new();
    let Value::Object(entries) = value else {
        return stored;
    };
    for (raw_route, keys) in entries {
        let Ok(cidr) = parse_cidr(raw_route) else {
            continue;
        };
        if let Value::Array(items) = keys {
            stored.insert(
                cidr.to_string(),
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
            );
        }
    }
    stored
}

fn sanitize_route_access(
    value: &Value,
    routes: &[String],
    client: &Client,
    clients: &[Client],
    strict_identity: bool,
    previous_access: &Value,
) -> Result<Value, String> {
    let advertised: BTreeMap<String, Ipv4Net> = routes
        .iter()
        .map(|route| (route.clone(), parse_cidr(route).expect("validated route")))
        .collect();
    let own_key = client.public_key.as_str();
    let connected: BTreeSet<String> = validated_peers(clients)
        .into_iter()
        .filter(|peer| peer.public_key != own_key)
        .map(|peer| peer.public_key)
        .collect();
    let previously_stored = stored_recipient_keys(previous_access);

    let empty = Map::new();
    let entries = match value {
        Value::Null => &empty,
        Value::Object(entries) => entries,
        _ => {
            if strict_identity {
                return Err(
                    "Route access must map advertised routes to peer public keys.".to_string(),
                );
            }
            let mut fail_closed = Map::new();
            for route in routes {
                fail_closed.insert(route.clone(), Value::Array(Vec::new()));
            }
            return Ok(Value::Object(fail_closed));
        }
    };
    let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (raw_route, raw_keys) in entries {
        let route = match parse_cidr(raw_route) {
            Ok(route) => route,
            Err(_) => {
                if strict_identity {
                    return Err(format!("Invalid route access range: '{raw_route}'."));
                }
                continue;
            }
        };
        let cidr = route.to_string();
        if !advertised.contains_key(&cidr) {
            if advertised
                .values()
                .any(|existing| networks_overlap(route, *existing))
                && strict_identity
            {
                return Err(format!(
                    "Route access range overlaps an advertised route: {cidr}"
                ));
            }
            continue;
        }
        let keys = match raw_keys {
            Value::Array(items) if items.len() <= 256 => items,
            _ => {
                if strict_identity {
                    return Err(
                        "Each route access entry must be a list of up to 256 peer public keys."
                            .to_string(),
                    );
                }
                result.insert(cidr, Vec::new());
                continue;
            }
        };
        let mut selected: Vec<String> = Vec::new();
        for key in keys {
            let Some(key) = key.as_str() else {
                if strict_identity {
                    return Err("Route access lists an unknown peer: <non-string>.".to_string());
                }
                continue;
            };
            if key == own_key {
                if strict_identity {
                    return Err("A peer cannot grant itself route access.".to_string());
                }
                continue;
            }
            if !connected.contains(key) {
                // A recipient deleted since the last save stays revoked; it is not
                // accepted as a new selection.
                let was_stored = previously_stored
                    .get(&cidr)
                    .is_some_and(|stored| stored.contains(key));
                if strict_identity && !was_stored {
                    return Err(format!(
                        "Route access lists an unknown peer: '{}'.",
                        key.chars().take(64).collect::<String>()
                    ));
                }
                continue;
            }
            if !selected.iter().any(|existing| existing == key) {
                selected.push(key.to_string());
            }
        }
        selected.sort();
        result.insert(cidr, selected);
    }

    let mut ordered: Vec<(Ipv4Net, Vec<String>)> = result
        .into_iter()
        .map(|(cidr, keys)| (parse_cidr(&cidr).expect("canonical route"), keys))
        .collect();
    ordered.sort_by_key(|(route, _)| (u32::from(route.network()), route.prefix_len()));
    let mut output = Map::new();
    for (route, keys) in ordered {
        output.insert(route.to_string(), Value::Array(string_array(&keys)));
    }
    Ok(Value::Object(output))
}

pub fn validate_options(
    raw: &Map<String, Value>,
    client: &Client,
    clients: &[Client],
    network: Ipv4Net,
) -> Result<PeerSettings, String> {
    const ALLOWED: [&str; 6] = [
        "advertised_routes",
        "route_access",
        "split_tunnel",
        "dns",
        "mtu",
        "keepalive",
    ];
    if raw.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err("Invalid peer options.".to_string());
    }
    let mut merged = client.options().as_map();
    for (key, value) in raw {
        merged.insert(key.clone(), value.clone());
    }
    let routes_value = merged
        .get("advertised_routes")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let route_values = routes_value
        .as_array()
        .ok_or_else(|| "Enter up to 32 advertised IPv4 routes.".to_string())?;
    if route_values.len() > 32 {
        return Err("Enter up to 32 advertised IPv4 routes.".to_string());
    }

    let mut occupied: Vec<Ipv4Net> = vec![network];
    for peer in clients {
        if peer.name != client.name {
            for route in peer.options().advertised_routes {
                let parsed = parse_cidr(&route)
                    .map_err(|_| format!("Invalid stored routes for peer {}.", peer.name))?;
                occupied.push(parsed);
            }
        }
    }
    let mut normalized = Vec::new();
    for value in route_values {
        let Some(value) = value.as_str() else {
            return Err("Each advertised route must be an IPv4 address or CIDR.".to_string());
        };
        let route = parse_cidr(value).map_err(|_| format!("Invalid advertised route: {value}"))?;
        if !is_private(route) {
            return Err(format!(
                "Advertise an address within a private or shared IPv4 range: {route}"
            ));
        }
        if occupied.iter().any(|other| networks_overlap(route, *other)) {
            return Err(format!("Advertised route overlaps another route: {route}"));
        }
        occupied.push(route);
        normalized.push(route.to_string());
    }
    normalized.sort();

    let previous_access = client
        .extra
        .get("route_access")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let route_access = sanitize_route_access(
        merged.get("route_access").unwrap_or(&Value::Null),
        &normalized,
        client,
        clients,
        raw.contains_key("route_access"),
        &previous_access,
    )?;

    let split_tunnel = merged
        .get("split_tunnel")
        .and_then(Value::as_bool)
        .ok_or_else(|| "Split tunnel must be enabled or disabled.".to_string())?;

    let dns_text = merged
        .get("dns")
        .and_then(Value::as_str)
        .ok_or_else(|| "DNS must be a comma-separated list of IP addresses.".to_string())?;
    if dns_text.contains('%') {
        return Err("DNS must be a comma-separated list of IP addresses.".to_string());
    }
    let mut dns_parts = Vec::new();
    for part in dns_text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let address: std::net::IpAddr = part
            .parse()
            .map_err(|_| "DNS must be a comma-separated list of IP addresses.".to_string())?;
        dns_parts.push(address.to_string());
    }
    let dns = dns_parts.join(", ");

    let mtu = match merged.get("mtu") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let number = value
                .as_i64()
                .ok_or_else(|| "MTU must be between 1280 and 9000.".to_string())?;
            if !(1280..=9000).contains(&number) {
                return Err("MTU must be between 1280 and 9000.".to_string());
            }
            Some(number)
        }
    };
    let keepalive = merged
        .get("keepalive")
        .and_then(Value::as_i64)
        .ok_or_else(|| "KEEPALIVE must be between 0 and 65535.".to_string())?;
    if !(0..=65535).contains(&keepalive) {
        return Err("KEEPALIVE must be between 0 and 65535.".to_string());
    }

    Ok(PeerSettings {
        advertised_routes: normalized,
        route_access,
        split_tunnel,
        dns,
        mtu,
        keepalive,
    })
}

/// Versions of an existing peer used by the API and profile rendering.
pub fn next_available_ip(
    network: Ipv4Net,
    server: Ipv4Addr,
    clients: &[Client],
) -> Option<Ipv4Addr> {
    let used: BTreeSet<Ipv4Addr> = std::iter::once(server)
        .chain(clients.iter().filter_map(Client::address_ip))
        .collect();
    host_addresses(network).find(|address| !used.contains(address))
}
