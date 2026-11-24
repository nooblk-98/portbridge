use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ipnet::Ipv4Net;
use regex::Regex;
use serde_json::{json, Value};

use crate::config::Config;
use crate::error::AppError;
use crate::model::{allowed_recipient_addresses, parse_cidr, validated_peers, Client};
use crate::rule_renderer::{render_rule, rule_is_valid};
use crate::runner::Runner;
use crate::storage::Storage;

fn egress_blocks() -> Vec<String> {
    let mut blocks: Vec<String> = crate::model::private_routes()
        .iter()
        .map(ToString::to_string)
        .collect();
    blocks.extend(
        [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "168.63.129.16/32",
            "192.0.0.0/24",
            "224.0.0.0/3",
        ]
        .iter()
        .map(|value| value.to_string()),
    );
    blocks
}

pub struct IPTablesService {
    pub config: Arc<Config>,
    pub storage: Arc<dyn Storage>,
    pub runner: Arc<dyn Runner>,
    lock: Mutex<()>,
}

impl IPTablesService {
    pub fn new(config: Arc<Config>, storage: Arc<dyn Storage>, runner: Arc<dyn Runner>) -> Self {
        Self {
            config,
            storage,
            runner,
            lock: Mutex::new(()),
        }
    }

    pub fn detect_primary_interface(&self) -> Result<String, AppError> {
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            "ip route show default | awk '{print $5; exit}'".to_string(),
        ];
        if let Ok(result) = self.runner.run(&command, false, None) {
            let iface = result.stdout.trim();
            if result.returncode == 0 && !iface.is_empty() {
                return Ok(iface.to_string());
            }
        }
        if self.config.allow_internet_egress {
            return Err(AppError::runtime(
                "Unable to determine the primary interface for internet egress.",
            ));
        }
        Ok("eth0".to_string())
    }

    fn install_chain(
        &self,
        table: &str,
        chain: &str,
        parent: &str,
        rules: &[Vec<String>],
    ) -> Result<(), AppError> {
        let argument = Regex::new(r"^[A-Za-z0-9_.:/,-]+$").expect("iptables argument regex");
        if rules
            .iter()
            .flat_map(|rule| rule.iter())
            .any(|value| !argument.is_match(value))
        {
            return Err(AppError::validation("Invalid firewall rule argument."));
        }
        let mut entries = vec![
            format!("*{table}"),
            format!(":{chain} - [0:0]"),
            format!("-F {chain}"),
        ];
        for rule in rules {
            entries.push(format!("-A {chain} {}", rule.join(" ")));
        }
        let jump = format!("-j {chain}");
        let check = vec![
            "iptables".to_string(),
            "-w".to_string(),
            "-t".to_string(),
            table.to_string(),
            "-C".to_string(),
            parent.to_string(),
            "-j".to_string(),
            chain.to_string(),
        ];
        let present = self.runner.run(&check, false, None)?.returncode == 0;
        if present && table == "filter" {
            entries.push(format!("-D {parent} {jump}"));
        }
        if !present || table == "filter" {
            entries.push(format!("-I {parent} 1 {jump}"));
        }
        let mut payload = entries.join("\n");
        payload.push_str("\nCOMMIT\n");
        self.runner.run(
            &[
                "iptables-restore".to_string(),
                "-w".to_string(),
                "--noflush".to_string(),
            ],
            true,
            Some(&payload),
        )?;
        Ok(())
    }

    pub fn routing_rules(&self, ext_iface: &str) -> Result<Vec<Vec<String>>, AppError> {
        let interface = self.config.wg_interface.clone();
        let network = self.config.wg_network.to_string();
        let same_tunnel = vec![
            "-i".to_string(),
            interface.clone(),
            "-o".to_string(),
            interface.clone(),
        ];
        let established = vec![
            "-m".to_string(),
            "conntrack".to_string(),
            "--ctstate".to_string(),
            "ESTABLISHED,RELATED".to_string(),
        ];
        let mut rules = vec![with(
            &same_tunnel,
            &["-s", &network, "-d", &network, "-j", "ACCEPT"],
        )];
        let clients = crate::model::load_clients(
            self.storage.as_ref(),
            &self.config.clients_file.to_string_lossy(),
        )?;
        let clients = validated_peers(&clients);
        for peer in &clients {
            for route in peer.options().advertised_routes {
                for address in allowed_recipient_addresses(peer, &route, &clients) {
                    rules.push(with(
                        &same_tunnel,
                        &["-s", &format!("{address}/32"), "-d", &route, "-j", "ACCEPT"],
                    ));
                    let mut reply = same_tunnel.clone();
                    reply.extend([
                        "-s".to_string(),
                        route.clone(),
                        "-d".to_string(),
                        format!("{address}/32"),
                    ]);
                    reply.extend(established.clone());
                    reply.extend(["-j".to_string(), "ACCEPT".to_string()]);
                    rules.push(reply);
                }
            }
        }
        if self.config.allow_internet_egress {
            let mut destinations = egress_blocks();
            destinations.extend(
                self.external_connected_routes(ext_iface)?
                    .into_iter()
                    .map(|network| network.to_string()),
            );
            for destination in destinations {
                rules.push(vec![
                    "-i".to_string(),
                    interface.clone(),
                    "-o".to_string(),
                    ext_iface.to_string(),
                    "-d".to_string(),
                    destination,
                    "-j".to_string(),
                    "DROP".to_string(),
                ]);
            }
            rules.push(vec![
                "-i".to_string(),
                interface.clone(),
                "-o".to_string(),
                ext_iface.to_string(),
                "-s".to_string(),
                network.clone(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ]);
            let mut reply = vec![
                "-i".to_string(),
                ext_iface.to_string(),
                "-o".to_string(),
                interface.clone(),
                "-d".to_string(),
                network,
            ];
            reply.extend(established);
            reply.extend(["-j".to_string(), "ACCEPT".to_string()]);
            rules.push(reply);
        }
        Ok(rules)
    }

    fn external_connected_routes(&self, interface: &str) -> Result<Vec<Ipv4Net>, AppError> {
        let command = vec![
            "ip".to_string(),
            "-j".to_string(),
            "-4".to_string(),
            "route".to_string(),
            "show".to_string(),
            "dev".to_string(),
            interface.to_string(),
        ];
        let result = self
            .runner
            .run(&command, false, None)
            .map_err(|_| AppError::runtime("Unable to read directly connected IPv4 routes."))?;
        if result.returncode != 0 {
            return Err(AppError::runtime(
                "Unable to read directly connected IPv4 routes.",
            ));
        }
        let parsed: Value = serde_json::from_str(&result.stdout)
            .map_err(|_| AppError::runtime("Unable to read directly connected IPv4 routes."))?;
        let Value::Array(entries) = parsed else {
            return Err(AppError::runtime(
                "Unable to read directly connected IPv4 routes.",
            ));
        };
        let mut routes = Vec::new();
        for entry in entries {
            let destination = entry.get("dst").and_then(Value::as_str).ok_or_else(|| {
                AppError::runtime("Unable to read directly connected IPv4 routes.")
            })?;
            if destination == "default" {
                continue;
            }
            routes.push(parse_cidr(destination).map_err(|_| {
                AppError::runtime("Unable to read directly connected IPv4 routes.")
            })?);
        }
        Ok(routes)
    }

    fn discovered_or_block<T>(&self, result: Result<T, AppError>) -> Result<T, AppError> {
        result.or_else(|error| {
            self.install_chain(
                "filter",
                &self.config.filter_chain,
                "FORWARD",
                &self.tunnel_drops(),
            )?;
            Err(error)
        })
    }

    /// The rules that end the forwarding chain.
    ///
    /// Everything that enters or leaves the tunnel and was not accepted above is
    /// dropped, except that programs on this server (a Docker reverse proxy, for
    /// example) may open connections to the peers that allow it, and those peers
    /// may answer. A peer allows it when its own setting says so, or, if it has
    /// none, when `allow_local_to_peers` is on. Peers still cannot start
    /// connections to this server's other services or reach each other outside
    /// route access, and the internet reaches peers only through a forwarding
    /// rule.
    pub fn tunnel_policy(&self, ext_iface: &str, clients: &[Client]) -> Vec<Vec<String>> {
        let tunnel = self.config.wg_interface.as_str();
        let rule =
            |parts: &[&str]| -> Vec<String> { parts.iter().map(|part| part.to_string()).collect() };
        let mut rules = vec![
            rule(&["-i", tunnel, "-o", tunnel, "-j", "DROP"]),
            rule(&["-i", tunnel, "-o", ext_iface, "-j", "DROP"]),
            rule(&[
                "-i",
                tunnel,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ]),
            rule(&["-i", tunnel, "-j", "DROP"]),
            rule(&["-i", ext_iface, "-o", tunnel, "-j", "DROP"]),
        ];
        for client in validated_peers(clients) {
            let options = client.options();
            if !options
                .local_access
                .unwrap_or(self.config.allow_local_to_peers)
            {
                continue;
            }
            let mut destinations = vec![format!("{}/32", client.address)];
            destinations.extend(options.advertised_routes);
            for destination in &destinations {
                rules.push(rule(&[
                    "-o",
                    tunnel,
                    "-d",
                    destination.as_str(),
                    "-j",
                    "ACCEPT",
                ]));
            }
        }
        rules.push(rule(&["-o", tunnel, "-j", "DROP"]));
        rules
    }

    fn tunnel_drops(&self) -> [Vec<String>; 2] {
        ["-i", "-o"].map(|direction| {
            [direction, &self.config.wg_interface, "-j", "DROP"]
                .map(str::to_owned)
                .to_vec()
        })
    }

    pub fn apply_forwardings(&self, rules: &[Value]) -> Result<(), AppError> {
        let _guard = self.lock.lock().expect("iptables lock");
        let ext_iface = self.discovered_or_block(self.detect_primary_interface())?;
        let routing = self.discovered_or_block(self.routing_rules(&ext_iface))?;
        let interface = self.config.wg_interface.clone();
        let network = self.config.wg_network.to_string();
        let clients = crate::model::load_clients(
            self.storage.as_ref(),
            &self.config.clients_file.to_string_lossy(),
        )?;
        let policy_clients = clients.clone();
        let owners: BTreeMap<String, String> = clients
            .into_iter()
            .map(|client| (client.address, client.public_key))
            .collect();
        let active: Vec<&Value> = rules
            .iter()
            .filter(|rule| {
                if !rule_is_valid(rule) {
                    return false;
                }
                let peer_key = rule
                    .get("peer_public_key")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let client_ip = rule
                    .get("client_ip")
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| value.to_string())
                    })
                    .unwrap_or_default();
                !peer_key.is_empty() && owners.get(&client_ip).map(String::as_str) == Some(peer_key)
            })
            .collect();
        let mut dnat = Vec::new();
        let mut public = Vec::new();
        for rule in &active {
            for command in render_rule(rule, &ext_iface) {
                if command.table == "nat" {
                    dnat.push(command.args);
                } else {
                    let mut args = vec![
                        "-i".to_string(),
                        ext_iface.clone(),
                        "-o".to_string(),
                        interface.clone(),
                        "-m".to_string(),
                        "conntrack".to_string(),
                        "--ctstate".to_string(),
                        "DNAT".to_string(),
                    ];
                    args.extend(command.args);
                    public.push(args);
                }
            }
        }
        if !public.is_empty() {
            public.push(vec![
                "-i".to_string(),
                interface.clone(),
                "-o".to_string(),
                ext_iface.clone(),
                "-s".to_string(),
                network.clone(),
                "-m".to_string(),
                "conntrack".to_string(),
                "--ctstate".to_string(),
                "DNAT".to_string(),
                "--ctdir".to_string(),
                "REPLY".to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ]);
        }
        let mut policy = public;
        policy.extend(routing);
        policy.extend(self.tunnel_policy(&ext_iface, &policy_clients));
        self.install_chain("filter", &self.config.filter_chain, "FORWARD", &policy)?;
        self.install_chain("nat", &self.config.nat_chain, "PREROUTING", &dnat)?;
        let mut masquerade = Vec::new();
        if self.config.allow_internet_egress {
            masquerade.push(vec![
                "-s".to_string(),
                network,
                "-o".to_string(),
                ext_iface,
                "-j".to_string(),
                "MASQUERADE".to_string(),
            ]);
        }
        let post_chain = format!("{}_POST", self.config.nat_chain);
        self.install_chain("nat", &post_chain, "POSTROUTING", &masquerade)?;
        tracing::info!("Applied {} forwarding rules", rules.len());
        Ok(())
    }

    pub fn load_forwardings(&self, default_client_ip: Option<&str>) -> Vec<Value> {
        let path = self.config.forward_file.to_string_lossy();
        let payload = self.storage.load_json(&path, Value::Null);
        if let Value::Array(items) = payload {
            return items;
        }
        if let Some(client_ip) = default_client_ip {
            let seed = vec![json!({
                "port": 30000,
                "protocol": "both",
                "client_ip": client_ip,
                "target_port": 8080,
            })];
            if let Err(error) = self.storage.save_json(&path, &Value::Array(seed.clone())) {
                tracing::error!("Could not save the default forwarding rule: {error}");
            }
            return seed;
        }
        if let Err(error) = self.storage.save_json(&path, &json!([])) {
            tracing::error!("Could not save the empty forwarding list: {error}");
        }
        Vec::new()
    }
}

fn with(base: &[String], extra: &[&str]) -> Vec<String> {
    let mut values = base.to_vec();
    values.extend(extra.iter().map(|value| value.to_string()));
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::FakeRunner;
    use crate::storage::InMemoryStorage;
    use serde_json::json;

    fn service(allow_local: bool) -> IPTablesService {
        let mut config = Config::for_test(std::env::temp_dir());
        config.allow_local_to_peers = allow_local;
        IPTablesService::new(
            Arc::new(config),
            Arc::new(InMemoryStorage::new()),
            Arc::new(FakeRunner::new()),
        )
    }

    fn peer(name: &str, key: &str, address: &str, extra: serde_json::Value) -> Client {
        Client {
            name: name.to_string(),
            address: address.to_string(),
            private_key: "private".to_string(),
            public_key: key.to_string(),
            created_at: 0,
            extra: extra.as_object().cloned().unwrap_or_default(),
        }
    }

    fn joined(rules: &[Vec<String>]) -> Vec<String> {
        rules.iter().map(|rule| rule.join(" ")).collect()
    }

    fn position(rules: &[String], needle: &str) -> usize {
        rules.iter().position(|rule| rule == needle).expect(needle)
    }

    #[test]
    fn local_programs_may_reach_peers_and_their_routes_when_the_default_is_on() {
        let clients = vec![
            peer(
                "home",
                "k1",
                "10.8.0.2",
                json!({"advertised_routes": ["192.168.1.0/24"]}),
            ),
            peer("phone", "k2", "10.8.0.3", json!({})),
        ];
        let rules = joined(&service(true).tunnel_policy("eth0", &clients));
        let allow_home = position(&rules, "-o wg0 -d 10.8.0.2/32 -j ACCEPT");
        let allow_route = position(&rules, "-o wg0 -d 192.168.1.0/24 -j ACCEPT");
        let allow_phone = position(&rules, "-o wg0 -d 10.8.0.3/32 -j ACCEPT");
        // Peers cannot reach each other or the internet through these rules, and the
        // internet cannot enter the tunnel, before any local traffic is accepted.
        assert!(position(&rules, "-i wg0 -o wg0 -j DROP") < allow_home);
        assert!(position(&rules, "-i eth0 -o wg0 -j DROP") < allow_home);
        assert!(allow_home < allow_route && allow_route < allow_phone);
        // Replies from peers are accepted but new connections from them are not.
        let replies = position(
            &rules,
            "-i wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        );
        assert!(replies < position(&rules, "-i wg0 -j DROP"));
        assert_eq!(rules.last().map(String::as_str), Some("-o wg0 -j DROP"));
    }

    #[test]
    fn a_peer_can_opt_out_of_server_access() {
        let clients = vec![
            peer("home", "k1", "10.8.0.2", json!({})),
            peer(
                "private",
                "k2",
                "10.8.0.3",
                json!({"local_access": false, "advertised_routes": ["10.99.0.0/24"]}),
            ),
        ];
        let rules = joined(&service(true).tunnel_policy("eth0", &clients));
        assert!(rules.contains(&"-o wg0 -d 10.8.0.2/32 -j ACCEPT".to_string()));
        assert!(!rules
            .iter()
            .any(|rule| rule.contains("10.8.0.3") || rule.contains("10.99.0.0")));
    }

    #[test]
    fn the_server_wide_setting_is_only_a_default() {
        let clients = vec![
            peer("home", "k1", "10.8.0.2", json!({})),
            peer(
                "proxy-target",
                "k2",
                "10.8.0.3",
                json!({"local_access": true}),
            ),
        ];
        let rules = joined(&service(false).tunnel_policy("eth0", &clients));
        assert!(!rules.iter().any(|rule| rule.contains("10.8.0.2")));
        assert!(rules.contains(&"-o wg0 -d 10.8.0.3/32 -j ACCEPT".to_string()));
        // With no peer allowed, everything into the tunnel is dropped.
        let none = joined(&service(false).tunnel_policy("eth0", &clients[..1]));
        assert!(none
            .iter()
            .all(|rule| !rule.contains("ACCEPT") || rule.contains("RELATED,ESTABLISHED")));
        assert_eq!(none.last().map(String::as_str), Some("-o wg0 -j DROP"));
    }
}
