use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ipnet::Ipv4Net;
use regex::Regex;
use serde_json::{json, Value};

use crate::config::Config;
use crate::error::AppError;
use crate::model::{allowed_recipient_addresses, parse_cidr, validated_peers, Client};
use crate::rule_renderer::render_rule;
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
            if !iface.is_empty() {
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
        let raw = self
            .storage
            .load_json(&self.config.clients_file.to_string_lossy(), json!([]));
        let clients: Vec<Client> = raw
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| serde_json::from_value::<Client>(item.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
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

    pub fn apply_forwardings(&self, rules: &[Value]) -> Result<(), AppError> {
        let _guard = self.lock.lock().expect("iptables lock");
        let ext_iface = self.detect_primary_interface()?;
        let interface = self.config.wg_interface.clone();
        let network = self.config.wg_network.to_string();
        let raw = self
            .storage
            .load_json(&self.config.clients_file.to_string_lossy(), json!([]));
        let owners: BTreeMap<String, String> = raw
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|client| {
                        let address = client.get("address")?.as_str()?.to_string();
                        let key = client.get("public_key")?.as_str()?.to_string();
                        Some((address, key))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let active: Vec<&Value> = rules
            .iter()
            .filter(|rule| {
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
        policy.extend(self.routing_rules(&ext_iface)?);
        policy.push(vec![
            "-i".to_string(),
            interface.clone(),
            "-j".to_string(),
            "DROP".to_string(),
        ]);
        policy.push(vec![
            "-o".to_string(),
            interface.clone(),
            "-j".to_string(),
            "DROP".to_string(),
        ]);
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
