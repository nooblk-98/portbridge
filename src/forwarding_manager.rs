use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::config::Config;
use crate::error::AppError;
use crate::iptables::IPTablesService;
use crate::rule_renderer::{parse_ipv4_network_lenient, protocols_overlap};
use crate::storage::Storage;

pub struct ForwardingManager {
    pub ipt: Arc<IPTablesService>,
    pub storage: Arc<dyn Storage>,
    pub config: Arc<Config>,
}

impl ForwardingManager {
    pub fn new(ipt: Arc<IPTablesService>, storage: Arc<dyn Storage>, config: Arc<Config>) -> Self {
        Self {
            ipt,
            storage,
            config,
        }
    }

    pub fn list_rules(&self) -> Vec<Value> {
        let rules = self.ipt.load_forwardings(None);
        let owners = self.owners();
        rules
            .into_iter()
            .filter(|rule| {
                let peer_key = rule
                    .get("peer_public_key")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if peer_key.is_empty() {
                    return false;
                }
                let client_ip = rule.get("client_ip").and_then(Value::as_str).unwrap_or("");
                owners.get(client_ip).map(String::as_str) == Some(peer_key)
            })
            .collect()
    }

    fn owners(&self) -> BTreeMap<String, String> {
        let raw = self
            .storage
            .load_json(&self.config.clients_file.to_string_lossy(), json!([]));
        raw.as_array()
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
            .unwrap_or_default()
    }

    pub fn add_rule(&self, data: &Map<String, Value>) -> Result<Value, AppError> {
        let port_raw = data.get("port").filter(|value| !value.is_null());
        let port_text = match port_raw {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) => number.to_string(),
            _ => {
                return Err(AppError::validation(
                    "Port must be numeric or range (e.g. 8000-8100).",
                ))
            }
        };
        let port: Value = if port_text.contains('-') {
            let parts: Vec<&str> = port_text.split('-').collect();
            if parts.len() != 2 {
                return Err(AppError::validation(
                    "Port must be numeric or range (e.g. 8000-8100).",
                ));
            }
            let start = parts[0].parse::<u16>().map_err(|_| {
                AppError::validation("Port must be numeric or range (e.g. 8000-8100).")
            })?;
            let end = parts[1].parse::<u16>().map_err(|_| {
                AppError::validation("Port must be numeric or range (e.g. 8000-8100).")
            })?;
            if start >= end {
                return Err(AppError::validation("Invalid port range."));
            }
            Value::String(port_text.clone())
        } else {
            let port = port_text.parse::<u16>().map_err(|_| {
                AppError::validation("Port must be numeric or range (e.g. 8000-8100).")
            })?;
            Value::from(port)
        };

        let protocol = data
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("both")
            .to_lowercase();
        if !matches!(protocol.as_str(), "tcp" | "udp" | "both") {
            return Err(AppError::validation("Protocol must be tcp, udp, or both."));
        }

        let client_ip_raw = data
            .get("client_ip")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("client_ip is required."))?;
        let client_ip: Ipv4Addr = client_ip_raw
            .parse()
            .map_err(|_| AppError::validation("Invalid client_ip."))?;

        let source_ip = match data.get("source_ip").and_then(Value::as_str) {
            Some(value) if !value.trim().is_empty() => Some(
                parse_ipv4_network_lenient(value)
                    .ok_or_else(|| AppError::validation("Invalid IPv4 source IP/CIDR."))?
                    .to_string(),
            ),
            _ => None,
        };

        let target_port_value = data
            .get("target_port")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| port.clone());
        let target_port = match target_port_value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.parse::<i64>().ok(),
            _ => None,
        }
        .ok_or_else(|| AppError::validation("target_port must be numeric."))?;

        if !self.config.wg_network.contains(&client_ip) {
            return Err(AppError::validation("client_ip outside WireGuard network."));
        }

        let owners = self.owners();
        let owner = owners
            .get(&client_ip.to_string())
            .cloned()
            .ok_or_else(|| AppError::validation("Select an existing WireGuard peer."))?;

        let reserved = [self.config.wg_port, self.config.app_port];
        let conflict_reserved = match &port {
            Value::String(text) => {
                let parts: Vec<&str> = text.split('-').collect();
                let start = parts[0].parse::<u16>().unwrap_or(0);
                let end = parts[1].parse::<u16>().unwrap_or(0);
                reserved.iter().any(|port| start <= *port && *port <= end)
            }
            Value::Number(number) => number
                .as_u64()
                .is_some_and(|port| reserved.iter().any(|reserved| u64::from(*reserved) == port)),
            _ => false,
        };
        if conflict_reserved {
            return Err(AppError::validation(format!(
                "Cannot forward reserved system ports ({}).",
                reserved
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        let client_ip_text = client_ip.to_string();
        for rule in self.list_rules() {
            let existing_port = rule
                .get("port")
                .map(port_string)
                .unwrap_or_else(|| "-1".to_string());
            let existing_proto = rule
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("both");
            if existing_port == port_string(&port)
                && protocols_overlap(existing_proto, &protocol)
                && rule.get("client_ip").and_then(Value::as_str) != Some(client_ip_text.as_str())
            {
                return Err(AppError::validation(
                    "Port is already in use by another client.",
                ));
            }
        }

        let mut rules = self.ipt.load_forwardings(None);
        rules.retain(|rule| {
            let same_port = rule
                .get("port")
                .map(port_string)
                .unwrap_or_else(|| "-1".to_string())
                == port_string(&port);
            let same_protocol = rule
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("both")
                == protocol;
            !(same_port && same_protocol)
        });
        rules.push(json!({
            "port": port,
            "protocol": protocol,
            "client_ip": client_ip.to_string(),
            "peer_public_key": owner,
            "target_port": target_port,
            "source_ip": source_ip,
        }));
        self.storage.save_json(
            &self.config.forward_file.to_string_lossy(),
            &Value::Array(rules.clone()),
        )?;
        self.ipt.apply_forwardings(&rules)?;
        Ok(json!({
            "port": port,
            "protocol": protocol,
            "client_ip": client_ip.to_string(),
            "target_port": target_port,
        }))
    }

    pub fn remove_rule(&self, port: &str, protocol: &str) -> Result<Value, AppError> {
        let protocol = protocol.to_lowercase();
        let rules = self.ipt.load_forwardings(None);
        let mut updated = Vec::new();
        let mut removed = false;
        for rule in rules {
            let same_port = rule
                .get("port")
                .map(port_string)
                .unwrap_or_else(|| "-1".to_string())
                == port;
            let same_protocol = rule
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("both")
                == protocol;
            if same_port && same_protocol {
                removed = true;
            } else {
                updated.push(rule);
            }
        }
        if !removed {
            return Err(AppError::not_found("Forwarding rule not found."));
        }
        self.storage.save_json(
            &self.config.forward_file.to_string_lossy(),
            &Value::Array(updated.clone()),
        )?;
        self.ipt.apply_forwardings(&updated)?;
        Ok(json!({"removed": {"port": port, "protocol": protocol}}))
    }

    pub fn seed_if_empty(&self, default_client_ip: &str) -> Result<(), AppError> {
        let rules = self.ipt.load_forwardings(None);
        if !rules.is_empty() {
            return Ok(());
        }
        if let Some(owner) = self.owners().get(default_client_ip) {
            let seed = vec![json!({
                "port": 30000,
                "protocol": "both",
                "client_ip": default_client_ip,
                "peer_public_key": owner,
                "target_port": 8080,
            })];
            self.storage.save_json(
                &self.config.forward_file.to_string_lossy(),
                &Value::Array(seed),
            )?;
        }
        Ok(())
    }

    pub fn apply_all(&self) -> Result<(), AppError> {
        let rules = self.ipt.load_forwardings(None);
        self.ipt.apply_forwardings(&rules)
    }
}

fn port_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}
