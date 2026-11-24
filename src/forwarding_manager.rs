use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::config::Config;
use crate::error::AppError;
use crate::iptables::IPTablesService;
use crate::rule_renderer::{parse_ipv4_network_lenient, protocols_overlap, rule_is_valid};
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

    pub fn list_rules(&self) -> Result<Vec<Value>, AppError> {
        let rules = self.ipt.load_forwardings()?;
        let owners = self.owners()?;
        Ok(rules
            .into_iter()
            .filter(|rule| {
                if !rule_is_valid(rule) {
                    return false;
                }
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
            .collect())
    }

    fn owners(&self) -> Result<BTreeMap<String, String>, AppError> {
        let clients = crate::model::load_clients(
            self.storage.as_ref(),
            &self.config.clients_file.to_string_lossy(),
        )?;
        Ok(clients
            .into_iter()
            .map(|client| (client.address, client.public_key))
            .collect())
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
            let (start, end) = port_text.split_once('-').ok_or_else(|| {
                AppError::validation("Port must be numeric or range (e.g. 8000-8100).")
            })?;
            if end.contains('-') {
                return Err(AppError::validation(
                    "Port must be numeric or range (e.g. 8000-8100).",
                ));
            }
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start >= end {
                return Err(AppError::validation("Invalid port range."));
            }
            Value::String(format!("{start}-{end}"))
        } else {
            Value::from(parse_port(&port_text)?)
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

        let target_port = match data.get("target_port").filter(|value| {
            !value.is_null() && !value.as_str().is_some_and(|text| text.trim().is_empty())
        }) {
            None => port.as_u64().map(|value| value as u16),
            Some(Value::Number(number)) => Some(parse_port(&number.to_string())?),
            Some(Value::String(text)) => Some(parse_port(text.trim())?),
            _ => return Err(AppError::validation("target_port must be numeric.")),
        };

        if !self.config.wg_network.contains(&client_ip) {
            return Err(AppError::validation("client_ip outside WireGuard network."));
        }

        let owners = self.owners()?;
        let owner = owners
            .get(&client_ip.to_string())
            .cloned()
            .ok_or_else(|| AppError::validation("Select an existing WireGuard peer."))?;

        let reserved = [self.config.wg_port, self.config.app_port];
        let conflict_reserved = match &port {
            Value::String(text) => {
                let (start, end) = text.split_once('-').expect("validated range");
                let start = start.parse::<u16>().unwrap_or(0);
                let end = end.parse::<u16>().unwrap_or(0);
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
        for rule in self.list_rules()? {
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

        let previous = self.ipt.load_forwardings()?;
        let mut rules = previous.clone();
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
        self.replace_and_apply(&previous, &rules)?;
        Ok(json!({
            "port": port,
            "protocol": protocol,
            "client_ip": client_ip.to_string(),
            "target_port": target_port,
        }))
    }

    pub fn remove_rule(&self, port: &str, protocol: &str) -> Result<Value, AppError> {
        let protocol = protocol.to_lowercase();
        let previous = self.ipt.load_forwardings()?;
        let mut updated = Vec::new();
        let mut removed = false;
        for rule in &previous {
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
                updated.push(rule.clone());
            }
        }
        if !removed {
            return Err(AppError::not_found("Forwarding rule not found."));
        }
        self.replace_and_apply(&previous, &updated)?;
        Ok(json!({"removed": {"port": port, "protocol": protocol}}))
    }

    pub fn seed_if_empty(&self, default_client_ip: &str) -> Result<(), AppError> {
        let rules = self.ipt.load_forwardings()?;
        if !rules.is_empty() {
            return Ok(());
        }
        if let Some(owner) = self.owners()?.get(default_client_ip) {
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
        let rules = self.ipt.load_forwardings()?;
        self.ipt.apply_forwardings(&rules)
    }

    fn replace_and_apply(&self, previous: &[Value], next: &[Value]) -> Result<(), AppError> {
        let path = self.config.forward_file.to_string_lossy();
        self.storage
            .save_json(&path, &Value::Array(next.to_vec()))?;
        if let Err(error) = self.ipt.apply_forwardings(next) {
            if let Err(rollback) = self
                .storage
                .save_json(&path, &Value::Array(previous.to_vec()))
            {
                tracing::error!("Could not restore the previous forwarding rules: {rollback}");
            }
            if let Err(rollback) = self.ipt.apply_forwardings(previous) {
                tracing::error!("Could not restore the previous firewall policy: {rollback}");
            }
            return Err(error);
        }
        Ok(())
    }
}

fn parse_port(value: &str) -> Result<u16, AppError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| (1..=65535).contains(port))
        .ok_or_else(|| AppError::validation("Port must be between 1 and 65535 (or a valid range)."))
}

fn port_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::FakeRunner;
    use crate::storage::InMemoryStorage;

    #[test]
    fn forwarding_operations_preserve_an_invalid_rules_file() {
        let config = Arc::new(Config::for_test(std::env::temp_dir()));
        let storage = Arc::new(InMemoryStorage::new());
        let services = crate::build_services_with(
            config.clone(),
            storage.clone(),
            Arc::new(FakeRunner::new()),
        );
        let manager = &services.forwarding_manager;
        let path = config.forward_file.to_str().unwrap();
        assert!(manager.list_rules().unwrap().is_empty());
        assert!(!storage.exists(path));

        for invalid in ["{ broken", "{}"] {
            storage.write_text(path, invalid).unwrap();
            assert!(manager.list_rules().is_err());
            assert!(manager.remove_rule("30000", "tcp").is_err());
            assert!(manager.seed_if_empty("10.8.0.2").is_err());
            assert!(manager.apply_all().is_err());
            assert_eq!(storage.read_text(path).as_deref(), Some(invalid));
        }
    }

    #[test]
    fn add_forwarding_accepts_blank_and_explicit_internal_ports() {
        let config = Arc::new(Config::for_test(std::env::temp_dir()));
        let storage = Arc::new(InMemoryStorage::new());
        let services = crate::build_services_with(
            config.clone(),
            storage.clone(),
            Arc::new(FakeRunner::new()),
        );
        storage.save_json(config.clients_file.to_str().unwrap(), &json!([{
            "name": "home", "address": "10.8.0.2", "private_key": "private", "public_key": "public"
        }])).unwrap();
        let manager = &services.forwarding_manager;

        for (public, internal, expected) in [
            (json!(8000), json!(""), json!(8000)),
            (json!("8001-8002"), json!(""), Value::Null),
            (json!("8003-8004"), json!(8080), json!(8080)),
        ] {
            let data = json!({"port": public, "target_port": internal, "client_ip": "10.8.0.2"});
            let rule = manager.add_rule(data.as_object().unwrap()).unwrap();
            assert_eq!(rule["target_port"], expected);
        }
        assert_eq!(manager.list_rules().unwrap().len(), 3);
    }
}
