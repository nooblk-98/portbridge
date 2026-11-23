use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IptablesCommand {
    pub table: String,
    pub args: Vec<String>,
}

fn arg(value: impl Into<String>) -> String {
    value.into()
}

pub fn parse_ipv4_network_lenient(value: &str) -> Option<Ipv4Net> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((address, prefix)) = trimmed.split_once('/') {
        let address: Ipv4Addr = address.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        Ipv4Net::new(address, prefix).ok()
    } else {
        let address: Ipv4Addr = trimmed.parse().ok()?;
        Ipv4Net::new(address, 32).ok()
    }
}

/// Translate a stored forwarding rule into iptables arguments.
pub fn render_rule(rule: &Value, ext_iface: &str) -> Vec<IptablesCommand> {
    let Some(object) = rule.as_object() else {
        return Vec::new();
    };
    let port_value = object.get("port");
    let port_text = match port_value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => {
            tracing::error!("Skipping invalid rule {rule}: missing port");
            return Vec::new();
        }
    };
    let is_range = port_text.contains('-');
    let (start_port, end_port, dport_arg) = if is_range {
        let parts: Vec<&str> = port_text.split('-').collect();
        if parts.len() != 2 {
            tracing::error!("Skipping invalid rule {rule}: invalid range");
            return Vec::new();
        }
        let Ok(start) = parts[0].parse::<u16>() else {
            tracing::error!("Skipping invalid rule {rule}: invalid range");
            return Vec::new();
        };
        let Ok(end) = parts[1].parse::<u16>() else {
            tracing::error!("Skipping invalid rule {rule}: invalid range");
            return Vec::new();
        };
        (start, end, format!("{start}:{end}"))
    } else {
        let Ok(port) = port_text.parse::<u16>() else {
            tracing::error!("Skipping invalid rule {rule}: invalid port");
            return Vec::new();
        };
        (port, port, port.to_string())
    };
    let protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("both")
        .to_lowercase();
    if !matches!(protocol.as_str(), "tcp" | "udp" | "both") {
        return Vec::new();
    }
    let Some(client_ip_text) = object.get("client_ip").and_then(Value::as_str) else {
        tracing::error!("Skipping invalid rule {rule}: missing client_ip");
        return Vec::new();
    };
    let Ok(client_ip) = client_ip_text.parse::<Ipv4Addr>() else {
        tracing::error!("Skipping invalid rule {rule}: invalid client_ip");
        return Vec::new();
    };

    let (to_dest, dest_port_arg) = if is_range {
        (
            format!("{client_ip}:{start_port}-{end_port}"),
            dport_arg.clone(),
        )
    } else {
        let target_port = match object.get("target_port") {
            Some(Value::Number(number)) => number.as_i64(),
            Some(Value::String(text)) => text.parse::<i64>().ok(),
            _ => Some(start_port as i64),
        };
        let Some(target_port) = target_port else {
            tracing::error!("Skipping invalid rule {rule}: invalid target_port");
            return Vec::new();
        };
        (
            format!("{client_ip}:{target_port}"),
            target_port.to_string(),
        )
    };

    let source_ip = object
        .get("source_ip")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let source_ip = if source_ip.is_empty() {
        None
    } else {
        match parse_ipv4_network_lenient(&source_ip) {
            Some(network) => Some(network.to_string()),
            None => {
                tracing::error!("Skipping invalid rule {rule}: invalid source_ip");
                return Vec::new();
            }
        }
    };

    let protocols: Vec<&str> = if protocol == "both" {
        vec!["tcp", "udp"]
    } else {
        vec![protocol.as_str()]
    };
    let mut commands = Vec::new();
    for name in protocols {
        let mut dnat_args = vec![
            arg("-i"),
            arg(ext_iface),
            arg("-p"),
            arg(name),
            arg("--dport"),
            arg(dport_arg.clone()),
            arg("-j"),
            arg("DNAT"),
            arg("--to-destination"),
            arg(to_dest.clone()),
        ];
        if let Some(source) = &source_ip {
            dnat_args.push(arg("-s"));
            dnat_args.push(arg(source.clone()));
        }
        commands.push(IptablesCommand {
            table: "nat".to_string(),
            args: dnat_args,
        });

        let mut filter_args = vec![
            arg("-p"),
            arg(name),
            arg("-d"),
            arg(client_ip.to_string()),
            arg("--dport"),
            arg(dest_port_arg.clone()),
            arg("-m"),
            arg("conntrack"),
            arg("--ctorigdstport"),
            arg(dport_arg.clone()),
            arg("-j"),
            arg("ACCEPT"),
        ];
        if let Some(source) = &source_ip {
            filter_args.push(arg("-s"));
            filter_args.push(arg(source.clone()));
        }
        commands.push(IptablesCommand {
            table: "filter".to_string(),
            args: filter_args,
        });
    }
    commands
}

pub fn protocols_overlap(existing: &str, new: &str) -> bool {
    let existing = existing.to_lowercase();
    let new = new.to_lowercase();
    existing == "both" || new == "both" || existing == new
}
