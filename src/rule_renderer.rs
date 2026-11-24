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

struct ParsedRule {
    protocol: String,
    dport_arg: String,
    client_ip: Ipv4Addr,
    target_port: Option<u16>,
    source_ip: Option<String>,
}

fn parse_port(value: &str) -> Option<u16> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| (1..=65535).contains(port))
}

fn parse_rule(rule: &Value) -> Option<ParsedRule> {
    let object = rule.as_object()?;
    let port_text = match object.get("port") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => return None,
    };
    let is_range = port_text.contains('-');
    let (start_port, dport_arg) = if is_range {
        let (start, end) = port_text.split_once('-')?;
        if end.contains('-') {
            return None;
        }
        let start = parse_port(start)?;
        let end = parse_port(end)?;
        if start >= end {
            return None;
        }
        (start, format!("{start}:{end}"))
    } else {
        let port = parse_port(&port_text)?;
        (port, port.to_string())
    };
    let protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("both")
        .to_lowercase();
    if !matches!(protocol.as_str(), "tcp" | "udp" | "both") {
        return None;
    }
    let client_ip = object
        .get("client_ip")?
        .as_str()?
        .parse::<Ipv4Addr>()
        .ok()?;
    let target_supplied = object
        .get("target_port")
        .is_some_and(|value| !value.is_null());
    let target_port = match object.get("target_port") {
        None | Some(Value::Null) => {
            if is_range {
                None
            } else {
                Some(start_port)
            }
        }
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|port| (1..=65535).contains(port)),
        Some(Value::String(text)) => parse_port(text),
        _ => None,
    };
    if (target_supplied || !is_range) && target_port.is_none() {
        return None;
    }
    let source_ip = object
        .get("source_ip")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let source_ip = if source_ip.is_empty() {
        None
    } else {
        Some(parse_ipv4_network_lenient(&source_ip)?.to_string())
    };

    Some(ParsedRule {
        protocol,
        dport_arg,
        client_ip,
        target_port,
        source_ip,
    })
}

/// Whether a stored forwarding rule is safe to render and expose.
pub fn rule_is_valid(rule: &Value) -> bool {
    parse_rule(rule).is_some()
}

/// Translate a stored forwarding rule into iptables arguments.
pub fn render_rule(rule: &Value, ext_iface: &str) -> Vec<IptablesCommand> {
    let Some(parsed) = parse_rule(rule) else {
        tracing::error!("Skipping invalid forwarding rule");
        return Vec::new();
    };
    let (to_dest, dest_port_arg) = if let Some(target_port) = parsed.target_port {
        (
            format!("{}:{target_port}", parsed.client_ip),
            target_port.to_string(),
        )
    } else {
        (parsed.client_ip.to_string(), parsed.dport_arg.clone())
    };

    let protocols: Vec<&str> = if parsed.protocol == "both" {
        vec!["tcp", "udp"]
    } else {
        vec![parsed.protocol.as_str()]
    };
    let mut commands = Vec::new();
    for name in protocols {
        let mut dnat_args = vec![
            arg("-i"),
            arg(ext_iface),
            arg("-p"),
            arg(name),
            arg("--dport"),
            arg(parsed.dport_arg.clone()),
            arg("-j"),
            arg("DNAT"),
            arg("--to-destination"),
            arg(to_dest.clone()),
        ];
        if let Some(source) = &parsed.source_ip {
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
            arg(parsed.client_ip.to_string()),
            arg("--dport"),
            arg(dest_port_arg.clone()),
            arg("-m"),
            arg("conntrack"),
            arg("--ctorigdstport"),
            arg(parsed.dport_arg.clone()),
            arg("-j"),
            arg("ACCEPT"),
        ];
        if let Some(source) = &parsed.source_ip {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn joined(command: &IptablesCommand) -> String {
        format!("{} {}", command.table, command.args.join(" "))
    }

    #[test]
    fn renders_single_tcp_rule() {
        let rule =
            json!({"port": 8080, "protocol": "tcp", "client_ip": "10.8.0.2", "target_port": 80});
        let commands = render_rule(&rule, "eth0");
        assert_eq!(commands.len(), 2);
        assert_eq!(
            joined(&commands[0]),
            "nat -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 10.8.0.2:80"
        );
        assert_eq!(commands[1].table, "filter");
        assert!(joined(&commands[1]).contains("-d 10.8.0.2 --dport 80"));
    }

    #[test]
    fn both_protocol_renders_tcp_and_udp() {
        let rule = json!({"port": "53", "protocol": "both", "client_ip": "10.8.0.3"});
        let commands = render_rule(&rule, "eth0");
        assert_eq!(commands.len(), 4);
        assert!(joined(&commands[0]).contains("-p tcp"));
        assert!(joined(&commands[2]).contains("-p udp"));
        // The target port defaults to the public port.
        assert!(joined(&commands[0]).ends_with("10.8.0.3:53"));
    }

    #[test]
    fn source_restriction_is_applied_to_both_chains() {
        let rule = json!({"port": 22, "protocol": "tcp", "client_ip": "10.8.0.4", "source_ip": "203.0.113.0/24"});
        let commands = render_rule(&rule, "eth0");
        assert!(commands
            .iter()
            .all(|c| c.args.join(" ").contains("-s 203.0.113.0/24")));
    }

    #[test]
    fn port_ranges_need_ordered_bounds() {
        let ok = json!({"port": "30000-30010", "protocol": "udp", "client_ip": "10.8.0.5"});
        assert!(rule_is_valid(&ok));
        assert!(joined(&render_rule(&ok, "eth0")[0]).contains("--dport 30000:30010"));
        let reversed = json!({"port": "30010-30000", "client_ip": "10.8.0.5"});
        assert!(!rule_is_valid(&reversed));
    }

    #[test]
    fn ranges_preserve_public_ports_or_forward_to_the_explicit_target() {
        let mut rule = json!({"port": "30000-30010", "protocol": "tcp", "client_ip": "10.8.0.5"});
        let commands = render_rule(&rule, "eth0");
        assert!(joined(&commands[0]).ends_with("--to-destination 10.8.0.5"));
        assert!(joined(&commands[1]).contains("--dport 30000:30010"));

        rule["target_port"] = json!(8080);
        let commands = render_rule(&rule, "eth0");
        assert!(joined(&commands[0]).ends_with("--to-destination 10.8.0.5:8080"));
        assert!(
            joined(&commands[1]).contains("--dport 8080 -m conntrack --ctorigdstport 30000:30010")
        );
    }

    #[test]
    fn invalid_rules_render_nothing() {
        for rule in [
            json!({"port": 0, "client_ip": "10.8.0.2"}),
            json!({"port": 80, "protocol": "icmp", "client_ip": "10.8.0.2"}),
            json!({"port": 80, "client_ip": "not-an-ip"}),
            json!({"port": 80, "client_ip": "10.8.0.2", "source_ip": "bogus"}),
            json!({"client_ip": "10.8.0.2"}),
        ] {
            assert!(!rule_is_valid(&rule), "{rule}");
            assert!(render_rule(&rule, "eth0").is_empty(), "{rule}");
        }
    }

    #[test]
    fn protocol_overlap_rules() {
        assert!(protocols_overlap("tcp", "TCP"));
        assert!(protocols_overlap("both", "udp"));
        assert!(!protocols_overlap("tcp", "udp"));
    }

    #[test]
    fn lenient_network_parsing() {
        assert_eq!(
            parse_ipv4_network_lenient(" 192.0.2.1 ").map(|n| n.to_string()),
            Some("192.0.2.1/32".to_string())
        );
        assert!(parse_ipv4_network_lenient("").is_none());
        assert!(parse_ipv4_network_lenient("10.0.0.0/33").is_none());
    }
}
