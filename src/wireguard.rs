use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ipnet::Ipv4Net;
use serde_json::{json, Value};

use crate::config::Config;
use crate::error::AppError;
use crate::model::{may_receive_route, networks_overlap, next_available_ip, parse_cidr, Client};
use crate::runner::Runner;
use crate::storage::Storage;

#[derive(Clone, Debug, Default)]
pub struct PeerStatus {
    pub handshake: i64,
    pub online: bool,
    pub age: Option<i64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub struct WireGuardService {
    pub config: Arc<Config>,
    pub storage: Arc<dyn Storage>,
    pub runner: Arc<dyn Runner>,
}

impl WireGuardService {
    pub fn new(config: Arc<Config>, storage: Arc<dyn Storage>, runner: Arc<dyn Runner>) -> Self {
        Self {
            config,
            storage,
            runner,
        }
    }

    fn client_conf_path(&self, name: &str) -> String {
        self.config
            .clients_dir
            .join(format!("{name}.conf"))
            .to_string_lossy()
            .into_owned()
    }

    pub fn ensure_dirs(&self) {
        let _ = crate::storage::secure_directory(&self.config.data_dir);
        let _ = crate::storage::secure_directory(&self.config.clients_dir);
        if let Some(parent) = self.config.wg_config_path.parent() {
            let _ = crate::storage::secure_directory_if_safe(parent);
        }
        for path in [
            self.config.data_dir.join("server.privatekey"),
            self.config.data_dir.join("server.publickey"),
            self.config.data_dir.join(".secret_key"),
            self.config.sessions_file.clone(),
            self.config.clients_file.clone(),
            self.config.forward_file.clone(),
            self.config.wg_config_path.clone(),
        ] {
            crate::storage::normalize_private_file(&path);
        }
        if let Ok(entries) = std::fs::read_dir(&self.config.clients_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|value| value.to_str()) == Some("conf") {
                    crate::storage::normalize_private_file(&entry.path());
                }
            }
        }
    }

    pub fn ensure_server_keys(&self) -> Result<(String, String), AppError> {
        let private_path = self.config.data_dir.join("server.privatekey");
        let public_path = self.config.data_dir.join("server.publickey");
        let private_path_text = private_path.to_string_lossy().into_owned();
        let public_path_text = public_path.to_string_lossy().into_owned();
        if !self.storage.exists(&private_path_text) {
            let private = self
                .runner
                .run(&args(&["wg", "genkey"]), true, None)?
                .stdout
                .trim()
                .to_string();
            let public = self
                .runner
                .run(
                    &args(&["wg", "pubkey"]),
                    true,
                    Some(&format!("{private}\n")),
                )?
                .stdout
                .trim()
                .to_string();
            self.storage
                .write_text(&private_path_text, &format!("{private}\n"))?;
            self.storage
                .write_text(&public_path_text, &format!("{public}\n"))?;
            set_private_permissions(&private_path);
            set_private_permissions(&public_path);
        }
        crate::storage::normalize_private_file(&private_path);
        crate::storage::normalize_private_file(&public_path);
        let private = self
            .storage
            .read_text(&private_path_text)
            .unwrap_or_default()
            .trim()
            .to_string();
        let public = self
            .storage
            .read_text(&public_path_text)
            .unwrap_or_default()
            .trim()
            .to_string();
        Ok((private, public))
    }

    pub fn generate_keypair(&self) -> Result<(String, String), AppError> {
        let private = self
            .runner
            .run(&args(&["wg", "genkey"]), true, None)?
            .stdout
            .trim()
            .to_string();
        let public = self
            .runner
            .run(
                &args(&["wg", "pubkey"]),
                true,
                Some(&format!("{private}\n")),
            )?
            .stdout
            .trim()
            .to_string();
        Ok((private, public))
    }

    pub fn load_clients(&self) -> Vec<Client> {
        let raw = self
            .storage
            .load_json(&self.config.clients_file.to_string_lossy(), json!([]));
        let Value::Array(items) = raw else {
            return Vec::new();
        };
        items
            .into_iter()
            .filter_map(|item| serde_json::from_value::<Client>(item).ok())
            .filter(|client| client.address_ip().is_some())
            .collect()
    }

    pub fn save_clients(&self, clients: &[Client]) -> Result<(), AppError> {
        let payload = serde_json::to_value(clients).unwrap_or(Value::Array(Vec::new()));
        self.storage
            .save_json(&self.config.clients_file.to_string_lossy(), &payload)
    }

    pub fn render_client_config(
        &self,
        client: &Client,
        server_public: &str,
        clients: &[Client],
    ) -> String {
        let options = client.options();
        let mut routes: Vec<String> = Vec::new();
        if options.split_tunnel {
            routes.push(self.config.wg_network.to_string());
            for peer in clients {
                if peer.name == client.name {
                    continue;
                }
                for route in peer.options().advertised_routes {
                    if may_receive_route(client, peer, &route, clients) && !routes.contains(&route)
                    {
                        routes.push(route);
                    }
                }
            }
        } else {
            routes.push("0.0.0.0/0".to_string());
        }
        let mut lines: Vec<String> = vec![
            "[Interface]".to_string(),
            format!("PrivateKey = {}", client.private_key),
            format!("Address = {}/{}", client.address, self.config.wg_prefix_len),
        ];
        if !options.dns.is_empty() {
            lines.push(format!("DNS = {}", options.dns));
        }
        if let Some(mtu) = options.mtu {
            lines.push(format!("MTU = {mtu}"));
        }
        let mut host = self.config.wg_host.clone();
        if host.contains(':') && !host.starts_with('[') {
            host = format!("[{host}]");
        }
        lines.extend([
            String::new(),
            "[Peer]".to_string(),
            format!("PublicKey = {server_public}"),
            format!("Endpoint = {host}:{}", self.config.wg_port),
            format!("AllowedIPs = {}", routes.join(", ")),
            format!("PersistentKeepalive = {}", options.keepalive),
            String::new(),
        ]);
        lines.join("\n")
    }

    pub fn write_client_config(
        &self,
        client: &Client,
        server_public: &str,
        clients: &[Client],
    ) -> Result<String, AppError> {
        let content = self.render_client_config(client, server_public, clients);
        let path = self.client_conf_path(&client.name);
        self.storage.write_text(&path, &content)?;
        set_private_permissions(std::path::Path::new(&path));
        Ok(path)
    }

    pub fn next_available_ip(&self, clients: &[Client]) -> Result<Ipv4Addr, AppError> {
        next_available_ip(self.config.wg_network, self.config.wg_address, clients).ok_or_else(
            || AppError::runtime("No free client addresses remain in the configured network."),
        )
    }

    pub fn render_wireguard_config(
        &self,
        clients: &[Client],
        server_private: &str,
    ) -> Result<(), AppError> {
        let mut lines = vec![
            "[Interface]".to_string(),
            format!("Address = {}", self.config.wg_address_cidr()),
            format!("ListenPort = {}", self.config.wg_port),
            format!("PrivateKey = {server_private}"),
            "SaveConfig = false".to_string(),
            String::new(),
        ];
        for client in clients {
            let mut allowed = vec![format!("{}/32", client.address)];
            allowed.extend(client.options().advertised_routes);
            lines.extend([
                "[Peer]".to_string(),
                format!("PublicKey = {}", client.public_key),
                format!("AllowedIPs = {}", allowed.join(", ")),
                String::new(),
            ]);
        }
        let path = self.config.wg_config_path.to_string_lossy().into_owned();
        self.storage.write_text(&path, &lines.join("\n"))?;
        set_private_permissions(&self.config.wg_config_path);
        Ok(())
    }

    pub fn log_wireguard_status(&self) {
        if let Ok(status) = self.runner.run(&args(&["wg", "show"]), false, None) {
            let payload = if status.stdout.is_empty() {
                status.stderr
            } else {
                status.stdout
            };
            if !payload.trim().is_empty() {
                tracing::info!("WireGuard status:\n{}", payload.trim());
            }
        }
    }

    pub fn bounce_interface(&self) -> Result<(), AppError> {
        let path = self.config.wg_config_path.to_string_lossy().into_owned();
        let _ = self
            .runner
            .run(&args(&["wg-quick", "down", &path]), false, None);
        self.runner
            .run(&args(&["wg-quick", "up", &path]), true, None)?;
        if self.config.enable_ipv4_forwarding {
            self.runner.run(
                &args(&["sysctl", "-w", "net.ipv4.ip_forward=1"]),
                true,
                None,
            )?;
        }
        self.log_wireguard_status();
        Ok(())
    }

    pub fn seamless_reload(&self) -> Result<(), AppError> {
        let path = self.config.wg_config_path.to_string_lossy().into_owned();
        let result = (|| -> Result<(), AppError> {
            let stripped = self
                .runner
                .run(&args(&["wg-quick", "strip", &path]), true, None)?
                .stdout;
            self.runner.run(
                &args(&["wg", "syncconf", &self.config.wg_interface, "/dev/stdin"]),
                true,
                Some(&stripped),
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.log_wireguard_status();
                Ok(())
            }
            Err(error) => {
                tracing::warn!("Seamless reload failed ({error}), falling back to bounce");
                self.bounce_interface()
            }
        }
    }

    pub fn refresh_wireguard(&self, clients: &[Client]) -> Result<(), AppError> {
        let (server_private, _) = self.ensure_server_keys()?;
        self.render_wireguard_config(clients, &server_private)?;
        self.seamless_reload()?;
        tracing::info!("Reloaded WireGuard with {} clients", clients.len());
        Ok(())
    }

    pub fn check_local_routes(&self, routes: &[String]) -> Result<(), AppError> {
        if routes.is_empty() {
            return Ok(());
        }
        let output = self
            .runner
            .run(
                &args(&["ip", "-j", "-4", "route", "show", "table", "all"]),
                true,
                None,
            )?
            .stdout;
        let entries: Value = serde_json::from_str(&output)
            .map_err(|_| AppError::runtime("Unable to read server IPv4 routes."))?;
        let Value::Array(entries) = entries else {
            return Err(AppError::runtime("Unable to read server IPv4 routes."));
        };
        let mut local: Vec<Ipv4Net> = Vec::new();
        for entry in entries {
            let Some(object) = entry.as_object() else {
                continue;
            };
            let destination = object.get("dst").and_then(Value::as_str).unwrap_or("");
            if destination.is_empty() || destination == "default" {
                continue;
            }
            if object.get("dev").and_then(Value::as_str) == Some(self.config.wg_interface.as_str())
            {
                continue;
            }
            if let Ok(network) = parse_cidr(destination) {
                local.push(network);
            }
        }
        for route in routes {
            let route = parse_cidr(route)
                .map_err(|_| AppError::validation(format!("Invalid route: {route}")))?;
            if local
                .iter()
                .any(|existing| networks_overlap(route, *existing))
            {
                return Err(AppError::validation(format!(
                    "Advertised route overlaps a server route: {route}"
                )));
            }
        }
        Ok(())
    }

    pub fn replace_routes(&self, previous: &[Client], clients: &[Client]) -> Result<(), AppError> {
        let (server_private, _) = self.ensure_server_keys()?;
        let path = self.config.wg_config_path.to_string_lossy().into_owned();
        self.runner
            .run(&args(&["wg-quick", "down", &path]), true, None)?;
        let result = (|| -> Result<(), AppError> {
            self.render_wireguard_config(clients, &server_private)?;
            self.runner
                .run(&args(&["wg-quick", "up", &path]), true, None)?;
            Ok(())
        })();
        if let Err(error) = result {
            let restore = (|| -> Result<(), AppError> {
                self.render_wireguard_config(previous, &server_private)?;
                self.runner
                    .run(&args(&["wg-quick", "up", &path]), true, None)?;
                Ok(())
            })();
            if let Err(restore_error) = restore {
                tracing::error!(
                    "Could not restore the previous WireGuard configuration: {restore_error}"
                );
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn peer_status_map(&self) -> BTreeMap<String, PeerStatus> {
        let mut status = BTreeMap::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);

        let mut transfer: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        if let Ok(result) = self.runner.run(
            &args(&["wg", "show", &self.config.wg_interface, "transfer"]),
            false,
            None,
        ) {
            if result.returncode == 0 {
                for line in result.stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if let (Ok(rx), Ok(tx)) = (parts[1].parse::<u64>(), parts[2].parse::<u64>())
                        {
                            transfer.insert(parts[0].to_string(), (rx, tx));
                        }
                    }
                }
            }
        }

        let Ok(result) = self.runner.run(
            &args(&["wg", "show", &self.config.wg_interface, "latest-handshakes"]),
            false,
            None,
        ) else {
            return status;
        };
        if result.returncode != 0 {
            return status;
        }
        for line in result.stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let timestamp = parts[1].parse::<i64>().unwrap_or(0);
            let online = timestamp > 0 && (now - timestamp) < 180;
            let (rx, tx) = transfer.get(parts[0]).copied().unwrap_or((0, 0));
            status.insert(
                parts[0].to_string(),
                PeerStatus {
                    handshake: timestamp,
                    online,
                    age: if timestamp > 0 {
                        Some(now - timestamp)
                    } else {
                        None
                    },
                    rx_bytes: rx,
                    tx_bytes: tx,
                },
            );
        }
        status
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn set_private_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }
}
