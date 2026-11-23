use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::sha256_hex;
use crate::config::Config;
use crate::error::AppError;
use crate::forwarding_manager::ForwardingManager;
use crate::model::{allowed_recipient_keys, validate_options, Client};
use crate::storage::Storage;
use crate::wireguard::WireGuardService;
use regex::Regex;
use serde_json::{json, Map, Value};

pub struct ClientManager {
    pub wg: Arc<WireGuardService>,
    pub storage: Arc<dyn Storage>,
    pub config: Arc<Config>,
    pub fwd: Arc<ForwardingManager>,
    lock: Mutex<()>,
}

impl ClientManager {
    pub fn new(
        wg: Arc<WireGuardService>,
        storage: Arc<dyn Storage>,
        config: Arc<Config>,
        fwd: Arc<ForwardingManager>,
    ) -> Self {
        Self {
            wg,
            storage,
            config,
            fwd,
            lock: Mutex::new(()),
        }
    }

    pub fn list_clients(&self) -> Result<Value, AppError> {
        let _guard = self.lock.lock().expect("client lock");
        self.list_clients_locked()
    }

    fn list_clients_locked(&self) -> Result<Value, AppError> {
        let server_public = self.wg.ensure_server_keys()?.1;
        let clients = self.wg.load_clients();
        let forwardings = self.fwd.list_rules();
        let status = self.wg.peer_status_map();
        let exports = self.load_profile_exports();
        let mut items = Vec::new();
        let mut routes = Vec::new();
        let mut profiles = Vec::new();
        for client in &clients {
            let forwards: Vec<Value> = forwardings
                .iter()
                .filter(|rule| {
                    rule.get("client_ip").and_then(Value::as_str) == Some(client.address.as_str())
                })
                .cloned()
                .collect();
            let peer_state = status.get(&client.public_key);
            let options = client.options();
            items.push(json!({
                "name": client.name,
                "address": format!("{}/{}", client.address, self.config.wg_prefix_len),
                "public_key": client.public_key,
                "config": format!("/clients/{}.conf", client.name),
                "online": peer_state.is_some_and(|state| state.online),
                "last_handshake": peer_state.map(|state| state.handshake),
                "rx_bytes": peer_state.map(|state| state.rx_bytes).unwrap_or(0),
                "tx_bytes": peer_state.map(|state| state.tx_bytes).unwrap_or(0),
                "forwardings": forwards,
                "options": Value::Object(options.as_map()),
            }));
            for route in &options.advertised_routes {
                let allowed = allowed_recipient_keys(client, route, &clients);
                routes.push(json!({
                    "cidr": route,
                    "owner_name": client.name,
                    "owner_public_key": client.public_key,
                    "owner_online": peer_state.is_some_and(|state| state.online),
                    "owner_last_handshake": peer_state.map(|state| state.handshake),
                    "allowed_peer_public_keys": allowed.map(|keys| Value::Array(keys.into_iter().map(Value::String).collect())),
                }));
            }
            if options.split_tunnel {
                let exported = exports.get(&client.name);
                let current = self.profile_revision(client, &clients, Some(&server_public));
                profiles.push(json!({
                    "name": client.name,
                    "profile_refresh_required": exported.map(|revision| revision != &current),
                }));
            }
        }
        Ok(json!({
            "server_public_key": server_public,
            "items": items,
            "routes": routes,
            "split_tunnel_profiles": profiles,
        }))
    }

    fn profile_exports_path(&self) -> String {
        self.config
            .data_dir
            .join("profile_exports.json")
            .to_string_lossy()
            .into_owned()
    }

    fn load_profile_exports(&self) -> BTreeMap<String, String> {
        let payload = self
            .storage
            .load_json(&self.profile_exports_path(), json!({}));
        payload
            .as_object()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .as_str()
                            .map(|value| (name.clone(), value.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn profile_revision(
        &self,
        client: &Client,
        clients: &[Client],
        server_public: Option<&str>,
    ) -> String {
        let server_public = match server_public {
            Some(value) => value.to_string(),
            None => self
                .wg
                .ensure_server_keys()
                .map(|keys| keys.1)
                .unwrap_or_default(),
        };
        let content = self
            .wg
            .render_client_config(client, &server_public, clients);
        sha256_hex(&content)
    }

    pub fn record_profile_export(&self, name: &str, content: Option<&str>) -> Result<(), AppError> {
        let _guard = self.lock.lock().expect("client lock");
        let clients = self.wg.load_clients();
        let client = clients
            .iter()
            .find(|client| client.name == name)
            .ok_or_else(|| AppError::not_found("Client not found."))?;
        let content = match content {
            Some(text) => text.to_string(),
            None => match self.storage.read_text(
                &self
                    .config
                    .clients_dir
                    .join(format!("{name}.conf"))
                    .to_string_lossy(),
            ) {
                Some(text) => text,
                None => {
                    let server_public = self.wg.ensure_server_keys()?.1;
                    self.wg
                        .render_client_config(client, &server_public, &clients)
                }
            },
        };
        let mut exports = self.load_profile_exports();
        exports.insert(name.to_string(), sha256_hex(&content));
        let payload = exports
            .into_iter()
            .fold(Map::new(), |mut map, (name, revision)| {
                map.insert(name, Value::String(revision));
                map
            });
        self.storage
            .save_json(&self.profile_exports_path(), &Value::Object(payload))?;
        Ok(())
    }

    pub fn create_client(&self, name: &str, address: Option<&str>) -> Result<Value, AppError> {
        let _guard = self.lock.lock().expect("client lock");
        validate_name(name)?;
        let mut clients = self.wg.load_clients();
        if clients.iter().any(|client| client.name == name) {
            return Err(AppError::validation("Client name already exists."));
        }
        let address_ip = match address.filter(|value| !value.is_empty()) {
            Some(text) => {
                let parsed: Ipv4Addr = text
                    .parse()
                    .map_err(|_| AppError::validation("Invalid client IP."))?;
                if !self.config.wg_network.contains(&parsed) {
                    return Err(AppError::validation("Client IP outside WireGuard network."));
                }
                if parsed == self.config.wg_address
                    || clients
                        .iter()
                        .any(|client| client.address_ip() == Some(parsed))
                {
                    return Err(AppError::validation("Client IP already in use."));
                }
                parsed
            }
            None => self.wg.next_available_ip(&clients)?,
        };
        let (private_key, public_key) = self.wg.generate_keypair()?;
        let client = Client {
            name: name.to_string(),
            address: address_ip.to_string(),
            private_key,
            public_key,
            created_at: now_epoch(),
            extra: Map::new(),
        };
        clients.push(client.clone());
        self.wg.save_clients(&clients)?;
        let server_public = self.wg.ensure_server_keys()?.1;
        self.wg
            .write_client_config(&client, &server_public, &clients)?;
        self.wg.refresh_wireguard(&clients)?;
        self.fwd.apply_all()?;
        Ok(json!({"name": name, "config": format!("/clients/{name}.conf")}))
    }

    pub fn rename_client(&self, old_name: &str, new_name: &str) -> Result<Value, AppError> {
        let _guard = self.lock.lock().expect("client lock");
        validate_name(new_name)?;
        let mut clients = self.wg.load_clients();
        let index = clients
            .iter()
            .position(|client| client.name == old_name)
            .ok_or_else(|| AppError::not_found("Client not found."))?;
        if clients
            .iter()
            .any(|client| client.name == new_name && client.name != old_name)
        {
            return Err(AppError::validation("Client name already exists."));
        }
        let old_conf = self.config.clients_dir.join(format!("{old_name}.conf"));
        let new_conf = self.config.clients_dir.join(format!("{new_name}.conf"));
        if self.storage.exists(&old_conf.to_string_lossy()) {
            self.storage
                .rename(&old_conf.to_string_lossy(), &new_conf.to_string_lossy());
        }
        clients[index].name = new_name.to_string();
        self.wg.save_clients(&clients)?;
        let mut exports = self.load_profile_exports();
        if let Some(revision) = exports.remove(old_name) {
            exports.insert(new_name.to_string(), revision);
            let payload = exports
                .into_iter()
                .fold(Map::new(), |mut map, (name, revision)| {
                    map.insert(name, Value::String(revision));
                    map
                });
            self.storage
                .save_json(&self.profile_exports_path(), &Value::Object(payload))?;
        }
        let server_public = self.wg.ensure_server_keys()?.1;
        self.wg
            .write_client_config(&clients[index], &server_public, &clients)?;
        self.wg.refresh_wireguard(&clients)?;
        Ok(json!({"name": new_name}))
    }

    pub fn update_options(&self, name: &str, raw: &Map<String, Value>) -> Result<Value, AppError> {
        let _guard = self.lock.lock().expect("client lock");
        let clients = self.wg.load_clients();
        let target = clients
            .iter()
            .find(|client| client.name == name)
            .cloned()
            .ok_or_else(|| AppError::not_found("Client not found."))?;
        let previous_settings = target.options();
        let settings = validate_options(raw, &target, &clients, self.config.wg_network)
            .map_err(AppError::validation)?;
        let mut updated = clients.clone();
        for client in &mut updated {
            if client.name == name {
                client.set_options(&settings);
            }
        }
        let routes_changed = settings.advertised_routes != previous_settings.advertised_routes;
        let access_changed = settings.route_access != previous_settings.route_access;
        if routes_changed {
            self.wg.check_local_routes(&settings.advertised_routes)?;
        }
        self.apply_peer_changes(&clients, &updated, routes_changed, false, access_changed)?;
        Ok(json!({"name": name, "options": Value::Object(settings.as_map())}))
    }

    fn write_profiles(&self, clients: &[Client]) -> Result<(), AppError> {
        let server_public = self.wg.ensure_server_keys()?.1;
        for client in clients {
            self.wg
                .write_client_config(client, &server_public, clients)?;
        }
        Ok(())
    }

    fn apply_peer_changes(
        &self,
        previous: &[Client],
        updated: &[Client],
        routes_changed: bool,
        refresh: bool,
        policy_changed: bool,
    ) -> Result<(), AppError> {
        if routes_changed {
            self.wg.replace_routes(previous, updated)?;
        }
        let result = (|| -> Result<(), AppError> {
            self.wg.save_clients(updated)?;
            self.write_profiles(updated)?;
            if refresh && !routes_changed {
                self.wg.refresh_wireguard(updated)?;
            }
            if routes_changed || refresh || policy_changed {
                self.fwd.apply_all()?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            if let Err(error) = self.wg.save_clients(previous) {
                tracing::error!("Could not restore the previous client state: {error}");
            }
            if let Err(restore_error) = self.write_profiles(previous) {
                tracing::error!("Could not restore the previous peer profiles: {restore_error}");
            }
            if routes_changed {
                if let Err(restore_error) = self.wg.replace_routes(updated, previous) {
                    tracing::error!(
                        "Could not restore the previous WireGuard configuration: {restore_error}"
                    );
                }
            } else if refresh {
                if let Err(restore_error) = self.wg.refresh_wireguard(previous) {
                    tracing::error!(
                        "Could not restore the previous WireGuard configuration: {restore_error}"
                    );
                }
            }
            if refresh || routes_changed || policy_changed {
                if let Err(restore_error) = self.fwd.apply_all() {
                    tracing::error!(
                        "Could not restore the previous firewall state: {restore_error}"
                    );
                }
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn delete_client(&self, name: &str) -> Result<Value, AppError> {
        let _guard = self.lock.lock().expect("client lock");
        let clients = self.wg.load_clients();
        let removed = clients
            .iter()
            .find(|client| client.name == name)
            .cloned()
            .ok_or_else(|| AppError::not_found("Client not found."))?;
        let updated: Vec<Client> = clients
            .iter()
            .filter(|client| client.name != name)
            .cloned()
            .collect();
        let routed = !removed.options().advertised_routes.is_empty();
        self.apply_peer_changes(&clients, &updated, routed, true, false)?;
        self.storage.remove(
            &self
                .config
                .clients_dir
                .join(format!("{name}.conf"))
                .to_string_lossy(),
        );
        let mut exports = self.load_profile_exports();
        if exports.remove(name).is_some() {
            let payload = exports
                .into_iter()
                .fold(Map::new(), |mut map, (name, revision)| {
                    map.insert(name, Value::String(revision));
                    map
                });
            self.storage
                .save_json(&self.profile_exports_path(), &Value::Object(payload))?;
        }
        Ok(json!({"removed": name}))
    }

    pub fn download_config_path(&self, name: &str) -> Result<PathBuf, AppError> {
        let _guard = self.lock.lock().expect("client lock");
        if !self
            .wg
            .load_clients()
            .iter()
            .any(|client| client.name == name)
        {
            return Err(AppError::not_found("Config not found."));
        }
        let path = self.config.clients_dir.join(format!("{name}.conf"));
        if !self.storage.exists(&path.to_string_lossy()) {
            return Err(AppError::not_found("Config not found."));
        }
        Ok(path)
    }

    pub fn read_config(&self, name: &str) -> Result<String, AppError> {
        let path = self.download_config_path(name)?;
        self.storage
            .read_text(&path.to_string_lossy())
            .ok_or_else(|| AppError::not_found("Config not found."))
    }

    pub fn bootstrap(&self) -> Result<(), AppError> {
        self.wg.ensure_dirs();
        let (server_private, server_public) = self.wg.ensure_server_keys()?;
        let mut clients = self.wg.load_clients();
        if clients.is_empty() {
            let default_ip = self.wg.next_available_ip(&[])?;
            let (private_key, public_key) = self.wg.generate_keypair()?;
            let client = Client {
                name: self.config.default_client_name.clone(),
                address: default_ip.to_string(),
                private_key,
                public_key,
                created_at: now_epoch(),
                extra: Map::new(),
            };
            clients.push(client.clone());
            self.wg.save_clients(&clients)?;
            self.wg.write_client_config(&client, &server_public, &[])?;
        }
        for client in &clients {
            self.wg
                .write_client_config(client, &server_public, &clients)?;
        }
        for client in &clients {
            let settings = validate_options(&Map::new(), client, &clients, self.config.wg_network)
                .map_err(AppError::validation)?;
            self.wg.check_local_routes(&settings.advertised_routes)?;
        }
        self.wg.render_wireguard_config(&clients, &server_private)?;
        let default_client_ip = clients.first().map(|client| client.address.clone());
        if self.config.seed_forwarding {
            if let Some(client_ip) = default_client_ip.as_deref() {
                self.fwd.seed_if_empty(client_ip)?;
            }
        }
        self.fwd.apply_all()?;
        self.wg.bounce_interface()?;
        tracing::info!("Bootstrap: {} clients loaded", clients.len());
        Ok(())
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn validate_name(name: &str) -> Result<(), AppError> {
    let pattern = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$").expect("name regex");
    if pattern.is_match(name) {
        Ok(())
    } else {
        Err(AppError::validation(
            "Use 1–64 letters, numbers, dots, underscores or hyphens, starting with a letter or number.",
        ))
    }
}
