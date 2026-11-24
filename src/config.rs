use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ipnet::Ipv4Net;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::AppError;

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub clients_dir: PathBuf,
    pub clients_file: PathBuf,
    pub forward_file: PathBuf,
    pub sessions_file: PathBuf,
    pub wg_config_path: PathBuf,
    pub wg_interface: String,
    pub wg_port: u16,
    pub wg_host: String,
    pub app_host: String,
    pub app_port: u16,
    pub wg_network: Ipv4Net,
    pub wg_address: std::net::Ipv4Addr,
    pub wg_address_text: String,
    pub wg_prefix_len: u8,
    pub admin_password: String,
    pub metrics_file: PathBuf,
    pub default_client_name: String,
    pub default_forward_target: String,
    pub nat_chain: String,
    pub filter_chain: String,
    pub template_dir: PathBuf,
    pub static_dir: PathBuf,
    pub allow_internet_egress: bool,
    pub allow_local_to_peers: bool,
    pub seed_forwarding: bool,
    pub enable_ipv4_forwarding: bool,
    secret_key: Vec<u8>,
}

/// IPv4 addresses in a subnet, following Python's `ipaddress` host rules.
pub struct Hosts {
    next: u32,
    last: u32,
    done: bool,
}

impl Iterator for Hosts {
    type Item = std::net::Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.next > self.last {
            return None;
        }
        let address = std::net::Ipv4Addr::from(self.next);
        if self.next == self.last {
            self.done = true;
        } else {
            self.next += 1;
        }
        Some(address)
    }
}

pub fn host_addresses(network: Ipv4Net) -> Hosts {
    let network_u32 = u32::from(network.network());
    let broadcast_u32 = u32::from(network.broadcast());
    let (first, last) = match network.prefix_len() {
        0..=30 => (
            network_u32.saturating_add(1),
            broadcast_u32.saturating_sub(1),
        ),
        31 => (network_u32, broadcast_u32),
        _ => (network_u32, network_u32),
    };
    Hosts {
        next: first,
        last,
        done: first > last,
    }
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

/// Reject a missing, blank or default dashboard password before any state is
/// created on disk.
pub fn validate_admin_password(value: Option<&str>) -> Result<String, AppError> {
    let value = value.unwrap_or("").trim();
    if value.is_empty() {
        return Err(AppError::config(
            "Set ADMIN_PASSWORD to a non-default password before starting PortBridge.",
        ));
    }
    if value.eq_ignore_ascii_case("admin") {
        return Err(AppError::config(
            "Set ADMIN_PASSWORD to a non-default password before starting PortBridge.",
        ));
    }
    if crate::auth::is_password_hash(value) {
        return Err(AppError::config(
            "ADMIN_PASSWORD looks like a password hash. Put hashes in ADMIN_PASSWORD_HASH.",
        ));
    }
    Ok(value.to_string())
}

/// Accept a well-formed `ADMIN_PASSWORD_HASH` produced by `portbridge hash-password`.
pub fn validate_admin_password_hash(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if !crate::auth::is_valid_password_hash(value) {
        return Err(AppError::config(
            "ADMIN_PASSWORD_HASH is not valid. Create one with: portbridge hash-password",
        ));
    }
    Ok(value.to_string())
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        // A hash takes precedence so the plaintext password need not be stored.
        let admin_password = match var("ADMIN_PASSWORD_HASH") {
            Some(hash) => validate_admin_password_hash(&hash)?,
            None => validate_admin_password(env::var("ADMIN_PASSWORD").ok().as_deref())?,
        };
        let data_dir = PathBuf::from(env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_string()));
        let clients_dir = data_dir.join("clients");
        let clients_file = data_dir.join("clients.json");
        let forward_file = absolute(PathBuf::from(
            env::var("FORWARD_CONFIG")
                .unwrap_or_else(|_| data_dir.join("forwardings.json").to_string_lossy().into()),
        ));
        let wg_interface = env::var("WG_INTERFACE").unwrap_or_else(|_| "wg0".to_string());
        let wg_config_path = absolute(PathBuf::from(
            env::var("WG_CONFIG_PATH")
                .unwrap_or_else(|_| format!("/etc/wireguard/{wg_interface}.conf")),
        ));
        if wg_config_path.file_name().and_then(|name| name.to_str())
            != Some(&format!("{wg_interface}.conf"))
        {
            return Err(AppError::config(
                "WG_CONFIG_PATH filename must match WG_INTERFACE.",
            ));
        }
        let wg_port = parse_env("WG_PORT", 51820_u16)?;
        let app_port = parse_env("APP_PORT", 3000_u16)?;
        let wg_host = env::var("WG_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let app_host = env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let network_text = env::var("WG_NETWORK").unwrap_or_else(|_| "10.8.0.0/24".to_string());
        let wg_network: Ipv4Net = network_text
            .parse()
            .map_err(|_| AppError::config(format!("Invalid WG_NETWORK: {network_text}")))?;
        let mut hosts = host_addresses(wg_network);
        let first_host = hosts
            .next()
            .ok_or_else(|| AppError::config("WG_NETWORK has no usable addresses.".to_string()))?;
        let default_forward_target = hosts.next().unwrap_or(first_host);
        let (wg_address, wg_address_text) = match var("WG_ADDRESS") {
            Some(value) => {
                let parsed: ipnet::Ipv4Net = value
                    .trim()
                    .parse()
                    .map_err(|_| AppError::config(format!("Invalid WG_ADDRESS: {value}")))?;
                (parsed.addr(), value.trim().to_string())
            }
            None => (
                first_host,
                format!("{first_host}/{}", wg_network.prefix_len()),
            ),
        };
        let default_forward_target = match var("DEFAULT_FORWARD_TARGET") {
            Some(value) => value
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| AppError::config(format!("Invalid DEFAULT_FORWARD_TARGET: {value}")))?
                .to_string(),
            None => default_forward_target.to_string(),
        };

        let default_client_name =
            env::var("DEFAULT_CLIENT_NAME").unwrap_or_else(|_| "default".to_string());
        let template_dir =
            PathBuf::from(env::var("TEMPLATE_DIR").unwrap_or_else(|_| "app/templates".to_string()));
        let static_dir =
            PathBuf::from(env::var("STATIC_DIR").unwrap_or_else(|_| "app/static".to_string()));
        let secret_key = load_or_create_secret_key(&data_dir)?;
        let sessions_file = data_dir.join("sessions.json");
        let metrics_file = data_dir.join("metrics.json");

        Ok(Config {
            metrics_file,
            data_dir,
            clients_dir,
            clients_file,
            forward_file,
            sessions_file,
            wg_config_path,
            wg_interface,
            wg_port,
            wg_host,
            app_host,
            app_port,
            wg_network,
            wg_address,
            wg_address_text,
            wg_prefix_len: wg_network.prefix_len(),
            admin_password,
            default_client_name,
            default_forward_target,
            nat_chain: "WG_FORWARDER".to_string(),
            filter_chain: "WG_FORWARDER_FWD".to_string(),
            template_dir,
            static_dir,
            // Peers may reach the internet through the server unless this is
            // switched off with ALLOW_INTERNET_EGRESS=0.
            // Programs on the PortBridge hosted server, such as a Docker reverse proxy,
            // may reach a peer only when it is switched on for that peer. This is the
            // default for peers without a setting; ALLOW_LOCAL_TO_PEERS=1 makes it on.
            allow_local_to_peers: matches!(
                env::var("ALLOW_LOCAL_TO_PEERS").as_deref(),
                Ok("1" | "true")
            ),
            allow_internet_egress: !matches!(
                env::var("ALLOW_INTERNET_EGRESS").as_deref(),
                Ok("0" | "false")
            ),
            seed_forwarding: env::var("SEED_FORWARDING").as_deref() == Ok("1"),
            enable_ipv4_forwarding: env::var("ENABLE_IPV4_FORWARDING").as_deref() == Ok("1"),
            secret_key,
        })
    }

    pub fn wg_address_cidr(&self) -> String {
        self.wg_address_text.clone()
    }

    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    /// Deterministic configuration for tests; never used by the binary.
    pub fn for_test(data_dir: PathBuf) -> Self {
        let wg_network: Ipv4Net = "10.8.0.0/24".parse().expect("test network");
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let sessions_file = data_dir.join("sessions.json");
        Self {
            metrics_file: data_dir.join("metrics.json"),
            clients_dir: data_dir.join("clients"),
            clients_file: data_dir.join("clients.json"),
            forward_file: data_dir.join("forwardings.json"),
            sessions_file,
            wg_config_path: data_dir.join("wg0.conf"),
            template_dir: repo.join("app/templates"),
            static_dir: repo.join("app/static"),
            secret_key: b"0123456789abcdef0123456789abcdef".to_vec(),
            data_dir,
            wg_interface: "wg0".to_string(),
            wg_port: 51820,
            wg_host: "203.0.113.10".to_string(),
            app_host: "127.0.0.1".to_string(),
            app_port: 3000,
            wg_network,
            wg_address: "10.8.0.1".parse().expect("test address"),
            wg_address_text: "10.8.0.1/24".to_string(),
            wg_prefix_len: 24,
            admin_password: "test-password".to_string(),
            default_client_name: "default".to_string(),
            default_forward_target: "10.8.0.2".to_string(),
            nat_chain: "WG_FORWARDER".to_string(),
            filter_chain: "WG_FORWARDER_FWD".to_string(),
            allow_internet_egress: false,
            allow_local_to_peers: false,
            seed_forwarding: false,
            enable_ipv4_forwarding: false,
        }
    }
}

fn absolute(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&path))
            .unwrap_or(path)
    }
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> Result<T, AppError> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| AppError::config(format!("Invalid {name}: {value}"))),
        Err(_) => Ok(default),
    }
}

fn load_or_create_secret_key(data_dir: &Path) -> Result<Vec<u8>, AppError> {
    let key_file = data_dir.join(".secret_key");
    let read = || -> std::io::Result<Vec<u8>> { fs::read(&key_file) };
    if let Ok(key) = read() {
        if key.len() >= 24 {
            crate::storage::normalize_private_file(&key_file)?;
            crate::storage::create_private_directory(data_dir)?;
            return Ok(key);
        }
    }
    let mut key = vec![0_u8; 32];
    OsRng.fill_bytes(&mut key);
    crate::storage::create_private_directory(data_dir)?;
    crate::storage::write_atomic(&key_file, &key)?;
    Ok(key)
}
