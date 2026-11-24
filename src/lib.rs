pub mod auth;
pub mod client_manager;
pub mod config;
pub mod error;
pub mod forwarding_manager;
pub mod iptables;
pub mod metrics;
pub mod model;
pub mod qr;
pub mod rule_renderer;
pub mod runner;
pub mod stats;
pub mod storage;
pub mod system;
pub mod web;
pub mod wireguard;

use std::sync::Arc;

/// True for a release build, which carries its release tag in
/// `PORTBRIDGE_VERSION`. A local development build does not.
pub fn is_release_build() -> bool {
    matches!(option_env!("PORTBRIDGE_VERSION"), Some(tag) if !tag.is_empty())
}

/// Release version: the `PORTBRIDGE_VERSION` build variable (a release tag)
/// when set, otherwise the crate version.
pub fn version() -> &'static str {
    match option_env!("PORTBRIDGE_VERSION") {
        Some(tag) if !tag.is_empty() => tag.trim_start_matches('v'),
        _ => env!("CARGO_PKG_VERSION"),
    }
}

use crate::auth::Auth;
use crate::client_manager::ClientManager;
use crate::config::Config;
use crate::forwarding_manager::ForwardingManager;
use crate::iptables::IPTablesService;
use crate::metrics::MetricsService;
use crate::runner::{Runner, SystemRunner};
use crate::stats::StatsService;
use crate::storage::{JsonFileStorage, Storage};
use crate::wireguard::WireGuardService;

pub struct Services {
    pub config: Arc<Config>,
    pub storage: Arc<dyn Storage>,
    pub runner: Arc<dyn Runner>,
    pub wireguard: Arc<WireGuardService>,
    pub iptables: Arc<IPTablesService>,
    pub forwarding_manager: Arc<ForwardingManager>,
    pub client_manager: Arc<ClientManager>,
    pub auth: Arc<Auth>,
    pub stats: Arc<StatsService>,
}

pub fn build_services(config: Config) -> Services {
    let config = Arc::new(config);
    let storage: Arc<dyn Storage> = Arc::new(JsonFileStorage::new(Some(config.data_dir.clone())));
    let runner: Arc<dyn Runner> = Arc::new(SystemRunner::new());
    build_services_with(config, storage, runner)
}

pub fn build_services_with(
    config: Arc<Config>,
    storage: Arc<dyn Storage>,
    runner: Arc<dyn Runner>,
) -> Services {
    let wireguard = Arc::new(WireGuardService::new(
        config.clone(),
        storage.clone(),
        runner.clone(),
    ));
    let iptables = Arc::new(IPTablesService::new(
        config.clone(),
        storage.clone(),
        runner.clone(),
    ));
    let forwarding_manager = Arc::new(ForwardingManager::new(
        iptables.clone(),
        storage.clone(),
        config.clone(),
    ));
    let client_manager = Arc::new(ClientManager::new(
        wireguard.clone(),
        storage.clone(),
        config.clone(),
        forwarding_manager.clone(),
    ));
    let auth = Arc::new(Auth::new(
        storage.clone(),
        config.sessions_file.to_string_lossy().into_owned(),
        config.secret_key().to_vec(),
    ));
    let metrics = Arc::new(MetricsService::new(
        storage.clone(),
        config.metrics_file.to_string_lossy().into_owned(),
    ));
    let stats = Arc::new(StatsService::new(
        config.clone(),
        wireguard.clone(),
        metrics,
    ));
    Services {
        config,
        storage,
        runner,
        wireguard,
        iptables,
        forwarding_manager,
        client_manager,
        auth,
        stats,
    }
}
