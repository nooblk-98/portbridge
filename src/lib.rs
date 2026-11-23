pub mod auth;
pub mod client_manager;
pub mod config;
pub mod error;
pub mod forwarding_manager;
pub mod iptables;
pub mod model;
pub mod qr;
pub mod rule_renderer;
pub mod runner;
pub mod storage;
pub mod web;
pub mod wireguard;

use std::sync::Arc;

use crate::auth::Auth;
use crate::client_manager::ClientManager;
use crate::config::Config;
use crate::forwarding_manager::ForwardingManager;
use crate::iptables::IPTablesService;
use crate::runner::{Runner, SystemRunner};
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
    let auth = Arc::new(Auth::new(config.secret_key().to_vec()));
    Services {
        config,
        storage,
        runner,
        wireguard,
        iptables,
        forwarding_manager,
        client_manager,
        auth,
    }
}
