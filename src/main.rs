use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use portbridge::config::Config;
use portbridge::web::{router, templates, AppState};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if config.admin_password == "admin" {
        tracing::warn!(
            "SECURITY: ADMIN_PASSWORD is set to the default 'admin'. \
Set the ADMIN_PASSWORD environment variable to a strong password."
        );
    }
    if config.wg_host == "127.0.0.1" {
        tracing::warn!(
            "CONFIG: WG_HOST is '127.0.0.1' (default). \
Clients will receive an unusable config. Set WG_HOST to your server's public IP or hostname."
        );
    }
    if config.admin_password == "admin" {
        eprintln!("Set ADMIN_PASSWORD to a non-default password before starting PortBridge.");
        return ExitCode::FAILURE;
    }

    let services = portbridge::build_services(config);
    if let Err(error) = services.client_manager.bootstrap() {
        eprintln!("Bootstrap failed: {error}");
        return ExitCode::FAILURE;
    }
    tracing::info!("Bootstrap complete");

    let templates = Arc::new(templates(&services.config));
    let state = AppState {
        config: services.config.clone(),
        client_manager: services.client_manager.clone(),
        forwarding_manager: services.forwarding_manager.clone(),
        auth: services.auth.clone(),
        runner: services.runner.clone(),
        templates,
    };
    let app = router(state);
    let address = format!("{}:{}", services.config.app_host, services.config.app_port);
    let listener = match TcpListener::bind(&address).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("Could not listen on {address}: {error}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!("PortBridge listening on {address}");
    if let Err(error) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        eprintln!("Server error: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
