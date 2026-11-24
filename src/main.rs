use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use portbridge::config::Config;
use portbridge::web::{router, templates, AppState};
use tokio::net::TcpListener;

/// Handle `--version` and `hash-password` before any server setup.
fn run_cli() -> Option<ExitCode> {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V" | "version") => {
            println!("portbridge {}", portbridge::version());
            Some(ExitCode::SUCCESS)
        }
        Some("hash-password") => {
            let mut password = String::new();
            if std::io::stdin().read_line(&mut password).is_err() {
                eprintln!("Could not read the password from standard input.");
                return Some(ExitCode::FAILURE);
            }
            let password = password.trim_end_matches(['\r', '\n']);
            if password.is_empty() {
                eprintln!("Provide the password on standard input.");
                return Some(ExitCode::FAILURE);
            }
            println!("{}", portbridge::auth::hash_password(password));
            Some(ExitCode::SUCCESS)
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Some(code) = run_cli() {
        return code;
    }
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
    if config.wg_host == "127.0.0.1" {
        tracing::warn!(
            "CONFIG: WG_HOST is '127.0.0.1' (default). \
Clients will receive an unusable config. Set WG_HOST to your server's public IP or hostname."
        );
    }
    let services = portbridge::build_services(config);
    if let Err(error) = services.client_manager.bootstrap() {
        eprintln!("Bootstrap failed: {error}");
        return ExitCode::FAILURE;
    }
    tracing::info!("Bootstrap complete (version {})", portbridge::version());

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
