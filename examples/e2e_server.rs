//! A real PortBridge dashboard backed by fixture data and a fake command runner,
//! used by the browser end-to-end tests in `frontend/e2e`.
//!
//! No WireGuard or firewall command is ever run: the runner answers `wg show`
//! from fixtures and accepts everything else. State lives in a throw-away
//! directory, so every start begins from the same peers.
//!
//! ```sh
//! E2E_PORT=43210 cargo run --example e2e_server
//! ```
//! Sign in with the password `e2e-password`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use portbridge::config::Config;
use portbridge::error::AppError;
use portbridge::metrics::MetricsService;
use portbridge::runner::{CommandResult, FakeRunner, Runner};
use portbridge::storage::{JsonFileStorage, Storage};
use portbridge::web::{router, templates, AppState};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const PASSWORD: &str = "e2e-password";

/// A fixture peer.
struct Peer {
    name: &'static str,
    address: &'static str,
    public_key: &'static str,
    /// Seconds since its last handshake.
    handshake_age: i64,
    /// Bytes the server received from, and sent to, the peer.
    received: u64,
    sent: u64,
}

const PEERS: [Peer; 4] = [
    Peer {
        name: "home",
        address: "10.8.0.2",
        public_key: "e2e-public-0",
        handshake_age: 5,
        received: 11_900_000,
        sent: 4_500_000,
    },
    Peer {
        name: "laptop",
        address: "10.8.0.3",
        public_key: "e2e-public-1",
        handshake_age: 70,
        received: 12_000_000,
        sent: 9_000_000,
    },
    Peer {
        name: "phone",
        address: "10.8.0.4",
        public_key: "e2e-public-2",
        handshake_age: 120,
        received: 12_100_000,
        sent: 13_500_000,
    },
    Peer {
        name: "router",
        address: "10.8.0.5",
        public_key: "e2e-public-3",
        handshake_age: 900,
        received: 12_200_000,
        sent: 18_000_000,
    },
];

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Answers `wg show` from the fixtures, with handshake ages relative to now so
/// the online and offline peers stay that way however long the tests run.
struct E2eRunner {
    fake: FakeRunner,
    keys: AtomicU32,
}

impl Runner for E2eRunner {
    fn run(
        &self,
        cmd: &[String],
        check: bool,
        input: Option<&str>,
    ) -> Result<CommandResult, AppError> {
        let joined = cmd.join(" ");
        if joined == "wg show wg0 latest-handshakes" {
            let lines: Vec<String> = PEERS
                .iter()
                .map(|peer| format!("{}\t{}", peer.public_key, now() - peer.handshake_age))
                .collect();
            return Ok(CommandResult::ok(lines.join("\n")));
        }
        // New peers need key pairs; hand out unique fake ones.
        match joined.as_str() {
            "wg genkey" => {
                let id = self.keys.fetch_add(1, Ordering::Relaxed);
                return Ok(CommandResult::ok(format!("e2e-generated-private-{id}\n")));
            }
            "wg pubkey" => {
                let private = input.unwrap_or_default().trim();
                return Ok(CommandResult::ok(format!("public-of-{private}\n")));
            }
            _ => {}
        }
        self.fake.run(cmd, check, input)
    }
}

#[tokio::main]
async fn main() {
    let data_dir = std::env::temp_dir().join(format!("portbridge-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).expect("create the data directory");
    let mut config = Config::for_test(data_dir.clone());
    config.admin_password = PASSWORD.to_string();
    config.app_port = std::env::var("E2E_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(0);
    let config = Arc::new(config);

    let storage: Arc<dyn Storage> = Arc::new(JsonFileStorage::new(Some(data_dir.clone())));
    let clients: Vec<Value> = PEERS
        .iter()
        .map(|peer| {
            let mut entry = json!({
                "name": peer.name,
                "address": peer.address,
                "private_key": format!("e2e-private-{}", peer.name),
                "public_key": peer.public_key,
                "created_at": 1_700_000_000,
            });
            if peer.name == "home" {
                entry["advertised_routes"] = json!(["192.168.1.106/32"]);
            }
            entry
        })
        .collect();
    storage
        .save_json(
            &config.clients_file.to_string_lossy(),
            &Value::Array(clients),
        )
        .expect("write the peers");
    storage
        .save_json(
            &config.forward_file.to_string_lossy(),
            &json!([{
                "port": "18000-18010", "protocol": "tcp", "client_ip": "10.8.0.2",
                "target_port": null, "source_ip": null, "peer_public_key": "e2e-public-0",
            }]),
        )
        .expect("write the forwarding rules");

    // Two hours of traffic so the chart and top talkers have something to show.
    let metrics = MetricsService::new(
        storage.clone(),
        config.metrics_file.to_string_lossy().into(),
    );
    let start = now() - 2 * 3600;
    for step in 0..=120 {
        let counters: BTreeMap<String, (u64, u64)> = PEERS
            .iter()
            .enumerate()
            .map(|(index, peer)| {
                let growth = (step as u64) * (index as u64 + 1) * 4_000;
                (
                    peer.public_key.to_string(),
                    (peer.received + growth, peer.sent + growth * 2),
                )
            })
            .collect();
        metrics.record(start + step * 60, &counters);
    }
    metrics.persist();

    let fake = FakeRunner::new();
    fake.set_stdout("wg show wg0 listen-port", "51820\n");
    // The server's own networks, which peers may not advertise.
    fake.set_stdout(
        "ip -j -4 route show table all",
        r#"[{"dst":"default","dev":"eth0"},{"dst":"172.20.0.0/16","dev":"eth0"}]"#,
    );
    fake.set_stdout(
        "iptables -w -t filter -S WG_FORWARDER_FWD",
        "-N WG_FORWARDER_FWD\n",
    );
    let transfer: Vec<String> = PEERS
        .iter()
        .map(|peer| format!("{}\t{}\t{}", peer.public_key, peer.received, peer.sent))
        .collect();
    fake.set_stdout("wg show wg0 transfer", transfer.join("\n"));
    let runner: Arc<dyn Runner> = Arc::new(E2eRunner {
        fake,
        keys: AtomicU32::new(0),
    });

    let services = portbridge::build_services_with(config.clone(), storage, runner);
    services.client_manager.bootstrap().expect("bootstrap");
    let state = AppState {
        config: services.config.clone(),
        client_manager: services.client_manager.clone(),
        forwarding_manager: services.forwarding_manager.clone(),
        auth: services.auth.clone(),
        runner: services.runner.clone(),
        stats: services.stats.clone(),
        templates: Arc::new(templates(&services.config)),
    };
    let listener = TcpListener::bind(format!("127.0.0.1:{}", config.app_port))
        .await
        .expect("listen");
    let address = listener.local_addr().expect("address");
    println!("E2E_URL=http://{address}");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve");
}
