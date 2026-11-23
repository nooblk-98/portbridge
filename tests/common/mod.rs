use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use portbridge::auth::Auth;
use portbridge::client_manager::ClientManager;
use portbridge::config::Config;
use portbridge::forwarding_manager::ForwardingManager;
use portbridge::iptables::IPTablesService;
use portbridge::model::Client;
use portbridge::runner::{CommandResult, FakeRunner};
use portbridge::storage::{InMemoryStorage, Storage};
use portbridge::web::{router, templates, AppState};
use portbridge::wireguard::WireGuardService;
use serde_json::{json, Map, Value};
use tempfile::TempDir;
use tower::ServiceExt;

pub struct Setup {
    pub _temp: TempDir,
    pub config: Arc<Config>,
    pub storage: Arc<InMemoryStorage>,
    pub runner: Arc<FakeRunner>,
    pub wg: Arc<WireGuardService>,
    pub iptables: Arc<IPTablesService>,
    pub forwarding: Arc<ForwardingManager>,
    pub manager: Arc<ClientManager>,
    pub auth: Arc<Auth>,
}

impl Setup {
    pub fn new() -> Self {
        let temp = TempDir::new().expect("temp dir");
        let config = Arc::new(Config::for_test(temp.path().to_path_buf()));
        let storage = Arc::new(InMemoryStorage::new());
        let runner = Arc::new(FakeRunner::new());
        runner.set_stdout("ip -j -4 route show table all", "[]");
        runner.set_stdout("ip -j -4 route show dev eth0", "[]");
        let storage_trait: Arc<dyn Storage> = storage.clone();
        let runner_trait: Arc<dyn portbridge::runner::Runner> = runner.clone();
        let wg = Arc::new(WireGuardService::new(
            config.clone(),
            storage_trait.clone(),
            runner_trait.clone(),
        ));
        let iptables = Arc::new(IPTablesService::new(
            config.clone(),
            storage_trait.clone(),
            runner_trait.clone(),
        ));
        let forwarding = Arc::new(ForwardingManager::new(
            iptables.clone(),
            storage_trait.clone(),
            config.clone(),
        ));
        let manager = Arc::new(ClientManager::new(
            wg.clone(),
            storage_trait,
            config.clone(),
            forwarding.clone(),
        ));
        let auth = Arc::new(Auth::new(config.secret_key().to_vec()));
        Self {
            _temp: temp,
            config,
            storage,
            runner,
            wg,
            iptables,
            forwarding,
            manager,
            auth,
        }
    }

    pub fn seed_keys(&self) {
        self.storage
            .write_text(
                &self
                    .config
                    .data_dir
                    .join("server.privatekey")
                    .to_string_lossy(),
                "server-private\n",
            )
            .expect("private key");
        self.storage
            .write_text(
                &self
                    .config
                    .data_dir
                    .join("server.publickey")
                    .to_string_lossy(),
                "server-public\n",
            )
            .expect("public key");
    }

    pub fn store(&self, clients: &[Client]) {
        let payload = serde_json::to_value(clients).expect("clients json");
        self.storage
            .save_json(&self.config.clients_file.to_string_lossy(), &payload)
            .expect("clients");
    }

    pub fn clients(&self) -> Vec<Client> {
        serde_json::from_value(
            self.storage
                .load_json(&self.config.clients_file.to_string_lossy(), json!([])),
        )
        .expect("clients")
    }

    pub fn app(&self) -> AppState {
        AppState {
            config: self.config.clone(),
            client_manager: self.manager.clone(),
            forwarding_manager: self.forwarding.clone(),
            auth: self.auth.clone(),
            runner: self.runner.clone(),
            templates: Arc::new(templates(&self.config)),
        }
    }

    pub fn router(&self) -> Router {
        router(self.app())
    }

    pub fn cookie(&self) -> String {
        self.auth.new_session_cookie()
    }

    pub fn store_forwarding(&self, rule: Value) {
        self.storage
            .save_json(
                &self.config.forward_file.to_string_lossy(),
                &Value::Array(vec![rule]),
            )
            .expect("forwarding");
    }
}

pub fn client(name: &str, address: &str, key: &str) -> Client {
    Client {
        name: name.to_string(),
        address: address.to_string(),
        private_key: format!("private-{name}"),
        public_key: key.to_string(),
        created_at: 1_700_000_000,
        extra: Map::new(),
    }
}

pub fn with_options(mut client: Client, options: Value) -> Client {
    if let Value::Object(entries) = options {
        for (key, value) in entries {
            client.extra.insert(key, value);
        }
    }
    client
}

pub fn packet_verdict(
    rules: &[Vec<String>],
    source: &str,
    destination: &str,
    established: bool,
) -> String {
    fn contains(rule: &[String], flag: &str, address: &str) -> bool {
        rule.windows(2).any(|pair| {
            pair[0] == flag
                && pair[1]
                    .parse::<ipnet::Ipv4Net>()
                    .map(|network| {
                        network.contains(&address.parse::<std::net::Ipv4Addr>().expect("address"))
                    })
                    .unwrap_or(false)
        })
    }
    for rule in rules {
        if let Some(index) = rule.iter().position(|value| value == "--ctstate") {
            let states = rule.get(index + 1).map(String::as_str).unwrap_or("");
            if !(established && (states.contains("ESTABLISHED") || states.contains("RELATED"))) {
                continue;
            }
        }
        if rule.iter().any(|value| value == "-s") && !contains(rule, "-s", source) {
            continue;
        }
        if rule.iter().any(|value| value == "-d") && !contains(rule, "-d", destination) {
            continue;
        }
        if let Some(index) = rule.iter().position(|value| value == "-j") {
            return rule.get(index + 1).cloned().unwrap_or_default();
        }
    }
    "NONE".to_string()
}

pub async fn api_request(
    app: Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, String) {
    let (status, headers, bytes) = api_request_raw(app, method, uri, cookie, body).await;
    (status, headers, String::from_utf8_lossy(&bytes).to_string())
}

pub async fn api_request_raw(
    app: Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("Cookie", format!("session={cookie}"));
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("Content-Type", "application/json");
            Body::from(serde_json::to_vec(&value).expect("body"))
        }
        None => Body::empty(),
    };
    let mut request = builder.body(body).expect("request");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::from([127, 0, 0, 1]),
        50000,
    )));
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 10 * 1024 * 1024)
        .await
        .expect("body");
    (status, headers, bytes.to_vec())
}

pub fn ok_stdout(runner: &FakeRunner, command: &str, stdout: &str) {
    runner.set_response(command, CommandResult::ok(stdout));
}
