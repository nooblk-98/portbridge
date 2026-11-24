use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::Router;
use minijinja::{path_loader, Environment};
use serde_json::{json, Map, Value};
use tower_http::services::ServeDir;

use crate::auth::Auth;
use crate::client_manager::ClientManager;
use crate::config::Config;
use crate::error::AppError;
use crate::forwarding_manager::ForwardingManager;
use crate::qr::profile_png;
use crate::runner::Runner;

const CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-eval'; \
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; \
object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

/// The only outside address the page may call: GitHub's public releases API,
/// used to look for a newer version. Allowed only when update checks are on.
const UPDATE_CHECK_CSP: &str = "; connect-src 'self' https://api.github.com";

fn content_security_policy(update_check: bool) -> HeaderValue {
    let mut policy = CSP.to_string();
    if update_check {
        policy.push_str(UPDATE_CHECK_CSP);
    }
    HeaderValue::from_str(&policy).expect("the policy is ASCII")
}

const REPO_URL: &str = "https://github.com/nooblk-98/portbridge";

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub client_manager: Arc<ClientManager>,
    pub forwarding_manager: Arc<ForwardingManager>,
    pub auth: Arc<Auth>,
    pub runner: Arc<dyn Runner>,
    pub stats: Arc<crate::stats::StatsService>,
    pub templates: Arc<Environment<'static>>,
}

pub fn templates(config: &Config) -> Environment<'static> {
    let mut environment = Environment::new();
    environment.set_loader(path_loader(config.template_dir.clone()));
    // Shown in the dashboard and sign-in footers.
    environment.add_global("app_version", crate::version());
    environment.add_global("update_check", config.update_check);
    environment.add_global("wg_interface", config.wg_interface.clone());
    environment.add_global("wg_network", config.wg_network.to_string());
    // A constant URL, so it is safe to emit without HTML escaping its slashes.
    environment.add_global(
        "repo_url",
        minijinja::value::Value::from_safe_string(REPO_URL.to_string()),
    );
    environment.add_function(
        "url_for",
        |endpoint: String, kwargs: minijinja::value::Kwargs| {
            let filename: String = kwargs.get("filename")?;
            if endpoint != "static" {
                return Err(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    format!("unknown endpoint {endpoint}"),
                ));
            }
            Ok(minijinja::value::Value::from_safe_string(format!(
                "/static/{filename}"
            )))
        },
    );
    environment
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/clients", get(clients_page))
        .route("/routes", get(routes_page))
        .route("/forwarding", get(forwarding_page))
        .route("/login", get(login_page))
        .route("/auth/login", post(auth_login))
        .route("/auth/logout", post(auth_logout))
        .route("/api/state", get(api_state))
        .route("/api/stats", get(api_stats))
        .route("/api/stats/history", get(api_stats_history))
        .route("/api/clients", get(api_clients).post(api_create_client))
        .route(
            "/api/clients/{name}",
            patch(api_rename_client).delete(api_delete_client),
        )
        .route("/api/clients/{name}/options", patch(api_peer_options))
        .route(
            "/api/clients/{name}/profile-imported",
            post(api_profile_imported),
        )
        .route("/clients/{file}", get(download_or_qr))
        .route(
            "/api/forwardings",
            get(api_forwardings).post(api_add_forwarding),
        )
        .route(
            "/api/forwardings/{port}/{proto}",
            delete(api_delete_forwarding),
        )
        .route("/api/wg/status", get(api_wg_status))
        .nest_service("/static", ServeDir::new(state.config.static_dir.clone()))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

async fn security_headers(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let is_static = request.uri().path().starts_with("/static/");
    let token = (!is_static)
        .then(|| {
            state
                .auth
                .session_token(request.headers(), &state.config.admin_password)
        })
        .flatten();
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        content_security_policy(state.config.update_check),
    );
    if is_static {
        if response.status().is_success() || response.status() == StatusCode::NOT_MODIFIED {
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, no-cache"),
            );
        }
    } else {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Cookie"));
        // Flask refreshes the session cookie on every authenticated response.
        if let Some(token) = token.filter(|_| !response.headers().contains_key(header::SET_COOKIE))
        {
            let cookie = format!("session={token}; HttpOnly; Path=/; SameSite=Lax");
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
        }
    }
    response
}

/// Flask's JSON provider sorts keys and uses compact separators; match it so the
/// dashboard API is byte-compatible with the reference backend.
pub fn json_response(status: StatusCode, value: Value) -> Response {
    let sorted = sort_json(value);
    let mut body = serde_json::to_string(&sorted).unwrap_or_else(|_| "{}".to_string());
    body.push('\n');
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(entries) => {
            let mut keys: Vec<String> = entries.keys().cloned().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                if let Some(value) = entries.get(&key) {
                    sorted.insert(key, sort_json(value.clone()));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_json).collect()),
        other => other,
    }
}

fn render(state: &AppState, template: &str) -> Result<Response, AppError> {
    let rendered = state
        .templates
        .get_template(template)?
        .render(minijinja::context! {})?;
    Ok(axum::response::Html(rendered).into_response())
}

fn require_auth(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if state
        .auth
        .authenticate(headers, &state.config.admin_password)
    {
        None
    } else {
        Some(
            (
                StatusCode::UNAUTHORIZED,
                json_response(
                    StatusCode::UNAUTHORIZED,
                    json!({"description": "Unauthorized"}),
                ),
            )
                .into_response(),
        )
    }
}

fn redirect_found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// The dashboard shell is one template; the path picks which page it shows.
fn app_page(state: &AppState, headers: &HeaderMap, path: &str) -> Response {
    if !state
        .auth
        .authenticate(headers, &state.config.admin_password)
    {
        return redirect_found(&format!("/login?next={path}"));
    }
    match render(state, "index.html") {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    app_page(&state, &headers, "/")
}

async fn clients_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    app_page(&state, &headers, "/clients")
}

async fn routes_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    app_page(&state, &headers, "/routes")
}

async fn forwarding_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    app_page(&state, &headers, "/forwarding")
}

async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if state
        .auth
        .authenticate(&headers, &state.config.admin_password)
    {
        return redirect_found("/");
    }
    match render(&state, "login.html") {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

fn with_cookies(mut response: Response, cookies: Vec<String>) -> Response {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

async fn auth_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if state.auth.is_rate_limited(peer.ip()) {
        return json_response(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error": "Too many login attempts. Try again in a minute."}),
        );
    }
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let password = payload
        .get("password")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());
    let Some(password) = password else {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Invalid password"}),
        );
    };
    if state
        .auth
        .password_matches(password, &state.config.admin_password)
    {
        state.auth.clear_rate_limit(peer.ip());
        return match state.auth.login(&state.config.admin_password) {
            Ok(cookies) => with_cookies(
                json_response(StatusCode::OK, json!({"status": "ok"})),
                cookies,
            ),
            Err(error) => error.into_response(),
        };
    }
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({"error": "Invalid password"}),
    )
}

async fn auth_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    if let Err(error) = state.auth.logout(&headers) {
        return error.into_response();
    }
    with_cookies(
        json_response(StatusCode::OK, json!({"status": "ok"})),
        state.auth.logout_cookies(),
    )
}

async fn api_state(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    let result = (|| -> Result<Value, AppError> {
        let clients = state.client_manager.list_clients()?;
        let forwardings = state.forwarding_manager.list_rules()?;
        Ok(json!({
            "endpoint": format!("{}:{}", state.config.wg_host, state.config.wg_port),
            "interface": state.config.wg_interface,
            "address": state.config.wg_address_cidr(),
            "network": state.config.wg_network.to_string(),
            "clients": clients.get("items").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
            "forwardings": forwardings.len(),
            "version": crate::version(),
        }))
    })();
    match result {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

/// Live dashboard numbers: peers, traffic totals, host gauges and health checks.
async fn api_stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    let stats = state.stats.clone();
    match tokio::task::spawn_blocking(move || stats.snapshot()).await {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(_) => AppError::runtime("Could not read statistics.").into_response(),
    }
}

/// Traffic over time and the busiest peers for `?range=1h|24h|7d`.
async fn api_stats_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    let range = query.get("range").map(String::as_str).unwrap_or("1h");
    let Some(range) = crate::metrics::Range::parse(range) else {
        return AppError::validation("Range must be 1h, 24h or 7d.").into_response();
    };
    let stats = state.stats.clone();
    match tokio::task::spawn_blocking(move || stats.history(range)).await {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(_) => AppError::runtime("Could not read traffic history.").into_response(),
    }
}

async fn api_clients(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    match state.client_manager.list_clients() {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

async fn api_create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let object = payload.as_object().cloned().unwrap_or_default();
    let name = match object.get("name") {
        None | Some(Value::Null) => format!("client-{}", now_epoch()),
        Some(Value::String(value)) if value.is_empty() => format!("client-{}", now_epoch()),
        Some(Value::String(value)) => value.clone(),
        Some(_) => return AppError::validation("Invalid client name.").into_response(),
    };
    let address = object.get("address").and_then(Value::as_str);
    match state.client_manager.create_client(&name, address) {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

async fn api_rename_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let new_name = payload
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if new_name.is_empty() {
        return AppError::validation("New name is required.").into_response();
    }
    match state.client_manager.rename_client(&name, &new_name) {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

async fn api_peer_options(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Some(options) = payload.as_object() else {
        return AppError::validation("Invalid peer options.").into_response();
    };
    match state.client_manager.update_options(&name, options) {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

async fn api_profile_imported(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    match state.client_manager.acknowledge_profile(&name) {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

async fn api_delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    match state.client_manager.delete_client(&name) {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

async fn download_or_qr(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file): Path<String>,
) -> Response {
    if let Some(name) = file.strip_suffix(".conf") {
        return download_config(&state, &headers, name).await;
    }
    if let Some(name) = file.strip_suffix(".png") {
        return qr_code(&state, &headers, name).await;
    }
    AppError::not_found("Not found.").into_response()
}

async fn download_config(state: &AppState, headers: &HeaderMap, name: &str) -> Response {
    if let Some(response) = require_auth(state, headers) {
        return response;
    }
    let content = match state.client_manager.read_config(name) {
        Ok(content) => content,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = state
        .client_manager
        .record_profile_export(name, Some(&content))
    {
        return error.into_response();
    }
    let mut response = content.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    let disposition = format!("attachment; filename=\"{name}.conf\"");
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn qr_code(state: &AppState, headers: &HeaderMap, name: &str) -> Response {
    if let Some(response) = require_auth(state, headers) {
        return response;
    }
    let content = match state.client_manager.read_config(name) {
        Ok(content) => content,
        Err(error) => return error.into_response(),
    };
    let png = match profile_png(&content) {
        Ok(png) => png,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = state
        .client_manager
        .record_profile_export(name, Some(&content))
    {
        return error.into_response();
    }
    let mut response = png.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    let disposition = format!("attachment; filename=\"{name}.png\"");
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn api_forwardings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    match state.forwarding_manager.list_rules() {
        Ok(items) => json_response(StatusCode::OK, json!({"items": items})),
        Err(error) => error.into_response(),
    }
}

async fn api_add_forwarding(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let object = payload.as_object().cloned().unwrap_or_default();
    match state.forwarding_manager.add_rule(&object) {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

async fn api_delete_forwarding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((port, proto)): Path<(String, String)>,
) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    match state.forwarding_manager.remove_rule(&port, &proto) {
        Ok(value) => json_response(StatusCode::OK, value),
        Err(error) => error.into_response(),
    }
}

async fn api_wg_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(response) = require_auth(&state, &headers) {
        return response;
    }
    let command = vec!["wg".to_string(), "show".to_string()];
    match state.runner.run(&command, false, None) {
        Ok(result) => {
            let output = if result.stdout.is_empty() {
                result.stderr
            } else {
                result.stdout
            };
            let lines: Vec<&str> = output.lines().collect();
            json_response(StatusCode::OK, json!({"output": lines}))
        }
        Err(error) => error.into_response(),
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Validation(message) => (StatusCode::BAD_REQUEST, message.clone()),
            AppError::NotFound(message) => (StatusCode::NOT_FOUND, message.clone()),
            AppError::Config(message) => (StatusCode::INTERNAL_SERVER_ERROR, message.clone()),
            AppError::Runtime(message) => (StatusCode::INTERNAL_SERVER_ERROR, message.clone()),
            AppError::Io(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
            AppError::Json(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
            AppError::Template(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        };
        json_response(status, json!({"description": message}))
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub fn body_object(body: &Bytes) -> Map<String, Value> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

// Keep `post` imported for the explicit router table above.
const _: fn(
    axum::routing::MethodRouter<AppState>,
    axum::routing::MethodRouter<AppState>,
) -> axum::routing::MethodRouter<AppState> = |a, _b| a;

#[cfg(test)]
mod footer_tests {
    use super::*;

    fn render_page(name: &str) -> String {
        let config = Config::for_test(std::env::temp_dir());
        templates(&config)
            .get_template(name)
            .expect("template")
            .render(minijinja::context! {})
            .expect("render")
    }

    #[test]
    fn the_page_may_call_github_only_when_update_checks_are_on() {
        let off = content_security_policy(false);
        assert!(!off.to_str().unwrap().contains("connect-src"));
        let on = content_security_policy(true);
        let on = on.to_str().unwrap();
        assert!(on.starts_with(CSP));
        assert!(on.ends_with("connect-src 'self' https://api.github.com"));
    }

    #[test]
    fn pages_tell_the_update_check_the_version_and_whether_it_is_on() {
        let html = render_page("index.html");
        assert!(html.contains(&format!(
            "<meta name=\"portbridge-version\" content=\"{}\">",
            crate::version()
        )));
        assert!(html.contains("<meta name=\"portbridge-update-check\" content=\"off\">"));

        let mut config = Config::for_test(std::env::temp_dir());
        config.update_check = true;
        let html = templates(&config)
            .get_template("index.html")
            .expect("template")
            .render(minijinja::context! {})
            .expect("render");
        assert!(html.contains("<meta name=\"portbridge-update-check\" content=\"on\">"));
    }

    #[test]
    fn dashboard_and_login_footers_link_the_repo_version_and_author() {
        let version = format!("v{}", crate::version());
        for page in ["index.html", "login.html"] {
            let html = render_page(page);
            assert!(html.contains("Made with"), "{page}");
            assert!(
                html.contains("href=\"https://github.com/nooblk-98\""),
                "{page}"
            );
            assert!(html.contains(&format!("href=\"{REPO_URL}\"")), "{page}");
            assert!(html.contains(&version), "{page}");
        }
    }
}
