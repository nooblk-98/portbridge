use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::storage::Storage;

const SESSION_COOKIE: &str = "session";
const REMEMBER_COOKIE: &str = "remember_token";
/// Absolute session lifetime; no sliding renewal.
pub const SESSION_TTL: u64 = 12 * 60 * 60;
/// Absolute remember-cookie lifetime, deliberately shorter than a year.
pub const REMEMBER_TTL: u64 = 30 * 24 * 60 * 60;
const REMEMBER_MAX_AGE: u64 = REMEMBER_TTL;
/// Tolerated clock skew for a record created in the future.
const FUTURE_SKEW: u64 = 60;
const MAX_ATTEMPTS: usize = 5;
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionRecord {
    created_at: u64,
    expires_at: u64,
    password_tag: String,
}

pub struct Auth {
    sessions: Mutex<HashMap<String, SessionRecord>>,
    storage: Arc<dyn Storage>,
    sessions_path: String,
    attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl Auth {
    pub fn new(storage: Arc<dyn Storage>, sessions_path: String) -> Self {
        let sessions = load_sessions(storage.as_ref(), &sessions_path);
        Self {
            sessions: Mutex::new(sessions),
            storage,
            sessions_path,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// True when this address has used its five attempts in the last minute.
    pub fn is_rate_limited(&self, address: IpAddr) -> bool {
        let mut attempts = self.attempts.lock().expect("rate limit lock");
        let now = Instant::now();
        let entries = attempts.entry(address).or_default();
        entries.retain(|entry| now.duration_since(*entry) < WINDOW);
        if entries.len() >= MAX_ATTEMPTS {
            return true;
        }
        entries.push(now);
        false
    }

    pub fn clear_rate_limit(&self, address: IpAddr) {
        self.attempts
            .lock()
            .expect("rate limit lock")
            .remove(&address);
    }

    pub fn password_matches(&self, supplied: &str, expected: &str) -> bool {
        let supplied = supplied.as_bytes();
        let expected = expected.as_bytes();
        if supplied.len() != expected.len() {
            return false;
        }
        supplied.ct_eq(expected).into()
    }

    /// Create one session token and one remember token, both server-side and
    /// bound to the current password.
    pub fn login(&self, password: &str) -> Result<Vec<String>, AppError> {
        self.login_at(password, now_epoch())
    }

    fn login_at(&self, password: &str, now: u64) -> Result<Vec<String>, AppError> {
        let mut sessions = self.sessions.lock().expect("session lock");
        prune(&mut sessions, now);
        while sessions.len() >= 512 {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, record)| record.expires_at)
                .map(|(token, _)| token.clone())
            {
                sessions.remove(&oldest);
            } else {
                break;
            }
        }
        let tag = password_tag(password);
        let session_token = random_token();
        let remember_token = random_token();
        sessions.insert(
            session_token.clone(),
            SessionRecord {
                created_at: now,
                expires_at: now.saturating_add(SESSION_TTL),
                password_tag: tag.clone(),
            },
        );
        sessions.insert(
            remember_token.clone(),
            SessionRecord {
                created_at: now,
                expires_at: now.saturating_add(REMEMBER_TTL),
                password_tag: tag,
            },
        );
        if let Err(error) = persist(self.storage.as_ref(), &self.sessions_path, &sessions) {
            sessions.remove(&session_token);
            sessions.remove(&remember_token);
            return Err(error);
        }
        Ok(vec![
            format!(
                "{SESSION_COOKIE}={session_token}; HttpOnly; Path=/; SameSite=Lax"
            ),
            format!(
                "{REMEMBER_COOKIE}={remember_token}; Max-Age={REMEMBER_MAX_AGE}; HttpOnly; Path=/; SameSite=Lax"
            ),
        ])
    }

    pub fn authenticate(&self, headers: &HeaderMap, password: &str) -> bool {
        self.authenticate_at(headers, password, now_epoch())
    }

    fn authenticate_at(&self, headers: &HeaderMap, password: &str, now: u64) -> bool {
        self.valid_token(headers, password, now).is_some()
    }

    /// The still-valid token presented by this request, if any.
    pub fn session_token(&self, headers: &HeaderMap, password: &str) -> Option<String> {
        self.valid_token(headers, password, now_epoch())
    }

    fn valid_token(&self, headers: &HeaderMap, password: &str, now: u64) -> Option<String> {
        let cookies = cookie_values(headers);
        let tag = password_tag(password);
        let sessions = self.sessions.lock().expect("session lock");
        for name in [SESSION_COOKIE, REMEMBER_COOKIE] {
            let Some(token) = cookies.get(name) else {
                continue;
            };
            let Some(record) = sessions.get(token) else {
                continue;
            };
            if record.created_at > now.saturating_add(FUTURE_SKEW) {
                continue;
            }
            if record.expires_at <= now {
                continue;
            }
            if record.password_tag != tag {
                continue;
            }
            return Some(token.clone());
        }
        None
    }

    /// Remove both presented tokens so a copied cookie stops working.
    pub fn logout(&self, headers: &HeaderMap) -> Result<(), AppError> {
        let cookies = cookie_values(headers);
        let mut sessions = self.sessions.lock().expect("session lock");
        let mut changed = false;
        for name in [SESSION_COOKIE, REMEMBER_COOKIE] {
            if let Some(token) = cookies.get(name) {
                changed |= sessions.remove(token).is_some();
            }
        }
        if changed {
            persist(self.storage.as_ref(), &self.sessions_path, &sessions)?;
        }
        Ok(())
    }

    pub fn logout_cookies(&self) -> Vec<String> {
        let expired = "Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0";
        vec![
            format!("{SESSION_COOKIE}=; {expired}; HttpOnly; Path=/; SameSite=Lax"),
            format!("{REMEMBER_COOKIE}=; {expired}; HttpOnly; Path=/; SameSite=Lax"),
        ]
    }
}

pub fn cookie_values(headers: &HeaderMap) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for header in headers.get_all(axum::http::header::COOKIE) {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for part in text.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            values.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    values
}

fn load_sessions(storage: &dyn Storage, path: &str) -> HashMap<String, SessionRecord> {
    let payload = storage.load_json(path, json!({}));
    let Value::Object(entries) = payload else {
        return HashMap::new();
    };
    entries
        .into_iter()
        .filter_map(|(token, value)| {
            let record: SessionRecord = serde_json::from_value(value).ok()?;
            Some((token, record))
        })
        .collect()
}

fn persist(
    storage: &dyn Storage,
    path: &str,
    sessions: &HashMap<String, SessionRecord>,
) -> Result<(), AppError> {
    let payload = sessions
        .iter()
        .fold(Map::new(), |mut map, (token, record)| {
            map.insert(
                token.clone(),
                serde_json::to_value(record).unwrap_or(Value::Null),
            );
            map
        });
    storage.save_json(path, &Value::Object(payload))
}

fn prune(sessions: &mut HashMap<String, SessionRecord>, now: u64) {
    sessions.retain(|_, record| {
        record.expires_at > now && record.created_at <= now.saturating_add(FUTURE_SKEW)
    });
}

pub fn password_tag(password: &str) -> String {
    sha256_hex(&format!("portbridge-session:{password}"))
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    to_hex(&hasher.finalize())
}

pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;
    use axum::http::HeaderValue;

    fn auth() -> (Auth, Arc<dyn Storage>) {
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        (
            Auth::new(storage.clone(), "/data/sessions.json".to_string()),
            storage,
        )
    }

    fn token(cookie: &str) -> String {
        cookie
            .split(';')
            .next()
            .unwrap_or("")
            .split_once('=')
            .map(|(_, value)| value.to_string())
            .unwrap_or_default()
    }

    fn headers(cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(cookie).expect("cookie"),
        );
        headers
    }

    #[test]
    fn session_and_remember_tokens_expire_absolutely() {
        let (auth, _) = auth();
        let cookies = auth.login_at("test-password", 1_000).expect("login");
        let session = format!("session={}", token(&cookies[0]));
        let remember = format!("remember_token={}", token(&cookies[1]));
        assert!(auth.authenticate_at(&headers(&session), "test-password", 1_001));
        assert!(auth.authenticate_at(
            &headers(&remember),
            "test-password",
            1_000 + REMEMBER_TTL - 1
        ));
        assert!(!auth.authenticate_at(&headers(&remember), "test-password", 1_000 + REMEMBER_TTL));
        assert!(!auth.authenticate_at(&headers(&session), "test-password", 1_000 + SESSION_TTL));
    }

    #[test]
    fn future_and_expired_records_are_rejected() {
        let (auth, _) = auth();
        let cookies = auth.login_at("test-password", 2_000).expect("login");
        let session = format!("session={}", token(&cookies[0]));
        assert!(!auth.authenticate_at(&headers(&session), "test-password", 1_900));
        assert!(!auth.authenticate_at(&headers(&session), "test-password", 2_000 + SESSION_TTL));
    }

    #[test]
    fn sessions_are_bound_to_the_current_password() {
        let (auth, _) = auth();
        let cookies = auth.login_at("old-password", 3_000).expect("login");
        let session = format!("session={}", token(&cookies[0]));
        assert!(auth.authenticate_at(&headers(&session), "old-password", 3_001));
        assert!(!auth.authenticate_at(&headers(&session), "new-password", 3_001));
    }

    #[test]
    fn logout_invalidates_the_presented_tokens() {
        let (auth, _) = auth();
        let cookies = auth.login_at("test-password", 4_000).expect("login");
        let session = format!("session={}", token(&cookies[0]));
        let remember = format!("remember_token={}", token(&cookies[1]));
        auth.logout(&headers(&session)).expect("logout");
        assert!(!auth.authenticate_at(&headers(&session), "test-password", 4_001));
        assert!(auth.authenticate_at(&headers(&remember), "test-password", 4_001));
        auth.logout(&headers(&remember)).expect("logout");
        assert!(!auth.authenticate_at(&headers(&remember), "test-password", 4_002));
    }

    #[test]
    fn legacy_flask_cookies_are_rejected() {
        let (auth, _) = auth();
        let legacy =
            "session=eyJfdXNlcl9pZCI6IjEiLCJfZnJlc2giOnRydWV9.awRTyA.nbJPbzvLnVmqIuFqYFeppOhLz5Q";
        assert!(!auth.authenticate_at(&headers(legacy), "test-password", 5_000));
    }

    #[test]
    fn tokens_are_persisted_across_instances() {
        let (auth, storage) = auth();
        let cookies = auth.login_at("test-password", 6_000).expect("login");
        let session = format!("session={}", token(&cookies[0]));
        let restarted = Auth::new(storage, "/data/sessions.json".to_string());
        assert!(restarted.authenticate_at(&headers(&session), "test-password", 6_001));
    }

    #[test]
    fn rate_limit_allows_five_then_blocks() {
        let (auth, _) = auth();
        let address: IpAddr = "192.0.2.10".parse().unwrap();
        for _ in 0..5 {
            assert!(!auth.is_rate_limited(address));
        }
        assert!(auth.is_rate_limited(address));
        auth.clear_rate_limit(address);
        assert!(!auth.is_rate_limited(address));
    }
}
