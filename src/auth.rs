use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
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
    secret_key: Vec<u8>,
    attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl Auth {
    pub fn new(storage: Arc<dyn Storage>, sessions_path: String, secret_key: Vec<u8>) -> Self {
        let sessions = load_sessions(storage.as_ref(), &sessions_path);
        Self {
            sessions: Mutex::new(sessions),
            storage,
            sessions_path,
            secret_key,
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

    fn password_tag(&self, password: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).expect("session MAC key");
        mac.update(b"portbridge-session:");
        mac.update(password.as_bytes());
        to_hex(&mac.finalize().into_bytes())
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
        let tag = self.password_tag(password);
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

    /// The still-valid session cookie token presented by this request. A
    /// remember-only request must not be promoted into a session cookie.
    pub fn session_token(&self, headers: &HeaderMap, password: &str) -> Option<String> {
        let cookies = cookie_values(headers);
        let token = cookies.get(SESSION_COOKIE)?;
        let tag = self.password_tag(password);
        let sessions = self.sessions.lock().expect("session lock");
        if self.record_is_valid(&sessions, token, &tag, now_epoch()) {
            Some(token.clone())
        } else {
            None
        }
    }

    fn valid_token(&self, headers: &HeaderMap, password: &str, now: u64) -> Option<String> {
        let cookies = cookie_values(headers);
        let tag = self.password_tag(password);
        let sessions = self.sessions.lock().expect("session lock");
        for name in [SESSION_COOKIE, REMEMBER_COOKIE] {
            let Some(token) = cookies.get(name) else {
                continue;
            };
            if self.record_is_valid(&sessions, token, &tag, now) {
                return Some(token.clone());
            }
        }
        None
    }

    fn record_is_valid(
        &self,
        sessions: &HashMap<String, SessionRecord>,
        token: &str,
        tag: &str,
        now: u64,
    ) -> bool {
        let Some(record) = sessions.get(token) else {
            return false;
        };
        record.created_at <= now.saturating_add(FUTURE_SKEW)
            && record.expires_at > now
            && record.password_tag == tag
    }

    /// Remove both presented tokens so a copied cookie stops working.
    pub fn logout(&self, headers: &HeaderMap) -> Result<(), AppError> {
        let cookies = cookie_values(headers);
        let mut sessions = self.sessions.lock().expect("session lock");
        let mut replacement = sessions.clone();
        let mut changed = false;
        for name in [SESSION_COOKIE, REMEMBER_COOKIE] {
            if let Some(token) = cookies.get(name) {
                changed |= replacement.remove(token).is_some();
            }
        }
        if changed {
            // Persist first: a failed write leaves the live session usable so
            // the client can retry instead of being locked out after a 500.
            persist(self.storage.as_ref(), &self.sessions_path, &replacement)?;
            *sessions = replacement;
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
