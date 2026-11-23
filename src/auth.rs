use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

const SESSION_COOKIE: &str = "session";
const REMEMBER_COOKIE: &str = "remember_token";
const REMEMBER_MAX_AGE: u64 = 365 * 24 * 60 * 60;
const MAX_ATTEMPTS: usize = 5;
const WINDOW: Duration = Duration::from_secs(60);

type HmacSha1 = Hmac<Sha1>;
type HmacSha512 = Hmac<Sha512>;

pub struct Auth {
    secret_key: Vec<u8>,
    attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl Auth {
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
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

    pub fn password_matches(&self, supplied: &str, expected: &str) -> bool {
        let supplied = supplied.as_bytes();
        let expected = expected.as_bytes();
        if supplied.len() != expected.len() {
            return false;
        }
        supplied.ct_eq(expected).into()
    }

    fn derived_key(&self, salt: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha1::new_from_slice(&self.secret_key).expect("hmac key");
        mac.update(salt);
        mac.finalize().into_bytes().to_vec()
    }

    fn sign_value(&self, key: &[u8], value: &str) -> String {
        let mut mac = HmacSha1::new_from_slice(key).expect("hmac key");
        mac.update(value.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    pub fn new_session_cookie(&self) -> String {
        self.session_cookie_for(br#"{"_user_id":"1","_fresh":true}"#)
    }

    /// The refreshed cookie Flask sends after the first authenticated request.
    pub fn refreshed_session_cookie(&self) -> String {
        self.session_cookie_for(br#"{"_fresh":false,"_user_id":"1"}"#)
    }

    fn session_cookie_for(&self, payload: &[u8]) -> String {
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let timestamp = URL_SAFE_NO_PAD.encode(minimal_bytes(now_epoch()));
        let value = format!("{payload}.{timestamp}");
        let signature = self.sign_value(&self.derived_key(b"cookie-session"), &value);
        format!("{value}.{signature}")
    }

    /// Verify a Flask/itsdangerous session cookie, including cookies issued by
    /// the Python reference before the upgrade.
    pub fn session_user(&self, cookie: &str) -> Option<String> {
        let mut parts = cookie.rsplitn(3, '.');
        let signature = parts.next()?;
        let timestamp = parts.next()?;
        let payload = parts.next()?;
        if payload.is_empty() || timestamp.is_empty() || signature.is_empty() {
            return None;
        }
        let value = format!("{payload}.{timestamp}");
        let expected = self.sign_value(&self.derived_key(b"cookie-session"), &value);
        if !constant_time_equal(&expected, signature) {
            return None;
        }
        let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let session: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
        session
            .get("_user_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    pub fn new_remember_cookie(&self) -> String {
        let payload = "1";
        let digest = remember_digest(&self.secret_key, payload);
        format!("{payload}|{digest}")
    }

    pub fn remember_user(&self, cookie: &str) -> Option<String> {
        let (payload, digest) = cookie.rsplit_once('|')?;
        if payload.is_empty() {
            return None;
        }
        let expected = remember_digest(&self.secret_key, payload);
        if constant_time_equal(&expected, digest) {
            Some(payload.to_string())
        } else {
            None
        }
    }

    pub fn is_authenticated(&self, headers: &HeaderMap) -> bool {
        let cookies = cookie_values(headers);
        if let Some(cookie) = cookies.get(SESSION_COOKIE) {
            if self.session_user(cookie).is_some() {
                return true;
            }
        }
        if let Some(cookie) = cookies.get(REMEMBER_COOKIE) {
            if self.remember_user(cookie).is_some() {
                return true;
            }
        }
        false
    }

    pub fn login_cookies(&self) -> Vec<String> {
        vec![
            format!(
                "{SESSION_COOKIE}={}; HttpOnly; Path=/; SameSite=Lax",
                self.new_session_cookie()
            ),
            format!(
                "{REMEMBER_COOKIE}={}; Max-Age={REMEMBER_MAX_AGE}; HttpOnly; Path=/; SameSite=Lax",
                self.new_remember_cookie()
            ),
        ]
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

fn remember_digest(secret_key: &[u8], payload: &str) -> String {
    let mut mac = HmacSha512::new_from_slice(secret_key).expect("hmac key");
    mac.update(payload.as_bytes());
    to_hex(&mac.finalize().into_bytes())
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn minimal_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
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

    #[test]
    fn flask_session_cookie_round_trips() {
        let auth = Auth::new(b"0123456789abcdef0123456789abcdef".to_vec());
        let cookie = auth.new_session_cookie();
        assert_eq!(auth.session_user(&cookie).as_deref(), Some("1"));
        assert!(auth.session_user(&cookie.replace('a', "b")).is_none());
    }

    #[test]
    fn flask_login_remember_cookie_is_accepted() {
        let auth = Auth::new(b"0123456789abcdef0123456789abcdef".to_vec());
        let flask = "1|5ce330b5e14f619d94b69cb6c3df4db95ebf66cb72f379401f220e720ee02d3d84f4f613d28de5f1059b89f06f12d0c0ebfc3a5e9b1f522e188e3c1004093d35";
        assert_eq!(auth.remember_user(flask).as_deref(), Some("1"));
    }

    #[test]
    fn remember_cookie_round_trips() {
        let auth = Auth::new(b"0123456789abcdef0123456789abcdef".to_vec());
        let cookie = auth.new_remember_cookie();
        assert_eq!(auth.remember_user(&cookie).as_deref(), Some("1"));
        assert!(auth.remember_user("1|deadbeef").is_none());
    }

    #[test]
    fn rate_limit_allows_five_then_blocks() {
        let auth = Auth::new(b"secret".to_vec());
        let address: IpAddr = "192.0.2.10".parse().unwrap();
        for _ in 0..5 {
            assert!(!auth.is_rate_limited(address));
        }
        assert!(auth.is_rate_limited(address));
        auth.clear_rate_limit(address);
        assert!(!auth.is_rate_limited(address));
    }
}
