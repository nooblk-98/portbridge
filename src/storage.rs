use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::Value;

pub trait Storage: Send + Sync {
    fn load_json(&self, path: &str, default: Value) -> Value;
    fn save_json(&self, path: &str, payload: &Value) -> Result<(), crate::error::AppError>;
    fn read_text(&self, path: &str) -> Option<String>;
    fn write_text(&self, path: &str, content: &str) -> Result<(), crate::error::AppError>;
    fn exists(&self, path: &str) -> bool;
    fn remove(&self, path: &str);
    fn rename(&self, from: &str, to: &str);
}

pub struct JsonFileStorage {
    base_dir: Option<PathBuf>,
}

impl JsonFileStorage {
    pub fn new(base_dir: Option<PathBuf>) -> Self {
        Self { base_dir }
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let candidate = Path::new(path);
        if candidate.is_absolute() {
            candidate.to_path_buf()
        } else if let Some(base) = &self.base_dir {
            base.join(candidate)
        } else {
            candidate.to_path_buf()
        }
    }
}

impl Storage for JsonFileStorage {
    fn load_json(&self, path: &str, default: Value) -> Value {
        match fs::read_to_string(self.resolve(path)) {
            Ok(text) => serde_json::from_str(&text).unwrap_or(default),
            Err(_) => default,
        }
    }

    fn save_json(&self, path: &str, payload: &Value) -> Result<(), crate::error::AppError> {
        let target = self.resolve(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(payload)?;
        fs::write(target, text)?;
        Ok(())
    }

    fn read_text(&self, path: &str) -> Option<String> {
        fs::read_to_string(self.resolve(path)).ok()
    }

    fn write_text(&self, path: &str, content: &str) -> Result<(), crate::error::AppError> {
        let target = self.resolve(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, content)?;
        Ok(())
    }

    fn exists(&self, path: &str) -> bool {
        self.resolve(path).exists()
    }

    fn remove(&self, path: &str) {
        let _ = fs::remove_file(self.resolve(path));
    }

    fn rename(&self, from: &str, to: &str) {
        let _ = fs::rename(self.resolve(from), self.resolve(to));
    }
}

pub struct InMemoryStorage {
    values: Mutex<HashMap<String, Value>>,
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            values: Mutex::new(HashMap::new()),
        }
    }
}

impl Storage for InMemoryStorage {
    fn load_json(&self, path: &str, default: Value) -> Value {
        self.values
            .lock()
            .expect("storage lock")
            .get(path)
            .cloned()
            .unwrap_or(default)
    }

    fn save_json(&self, path: &str, payload: &Value) -> Result<(), crate::error::AppError> {
        self.values
            .lock()
            .expect("storage lock")
            .insert(path.to_string(), payload.clone());
        Ok(())
    }

    fn read_text(&self, path: &str) -> Option<String> {
        self.values
            .lock()
            .expect("storage lock")
            .get(path)
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    fn write_text(&self, path: &str, content: &str) -> Result<(), crate::error::AppError> {
        self.values
            .lock()
            .expect("storage lock")
            .insert(path.to_string(), Value::String(content.to_string()));
        Ok(())
    }

    fn exists(&self, path: &str) -> bool {
        self.values.lock().expect("storage lock").contains_key(path)
    }

    fn remove(&self, path: &str) {
        self.values.lock().expect("storage lock").remove(path);
    }

    fn rename(&self, from: &str, to: &str) {
        let mut values = self.values.lock().expect("storage lock");
        if let Some(value) = values.remove(from) {
            values.insert(to.to_string(), value);
        }
    }
}
