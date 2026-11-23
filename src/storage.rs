use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::error::AppError;

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

    fn save_json(&self, path: &str, payload: &Value) -> Result<(), AppError> {
        let target = self.resolve(path);
        let text = serde_json::to_string_pretty(payload)?;
        write_atomic(&target, text.as_bytes())
    }

    fn read_text(&self, path: &str) -> Option<String> {
        fs::read_to_string(self.resolve(path)).ok()
    }

    fn write_text(&self, path: &str, content: &str) -> Result<(), AppError> {
        let target = self.resolve(path);
        write_atomic(&target, content.as_bytes())
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

/// Create a directory and restrict it to the service account.
pub fn secure_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Bring an existing private file created by an older release to 0600.
pub fn normalize_private_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            if !metadata.is_file() {
                return;
            }
            let mut permissions = metadata.permissions();
            if permissions.mode() & 0o777 != 0o600 {
                permissions.set_mode(0o600);
                let _ = fs::set_permissions(path, permissions);
            }
        }
    }
}

pub fn write_atomic(target: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let parent = target
        .parent()
        .ok_or_else(|| AppError::runtime("State file has no parent directory."))?;
    fs::create_dir_all(parent)?;
    secure_directory_if_safe(parent)?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let temp = parent.join(format!(".{file_name}.tmp.{}.{nanos}", std::process::id()));
    let result = (|| -> Result<(), AppError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        normalize_private_file(&temp);
        fs::rename(&temp, target)?;
        normalize_private_file(target);
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Never chmod broad system directories such as `/etc`; only their private
/// child directories (for example `/etc/wireguard`).
pub fn secure_directory_if_safe(path: &Path) -> std::io::Result<()> {
    const BROAD: [&str; 10] = [
        "/", "/bin", "/boot", "/etc", "/home", "/opt", "/sbin", "/tmp", "/usr", "/var",
    ];
    if BROAD.contains(&path.to_string_lossy().as_ref()) {
        return Ok(());
    }
    secure_directory(path)
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
