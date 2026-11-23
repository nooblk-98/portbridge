#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use portbridge::config::{validate_admin_password, Config};
use tempfile::TempDir;

#[test]
fn admin_password_rejects_missing_blank_and_default_values() {
    for value in [None, Some(""), Some("   "), Some("admin"), Some("ADMIN")] {
        assert!(
            validate_admin_password(value).is_err(),
            "{value:?} should be rejected"
        );
    }
    assert_eq!(
        validate_admin_password(Some("  strong-password  ")).unwrap(),
        "strong-password"
    );
}

#[test]
fn admin_password_guard_runs_before_state_creation() {
    let temp = TempDir::new().expect("temp");
    let data_dir = temp.path().join("state");
    let wg_config = temp.path().join("wg0.conf");
    std::env::set_var("DATA_DIR", &data_dir);
    std::env::set_var("WG_CONFIG_PATH", &wg_config);

    std::env::set_var("ADMIN_PASSWORD", "admin");
    assert!(Config::from_env().is_err());
    assert!(!data_dir.exists());

    std::env::remove_var("ADMIN_PASSWORD");
    assert!(Config::from_env().is_err());
    assert!(!data_dir.exists());

    std::env::set_var("ADMIN_PASSWORD", "strong-password");
    let config = Config::from_env().expect("config");
    assert_eq!(config.admin_password, "strong-password");
    let key = data_dir.join(".secret_key");
    assert!(key.exists());
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );

    std::env::remove_var("ADMIN_PASSWORD");
    std::env::remove_var("DATA_DIR");
    std::env::remove_var("WG_CONFIG_PATH");
}
