#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use portbridge::storage::{
    normalize_private_file, secure_app_directory, set_private_file, JsonFileStorage, Storage,
};
use serde_json::json;
use tempfile::TempDir;

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn writes_are_atomic_and_private() {
    let temp = TempDir::new().expect("temp");
    let storage = JsonFileStorage::new(Some(temp.path().to_path_buf()));
    let text_path = temp.path().join("nested/clients/peer.conf");
    let json_path = temp.path().join("nested/clients.json");

    storage
        .write_text(&text_path.to_string_lossy(), "[Interface]\n")
        .expect("text");
    storage
        .save_json(&json_path.to_string_lossy(), &json!({"ok": true}))
        .expect("json");

    assert_eq!(fs::read_to_string(&text_path).unwrap(), "[Interface]\n");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&json_path).unwrap())
            .unwrap(),
        json!({"ok": true})
    );
    assert_eq!(mode(&text_path), 0o600);
    assert_eq!(mode(&json_path), 0o600);
    assert_eq!(mode(&temp.path().join("nested/clients")), 0o700);
    let leftovers: Vec<_> = fs::read_dir(temp.path().join("nested/clients"))
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn upgrade_normalizes_existing_private_files_and_directories() {
    let temp = TempDir::new().expect("temp");
    let data = temp.path().join("state");
    fs::create_dir_all(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
    let key = data.join("server.privatekey");
    fs::write(&key, "private").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    secure_app_directory(&data).expect("directory");
    normalize_private_file(&key).expect("normalize");

    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(&key), 0o600);
}

#[test]
fn startup_normalizes_existing_private_state() {
    use std::sync::Arc;

    use portbridge::config::Config;
    use portbridge::runner::FakeRunner;
    use portbridge::wireguard::WireGuardService;

    let temp = TempDir::new().expect("temp");
    let data = temp.path().join("state");
    fs::create_dir_all(data.join("clients")).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(data.join("clients"), fs::Permissions::from_mode(0o755)).unwrap();
    for path in [
        data.join("clients.json"),
        data.join("wg0.conf"),
        data.join("sessions.json"),
        data.join("clients/owner.conf"),
    ] {
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    let config = Config::for_test(data.clone());
    let storage = Arc::new(JsonFileStorage::new(Some(data.clone())));
    let service = WireGuardService::new(Arc::new(config), storage, Arc::new(FakeRunner::new()));
    service.ensure_dirs().expect("dirs");

    // An existing shared DATA_DIR must keep its mode; only the dedicated
    // clients child and the files become private.
    assert_eq!(mode(&data), 0o755);
    assert_eq!(mode(&data.join("clients")), 0o700);
    for path in [
        data.join("clients.json"),
        data.join("wg0.conf"),
        data.join("sessions.json"),
        data.join("clients/owner.conf"),
    ] {
        assert_eq!(mode(&path), 0o600, "{}", path.display());
    }
}

#[test]
fn existing_external_directories_keep_their_modes() {
    use std::sync::Arc;

    use portbridge::config::Config;
    use portbridge::runner::FakeRunner;
    use portbridge::wireguard::WireGuardService;

    let temp = TempDir::new().expect("temp");
    let data = temp.path().join("state");
    let external = temp.path().join("external-wireguard");
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&external).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&external, fs::Permissions::from_mode(0o755)).unwrap();

    let mut config = Config::for_test(data.clone());
    config.wg_config_path = external.join("wg0.conf");
    let storage = Arc::new(JsonFileStorage::new(Some(data.clone())));
    let service = WireGuardService::new(Arc::new(config), storage, Arc::new(FakeRunner::new()));
    service.ensure_dirs().expect("dirs");

    assert_eq!(mode(&data), 0o755);
    assert_eq!(mode(&external), 0o755);
    assert_eq!(mode(&data.join("clients")), 0o700);
}

#[test]
fn security_relevant_permission_failures_propagate() {
    use std::sync::Arc;

    use portbridge::config::Config;
    use portbridge::error::AppError;
    use portbridge::runner::FakeRunner;
    use portbridge::wireguard::WireGuardService;

    let temp = TempDir::new().expect("temp");
    let data = temp.path().join("state");
    fs::write(&data, "not a directory").unwrap();
    let config = Config::for_test(data.clone());
    let storage = Arc::new(JsonFileStorage::new(Some(data.clone())));
    let service = WireGuardService::new(Arc::new(config), storage, Arc::new(FakeRunner::new()));
    assert!(matches!(service.ensure_dirs(), Err(AppError::Runtime(_))));

    let directory = temp.path().join("a-directory");
    fs::create_dir_all(&directory).unwrap();
    assert!(set_private_file(&directory).is_err());
}
