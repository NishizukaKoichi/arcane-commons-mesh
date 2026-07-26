#![forbid(unsafe_code)]

use arcane_mesh_core::{
    recovery::{export, RecoveryPayload},
    store::ObjectStore,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use tauri::Manager;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopStatus {
    protocol_version: u16,
    chunk_size_bytes: usize,
    secret_store: &'static str,
}

#[tauri::command]
fn desktop_status() -> DesktopStatus {
    DesktopStatus {
        protocol_version: arcane_mesh_core::PROTOCOL_VERSION,
        chunk_size_bytes: arcane_mesh_core::DEFAULT_CHUNK_SIZE,
        secret_store: "stronghold",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryExport {
    path: String,
    bytes: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderConfig {
    root: String,
    enabled: bool,
    quota_bytes: u64,
}

#[tauri::command]
fn create_recovery_kit(
    app: tauri::AppHandle,
    passphrase: String,
) -> Result<RecoveryExport, String> {
    if passphrase.chars().count() < 12 {
        return Err("復旧パスフレーズは12文字以上にしてください".into());
    }
    let download = app
        .path()
        .download_dir()
        .map_err(|error| error.to_string())?;
    let path = unique_recovery_path(&download);
    let bytes = recovery_bytes(&passphrase).map_err(|error| error.to_string())?;
    write_private_new(&path, &bytes).map_err(|error| error.to_string())?;
    Ok(RecoveryExport {
        path: path.display().to_string(),
        bytes: bytes.len(),
    })
}

#[tauri::command]
fn configure_storage(
    app: tauri::AppHandle,
    root: String,
    enabled: bool,
    quota_bytes: u64,
) -> Result<ProviderConfig, String> {
    if quota_bytes == 0 {
        return Err("提供上限は1バイト以上にしてください".into());
    }
    let canonical = fs::canonicalize(&root).map_err(|error| error.to_string())?;
    if !canonical.is_dir()
        || fs::symlink_metadata(&root)
            .map_err(|error| error.to_string())?
            .file_type()
            .is_symlink()
    {
        return Err("実在する専用フォルダを選択してください".into());
    }
    ObjectStore::new(&canonical, quota_bytes).map_err(|error| error.to_string())?;
    let config = ProviderConfig {
        root: canonical.display().to_string(),
        enabled,
        quota_bytes,
    };
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| error.to_string())?;
    fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
    fs::write(
        data_dir.join("provider-config.json"),
        serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(config)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let salt_path = app
                .path()
                .app_local_data_dir()
                .expect("could not resolve app local data path")
                .join("stronghold-salt");
            app.handle()
                .plugin(tauri_plugin_stronghold::Builder::with_argon2(&salt_path).build())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            desktop_status,
            create_recovery_kit,
            configure_storage
        ])
        .run(tauri::generate_context!())
        .expect("error while running Arcane Commons Mesh");
}

fn recovery_bytes(passphrase: &str) -> Result<Vec<u8>, arcane_mesh_core::recovery::RecoveryError> {
    let mut identity_seed = [0_u8; 32];
    let mut vault_master_key = [0_u8; 32];
    OsRng.fill_bytes(&mut identity_seed);
    OsRng.fill_bytes(&mut vault_master_key);
    export(
        &RecoveryPayload {
            identity_seed,
            vault_master_key,
            community_ids: Vec::new(),
            control_plane_urls: vec!["http://127.0.0.1:8787".into()],
        },
        passphrase.as_bytes(),
    )
}

fn unique_recovery_path(directory: &Path) -> PathBuf {
    for suffix in 0..10_000 {
        let name = if suffix == 0 {
            "Arcane-Commons-Mesh.acm-recovery".into()
        } else {
            format!("Arcane-Commons-Mesh-{suffix}.acm-recovery")
        };
        let candidate = directory.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    directory.join(format!(
        "Arcane-Commons-Mesh-{}.acm-recovery",
        std::process::id()
    ))
}

fn write_private_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_reports_shared_core_and_stronghold() {
        let status = desktop_status();
        assert_eq!(status.protocol_version, 1);
        assert_eq!(status.chunk_size_bytes, 4 * 1024 * 1024);
        assert_eq!(status.secret_store, "stronghold");
    }

    #[test]
    fn recovery_export_is_encrypted_and_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner.acm-recovery");
        let bytes = recovery_bytes("correct horse battery staple").unwrap();
        write_private_new(&path, &bytes).unwrap();
        let written = fs::read(&path).unwrap();
        assert!(!written
            .windows(b"correct horse battery staple".len())
            .any(|window| window == b"correct horse battery staple"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
