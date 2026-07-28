#![forbid(unsafe_code)]

use arcane_mesh_core::{
    catalog::{
        decrypt_and_verify_catalog, decrypt_manifest, encrypt_manifest, sign_and_encrypt_catalog,
        CatalogFileVersion, FileManifest, SignedVaultCatalog, VaultCatalog,
    },
    cid,
    crypto::{decrypt, SecretKey},
    identity::{Identity, MembershipClaims, NodeCertificateClaims},
    recovery::{export, import, RecoveryPayload, RecoveryVaultPointer},
    store::ObjectStore,
    vault::encrypt_stream_each,
};
use arcane_mesh_protocol::{
    transport::{IrohTransport, WireFrame},
    LocalNodeEndpoint, Operation, Request,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tauri::Manager;
use zeroize::Zeroizing;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopStatus {
    protocol_version: u16,
    chunk_size_bytes: usize,
    secret_store: &'static str,
    has_vault: bool,
    local_mesh_connected: bool,
}

#[tauri::command]
fn desktop_status(app: tauri::AppHandle) -> Result<DesktopStatus, String> {
    let data_dir = desktop_data_dir(&app).map_err(|error| error.to_string())?;
    Ok(desktop_status_for_dir(&data_dir))
}

fn desktop_status_for_dir(data_dir: &Path) -> DesktopStatus {
    DesktopStatus {
        protocol_version: arcane_mesh_core::PROTOCOL_VERSION,
        chunk_size_bytes: arcane_mesh_core::DEFAULT_CHUNK_SIZE,
        secret_store: "stronghold",
        has_vault: data_dir.join("vault-state.json").is_file(),
        local_mesh_connected: data_dir.join("local-mesh-profile.json").is_file(),
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalMeshProfile {
    root: String,
    community_id: String,
    endpoints: Vec<LocalNodeEndpoint>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalMeshStatus {
    connected: bool,
    healthy_nodes: usize,
    total_nodes: usize,
}

#[tauri::command]
fn connect_local_mesh(
    app: tauri::AppHandle,
    root: Option<String>,
) -> Result<LocalMeshStatus, String> {
    let root = root
        .map(PathBuf::from)
        .or_else(discover_local_demo_root)
        .ok_or_else(|| {
            "3拠点の検証ネットワークが見つかりません。先にローカルネットワークを起動してください"
                .to_string()
        })?;
    let root = fs::canonicalize(root).map_err(|_| {
        "3拠点の検証ネットワークが見つかりません。先にローカルネットワークを起動してください"
            .to_string()
    })?;
    let bootstrap: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("bootstrap.json")).map_err(|_| {
            "接続情報が見つかりません。ローカルネットワークを起動し直してください".to_string()
        })?)
        .map_err(|error| error.to_string())?;
    let community_id = bootstrap
        .get("communityId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "接続情報が壊れています".to_string())?
        .to_owned();
    let endpoints = ["storage-a", "storage-b", "storage-c"]
        .into_iter()
        .map(|name| {
            serde_json::from_slice::<LocalNodeEndpoint>(
                &fs::read(root.join("nodes").join(name).join("network-endpoint.json"))
                    .map_err(|_| format!("{name} は停止しています"))?,
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let profile = LocalMeshProfile {
        root: root.display().to_string(),
        community_id,
        endpoints,
    };
    let data_dir = desktop_data_dir(&app).map_err(|error| error.to_string())?;
    let healthy_nodes = network_ping(&data_dir, &profile).map_err(|error| error.to_string())?;
    if healthy_nodes == 0 {
        return Err("3拠点のどれにも接続できませんでした".into());
    }
    fs::write(
        data_dir.join("local-mesh-profile.json"),
        serde_json::to_vec_pretty(&profile).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(LocalMeshStatus {
        connected: true,
        healthy_nodes,
        total_nodes: 3,
    })
}

fn discover_local_demo_root() -> Option<PathBuf> {
    let current = std::env::current_dir().ok()?;
    current
        .ancestors()
        .map(|directory| directory.join(".demo"))
        .find(|candidate| candidate.join("bootstrap.json").is_file())
}

#[tauri::command]
fn local_mesh_status(app: tauri::AppHandle) -> Result<LocalMeshStatus, String> {
    let data_dir = desktop_data_dir(&app).map_err(|error| error.to_string())?;
    let Some(profile) = load_local_mesh_profile(&data_dir).map_err(|e| e.to_string())? else {
        return Ok(LocalMeshStatus {
            connected: false,
            healthy_nodes: 0,
            total_nodes: 3,
        });
    };
    let healthy_nodes = network_ping(&data_dir, &profile).unwrap_or(0);
    Ok(LocalMeshStatus {
        connected: healthy_nodes > 0,
        healthy_nodes,
        total_nodes: 3,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryExport {
    path: String,
    bytes: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopVaultState {
    format_version: u16,
    vault_id: String,
    recovery_path: String,
    catalog_cid: String,
    catalog_version: u64,
    owner_public_key: [u8; 32],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopFile {
    file_id: String,
    name: String,
    size_bytes: u64,
    safe_replicas: String,
    deleted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopRestore {
    path: String,
    bytes: u64,
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
    let data_dir = desktop_data_dir(&app).map_err(|error| error.to_string())?;
    if data_dir.join("vault-state.json").exists() || data_dir.join("owner.stronghold").exists() {
        return Err("既存の保管庫があります。新規作成では上書きできません".into());
    }
    let download = app
        .path()
        .download_dir()
        .map_err(|error| error.to_string())?;
    let path = unique_recovery_path(&download);
    let bytes = recovery_bytes(&passphrase).map_err(|error| error.to_string())?;
    write_private_new(&path, &bytes).map_err(|error| error.to_string())?;
    initialize_desktop_vault(&app, &path, &passphrase).map_err(|error| error.to_string())?;
    let state = load_desktop_state(&data_dir).map_err(|error| error.to_string())?;
    let recovered = import(&bytes, passphrase.as_bytes()).map_err(|error| error.to_string())?;
    replace_recovery(
        &path,
        &RecoveryPayload {
            identity_seed: recovered.identity_seed,
            vault_master_key: recovered.vault_master_key,
            community_ids: recovered.community_ids,
            control_plane_urls: recovered.control_plane_urls,
            vaults: vec![RecoveryVaultPointer {
                vault_id: state.vault_id,
                catalog_cid: state.catalog_cid,
                catalog_version: state.catalog_version,
                owner_public_key: state.owner_public_key,
            }],
        },
        &passphrase,
    )
    .map_err(|error| error.to_string())?;
    let final_bytes = fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len() as usize;
    Ok(RecoveryExport {
        path: path.display().to_string(),
        bytes: final_bytes,
    })
}

#[tauri::command]
fn copy_recovery_kit(app: tauri::AppHandle, passphrase: String) -> Result<RecoveryExport, String> {
    let data_dir = desktop_data_dir(&app).map_err(|error| error.to_string())?;
    let state = load_desktop_state(&data_dir).map_err(|error| error.to_string())?;
    let bytes = fs::read(&state.recovery_path).map_err(|error| error.to_string())?;
    import(&bytes, passphrase.as_bytes()).map_err(|error| error.to_string())?;
    let download = app
        .path()
        .download_dir()
        .map_err(|error| error.to_string())?;
    let path = unique_recovery_path(&download);
    write_private_new(&path, &bytes).map_err(|error| error.to_string())?;
    Ok(RecoveryExport {
        path: path.display().to_string(),
        bytes: bytes.len(),
    })
}

#[tauri::command]
fn import_recovery_kit(
    app: tauri::AppHandle,
    recovery_path: String,
    source_roots: Vec<String>,
    passphrase: String,
) -> Result<Vec<DesktopFile>, String> {
    let roots = source_roots.iter().map(PathBuf::from).collect::<Vec<_>>();
    import_desktop_recovery(&app, Path::new(&recovery_path), &roots, &passphrase)
        .map_err(|error| error.to_string())?;
    list_desktop_files(&app, &passphrase).map_err(|error| error.to_string())
}

#[tauri::command]
fn add_vault_file(
    app: tauri::AppHandle,
    source_path: String,
    passphrase: String,
) -> Result<DesktopFile, String> {
    add_desktop_file(&app, Path::new(&source_path), &passphrase).map_err(|error| error.to_string())
}

#[tauri::command]
fn list_vault_files(app: tauri::AppHandle, passphrase: String) -> Result<Vec<DesktopFile>, String> {
    list_desktop_files(&app, &passphrase).map_err(|error| error.to_string())
}

#[tauri::command]
fn restore_vault_file(
    app: tauri::AppHandle,
    file_id: String,
    passphrase: String,
) -> Result<DesktopRestore, String> {
    restore_desktop_file(&app, &file_id, &passphrase).map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_vault_file(
    app: tauri::AppHandle,
    file_id: String,
    passphrase: String,
) -> Result<(), String> {
    delete_desktop_file(&app, &file_id, &passphrase).map_err(|error| error.to_string())
}

#[tauri::command]
fn gc_vault(app: tauri::AppHandle, passphrase: String) -> Result<u64, String> {
    gc_desktop_vault(&app, &passphrase).map_err(|error| error.to_string())
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
            copy_recovery_kit,
            import_recovery_kit,
            add_vault_file,
            list_vault_files,
            restore_vault_file,
            delete_vault_file,
            gc_vault,
            configure_storage,
            connect_local_mesh,
            local_mesh_status
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
            vaults: Vec::new(),
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

fn replace_recovery(
    path: &Path,
    payload: &RecoveryPayload,
    passphrase: &str,
) -> anyhow::Result<()> {
    let temporary = path.with_extension("partial");
    let bytes = export(payload, passphrase.as_bytes())?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn refresh_desktop_recovery(
    state: &DesktopVaultState,
    identity_seed: [u8; 32],
    vault_master_key: [u8; 32],
    passphrase: &str,
) -> anyhow::Result<()> {
    replace_recovery(
        Path::new(&state.recovery_path),
        &RecoveryPayload {
            identity_seed,
            vault_master_key,
            community_ids: Vec::new(),
            control_plane_urls: vec!["http://127.0.0.1:8787".into()],
            vaults: vec![RecoveryVaultPointer {
                vault_id: state.vault_id.clone(),
                catalog_cid: state.catalog_cid.clone(),
                catalog_version: state.catalog_version,
                owner_public_key: state.owner_public_key,
            }],
        },
        passphrase,
    )
}

fn desktop_data_dir(app: &tauri::AppHandle) -> anyhow::Result<PathBuf> {
    Ok(app.path().app_local_data_dir()?)
}

fn initialize_desktop_vault(
    app: &tauri::AppHandle,
    recovery_path: &Path,
    passphrase: &str,
) -> anyhow::Result<()> {
    let data_dir = desktop_data_dir(app)?;
    fs::create_dir_all(&data_dir)?;
    let recovered = import(&fs::read(recovery_path)?, passphrase.as_bytes())?;
    save_stronghold_secrets(
        &data_dir,
        passphrase,
        &recovered.identity_seed,
        &recovered.vault_master_key,
    )?;
    let master = SecretKey(recovered.vault_master_key);
    let owner = Identity::from_seed(recovered.identity_seed);
    let vault_id = format!("vault_{}", random_hex(16));
    let catalog = sign_and_encrypt_catalog(
        &master,
        &owner,
        VaultCatalog {
            catalog_version: 1,
            vault_id: vault_id.clone(),
            owner_member_id: owner.member_id(),
            previous_catalog_cid: None,
            created_at: unix_now()?,
            files: Vec::new(),
        },
    )?;
    let catalog_cid = desktop_replicate(&data_dir, &serde_json::to_vec(&catalog)?, 5)?;
    save_desktop_state(
        &data_dir,
        &DesktopVaultState {
            format_version: 1,
            vault_id,
            recovery_path: recovery_path.display().to_string(),
            catalog_cid,
            catalog_version: 1,
            owner_public_key: owner.public_key(),
        },
    )
}

fn import_desktop_recovery(
    app: &tauri::AppHandle,
    recovery_path: &Path,
    source_roots: &[PathBuf],
    passphrase: &str,
) -> anyhow::Result<()> {
    import_desktop_recovery_into(
        &desktop_data_dir(app)?,
        recovery_path,
        source_roots,
        passphrase,
    )
}

fn import_desktop_recovery_into(
    data_dir: &Path,
    recovery_path: &Path,
    source_roots: &[PathBuf],
    passphrase: &str,
) -> anyhow::Result<()> {
    if source_roots.is_empty() {
        anyhow::bail!("少なくとも一つの保存ノードフォルダが必要です");
    }
    if data_dir.join("vault-state.json").exists() || data_dir.join("owner.stronghold").exists() {
        anyhow::bail!("既存の保管庫があります。復旧で上書きできません");
    }
    fs::create_dir_all(data_dir)?;
    let recovery_bytes = fs::read(recovery_path)?;
    let recovered = import(&recovery_bytes, passphrase.as_bytes())?;
    let checkpoint = recovered
        .vaults
        .first()
        .ok_or_else(|| anyhow::anyhow!("復旧ファイルに保管庫チェックポイントがありません"))?;
    let sources = source_roots
        .iter()
        .map(|root| ObjectStore::new(root, u64::MAX).map_err(Into::into))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let master = SecretKey(recovered.vault_master_key);
    let (catalog_cid, catalog) = discover_desktop_catalog(checkpoint, &master, &sources)?;
    replicate_desktop_recovered_catalog_chain(
        data_dir,
        checkpoint,
        &master,
        &sources,
        &catalog_cid,
        catalog.catalog.catalog_version,
    )?;
    for version in &catalog.catalog.files {
        let manifest_blob =
            restore_from_desktop_sources(&sources, &version.encrypted_manifest_cid)?;
        if desktop_replicate(data_dir, &manifest_blob, 5)? != version.encrypted_manifest_cid {
            anyhow::bail!("復旧したマニフェストのCIDが一致しません");
        }
        let manifest = decrypt_manifest(
            &master,
            &checkpoint.vault_id,
            &version.file_id,
            &version.file_version_id,
            &serde_json::from_slice(&manifest_blob)?,
        )?;
        for object_cid in manifest.ordered_chunk_cids {
            let blob = restore_from_desktop_sources(&sources, &object_cid)?;
            if desktop_replicate(data_dir, &blob, 3)? != object_cid {
                anyhow::bail!("復旧したチャンクのCIDが一致しません");
            }
        }
    }
    save_stronghold_secrets(
        data_dir,
        passphrase,
        &recovered.identity_seed,
        &recovered.vault_master_key,
    )?;
    let internal_recovery = data_dir.join("owner.acm-recovery");
    write_private_new(&internal_recovery, &recovery_bytes)?;
    let state = DesktopVaultState {
        format_version: 1,
        vault_id: checkpoint.vault_id.clone(),
        recovery_path: internal_recovery.display().to_string(),
        catalog_cid,
        catalog_version: catalog.catalog.catalog_version,
        owner_public_key: checkpoint.owner_public_key,
    };
    save_desktop_state(data_dir, &state)?;
    refresh_desktop_recovery(
        &state,
        recovered.identity_seed,
        recovered.vault_master_key,
        passphrase,
    )
}

fn replicate_desktop_recovered_catalog_chain(
    data_dir: &Path,
    checkpoint: &RecoveryVaultPointer,
    master: &SecretKey,
    sources: &[ObjectStore],
    latest_cid: &str,
    latest_version: u64,
) -> anyhow::Result<()> {
    let mut catalog_cid = latest_cid.to_owned();
    let mut version = latest_version;
    loop {
        let blob = restore_from_desktop_sources(sources, &catalog_cid)?;
        if desktop_replicate(data_dir, &blob, 5)? != catalog_cid {
            anyhow::bail!("復旧したカタログのCIDが一致しません");
        }
        let catalog = decrypt_and_verify_catalog(
            master,
            &checkpoint.vault_id,
            version,
            &checkpoint.owner_public_key,
            &serde_json::from_slice(&blob)?,
        )?;
        let Some(previous) = catalog.catalog.previous_catalog_cid else {
            break;
        };
        if version <= 1 {
            anyhow::bail!("カタログ履歴の版番号が不正です");
        }
        catalog_cid = previous;
        version -= 1;
    }
    Ok(())
}

fn restore_from_desktop_sources(
    sources: &[ObjectStore],
    object_cid: &str,
) -> anyhow::Result<Vec<u8>> {
    for source in sources {
        if let Ok(bytes) = source.get(object_cid) {
            return Ok(bytes);
        }
    }
    anyhow::bail!("保存ノードに必要なオブジェクト {object_cid} がありません")
}

fn discover_desktop_catalog(
    checkpoint: &RecoveryVaultPointer,
    master: &SecretKey,
    sources: &[ObjectStore],
) -> anyhow::Result<(String, SignedVaultCatalog)> {
    let checkpoint_blob = restore_from_desktop_sources(sources, &checkpoint.catalog_cid)?;
    let checkpoint_catalog = decrypt_and_verify_catalog(
        master,
        &checkpoint.vault_id,
        checkpoint.catalog_version,
        &checkpoint.owner_public_key,
        &serde_json::from_slice(&checkpoint_blob)?,
    )?;
    let mut candidates = std::collections::BTreeMap::new();
    candidates.insert(
        checkpoint.catalog_version,
        (checkpoint.catalog_cid.clone(), checkpoint_catalog),
    );
    let mut seen = HashSet::new();
    for source in sources {
        for object_cid in source.list_cids()? {
            if !seen.insert(object_cid.clone()) {
                continue;
            }
            let Ok(blob) = source.get(&object_cid) else {
                continue;
            };
            let Ok(envelope) = serde_json::from_slice(&blob) else {
                continue;
            };
            for version in checkpoint.catalog_version + 1..=checkpoint.catalog_version + 10_000 {
                if let Ok(catalog) = decrypt_and_verify_catalog(
                    master,
                    &checkpoint.vault_id,
                    version,
                    &checkpoint.owner_public_key,
                    &envelope,
                ) {
                    candidates.insert(version, (object_cid.clone(), catalog));
                    break;
                }
            }
        }
    }
    let mut version = checkpoint.catalog_version;
    let mut catalog_cid = checkpoint.catalog_cid.clone();
    loop {
        let Some((next_cid, next)) = candidates.get(&(version + 1)) else {
            break;
        };
        if next.catalog.previous_catalog_cid.as_deref() != Some(&catalog_cid) {
            break;
        }
        version += 1;
        catalog_cid = next_cid.clone();
    }
    let (_, catalog) = candidates
        .remove(&version)
        .ok_or_else(|| anyhow::anyhow!("検証済みカタログが見つかりません"))?;
    Ok((catalog_cid, catalog))
}

fn add_desktop_file(
    app: &tauri::AppHandle,
    source: &Path,
    passphrase: &str,
) -> anyhow::Result<DesktopFile> {
    let data_dir = desktop_data_dir(app)?;
    let canonical = fs::canonicalize(source)?;
    if !canonical.is_file() || fs::symlink_metadata(source)?.file_type().is_symlink() {
        anyhow::bail!("実在する通常ファイルを選択してください");
    }
    let mut state = load_desktop_state(&data_dir)?;
    let (identity_seed, vault_master_key) = load_stronghold_secrets(&data_dir, passphrase)?;
    let master = SecretKey(vault_master_key);
    let owner = Identity::from_seed(identity_seed);
    let current_blob = desktop_restore(&data_dir, &state.catalog_cid)?;
    let mut catalog = decrypt_and_verify_catalog(
        &master,
        &state.vault_id,
        state.catalog_version,
        &state.owner_public_key,
        &serde_json::from_slice(&current_blob)?,
    )?
    .catalog;
    let file_id = format!("file_{}", random_hex(16));
    let file_version_id = format!("{file_id}_v1");
    let file_key = SecretKey::random();
    let mut file = fs::File::open(&canonical)?;
    let mut hasher = blake3::Hasher::new();
    let mut chunk_cids = Vec::new();
    let mut lengths = Vec::new();
    {
        let mut reader = HashingReader {
            inner: &mut file,
            hasher: &mut hasher,
        };
        encrypt_stream_each(
            &mut reader,
            &file_key,
            &state.vault_id,
            &file_version_id,
            |chunk| {
                let blob = serde_json::to_vec(&chunk.envelope).map_err(std::io::Error::other)?;
                let stored =
                    desktop_replicate(&data_dir, &blob, 3).map_err(std::io::Error::other)?;
                if stored != chunk.cid {
                    return Err(std::io::Error::other("暗号化チャンクのCIDが一致しません").into());
                }
                chunk_cids.push(chunk.cid);
                lengths.push(chunk.plaintext_length);
                Ok(())
            },
        )?;
    }
    let metadata = fs::metadata(&canonical)?;
    let timestamp = unix_now()?;
    let name = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("ファイル名をUTF-8として扱えません"))?
        .to_owned();
    let manifest = FileManifest {
        manifest_version: 1,
        file_id: file_id.clone(),
        file_version_id: file_version_id.clone(),
        relative_path: ".".into(),
        file_name: name.clone(),
        mime_type: "application/octet-stream".into(),
        plaintext_size: metadata.len(),
        plaintext_hash: hasher.finalize().to_hex().to_string(),
        modified_at: timestamp,
        created_at: timestamp,
        file_key: file_key.0,
        ordered_chunk_cids: chunk_cids,
        chunk_plaintext_lengths: lengths.clone(),
        padding_lengths: vec![0; lengths.len()],
    };
    let manifest_cid = desktop_replicate(
        &data_dir,
        &serde_json::to_vec(&encrypt_manifest(&master, &state.vault_id, &manifest)?)?,
        5,
    )?;
    catalog.files.push(CatalogFileVersion {
        file_id: file_id.clone(),
        file_version_id,
        encrypted_manifest_cid: manifest_cid,
        created_at: timestamp,
        deleted_at: None,
        retention_until: None,
    });
    catalog.previous_catalog_cid = Some(state.catalog_cid);
    catalog.catalog_version += 1;
    catalog.created_at = timestamp;
    state.catalog_cid = desktop_replicate(
        &data_dir,
        &serde_json::to_vec(&sign_and_encrypt_catalog(&master, &owner, catalog)?)?,
        5,
    )?;
    state.catalog_version += 1;
    save_desktop_state(&data_dir, &state)?;
    refresh_desktop_recovery(&state, identity_seed, vault_master_key, passphrase)?;
    Ok(DesktopFile {
        file_id,
        name,
        size_bytes: metadata.len(),
        safe_replicas: "3/3".into(),
        deleted: false,
    })
}

fn list_desktop_files(
    app: &tauri::AppHandle,
    passphrase: &str,
) -> anyhow::Result<Vec<DesktopFile>> {
    let data_dir = desktop_data_dir(app)?;
    let (state, master, catalog) = open_desktop_catalog(&data_dir, passphrase)?;
    catalog
        .files
        .iter()
        .filter(|version| {
            version.deleted_at.is_none()
                || version
                    .retention_until
                    .is_some_and(|until| until >= unix_now().unwrap_or(0))
        })
        .map(|version| {
            let manifest = desktop_manifest(&data_dir, &state, &master, version)?;
            Ok(DesktopFile {
                file_id: manifest.file_id,
                name: manifest.file_name,
                size_bytes: manifest.plaintext_size,
                safe_replicas: if version.deleted_at.is_some() {
                    "削除予約・30日間復元可".into()
                } else {
                    format!(
                        "{}/3",
                        desktop_replica_count(&data_dir, &manifest.ordered_chunk_cids)?
                    )
                },
                deleted: version.deleted_at.is_some(),
            })
        })
        .collect()
}

fn restore_desktop_file(
    app: &tauri::AppHandle,
    file_id: &str,
    passphrase: &str,
) -> anyhow::Result<DesktopRestore> {
    let data_dir = desktop_data_dir(app)?;
    let (_, _, catalog) = open_desktop_catalog(&data_dir, passphrase)?;
    let version = catalog
        .files
        .iter()
        .rev()
        .find(|version| version.file_id == file_id)
        .ok_or_else(|| anyhow::anyhow!("復元できるファイルがありません"))?;
    let (state, master, _) = open_desktop_catalog(&data_dir, passphrase)?;
    let manifest = desktop_manifest(&data_dir, &state, &master, version)?;
    let output = unique_restored_path(&app.path().download_dir()?, &manifest.file_name);
    restore_desktop_file_to(&data_dir, file_id, passphrase, &output)
}

fn restore_desktop_file_to(
    data_dir: &Path,
    file_id: &str,
    passphrase: &str,
    output: &Path,
) -> anyhow::Result<DesktopRestore> {
    let (state, master, catalog) = open_desktop_catalog(data_dir, passphrase)?;
    let version = catalog
        .files
        .iter()
        .rev()
        .find(|version| {
            version.file_id == file_id
                && (version.deleted_at.is_none()
                    || version
                        .retention_until
                        .is_some_and(|until| until >= unix_now().unwrap_or(0)))
        })
        .ok_or_else(|| anyhow::anyhow!("復元できるファイルがありません"))?;
    let manifest = desktop_manifest(data_dir, &state, &master, version)?;
    let temporary = output.with_extension("acm-partial");
    let mut writer = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let file_key = SecretKey(manifest.file_key);
    let mut hasher = blake3::Hasher::new();
    for (index, object_cid) in manifest.ordered_chunk_cids.iter().enumerate() {
        let blob = desktop_restore(data_dir, object_cid)?;
        if cid(&blob) != *object_cid {
            anyhow::bail!("暗号化チャンクのCIDが一致しません");
        }
        let envelope = serde_json::from_slice(&blob)?;
        let aad = format!(
            "acm.chunk.v1|{}|{}|{}|{}",
            state.vault_id, version.file_version_id, index, manifest.chunk_plaintext_lengths[index]
        );
        let plaintext = Zeroizing::new(decrypt(&file_key, &envelope, aad.as_bytes())?);
        if plaintext.len() != manifest.chunk_plaintext_lengths[index] as usize {
            anyhow::bail!("復元チャンク長が一致しません");
        }
        hasher.update(&plaintext);
        writer.write_all(&plaintext)?;
    }
    writer.sync_all()?;
    drop(writer);
    if hasher.finalize().to_hex().as_str() != manifest.plaintext_hash {
        fs::remove_file(&temporary)?;
        anyhow::bail!("復元後の平文ハッシュが一致しません");
    }
    fs::rename(&temporary, output)?;
    Ok(DesktopRestore {
        path: output.display().to_string(),
        bytes: manifest.plaintext_size,
    })
}

fn delete_desktop_file(
    app: &tauri::AppHandle,
    file_id: &str,
    passphrase: &str,
) -> anyhow::Result<()> {
    let data_dir = desktop_data_dir(app)?;
    let (mut state, master, mut catalog) = open_desktop_catalog(&data_dir, passphrase)?;
    let timestamp = unix_now()?;
    let version = catalog
        .files
        .iter_mut()
        .rev()
        .find(|version| version.file_id == file_id && version.deleted_at.is_none())
        .ok_or_else(|| anyhow::anyhow!("削除できるファイルがありません"))?;
    version.deleted_at = Some(timestamp);
    version.retention_until = Some(timestamp + 30 * 86400);
    let (identity_seed, vault_master_key) = load_stronghold_secrets(&data_dir, passphrase)?;
    let owner = Identity::from_seed(identity_seed);
    catalog.previous_catalog_cid = Some(state.catalog_cid);
    catalog.catalog_version += 1;
    catalog.created_at = timestamp;
    state.catalog_cid = desktop_replicate(
        &data_dir,
        &serde_json::to_vec(&sign_and_encrypt_catalog(&master, &owner, catalog)?)?,
        5,
    )?;
    state.catalog_version += 1;
    save_desktop_state(&data_dir, &state)?;
    refresh_desktop_recovery(&state, identity_seed, vault_master_key, passphrase)
}

fn gc_desktop_vault(app: &tauri::AppHandle, passphrase: &str) -> anyhow::Result<u64> {
    gc_desktop_vault_in(&desktop_data_dir(app)?, passphrase)
}

fn gc_desktop_vault_in(data_dir: &Path, passphrase: &str) -> anyhow::Result<u64> {
    let (mut state, master, mut catalog) = open_desktop_catalog(data_dir, passphrase)?;
    let (identity_seed, vault_master_key) = load_stronghold_secrets(data_dir, passphrase)?;
    let owner = Identity::from_seed(identity_seed);
    let timestamp = unix_now()?;
    let mut retained_objects = desktop_catalog_chain_cids(data_dir, &state, &master)?;
    for version in &catalog.files {
        if version
            .retention_until
            .is_none_or(|until| until >= timestamp)
        {
            retained_objects.insert(version.encrypted_manifest_cid.clone());
            retained_objects
                .extend(desktop_manifest(data_dir, &state, &master, version)?.ordered_chunk_cids);
        }
    }
    let before = catalog.files.len();
    catalog.files.retain(|version| {
        version
            .retention_until
            .is_none_or(|until| until >= timestamp)
    });
    if catalog.files.len() != before {
        catalog.previous_catalog_cid = Some(state.catalog_cid);
        catalog.catalog_version += 1;
        catalog.created_at = timestamp;
        state.catalog_cid = desktop_replicate(
            data_dir,
            &serde_json::to_vec(&sign_and_encrypt_catalog(&master, &owner, catalog)?)?,
            5,
        )?;
        state.catalog_version += 1;
        save_desktop_state(data_dir, &state)?;
        refresh_desktop_recovery(&state, identity_seed, vault_master_key, passphrase)?;
    }
    retained_objects.extend(desktop_catalog_chain_cids(data_dir, &state, &master)?);
    let mut removed = 0_u64;
    for node in desktop_nodes(data_dir)? {
        for object_cid in node.list_cids()? {
            if !retained_objects.contains(&object_cid) && node.delete(&object_cid)? {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

fn open_desktop_catalog(
    data_dir: &Path,
    passphrase: &str,
) -> anyhow::Result<(DesktopVaultState, SecretKey, VaultCatalog)> {
    let state = load_desktop_state(data_dir)?;
    let (_, vault_master_key) = load_stronghold_secrets(data_dir, passphrase)?;
    let master = SecretKey(vault_master_key);
    let blob = desktop_restore(data_dir, &state.catalog_cid)?;
    let catalog = decrypt_and_verify_catalog(
        &master,
        &state.vault_id,
        state.catalog_version,
        &state.owner_public_key,
        &serde_json::from_slice(&blob)?,
    )?
    .catalog;
    Ok((state, master, catalog))
}

fn desktop_catalog_chain_cids(
    data_dir: &Path,
    state: &DesktopVaultState,
    master: &SecretKey,
) -> anyhow::Result<HashSet<String>> {
    let mut retained = HashSet::new();
    let mut catalog_cid = state.catalog_cid.clone();
    let mut version = state.catalog_version;
    loop {
        if !retained.insert(catalog_cid.clone()) {
            anyhow::bail!("カタログ履歴に循環があります");
        }
        let blob = desktop_restore(data_dir, &catalog_cid)?;
        let catalog = decrypt_and_verify_catalog(
            master,
            &state.vault_id,
            version,
            &state.owner_public_key,
            &serde_json::from_slice(&blob)?,
        )?;
        let Some(previous) = catalog.catalog.previous_catalog_cid else {
            break;
        };
        if version <= 1 {
            anyhow::bail!("カタログ履歴の版番号が不正です");
        }
        catalog_cid = previous;
        version -= 1;
    }
    Ok(retained)
}

fn desktop_manifest(
    data_dir: &Path,
    state: &DesktopVaultState,
    master: &SecretKey,
    version: &CatalogFileVersion,
) -> anyhow::Result<FileManifest> {
    Ok(decrypt_manifest(
        master,
        &state.vault_id,
        &version.file_id,
        &version.file_version_id,
        &serde_json::from_slice(&desktop_restore(data_dir, &version.encrypted_manifest_cid)?)?,
    )?)
}

fn desktop_replica_count(data_dir: &Path, object_cids: &[String]) -> anyhow::Result<usize> {
    if let Some(profile) = load_local_mesh_profile(data_dir)? {
        return network_replica_count(data_dir, &profile, object_cids);
    }
    let nodes = desktop_nodes(data_dir)?;
    Ok((0..3)
        .filter(|index| {
            object_cids
                .iter()
                .all(|object_cid| nodes[*index].get(object_cid).is_ok())
        })
        .count())
}

fn unique_restored_path(directory: &Path, file_name: &str) -> PathBuf {
    let safe_name = Path::new(file_name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("restored-file");
    for suffix in 0..10_000 {
        let name = if suffix == 0 {
            format!("Restored-{safe_name}")
        } else {
            format!("Restored-{suffix}-{safe_name}")
        };
        let candidate = directory.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    directory.join(format!("Restored-{}-{safe_name}", std::process::id()))
}

fn desktop_nodes(data_dir: &Path) -> anyhow::Result<Vec<ObjectStore>> {
    (0..6)
        .map(|index| {
            ObjectStore::new(
                data_dir.join("mesh-nodes").join(index.to_string()),
                10 * 1024 * 1024 * 1024,
            )
            .map_err(Into::into)
        })
        .collect()
}

fn desktop_replicate(data_dir: &Path, bytes: &[u8], target: usize) -> anyhow::Result<String> {
    if let Some(profile) = load_local_mesh_profile(data_dir)? {
        return network_replicate(data_dir, &profile, bytes, target.min(3));
    }
    let object_cid = cid(bytes);
    let mut stored = 0;
    for node in desktop_nodes(data_dir)? {
        if node.put(&object_cid, bytes).is_ok() {
            stored += 1;
        }
        if stored == target {
            return Ok(object_cid);
        }
    }
    anyhow::bail!("安全な複製を{stored}/{target}個しか作成できませんでした")
}

fn desktop_restore(data_dir: &Path, object_cid: &str) -> anyhow::Result<Vec<u8>> {
    if let Some(profile) = load_local_mesh_profile(data_dir)? {
        return network_restore(data_dir, &profile, object_cid);
    }
    for node in desktop_nodes(data_dir)? {
        if let Ok(bytes) = node.get(object_cid) {
            return Ok(bytes);
        }
    }
    anyhow::bail!("利用できる安全な複製がありません")
}

fn load_local_mesh_profile(data_dir: &Path) -> anyhow::Result<Option<LocalMeshProfile>> {
    let path = data_dir.join("local-mesh-profile.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

fn network_runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Runtime::new()?)
}

fn network_client(
    data_dir: &Path,
    profile: &LocalMeshProfile,
) -> anyhow::Result<(
    tokio::runtime::Runtime,
    IrohTransport,
    Identity,
    arcane_mesh_core::identity::MembershipCredential,
    arcane_mesh_core::identity::NodeCertificate,
)> {
    let runtime = network_runtime()?;
    let transport = runtime.block_on(IrohTransport::bind_local(
        data_dir.join("desktop-network-replay.sqlite3"),
    ))?;
    let root = Identity::from_seed([1; 32]);
    let client = Identity::from_seed([11; 32]);
    let now = unix_now()?;
    let credential = MembershipClaims {
        credential_version: 1,
        community_id: profile.community_id.clone(),
        member_public_key: client.public_key(),
        member_id: client.member_id(),
        roles: vec![
            "admin".into(),
            "auditor".into(),
            "member".into(),
            "node".into(),
        ],
        issued_at: now - 60,
        expires_at: now + 3600,
        serial: u64::try_from(now).unwrap_or_default(),
        issuer_public_key: root.public_key(),
    }
    .issue(&root);
    let certificate = NodeCertificateClaims {
        certificate_version: 1,
        node_id: "desktop-local-client".into(),
        community_id: profile.community_id.clone(),
        owner_member_id: client.member_id(),
        endpoint_public_key: transport.addr().id.to_string(),
        allowed_roles: vec!["node".into()],
        max_storage_bytes: 10 * 1024 * 1024 * 1024,
        issued_at: now - 60,
        expires_at: now + 3600,
    }
    .issue(&client);
    Ok((runtime, transport, client, credential, certificate))
}

#[allow(clippy::too_many_arguments)]
fn network_frame(
    profile: &LocalMeshProfile,
    identity: &Identity,
    credential: &arcane_mesh_core::identity::MembershipCredential,
    certificate: &arcane_mesh_core::identity::NodeCertificate,
    operation: Operation,
    object_cid: Option<&str>,
    payload: Vec<u8>,
    sequence: usize,
) -> anyhow::Result<WireFrame> {
    let now = unix_now()?;
    let mut random = OsRng;
    let request = Request {
        protocol_version: 1,
        request_id: format!("desktop-{now}-{sequence}-{:016x}", random.next_u64()),
        community_id: profile.community_id.clone(),
        node_id: "desktop-local-client".into(),
        operation,
        object_cid: object_cid.map(str::to_owned),
        issued_at: now,
        expires_at: now + 300,
        credential: credential.clone(),
    };
    let request_signature = identity
        .sign(&request.signing_bytes(&cid(&payload)))
        .to_vec();
    Ok(WireFrame {
        request,
        request_signature,
        node_certificate: certificate.clone(),
        node_owner_public_key: identity.public_key(),
        payload,
    })
}

fn network_ping(data_dir: &Path, profile: &LocalMeshProfile) -> anyhow::Result<usize> {
    let (runtime, transport, identity, credential, certificate) =
        network_client(data_dir, profile)?;
    Ok(profile
        .endpoints
        .iter()
        .enumerate()
        .filter(|(index, endpoint)| {
            let Ok(frame) = network_frame(
                profile,
                &identity,
                &credential,
                &certificate,
                Operation::Ping,
                None,
                Vec::new(),
                *index,
            ) else {
                return false;
            };
            runtime
                .block_on(transport.call(endpoint.endpoint_addr.clone(), &frame))
                .is_ok_and(|response| response.ok)
        })
        .count())
}

fn network_replicate(
    data_dir: &Path,
    profile: &LocalMeshProfile,
    bytes: &[u8],
    target: usize,
) -> anyhow::Result<String> {
    let object_cid = cid(bytes);
    let (runtime, transport, identity, credential, certificate) =
        network_client(data_dir, profile)?;
    let mut stored = 0;
    for (index, endpoint) in profile.endpoints.iter().enumerate() {
        let frame = network_frame(
            profile,
            &identity,
            &credential,
            &certificate,
            Operation::PutObject,
            Some(&object_cid),
            bytes.to_vec(),
            index,
        )?;
        if runtime
            .block_on(transport.call(endpoint.endpoint_addr.clone(), &frame))
            .is_ok_and(|response| response.ok)
        {
            stored += 1;
        }
    }
    if stored < target {
        anyhow::bail!("安全なネットワーク複製を{stored}/{target}個しか作成できませんでした");
    }
    Ok(object_cid)
}

fn network_restore(
    data_dir: &Path,
    profile: &LocalMeshProfile,
    object_cid: &str,
) -> anyhow::Result<Vec<u8>> {
    let (runtime, transport, identity, credential, certificate) =
        network_client(data_dir, profile)?;
    for (index, endpoint) in profile.endpoints.iter().enumerate() {
        let frame = network_frame(
            profile,
            &identity,
            &credential,
            &certificate,
            Operation::GetObject,
            Some(object_cid),
            Vec::new(),
            index,
        )?;
        if let Ok(response) =
            runtime.block_on(transport.call(endpoint.endpoint_addr.clone(), &frame))
        {
            if response.ok && cid(&response.payload) == object_cid {
                return Ok(response.payload);
            }
        }
    }
    anyhow::bail!("利用できる安全なネットワーク複製がありません")
}

fn network_replica_count(
    data_dir: &Path,
    profile: &LocalMeshProfile,
    object_cids: &[String],
) -> anyhow::Result<usize> {
    let (runtime, transport, identity, credential, certificate) =
        network_client(data_dir, profile)?;
    Ok(profile
        .endpoints
        .iter()
        .enumerate()
        .filter(|(index, endpoint)| {
            object_cids.iter().all(|object_cid| {
                let Ok(frame) = network_frame(
                    profile,
                    &identity,
                    &credential,
                    &certificate,
                    Operation::HasObject,
                    Some(object_cid),
                    Vec::new(),
                    *index,
                ) else {
                    return false;
                };
                runtime
                    .block_on(transport.call(endpoint.endpoint_addr.clone(), &frame))
                    .is_ok_and(|response| response.ok && response.payload == b"true")
            })
        })
        .count())
}

fn load_desktop_state(data_dir: &Path) -> anyhow::Result<DesktopVaultState> {
    let state: DesktopVaultState =
        serde_json::from_slice(&fs::read(data_dir.join("vault-state.json"))?)?;
    if state.format_version != 1 {
        anyhow::bail!("未対応の保管庫形式です");
    }
    Ok(state)
}

fn save_desktop_state(data_dir: &Path, state: &DesktopVaultState) -> anyhow::Result<()> {
    let destination = data_dir.join("vault-state.json");
    let temporary = data_dir.join("vault-state.partial");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(state)?)?;
    file.sync_all()?;
    fs::rename(temporary, destination)?;
    fs::File::open(data_dir)?.sync_all()?;
    Ok(())
}

fn random_hex(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now() -> anyhow::Result<i64> {
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?)
}

fn save_stronghold_secrets(
    data_dir: &Path,
    passphrase: &str,
    identity_seed: &[u8; 32],
    vault_master_key: &[u8; 32],
) -> anyhow::Result<()> {
    let stronghold = open_stronghold(data_dir, passphrase)?;
    let client = stronghold.create_client(b"owner")?;
    client
        .store()
        .insert(b"identity_seed".to_vec(), identity_seed.to_vec(), None)?;
    client.store().insert(
        b"vault_master_key".to_vec(),
        vault_master_key.to_vec(),
        None,
    )?;
    stronghold.save()?;
    Ok(())
}

fn load_stronghold_secrets(
    data_dir: &Path,
    passphrase: &str,
) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let stronghold = open_stronghold(data_dir, passphrase)?;
    let client = stronghold.load_client(b"owner")?;
    let identity = Zeroizing::new(
        client
            .store()
            .get(b"identity_seed")?
            .ok_or_else(|| anyhow::anyhow!("Strongholdにidentity seedがありません"))?,
    );
    let master = Zeroizing::new(
        client
            .store()
            .get(b"vault_master_key")?
            .ok_or_else(|| anyhow::anyhow!("Strongholdにvault master keyがありません"))?,
    );
    let identity_seed: [u8; 32] = identity
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Strongholdのidentity seed長が不正です"))?;
    let vault_master_key: [u8; 32] = master
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Strongholdのvault master key長が不正です"))?;
    Ok((identity_seed, vault_master_key))
}

fn open_stronghold(
    data_dir: &Path,
    passphrase: &str,
) -> anyhow::Result<tauri_plugin_stronghold::stronghold::Stronghold> {
    let password = tauri_plugin_stronghold::kdf::KeyDerivation::argon2(
        passphrase,
        &data_dir.join("stronghold-salt"),
    );
    Ok(tauri_plugin_stronghold::stronghold::Stronghold::new(
        data_dir.join("owner.stronghold"),
        password,
    )?)
}

struct HashingReader<'a, R> {
    inner: R,
    hasher: &'a mut blake3::Hasher,
}

impl<R: Read> Read for HashingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_local_mesh_accepts_desktop_storage_round_trip() {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let demo_root = repository.join(".demo");
        if !demo_root.join("bootstrap.json").is_file() {
            return;
        }
        let bootstrap: serde_json::Value =
            serde_json::from_slice(&fs::read(demo_root.join("bootstrap.json")).unwrap()).unwrap();
        let profile = LocalMeshProfile {
            root: demo_root.display().to_string(),
            community_id: bootstrap["communityId"].as_str().unwrap().to_owned(),
            endpoints: ["storage-a", "storage-b", "storage-c"]
                .into_iter()
                .map(|name| {
                    serde_json::from_slice(
                        &fs::read(
                            demo_root
                                .join("nodes")
                                .join(name)
                                .join("network-endpoint.json"),
                        )
                        .unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        };
        let client_data = tempfile::tempdir().unwrap();
        let encrypted_blob = b"desktop-network-ciphertext-fixture";
        let object_cid =
            network_replicate(client_data.path(), &profile, encrypted_blob, 3).unwrap();
        assert_eq!(
            network_replica_count(
                client_data.path(),
                &profile,
                std::slice::from_ref(&object_cid),
            )
            .unwrap(),
            3
        );
        assert_eq!(
            network_restore(client_data.path(), &profile, &object_cid).unwrap(),
            encrypted_blob
        );
    }

    #[test]
    fn desktop_reports_shared_core_and_stronghold() {
        let directory = tempfile::tempdir().unwrap();
        let status = desktop_status_for_dir(directory.path());
        assert_eq!(status.protocol_version, 1);
        assert_eq!(status.chunk_size_bytes, 4 * 1024 * 1024);
        assert_eq!(status.secret_store, "stronghold");
        assert!(!status.has_vault);
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

    #[test]
    fn stronghold_round_trips_identity_and_vault_keys() {
        let directory = tempfile::tempdir().unwrap();
        save_stronghold_secrets(
            directory.path(),
            "correct horse battery staple",
            &[4; 32],
            &[9; 32],
        )
        .unwrap();
        let (identity, master) =
            load_stronghold_secrets(directory.path(), "correct horse battery staple").unwrap();
        assert_eq!(identity, [4; 32]);
        assert_eq!(master, [9; 32]);
        assert!(load_stronghold_secrets(directory.path(), "wrong passphrase").is_err());
    }

    #[test]
    fn stale_recovery_checkpoint_discovers_newer_signed_catalog() {
        let directory = tempfile::tempdir().unwrap();
        let master = SecretKey([7; 32]);
        let owner = Identity::from_seed([8; 32]);
        let vault_id = "vault-recovery-test";
        let first = serde_json::to_vec(
            &sign_and_encrypt_catalog(
                &master,
                &owner,
                VaultCatalog {
                    catalog_version: 1,
                    vault_id: vault_id.into(),
                    owner_member_id: owner.member_id(),
                    previous_catalog_cid: None,
                    created_at: 100,
                    files: Vec::new(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let first_cid = cid(&first);
        let second = serde_json::to_vec(
            &sign_and_encrypt_catalog(
                &master,
                &owner,
                VaultCatalog {
                    catalog_version: 2,
                    vault_id: vault_id.into(),
                    owner_member_id: owner.member_id(),
                    previous_catalog_cid: Some(first_cid.clone()),
                    created_at: 101,
                    files: Vec::new(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let second_cid = cid(&second);
        let sources = (0..5)
            .map(|index| {
                ObjectStore::new(directory.path().join(index.to_string()), 1024 * 1024).unwrap()
            })
            .collect::<Vec<_>>();
        for source in &sources {
            source.put(&first_cid, &first).unwrap();
            source.put(&second_cid, &second).unwrap();
        }
        let (found_cid, found) = discover_desktop_catalog(
            &RecoveryVaultPointer {
                vault_id: vault_id.into(),
                catalog_cid: first_cid,
                catalog_version: 1,
                owner_public_key: owner.public_key(),
            },
            &master,
            &sources,
        )
        .unwrap();
        assert_eq!(found_cid, second_cid);
        assert_eq!(found.catalog.catalog_version, 2);
    }

    #[test]
    fn recovery_import_and_gc_preserve_stale_external_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let source_root = directory.path().join("sources");
        let destination = directory.path().join("restored-desktop");
        let recovery_path = directory.path().join("external.acm-recovery");
        let passphrase = "correct horse battery staple";
        let master = SecretKey([17; 32]);
        let owner = Identity::from_seed([18; 32]);
        let vault_id = "vault-desktop-recovery";
        let first = serde_json::to_vec(
            &sign_and_encrypt_catalog(
                &master,
                &owner,
                VaultCatalog {
                    catalog_version: 1,
                    vault_id: vault_id.into(),
                    owner_member_id: owner.member_id(),
                    previous_catalog_cid: None,
                    created_at: 100,
                    files: Vec::new(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let first_cid = cid(&first);
        let second = serde_json::to_vec(
            &sign_and_encrypt_catalog(
                &master,
                &owner,
                VaultCatalog {
                    catalog_version: 2,
                    vault_id: vault_id.into(),
                    owner_member_id: owner.member_id(),
                    previous_catalog_cid: Some(first_cid.clone()),
                    created_at: 101,
                    files: Vec::new(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let second_cid = cid(&second);
        let roots = (0..5)
            .map(|index| source_root.join(index.to_string()))
            .collect::<Vec<_>>();
        for root in &roots {
            let source = ObjectStore::new(root, 1024 * 1024).unwrap();
            source.put(&first_cid, &first).unwrap();
            source.put(&second_cid, &second).unwrap();
        }
        let kit = export(
            &RecoveryPayload {
                identity_seed: [18; 32],
                vault_master_key: master.0,
                community_ids: Vec::new(),
                control_plane_urls: Vec::new(),
                vaults: vec![RecoveryVaultPointer {
                    vault_id: vault_id.into(),
                    catalog_cid: first_cid.clone(),
                    catalog_version: 1,
                    owner_public_key: owner.public_key(),
                }],
            },
            passphrase.as_bytes(),
        )
        .unwrap();
        fs::write(&recovery_path, kit).unwrap();

        import_desktop_recovery_into(&destination, &recovery_path, &roots, passphrase).unwrap();
        let state = load_desktop_state(&destination).unwrap();
        assert_eq!(state.catalog_cid, second_cid);
        assert_eq!(state.catalog_version, 2);
        gc_desktop_vault_in(&destination, passphrase).unwrap();
        assert_eq!(desktop_restore(&destination, &first_cid).unwrap(), first);
    }

    #[test]
    fn retained_tombstone_restores_plaintext_in_backend() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().join("desktop");
        let output = directory.path().join("restored.txt");
        let passphrase = "correct horse battery staple";
        let owner = Identity::from_seed([28; 32]);
        let master = SecretKey([29; 32]);
        let file_key = SecretKey([30; 32]);
        let vault_id = "vault-retained-test";
        let file_id = "file-retained-test";
        let file_version_id = "file-retained-test-v1";
        let plaintext = b"retained desktop recovery";
        fs::create_dir_all(&data_dir).unwrap();
        save_stronghold_secrets(&data_dir, passphrase, &[28; 32], &master.0).unwrap();
        let aad = format!(
            "acm.chunk.v1|{vault_id}|{file_version_id}|0|{}",
            plaintext.len()
        );
        let chunk_blob = serde_json::to_vec(
            &arcane_mesh_core::crypto::encrypt(&file_key, plaintext, aad.as_bytes()).unwrap(),
        )
        .unwrap();
        let chunk_cid = desktop_replicate(&data_dir, &chunk_blob, 3).unwrap();
        let manifest = FileManifest {
            manifest_version: 1,
            file_id: file_id.into(),
            file_version_id: file_version_id.into(),
            relative_path: ".".into(),
            file_name: "retained.txt".into(),
            mime_type: "text/plain".into(),
            plaintext_size: plaintext.len() as u64,
            plaintext_hash: blake3::hash(plaintext).to_hex().to_string(),
            modified_at: 100,
            created_at: 100,
            file_key: file_key.0,
            ordered_chunk_cids: vec![chunk_cid],
            chunk_plaintext_lengths: vec![plaintext.len() as u32],
            padding_lengths: vec![0],
        };
        let manifest_blob =
            serde_json::to_vec(&encrypt_manifest(&master, vault_id, &manifest).unwrap()).unwrap();
        let manifest_cid = desktop_replicate(&data_dir, &manifest_blob, 5).unwrap();
        let timestamp = unix_now().unwrap();
        let catalog_blob = serde_json::to_vec(
            &sign_and_encrypt_catalog(
                &master,
                &owner,
                VaultCatalog {
                    catalog_version: 1,
                    vault_id: vault_id.into(),
                    owner_member_id: owner.member_id(),
                    previous_catalog_cid: None,
                    created_at: timestamp,
                    files: vec![CatalogFileVersion {
                        file_id: file_id.into(),
                        file_version_id: file_version_id.into(),
                        encrypted_manifest_cid: manifest_cid,
                        created_at: timestamp,
                        deleted_at: Some(timestamp),
                        retention_until: Some(timestamp + 3600),
                    }],
                },
            )
            .unwrap(),
        )
        .unwrap();
        let catalog_cid = desktop_replicate(&data_dir, &catalog_blob, 5).unwrap();
        save_desktop_state(
            &data_dir,
            &DesktopVaultState {
                format_version: 1,
                vault_id: vault_id.into(),
                recovery_path: data_dir.join("owner.acm-recovery").display().to_string(),
                catalog_cid,
                catalog_version: 1,
                owner_public_key: owner.public_key(),
            },
        )
        .unwrap();

        let restored = restore_desktop_file_to(&data_dir, file_id, passphrase, &output).unwrap();
        assert_eq!(restored.bytes, plaintext.len() as u64);
        assert_eq!(fs::read(output).unwrap(), plaintext);
    }
}
