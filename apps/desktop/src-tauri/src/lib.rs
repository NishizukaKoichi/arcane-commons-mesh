#![forbid(unsafe_code)]

use arcane_mesh_core::{
    catalog::{
        decrypt_and_verify_catalog, decrypt_manifest, encrypt_manifest, sign_and_encrypt_catalog,
        CatalogFileVersion, FileManifest, VaultCatalog,
    },
    cid,
    crypto::{decrypt, SecretKey},
    identity::Identity,
    recovery::{export, import, RecoveryPayload},
    store::ObjectStore,
    vault::encrypt_stream_each,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
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
    let download = app
        .path()
        .download_dir()
        .map_err(|error| error.to_string())?;
    let path = unique_recovery_path(&download);
    let bytes = recovery_bytes(&passphrase).map_err(|error| error.to_string())?;
    write_private_new(&path, &bytes).map_err(|error| error.to_string())?;
    initialize_desktop_vault(&app, &path, &passphrase).map_err(|error| error.to_string())?;
    Ok(RecoveryExport {
        path: path.display().to_string(),
        bytes: bytes.len(),
    })
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
            add_vault_file,
            list_vault_files,
            restore_vault_file,
            delete_vault_file,
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
    Ok(DesktopFile {
        file_id,
        name,
        size_bytes: metadata.len(),
        safe_replicas: "3/3".into(),
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
        .filter(|version| version.deleted_at.is_none())
        .map(|version| {
            let manifest = desktop_manifest(&data_dir, &state, &master, version)?;
            Ok(DesktopFile {
                file_id: manifest.file_id,
                name: manifest.file_name,
                size_bytes: manifest.plaintext_size,
                safe_replicas: format!(
                    "{}/3",
                    desktop_replica_count(&data_dir, &manifest.ordered_chunk_cids)?
                ),
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
    let (state, master, catalog) = open_desktop_catalog(&data_dir, passphrase)?;
    let version = catalog
        .files
        .iter()
        .rev()
        .find(|version| version.file_id == file_id && version.deleted_at.is_none())
        .ok_or_else(|| anyhow::anyhow!("復元できるファイルがありません"))?;
    let manifest = desktop_manifest(&data_dir, &state, &master, version)?;
    let download = app.path().download_dir()?;
    let output = unique_restored_path(&download, &manifest.file_name);
    let temporary = output.with_extension("acm-partial");
    let mut writer = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let file_key = SecretKey(manifest.file_key);
    let mut hasher = blake3::Hasher::new();
    for (index, object_cid) in manifest.ordered_chunk_cids.iter().enumerate() {
        let blob = desktop_restore(&data_dir, object_cid)?;
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
    fs::rename(&temporary, &output)?;
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
    let (identity_seed, _) = load_stronghold_secrets(&data_dir, passphrase)?;
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
    save_desktop_state(&data_dir, &state)
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
    for node in desktop_nodes(data_dir)? {
        if let Ok(bytes) = node.get(object_cid) {
            return Ok(bytes);
        }
    }
    anyhow::bail!("利用できる安全な複製がありません")
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
    fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    fs::rename(temporary, destination)?;
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
}
