use anyhow::{bail, Context, Result};
use arcane_mesh_core::{
    catalog::{
        decrypt_and_verify_catalog, decrypt_manifest, encrypt_manifest, sign_and_encrypt_catalog,
        CatalogFileVersion, FileManifest, SignedVaultCatalog, VaultCatalog,
    },
    cid,
    crypto::decrypt,
    crypto::SecretKey,
    identity::Identity,
    recovery::{export, import, RecoveryPayload, RecoveryVaultPointer},
    vault::encrypt_stream_each,
};
use arcane_mesh_node::StorageNode;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const STATE_ROOT: &str = ".acm";
const NODE_QUOTA: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct VaultState {
    format_version: u16,
    vault_id: String,
    recovery_path: String,
    catalog_cid: String,
    catalog_version: u64,
    owner_public_key: [u8; 32],
}

pub fn create(passphrase: &str) -> Result<()> {
    let root = Path::new(STATE_ROOT);
    if root.exists() {
        bail!("local vault already exists at {STATE_ROOT}");
    }
    fs::create_dir_all(root.join("nodes"))?;
    let mut identity_seed = [0_u8; 32];
    let mut vault_master_key = [0_u8; 32];
    OsRng.fill_bytes(&mut identity_seed);
    OsRng.fill_bytes(&mut vault_master_key);
    let owner = Identity::from_seed(identity_seed);
    let vault_id = format!("vault_{}", random_hex(16));
    let recovery_path = root.join("owner.acm-recovery");
    let catalog_blob = serde_json::to_vec(&sign_and_encrypt_catalog(
        &SecretKey(vault_master_key),
        &owner,
        VaultCatalog {
            catalog_version: 1,
            vault_id: vault_id.clone(),
            owner_member_id: owner.member_id(),
            previous_catalog_cid: None,
            created_at: now()?,
            files: Vec::new(),
        },
    )?)?;
    let catalog_cid = replicate(&catalog_blob, 5)?;
    let state = VaultState {
        format_version: 1,
        vault_id,
        recovery_path: recovery_path.display().to_string(),
        catalog_cid,
        catalog_version: 1,
        owner_public_key: owner.public_key(),
    };
    write_private_new(
        &recovery_path,
        &recovery_bytes(&state, identity_seed, vault_master_key, passphrase)?,
    )?;
    save_state(&state)?;
    println!("status=created");
    println!("recovery_kit={}", recovery_path.display());
    println!("catalog_replicas=5");
    Ok(())
}

pub fn recover(
    recovery_path: &Path,
    source_roots: &[std::path::PathBuf],
    passphrase: &str,
) -> Result<()> {
    let root = Path::new(STATE_ROOT);
    if root.exists() {
        bail!("local vault already exists at {STATE_ROOT}");
    }
    let recovery_bytes = fs::read(recovery_path)?;
    let recovered = import(&recovery_bytes, passphrase.as_bytes())?;
    let checkpoint = recovered
        .vaults
        .first()
        .context("Recovery Kit contains no vault checkpoint")?;
    let sources = source_roots
        .iter()
        .enumerate()
        .map(|(index, source)| {
            StorageNode::new(
                format!("recovery-source-{index}"),
                format!("recovery-domain-{index}"),
                source,
                u64::MAX,
            )
            .map(Arc::new)
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?;
    let master = SecretKey(recovered.vault_master_key);
    let (catalog_cid, catalog) = discover_latest_catalog(checkpoint, &master, &sources)?;

    fs::create_dir_all(root.join("nodes"))?;
    let internal_recovery = root.join("owner.acm-recovery");
    write_private_new(&internal_recovery, &recovery_bytes)?;
    let state = VaultState {
        format_version: 1,
        vault_id: checkpoint.vault_id.clone(),
        recovery_path: internal_recovery.display().to_string(),
        catalog_cid: catalog_cid.clone(),
        catalog_version: catalog.catalog.catalog_version,
        owner_public_key: checkpoint.owner_public_key,
    };
    replicate_recovered_catalog_chain(&state, &master, &sources)?;
    for version in &catalog.catalog.files {
        let manifest_blob = restore_from_sources(&sources, &version.encrypted_manifest_cid)?;
        if replicate(&manifest_blob, 5)? != version.encrypted_manifest_cid {
            bail!("recovered manifest CID mismatch");
        }
        let manifest = decrypt_manifest(
            &master,
            &state.vault_id,
            &version.file_id,
            &version.file_version_id,
            &serde_json::from_slice(&manifest_blob)?,
        )?;
        for object_cid in manifest.ordered_chunk_cids {
            let blob = restore_from_sources(&sources, &object_cid)?;
            if replicate(&blob, 3)? != object_cid {
                bail!("recovered chunk CID mismatch");
            }
        }
    }
    save_state(&state)?;
    refresh_recovery(&state, &recovered, passphrase)?;
    println!("status=recovered");
    println!("catalog_version={}", state.catalog_version);
    println!("files={}", catalog.catalog.files.len());
    Ok(())
}

fn replicate_recovered_catalog_chain(
    state: &VaultState,
    master: &SecretKey,
    sources: &[Arc<StorageNode>],
) -> Result<()> {
    let mut catalog_cid = state.catalog_cid.clone();
    let mut version = state.catalog_version;
    loop {
        let blob = restore_from_sources(sources, &catalog_cid)?;
        if replicate(&blob, 5)? != catalog_cid {
            bail!("recovered catalog CID mismatch");
        }
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
            bail!("catalog history underflow");
        }
        catalog_cid = previous;
        version -= 1;
    }
    Ok(())
}

fn restore_from_sources(sources: &[Arc<StorageNode>], object_cid: &str) -> Result<Vec<u8>> {
    for source in sources {
        if let Ok(bytes) = source.get(object_cid) {
            return Ok(bytes);
        }
    }
    bail!("recovery source does not contain {object_cid}")
}

fn discover_latest_catalog(
    checkpoint: &RecoveryVaultPointer,
    master: &SecretKey,
    sources: &[Arc<StorageNode>],
) -> Result<(String, SignedVaultCatalog)> {
    let checkpoint_blob = restore_from_sources(sources, &checkpoint.catalog_cid)?;
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
    let mut current_version = checkpoint.catalog_version;
    let mut current_cid = checkpoint.catalog_cid.clone();
    loop {
        let next_version = current_version + 1;
        let Some((next_cid, next_catalog)) = candidates.get(&next_version) else {
            break;
        };
        if next_catalog.catalog.previous_catalog_cid.as_deref() != Some(&current_cid) {
            break;
        }
        current_version = next_version;
        current_cid = next_cid.clone();
    }
    let (_, catalog) = candidates
        .remove(&current_version)
        .context("validated catalog checkpoint disappeared")?;
    Ok((current_cid, catalog))
}

pub fn add(input: &Path, passphrase: &str) -> Result<()> {
    let canonical = fs::canonicalize(input)?;
    if !canonical.is_file() || fs::symlink_metadata(input)?.file_type().is_symlink() {
        bail!("vault add currently accepts one regular non-symlink file");
    }
    let mut state = load_state()?;
    let recovered = load_recovery(&state, passphrase)?;
    let master = SecretKey(recovered.vault_master_key);
    let owner = Identity::from_seed(recovered.identity_seed);
    let mut catalog = load_catalog(&state, &master)?.catalog;
    let file_id = format!("file_{}", random_hex(16));
    let file_version_id = format!("{file_id}_v1");
    let file_key = SecretKey::random();
    let mut file = File::open(&canonical)?;
    let mut hashing_reader = HashingReader::new(&mut file);
    let mut chunk_cids = Vec::new();
    let mut lengths = Vec::new();
    encrypt_stream_each(
        &mut hashing_reader,
        &file_key,
        &state.vault_id,
        &file_version_id,
        |chunk| {
            let blob = serde_json::to_vec(&chunk.envelope).map_err(std::io::Error::other)?;
            let replicated = replicate(&blob, 3).map_err(std::io::Error::other)?;
            if replicated != chunk.cid {
                return Err(std::io::Error::other("chunk CID drift").into());
            }
            chunk_cids.push(chunk.cid);
            lengths.push(chunk.plaintext_length);
            Ok(())
        },
    )?;
    let metadata = fs::metadata(&canonical)?;
    let timestamp = now()?;
    let manifest = FileManifest {
        manifest_version: 1,
        file_id: file_id.clone(),
        file_version_id: file_version_id.clone(),
        relative_path: ".".into(),
        file_name: canonical
            .file_name()
            .and_then(|value| value.to_str())
            .context("file name is not valid UTF-8")?
            .into(),
        mime_type: "application/octet-stream".into(),
        plaintext_size: metadata.len(),
        plaintext_hash: hashing_reader.finalize(),
        modified_at: metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map_or(timestamp, |value| value.as_secs() as i64),
        created_at: timestamp,
        file_key: file_key.0,
        ordered_chunk_cids: chunk_cids,
        chunk_plaintext_lengths: lengths.clone(),
        padding_lengths: vec![0; lengths.len()],
    };
    let manifest_cid = replicate(
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
    let catalog_blob = serde_json::to_vec(&sign_and_encrypt_catalog(&master, &owner, catalog)?)?;
    state.catalog_cid = replicate(&catalog_blob, 5)?;
    state.catalog_version += 1;
    save_state(&state)?;
    refresh_recovery(&state, &recovered, passphrase)?;
    println!("status=stored");
    println!("file_id={file_id}");
    println!("data_replicas=3");
    println!("metadata_replicas=5");
    Ok(())
}

pub fn list(passphrase: &str) -> Result<()> {
    let state = load_state()?;
    let recovered = load_recovery(&state, passphrase)?;
    let master = SecretKey(recovered.vault_master_key);
    let catalog = load_catalog(&state, &master)?;
    for version in catalog
        .catalog
        .files
        .iter()
        .filter(|version| version.deleted_at.is_none())
    {
        let manifest = load_manifest(&state, &master, version)?;
        println!(
            "file_id={} size={} name={}",
            manifest.file_id, manifest.plaintext_size, manifest.file_name
        );
    }
    Ok(())
}

pub fn restore(file_id: &str, output: &Path, passphrase: &str) -> Result<()> {
    let state = load_state()?;
    let recovered = load_recovery(&state, passphrase)?;
    let master = SecretKey(recovered.vault_master_key);
    let catalog = load_catalog(&state, &master)?;
    let version = catalog
        .catalog
        .files
        .iter()
        .rev()
        .find(|version| {
            version.file_id == file_id
                && (version.deleted_at.is_none()
                    || version
                        .retention_until
                        .is_some_and(|until| until >= now().unwrap_or(0)))
        })
        .context("active or retained file not found")?;
    let manifest = load_manifest(&state, &master, version)?;
    let temporary = output.with_extension("acm-partial");
    let mut writer = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let file_key = SecretKey(manifest.file_key);
    let mut restored_hasher = blake3::Hasher::new();
    for (index, object_cid) in manifest.ordered_chunk_cids.iter().enumerate() {
        let blob = restore_object(object_cid)?;
        if cid(&blob) != *object_cid {
            bail!("encrypted chunk CID mismatch");
        }
        let envelope = serde_json::from_slice(&blob)?;
        let aad = format!(
            "acm.chunk.v1|{}|{}|{}|{}",
            state.vault_id, version.file_version_id, index, manifest.chunk_plaintext_lengths[index]
        );
        let plaintext = zeroize::Zeroizing::new(decrypt(&file_key, &envelope, aad.as_bytes())?);
        if plaintext.len() != manifest.chunk_plaintext_lengths[index] as usize {
            bail!("restored chunk length mismatch");
        }
        restored_hasher.update(&plaintext);
        writer.write_all(&plaintext)?;
    }
    writer.sync_all()?;
    drop(writer);
    let restored_hash = restored_hasher.finalize().to_hex().to_string();
    if restored_hash != manifest.plaintext_hash {
        fs::remove_file(&temporary)?;
        bail!("restored plaintext hash mismatch");
    }
    fs::rename(&temporary, output)?;
    println!("status=restored");
    println!("output={}", output.display());
    Ok(())
}

pub fn delete(file_id: &str, passphrase: &str) -> Result<()> {
    let mut state = load_state()?;
    let recovered = load_recovery(&state, passphrase)?;
    let master = SecretKey(recovered.vault_master_key);
    let owner = Identity::from_seed(recovered.identity_seed);
    let mut catalog = load_catalog(&state, &master)?.catalog;
    let timestamp = now()?;
    let version = catalog
        .files
        .iter_mut()
        .rev()
        .find(|version| version.file_id == file_id && version.deleted_at.is_none())
        .context("active file not found")?;
    version.deleted_at = Some(timestamp);
    version.retention_until = Some(timestamp + 30 * 86400);
    catalog.previous_catalog_cid = Some(state.catalog_cid);
    catalog.catalog_version += 1;
    catalog.created_at = timestamp;
    let catalog_blob = serde_json::to_vec(&sign_and_encrypt_catalog(&master, &owner, catalog)?)?;
    state.catalog_cid = replicate(&catalog_blob, 5)?;
    state.catalog_version += 1;
    save_state(&state)?;
    refresh_recovery(&state, &recovered, passphrase)?;
    println!("status=tombstoned");
    println!("retention_days=30");
    println!("physical_blobs_may_remain_until_gc=true");
    Ok(())
}

pub fn gc(passphrase: &str) -> Result<()> {
    let mut state = load_state()?;
    let recovered = load_recovery(&state, passphrase)?;
    let master = SecretKey(recovered.vault_master_key);
    let owner = Identity::from_seed(recovered.identity_seed);
    let mut catalog = load_catalog(&state, &master)?.catalog;
    let timestamp = now()?;
    let mut retained_objects = catalog_chain_cids(&state, &master)?;
    let mut expired = Vec::new();
    for version in &catalog.files {
        let manifest = load_manifest(&state, &master, version)?;
        let is_expired = version
            .retention_until
            .is_some_and(|retention_until| retention_until < timestamp);
        if is_expired {
            expired.push((
                version.encrypted_manifest_cid.clone(),
                manifest.ordered_chunk_cids,
            ));
        } else {
            retained_objects.insert(version.encrypted_manifest_cid.clone());
            retained_objects.extend(manifest.ordered_chunk_cids);
        }
    }
    let mut removed = 0_u64;
    for (manifest_cid, chunks) in expired {
        for object_cid in std::iter::once(manifest_cid).chain(chunks) {
            if retained_objects.contains(&object_cid) {
                continue;
            }
            for node in nodes()? {
                if node.delete(&object_cid).unwrap_or(false) {
                    removed += 1;
                }
            }
        }
    }
    let original_len = catalog.files.len();
    catalog.files.retain(|version| {
        version
            .retention_until
            .is_none_or(|until| until >= timestamp)
    });
    if catalog.files.len() != original_len {
        catalog.previous_catalog_cid = Some(state.catalog_cid);
        catalog.catalog_version += 1;
        catalog.created_at = timestamp;
        state.catalog_cid = replicate(
            &serde_json::to_vec(&sign_and_encrypt_catalog(&master, &owner, catalog)?)?,
            5,
        )?;
        state.catalog_version += 1;
        save_state(&state)?;
        refresh_recovery(&state, &recovered, passphrase)?;
    }
    retained_objects.extend(catalog_chain_cids(&state, &master)?);
    for node in nodes()? {
        for object_cid in node.list_cids()? {
            if !retained_objects.contains(&object_cid) && node.delete(&object_cid)? {
                removed += 1;
            }
        }
    }
    println!("status=gc-complete");
    println!("replicas_removed={removed}");
    Ok(())
}

pub fn verify(passphrase: &str) -> Result<()> {
    let state = load_state()?;
    let recovered = load_recovery(&state, passphrase)?;
    let master = SecretKey(recovered.vault_master_key);
    let catalog = load_catalog(&state, &master)?;
    let mut objects = vec![(state.catalog_cid.clone(), 5_usize)];
    for version in &catalog.catalog.files {
        objects.push((version.encrypted_manifest_cid.clone(), 5));
        let manifest = load_manifest(&state, &master, version)?;
        objects.extend(
            manifest
                .ordered_chunk_cids
                .into_iter()
                .map(|object_cid| (object_cid, 3)),
        );
    }
    for (object_cid, target) in objects {
        let healthy = healthy_replica_count(&object_cid)?;
        if healthy < target {
            bail!("{object_cid} has {healthy}/{target} healthy replicas");
        }
    }
    println!("status=verified");
    println!("catalog_version={}", state.catalog_version);
    Ok(())
}

fn nodes() -> Result<Vec<Arc<StorageNode>>> {
    (0..6)
        .map(|index| {
            StorageNode::new(
                format!("local-{index}"),
                format!("local-domain-{index}"),
                Path::new(STATE_ROOT).join("nodes").join(index.to_string()),
                NODE_QUOTA,
            )
            .map(Arc::new)
            .map_err(Into::into)
        })
        .collect()
}

fn replicate(bytes: &[u8], target: usize) -> Result<String> {
    let object_cid = cid(bytes);
    let mut stored = 0;
    for node in nodes()? {
        if node.put(&object_cid, bytes).is_ok() {
            stored += 1;
        }
        if stored == target {
            return Ok(object_cid);
        }
    }
    bail!("only {stored}/{target} replicas could be written")
}

fn restore_object(object_cid: &str) -> Result<Vec<u8>> {
    for node in nodes()? {
        if let Ok(bytes) = node.get(object_cid) {
            return Ok(bytes);
        }
    }
    bail!("no healthy replica for {object_cid}")
}

fn healthy_replica_count(object_cid: &str) -> Result<usize> {
    Ok(nodes()?
        .into_iter()
        .filter(|node| node.get(object_cid).is_ok())
        .count())
}

fn load_catalog(state: &VaultState, master: &SecretKey) -> Result<SignedVaultCatalog> {
    Ok(decrypt_and_verify_catalog(
        master,
        &state.vault_id,
        state.catalog_version,
        &state.owner_public_key,
        &serde_json::from_slice(&restore_object(&state.catalog_cid)?)?,
    )?)
}

fn catalog_chain_cids(state: &VaultState, master: &SecretKey) -> Result<HashSet<String>> {
    let mut retained = HashSet::new();
    let mut catalog_cid = state.catalog_cid.clone();
    let mut version = state.catalog_version;
    loop {
        if !retained.insert(catalog_cid.clone()) {
            bail!("catalog history contains a cycle");
        }
        let blob = restore_object(&catalog_cid)?;
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
            bail!("catalog history underflow");
        }
        catalog_cid = previous;
        version -= 1;
    }
    Ok(retained)
}

fn load_manifest(
    state: &VaultState,
    master: &SecretKey,
    version: &CatalogFileVersion,
) -> Result<FileManifest> {
    Ok(decrypt_manifest(
        master,
        &state.vault_id,
        &version.file_id,
        &version.file_version_id,
        &serde_json::from_slice(&restore_object(&version.encrypted_manifest_cid)?)?,
    )?)
}

fn load_recovery(state: &VaultState, passphrase: &str) -> Result<RecoveryPayload> {
    Ok(import(
        &fs::read(&state.recovery_path)
            .with_context(|| format!("could not read {}", state.recovery_path))?,
        passphrase.as_bytes(),
    )?)
}

fn load_state() -> Result<VaultState> {
    let state: VaultState = serde_json::from_slice(
        &fs::read(Path::new(STATE_ROOT).join("state.json"))
            .context("local vault is not initialized")?,
    )?;
    if state.format_version != 1 {
        bail!("unsupported local vault state");
    }
    Ok(state)
}

fn save_state(state: &VaultState) -> Result<()> {
    let path = Path::new(STATE_ROOT).join("state.json");
    let temporary = path.with_extension("partial");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(state)?)?;
    file.sync_all()?;
    fs::rename(temporary, &path)?;
    File::open(Path::new(STATE_ROOT))?.sync_all()?;
    Ok(())
}

fn recovery_bytes(
    state: &VaultState,
    identity_seed: [u8; 32],
    vault_master_key: [u8; 32],
    passphrase: &str,
) -> Result<Vec<u8>> {
    Ok(export(
        &RecoveryPayload {
            identity_seed,
            vault_master_key,
            community_ids: vec!["local-community".into()],
            control_plane_urls: vec!["http://127.0.0.1:8787".into()],
            vaults: vec![RecoveryVaultPointer {
                vault_id: state.vault_id.clone(),
                catalog_cid: state.catalog_cid.clone(),
                catalog_version: state.catalog_version,
                owner_public_key: state.owner_public_key,
            }],
        },
        passphrase.as_bytes(),
    )?)
}

fn refresh_recovery(
    state: &VaultState,
    recovered: &RecoveryPayload,
    passphrase: &str,
) -> Result<()> {
    let path = Path::new(&state.recovery_path);
    let temporary = path.with_extension("partial");
    let bytes = recovery_bytes(
        state,
        recovered.identity_seed,
        recovered.vault_master_key,
        passphrase,
    )?;
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
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn random_hex(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

struct HashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    fn finalize(&self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CurrentDirectory(std::path::PathBuf);

    impl Drop for CurrentDirectory {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).unwrap();
        }
    }

    #[test]
    fn stale_external_kit_discovers_latest_catalog_and_recovers() {
        let original = std::env::current_dir().unwrap();
        let _restore_directory = CurrentDirectory(original);
        let temporary = tempfile::tempdir().unwrap();
        std::env::set_current_dir(temporary.path()).unwrap();
        let passphrase = "correct horse battery staple";
        create(passphrase).unwrap();
        let external_kit = temporary.path().join("external.acm-recovery");
        fs::copy(".acm/owner.acm-recovery", &external_kit).unwrap();
        fs::write("fixture.txt", b"recover me from storage nodes").unwrap();
        add(Path::new("fixture.txt"), passphrase).unwrap();
        gc(passphrase).unwrap();
        let state = load_state().unwrap();
        let recovered = load_recovery(&state, passphrase).unwrap();
        let catalog = load_catalog(&state, &SecretKey(recovered.vault_master_key))
            .unwrap()
            .catalog;
        let file_id = catalog.files[0].file_id.clone();
        let source_root = temporary.path().join("source-nodes");
        fs::rename(".acm/nodes", &source_root).unwrap();
        fs::remove_dir_all(".acm").unwrap();
        let sources = (0..6)
            .map(|index| source_root.join(index.to_string()))
            .collect::<Vec<_>>();
        recover(&external_kit, &sources, passphrase).unwrap();
        restore(&file_id, Path::new("restored.txt"), passphrase).unwrap();
        assert_eq!(
            fs::read("restored.txt").unwrap(),
            b"recover me from storage nodes"
        );
        assert_eq!(load_state().unwrap().catalog_version, 2);
    }
}
