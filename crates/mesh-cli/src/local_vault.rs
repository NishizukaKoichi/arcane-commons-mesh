use anyhow::{bail, Context, Result};
use arcane_mesh_core::{
    catalog::{
        decrypt_and_verify_catalog, decrypt_manifest, encrypt_manifest, sign_and_encrypt_catalog,
        CatalogFileVersion, FileManifest, SignedVaultCatalog, VaultCatalog,
    },
    cid,
    crypto::SecretKey,
    identity::Identity,
    recovery::{export, import, RecoveryPayload},
    vault::{decrypt_stream, encrypt_stream_each, EncryptedChunk},
};
use arcane_mesh_node::StorageNode;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
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
    write_private_new(
        &recovery_path,
        &export(
            &RecoveryPayload {
                identity_seed,
                vault_master_key,
                community_ids: vec!["local-community".into()],
                control_plane_urls: vec!["http://127.0.0.1:8787".into()],
            },
            passphrase.as_bytes(),
        )?,
    )?;
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
    save_state(&VaultState {
        format_version: 1,
        vault_id,
        recovery_path: recovery_path.display().to_string(),
        catalog_cid,
        catalog_version: 1,
        owner_public_key: owner.public_key(),
    })?;
    println!("status=created");
    println!("recovery_kit={}", recovery_path.display());
    println!("catalog_replicas=5");
    Ok(())
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
        .find(|version| version.file_id == file_id && version.deleted_at.is_none())
        .context("active file not found")?;
    let manifest = load_manifest(&state, &master, version)?;
    let temporary = output.with_extension("acm-partial");
    let mut writer = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let chunks = manifest
        .ordered_chunk_cids
        .iter()
        .enumerate()
        .map(|(index, object_cid)| {
            let blob = restore_object(object_cid)?;
            Ok(EncryptedChunk {
                index: index as u64,
                plaintext_length: manifest.chunk_plaintext_lengths[index],
                cid: object_cid.clone(),
                envelope: serde_json::from_slice(&blob)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    decrypt_stream(
        &chunks,
        &mut writer,
        &SecretKey(manifest.file_key),
        &state.vault_id,
        &version.file_version_id,
    )?;
    writer.sync_all()?;
    drop(writer);
    let restored_hash = hash_file(&temporary)?;
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
    println!("status=tombstoned");
    println!("retention_days=30");
    println!("physical_blobs_may_remain_until_gc=true");
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
    fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    fs::rename(temporary, path)?;
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

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
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
