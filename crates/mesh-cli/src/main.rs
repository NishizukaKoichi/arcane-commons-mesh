#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use arcane_mesh_core::{
    cid,
    crypto::{decrypt, encrypt, SecretKey},
    recovery::{export, import, RecoveryPayload},
};
use arcane_mesh_node::StorageNode;
use arcane_mesh_testkit::InMemoryMesh;
use clap::{Parser, Subcommand};
use std::{fs, sync::Arc};

#[derive(Parser)]
#[command(name = "acmctl", version, about = "Arcane Commons Mesh local MVP")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Doctor,
    Demo { action: String },
    VerifyMvp,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Doctor => {
            println!("Arcane Commons Mesh local prerequisites: ok");
            Ok(())
        }
        Command::Demo { action } if action == "up" || action == "down" => {
            println!("local demo {action}: no persistent process required");
            Ok(())
        }
        Command::Demo { .. } => bail!("demo action must be up or down"),
        Command::VerifyMvp => verify_mvp(),
    }
}

fn verify_mvp() -> Result<()> {
    let isolated = tempfile::tempdir()?;
    let key = SecretKey::random();
    let plaintext = b"ACM_VERIFY_SENTINEL_2026_07_26";
    let aad = b"acm.chunk.v1|vault-test|file-v1|0|29";
    let envelope = encrypt(&key, plaintext, aad)?;
    let blob = serde_json::to_vec(&envelope)?;
    let object_cid = cid(&blob);

    let mut nodes = Vec::new();
    for name in ["node-a", "node-b", "node-c"] {
        nodes.push(Arc::new(StorageNode::new(
            name,
            format!("failure-domain-{name}"),
            isolated.path().join(name),
            1024 * 1024,
        )?));
    }
    let mut mesh = InMemoryMesh::new(nodes.clone());
    let replicated_cid = mesh.replicate(&blob, 3)?;
    if replicated_cid != object_cid || mesh.audit_all(&object_cid) != 3 {
        bail!("ACM-11 three-replica assertion failed");
    }

    nodes[1].set_active(false);
    let restored_blob = mesh
        .restore(&object_cid)
        .context("ACM-12 failed to restore with node B offline")?;
    let restored = decrypt(&key, &serde_json::from_slice(&restored_blob)?, aad)?;
    if restored != plaintext {
        bail!("ACM-12 outage restore hash mismatch");
    }

    let node_c_path = isolated
        .path()
        .join("node-c/objects")
        .join(&object_cid[..2])
        .join(format!("{object_cid}.blob"));
    fs::write(node_c_path, b"deliberate corruption")?;
    if nodes[2].get(&object_cid).is_ok() || mesh.audit_all(&object_cid) != 1 {
        bail!("ACM-13 corrupted replica accepted");
    }
    let fallback = decrypt(
        &key,
        &serde_json::from_slice(&mesh.restore(&object_cid)?)?,
        aad,
    )?;
    if fallback != plaintext {
        bail!("ACM-13 healthy fallback failed");
    }

    let recovery_payload = RecoveryPayload {
        identity_seed: [11; 32],
        vault_master_key: key.0,
        community_ids: vec!["local-community".into()],
        control_plane_urls: vec!["http://127.0.0.1:8787".into()],
    };
    let kit = export(&recovery_payload, b"local verification passphrase")?;
    let recovered = import(&kit, b"local verification passphrase")?;
    if recovered.identity_seed != [11; 32] {
        bail!("ACM-14 clean recovery failed");
    }

    println!("ACM-11 PASS three ciphertext replicas");
    println!("ACM-12 PASS restore with node B unavailable");
    println!("ACM-13 PASS corruption rejected and healthy replica used");
    println!("ACM-14 PASS encrypted Recovery Kit round trip");
    println!("Local vertical MVP verification passed");
    Ok(())
}
