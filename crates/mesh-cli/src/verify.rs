use anyhow::{bail, Context, Result};
use arcane_mesh_control::{Community, LocalControlPlane, Member, Proposal, Vote, VoteChoice};
use arcane_mesh_core::{
    audit::{merkle_root, verify_chain},
    cid,
    credit::{CreditEntry, CreditLedger, CreditReason},
    crypto::{decrypt, encrypt, SecretKey},
    identity::{Identity, MembershipClaims},
    recovery::{export, import, RecoveryPayload},
};
use arcane_mesh_node::StorageNode;
use arcane_mesh_testkit::InMemoryMesh;
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::Duration,
};

const CONTENT_SENTINEL: &[u8] = b"ACM_CONTENT_SENTINEL_2026_07_26_7f98a21d";
const FILE_NAME_SENTINEL: &str = "ACM_FILENAME_SENTINEL_7f98a21d.txt";
const OPENAPI: &str = include_str!("../../../apps/api/openapi.yaml");
const MIGRATION: &str = include_str!("../../../apps/api/migrations/0001_initial.sql");

#[derive(Serialize)]
struct VerificationStep {
    id: u8,
    name: &'static str,
    status: &'static str,
}

#[derive(Serialize)]
struct VerificationReport {
    format_version: u16,
    seed: &'static str,
    transport: &'static str,
    external_network_required: bool,
    steps: Vec<VerificationStep>,
    acceptance_ids: Vec<&'static str>,
    result: &'static str,
}

pub fn verify_mvp() -> Result<()> {
    let isolated = tempfile::tempdir()?;
    let owner_root = isolated.path().join("owner");
    let node_root = isolated.path().join("nodes");
    let recovery_root = isolated.path().join("clean-recovery");
    fs::create_dir_all(&owner_root)?;
    fs::create_dir_all(&node_root)?;
    fs::create_dir_all(&recovery_root)?;
    let mut process_nodes = ProcessNodes::start(isolated.path().join("process-nodes"))?;
    process_nodes.assert_running()?;

    let fixture_path = owner_root.join(FILE_NAME_SENTINEL);
    fs::write(&fixture_path, CONTENT_SENTINEL)?;
    pass(1, "deterministic fixture created");

    let key = SecretKey::random();
    let aad = format!(
        "acm.chunk.v1|vault-test|file-v1|0|{}",
        CONTENT_SENTINEL.len()
    );
    let envelope = encrypt(&key, CONTENT_SENTINEL, aad.as_bytes())?;
    let blob = serde_json::to_vec(&envelope)?;
    let object_cid = cid(&blob);
    pass(2, "fixture encrypted on owner device");

    let nodes: Vec<_> = ["node-a", "node-b", "node-c", "node-d"]
        .into_iter()
        .map(|name| {
            StorageNode::new(
                name,
                format!("failure-domain-{name}"),
                node_root.join(name),
                1024 * 1024,
            )
            .map(Arc::new)
        })
        .collect::<Result<_, _>>()?;
    let mut mesh = InMemoryMesh::new(nodes.clone());
    let replicated_cid = mesh.replicate(&blob, 3)?;
    if replicated_cid != object_cid || mesh.audit_all(&object_cid) != 3 {
        bail!("step 3: three-replica assertion failed");
    }
    process_nodes.assert_running()?;
    pass(
        3,
        "ciphertext replicated to three failure domains; four node processes are live",
    );

    fs::remove_file(&fixture_path)?;
    if fixture_path.exists() {
        bail!("step 4: owner fixture was not isolated");
    }
    pass(4, "original fixture isolated");

    nodes[1].set_active(false);
    if nodes[1].get(&object_cid).is_ok() {
        bail!("step 5: stopped node still served data");
    }
    pass(5, "node B stopped and GET rejected");

    let restored_blob = mesh
        .restore(&object_cid)
        .context("step 6: restore with node B offline")?;
    let restored = decrypt(
        &key,
        &serde_json::from_slice(&restored_blob)?,
        aad.as_bytes(),
    )?;
    if restored != CONTENT_SENTINEL {
        bail!("step 6: outage restore plaintext hash mismatch");
    }
    pass(6, "restored through one-node outage");

    let node_c_path = object_path(nodes[2].root(), &object_cid);
    let mut corrupt = fs::read(&node_c_path)?;
    corrupt[0] ^= 1;
    fs::write(&node_c_path, corrupt)?;
    if nodes[2].get(&object_cid).is_ok() {
        bail!("step 7: corrupted replica was accepted");
    }
    pass(7, "one ciphertext byte deliberately corrupted");

    if mesh.audit_all(&object_cid) != 1 {
        bail!("step 8: corrupt/offline replicas were not marked unhealthy");
    }
    let fallback = decrypt(
        &key,
        &serde_json::from_slice(&mesh.restore(&object_cid)?)?,
        aad.as_bytes(),
    )?;
    if fallback != CONTENT_SENTINEL {
        bail!("step 8: healthy fallback failed");
    }
    nodes[1].set_active(true);
    if mesh.repair(&object_cid, 3)? < 3 {
        bail!("step 8: repair did not restore target");
    }
    pass(
        8,
        "corruption rejected, fallback restored, replicas repaired",
    );

    let (mut control, root, alice, alice_member) = control_plane()?;
    let earned = CreditLedger::physical_storage_cost(blob.len() as u64, 1, 3600)?;
    control.record_credit(
        &alice.member_id(),
        CreditEntry {
            idempotency_key: "audit-earned-node-a".into(),
            milli_gib_hour: earned,
            reason: CreditReason::AuditedStorageEarned,
            occurred_at: 200,
            expires_at: Some(200 + 90 * 24 * 3600),
        },
    )?;
    if control.credit_balance(&alice.member_id(), 201)? != earned {
        bail!("step 9: provider credit was not earned exactly once");
    }
    pass(9, "audited provider credit increased");

    control.record_credit(
        &alice.member_id(),
        CreditEntry {
            idempotency_key: "consume-owner-object".into(),
            milli_gib_hour: -CreditLedger::physical_storage_cost(blob.len() as u64, 3, 3600)?,
            reason: CreditReason::ReplicatedStorageConsumed,
            occurred_at: 202,
            expires_at: None,
        },
    )?;
    if control.credit_balance(&alice.member_id(), 203)? >= earned {
        bail!("step 10: owner credit did not decrease");
    }
    pass(10, "owner replicated-storage credit consumed");

    for forbidden in [
        "/transfer",
        "/buy",
        "/sell",
        "/exchange",
        "/wallet",
        "/token",
    ] {
        if OPENAPI.to_ascii_lowercase().contains(forbidden) {
            bail!("step 11: forbidden financial route found: {forbidden}");
        }
    }
    pass(11, "financial and credit-transfer routes absent");

    let bob = Identity::from_seed([3; 32]);
    let bob_member = member(&root, &bob, 2, &["member"]);
    control.add_member(bob_member, 210)?;
    control.create_proposal(
        Proposal {
            proposal_id: "proposal-one-person-one-vote".into(),
            title: "Audit interval".into(),
            body: "Use six-hour audit interval".into(),
            created_by_member_id: alice.member_id(),
            opens_at: 220,
            closes_at: 400,
            quorum_percent: 20,
            threshold_percent: 50,
        },
        215,
    )?;
    for (choice, cast_at) in [(VoteChoice::Yes, 230), (VoteChoice::No, 240)] {
        let mut vote = Vote {
            proposal_id: "proposal-one-person-one-vote".into(),
            member_id: bob.member_id(),
            choice,
            cast_at,
            member_signature: Vec::new(),
        };
        vote.member_signature = bob.sign(&vote.signing_bytes()).to_vec();
        control.cast_vote(vote)?;
    }
    let votes = control.vote_result("proposal-one-person-one-vote")?;
    if (votes.yes, votes.no, control.vote_history_len()) != (0, 1, 2) {
        bail!("step 12: duplicate vote counted twice or history lost");
    }
    if alice_member.roles != vec!["member", "admin"] {
        bail!("step 12: fixture role drift");
    }
    pass(12, "one-member-one-vote enforced with append-only history");

    let kit = export(
        &RecoveryPayload {
            identity_seed: [11; 32],
            vault_master_key: key.0,
            community_ids: vec!["local-community".into()],
            control_plane_urls: vec!["http://127.0.0.1:8787".into()],
        },
        b"local verification passphrase",
    )?;
    let kit_path = recovery_root.join("owner.acm-recovery");
    fs::write(&kit_path, &kit)?;
    if recovery_root.join("identity").exists() || recovery_root.join("catalog-cache").exists() {
        bail!("step 13: recovery environment was not clean");
    }
    let recovered = import(&fs::read(&kit_path)?, b"local verification passphrase")?;
    let recovered_key = SecretKey(recovered.vault_master_key);
    let recovered_plaintext = decrypt(
        &recovered_key,
        &serde_json::from_slice(&mesh.restore(&object_cid)?)?,
        aad.as_bytes(),
    )?;
    if recovered.identity_seed != [11; 32] || recovered_plaintext != CONTENT_SENTINEL {
        bail!("step 13: clean recovery could not restore fixture");
    }
    pass(13, "clean environment recovered identity, key, and fixture");

    scan_tree_absent(&node_root, FILE_NAME_SENTINEL.as_bytes())?;
    scan_tree_absent(&node_root, CONTENT_SENTINEL)?;
    let migration_lower = MIGRATION.to_ascii_lowercase();
    for forbidden_column in [
        "file_name",
        "relative_path",
        "file_key",
        "vault_master_key",
        "plaintext_content",
    ] {
        if migration_lower.contains(forbidden_column) {
            bail!("step 14: forbidden D1 column found: {forbidden_column}");
        }
    }
    pass(
        14,
        "D1 schema and node storage contain no fixture plaintext",
    );

    verify_chain(control.audit_events())?;
    let first_root = merkle_root(control.audit_events());
    let second_root = merkle_root(control.audit_events());
    if first_root != second_root || first_root.len() != 64 {
        bail!("step 15: audit Merkle root is not deterministic");
    }
    let snapshot = control.export_snapshot()?;
    LocalControlPlane::verify_snapshot(&snapshot)?;
    pass(15, "audit hash chain, Merkle root, and snapshot verified");

    let report = VerificationReport {
        format_version: 1,
        seed: "acm-v0.1-fixed-fixture-2026-07-26",
        transport: "in-memory-offline",
        external_network_required: false,
        steps: (1..=15)
            .zip([
                "fixture",
                "encrypt",
                "replicate",
                "isolate",
                "stop-node",
                "outage-restore",
                "corrupt",
                "fallback-repair",
                "credit-earned",
                "credit-consumed",
                "no-transfer",
                "one-vote",
                "recovery",
                "plaintext-absence",
                "audit-chain",
            ])
            .map(|(id, name)| VerificationStep {
                id,
                name,
                status: "pass",
            })
            .collect(),
        acceptance_ids: vec![
            "ACM-10", "ACM-11", "ACM-12", "ACM-13", "ACM-14", "ACM-15", "ACM-16", "ACM-18",
            "ACM-19", "ACM-20", "ACM-21",
        ],
        result: "pass",
    };
    write_report(&report)?;
    println!("verify:mvp PASS — all 15 deterministic steps succeeded");
    Ok(())
}

fn control_plane() -> Result<(LocalControlPlane, Identity, Identity, Member)> {
    let root = Identity::from_seed([1; 32]);
    let alice = Identity::from_seed([2; 32]);
    let alice_member = member(&root, &alice, 1, &["member", "admin"]);
    let control = LocalControlPlane::bootstrap(
        Community {
            community_id: "local-community".into(),
            name: "Local Commons".into(),
            root_public_key: root.public_key(),
            created_at: 100,
            policy_version: 1,
            status: "active".into(),
        },
        alice_member.clone(),
    )?;
    Ok((control, root, alice, alice_member))
}

fn member(root: &Identity, identity: &Identity, serial: u64, roles: &[&str]) -> Member {
    let claims = MembershipClaims {
        credential_version: 1,
        community_id: "local-community".into(),
        member_public_key: identity.public_key(),
        member_id: identity.member_id(),
        roles: roles.iter().map(|role| (*role).into()).collect(),
        issued_at: 100,
        expires_at: 1000,
        serial,
        issuer_public_key: root.public_key(),
    };
    Member {
        member_id: identity.member_id(),
        public_key: identity.public_key(),
        roles: claims.roles.clone(),
        status: "active".into(),
        credential: claims.issue(root),
    }
}

fn object_path(root: &Path, object_cid: &str) -> PathBuf {
    root.join("objects")
        .join(&object_cid[..2])
        .join(format!("{object_cid}.blob"))
}

fn scan_tree_absent(root: &Path, sentinel: &[u8]) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            scan_tree_absent(&path, sentinel)?;
        } else {
            let bytes = fs::read(&path)?;
            if contains(&bytes, sentinel) {
                bail!("plaintext sentinel found in {}", path.display());
            }
        }
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn pass(id: u8, message: &str) {
    println!("STEP-{id:02} PASS {message}");
}

fn write_report(report: &VerificationReport) -> Result<()> {
    let output = Path::new(".verify");
    fs::create_dir_all(output)?;
    fs::write(
        output.join("verify-mvp-report.json"),
        serde_json::to_vec_pretty(report)?,
    )?;
    Ok(())
}

struct ProcessNodes {
    children: Vec<Child>,
}

impl ProcessNodes {
    fn start(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        let executable = std::env::current_exe()?;
        let mut children = Vec::new();
        for name in ["storage-a", "storage-b", "storage-c", "auditor"] {
            let node_root = root.join(name);
            fs::create_dir_all(&node_root)?;
            children.push(
                Command::new(&executable)
                    .args(["node", "run"])
                    .arg(&node_root)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .with_context(|| format!("could not start process node {name}"))?,
            );
        }
        for _ in 0..50 {
            if ["storage-a", "storage-b", "storage-c", "auditor"]
                .iter()
                .all(|name| root.join(name).join("ready").exists())
            {
                return Ok(Self { children });
            }
            thread::sleep(Duration::from_millis(100));
        }
        for child in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
        bail!("process nodes did not become ready")
    }

    fn assert_running(&mut self) -> Result<()> {
        if self
            .children
            .iter_mut()
            .any(|child| child.try_wait().ok().flatten().is_some())
        {
            bail!("a local node process exited before verification completed");
        }
        Ok(())
    }
}

impl Drop for ProcessNodes {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
