#![forbid(unsafe_code)]

mod local_vault;
mod verify;

use anyhow::{bail, Context, Result};
use arcane_mesh_control::LocalControlPlane;
use arcane_mesh_core::{
    identity::{Identity, MembershipClaims, NodeCertificateClaims},
    recovery::{export, import, RecoveryPayload},
};
use arcane_mesh_node::StorageNode;
use arcane_mesh_protocol::{
    transport::{IrohTransport, TransportError, WireResponse},
    LocalNodeEndpoint, LocalNodeNetworkConfig, Operation,
};
use clap::{Parser, Subcommand};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const DEMO_NODE_QUOTA: u64 = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct ProcessRecord {
    name: String,
    pid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProcessRepairTask {
    task_id: String,
    object_cid: String,
    challenge: String,
    source_roots: Vec<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProcessRepairReceipt {
    task_id: String,
    object_cid: String,
    challenge: String,
    source_node: String,
}

#[derive(Parser)]
#[command(name = "acmctl", version, about = "Arcane Commons Mesh local MVP")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Doctor,
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    Community {
        #[command(subcommand)]
        command: CommunityCommand,
    },
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Demo {
        #[command(subcommand)]
        command: DemoCommand,
    },
    VerifyMvp,
}

#[derive(Subcommand)]
enum IdentityCommand {
    Create,
}

#[derive(Subcommand)]
enum RecoveryCommand {
    Export {
        output: PathBuf,
    },
    Import {
        input: PathBuf,
        #[arg(long = "source")]
        sources: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CommunityCommand {
    Create,
    JoinRequest,
    ApproveMember,
    ExportSnapshot { output: PathBuf },
    VerifySnapshot { input: PathBuf },
}

#[derive(Subcommand)]
enum VaultCommand {
    Create,
    Recover {
        recovery: PathBuf,
        #[arg(long = "source", required = true)]
        sources: Vec<PathBuf>,
    },
    Add {
        path: PathBuf,
    },
    List,
    Restore {
        file_id: String,
        output: PathBuf,
    },
    Delete {
        file_id: String,
    },
    Gc,
    Verify,
}

#[derive(Subcommand)]
enum NodeCommand {
    Init { root: PathBuf },
    Run { root: PathBuf },
    Status { root: PathBuf },
}

#[derive(Subcommand)]
enum DemoCommand {
    Up,
    Down,
    Seed,
    Smoke,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Doctor => doctor(),
        Command::Identity {
            command: IdentityCommand::Create,
        } => identity_create(),
        Command::Recovery { command } => recovery(command),
        Command::Community { command } => community(command),
        Command::Vault { command } => vault(command),
        Command::Node { command } => node(command),
        Command::Demo { command } => demo(command),
        Command::VerifyMvp => verify::verify_mvp(),
    }
}

fn doctor() -> Result<()> {
    let current = fs::canonicalize(".")?;
    let repository = current
        .ancestors()
        .find(|candidate| candidate.join(".git").exists());
    println!("working_directory: {}", current.display());
    match repository {
        Some(path) => println!("repository: {}", path.display()),
        None => println!("repository: not detected (release binary mode)"),
    }
    println!("protocol: arcane-commons-mesh/1");
    println!("status: local prerequisites ok");
    Ok(())
}

fn identity_create() -> Result<()> {
    let identity = Identity::generate();
    println!("member_id={}", identity.member_id());
    println!("public_key_hex={}", hex(&identity.public_key()));
    println!("secret_persisted=false");
    println!("Use the desktop Stronghold flow or immediately create a Recovery Kit.");
    Ok(())
}

fn recovery(command: RecoveryCommand) -> Result<()> {
    match command {
        RecoveryCommand::Export { output } => {
            let passphrase = read_passphrase_stdin()?;
            let mut identity_seed = [0_u8; 32];
            let mut vault_master_key = [0_u8; 32];
            OsRng.fill_bytes(&mut identity_seed);
            OsRng.fill_bytes(&mut vault_master_key);
            let kit = export(
                &RecoveryPayload {
                    identity_seed,
                    vault_master_key,
                    community_ids: Vec::new(),
                    control_plane_urls: vec!["http://127.0.0.1:8787".into()],
                    vaults: Vec::new(),
                },
                passphrase.trim_end().as_bytes(),
            )?;
            write_private_new(&output, &kit)?;
            println!("Recovery Kit written to {}", output.display());
            Ok(())
        }
        RecoveryCommand::Import { input, sources } => {
            let passphrase = read_passphrase_stdin()?;
            if !sources.is_empty() {
                return local_vault::recover(&input, &sources, passphrase.trim_end());
            }
            let kit = fs::read(&input)?;
            let recovered = import(&kit, passphrase.trim_end().as_bytes())?;
            println!("format=valid");
            println!("communities={}", recovered.community_ids.len());
            println!("control_planes={}", recovered.control_plane_urls.len());
            Ok(())
        }
    }
}

fn community(command: CommunityCommand) -> Result<()> {
    match command {
        CommunityCommand::Create => status("community create", "desktop signature required"),
        CommunityCommand::JoinRequest => status(
            "community join-request",
            "invite and local identity required",
        ),
        CommunityCommand::ApproveMember => status(
            "community approve-member",
            "community authority signature required",
        ),
        CommunityCommand::ExportSnapshot { output } => {
            bail!(
                "no local control-plane state loaded; use the desktop export flow for {}",
                output.display()
            )
        }
        CommunityCommand::VerifySnapshot { input } => {
            let bytes = fs::read(&input)?;
            let snapshot = LocalControlPlane::verify_snapshot(&bytes)?;
            println!("snapshot=valid");
            println!("community_id={}", snapshot.community.community_id);
            println!("members={}", snapshot.members.len());
            println!("nodes={}", snapshot.nodes.len());
            Ok(())
        }
    }
}

fn vault(command: VaultCommand) -> Result<()> {
    let passphrase = read_passphrase_stdin()?;
    match command {
        VaultCommand::Create => local_vault::create(passphrase.trim_end()),
        VaultCommand::Recover { recovery, sources } => {
            local_vault::recover(&recovery, &sources, passphrase.trim_end())
        }
        VaultCommand::Add { path } => local_vault::add(&path, passphrase.trim_end()),
        VaultCommand::List => local_vault::list(passphrase.trim_end()),
        VaultCommand::Restore { file_id, output } => {
            local_vault::restore(&file_id, &output, passphrase.trim_end())
        }
        VaultCommand::Delete { file_id } => local_vault::delete(&file_id, passphrase.trim_end()),
        VaultCommand::Gc => local_vault::gc(passphrase.trim_end()),
        VaultCommand::Verify => local_vault::verify(passphrase.trim_end()),
    }
}

fn node(command: NodeCommand) -> Result<()> {
    match command {
        NodeCommand::Init { root } => {
            if root.exists() && fs::read_dir(&root)?.next().is_some() {
                bail!("node root must be a new or empty dedicated directory");
            }
            fs::create_dir_all(&root)?;
            println!("node_root={}", fs::canonicalize(root)?.display());
            println!("status=initialized");
            Ok(())
        }
        NodeCommand::Run { root } => {
            let canonical = fs::canonicalize(root)?;
            let node_id = canonical
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("storage-node")
                .to_owned();
            let node = StorageNode::new(
                &node_id,
                format!("local-{node_id}"),
                &canonical,
                DEMO_NODE_QUOTA,
            )?;
            fs::write(canonical.join("node.pid"), std::process::id().to_string())?;
            let network_config = canonical.join("network-config.json");
            if network_config.exists() {
                let config: LocalNodeNetworkConfig =
                    serde_json::from_slice(&fs::read(network_config)?)?;
                let runtime = tokio::runtime::Runtime::new()?;
                return runtime.block_on(service_network_requests(&node, &canonical, &config));
            }
            service_node_requests(&node, &canonical)?;
            fs::write(canonical.join("ready"), b"ready\n")?;
            println!("node_root={}", canonical.display());
            println!("status=running");
            loop {
                fs::write(canonical.join("heartbeat"), unix_timestamp()?.to_string())?;
                service_node_requests(&node, &canonical)?;
                thread::sleep(Duration::from_millis(50));
            }
        }
        NodeCommand::Status { root } => {
            let canonical = fs::canonicalize(root)?;
            let pid = fs::read_to_string(canonical.join("node.pid"))
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok());
            println!("node_root={}", canonical.display());
            println!(
                "status={}",
                pid.filter(|value| process_is_alive(*value))
                    .map_or("stopped", |_| "running")
            );
            Ok(())
        }
    }
}

async fn service_network_requests(
    node: &StorageNode,
    root: &Path,
    config: &LocalNodeNetworkConfig,
) -> Result<()> {
    let transport = IrohTransport::bind_local(root.join("network-replay.sqlite3")).await?;
    let endpoint = LocalNodeEndpoint {
        endpoint_addr: transport.addr(),
    };
    fs::write(
        root.join("network-endpoint.json"),
        serde_json::to_vec_pretty(&endpoint)?,
    )?;
    fs::write(root.join("ready"), b"network-ready\n")?;
    println!("node_root={}", root.display());
    println!("transport=iroh-quic-loopback");
    println!("status=running");
    loop {
        fs::write(root.join("heartbeat"), unix_timestamp()?.to_string())?;
        let accepted = match transport
            .accept_rpc(
                &config.community_root_public_key,
                unix_timestamp()?.try_into()?,
            )
            .await
        {
            Ok(accepted) => accepted,
            Err(TransportError::Timeout) => continue,
            Err(error) => return Err(error.into()),
        };
        let request_id = accepted.frame.request.request_id.clone();
        let object_cid = accepted.frame.request.object_cid.clone();
        let operation = accepted.frame.request.operation;
        let request_payload = accepted.frame.payload.clone();
        let (ok, error_code, payload) = match operation {
            Operation::PutObject | Operation::ReplicateObject => {
                let matches_cid = object_cid
                    .as_deref()
                    .is_some_and(|expected| arcane_mesh_core::cid(&request_payload) == expected);
                if matches_cid
                    && node
                        .put(object_cid.as_deref().unwrap_or_default(), &request_payload)
                        .is_ok()
                {
                    (true, None, Vec::new())
                } else {
                    (false, Some("storage_rejected".into()), Vec::new())
                }
            }
            Operation::GetObject => {
                match object_cid.as_deref().and_then(|cid| node.get(cid).ok()) {
                    Some(bytes) => (true, None, bytes),
                    None => (false, Some("not_found".into()), Vec::new()),
                }
            }
            Operation::HasObject | Operation::AuditObject => {
                let healthy = object_cid
                    .as_deref()
                    .is_some_and(|cid| node.audit(cid).unwrap_or(false));
                (true, None, healthy.to_string().into_bytes())
            }
            Operation::DeleteAfter => {
                let deleted = object_cid
                    .as_deref()
                    .is_some_and(|cid| node.delete(cid).unwrap_or(false));
                (deleted, (!deleted).then(|| "not_found".into()), Vec::new())
            }
            Operation::Hello | Operation::Ping => (true, None, Vec::new()),
        };
        let response = WireResponse {
            protocol_version: 1,
            request_id,
            ok,
            error_code,
            payload_cid: arcane_mesh_core::cid(&payload),
            payload,
        };
        // A desktop client may disappear immediately after receiving enough
        // healthy replicas. A single closed response stream must not terminate
        // the long-lived storage node.
        if accepted.respond(&response).await.is_err() {
            continue;
        }
    }
}

fn demo(command: DemoCommand) -> Result<()> {
    match command {
        DemoCommand::Up => {
            let demo_root = PathBuf::from(".demo");
            fs::create_dir_all(demo_root.join("nodes"))?;
            let record_path = demo_root.join("processes.json");
            if record_path.exists() {
                let records: Vec<ProcessRecord> = serde_json::from_slice(&fs::read(&record_path)?)?;
                if records.iter().any(|record| process_is_alive(record.pid)) {
                    bail!("local demo already has running processes; run `pnpm demo:down` first");
                }
            }
            let executable = std::env::current_exe()?;
            apply_demo_migrations()?;
            let worker_log = OpenOptions::new()
                .create(true)
                .append(true)
                .open(demo_root.join("worker.log"))?;
            let mut records = vec![start_demo_worker(worker_log.try_clone()?, worker_log)?];
            for name in ["storage-a", "storage-b", "storage-c", "auditor"] {
                let root = demo_root.join("nodes").join(name);
                fs::create_dir_all(&root)?;
                fs::write(
                    root.join("network-config.json"),
                    serde_json::to_vec_pretty(&LocalNodeNetworkConfig {
                        community_root_public_key: Identity::from_seed([1; 32]).public_key(),
                    })?,
                )?;
                let log = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(demo_root.join(format!("{name}.log")))?;
                records.push(start_demo_node(
                    &executable,
                    &root,
                    name,
                    log.try_clone()?,
                    log,
                )?);
            }
            fs::write(&record_path, serde_json::to_vec_pretty(&records)?)?;
            wait_for_demo_nodes(&demo_root)?;
            wait_for_worker()?;
            seed_demo_control_plane()?;
            println!("demo_root={}", fs::canonicalize(&demo_root)?.display());
            println!("storage_nodes=3");
            println!("auditor_nodes=1");
            println!("transport=iroh-quic-loopback-authenticated");
            println!("control_plane=http://127.0.0.1:8787");
            println!("status=running");
            Ok(())
        }
        DemoCommand::Down => {
            let demo_root = Path::new(".demo");
            let record_path = demo_root.join("processes.json");
            if record_path.exists() {
                let records: Vec<ProcessRecord> = serde_json::from_slice(&fs::read(&record_path)?)?;
                for record in records {
                    stop_process(record.pid)?;
                }
            }
            if demo_root.exists() {
                fs::remove_dir_all(demo_root)?;
            }
            println!("local demo state stopped");
            Ok(())
        }
        DemoCommand::Seed => {
            fs::create_dir_all(".demo")?;
            fs::write(".demo/README", b"Redacted deterministic local demo state\n")?;
            println!("local demo seed prepared");
            Ok(())
        }
        DemoCommand::Smoke => demo_network_smoke(),
    }
}

fn demo_network_smoke() -> Result<()> {
    let demo_root = Path::new(".demo");
    let bootstrap: serde_json::Value =
        serde_json::from_slice(&fs::read(demo_root.join("bootstrap.json"))?)?;
    let community_id = bootstrap
        .get("communityId")
        .and_then(serde_json::Value::as_str)
        .context("demo bootstrap has no community ID")?;
    let endpoints = ["storage-a", "storage-b", "storage-c"]
        .into_iter()
        .map(|name| {
            Ok(serde_json::from_slice::<LocalNodeEndpoint>(&fs::read(
                demo_root
                    .join("nodes")
                    .join(name)
                    .join("network-endpoint.json"),
            )?)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let runtime = tokio::runtime::Runtime::new()?;
    let transport = runtime.block_on(IrohTransport::bind_local(
        demo_root.join("smoke-client-replay.sqlite3"),
    ))?;
    let community_root = Identity::from_seed([1; 32]);
    let client = Identity::from_seed([11; 32]);
    let now: i64 = unix_timestamp()?.try_into()?;
    let credential = MembershipClaims {
        credential_version: 1,
        community_id: community_id.into(),
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
        serial: 100,
        issuer_public_key: community_root.public_key(),
    }
    .issue(&community_root);
    let certificate = NodeCertificateClaims {
        certificate_version: 1,
        node_id: "demo-smoke-client".into(),
        community_id: community_id.into(),
        owner_member_id: client.member_id(),
        endpoint_public_key: transport.addr().id.to_string(),
        allowed_roles: vec!["node".into()],
        max_storage_bytes: DEMO_NODE_QUOTA,
        issued_at: now - 60,
        expires_at: now + 3600,
    }
    .issue(&client);
    let mut payload = vec![0_u8; 4096];
    OsRng.fill_bytes(&mut payload);
    let object_cid = arcane_mesh_core::cid(&payload);
    let mut sequence = 0_u64;
    for endpoint in &endpoints {
        sequence += 1;
        let frame = signed_demo_frame(
            community_id,
            &client,
            &credential,
            &certificate,
            Operation::PutObject,
            Some(&object_cid),
            payload.clone(),
            now,
            sequence,
        );
        let response = runtime.block_on(transport.call(endpoint.endpoint_addr.clone(), &frame))?;
        if !response.ok {
            bail!("demo QUIC PUT failed");
        }
    }
    for endpoint in &endpoints {
        sequence += 1;
        let frame = signed_demo_frame(
            community_id,
            &client,
            &credential,
            &certificate,
            Operation::GetObject,
            Some(&object_cid),
            Vec::new(),
            now,
            sequence,
        );
        let response = runtime.block_on(transport.call(endpoint.endpoint_addr.clone(), &frame))?;
        if !response.ok
            || response.payload != payload
            || arcane_mesh_core::cid(&response.payload) != object_cid
        {
            bail!("demo QUIC GET verification failed");
        }
    }
    println!("transport=iroh-quic-loopback-authenticated");
    println!("replicas=3/3");
    println!("round_trip=pass");
    println!("plaintext_sent=false");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn signed_demo_frame(
    community_id: &str,
    identity: &Identity,
    credential: &arcane_mesh_core::identity::MembershipCredential,
    certificate: &arcane_mesh_core::identity::NodeCertificate,
    operation: Operation,
    object_cid: Option<&str>,
    payload: Vec<u8>,
    now: i64,
    sequence: u64,
) -> arcane_mesh_protocol::transport::WireFrame {
    let request = arcane_mesh_protocol::Request {
        protocol_version: 1,
        request_id: format!("demo-network-request-{sequence:016x}"),
        community_id: community_id.into(),
        node_id: "demo-smoke-client".into(),
        operation,
        object_cid: object_cid.map(str::to_owned),
        issued_at: now,
        expires_at: now + 300,
        credential: credential.clone(),
    };
    let request_signature = identity
        .sign(&request.signing_bytes(&arcane_mesh_core::cid(&payload)))
        .to_vec();
    arcane_mesh_protocol::transport::WireFrame {
        request,
        request_signature,
        node_certificate: certificate.clone(),
        node_owner_public_key: identity.public_key(),
        payload,
    }
}

fn status(command: &str, detail: &str) -> Result<()> {
    writeln!(io::stdout(), "command={command}")?;
    writeln!(io::stdout(), "status=requires_initialized_local_state")?;
    writeln!(io::stdout(), "detail={detail}")?;
    Ok(())
}

fn read_passphrase_stdin() -> Result<String> {
    if atty_stdin() {
        bail!("passphrase must be piped through stdin; it is never accepted as an argument");
    }
    let mut value = String::new();
    io::stdin().read_to_string(&mut value)?;
    if value.trim_end().len() < 12 {
        bail!("recovery passphrase must be at least 12 characters");
    }
    Ok(value)
}

fn atty_stdin() -> bool {
    std::io::IsTerminal::is_terminal(&io::stdin())
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

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn process_is_alive(pid: u32) -> bool {
    ProcessCommand::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn stop_process(pid: u32) -> Result<()> {
    if !process_is_alive(pid) {
        return Ok(());
    }
    let status = ProcessCommand::new("kill")
        .arg(pid.to_string())
        .status()
        .context("could not stop local demo process")?;
    if !status.success() {
        bail!("could not stop local demo process {pid}");
    }
    Ok(())
}

fn wait_for_demo_nodes(demo_root: &Path) -> Result<()> {
    for _ in 0..50 {
        if ["storage-a", "storage-b", "storage-c", "auditor"]
            .iter()
            .all(|name| demo_root.join("nodes").join(name).join("ready").exists())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("local demo nodes did not become ready")
}

fn start_demo_node(
    executable: &Path,
    root: &Path,
    name: &str,
    stdout: fs::File,
    stderr: fs::File,
) -> Result<ProcessRecord> {
    let root = fs::canonicalize(root)?;
    let child = ProcessCommand::new("nohup")
        .arg(executable)
        .args(["node", "run"])
        .arg(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    Ok(ProcessRecord {
        name: name.into(),
        pid: child.id(),
    })
}

fn apply_demo_migrations() -> Result<()> {
    let status = ProcessCommand::new("pnpm")
        .args([
            "--filter",
            "@arcane-commons/api",
            "exec",
            "wrangler",
            "d1",
            "migrations",
            "apply",
            "arcane-commons-mesh-local",
            "--local",
            "--persist-to",
            "../../.demo/wrangler",
        ])
        .status()
        .context("could not apply local demo D1 migrations")?;
    if !status.success() {
        bail!("local demo D1 migrations failed");
    }
    Ok(())
}

fn start_demo_worker(stdout: fs::File, stderr: fs::File) -> Result<ProcessRecord> {
    let child = ProcessCommand::new("nohup")
        .args([
            "pnpm",
            "--filter",
            "@arcane-commons/api",
            "exec",
            "wrangler",
            "dev",
            "--local",
            "--port",
            "8787",
            "--persist-to",
            "../../.demo/wrangler",
            "--var",
            "INTERNAL_SECRET:local-demo-only",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    Ok(ProcessRecord {
        name: "worker".into(),
        pid: child.id(),
    })
}

fn wait_for_worker() -> Result<()> {
    let address: SocketAddr = "127.0.0.1:8787".parse()?;
    for _ in 0..100 {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("local Worker did not become ready")
}

fn seed_demo_control_plane() -> Result<()> {
    let status = ProcessCommand::new("node")
        .arg("apps/api/test/demo-seed.mjs")
        .status()
        .context("could not seed local demo control plane")?;
    if !status.success() {
        bail!("local demo control-plane seed failed");
    }
    Ok(())
}

fn service_node_requests(node: &StorageNode, root: &Path) -> Result<()> {
    let requests = root.join("ipc").join("requests");
    let responses = root.join("ipc").join("responses");
    fs::create_dir_all(&requests)?;
    fs::create_dir_all(&responses)?;
    for entry in fs::read_dir(&requests)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if let Some(object_cid) = name
            .strip_prefix("put-")
            .and_then(|value| value.strip_suffix(".blob"))
        {
            let result = node.put(object_cid, &fs::read(&path)?);
            let suffix = if result.is_ok() { "ok" } else { "err" };
            fs::write(responses.join(format!("put-{object_cid}.{suffix}")), b"")?;
            fs::remove_file(path)?;
        } else if let Some(object_cid) = name
            .strip_prefix("get-")
            .and_then(|value| value.strip_suffix(".req"))
        {
            match node.get(object_cid) {
                Ok(bytes) => fs::write(responses.join(format!("get-{object_cid}.blob")), bytes)?,
                Err(_) => fs::write(responses.join(format!("get-{object_cid}.err")), b"")?,
            }
            fs::remove_file(path)?;
        } else if name.starts_with("repair-") && name.ends_with(".json") {
            let task: ProcessRepairTask = serde_json::from_slice(&fs::read(&path)?)?;
            let response_object_cid = task.object_cid.clone();
            let result = (|| -> Result<ProcessRepairReceipt> {
                if task.task_id.len() < 16 || task.challenge.len() < 16 {
                    bail!("invalid repair task binding");
                }
                for (index, source_root) in task.source_roots.iter().enumerate() {
                    let source = StorageNode::new(
                        format!("repair-source-{index}"),
                        format!("repair-source-domain-{index}"),
                        source_root,
                        u64::MAX,
                    )?;
                    if let Ok(bytes) = source.get(&task.object_cid) {
                        node.put(&task.object_cid, &bytes)?;
                        if node.get(&task.object_cid)? != bytes {
                            bail!("repair destination verification failed");
                        }
                        return Ok(ProcessRepairReceipt {
                            task_id: task.task_id,
                            object_cid: task.object_cid,
                            challenge: task.challenge,
                            source_node: source.node_id().to_owned(),
                        });
                    }
                }
                bail!("no healthy repair source")
            })();
            let response_name = match &result {
                Ok(_) => format!("repair-{response_object_cid}.json"),
                Err(_) => format!("repair-{response_object_cid}.err"),
            };
            let response_bytes = match result {
                Ok(receipt) => serde_json::to_vec(&receipt)?,
                Err(error) => error.to_string().into_bytes(),
            };
            fs::write(responses.join(response_name), response_bytes)?;
            fs::remove_file(path)?;
        } else if !name.starts_with('.') {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}
