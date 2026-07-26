#![forbid(unsafe_code)]

mod local_vault;
mod verify;

use anyhow::{bail, Context, Result};
use arcane_mesh_control::LocalControlPlane;
use arcane_mesh_core::{
    identity::Identity,
    recovery::{export, import, RecoveryPayload},
};
use arcane_mesh_node::StorageNode;
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
    Export { output: PathBuf },
    Import { input: PathBuf },
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
    Add { path: PathBuf },
    List,
    Restore { file_id: String, output: PathBuf },
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
    let canonical = fs::canonicalize("/Volumes/Pensive")
        .context("Pensive is not mounted at /Volumes/Pensive")?;
    if !current.starts_with(&canonical) {
        bail!("current directory is not inside the canonical Pensive volume");
    }
    println!("repository: {}", current.display());
    println!("canonical volume: {}", canonical.display());
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
                },
                passphrase.trim_end().as_bytes(),
            )?;
            write_private_new(&output, &kit)?;
            println!("Recovery Kit written to {}", output.display());
            Ok(())
        }
        RecoveryCommand::Import { input } => {
            let passphrase = read_passphrase_stdin()?;
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
        VaultCommand::Add { path } => local_vault::add(&path, passphrase.trim_end()),
        VaultCommand::List => local_vault::list(passphrase.trim_end()),
        VaultCommand::Restore { file_id, output } => {
            local_vault::restore(&file_id, &output, passphrase.trim_end())
        }
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
            let _node = StorageNode::new(
                &node_id,
                format!("local-{node_id}"),
                &canonical,
                DEMO_NODE_QUOTA,
            )?;
            fs::write(canonical.join("node.pid"), std::process::id().to_string())?;
            fs::write(canonical.join("ready"), b"ready\n")?;
            println!("node_root={}", canonical.display());
            println!("status=running");
            loop {
                fs::write(canonical.join("heartbeat"), unix_timestamp()?.to_string())?;
                thread::sleep(Duration::from_secs(1));
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
            wait_for_demo_nodes(&demo_root)?;
            wait_for_worker()?;
            fs::write(&record_path, serde_json::to_vec_pretty(&records)?)?;
            fs::write(
                demo_root.join("community.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "community": "local-demo",
                    "members": ["Alice", "Bob"],
                    "storageNodes": ["storage-a", "storage-b", "storage-c"],
                    "auditor": "auditor",
                    "plaintextFixtureIncluded": false
                }))?,
            )?;
            println!("demo_root={}", fs::canonicalize(&demo_root)?.display());
            println!("storage_nodes=3");
            println!("auditor_nodes=1");
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
