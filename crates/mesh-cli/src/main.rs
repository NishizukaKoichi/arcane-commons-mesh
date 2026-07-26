#![forbid(unsafe_code)]

mod verify;

use anyhow::{bail, Context, Result};
use arcane_mesh_control::LocalControlPlane;
use arcane_mesh_core::{
    identity::Identity,
    recovery::{export, import, RecoveryPayload},
};
use clap::{Parser, Subcommand};
use rand_core::{OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

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
    match command {
        VaultCommand::Create => status("vault create", "Stronghold identity required"),
        VaultCommand::Add { path } => {
            let canonical = fs::canonicalize(path)?;
            if !canonical.is_file() && !canonical.is_dir() {
                bail!("vault input is not a file or directory");
            }
            println!("validated_path={}", canonical.display());
            println!("status=ready_for_desktop_confirmation");
            Ok(())
        }
        VaultCommand::List => status("vault list", "no local catalog selected"),
        VaultCommand::Restore { file_id, output } => {
            println!("file_id={file_id}");
            println!("output={}", output.display());
            status("vault restore", "catalog and placement selection required")
        }
        VaultCommand::Verify => status("vault verify", "no local catalog selected"),
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
            println!("node_root={}", canonical.display());
            status(
                "node run",
                "interactive local transport is not persistent in this command",
            )
        }
        NodeCommand::Status { root } => {
            println!("node_root={}", fs::canonicalize(root)?.display());
            println!("status=stopped");
            Ok(())
        }
    }
}

fn demo(command: DemoCommand) -> Result<()> {
    match command {
        DemoCommand::Up => {
            fs::create_dir_all(".demo")?;
            println!("local demo state initialized in .demo");
            println!("Run `pnpm verify:mvp` for the deterministic multi-node scenario.");
            Ok(())
        }
        DemoCommand::Down => {
            if Path::new(".demo").exists() {
                fs::remove_dir_all(".demo")?;
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
