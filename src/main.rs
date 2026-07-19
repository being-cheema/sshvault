//! sshvault CLI. Thin dispatch layer: all logic lives in the library modules.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{Args, Parser, Subcommand, ValueEnum};
use sha2::{Digest, Sha256};
use sshvault::record::{ForwardKind, Host, KeyMeta, Kind, PortForward, PrivateKey, Snippet};
use sshvault::sshconfig;
use sshvault::vault::{self, Vault};
use std::io::Write as _;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "sshvault", version, about = "End-to-end-encrypted sync for your SSH workflow", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault (prints your recovery phrase — store it safely!)
    Init {
        /// Human-readable name for this device
        #[arg(long, default_value_t = hostname())]
        device_name: String,
    },
    /// Manage SSH hosts
    Host {
        #[command(subcommand)]
        cmd: HostCmd,
    },
    /// Manage reusable command snippets
    Snippet {
        #[command(subcommand)]
        cmd: SnippetCmd,
    },
    /// Manage SSH key metadata (public keys only — private keys never enter the vault)
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Manage port-forward definitions
    Fwd {
        #[command(subcommand)]
        cmd: FwdCmd,
    },
    /// Regenerate ~/.ssh/sshvault.conf and ensure your config Includes it
    Apply {
        /// Target .ssh directory (defaults to ~/.ssh)
        #[arg(long)]
        ssh_dir: Option<PathBuf>,
    },
    /// Export the vault as plaintext JSON to stdout (you own your data)
    Export,
    /// Import a JSON export (skips entries whose name already exists)
    Import {
        /// Path to a JSON file produced by `sshvault export` ("-" for stdin)
        file: String,
    },
    /// Sync with a relay (push local changes, pull remote ones)
    Sync {
        /// Relay URL, e.g. https://relay.example.com — remembered after first use
        #[arg(long)]
        relay: Option<String>,
    },
    /// Sync continuously in the foreground: follow relay change notifications
    /// over WebSocket and reconcile on each one (Ctrl-C to stop)
    Syncd {
        /// Also regenerate ~/.ssh/sshvault.conf after every round that pulled changes
        #[arg(long)]
        apply: bool,
    },
    /// Run the relay server (zero-knowledge blob store)
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: String,
        /// SQLite database path
        #[arg(long, default_value = "sshvault-relay.db")]
        db: String,
        /// PEM certificate chain to terminate TLS directly (requires --tls-key).
        /// Omit to serve plain HTTP behind a reverse proxy.
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<std::path::PathBuf>,
        /// PEM private key matching --tls-cert.
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<std::path::PathBuf>,
    },
    /// Manage devices enrolled in your vault
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Manage shares (compartments): named subsets of records visible only to
    /// their members. Records not in a share live in the default share everyone
    /// sees.
    Share {
        #[command(subcommand)]
        cmd: ShareCmd,
    },
    /// Recover a vault on this machine from your 24-word recovery phrase
    Recover {
        /// Relay URL the vault syncs with
        #[arg(long)]
        relay: String,
        /// Human-readable name for this device
        #[arg(long, default_value_t = hostname())]
        device_name: String,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Enroll THIS machine into an existing vault and wait for approval
    Enroll {
        /// Vault id to join (shown by `sshvault device list` on an enrolled device)
        #[arg(long)]
        vault: String,
        /// Relay URL the vault syncs with
        #[arg(long)]
        relay: String,
        /// Human-readable name for this device
        #[arg(long, default_value_t = hostname())]
        device_name: String,
    },
    /// Approve a pending device by its short code
    Approve { code: String },
    /// List devices enrolled in your vault
    List,
    /// Revoke a device by its short code (it can no longer sync or re-enroll).
    /// With --rotate, also rotate the vault key so the revoked device cannot read
    /// data written after this point (requires your recovery phrase).
    Revoke {
        code: String,
        /// Rotate the vault key for forward secrecy (prompts for recovery phrase)
        #[arg(long)]
        rotate: bool,
    },
}

#[derive(Subcommand)]
enum ShareCmd {
    /// Create a share and grant it to the given device short codes
    Create {
        /// Human name for the share
        name: String,
        /// Device short code to add as a member (repeatable)
        #[arg(long = "member")]
        members: Vec<String>,
    },
    /// Add members (device short codes) to an existing share
    Add {
        name: String,
        #[arg(long = "member")]
        members: Vec<String>,
    },
    /// Remove a member from a share and rotate its key (forward secrecy)
    Remove {
        name: String,
        /// Device short code to remove
        code: String,
    },
    /// List shares known to this device and whether you're a member
    List,
}

#[derive(Subcommand)]
enum HostCmd {
    /// Add a host
    Add {
        alias: String,
        #[command(flatten)]
        opts: HostOpts,
    },
    /// Edit a host (only the flags you pass change)
    Edit {
        alias: String,
        #[command(flatten)]
        opts: HostOpts,
    },
    /// Remove a host
    Rm { alias: String },
    /// List hosts
    List,
}

#[derive(Args, Default)]
struct HostOpts {
    /// Real hostname or IP (ssh HostName)
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    user: Option<String>,
    /// ProxyJump host
    #[arg(long)]
    jump: Option<String>,
    /// IdentityFile path
    #[arg(long)]
    identity: Option<String>,
    /// Tag (repeatable); on edit, replaces all tags
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Place this host in a named share (only its members can see it). Default:
    /// the shared-with-everyone default share. Ignored on edit.
    #[arg(long)]
    share: Option<String>,
}

#[derive(Subcommand)]
enum SnippetCmd {
    /// Add a snippet
    Add {
        name: String,
        /// The shell command (quote it)
        command: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// Edit a snippet (only the flags you pass change)
    Edit {
        name: String,
        #[arg(long)]
        command: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// Remove a snippet
    Rm { name: String },
    /// List snippets
    List,
    /// Run a snippet through your shell
    Run { name: String },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Add key metadata from a public-key file (private keys are rejected)
    Add {
        name: String,
        /// Path to the PUBLIC key file (e.g. ~/.ssh/id_ed25519.pub)
        #[arg(long)]
        pubkey: PathBuf,
        /// Host alias that uses this key (repeatable)
        #[arg(long = "host")]
        hosts: Vec<String>,
    },
    /// Edit key metadata (only the flags you pass change)
    Edit {
        name: String,
        /// Path to a new PUBLIC key file
        #[arg(long)]
        pubkey: Option<PathBuf>,
        /// Host alias that uses this key (repeatable); replaces all hosts
        #[arg(long = "host")]
        hosts: Vec<String>,
    },
    /// Remove key metadata
    Rm { name: String },
    /// List key metadata (and any synced private keys, marked `[private]`)
    List,
    /// Store a PRIVATE key in the vault (opt-in; sealed E2E like every record).
    /// A deliberate, separate command from `add` so this is never accidental.
    AddPrivate {
        name: String,
        /// Path to the PRIVATE key file (e.g. ~/.ssh/id_ed25519)
        #[arg(long = "private")]
        private: PathBuf,
        /// Optional matching PUBLIC key file (e.g. ~/.ssh/id_ed25519.pub)
        #[arg(long = "public")]
        public: Option<PathBuf>,
    },
    /// Materialize a synced private key to disk (default ~/.ssh/<name>, mode 0600)
    Install {
        name: String,
        /// Destination path (default ~/.ssh/<name>)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite an existing file at the destination
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum FwdCmd {
    /// Add a port-forward
    Add {
        name: String,
        /// local: `port:host:port` · remote: `port:host:port` · dynamic: `port`
        spec: String,
        /// Host alias this forward belongs to
        #[arg(long)]
        host: String,
        #[arg(long = "type", value_enum, default_value = "local")]
        kind: FwdType,
    },
    /// Edit a port-forward (only the flags you pass change)
    Edit {
        name: String,
        /// New spec — local/remote: `port:host:port` · dynamic: `port`
        #[arg(long)]
        spec: Option<String>,
        /// Host alias this forward belongs to
        #[arg(long)]
        host: Option<String>,
        #[arg(long = "type", value_enum)]
        kind: Option<FwdType>,
    },
    /// Remove a port-forward
    Rm { name: String },
    /// List port-forwards
    List,
}

#[derive(Clone, Copy, ValueEnum)]
enum FwdType {
    Local,
    Remote,
    Dynamic,
}

impl From<FwdType> for ForwardKind {
    fn from(t: FwdType) -> Self {
        match t {
            FwdType::Local => ForwardKind::Local,
            FwdType::Remote => ForwardKind::Remote,
            FwdType::Dynamic => ForwardKind::Dynamic,
        }
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { device_name } => init(&device_name),
        Cmd::Host { cmd } => host_cmd(cmd),
        Cmd::Snippet { cmd } => snippet_cmd(cmd),
        Cmd::Key { cmd } => key_cmd(cmd),
        Cmd::Fwd { cmd } => fwd_cmd(cmd),
        Cmd::Apply { ssh_dir } => apply(ssh_dir),
        Cmd::Export => {
            let v = open_vault()?;
            println!("{}", serde_json::to_string_pretty(&v.export_json())?);
            Ok(())
        }
        Cmd::Import { file } => import(&file),
        Cmd::Sync { relay } => sync(relay),
        Cmd::Syncd { apply } => syncd(apply),
        Cmd::Serve {
            addr,
            db,
            tls_cert,
            tls_key,
        } => serve(&addr, &db, tls_cert, tls_key),
        Cmd::Device { cmd } => device_cmd(cmd),
        Cmd::Share { cmd } => share_cmd(cmd),
        Cmd::Recover { relay, device_name } => recover(&relay, &device_name),
    }
}

fn init(device_name: &str) -> Result<()> {
    let dir = vault::default_dir();
    let pass = prompt_new_passphrase()?;
    let (_vault, phrase) = Vault::init(&dir, device_name, &pass)?;
    println!("Vault created at {}", dir.display());
    println!("\nYour recovery phrase (24 words). Write it down and store it OFFLINE —");
    println!("it is the ONLY way to recover your vault if you lose this device:\n");
    println!("    {phrase}\n");
    println!("Next steps:");
    println!("    sshvault host add <alias> --hostname <host>   # add your first host");
    println!("    sshvault apply                                # wire it into ~/.ssh/config");
    Ok(())
}

fn host_cmd(cmd: HostCmd) -> Result<()> {
    let mut v = open_vault()?;
    match cmd {
        HostCmd::Add { alias, opts } => {
            let share = match &opts.share {
                None => uuid::Uuid::nil(),
                Some(name) => v.resolve_share(name).with_context(|| {
                    format!(
                        "no share named '{name}' — create it with `sshvault share create {name}`"
                    )
                })?,
            };
            let host = Host {
                alias: alias.clone(),
                hostname: opts.hostname,
                port: opts.port,
                user: opts.user,
                jump_host: opts.jump,
                identity_file: opts.identity,
                tags: opts.tags,
            };
            v.add_in(Kind::Host, "alias", &alias, &host, share)?;
            println!("added host '{alias}' — run `sshvault apply` to update ssh config");
        }
        HostCmd::Edit { alias, opts } => {
            let rec = v
                .find(Kind::Host, "alias", &alias)
                .with_context(|| format!("host '{alias}' not found"))?;
            let mut host: Host = rec.payload()?;
            if let Some(x) = opts.hostname {
                host.hostname = Some(x)
            }
            if let Some(x) = opts.port {
                host.port = Some(x)
            }
            if let Some(x) = opts.user {
                host.user = Some(x)
            }
            if let Some(x) = opts.jump {
                host.jump_host = Some(x)
            }
            if let Some(x) = opts.identity {
                host.identity_file = Some(x)
            }
            if !opts.tags.is_empty() {
                host.tags = opts.tags
            }
            v.edit(Kind::Host, "alias", &alias, &host)?;
            println!("updated host '{alias}' — run `sshvault apply` to update ssh config");
        }
        HostCmd::Rm { alias } => {
            v.remove(Kind::Host, "alias", &alias)?;
            println!("removed host '{alias}' — run `sshvault apply` to update ssh config");
        }
        HostCmd::List => {
            let mut hosts = v.list::<Host>(Kind::Host);
            hosts.sort_by(|a, b| a.1.alias.cmp(&b.1.alias));
            for (_, h) in hosts {
                let mut line = h.alias.clone();
                if let Some(hn) = &h.hostname {
                    let user = h
                        .user
                        .as_deref()
                        .map(|u| format!("{u}@"))
                        .unwrap_or_default();
                    let port = h.port.map(|p| format!(":{p}")).unwrap_or_default();
                    line += &format!("  →  {user}{hn}{port}");
                }
                if !h.tags.is_empty() {
                    line += &format!("  [{}]", h.tags.join(", "));
                }
                println!("{line}");
            }
        }
    }
    Ok(())
}

fn snippet_cmd(cmd: SnippetCmd) -> Result<()> {
    let mut v = open_vault()?;
    match cmd {
        SnippetCmd::Add {
            name,
            command,
            description,
            tags,
        } => {
            let s = Snippet {
                name: name.clone(),
                command,
                description,
                tags,
            };
            v.add(Kind::Snippet, "name", &name, &s)?;
            println!("added snippet '{name}'");
        }
        SnippetCmd::Edit {
            name,
            command,
            description,
            tags,
        } => {
            let rec = v
                .find(Kind::Snippet, "name", &name)
                .with_context(|| format!("snippet '{name}' not found"))?;
            let mut s: Snippet = rec.payload()?;
            if let Some(x) = command {
                s.command = x
            }
            if let Some(x) = description {
                s.description = Some(x)
            }
            if !tags.is_empty() {
                s.tags = tags
            }
            v.edit(Kind::Snippet, "name", &name, &s)?;
            println!("updated snippet '{name}'");
        }
        SnippetCmd::Rm { name } => {
            v.remove(Kind::Snippet, "name", &name)?;
            println!("removed snippet '{name}'");
        }
        SnippetCmd::List => {
            let mut snippets = v.list::<Snippet>(Kind::Snippet);
            snippets.sort_by(|a, b| a.1.name.cmp(&b.1.name));
            for (_, s) in snippets {
                let desc = s
                    .description
                    .as_deref()
                    .map(|d| format!("  # {d}"))
                    .unwrap_or_default();
                println!("{}  →  {}{desc}", s.name, s.command);
            }
        }
        SnippetCmd::Run { name } => {
            let rec = v
                .find(Kind::Snippet, "name", &name)
                .with_context(|| format!("snippet '{name}' not found"))?;
            let s: Snippet = rec.payload()?;
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            let status = std::process::Command::new(shell)
                .arg("-c")
                .arg(&s.command)
                .status()
                .with_context(|| format!("failed to run snippet '{name}'"))?;
            if !status.success() {
                bail!("snippet '{name}' exited with {status}");
            }
        }
    }
    Ok(())
}

fn key_cmd(cmd: KeyCmd) -> Result<()> {
    let mut v = open_vault()?;
    match cmd {
        KeyCmd::Add {
            name,
            pubkey,
            hosts,
        } => {
            let public_key = read_public_key(&pubkey)?;
            let fingerprint = ssh_fingerprint(&public_key);
            let key = KeyMeta {
                name: name.clone(),
                public_key,
                fingerprint,
                hosts,
            };
            v.add(Kind::KeyMeta, "name", &name, &key)?;
            println!("added key '{name}'");
        }
        KeyCmd::Edit {
            name,
            pubkey,
            hosts,
        } => {
            let rec = v
                .find(Kind::KeyMeta, "name", &name)
                .with_context(|| format!("key '{name}' not found"))?;
            let mut key: KeyMeta = rec.payload()?;
            if let Some(path) = pubkey {
                let public_key = read_public_key(&path)?;
                key.fingerprint = ssh_fingerprint(&public_key);
                key.public_key = public_key;
            }
            if !hosts.is_empty() {
                key.hosts = hosts
            }
            v.edit(Kind::KeyMeta, "name", &name, &key)?;
            println!("updated key '{name}'");
        }
        KeyCmd::Rm { name } => {
            v.remove(Kind::KeyMeta, "name", &name)?;
            println!("removed key '{name}'");
        }
        KeyCmd::List => {
            let mut keys = v.list::<KeyMeta>(Kind::KeyMeta);
            keys.sort_by(|a, b| a.1.name.cmp(&b.1.name));
            for (_, k) in keys {
                let fp = k.fingerprint.as_deref().unwrap_or("(no fingerprint)");
                let hosts = if k.hosts.is_empty() {
                    String::new()
                } else {
                    format!("  (hosts: {})", k.hosts.join(", "))
                };
                println!("{}  {fp}{hosts}", k.name);
            }
            // Private keys, distinctly marked. NEVER print any key bytes.
            let mut priv_keys = v.list::<PrivateKey>(Kind::PrivateKey);
            priv_keys.sort_by(|a, b| a.1.name.cmp(&b.1.name));
            for (_, k) in priv_keys {
                let pub_note = if k.public_key.is_some() {
                    "  (public key stored)"
                } else {
                    ""
                };
                println!("{}  [private]{pub_note}", k.name);
            }
        }
        KeyCmd::AddPrivate {
            name,
            private,
            public,
        } => {
            safe_key_name(&name)?;
            // Hold the secret in zeroized memory for its whole lifetime.
            let key_pem = Zeroizing::new(
                std::fs::read_to_string(&private)
                    .with_context(|| format!("cannot read {}", private.display()))?,
            );
            if !key_pem.contains("PRIVATE KEY") {
                bail!(
                    "{} does not look like a PEM private key (no 'PRIVATE KEY' marker)",
                    private.display()
                );
            }
            let public_key = match public {
                Some(p) => Some(read_public_key(&p)?),
                None => None,
            };
            let payload = PrivateKey {
                name: name.clone(),
                key_pem: key_pem.to_string(),
                public_key,
            };
            v.add(Kind::PrivateKey, "name", &name, &payload)?;
            println!("stored private key '{name}' (sealed, end-to-end encrypted)");
        }
        KeyCmd::Install { name, out, force } => {
            let rec = v
                .find(Kind::PrivateKey, "name", &name)
                .with_context(|| format!("private key '{name}' not found"))?;
            let payload: PrivateKey = rec.payload()?;
            let pem = Zeroizing::new(payload.key_pem);
            let out = match out {
                // An explicit --out is the user's own typed choice.
                Some(p) => p,
                // The default path is derived from the record's name, which may
                // have arrived over sync unvalidated — constrain it to a plain
                // filename under ~/.ssh so it can't escape to an arbitrary path.
                None => {
                    let safe = safe_key_name(&payload.name).with_context(|| {
                        format!(
                            "refusing to install private key with unsafe name {:?}",
                            payload.name
                        )
                    })?;
                    dirs::home_dir()
                        .context("cannot determine home directory")?
                        .join(".ssh")
                        .join(safe)
                }
            };
            write_private_key(&out, &pem, force)?;
            println!(
                "installed private key '{name}' to {} (mode 0600)",
                out.display()
            );
        }
    }
    Ok(())
}

/// Reject a key name that could escape `~/.ssh/<name>` when used to build the
/// install path. This is the real security boundary: a `PrivateKey` record can
/// arrive over sync (`apply_remote_entry` does NOT run `validate_payload`), so a
/// malicious co-member could ship `name = "config"`, an absolute path, or one
/// with `..` to overwrite an arbitrary file with attacker-controlled contents
/// (→ ssh `ProxyCommand` RCE). We refuse any name that is not a single, plain
/// filename component.
fn safe_key_name(name: &str) -> Result<&str> {
    let ok = !name.is_empty()
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\\')
        && std::path::Path::new(name)
            .file_name()
            .and_then(|s| s.to_str())
            == Some(name);
    if !ok {
        bail!("invalid key name {name:?}: must be a plain filename (no '/', '\\', '..', or leading '.')");
    }
    Ok(name)
}

/// Write private-key PEM to `out`, creating the file with mode 0600 AT CREATION
/// (never a world-readable window). Deliberately does NOT reuse `atomic_write`,
/// whose `File::create` opens at the umask default (typically 0644) and only
/// chmods to 0600 afterward — that leak window is unacceptable for plaintext key
/// material. `create_new(true)` sets O_EXCL so an existing file is an error;
/// `--force` removes the old file first, then still creates 0600 via O_EXCL
/// (never a plain truncating open that could momentarily widen perms).
fn write_private_key(out: &std::path::Path, pem: &Zeroizing<String>, force: bool) -> Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
        // A newly created ~/.ssh at umask default is often 0755; tighten any dir
        // we just made to 0700 so the key's parent isn't world-traversable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    if force && out.exists() {
        std::fs::remove_file(out).with_context(|| format!("cannot replace {}", out.display()))?;
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_CREAT|O_EXCL: refuse if it already exists
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600); // perms fixed at creation, before any bytes are written
    }
    // On non-unix we still get O_EXCL create; file perms are best-effort only
    // (Windows ACLs are out of scope — see module note).
    let mut f = opts.open(out).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "{} already exists (use --force to overwrite)",
                out.display()
            )
        } else {
            // Never leak key bytes into an error; only the path/os error.
            anyhow::Error::new(e).context(format!("cannot create {}", out.display()))
        }
    })?;
    f.write_all(pem.as_bytes())
        .with_context(|| format!("cannot write {}", out.display()))?;
    f.sync_all()
        .with_context(|| format!("cannot flush {}", out.display()))?;

    // Defense in depth: verify the on-disk perms are exactly 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(out)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "{} has unexpected mode {:o} (expected 600)",
                out.display(),
                mode
            );
        }
    }
    Ok(())
}

/// Read a PUBLIC key file, rejecting anything that looks like private key
/// material. The vault layer enforces this too, but we fail early with a
/// friendly message so private keys never even reach the vault.
fn read_public_key(path: &std::path::Path) -> Result<String> {
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    if contents.contains("PRIVATE KEY") {
        bail!(
            "{} looks like a PRIVATE key — only public keys (.pub) belong in the vault",
            path.display()
        );
    }
    Ok(contents.trim().to_string())
}

/// Compute an OpenSSH-style fingerprint (`SHA256:<base64-no-pad>`) over the
/// wire blob (the base64-decoded second field of a `ssh-* <base64> comment`
/// line). Returns `None` if the line has no parseable base64 blob.
fn ssh_fingerprint(public_key: &str) -> Option<String> {
    let blob_b64 = public_key.split_whitespace().nth(1)?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .ok()?;
    let digest = Sha256::digest(&blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    Some(format!("SHA256:{b64}"))
}

fn fwd_cmd(cmd: FwdCmd) -> Result<()> {
    let mut v = open_vault()?;
    match cmd {
        FwdCmd::Add {
            name,
            spec,
            host,
            kind,
        } => {
            let kind: ForwardKind = kind.into();
            sshconfig::validate_forward_spec(kind, &spec)?;
            if v.find(Kind::Host, "alias", &host).is_none() {
                bail!("host '{host}' not found — add it first with `sshvault host add {host}`");
            }
            let f = PortForward {
                name: name.clone(),
                kind,
                spec,
                host,
            };
            v.add(Kind::PortForward, "name", &name, &f)?;
            println!("added forward '{name}' — run `sshvault apply` to update ssh config");
        }
        FwdCmd::Edit {
            name,
            spec,
            host,
            kind,
        } => {
            let rec = v
                .find(Kind::PortForward, "name", &name)
                .with_context(|| format!("forward '{name}' not found"))?;
            let mut f: PortForward = rec.payload()?;
            if let Some(k) = kind {
                f.kind = k.into()
            }
            if let Some(s) = spec {
                f.spec = s
            }
            if let Some(h) = host {
                f.host = h
            }
            // re-validate against the *final* kind/spec/host combination
            sshconfig::validate_forward_spec(f.kind, &f.spec)?;
            if v.find(Kind::Host, "alias", &f.host).is_none() {
                bail!(
                    "host '{}' not found — add it first with `sshvault host add {}`",
                    f.host,
                    f.host
                );
            }
            v.edit(Kind::PortForward, "name", &name, &f)?;
            println!("updated forward '{name}' — run `sshvault apply` to update ssh config");
        }
        FwdCmd::Rm { name } => {
            v.remove(Kind::PortForward, "name", &name)?;
            println!("removed forward '{name}' — run `sshvault apply` to update ssh config");
        }
        FwdCmd::List => {
            let mut fwds = v.list::<PortForward>(Kind::PortForward);
            fwds.sort_by(|a, b| a.1.name.cmp(&b.1.name));
            for (_, f) in fwds {
                let kind = match f.kind {
                    ForwardKind::Local => "local",
                    ForwardKind::Remote => "remote",
                    ForwardKind::Dynamic => "dynamic",
                };
                println!("{}  {kind}  {}  (host: {})", f.name, f.spec, f.host);
            }
        }
    }
    Ok(())
}

fn apply(ssh_dir: Option<PathBuf>) -> Result<()> {
    let v = open_vault()?;
    apply_vault(&v, ssh_dir)
}

fn apply_vault(v: &Vault, ssh_dir: Option<PathBuf>) -> Result<()> {
    let ssh_dir = match ssh_dir {
        Some(d) => d,
        None => dirs::home_dir()
            .context("cannot determine home directory")?
            .join(".ssh"),
    };
    let hosts: Vec<Host> = v.list(Kind::Host).into_iter().map(|(_, h)| h).collect();
    let fwds: Vec<PortForward> = v
        .list(Kind::PortForward)
        .into_iter()
        .map(|(_, f)| f)
        .collect();
    let n_hosts = hosts.len();
    let applied = sshconfig::apply(&hosts, &fwds, &ssh_dir)?;
    println!("wrote {} ({n_hosts} hosts)", applied.managed_path.display());
    if applied.include_added {
        println!(
            "added `Include` directive to {}",
            ssh_dir.join("config").display()
        );
    }
    Ok(())
}

fn import(file: &str) -> Result<()> {
    let json: serde_json::Value = if file == "-" {
        serde_json::from_reader(std::io::stdin()).context("stdin is not valid JSON")?
    } else {
        serde_json::from_str(
            &std::fs::read_to_string(file).with_context(|| format!("cannot read {file}"))?,
        )
        .with_context(|| format!("{file} is not valid JSON"))?
    };
    let mut v = open_vault()?;
    let (imported, skipped) = v.import_json(&json)?;
    println!("imported {imported} records ({skipped} skipped as duplicates)");
    Ok(())
}

// ---- helpers ----------------------------------------------------------------

fn sync(relay: Option<String>) -> Result<()> {
    let mut v = open_vault()?;
    let rt = tokio::runtime::Runtime::new().context("failed to start async runtime")?;
    rt.block_on(async {
        if let Some(url) = relay {
            let url = url.trim_end_matches('/').to_string();
            v.set_relay_url(&url)?;
            sshvault::sync::enroll(&v, &url).await?;
            println!("enrolled this device with {url}");
        }
        let (pushed, pulled) = sshvault::sync::sync_once(&mut v).await?;
        println!("synced: {pushed} pushed, {pulled} pulled");
        Ok::<_, anyhow::Error>(())
    })
}

fn syncd(apply: bool) -> Result<()> {
    let mut v = open_vault()?;
    if v.relay_url().is_none() {
        bail!("no relay configured — run `sshvault sync --relay <url>` once to set it");
    }
    let rt = tokio::runtime::Runtime::new().context("failed to start async runtime")?;
    rt.block_on(async {
        println!("syncd: watching relay for changes (Ctrl-C to stop)");
        tokio::select! {
            r = sshvault::sync::syncd(&mut v, |v, pushed, pulled| {
                if pushed + pulled > 0 {
                    println!("synced: {pushed} pushed, {pulled} pulled");
                }
                if apply && pulled > 0 {
                    if let Err(e) = apply_vault(v, None) {
                        eprintln!("apply failed: {e:#}");
                    }
                }
            }) => r.map_err(anyhow::Error::from),
            _ = tokio::signal::ctrl_c() => {
                println!("\nsyncd: stopped");
                Ok(())
            }
        }
    })
}

fn serve(
    addr: &str,
    db: &str,
    tls_cert: Option<std::path::PathBuf>,
    tls_key: Option<std::path::PathBuf>,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    // clap's `requires` guarantees both or neither.
    let tls = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => Some(sshvault::relay::TlsPaths { cert, key }),
        _ => None,
    };
    let rt = tokio::runtime::Runtime::new().context("failed to start async runtime")?;
    rt.block_on(sshvault::relay::serve(addr, db, tls))
}

fn device_cmd(cmd: DeviceCmd) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to start async runtime")?;
    match cmd {
        DeviceCmd::Enroll {
            vault,
            relay,
            device_name,
        } => {
            let vault_id = uuid::Uuid::parse_str(vault.trim())
                .context("invalid vault id — copy it from `sshvault device list`")?;
            let relay = relay.trim_end_matches('/').to_string();
            let dir = sshvault::device::default_dir();
            let pass = prompt_new_passphrase()?;
            rt.block_on(async {
                println!("enrolling this device — waiting for approval...");
                sshvault::device::enroll_and_wait(
                    &dir,
                    &device_name,
                    &pass,
                    vault_id,
                    &relay,
                    |code| {
                        println!("\nOn an already-enrolled device, run:");
                        println!("    sshvault device approve {code}\n");
                        println!("(code for THIS device: {code})");
                    },
                )
                .await
            })?;
            println!("approved — vault key installed. Run `sshvault sync` to pull your data.");
            Ok(())
        }
        DeviceCmd::Approve { code } => {
            let v = open_vault()?;
            let relay = require_relay(&v)?;
            let name = rt.block_on(sshvault::device::approve(&v, &relay, &code))?;
            println!("approved '{name}' ({code}) — it can now sync.");
            Ok(())
        }
        DeviceCmd::List => {
            let v = open_vault()?;
            let relay = require_relay(&v)?;
            let devices = rt.block_on(sshvault::device::list_devices(&v, &relay))?;
            println!("vault: {}", v.vault_id());
            for d in devices {
                let code = sshvault::device::short_code(&d.ed25519_pub_b64);
                let status = if d.revoked {
                    "revoked"
                } else if d.approved {
                    "approved"
                } else {
                    "pending"
                };
                println!("  {code}  {:<10}  {}", status, d.name);
            }
            Ok(())
        }
        DeviceCmd::Revoke { code, rotate } => {
            let mut v = open_vault()?;
            let relay = require_relay(&v)?;
            if rotate {
                let phrase = rpassword::prompt_password("Enter your 24-word recovery phrase: ")
                    .context("failed to read recovery phrase")?;
                let name = rt.block_on(sshvault::device::revoke_and_rotate(
                    &mut v,
                    &relay,
                    &code,
                    phrase.trim(),
                ))?;
                println!(
                    "revoked '{name}' ({code}) and rotated the vault key — it can no longer sync, \
                     and cannot read data written from now on."
                );
                println!("Run `sshvault sync` on your other devices to pick up the new key.");
            } else {
                let name = rt.block_on(sshvault::device::revoke(&v, &relay, &code))?;
                println!("revoked '{name}' ({code}) — it can no longer sync or re-enroll.");
                println!(
                    "note: it still holds the current vault key. Use `--rotate` for forward secrecy."
                );
            }
            Ok(())
        }
    }
}

fn share_cmd(cmd: ShareCmd) -> Result<()> {
    let mut v = open_vault()?;
    let rt = tokio::runtime::Runtime::new().context("failed to start async runtime")?;
    match cmd {
        ShareCmd::Create { name, members } => {
            let relay = require_relay(&v)?;
            let id = rt.block_on(sshvault::device::create_share(
                &mut v, &relay, &name, &members,
            ))?;
            println!(
                "created share '{name}' ({id}) with {} member(s).",
                members.len()
            );
            println!("Add hosts to it with `sshvault host add <alias> --share {name}`.");
            Ok(())
        }
        ShareCmd::Add { name, members } => {
            let relay = require_relay(&v)?;
            let id = v
                .resolve_share(&name)
                .with_context(|| format!("no share named '{name}'"))?;
            rt.block_on(sshvault::device::share_add(&v, &relay, id, &members))?;
            println!("granted '{name}' to {} member(s).", members.len());
            Ok(())
        }
        ShareCmd::Remove { name, code } => {
            let relay = require_relay(&v)?;
            let id = v
                .resolve_share(&name)
                .with_context(|| format!("no share named '{name}'"))?;
            let who = rt.block_on(sshvault::device::share_remove(&mut v, &relay, id, &code))?;
            println!(
                "removed '{who}' ({code}) from share '{name}' and rotated its key — \
                 it can no longer read data written to '{name}' from now on."
            );
            Ok(())
        }
        ShareCmd::List => {
            let shares = v.share_names();
            if shares.is_empty() {
                println!("no named shares — everything is in the default (shared-with-all) share.");
            }
            for (name, id) in shares {
                let member = if v.has_share(id) {
                    "member"
                } else {
                    "not a member"
                };
                println!("  {name}  ({id})  {member}");
            }
            Ok(())
        }
    }
}

fn recover(relay: &str, device_name: &str) -> Result<()> {
    let dir = sshvault::device::default_dir();
    let relay = relay.trim_end_matches('/').to_string();
    let phrase = rpassword::prompt_password("Enter your 24-word recovery phrase: ")
        .context("failed to read recovery phrase")?;
    let pass = prompt_new_passphrase()?;
    let rt = tokio::runtime::Runtime::new().context("failed to start async runtime")?;
    let mut v = rt.block_on(sshvault::device::recover(
        &dir,
        device_name,
        &pass,
        phrase.trim(),
        &relay,
    ))?;
    let (_, pulled) = rt.block_on(sshvault::sync::sync_once(&mut v))?;
    println!(
        "recovered vault {} — pulled {pulled} records.",
        v.vault_id()
    );
    println!("run `sshvault apply` to write your ssh config.");
    Ok(())
}

fn require_relay(v: &Vault) -> Result<String> {
    v.relay_url()
        .map(|s| s.to_string())
        .context("no relay configured — run `sshvault sync --relay <url>` first")
}

fn open_vault() -> Result<Vault> {
    let dir = vault::default_dir();
    let pass = passphrase("Vault passphrase: ")?;
    Ok(Vault::open(&dir, &pass)?)
}

/// `$SSHVAULT_PASSPHRASE` (scripts/tests) or interactive prompt.
fn passphrase(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("SSHVAULT_PASSPHRASE") {
        return Ok(p);
    }
    rpassword::prompt_password(prompt).context("failed to read passphrase")
}

fn prompt_new_passphrase() -> Result<String> {
    if let Ok(p) = std::env::var("SSHVAULT_PASSPHRASE") {
        return Ok(p);
    }
    let first = rpassword::prompt_password("Choose a vault passphrase: ")?;
    if first.len() < 8 {
        bail!("passphrase must be at least 8 characters");
    }
    let second = rpassword::prompt_password("Repeat passphrase: ")?;
    if first != second {
        bail!("passphrases do not match");
    }
    Ok(first)
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unnamed-device".into())
}

#[cfg(test)]
mod tests {
    use super::ssh_fingerprint;
    /// A well-formed OpenSSH ed25519 public-key line (51-byte wire blob).
    const PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDCypbnDnL/FGaVRCiLo6/QO2ueMrRKGBUhexVRJ/3HX test@host";

    /// Ask `ssh-keygen -lf` for the fingerprint of a pubkey line, if available.
    /// Returns the `SHA256:...` token, or None if ssh-keygen isn't installed /
    /// rejects the input.
    fn ssh_keygen_fingerprint(pubkey: &str) -> Option<String> {
        let dir = tempfile::tempdir().ok()?;
        let path = dir.path().join("k.pub");
        std::fs::write(&path, format!("{pubkey}\n")).ok()?;
        let out = std::process::Command::new("ssh-keygen")
            .arg("-lf")
            .arg(&path)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        // Output: "256 SHA256:<b64> comment (ED25519)"
        String::from_utf8(out.stdout)
            .ok()?
            .split_whitespace()
            .find(|f| f.starts_with("SHA256:"))
            .map(str::to_string)
    }

    #[test]
    fn fingerprint_matches_ssh_keygen_or_is_well_formed() {
        let got = ssh_fingerprint(PUBKEY).expect("well-formed pubkey yields a fingerprint");

        match ssh_keygen_fingerprint(PUBKEY) {
            Some(expected) => {
                // Known-answer: our fingerprint must equal ssh-keygen's exactly.
                assert_eq!(got, expected, "fingerprint disagrees with ssh-keygen");
            }
            None => {
                // ssh-keygen unavailable: assert the OpenSSH format and stability.
                let b64 = got.strip_prefix("SHA256:").expect("SHA256: prefix");
                assert_eq!(b64.len(), 43, "SHA256 → 32 bytes → 43 no-pad base64 chars");
                assert!(!b64.contains('='), "no-pad base64 has no trailing '='");
                assert_eq!(
                    got,
                    ssh_fingerprint(PUBKEY).unwrap(),
                    "fingerprint is deterministic across calls"
                );
            }
        }
    }

    #[test]
    fn unparseable_key_has_no_fingerprint() {
        // No base64 second field → None, but the caller still stores public_key.
        assert_eq!(ssh_fingerprint("not-a-key"), None);
        assert_eq!(ssh_fingerprint(""), None);
    }

    // ---- private-key materialization safety ------------------------------

    #[cfg(unix)]
    mod materialize {
        use super::super::write_private_key;
        use std::os::unix::fs::PermissionsExt;
        use zeroize::Zeroizing;

        const PEM: &str =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n";

        fn mode(p: &std::path::Path) -> u32 {
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        }

        #[test]
        fn safe_key_name_blocks_path_escapes() {
            use super::super::safe_key_name;
            // plain filenames are allowed
            assert!(safe_key_name("id_ed25519").is_ok());
            assert!(safe_key_name("work-key").is_ok());
            // the exploit vectors from adversarial review must all be refused:
            // traversal, absolute paths, path separators, and dotfiles.
            for bad in [
                "",
                ".",
                "..",
                "../evil",
                "../../.bashrc",
                "/etc/passwd",
                "/home/victim/.bashrc",
                "a/b",
                "a\\b",
                ".hidden",
            ] {
                assert!(
                    safe_key_name(bad).is_err(),
                    "expected {bad:?} to be rejected as an unsafe key name"
                );
            }
        }

        #[test]
        fn materialized_file_is_0600() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("id_ed25519");
            write_private_key(&out, &Zeroizing::new(PEM.to_string()), false).unwrap();
            assert_eq!(mode(&out), 0o600);
            assert_eq!(std::fs::read_to_string(&out).unwrap(), PEM);
        }

        #[test]
        fn install_without_force_refuses_existing_file() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("id_ed25519");
            std::fs::write(&out, "pre-existing").unwrap();
            let err = write_private_key(&out, &Zeroizing::new(PEM.to_string()), false).unwrap_err();
            assert!(
                err.to_string().contains("already exists"),
                "expected refusal, got: {err}"
            );
            // The original file must be untouched.
            assert_eq!(std::fs::read_to_string(&out).unwrap(), "pre-existing");
        }

        #[test]
        fn install_with_force_replaces_and_stays_0600() {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("id_ed25519");
            // Pre-existing world-readable file.
            std::fs::write(&out, "old").unwrap();
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();
            write_private_key(&out, &Zeroizing::new(PEM.to_string()), true).unwrap();
            assert_eq!(
                mode(&out),
                0o600,
                "replaced file must be 0600, not the old 0644"
            );
            assert_eq!(std::fs::read_to_string(&out).unwrap(), PEM);
        }
    }
}
