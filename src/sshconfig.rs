//! `sshvault apply`: generate the managed include file and wire it into the
//! user's `~/.ssh/config` without ever touching their hand-written content.
//!
//! Invariants (Phase 1 gate):
//! - `sshvault.conf` is fully owned by us and regenerated atomically
//! - the user's `config` is modified exactly once (prepending the `Include`);
//!   if the include is already present the file is not even opened for write
//! - output is accepted by `ssh -G`

use crate::record::{ForwardKind, Host, PortForward};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MANAGED_FILE: &str = "sshvault.conf";

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("cannot write ssh config: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid forward spec '{spec}': expected {expected}")]
    BadForwardSpec {
        spec: String,
        expected: &'static str,
    },
}

/// Validate a port-forward spec at input time (CLI `fwd add`).
/// local/remote: `[bind:]listen_port:host:port`; dynamic: `[bind:]listen_port`.
pub fn validate_forward_spec(kind: ForwardKind, spec: &str) -> Result<(), ApplyError> {
    let err = |expected| ApplyError::BadForwardSpec {
        spec: spec.into(),
        expected,
    };
    let parts: Vec<&str> = spec.split(':').collect();
    let port_ok = |s: &str| s.parse::<u16>().is_ok();
    match kind {
        ForwardKind::Dynamic => match parts.as_slice() {
            [p] if port_ok(p) => Ok(()),
            [_bind, p] if port_ok(p) => Ok(()),
            _ => Err(err("`port` or `bind:port`")),
        },
        ForwardKind::Local | ForwardKind::Remote => match parts.as_slice() {
            [lp, _host, dp] if port_ok(lp) && port_ok(dp) => Ok(()),
            [_bind, lp, _host, dp] if port_ok(lp) && port_ok(dp) => Ok(()),
            _ => Err(err(
                "`listen_port:host:port` or `bind:listen_port:host:port`",
            )),
        },
    }
}

/// Render the managed config from live vault records. Deterministic: hosts
/// sorted by alias, forwards by name.
pub fn render(hosts: &[Host], forwards: &[PortForward]) -> String {
    let mut hosts: Vec<&Host> = hosts.iter().collect();
    hosts.sort_by(|a, b| a.alias.cmp(&b.alias));
    let mut out = String::from(
        "# Managed by sshvault — DO NOT EDIT.\n\
         # Regenerate with `sshvault apply`. Your own config lives in ~/.ssh/config.\n",
    );
    for host in hosts {
        out.push('\n');
        out.push_str(&format!("Host {}\n", quote(&host.alias)));
        if let Some(v) = &host.hostname {
            out.push_str(&format!("    HostName {}\n", quote(v)));
        }
        if let Some(p) = host.port {
            out.push_str(&format!("    Port {p}\n"));
        }
        if let Some(v) = &host.user {
            out.push_str(&format!("    User {}\n", quote(v)));
        }
        if let Some(v) = &host.jump_host {
            out.push_str(&format!("    ProxyJump {}\n", quote(v)));
        }
        if let Some(v) = &host.identity_file {
            out.push_str(&format!("    IdentityFile {}\n", quote(v)));
        }
        let mut fwds: Vec<&PortForward> =
            forwards.iter().filter(|f| f.host == host.alias).collect();
        fwds.sort_by(|a, b| a.name.cmp(&b.name));
        for f in fwds {
            out.push_str(&render_forward(f));
        }
    }
    out
}

/// `spec` was validated at input; render it in ssh_config token form
/// (`listen` and `host:port` are separate tokens).
fn render_forward(f: &PortForward) -> String {
    let parts: Vec<&str> = f.spec.split(':').collect();
    match f.kind {
        ForwardKind::Dynamic => format!("    DynamicForward {}\n", f.spec),
        ForwardKind::Local | ForwardKind::Remote => {
            let keyword = if f.kind == ForwardKind::Local {
                "LocalForward"
            } else {
                "RemoteForward"
            };
            let (listen, dest) = if parts.len() == 4 {
                (
                    format!("{}:{}", parts[0], parts[1]),
                    format!("{}:{}", parts[2], parts[3]),
                )
            } else {
                (parts[0].to_string(), format!("{}:{}", parts[1], parts[2]))
            };
            format!("    {keyword} {listen} {dest}\n")
        }
    }
}

fn quote(token: &str) -> String {
    // newlines and double quotes are rejected at the vault input boundary
    if token.contains(' ') || token.contains('\t') || token.is_empty() {
        format!("\"{token}\"")
    } else {
        token.to_string()
    }
}

/// Result of an [`apply`] run, for user-facing reporting.
#[derive(Debug, PartialEq)]
pub struct Applied {
    pub managed_path: PathBuf,
    /// true if we prepended the Include to the user's config this run
    pub include_added: bool,
}

/// Write `<ssh_dir>/sshvault.conf` and make sure `<ssh_dir>/config` includes it.
pub fn apply(
    hosts: &[Host],
    forwards: &[PortForward],
    ssh_dir: &Path,
) -> Result<Applied, ApplyError> {
    fs::create_dir_all(ssh_dir)?;
    let managed_path = ssh_dir.join(MANAGED_FILE);
    let content = render(hosts, forwards);
    atomic_write(&managed_path, content.as_bytes())?;

    // In the real ~/.ssh use the portable tilde form; elsewhere (tests) absolute.
    let include_target = if Some(ssh_dir) == dirs::home_dir().map(|h| h.join(".ssh")).as_deref() {
        format!("~/.ssh/{MANAGED_FILE}")
    } else {
        managed_path.display().to_string()
    };
    let include_added = ensure_include(&ssh_dir.join("config"), &include_target)?;
    Ok(Applied {
        managed_path,
        include_added,
    })
}

/// Prepend `Include <target>` to the user's config unless any Include of our
/// managed file is already present. Never rewrites existing bytes.
fn ensure_include(config_path: &Path, include_target: &str) -> Result<bool, ApplyError> {
    let existing = match fs::read(config_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    // liberal detection: any Include line mentioning our file counts, so a
    // user who moved the directive keeps their layout untouched
    let already = String::from_utf8_lossy(&existing).lines().any(|line| {
        let l = line.trim();
        l.to_ascii_lowercase().starts_with("include") && l.contains(MANAGED_FILE)
    });
    if already {
        return Ok(false);
    }
    let mut new_content = format!("Include {include_target}\n\n").into_bytes();
    new_content.extend_from_slice(&existing);
    atomic_write(config_path, &new_content)?;
    Ok(true)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), ApplyError> {
    let tmp = path.with_extension("sshvault-tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample() -> (Vec<Host>, Vec<PortForward>) {
        (
            vec![
                Host {
                    alias: "web".into(),
                    hostname: Some("web.example.com".into()),
                    port: Some(2222),
                    user: Some("deploy".into()),
                    jump_host: Some("bastion".into()),
                    identity_file: Some("~/.ssh/id_ed25519".into()),
                    tags: vec![],
                },
                Host {
                    alias: "bastion".into(),
                    hostname: Some("1.2.3.4".into()),
                    ..Default::default()
                },
            ],
            vec![PortForward {
                name: "db".into(),
                kind: ForwardKind::Local,
                spec: "5432:localhost:5432".into(),
                host: "web".into(),
            }],
        )
    }

    #[test]
    fn render_is_deterministic_and_sorted() {
        let (hosts, fwds) = sample();
        let out = render(&hosts, &fwds);
        let bastion = out.find("Host bastion").unwrap();
        let web = out.find("Host web").unwrap();
        assert!(bastion < web, "hosts sorted by alias");
        assert!(out.contains("    LocalForward 5432 localhost:5432\n"));
        assert!(out.contains("    ProxyJump bastion\n"));
        assert_eq!(out, render(&hosts, &fwds));
    }

    #[test]
    fn forward_specs_validate() {
        use ForwardKind::*;
        assert!(validate_forward_spec(Local, "8080:localhost:80").is_ok());
        assert!(validate_forward_spec(Local, "127.0.0.1:8080:localhost:80").is_ok());
        assert!(validate_forward_spec(Dynamic, "1080").is_ok());
        assert!(validate_forward_spec(Dynamic, "localhost:1080").is_ok());
        assert!(validate_forward_spec(Local, "nope").is_err());
        assert!(
            validate_forward_spec(Local, "99999:h:80").is_err(),
            "port > u16 rejected"
        );
        assert!(validate_forward_spec(Dynamic, "8080:localhost:80").is_err());
    }

    #[test]
    fn user_config_survives_byte_for_byte() {
        let tmp = TempDir::new().unwrap();
        let user_config =
            "# my precious config\t \n\n\n  Host personal\n\tUser me   \n# trailing junk\n\t\t\n";
        fs::write(tmp.path().join("config"), user_config).unwrap();

        let (hosts, fwds) = sample();
        let first = apply(&hosts, &fwds, tmp.path()).unwrap();
        assert!(first.include_added);
        let after_first = fs::read_to_string(tmp.path().join("config")).unwrap();
        let expected_include = format!("Include {}\n\n", tmp.path().join(MANAGED_FILE).display());
        assert_eq!(
            after_first,
            format!("{expected_include}{user_config}"),
            "user bytes preserved exactly below the include"
        );

        // second apply: include detected, config not rewritten
        let second = apply(&hosts, &fwds, tmp.path()).unwrap();
        assert!(!second.include_added);
        assert_eq!(
            fs::read_to_string(tmp.path().join("config")).unwrap(),
            after_first
        );
    }

    #[test]
    fn missing_user_config_is_created() {
        let tmp = TempDir::new().unwrap();
        let (hosts, fwds) = sample();
        apply(&hosts, &fwds, tmp.path()).unwrap();
        let cfg = fs::read_to_string(tmp.path().join("config")).unwrap();
        assert!(cfg.starts_with("Include "));
    }

    #[test]
    fn ssh_accepts_generated_config() {
        let ssh = which_ssh();
        let Some(ssh) = ssh else {
            eprintln!("ssh not found; skipping ssh -G acceptance test");
            return;
        };
        let tmp = TempDir::new().unwrap();
        let (hosts, fwds) = sample();
        apply(&hosts, &fwds, tmp.path()).unwrap();
        let out = std::process::Command::new(ssh)
            .args(["-G", "-F"])
            .arg(tmp.path().join("config"))
            .arg("web")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ssh -G rejected config: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("hostname web.example.com"));
        assert!(stdout.contains("port 2222"));
        assert!(stdout.contains("proxyjump bastion"), "stdout: {stdout}");
    }

    fn which_ssh() -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join("ssh"))
                .find(|p| p.exists())
        })
    }
}
