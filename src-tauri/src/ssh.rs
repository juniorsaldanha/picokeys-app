//! SSH security keys (`ecdsa-sk` / `ed25519-sk`) and git SSH signing, driving the local
//! OpenSSH and git tools. Nothing here talks to the key directly: ssh-keygen/ssh do (FIDO).
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use types::{GitSetup, GitSigning, NewSshKey, SshEnv, SshKey};

type R<T> = Result<T, String>;

const EXE: &str = if cfg!(windows) { ".exe" } else { "" };

fn home() -> R<PathBuf> {
    std::env::home_dir().ok_or_else(|| "Can't find your home folder.".into())
}

fn ssh_dir() -> R<PathBuf> {
    Ok(home()?.join(".ssh"))
}

/// GUI apps don't get the shell's PATH on macOS, so look in the usual places first.
fn tool_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = if cfg!(windows) {
        vec![r"C:\Windows\System32\OpenSSH".into(), r"C:\Program Files\OpenSSH".into(), r"C:\Program Files\Git\usr\bin".into(), r"C:\Program Files\Git\cmd".into()]
    } else {
        ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"].iter().map(PathBuf::from).collect()
    };
    if let Some(p) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&p));
    }
    dirs
}

fn find(tool: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = tool_dirs().into_iter().map(|d| d.join(format!("{tool}{EXE}"))).filter(|p| p.is_file()).collect();
    out.dedup();
    out
}

fn run(cmd: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).stdin(Stdio::null()).output().ok()?;
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    Some(s.trim().to_string())
}

/// Why this ssh-keygen can't use security keys, if it can't (without touching the key).
fn fido_problem(keygen: &Path) -> Option<String> {
    let ssh = keygen.with_file_name(format!("ssh{EXE}"));
    if !run(&ssh, &["-Q", "key"]).is_some_and(|k| k.contains("sk-ecdsa-sha2-nistp256@openssh.com")) {
        return Some("This OpenSSH doesn't support security keys (needs OpenSSH 8.2 or newer).".into());
    }
    // Apple builds OpenSSH without the built-in FIDO provider.
    if cfg!(target_os = "macos") && keygen.starts_with("/usr/bin") && std::env::var_os("SSH_SK_PROVIDER").is_none() {
        return Some("Apple's built-in OpenSSH can't use security keys. Install OpenSSH from Homebrew.".into());
    }
    None
}

fn git() -> Option<PathBuf> {
    find("git").into_iter().next()
}

fn git_get(git: &Path, key: &str) -> Option<String> {
    let o = Command::new(git).args(["config", "--global", "--get", key]).stdin(Stdio::null()).output().ok()?;
    let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.status.success() && !v.is_empty()).then_some(v)
}

fn git_set(git: &Path, key: &str, value: &str) -> R<()> {
    let o = Command::new(git).args(["config", "--global", key, value]).stdin(Stdio::null()).output().map_err(|e| e.to_string())?;
    if o.status.success() { Ok(()) } else { Err(format!("git config {key} failed: {}", String::from_utf8_lossy(&o.stderr).trim())) }
}

fn signing(git: &Path) -> GitSigning {
    let b = |k| git_get(git, k).is_some_and(|v| v == "true");
    GitSigning {
        format: git_get(git, "gpg.format"),
        signing_key: git_get(git, "user.signingkey"),
        commit_sign: b("commit.gpgsign"),
        tag_sign: b("tag.gpgsign"),
        allowed_signers: git_get(git, "gpg.ssh.allowedSignersFile"),
        ssh_program: git_get(git, "gpg.ssh.program"),
        ssh_command: git_get(git, "core.sshCommand"),
        email: git_get(git, "user.email"),
    }
}

/// The first ssh-keygen that can use security keys, else the first one found (with its problem).
fn keygen() -> (Option<PathBuf>, Option<String>) {
    let all = find("ssh-keygen");
    if let Some(ok) = all.iter().find(|k| fido_problem(k).is_none()) {
        return (Some(ok.clone()), None);
    }
    match all.first() {
        Some(k) => (None, fido_problem(k)),
        None => (None, Some("OpenSSH isn't installed.".into())),
    }
}

pub fn env() -> R<SshEnv> {
    let (kg, problem) = keygen();
    let ssh = kg.as_ref().map(|k| k.with_file_name(format!("ssh{EXE}"))).or_else(|| find("ssh").into_iter().next());
    let git = git();
    Ok(SshEnv {
        os: std::env::consts::OS.into(),
        version: ssh.as_deref().and_then(|s| run(s, &["-V"])).unwrap_or_default(),
        keygen: kg.map(|p| p.display().to_string()),
        ssh: ssh.map(|p| p.display().to_string()),
        problem,
        brew: cfg!(target_os = "macos") && ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].iter().any(|p| Path::new(p).is_file()),
        signing: git.as_deref().map(signing).unwrap_or_default(),
        git: git.map(|p| p.display().to_string()),
    })
}

// ---------- public key files ----------

fn take_string<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
    let s = b.get(4..4 + n)?;
    *b = &b[4 + n..];
    Some(s)
}

/// `(kind, application, comment)` for an sk public key line; None for other key types.
fn parse_pub(line: &str) -> Option<(String, String, String)> {
    let mut parts = line.trim().splitn(3, ' ');
    let (ty, b64, comment) = (parts.next()?, parts.next()?, parts.next().unwrap_or(""));
    let blob = B64.decode(b64).ok()?;
    let mut b = &blob[..];
    if take_string(&mut b)? != ty.as_bytes() {
        return None;
    }
    let kind = match ty {
        "sk-ecdsa-sha2-nistp256@openssh.com" => {
            take_string(&mut b)?; // curve
            "ecdsa-sk"
        }
        "sk-ssh-ed25519@openssh.com" => "ed25519-sk",
        _ => return None,
    };
    take_string(&mut b)?; // public point
    let app = String::from_utf8(take_string(&mut b)?.to_vec()).ok()?;
    Some((kind.into(), app, comment.into()))
}

/// Same key? `signingkey` may be a path (`~/` allowed), `key::<type> <b64>` or a bare `<type> <b64>`.
fn is_signing_key(signing: Option<&str>, path: &Path, line: &str) -> bool {
    let Some(s) = signing else { return false };
    let key2 = |l: &str| l.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let lit = s.strip_prefix("key::").unwrap_or(s);
    if key2(lit) == key2(line) {
        return true;
    }
    let expanded = match s.strip_prefix("~/") {
        Some(rest) => home().map(|h| h.join(rest)).unwrap_or_default(),
        None => PathBuf::from(s),
    };
    expanded == path
}

pub fn keys() -> R<Vec<SshKey>> {
    let signing_key = git().and_then(|g| git_get(&g, "user.signingkey"));
    let Ok(rd) = std::fs::read_dir(ssh_dir()?) else { return Ok(vec![]) };
    let mut out: Vec<SshKey> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .filter_map(|p| {
            let line = std::fs::read_to_string(&p).ok()?.lines().next()?.to_string();
            let (kind, application, comment) = parse_pub(&line)?;
            Some(SshKey { signing: is_signing_key(signing_key.as_deref(), &p, &line), path: p.display().to_string(), kind, application, comment, public: line })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

// ---------- running OpenSSH with a PIN ----------

/// Runs an OpenSSH tool non-interactively. A PIN, if needed, is handed over through a
/// throwaway SSH_ASKPASS helper that echoes it from the environment (never on the command line).
fn run_openssh(tool: &Path, args: &[String], pin: Option<&str>, timeout: Duration) -> R<(bool, String)> {
    let dir = std::env::temp_dir().join(format!("pkm-askpass-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let helper = if cfg!(windows) {
        let p = dir.join("askpass.cmd");
        std::fs::write(&p, "@echo off\r\necho %PKM_SSH_PIN%\r\n").map_err(|e| e.to_string())?;
        p
    } else {
        let p = dir.join("askpass.sh");
        std::fs::write(&p, "#!/bin/sh\nprintf '%s\\n' \"$PKM_SSH_PIN\"\n").map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
        }
        p
    };
    let result = (|| {
        let mut child = Command::new(tool)
            .args(args)
            .env("SSH_ASKPASS", &helper)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", std::env::var("DISPLAY").unwrap_or_else(|_| ":0".into()))
            .env("PKM_SSH_PIN", pin.unwrap_or(""))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Couldn't run {}: {e}", tool.display()))?;
        let start = Instant::now();
        loop {
            if let Some(_status) = child.try_wait().map_err(|e| e.to_string())? {
                break;
            }
            if start.elapsed() > timeout {
                let _ = child.kill();
                return Err("Timed out waiting for the key (did you touch it?).".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let o = child.wait_with_output().map_err(|e| e.to_string())?;
        let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&o.stderr));
        Ok((o.status.success(), text.trim().to_string()))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn friendly(out: &str) -> String {
    let l = out.to_lowercase();
    if l.contains("incorrect pin") || l.contains("pin invalid") || l.contains("pin_invalid") {
        "Wrong PIN.".into()
    } else if l.contains("pin required") || l.contains("pin_required") {
        "The key needs its PIN for this.".into()
    } else if l.contains("device not found") || l.contains("no device") {
        "Security key not found. Is it plugged in?".into()
    } else if l.contains("unsupported") || l.contains("invalid format") && l.contains("ed25519") {
        "The key doesn't support this key type; try ECDSA.".into()
    } else if l.contains("no fido securitykeyprovider") {
        "This OpenSSH can't use security keys.".into()
    } else {
        out.lines().rfind(|x| !x.trim().is_empty()).unwrap_or("ssh-keygen failed.").to_string()
    }
}

fn valid_file(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) && !name.starts_with('.')
}

pub fn generate(n: &NewSshKey) -> R<SshKey> {
    let (kg, problem) = keygen();
    let kg = kg.ok_or(problem.unwrap_or_default())?;
    if !valid_file(&n.file) {
        return Err("File name may only use letters, digits, '.', '_' and '-'.".into());
    }
    let label = n.label.trim();
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
        return Err("Label may only use letters, digits, '.', '_' and '-'.".into());
    }
    let dir = ssh_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(&n.file);
    if path.exists() || path.with_extension("pub").exists() {
        return Err(format!("{} already exists.", path.display()));
    }
    let mut args: Vec<String> = vec!["-t".into(), if n.ed25519 { "ed25519-sk" } else { "ecdsa-sk" }.into()];
    args.extend(["-f".into(), path.display().to_string(), "-N".into(), String::new(), "-C".into(), n.comment.clone()]);
    args.extend(["-O".into(), format!("application=ssh:{label}")]);
    if n.resident {
        args.extend(["-O".into(), "resident".into()]);
    }
    if n.verify_required {
        args.extend(["-O".into(), "verify-required".into()]);
    }
    let (ok, out) = run_openssh(&kg, &args, n.pin.as_deref(), Duration::from_secs(90))?;
    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    if !ok || !pub_path.exists() {
        return Err(friendly(&out));
    }
    keys()?.into_iter().find(|k| Path::new(&k.path) == pub_path).ok_or_else(|| "Key created but couldn't be read back.".into())
}

// ---------- git ----------

fn allowed_signers_line(email: &str, public: &str) -> String {
    let key: Vec<&str> = public.split_whitespace().take(2).collect();
    format!("{email} namespaces=\"git\" {}", key.join(" "))
}

pub fn setup_git(s: &GitSetup) -> R<GitSigning> {
    let git = git().ok_or("git isn't installed.")?;
    let key = keys()?.into_iter().find(|k| k.path == s.key).ok_or("That key isn't in ~/.ssh anymore.")?;
    let email = s.email.trim();
    if email.is_empty() || email.contains(char::is_whitespace) {
        return Err("Enter the email you commit with.".into());
    }
    git_set(&git, "gpg.format", "ssh")?;
    git_set(&git, "user.signingkey", &key.path)?;
    git_set(&git, "commit.gpgsign", if s.sign_commits { "true" } else { "false" })?;
    git_set(&git, "tag.gpgsign", if s.sign_tags { "true" } else { "false" })?;

    // allowed_signers lets `git log --show-signature` / `git verify-commit` trust the key.
    let signers = match git_get(&git, "gpg.ssh.allowedSignersFile") {
        Some(p) => match p.strip_prefix("~/") {
            Some(rest) => home()?.join(rest),
            None => PathBuf::from(p),
        },
        None => {
            let p = home()?.join(".config").join("git").join("allowed_signers");
            git_set(&git, "gpg.ssh.allowedSignersFile", &p.display().to_string())?;
            p
        }
    };
    let existing = std::fs::read_to_string(&signers).unwrap_or_default();
    let b64 = key.public.split_whitespace().nth(1).unwrap_or_default();
    if !existing.lines().any(|l| l.starts_with(email) && l.contains(b64)) {
        if let Some(d) = signers.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let sep = if existing.is_empty() || existing.ends_with('\n') { "" } else { "\n" };
        std::fs::write(&signers, format!("{existing}{sep}{}\n", allowed_signers_line(email, &key.public))).map_err(|e| e.to_string())?;
    }

    // git runs `ssh-keygen -Y sign` from PATH; point it at the one that supports security keys.
    if let (Some(kg), _) = keygen()
        && cfg!(target_os = "macos")
        && !kg.starts_with("/usr/bin")
    {
        git_set(&git, "gpg.ssh.program", &kg.display().to_string())?;
        if s.use_for_transport {
            git_set(&git, "core.sshCommand", &kg.with_file_name("ssh").display().to_string())?;
        }
    }
    Ok(signing(&git))
}

// ---------- ssh client ----------

/// Appends a `Host` block using this key, unless the host already has one.
pub fn add_host(host: &str, key_pub: &str) -> R<String> {
    let host = host.trim();
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || ".-_*".contains(c)) {
        return Err("Enter a host name like github.com.".into());
    }
    let identity = key_pub.strip_suffix(".pub").ok_or("Pick a key.")?;
    let cfg = ssh_dir()?.join("config");
    let existing = std::fs::read_to_string(&cfg).unwrap_or_default();
    let block = format!("# Added by Pico Key Manager\nHost {host}\n  IdentityFile {identity}\n  IdentitiesOnly yes\n");
    if host_exists(&existing, host) {
        return Err(format!("~/.ssh/config already has a block for {host}. Add this line to it:\n  IdentityFile {identity}"));
    }
    let sep = if existing.is_empty() || existing.ends_with("\n\n") { "" } else if existing.ends_with('\n') { "\n" } else { "\n\n" };
    std::fs::write(&cfg, format!("{existing}{sep}{block}")).map_err(|e| e.to_string())?;
    Ok(block)
}

fn host_exists(cfg: &str, host: &str) -> bool {
    cfg.lines().any(|l| {
        let mut w = l.split_whitespace();
        w.next().is_some_and(|k| k.eq_ignore_ascii_case("host")) && w.any(|h| h == host)
    })
}

/// `ssh -T git@host` with just this key; returns what the server said.
pub fn test(host: &str, key_pub: &str, pin: Option<&str>) -> R<String> {
    let (kg, problem) = keygen();
    let kg = kg.ok_or(problem.unwrap_or_default())?;
    let ssh = kg.with_file_name(format!("ssh{EXE}"));
    let identity = key_pub.strip_suffix(".pub").ok_or("Pick a key.")?;
    let host = host.trim();
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || ".-_@".contains(c)) {
        return Err("Enter a host like git@github.com.".into());
    }
    let target = if host.contains('@') { host.to_string() } else { format!("git@{host}") };
    let args: Vec<String> = ["-T", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", "-i", identity, &target]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (_ok, out) = run_openssh(&ssh, &args, pin, Duration::from_secs(60))?;
    // GitHub/GitLab exit non-zero on -T even when auth worked, so judge by the message.
    let l = out.to_lowercase();
    if l.contains("successfully authenticated") || l.contains("welcome to gitlab") || l.contains("logged in as") {
        Ok(out.lines().find(|x| !x.trim().is_empty() && !x.to_lowercase().contains("touch")).unwrap_or(&out).to_string())
    } else {
        Err(friendly(&out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only: prints what this machine has. `cargo test -p picokeys-app -- --ignored ssh_env_probe --nocapture`
    #[test]
    #[ignore]
    fn ssh_env_probe() {
        println!("{:#?}\n{:#?}", env().unwrap(), keys().unwrap());
    }

    fn s(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_be_bytes()[..], b].concat()
    }

    #[test]
    fn pub_keys_and_config() {
        let ty = "sk-ecdsa-sha2-nistp256@openssh.com";
        let blob = [s(ty.as_bytes()), s(b"nistp256"), s(&[4; 65]), s(b"ssh:work")].concat();
        let line = format!("{ty} {} me@laptop", B64.encode(&blob));
        assert_eq!(parse_pub(&line), Some(("ecdsa-sk".into(), "ssh:work".into(), "me@laptop".into())));
        let ty = "sk-ssh-ed25519@openssh.com";
        let ed = format!("{ty} {}", B64.encode([s(ty.as_bytes()), s(&[1; 32]), s(b"ssh:")].concat()));
        assert_eq!(parse_pub(&ed).unwrap().1, "ssh:");
        assert_eq!(parse_pub("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPnWgjkG9d5Ow5r7rgCt/HjqTeoce4FCqKBGvH2/MD+I x"), None);

        let p = Path::new("/h/.ssh/id_ecdsa_sk.pub");
        assert!(is_signing_key(Some("/h/.ssh/id_ecdsa_sk.pub"), p, &line));
        assert!(is_signing_key(Some(&format!("key::{}", line.rsplit_once(' ').unwrap().0)), Path::new("/x"), &line));
        assert!(!is_signing_key(Some("ssh-ed25519 AAAA"), p, &line));

        assert_eq!(allowed_signers_line("a@b.c", "type KEY comment"), "a@b.c namespaces=\"git\" type KEY");
        assert!(host_exists("Host foo github.com\n  User git", "github.com"));
        assert!(!host_exists("Host github.company.com", "github.com"));
        assert!(valid_file("id_ecdsa_sk-work") && !valid_file("../x") && !valid_file(".hidden"));
    }
}
