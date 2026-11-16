//! Moving from regular SSH keys to Pico (security-key) SSH keys, one host at a time:
//! authorize the Pico key on the server with the current login, prove the Pico key works on
//! its own, point ~/.ssh/config at it, then archive the old key files.
use crate::ssh::{EXE, friendly, home, keygen, run_openssh, ssh_dir};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::LegacyKey;

type R<T> = Result<T, String>;

/// Git hosts that only accept RSA/ECDSA/Ed25519 keys, not `sk-` ones.
const NO_SK: [&str; 3] = ["dev.azure.com", "visualstudio.com", "codecommit"];

fn expand(p: &str) -> R<PathBuf> {
    let p = p.trim().trim_matches('"');
    let p = p.replace("%d", &home()?.display().to_string());
    Ok(match p.strip_prefix("~/") {
        Some(rest) => home()?.join(rest),
        None if Path::new(&p).is_relative() => ssh_dir()?.join(&p),
        None => PathBuf::from(p),
    })
}

/// IdentityFile may name the private key or (1Password style) the .pub; compare on the private path.
fn private_of(p: &Path) -> PathBuf {
    match p.to_str().and_then(|s| s.strip_suffix(".pub")) {
        Some(s) => PathBuf::from(s),
        None => p.to_path_buf(),
    }
}

/// `~/.ssh/x` form for paths under home, so edited config stays portable.
fn tilde(p: &Path) -> String {
    match home().ok().and_then(|h| p.strip_prefix(&h).ok().map(|r| r.to_path_buf())) {
        Some(r) => format!("~/{}", r.display()),
        None => p.display().to_string(),
    }
}

struct Ident {
    file: PathBuf,
    line: usize,
    hosts: Vec<String>,
    raw: String,
    private: PathBuf,
}

/// Single-`*` glob within one directory (what ssh config Includes use in practice).
fn glob(pattern: &Path) -> Vec<PathBuf> {
    let s = pattern.display().to_string();
    let Some((pre, post)) = s.split_once('*') else { return vec![pattern.to_path_buf()] };
    let sep = pre.rfind(['/', '\\']).map(|i| i + 1).unwrap_or(0);
    let (dir, name_pre) = (&pre[..sep], &pre[sep..]);
    let mut v: Vec<PathBuf> = std::fs::read_dir(if dir.is_empty() { "." } else { dir })
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(name_pre) && n.to_string_lossy().ends_with(post)))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Every IdentityFile in ~/.ssh/config and the files it Includes.
// ponytail: Match blocks are treated like Host blocks named "Match ..."; good enough to find key users.
fn identities() -> R<Vec<Ident>> {
    fn walk(file: &Path, depth: u8, out: &mut Vec<Ident>) -> R<()> {
        let Ok(text) = std::fs::read_to_string(file) else { return Ok(()) };
        let mut hosts: Vec<String> = vec!["*".into()];
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            let (key, val) = t.split_once(|c: char| c.is_whitespace() || c == '=').unwrap_or((t, ""));
            let val = val.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
            match key.to_ascii_lowercase().as_str() {
                "host" => hosts = val.split_whitespace().map(String::from).collect(),
                "match" => hosts = vec![format!("Match {val}")],
                "include" if depth < 5 => {
                    for inc in val.split_whitespace() {
                        for f in glob(&expand(inc)?) {
                            walk(&f, depth + 1, out)?;
                        }
                    }
                }
                "identityfile" => out.push(Ident { file: file.to_path_buf(), line: i, hosts: hosts.clone(), raw: val.to_string(), private: private_of(&expand(val)?) }),
                _ => {}
            }
        }
        Ok(())
    }
    let mut out = vec![];
    walk(&ssh_dir()?.join("config"), 0, &mut out)?;
    Ok(out)
}

pub fn inventory() -> R<Vec<LegacyKey>> {
    let ids = identities()?;
    let Ok(rd) = std::fs::read_dir(ssh_dir()?) else { return Ok(vec![]) };
    let mut out: Vec<LegacyKey> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .filter_map(|p| {
            let line = std::fs::read_to_string(&p).ok()?.lines().next()?.to_string();
            let mut w = line.split_whitespace();
            let kind = w.next()?.to_string();
            if kind.starts_with("sk-") || !kind.starts_with("ssh-") && !kind.starts_with("ecdsa-") {
                return None;
            }
            w.next()?;
            let private = private_of(&p);
            let mut hosts: Vec<String> = ids.iter().filter(|i| i.private == private).flat_map(|i| i.hosts.clone()).collect();
            hosts.dedup();
            let unsupported = hosts.iter().filter(|h| NO_SK.iter().any(|n| h.contains(n))).cloned().collect();
            Some(LegacyKey {
                on_disk: private.is_file(),
                private_path: private.display().to_string(),
                pub_path: Some(p.display().to_string()),
                comment: w.collect::<Vec<_>>().join(" "),
                kind,
                hosts,
                unsupported,
            })
        })
        .collect();
    out.sort_by(|a, b| a.private_path.cmp(&b.private_path));
    Ok(out)
}

fn ssh_bin() -> R<PathBuf> {
    let (kg, problem) = keygen();
    Ok(kg.ok_or(problem.unwrap_or_default())?.with_file_name(format!("ssh{EXE}")))
}

fn check_host(host: &str) -> R<&str> {
    let h = host.trim();
    if h.is_empty() || h.starts_with('-') || h.contains('*') || !h.chars().all(|c| c.is_ascii_alphanumeric() || ".-_@:".contains(c)) {
        return Err("Enter one real host name (no wildcards), e.g. pve or app.example.com.".into());
    }
    Ok(h)
}

/// `type base64` of a security-key public key file, safe to embed in a shell command.
fn pico_pub_line(pub_path: &str) -> R<String> {
    let line = std::fs::read_to_string(pub_path).map_err(|e| e.to_string())?;
    let mut w = line.split_whitespace();
    let (ty, b64) = (w.next().unwrap_or_default(), w.next().unwrap_or_default());
    if !ty.starts_with("sk-") || b64.is_empty() || !b64.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)) {
        return Err("Pick a Pico (security-key) SSH key.".into());
    }
    Ok(format!("{ty} {b64}"))
}

/// Adds the Pico public key to the server's authorized_keys, logging in the way ssh does today
/// (current key / agent from ~/.ssh/config). Idempotent.
// ponytail: assumes a POSIX shell on the server; Windows OpenSSH servers need a different command.
pub fn authorize(host: &str, pico_pub: &str) -> R<String> {
    let host = check_host(host)?;
    let key = pico_pub_line(pico_pub)?;
    let b64 = key.split(' ').nth(1).unwrap_or_default();
    let remote = format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qF '{b64}' ~/.ssh/authorized_keys || printf '%s\\n' '{key} pico-key-manager' >> ~/.ssh/authorized_keys) && echo PKM_OK"
    );
    let args: Vec<String> = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new", host, &remote].iter().map(|s| s.to_string()).collect();
    let (_ok, out) = run_openssh(&ssh_bin()?, &args, None, Duration::from_secs(90))?;
    if out.contains("PKM_OK") {
        Ok(format!("Pico key added to {host}."))
    } else if out.to_lowercase().contains("permission denied") {
        Err(format!("Couldn't log in to {host} with your current key, so the Pico key wasn't added."))
    } else {
        Err(friendly(&out))
    }
}

/// Logs in with only the Pico key (config and agents ignored, but HostName/User/Port/ProxyJump
/// resolved from the config) to prove the old key is no longer needed.
pub fn check(host: &str, pico_pub: &str, pin: Option<&str>) -> R<String> {
    let host = check_host(host)?;
    pico_pub_line(pico_pub)?;
    let ssh = ssh_bin()?;
    let (_, resolved) = run_openssh(&ssh, &["-G".into(), host.into()], None, Duration::from_secs(10))?;
    let get = |k: &str| resolved.lines().find_map(|l| l.strip_prefix(&format!("{k} ")).map(str::to_string));
    let identity = pico_pub.strip_suffix(".pub").ok_or("Pick a key.")?;
    let mut args: Vec<String> = [
        "-F", "none", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PreferredAuthentications=publickey",
        "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", "-i", identity,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(u) = get("user") {
        args.extend(["-l".into(), u]);
    }
    if let Some(p) = get("port") {
        args.extend(["-p".into(), p]);
    }
    if let Some(j) = get("proxyjump").filter(|j| j != "none") {
        args.extend(["-J".into(), j]);
    }
    args.push(get("hostname").unwrap_or_else(|| host.to_string()));
    args.push("echo PKM_OK".into());
    let (_ok, out) = run_openssh(&ssh, &args, pin, Duration::from_secs(60))?;
    if out.contains("PKM_OK") {
        Ok(format!("Logged in to {host} with the Pico key alone."))
    } else if out.to_lowercase().contains("permission denied") {
        Err(format!("{host} didn't accept the Pico key. Add it first; the server also needs OpenSSH 8.2 or newer."))
    } else {
        Err(friendly(&out))
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Rewrites every IdentityFile that points at the old key to the Pico key (keeping the
/// private-vs-.pub style of each line). Each edited file is backed up first.
pub fn switch_config(old_private: &str, pico_pub: &str) -> R<Vec<String>> {
    pico_pub_line(pico_pub)?;
    let old = PathBuf::from(old_private);
    let new_pub = PathBuf::from(pico_pub);
    let new_priv = private_of(&new_pub);
    let ids: Vec<Ident> = identities()?.into_iter().filter(|i| i.private == old).collect();
    if ids.is_empty() {
        return Err("~/.ssh/config doesn't use this key.".into());
    }
    let mut changed = vec![];
    let mut files: Vec<PathBuf> = ids.iter().map(|i| i.file.clone()).collect();
    files.dedup();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
        // Not next to the file: a backup inside an Include'd dir (config.d/*) would be read by ssh too.
        let backups = ssh_dir()?.join("pkm-backups");
        std::fs::create_dir_all(&backups).map_err(|e| e.to_string())?;
        let name = f.file_name().unwrap_or_default().to_string_lossy().into_owned();
        std::fs::write(backups.join(format!("{name}-{}", now_secs())), &text).map_err(|e| format!("Couldn't back up {}: {e}", f.display()))?;
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        for id in ids.iter().filter(|i| i.file == f) {
            let l = &lines[id.line];
            let indent: String = l.chars().take_while(|c| c.is_whitespace()).collect();
            let target = if id.raw.trim_matches('"').ends_with(".pub") { &new_pub } else { &new_priv };
            lines[id.line] = format!("{indent}IdentityFile {}", tilde(target));
            changed.push(format!("{}:{} ({})", tilde(&f), id.line + 1, id.hosts.join(" ")));
        }
        let trailing = if text.ends_with('\n') { "\n" } else { "" };
        std::fs::write(&f, lines.join("\n") + trailing).map_err(|e| e.to_string())?;
    }
    Ok(changed)
}

/// Moves the old key's files into ~/.ssh/retired/ once nothing in the config uses it.
pub fn archive(old_private: &str) -> R<String> {
    let old = PathBuf::from(old_private);
    let dir = ssh_dir()?;
    if !old.starts_with(&dir) {
        return Err("Only keys inside ~/.ssh can be archived.".into());
    }
    if identities()?.iter().any(|i| i.private == old) {
        return Err("~/.ssh/config still uses this key. Switch the config first.".into());
    }
    let retired = dir.join("retired");
    std::fs::create_dir_all(&retired).map_err(|e| e.to_string())?;
    let mut moved = vec![];
    for src in [old.clone(), PathBuf::from(format!("{}.pub", old.display()))] {
        if !src.is_file() {
            continue;
        }
        let name = src.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let mut dst = retired.join(&name);
        let mut n = 1;
        while dst.exists() {
            dst = retired.join(format!("{name}.{n}"));
            n += 1;
        }
        std::fs::rename(&src, &dst).map_err(|e| e.to_string())?;
        moved.push(dst.file_name().unwrap_or_default().to_string_lossy().into_owned());
    }
    if moved.is_empty() {
        return Err("No files for this key were found.".into());
    }
    Ok(format!("Moved {} to {}", moved.join(", "), tilde(&retired)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(private_of(Path::new("/h/.ssh/pve.pub")), PathBuf::from("/h/.ssh/pve"));
        assert_eq!(private_of(Path::new("/h/.ssh/pve")), PathBuf::from("/h/.ssh/pve"));
        assert!(check_host("pve").is_ok() && check_host("u@app.example.com").is_ok());
        assert!(check_host("*.example.com").is_err() && check_host("-oProxyCommand=x").is_err() && check_host("a;b").is_err());
        assert!(expand("~/.ssh/x").unwrap().ends_with(".ssh/x"));
        assert!(expand("id_rsa").unwrap().ends_with(".ssh/id_rsa"));
    }


    /// switch_config + archive against a throwaway HOME (Include, .pub-style and private-style lines).
    #[test]
    fn switch_and_archive() {
        let h = std::env::temp_dir().join(format!("pkm-home-{}", std::process::id()));
        let ssh = h.join(".ssh");
        std::fs::create_dir_all(ssh.join("config.d")).unwrap();
        // SAFETY: only this test reads HOME-derived paths; other tests don't touch home().
        // home_dir() reads USERPROFILE on Windows.
        unsafe {
            std::env::set_var("HOME", &h);
            std::env::set_var("USERPROFILE", &h);
        }
        std::fs::write(ssh.join("config"), "Include ~/.ssh/config.d/*\n\nHost pve\n\tIdentityFile ~/.ssh/pve.pub\n\nHost other\n  IdentityFile ~/.ssh/keep\n").unwrap();
        std::fs::write(ssh.join("config.d/deploy"), "Host deploy\n    IdentityFile ~/.ssh/pve\n").unwrap();
        std::fs::write(ssh.join("pve.pub"), "ssh-rsa AAAAB3Nza me\n").unwrap();
        std::fs::write(ssh.join("pve"), "PRIVATE").unwrap();
        std::fs::write(ssh.join("id_ecdsa_sk.pub"), "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr me\n").unwrap();

        let old = ssh.join("pve").display().to_string();
        let pico = ssh.join("id_ecdsa_sk.pub").display().to_string();
        let inv = inventory().unwrap();
        assert_eq!(inv.iter().find(|k| k.private_path == old).unwrap().hosts, vec!["deploy", "pve"]);
        assert!(archive(&old).is_err(), "still referenced");

        let changed = switch_config(&old, &pico).unwrap();
        assert_eq!(changed.len(), 2);
        let cfg = std::fs::read_to_string(ssh.join("config")).unwrap();
        assert!(cfg.contains("Host pve\n\tIdentityFile ~/.ssh/id_ecdsa_sk.pub\n"), "{cfg}");
        assert!(cfg.contains("IdentityFile ~/.ssh/keep"));
        assert!(std::fs::read_to_string(ssh.join("config.d/deploy")).unwrap().contains("    IdentityFile ~/.ssh/id_ecdsa_sk\n"));
        assert_eq!(std::fs::read_dir(ssh.join("pkm-backups")).unwrap().count(), 2, "one backup per edited file");
        assert_eq!(std::fs::read_dir(ssh.join("config.d")).unwrap().count(), 1, "nothing added inside the Include dir");

        archive(&old).unwrap();
        assert!(!ssh.join("pve").exists() && ssh.join("retired/pve").exists() && ssh.join("retired/pve.pub").exists());
        let _ = std::fs::remove_dir_all(&h);
    }

    /// Read-only: prints the migration inventory. `cargo test -p picokeys-app -- --ignored migrate_inventory --nocapture`
    #[test]
    #[ignore]
    fn migrate_inventory() {
        for k in inventory().unwrap() {
            println!("{} {} on_disk={} hosts={:?} unsupported={:?}", k.kind, tilde(Path::new(&k.private_path)), k.on_disk, k.hosts, k.unsupported);
        }
    }
}
