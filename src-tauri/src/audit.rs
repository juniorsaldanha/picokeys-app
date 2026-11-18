//! App-side audit log: every change made through this app, one JSON line each, hash-chained
//! (each entry's hash covers the previous hash) so edits and deletions break the chain.
//! It can't see what other tools do to the key.
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use types::{AuditEntry, AuditLog};

type R<T> = Result<T, String>;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static WRITE: Mutex<()> = Mutex::new(());

#[derive(Serialize)]
struct Body<'a> {
    ts: u64,
    action: &'a str,
    detail: &'a str,
    ok: bool,
    error: Option<&'a str>,
    prev: &'a str,
}

#[derive(Deserialize)]
struct Line {
    ts: u64,
    action: String,
    detail: String,
    ok: bool,
    error: Option<String>,
    prev: String,
    hash: String,
}

fn hash(b: &Body) -> String {
    crate::fido::hex(
        digest(
            &SHA256,
            serde_json::to_string(b).unwrap_or_default().as_bytes(),
        )
        .as_ref(),
    )
}

pub fn path() -> R<PathBuf> {
    Ok(crate::ssh::home()?.join(".pico-key-manager/audit.log"))
}

fn last_hash(p: &Path) -> String {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|t| {
            t.lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .and_then(|l| serde_json::from_str::<Line>(l).ok())
        })
        .map(|l| l.hash)
        .unwrap_or_else(|| GENESIS.into())
}

fn append(p: &Path, action: &str, detail: &str, error: Option<&str>) -> R<()> {
    let _g = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let prev = last_hash(p);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = Body {
        ts,
        action,
        detail,
        ok: error.is_none(),
        error,
        prev: &prev,
    };
    let mut v = serde_json::to_value(&body).map_err(|e| e.to_string())?;
    v["hash"] = hash(&body).into();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    writeln!(f, "{v}").map_err(|e| e.to_string())
}

/// Records the outcome of `r` and passes it through. Logging failures never block the action.
pub fn log<T>(action: &str, detail: &str, r: Result<T, String>) -> Result<T, String> {
    if let Ok(p) = path()
        && let Err(e) = append(&p, action, detail, r.as_ref().err().map(String::as_str))
    {
        eprintln!("audit: {e}");
    }
    r
}

fn read(p: &Path) -> AuditLog {
    let text = std::fs::read_to_string(p).unwrap_or_default();
    let mut prev = GENESIS.to_string();
    let mut broken_at = None;
    let mut entries = vec![];
    for (i, l) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let Ok(e) = serde_json::from_str::<Line>(l) else {
            broken_at.get_or_insert(i as u32);
            continue;
        };
        let body = Body {
            ts: e.ts,
            action: &e.action,
            detail: &e.detail,
            ok: e.ok,
            error: e.error.as_deref(),
            prev: &e.prev,
        };
        if e.prev != prev || hash(&body) != e.hash {
            broken_at.get_or_insert(i as u32);
        }
        prev = e.hash.clone();
        entries.push(AuditEntry {
            ts: e.ts,
            action: e.action,
            detail: e.detail,
            ok: e.ok,
            error: e.error,
        });
    }
    AuditLog {
        path: p.display().to_string(),
        chain_ok: broken_at.is_none(),
        broken_at,
        entries,
    }
}

pub fn load() -> R<AuditLog> {
    Ok(read(&path()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_tampering() {
        let p = std::env::temp_dir().join(format!("pkm-audit-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&p);
        append(&p, "fido_reset", "", None).unwrap();
        append(&p, "oath_delete", "GitHub", Some("Wrong PIN.")).unwrap();
        append(&p, "otp_swap", "", None).unwrap();
        let log = read(&p);
        assert!(log.chain_ok);
        assert_eq!(log.entries.len(), 3);
        assert_eq!(
            (log.entries[1].ok, log.entries[1].error.as_deref()),
            (false, Some("Wrong PIN."))
        );

        // Edit the middle entry: the chain breaks there.
        let text = std::fs::read_to_string(&p)
            .unwrap()
            .replace("GitHub", "Gitlab");
        std::fs::write(&p, text).unwrap();
        assert_eq!(read(&p).broken_at, Some(1));

        // Delete the first entry: the (new) first one no longer chains to genesis.
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.lines().skip(1).collect::<Vec<_>>().join("\n")).unwrap();
        assert_eq!(read(&p).broken_at, Some(0));
        std::fs::remove_file(&p).unwrap();
    }
}
