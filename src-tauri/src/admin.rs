//! App admin lock: a passphrase (PBKDF2-HMAC-SHA256, stored on this computer) that risky actions
//! need. Unlocking lasts a few minutes. It guards this app only, not the key itself: the
//! open firmware has no admin/user PIN split.
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use types::AdminStatus;

type R<T> = Result<T, String>;
const WINDOW: Duration = Duration::from_secs(5 * 60);
const ITERATIONS: u32 = 600_000;
static UNTIL: Mutex<Option<Instant>> = Mutex::new(None);

#[derive(Serialize, Deserialize)]
struct Stored {
    salt: String,
    hash: String,
    iterations: u32,
}

fn path() -> R<PathBuf> {
    Ok(crate::ssh::home()?.join(".pico-key-manager/admin.json"))
}

fn load(p: &Path) -> Option<Stored> {
    serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
}

fn check(s: &Stored, pass: &str) -> bool {
    let (Ok(salt), Ok(hash), Some(n)) = (
        crate::fido::unhex(&s.salt),
        crate::fido::unhex(&s.hash),
        NonZeroU32::new(s.iterations),
    ) else {
        return false;
    };
    pbkdf2::verify(pbkdf2::PBKDF2_HMAC_SHA256, n, &salt, pass.as_bytes(), &hash).is_ok()
}

fn store(p: &Path, pass: &str) -> R<()> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    let mut hash = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS).unwrap(),
        &salt,
        pass.as_bytes(),
        &mut hash,
    );
    let s = Stored {
        salt: crate::fido::hex(&salt),
        hash: crate::fido::hex(&hash),
        iterations: ITERATIONS,
    };
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(p, serde_json::to_string(&s).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn left() -> Option<Duration> {
    UNTIL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .and_then(|t| t.checked_duration_since(Instant::now()))
}

pub fn status() -> R<AdminStatus> {
    let enabled = load(&path()?).is_some();
    let secs = if enabled {
        left().map(|d| d.as_secs() as u32)
    } else {
        None
    };
    Ok(AdminStatus {
        enabled,
        unlocked: !enabled || secs.is_some(),
        seconds_left: secs,
    })
}

/// Gate for risky commands. "ADMIN_LOCKED" tells the UI to ask for the passphrase.
pub fn require() -> R<()> {
    if status()?.unlocked {
        Ok(())
    } else {
        Err("ADMIN_LOCKED".into())
    }
}

pub fn unlock(pass: &str) -> R<()> {
    let s = load(&path()?).ok_or("The admin lock isn't set up.")?;
    if !check(&s, pass) {
        return Err("Wrong admin passphrase.".into());
    }
    *UNTIL.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now() + WINDOW);
    Ok(())
}

pub fn lock() {
    *UNTIL.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Set up or change the passphrase. Changing needs the current one.
pub fn set(current: Option<&str>, new: &str) -> R<()> {
    set_in(&path()?, current, new)
}

fn set_in(p: &Path, current: Option<&str>, new: &str) -> R<()> {
    if new.chars().count() < 8 {
        return Err("Use at least 8 characters.".into());
    }
    if let Some(s) = load(p)
        && !check(&s, current.unwrap_or_default())
    {
        return Err("Wrong admin passphrase.".into());
    }
    store(p, new)
}

pub fn remove(current: &str) -> R<()> {
    let p = path()?;
    let s = load(&p).ok_or("The admin lock isn't set up.")?;
    if !check(&s, current) {
        return Err("Wrong admin passphrase.".into());
    }
    std::fs::remove_file(&p).map_err(|e| e.to_string())?;
    lock();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_roundtrip() {
        let p = std::env::temp_dir().join(format!("pkm-admin-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        assert!(set_in(&p, None, "short").is_err());
        set_in(&p, None, "correct horse").unwrap();
        let s = load(&p).unwrap();
        assert!(check(&s, "correct horse"));
        assert!(!check(&s, "wrong horse"));
        assert!(set_in(&p, Some("nope"), "another one").is_err());
        set_in(&p, Some("correct horse"), "another one").unwrap();
        assert!(check(&load(&p).unwrap(), "another one"));
        std::fs::remove_file(&p).unwrap();
    }
}
