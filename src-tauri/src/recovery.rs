//! Secure-boot recovery files kept under ~/.pico-key-manager: the boot signing key and flash
//! backups. They only leave that folder through an explicit, confirmed "Save as" export.
use std::path::{Path, PathBuf};
use types::RecoveryFile;

type R<T> = Result<T, String>;

fn root() -> R<PathBuf> {
    Ok(crate::ssh::home()?.join(".pico-key-manager"))
}

fn scan(root: &Path) -> Vec<RecoveryFile> {
    let mut out = vec![];
    let key = root.join("secure-boot/signing-key.pem");
    let mut add = |kind: &str, p: PathBuf| {
        if let Ok(m) = std::fs::metadata(&p) {
            let name = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
            out.push(RecoveryFile { kind: kind.into(), name, path: p.display().to_string(), size: m.len() });
        }
    };
    add("signing-key", key);
    if let Ok(rd) = std::fs::read_dir(root.join("recovery")) {
        let mut backups: Vec<PathBuf> =
            rd.flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("flash-"))).collect();
        backups.sort();
        for p in backups {
            add("flash-backup", p);
        }
    }
    out
}

pub fn files() -> R<Vec<RecoveryFile>> {
    Ok(scan(&root()?))
}

/// Copies one of `files()` to `dest` (0600). Refuses anything else.
pub fn export(src: &str, dest: &Path) -> R<()> {
    if !files()?.iter().any(|f| f.path == src) {
        return Err("That isn't one of the recovery files.".into());
    }
    std::fs::copy(src, dest).map_err(|e| format!("Couldn't save: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_known_files_only() {
        let dir = std::env::temp_dir().join(format!("pkm-recovery-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("secure-boot")).unwrap();
        std::fs::create_dir_all(dir.join("recovery")).unwrap();
        std::fs::write(dir.join("secure-boot/signing-key.pem"), "k").unwrap();
        std::fs::write(dir.join("recovery/flash-0-3MB.bin"), "ff").unwrap();
        std::fs::write(dir.join("recovery/partitions.bin"), "x").unwrap();
        let f = scan(&dir);
        let kinds: Vec<_> = f.iter().map(|f| (f.kind.as_str(), f.name.as_str(), f.size)).collect();
        assert_eq!(kinds, [("signing-key", "signing-key.pem", 1), ("flash-backup", "flash-0-3MB.bin", 2)]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
