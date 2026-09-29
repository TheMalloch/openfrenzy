use anyhow::{Context, Result};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use subtle::ConstantTimeEq;

/// Write `data` to `path` atomically: write a temp file in the same directory,
/// fsync it, then rename over the target. A crash leaves either the old or the
/// new file, never a truncated one. An existing file's mode is kept; a new
/// file gets `default_mode`.
pub fn write_atomic(path: &Path, data: &[u8], default_mode: u32) -> Result<()> {
    let mode = existing_mode(path).unwrap_or(default_mode);
    write_atomic_mode(path, data, mode)
}

/// Atomically write a file that holds secrets (private key, auth token).
///
/// These files live in the setgid `root:meshlink` config directory and must
/// be readable by the `meshlink` group (the services run as that user), but
/// never by others: an existing mode keeps its owner/group bits with all
/// "other" bits stripped; a new file gets 0660.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mode = existing_mode(path).map(|m| m & 0o770).unwrap_or(0o660);
    write_atomic_mode(path, data, mode)
}

/// Remove all "other" permission bits from an existing file. Returns true if
/// the mode was changed, false if it was already private or does not exist.
pub fn restrict_other_access(path: &Path) -> Result<bool> {
    let Some(mode) = existing_mode(path) else {
        return Ok(false);
    };
    if mode & 0o007 == 0 {
        return Ok(false);
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o770))
        .with_context(|| format!("restricting permissions on {path:?}"))?;
    Ok(true)
}

fn existing_mode(path: &Path) -> Option<u32> {
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o7777)
}

fn write_atomic_mode(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let file_name = path
        .file_name()
        .with_context(|| format!("{path:?} has no file name"))?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        // `mode()` above is filtered by the umask; set the exact mode.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();

    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Constant-time token comparison — avoids timing side channels.
pub fn token_eq(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        let _ = b.ct_eq(b); // keep timing uniform
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_and_keeps_mode() {
        let dir = std::env::temp_dir().join(format!("meshlink_util_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cfg.toml");

        write_atomic(&path, b"one", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic(&path, b"two", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);

        let leftovers = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_private_is_group_readable_never_world() {
        let dir = std::env::temp_dir().join(format!("meshlink_priv_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let fresh = dir.join("credentials.json");
        write_private(&fresh, b"{}").unwrap();
        assert_eq!(mode_of(&fresh), 0o660);

        let loose = dir.join("config.toml");
        std::fs::write(&loose, b"old").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o664)).unwrap();
        write_private(&loose, b"new").unwrap();
        assert_eq!(mode_of(&loose), 0o660);
        assert_eq!(std::fs::read(&loose).unwrap(), b"new");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restrict_other_access_strips_world_bits_only() {
        let dir = std::env::temp_dir().join(format!("meshlink_restrict_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, b"x").unwrap();

        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(restrict_other_access(&p).unwrap());
        assert_eq!(mode_of(&p), 0o640);

        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(!restrict_other_access(&p).unwrap());
        assert_eq!(mode_of(&p), 0o660);

        assert!(!restrict_other_access(&dir.join("missing")).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_eq_basic() {
        assert!(token_eq("abc", "abc"));
        assert!(!token_eq("abc", "abd"));
        assert!(!token_eq("abc", "abcd"));
    }
}
