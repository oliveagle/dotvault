//! Backup subsystem: copy prior vault containers to a backups dir with
//! timestamped, namespace-prefixed names, and rotate them by mtime.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Copy `src` to the backups directory with a timestamped, namespace-prefixed
/// name. Best-effort: a backup failure is surfaced but does not destroy data.
pub fn backup_container(src: &Path, namespace: &str) -> Result<()> {
    let stamp = crate::util::now_stamp_compact();
    let dir = backups_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create backups dir {}", dir.display()))?;
    let mut rnd = [0u8; 4];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut rnd);
    let suffix = rnd.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let dst = dir.join(format!("{}-{}-{}.bin", namespace, stamp, suffix));
    std::fs::copy(src, &dst)
        .with_context(|| format!("failed to copy backup to {}", dst.display()))?;

    let keep = crate::config::Config::load()
        .map(|c| c.backup_keep())
        .unwrap_or(0);
    if let Err(e) = rotate_backups(&dir, keep) {
        eprintln!("warning: backup rotation failed (data is safe): {e}");
    }
    Ok(())
}

/// Keep only the `keep` most recent backups in `dir`, deleting older ones.
/// Orders by mtime (newest first); `keep == 0` means "no limit".
pub fn rotate_backups(dir: &Path, keep: usize) -> Result<()> {
    if keep == 0 {
        return Ok(());
    }
    let mut entries: Vec<(PathBuf, std::time::SystemTime)> = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read backup dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            let is_backup = p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".bin"))
                .unwrap_or(false);
            if !is_backup {
                return None;
            }
            let mtime = e.metadata().ok().and_then(|m| m.modified().ok());
            Some((p, mtime.unwrap_or(std::time::UNIX_EPOCH)))
        })
        .collect();
    entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    for (stale, _) in entries.into_iter().skip(keep) {
        if let Err(e) = std::fs::remove_file(&stale) {
            eprintln!(
                "warning: could not delete old backup {}: {e}",
                stale.display()
            );
        }
    }
    Ok(())
}

/// Backup directory. Priority: `DOTVAULT_BACKUP_DIR` env → config `backup_dir`
/// → `~/.dotvault/backups`.
pub fn backups_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("DOTVAULT_BACKUP_DIR") {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = crate::config::Config::load()
        .ok()
        .and_then(|c| c.backup_dir_path())
    {
        return Ok(p);
    }
    Ok(crate::vault::dotvault_home()?.join("backups"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_zero_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            std::fs::write(
                dir.path().join(format!("ns1-2020010{i}-000000.bin")),
                b"DV1",
            )
            .unwrap();
        }
        rotate_backups(dir.path(), 0).unwrap();
        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 3, "keep=0 must not delete anything");
    }

    #[test]
    fn rotate_ignores_non_backup_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ns1-20200101-000000.bin"), b"DV1").unwrap();
        std::fs::write(dir.path().join("readme.txt"), b"keep me").unwrap();
        rotate_backups(dir.path(), 0).unwrap();
        assert!(dir.path().join("readme.txt").exists());
    }

    #[test]
    fn rotate_with_fewer_than_keep_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..2u64 {
            let path = dir.path().join(format!("ns1-2020010{i}-000000.bin"));
            std::fs::write(&path, b"DV1").unwrap();
            let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000 + i);
            let _ = std::fs::File::options()
                .write(true)
                .open(&path)
                .and_then(|f| f.set_modified(mtime));
        }
        rotate_backups(dir.path(), 5).unwrap();
        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 2, "fewer-than-keep should delete nothing");
    }
}
