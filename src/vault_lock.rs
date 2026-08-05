//! Exclusive `.vault.lock` file locking, split out of `vault.rs` for file-size
//! hygiene.
//!
//! A project vault serializes concurrent writers via a `.vault.lock` file
//! (gitignored) that is held for the lifetime of a `Vault` and released on
//! drop. Acquisition is an atomic `create_new` busy-wait up to a timeout.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Result};

/// Busy-wait poll interval for acquiring the lock.
pub(crate) const LOCK_POLL_MS: u64 = 5;
/// Max time to wait for the lock before giving up.
pub(crate) const LOCK_TIMEOUT_SECS: u64 = 30;

/// Acquire an exclusive lock by atomically creating `path`. Busy-waits up to
/// `LOCK_TIMEOUT_SECS` before giving up.
pub(crate) fn acquire_lock(path: &Path) -> Result<PathBuf> {
    let deadline = std::time::Instant::now() + Duration::from_secs(LOCK_TIMEOUT_SECS);
    loop {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        match opts.open(path) {
            Ok(_) => return Ok(path.to_path_buf()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if std::time::Instant::now() > deadline {
                    bail!(
                        "timed out waiting for lock {} (another dotvault process may be stuck)",
                        path.display()
                    );
                }
                std::thread::sleep(Duration::from_millis(LOCK_POLL_MS));
            }
            Err(e) => {
                bail!("failed to create lock {}: {e}", path.display());
            }
        }
    }
}

/// Release a previously acquired lock. Best-effort: a failure here is logged
/// to stderr but does not propagate (the real work already succeeded).
pub(crate) fn release_lock(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("warning: could not remove lock {}: {e}", path.display());
        }
    }
}
