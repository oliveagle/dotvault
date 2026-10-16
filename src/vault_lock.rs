//! Exclusive `.vault.lock` file locking, split out of `vault.rs` for file-size
//! hygiene.
//!
//! A project vault serializes concurrent writers via a `.vault.lock` file
//! (gitignored) that is held for the lifetime of a `Vault` and released on
//! drop. Acquisition is an atomic `create_new` busy-wait up to a timeout.
//!
//! ## Stale-lock recovery
//!
//! The lock file records the owning `<pid> <hostname>`. If a holder dies
//! without running its `Drop` (SIGKILL, crash, OOM, a caller that times out
//! and kills the process), the file would otherwise linger forever and make
//! every later command busy-wait the full `LOCK_TIMEOUT_SECS` before failing.
//! On contention we therefore check whether the recorded holder is still alive
//! (same host, `kill(pid, 0)`); a dead holder's lock is broken immediately.
//!
//! A 0-byte/legacy lock file (crashed between `create_new` and the identity
//! write) carries no PID, so it is only broken once it is clearly older than
//! the tiny create-then-write window.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

/// Busy-wait poll interval for acquiring the lock.
pub(crate) const LOCK_POLL_MS: u64 = 5;
/// Max time to wait for the lock before giving up.
pub(crate) const LOCK_TIMEOUT_SECS: u64 = 30;
/// How often, while waiting, to re-check whether the holder has died.
const STALE_CHECK_INTERVAL_MS: u64 = 200;
/// An identity-less (empty/garbled) lock file older than this is treated as
/// stale. This is far larger than the create-then-write window, so a live
/// holder that has just created its lock is never stolen from.
const EMPTY_LOCK_STALE_AFTER_MS: u64 = 5_000;

/// Acquire an exclusive lock by atomically creating `path`. Busy-waits up to
/// `LOCK_TIMEOUT_SECS` before giving up, breaking stale locks left by dead
/// holders along the way.
pub(crate) fn acquire_lock(path: &Path) -> Result<PathBuf> {
    let deadline = Instant::now() + Duration::from_secs(LOCK_TIMEOUT_SECS);
    let mut next_stale_check = Instant::now();
    loop {
        match try_create_lock(path) {
            Ok(()) => return Ok(path.to_path_buf()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if Instant::now() > deadline {
                    bail!(
                        "timed out waiting for lock {} (another dotvault process may be stuck; \
                         if no dotvault is running, delete the file)",
                        path.display()
                    );
                }
                if Instant::now() >= next_stale_check {
                    next_stale_check =
                        Instant::now() + Duration::from_millis(STALE_CHECK_INTERVAL_MS);
                    break_if_stale(path);
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

/// Atomically create `path`, then stamp our identity into it. If stamping
/// fails the file is removed so we never leave an identity-less lock behind.
fn try_create_lock(path: &Path) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    let mut f = opts.open(path)?;
    if let Err(e) = f.write_all(lock_identity().as_bytes()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// `<pid> <hostname>\n` — enough to tell a live local holder from a dead one.
fn lock_identity() -> String {
    format!("{} {}\n", std::process::id(), hostname())
}

/// Break the lock at `path` if it was left behind by a dead holder.
///
/// Runs on contention only. A locked-but-live holder is left untouched (we
/// keep waiting), so a genuinely long-running holder is never stolen from.
fn break_if_stale(path: &Path) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let mut parts = content.split_whitespace();
    let pid = parts.next().and_then(|s| s.parse::<u32>().ok());
    let host = parts.next();

    let stale = match (pid, host) {
        // Recorded holder on THIS host is gone -> safe to break now.
        (Some(pid), Some(host)) if host == hostname() => !process_alive(pid),
        // Recorded holder on ANOTHER host: we cannot probe it, so never steal.
        (Some(_), Some(_)) => false,
        // No usable identity (0-byte / legacy / garbled): only break once it
        // is clearly older than the create-then-write window.
        _ => lock_age_ms(path).is_some_and(|ms| ms >= EMPTY_LOCK_STALE_AFTER_MS),
    };

    if stale {
        break_lock_if_unchanged(path, &content);
    }
}

/// Delete `path` only if it still holds exactly `expected`.
///
/// Shrinks the steal race: a fresh holder that re-created the lock between our
/// read and this call wrote different content, so we leave it alone.
fn break_lock_if_unchanged(path: &Path, expected: &str) {
    if std::fs::read_to_string(path).is_ok_and(|now| now == expected) {
        let _ = std::fs::remove_file(path);
    }
}

/// Age of `path` in milliseconds, or `None` if it cannot be stat'd.
fn lock_age_ms(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    std::time::SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// Is `pid` a live process on this host?
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    // kill(pid, 0): 0 => exists; -1/EPERM => exists but owned by another user;
    // -1/ESRCH => no such process.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Without a portable liveness probe, be conservative and never steal — the
/// caller still falls back to the lock timeout.
#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    true
}

/// This host's name, cached. Used only to decide whether a recorded holder is
/// local (probeable) or remote (leave alone), so exact form does not matter —
/// writer and reader on the same host must simply agree.
fn hostname() -> &'static str {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| {
        #[cfg(unix)]
        {
            let mut buf = [0 as libc::c_char; 256];
            // SAFETY: `buf` is a valid, owned, `buf.len()`-byte array and
            // gethostname writes at most that many bytes (NUL-terminated).
            if unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len()) } == 0 {
                let bytes: Vec<u8> = buf
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8)
                    .collect();
                if let Ok(s) = String::from_utf8(bytes) {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        return s;
                    }
                }
            }
        }
        std::env::var("HOSTNAME").unwrap_or_default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dead_pid() -> u32 {
        // Spawn a short-lived child and reap it, so its PID is (almost
        // certainly) no longer alive but was a real process.
        let child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        // Reap synchronously; after this the PID is dead.
        let mut child = child;
        let _ = child.wait();
        pid
    }

    #[test]
    fn breaks_lock_held_by_dead_local_pid() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".vault.lock");
        std::fs::write(&lock, format!("{} {}\n", dead_pid(), hostname())).unwrap();

        // Should acquire immediately (not wait the 30s timeout).
        let started = Instant::now();
        let got = acquire_lock(&lock).unwrap();
        assert_eq!(got, lock);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stale lock took too long to break: {:?}",
            started.elapsed()
        );
        release_lock(&lock);
        assert!(!lock.exists());
    }

    #[test]
    fn does_not_steal_lock_held_by_live_local_pid() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".vault.lock");
        // Our own PID is definitely alive on this host.
        std::fs::write(&lock, format!("{} {}\n", std::process::id(), hostname())).unwrap();

        break_if_stale(&lock);
        assert!(lock.exists(), "must not break a live holder's lock");
    }

    #[test]
    fn does_not_steal_lock_held_by_another_host() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".vault.lock");
        // Dead/hostless PID but a foreign hostname -> leave it alone.
        std::fs::write(&lock, format!("{} {}", dead_pid(), "some-other-host")).unwrap();

        break_if_stale(&lock);
        assert!(lock.exists(), "must not break a remote holder's lock");
    }

    #[test]
    fn breaks_old_identity_less_lock() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".vault.lock");
        std::fs::write(&lock, b"").unwrap();
        // Backdate the mtime past the grace window.
        let old = std::time::SystemTime::now() - Duration::from_secs(30);
        let f = std::fs::OpenOptions::new().write(true).open(&lock).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        drop(f);

        break_if_stale(&lock);
        assert!(!lock.exists(), "old 0-byte lock must be broken");
    }

    #[test]
    fn keeps_fresh_identity_less_lock() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(".vault.lock");
        std::fs::write(&lock, b"").unwrap();

        // Freshly-created (within the write window) -> must NOT be stolen.
        break_if_stale(&lock);
        assert!(lock.exists(), "fresh 0-byte lock must not be broken");
    }
}
