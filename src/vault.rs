//! Project-local vault storage: `.vault` (age-encrypted `.env`) and
//! `.vault.keys` (the authorized-public-key registry), both in the project
//! root and committed to git.
//!
//! - The **`.vault`** file is an age container encrypted to every public key
//!   listed in `.vault.keys`. Any single authorized private key decrypts it.
//! - The **`.vault.keys`** file is human-readable JSON listing the recipients;
//!   it is the source of truth for who can decrypt.
//! - A **`.vault.lock`** file (gitignored) serializes concurrent writers
//!   within a single checkout so the read-modify-write cycle is atomic.
//!
//! There is no global/central storage of secrets anymore — `~/.dotvault/`
//! holds only config, backups, and the update-check cache.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::access::{self, AuthorizedKey, VaultKeys, KEYS_FILE};
use crate::crypto;
use crate::envfmt;

/// The encrypted vault file in the project root.
pub const VAULT_FILE: &str = ".vault";
/// Companion file: agent-facing guide explaining this project uses dotvault,
/// committed to git alongside `.vault.keys` so AI agents (Claude Code, Codex,
/// Cursor, aider, Cline, etc.) discover it on `ls` / grep and reach for
/// `dotvault get NAME` instead of hardcoding or asking the user.
pub const KEYS_AGENTS_FILE: &str = ".vault.keys.AGENTS.md";
/// The (gitignored) exclusive lock file.
pub const LOCK_FILE: &str = ".vault.lock";
/// Busy-wait poll interval for acquiring the lock.
const LOCK_POLL_MS: u64 = 5;
/// Max time to wait for the lock before giving up.
const LOCK_TIMEOUT_SECS: u64 = 30;

/// Root of the global config dir: `~/.dotvault`. Override via `DOTVAULT_HOME`.
/// Holds config.toml, backups/, and the update-check cache — no secrets.
pub fn dotvault_home() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("DOTVAULT_HOME") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs_home().context("could not determine home directory")?;
    Ok(home.join(".dotvault"))
}

/// The project root directory for vault operations. Defaults to the current
/// working directory; override via `DOTVAULT_VAULT_DIR` (used by tests).
pub fn project_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("DOTVAULT_VAULT_DIR") {
        return Ok(PathBuf::from(p));
    }
    std::env::current_dir().context("could not determine current directory")
}

/// Path to the encrypted `.vault` file in the project root.
pub fn vault_path() -> Result<PathBuf> {
    Ok(project_dir()?.join(VAULT_FILE))
}

/// Path to the `.vault.keys` registry in the project root.
pub fn keys_path() -> Result<PathBuf> {
    Ok(project_dir()?.join(KEYS_FILE))
}

/// A loaded, locked project vault. The `.vault.lock` is held for the lifetime
/// of this struct (released on Drop), serializing concurrent writers.
pub struct Vault {
    /// The project root directory.
    pub dir: PathBuf,
    /// The authorized-public-key registry (`.vault.keys`).
    pub keys: VaultKeys,
    /// The SSH private key used to decrypt (and identify the current user).
    pub ssh_key: ssh_key::PrivateKey,
    /// The decrypted entries, in insertion order.
    pub entries: Vec<(String, String)>,
    /// Held `.vault.lock`, released on Drop.
    _lock: Option<PathBuf>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        if let Some(lock) = self._lock.take() {
            release_lock(&lock);
        }
    }
}

impl Vault {
    /// Create a new vault in the project root, seeded with the current user's
    /// public key as the sole initial recipient. Writes `.vault` (empty) +
    /// `.vault.keys` and (unless one already exists) the agent-facing
    /// `.vault.keys.AGENTS.md` companion that reminds AI agents to use
    /// `dotvault get NAME` instead of hardcoding secrets. Fails if a
    /// `.vault` already exists.
    ///
    /// `pubkey_line` is the authorized-keys line for the initial recipient
    /// (e.g. read from `~/.ssh/id_ed25519.pub`).
    pub fn init(ssh_key_path: &Path, pubkey_line: &str) -> Result<Self> {
        let dir = project_dir()?;
        let vpath = dir.join(VAULT_FILE);
        let kpath = dir.join(KEYS_FILE);
        let lpath = dir.join(LOCK_FILE);

        // Acquire the lock BEFORE the existence check to avoid a TOCTOU race
        // (two `init` calls both seeing "absent" then both creating).
        let lock = acquire_lock(&lpath)?;
        let result = (|| {
            if vpath.exists() {
                bail!(
                    "a vault already exists at {} (delete it first to re-initialize)",
                    vpath.display()
                );
            }
            let ssh_key = crypto::load_private_key(ssh_key_path)?;
            let initial = access::authorized_key_from_line(pubkey_line)?;
            let now = crate::util::now_iso();
            let keys = VaultKeys::new(initial, &now);
            let plaintext = envfmt::serialize(&Vec::new()).into_bytes();
            let container = crypto::encrypt_to_recipients(&keys.pubkey_lines(), &plaintext)?;
            access::write_atomic(&vpath, &container)?;
            access::save_keys(&kpath, &keys)?;
            // Drop the agent-facing companion note next to `.vault.keys` so any
            // AI agent that lands in this project via `ls`/grep/git ls-files
            // immediately learns that secrets live in `.vault` and should be
            // fetched via `dotvault get NAME`. Idempotent: never overwrites an
            // existing file (project owners may have edited it for their team).
            let note_path = dir.join(KEYS_AGENTS_FILE);
            if !note_path.exists() {
                let embedded = include_str!("../.vault.keys.AGENTS.md");
                std::fs::write(&note_path, embedded.as_bytes())
                    .with_context(|| format!("failed to write {}", note_path.display()))?;
            }
            Ok(Vault {
                dir,
                keys,
                ssh_key,
                entries: Vec::new(),
                _lock: None,
            })
        })();
        match result {
            Ok(mut v) => {
                v._lock = Some(lock);
                Ok(v)
            }
            Err(e) => {
                release_lock(&lock);
                Err(e)
            }
        }
    }

    /// Load and decrypt the project vault. Acquires `.vault.lock` for the
    /// lifetime of the returned `Vault`.
    pub fn load(ssh_key_path: &Path) -> Result<Self> {
        let dir = project_dir()?;
        let vpath = dir.join(VAULT_FILE);
        let lpath = dir.join(LOCK_FILE);
        // Fast-path existence check BEFORE locking: a missing vault should
        // report a clear "no vault" error rather than creating a stray lock
        // file. This is a read-only check; the authoritative check happens
        // inside the lock below.
        if !vpath.exists() {
            bail!(
                "no vault at {} (run `dotvault init` first)",
                vpath.display()
            );
        }
        let lock = acquire_lock(&lpath)?;
        let result = (|| {
            // Re-check inside the lock: the vault may have been removed
            // between the fast-path check and lock acquisition.
            if !vpath.exists() {
                bail!(
                    "no vault at {} (it was removed during load)",
                    vpath.display()
                );
            }
            Self::load_inner(&dir, ssh_key_path)
        })();
        match result {
            Ok(mut v) => {
                v._lock = Some(lock);
                Ok(v)
            }
            Err(e) => {
                release_lock(&lock);
                Err(e)
            }
        }
    }

    fn load_inner(dir: &Path, ssh_key_path: &Path) -> Result<Self> {
        let vpath = dir.join(VAULT_FILE);
        let kpath = dir.join(KEYS_FILE);
        let container =
            std::fs::read(&vpath).with_context(|| format!("failed to read {}", vpath.display()))?;
        let ssh_key = crypto::load_private_key(ssh_key_path)?;
        let plaintext = crypto::decrypt_with_key(&ssh_key, &container)?;
        let entries = envfmt::parse(&String::from_utf8_lossy(&plaintext))
            .context("vault document is corrupted (failed to parse)")?;
        let keys = access::load_keys(&kpath)?;
        Ok(Vault {
            dir: dir.to_path_buf(),
            keys,
            ssh_key,
            entries,
            _lock: None,
        })
    }

    /// Insert a NEW entry. Fails if the key already exists.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        if self.entries.iter().any(|(k, _)| k == key) {
            bail!(
                "secret {:?} already exists; run `dotvault rm {}` first to replace it",
                key,
                key
            );
        }
        self.entries.push((key.to_string(), value.to_string()));
        Ok(())
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Remove an entry. Returns true if it was present.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(k, _)| k != key);
        self.entries.len() != before
    }

    /// Serialize entries, re-encrypt to ALL authorized recipients, back up the
    /// prior container, and write the new `.vault` atomically.
    pub fn save(&mut self) -> Result<()> {
        let doc = envfmt::serialize(&self.entries);
        let plaintext = doc.as_bytes();
        let container = crypto::encrypt_to_recipients(&self.keys.pubkey_lines(), plaintext)?;

        let vpath = self.dir.join(VAULT_FILE);
        let kpath = self.dir.join(KEYS_FILE);

        if vpath.exists() {
            crate::backup::backup_container(&vpath, &self.dir)
                .context("failed to back up vault")?;
        }
        access::write_atomic(&vpath, &container)?;
        access::save_keys(&kpath, &self.keys)?;
        Ok(())
    }

    /// Add a recipient: append their public key to `.vault.keys` and re-encrypt.
    /// Returns the fingerprint of the added key, or an error if already present.
    pub fn add_key(&mut self, pubkey_line: &str) -> Result<String> {
        let new_key = access::authorized_key_from_line(pubkey_line)?;
        let fp = new_key.fingerprint.clone();
        let now = crate::util::now_iso();
        if !self.keys.add(new_key, &now) {
            bail!("key {} is already authorized", fp);
        }
        self.save()?;
        Ok(fp)
    }

    /// Remove a recipient by fingerprint or label and re-encrypt. Returns the
    /// removed key. Refuses to remove the last recipient (would lock everyone
    /// out). Does NOT revoke access to ciphertext already in git history.
    pub fn remove_key(&mut self, query: &str) -> Result<AuthorizedKey> {
        if self.keys.len() <= 1 {
            bail!("cannot remove the last authorized key — the vault would become unrecoverable");
        }
        let now = crate::util::now_iso();
        let removed = self
            .keys
            .remove(query, &now)
            .with_context(|| format!("no authorized key matches {:?}", query))?;
        self.save()?;
        Ok(removed)
    }

    /// Whether the current user's SSH key is among the authorized recipients.
    pub fn current_user_authorized(&self) -> bool {
        let my_fp = crypto::ssh_fingerprint(&self.ssh_key);
        self.keys.find(&my_fp).is_some()
    }
}

// ---------- file locking ----------

/// Acquire an exclusive lock by atomically creating `path`. Busy-waits up to
/// `LOCK_TIMEOUT_SECS` before giving up.
fn acquire_lock(path: &Path) -> Result<PathBuf> {
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
fn release_lock(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("warning: could not remove lock {}: {e}", path.display());
        }
    }
}

// ---------- home resolution ----------

fn dirs_home() -> Option<PathBuf> {
    // Unix uses HOME; Windows uses USERPROFILE.
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use std::sync::Mutex;

    /// Process-wide mutex that serializes any test which mutates
    /// `DOTVAULT_VAULT_DIR` or `std::env::current_dir()`. cargo test's default
    /// multi-threaded execution otherwise races two init tests that both
    /// `set_var` and `remove_var` the same env var, leading to one of them
    /// reading the other's intermediate state (or none at all, falling back
    /// to the real cwd — which in this very repo IS a vault directory used
    /// for smoke tests).
    ///
    /// Using `Mutex<()>::lock()` directly instead of `#[serial_test::serial]`
    /// keeps the rest of the test suite parallel (40 tests, not 4).
    static INIT_LOCK: Mutex<()> = Mutex::new(());

    /// Generate a throwaway ed25519 keypair into a tempdir and return
    /// (TempDir guard, private_key_path, authorized-keys line). The TempDir
    /// is returned so the caller can hold it alive across multiple init
    /// calls in the same test.
    fn make_test_key() -> (tempfile::TempDir, std::path::PathBuf, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_ed25519");
        let mut rng = rand::thread_rng();
        let kp = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("generate key");
        let pem = kp.to_openssh(LineEnding::LF).expect("encode key");
        std::fs::write(&path, pem.as_str().as_bytes()).expect("write key");
        let pub_line = kp.public_key().to_openssh().expect("encode pubkey");
        (dir, path, pub_line)
    }

    #[test]
    fn dotvault_home_respects_env() {
        std::env::set_var("DOTVAULT_HOME", "/tmp/dv-test-home");
        assert_eq!(dotvault_home().unwrap(), PathBuf::from("/tmp/dv-test-home"));
        std::env::remove_var("DOTVAULT_HOME");
    }

    #[test]
    fn project_dir_respects_env() {
        std::env::set_var("DOTVAULT_VAULT_DIR", "/tmp/dv-test-project");
        assert_eq!(
            project_dir().unwrap(),
            PathBuf::from("/tmp/dv-test-project")
        );
        std::env::remove_var("DOTVAULT_VAULT_DIR");
    }

    /// `init` must drop `.vault.keys.AGENTS.md` next to `.vault.keys` so any
    /// agent that lands in the project via `ls` immediately learns secrets
    /// live in `.vault` and should be fetched via `dotvault get NAME`.
    #[test]
    fn init_writes_agent_companion_note() {
        let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let project = tempfile::tempdir().expect("project tempdir");
        std::env::set_var("DOTVAULT_VAULT_DIR", project.path());
        let (keydir, key_path, pub_line) = make_test_key();
        // hold keydir alive until end of test so the test's private key file
        // is still readable when the Vault::init body reads it
        let _keep_keydir = keydir;

        let _v = Vault::init(&key_path, &pub_line).expect("init");

        let note = project.path().join(KEYS_AGENTS_FILE);
        assert!(
            note.is_file(),
            "expected companion note at {} after init",
            note.display()
        );
        let body = std::fs::read_to_string(&note).expect("read note");
        assert!(!body.trim().is_empty(), "companion note must not be empty");
        // The note MUST mention `dotvault get` so an agent that skims it
        // immediately sees the canonical command.
        assert!(
            body.contains("dotvault get"),
            "companion note must mention `dotvault get` (got first 200 chars: {:?})",
            &body[..body.len().min(200)]
        );
        std::env::remove_var("DOTVAULT_VAULT_DIR");
    }

    /// Re-running `init` must fail (vault already exists) and must NOT
    /// overwrite an owner-customized companion note — owners may have
    /// rewritten it for their team and we should not clobber their edits.
    #[test]
    fn init_does_not_overwrite_existing_companion_note() {
        let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let project = tempfile::tempdir().expect("project tempdir");
        std::env::set_var("DOTVAULT_VAULT_DIR", project.path());
        let (keydir, key_path, pub_line) = make_test_key();
        let _keep_keydir = keydir;

        let first = Vault::init(&key_path, &pub_line).expect("first init");
        // Drop the Vault explicitly to release its `.vault.lock` BEFORE the
        // second init call. Without this, the second init's `acquire_lock`
        // would spin for 30s waiting for the lock to clear. (Rust's `let _v`
        // is NOT immediate-drop; the binding lives until end of scope.)
        drop(first);

        // Owner customizes the note.
        let note = project.path().join(KEYS_AGENTS_FILE);
        std::fs::write(&note, "# custom owner note\n").expect("write custom note");

        // Re-init must fail because the vault already exists. The "no
        // overwrite on existing file" guard in `Vault::init` is defense-
        // in-depth — but in practice we never reach it because the existing-
        // vault check bails first.
        let again = Vault::init(&key_path, &pub_line);
        assert!(again.is_err(), "re-init must fail when .vault exists");
        let body = std::fs::read_to_string(&note).expect("read note");
        assert_eq!(
            body, "# custom owner note\n",
            "owner-customized companion note must survive re-init attempts"
        );
        std::env::remove_var("DOTVAULT_VAULT_DIR");
    }
}
