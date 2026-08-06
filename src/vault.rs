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

use anyhow::{bail, Context, Result};

use crate::access::{self, AuthorizedKey, VaultKeys, KEYS_FILE};
use crate::crypto;
use crate::envfmt;
use crate::vault_lock::{acquire_lock, release_lock};

/// The encrypted vault file in the project root.
pub const VAULT_FILE: &str = ".vault";
/// The (gitignored) exclusive lock file.
pub const LOCK_FILE: &str = ".vault.lock";
// Lock poll interval + timeout live in `vault_lock.rs` (along with the
// acquire/release helpers), to keep this file under the 500-line guideline.

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
    /// `None` when the vault was opened with a read-only token (`--token`),
    /// in which case write commands must be rejected by the caller.
    pub ssh_key: Option<ssh_key::PrivateKey>,
    /// The decrypted entries, in insertion order.
    pub entries: Vec<(String, String)>,
    /// Held `.vault.lock`, released on Drop. `pub(crate)` so the token-loading
    /// path in `vault_token.rs` (an extension impl) can construct a `Vault`.
    pub(crate) _lock: Option<PathBuf>,
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
    /// `.vault.keys` (whose top `//` comment guides AI agents to
    /// `dotvault --help`). Fails if a `.vault` already exists.
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
            crate::util::write_atomic(&vpath, &container)?;
            access::save_keys(&kpath, &keys)?;
            Ok(Vault {
                dir,
                keys,
                ssh_key: Some(ssh_key),
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
            ssh_key: Some(ssh_key),
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

    /// Serialize entries, re-encrypt to ALL authorized recipients (SSH keys
    /// AND read-only tokens), back up the prior container, and write the new
    /// `.vault` atomically.
    pub fn save(&mut self) -> Result<()> {
        let doc = envfmt::serialize(&self.entries);
        let plaintext = doc.as_bytes();
        let container = crypto::encrypt_to_recipients_with_tokens(
            &self.keys.pubkey_lines(),
            &self.keys.token_pubkeys(),
            plaintext,
        )?;

        let vpath = self.dir.join(VAULT_FILE);
        let kpath = self.dir.join(KEYS_FILE);

        if vpath.exists() {
            crate::backup::backup_container(&vpath, &self.dir)
                .context("failed to back up vault")?;
        }
        crate::util::write_atomic(&vpath, &container)?;
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
    /// Always `false` when opened with a token (no SSH key available).
    pub fn current_user_authorized(&self) -> bool {
        let Some(sk) = &self.ssh_key else {
            return false;
        };
        let my_fp = crypto::ssh_fingerprint(sk);
        self.keys.find(&my_fp).is_some()
    }

    // NOTE: token methods (load_with_token / add_token / remove_token) live in
    // `vault_token.rs` as an extension `impl Vault`, to keep this file under
    // the 500-line guideline.
}

// NOTE: the file-locking helpers (acquire_lock / release_lock) live in
// `vault_lock.rs`, to keep this file under the 500-line guideline.

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

    /// `init` writes a `.vault.keys` whose top `//` comment guides AI agents to
    /// `dotvault --help` (replacing the old standalone `.vault.keys.AGENTS.md`).
    #[test]
    fn init_writes_keys_with_agent_guidance_comment() {
        let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let project = tempfile::tempdir().expect("project tempdir");
        std::env::set_var("DOTVAULT_VAULT_DIR", project.path());
        let (keydir, key_path, pub_line) = make_test_key();
        let _keep_keydir = keydir;

        let _v = Vault::init(&key_path, &pub_line).expect("init");

        let kpath = project.path().join(crate::access::KEYS_FILE);
        let body = std::fs::read_to_string(&kpath).expect("read .vault.keys");
        assert!(
            body.starts_with("//"),
            ".vault.keys should start with the agent-guidance // comment"
        );
        assert!(
            body.contains("dotvault --help"),
            "guidance comment should point agents to `dotvault --help`"
        );
        std::env::remove_var("DOTVAULT_VAULT_DIR");
    }
}
