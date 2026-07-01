//! Centralized, namespaced vault storage under `~/.dotvault/namespaces/<ns>/`.
//!
//! v0.2 model:
//! - All vaults live centrally, one directory per namespace.
//! - The **SSH key** decrypts a namespace's vault (required every operation).
//! - The **access_key** (in the project's `.dotvault_key`) selects + authorizes
//!   a namespace. Its value is also stored encrypted-by-SSH-key in the
//!   namespace's `.access_key.enc` registry; on every load we verify the two
//!   match, so editing a project file can't impersonate another namespace.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::access::{self, AccessKey};
use crate::crypto;
use crate::envfmt;

/// File names inside a namespace directory.
pub const VAULT_FILE: &str = "vault.bin";
pub const META_FILE: &str = "vault.meta.json";

/// Metadata persisted alongside the encrypted container. Used to verify that
/// the same SSH key is being used and to carry the KDF salt.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Meta {
    pub version: u8,
    /// OpenSSH SHA-256 fingerprint, e.g. `SHA256:AbC...`.
    pub ssh_fingerprint: String,
    /// Base64-encoded KDF salt.
    pub kdf_salt: String,
    pub created_at: String,
    pub updated_at: String,
    pub entry_count: usize,
}

impl Meta {
    /// Decode the persisted base64 salt back into raw bytes.
    pub fn salt_bytes(&self) -> Result<Vec<u8>> {
        crate::util::base64_decode(&self.kdf_salt)
    }
}

/// Root of central storage: `~/.dotvault`. Override via `DOTVAULT_HOME`.
pub fn dotvault_home() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("DOTVAULT_HOME") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs_home().context("could not determine home directory")?;
    Ok(home.join(".dotvault"))
}

/// Directory for a namespace: `~/.dotvault/namespaces/<ns>/`. The namespace
/// name is validated strictly (see [`access::validate_namespace`]) — this is
/// the only defense against path traversal.
pub fn namespace_dir(ns: &str) -> Result<PathBuf> {
    access::validate_namespace(ns)?;
    Ok(dotvault_home()?.join("namespaces").join(ns))
}

/// List all namespace names currently in central storage (directory names
/// under `namespaces/` that pass validation and contain a vault).
pub fn list_namespaces() -> Result<Vec<String>> {
    let root = dotvault_home()?.join("namespaces");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in
        std::fs::read_dir(&root).with_context(|| format!("failed to read {}", root.display()))?
    {
        let entry = entry?;
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(String::from) else {
            continue;
        };
        // Only count well-formed namespaces that actually have a vault.
        if access::validate_namespace(&name).is_err() {
            continue;
        }
        if entry.path().join(VAULT_FILE).exists() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Remove a namespace directory entirely. Requires the SSH key to authorize
/// (proving the caller controls the vault). Returns true if it existed.
pub fn remove_namespace(ns: &str, key_path: &Path) -> Result<bool> {
    let dir = namespace_dir(ns)?;
    if !dir.exists() {
        return Ok(false);
    }
    // Authorize: the caller must be able to load the vault with this key.
    if dir.join(VAULT_FILE).exists() {
        // Verify key matches before deleting (fail-fast, no silent deletion).
        let _ = Vault::load(ns, key_path)?;
    }
    std::fs::remove_dir_all(&dir)
        .with_context(|| format!("failed to remove namespace dir {}", dir.display()))?;
    Ok(true)
}

/// Name of the lock file inside a namespace dir. Its EXISTENCE = locked.
const LOCK_FILE: &str = ".lock";
/// How long to wait for a contended lock before giving up.
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Poll interval while waiting for a lock.
const LOCK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// A vault loaded into memory: its namespace, metadata, SSH key, and entries.
///
/// Holding a `Vault` keeps an **exclusive lock** on the namespace (via an
/// atomically-created `.lock` file), so concurrent writers are serialized for
/// the whole read-modify-write cycle. The lock is released on `Drop` by
/// removing the file.
pub struct Vault {
    pub namespace: String,
    pub dir: PathBuf,
    pub meta: Meta,
    pub key: ssh_key::PrivateKey,
    pub entries: Vec<(String, String)>,
    /// Path of the held `.lock` file; removed on `Drop`.
    _lock: Option<PathBuf>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        if let Some(p) = self._lock.take() {
            release_lock(&p);
        }
    }
}

/// Acquire an exclusive lock by atomically creating `.lock` (create_new). If
/// it exists, busy-wait with backoff until the holder removes it. Pure
/// userspace + filesystem atomicity — no `flock`, so it behaves identically
/// under coverage instrumentation. The returned path is stored in the `Vault`
/// and removed on `Drop`.
fn acquire_lock(dir: &Path) -> Result<PathBuf> {
    let lock_path = dir.join(LOCK_FILE);
    let deadline = std::time::Instant::now() + LOCK_TIMEOUT;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => return Ok(lock_path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if std::time::Instant::now() > deadline {
                    bail!(
                        "timed out waiting for lock {} (another process may be stuck; \
                         remove it manually if stale)",
                        lock_path.display()
                    );
                }
                std::thread::sleep(LOCK_POLL_INTERVAL);
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to create lock {}", lock_path.display()))
            }
        }
    }
}

/// Release the lock by removing the `.lock` file. Best-effort: a missing file
/// (e.g. manual cleanup) is not an error.
fn release_lock(lock_path: &Path) {
    let _ = std::fs::remove_file(lock_path);
}

impl Vault {
    /// Resolve the SSH key path. Priority: `--key` flag → `DOTVAULT_KEY` env
    /// → `~/.dotvault/config.toml` `key` → hardcoded `~/.ssh/id_ed25519`.
    /// Returns the path plus a flag indicating whether the *hardcoded* default
    /// was used implicitly (so callers can warn).
    pub fn resolve_key_path(explicit: Option<&Path>) -> Result<(PathBuf, bool)> {
        if let Some(p) = explicit {
            return Ok((p.to_path_buf(), false));
        }
        if let Ok(p) = std::env::var("DOTVAULT_KEY") {
            return Ok((PathBuf::from(p), false));
        }
        if let Some(p) = crate::config::Config::load()
            .ok()
            .and_then(|c| c.key_path())
        {
            return Ok((p, false));
        }
        if let Some(home) = dirs_home() {
            let default = home.join(".ssh").join("id_ed25519");
            return Ok((default, true));
        }
        bail!("could not determine SSH key path; pass --key or set DOTVAULT_KEY");
    }

    /// Create a brand-new namespace vault + access-key registry. Generates a
    /// random access key and writes it (encrypted) into the namespace dir.
    /// Returns the vault and the generated `AccessKey` (caller writes the
    /// project file).
    pub fn init(namespace: &str, key_path: &Path) -> Result<(Self, AccessKey)> {
        access::validate_namespace(namespace)?;
        let dir = namespace_dir(namespace)?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create namespace dir {}", dir.display()))?;
        // Acquire the lock BEFORE the existence check to avoid a TOCTOU race
        // (two `init` calls both seeing "absent" then both creating).
        let lock = acquire_lock(&dir)?;
        // Build on success; release the lock on ANY error below.
        let result = (|| {
            if dir.join(VAULT_FILE).exists() {
                bail!("namespace {:?} already exists", namespace);
            }
            let key = crypto::load_private_key(key_path)?;
            let fingerprint = crypto::ssh_fingerprint(&key);
            let salt = crypto::random_salt();
            let now = crate::util::now_iso();
            let meta = Meta {
                version: crypto::VERSION,
                ssh_fingerprint: fingerprint,
                kdf_salt: crate::util::base64_encode(&salt),
                created_at: now.clone(),
                updated_at: now,
                entry_count: 0,
            };
            let mut vault = Vault {
                namespace: namespace.to_string(),
                dir: dir.clone(),
                meta,
                key: key.clone(),
                entries: Vec::new(),
                _lock: None,
            };
            vault.save_internal(false)?; // no prior container to back up

            // Generate + persist the access-key registry (encrypted by SSH key).
            let access_key = AccessKey::generate(namespace)?;
            access::write_registry(&vault.dir, &key, &access_key)?;
            Ok((vault, access_key))
        })();
        match result {
            Ok((mut vault, ak)) => {
                vault._lock = Some(lock);
                Ok((vault, ak))
            }
            Err(e) => {
                release_lock(&lock);
                Err(e)
            }
        }
    }

    /// Load a namespace vault: read the project `.dotvault_key`, verify its
    /// access_key matches the registered one, then decrypt with the SSH key.
    ///
    /// Acquires an exclusive lock held for the lifetime of the returned
    /// `Vault`, serializing concurrent writers (prevents lost updates).
    pub fn load(namespace: &str, key_path: &Path) -> Result<Self> {
        access::validate_namespace(namespace)?;
        let dir = namespace_dir(namespace)?;
        // Fast-path existence check BEFORE locking: a missing namespace should
        // report a clear "no vault" error rather than a lock-file creation
        // failure (the namespace dir doesn't exist). This is a read-only check,
        // so no TOCTOU concern for non-existent namespaces.
        if !dir.join(VAULT_FILE).exists() {
            bail!(
                "namespace {:?} has no vault at {} (run `dotvault init {}` first)",
                namespace,
                dir.display(),
                namespace
            );
        }
        // Lock before reading so the read-modify-write cycle is atomic w.r.t.
        // other processes. The lock is held by the returned Vault; if anything
        // below fails we must release it (no Vault exists yet to Drop it).
        let lock = acquire_lock(&dir)?;
        let result = Self::load_inner(namespace, &dir, key_path);
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

    /// Inner load logic, lock-free. Caller manages the lock.
    fn load_inner(namespace: &str, dir: &Path, key_path: &Path) -> Result<Self> {
        let meta_path = dir.join(META_FILE);
        let vault_path = dir.join(VAULT_FILE);
        let meta_text = std::fs::read_to_string(&meta_path).with_context(|| {
            format!(
                "namespace {:?} has no vault at {} (run `dotvault init {}` first)",
                namespace,
                dir.display(),
                namespace
            )
        })?;
        let meta: Meta = serde_json::from_str(&meta_text)
            .with_context(|| format!("failed to parse {}", meta_path.display()))?;
        let container = std::fs::read(&vault_path)
            .with_context(|| format!("failed to read {}", vault_path.display()))?;

        let key = crypto::load_private_key(key_path)?;
        let fingerprint = crypto::ssh_fingerprint(&key);
        if fingerprint != meta.ssh_fingerprint {
            bail!(
                "SSH key fingerprint mismatch for namespace {:?}.\n  vault expects: {}\n  \
                 current key:  {}\n\nIf you rotated your key, use `dotvault rekey`.",
                namespace,
                meta.ssh_fingerprint,
                fingerprint
            );
        }

        let salt = meta.salt_bytes()?;
        let aes_key = crypto::derive_key(&key, &salt)?;
        let plaintext = crypto::open(&aes_key, &container)?;
        let entries = envfmt::parse(&String::from_utf8_lossy(&plaintext))
            .context("vault document is corrupted (failed to parse)")?;

        Ok(Vault {
            namespace: namespace.to_string(),
            dir: dir.to_path_buf(),
            meta,
            key,
            entries,
            _lock: None,
        })
    }

    /// Verify a project's `.dotvault_key` authorizes this namespace: the key's
    /// value must equal the registered (decrypted) access_key.
    pub fn verify_access_key(&self, presented: &AccessKey) -> Result<()> {
        let registered = access::read_registry(&self.dir, &self.key)?;
        if presented.namespace != self.namespace {
            bail!(
                "namespace mismatch: project key says {:?}, vault is {:?}",
                presented.namespace,
                self.namespace
            );
        }
        if presented.key != registered.key {
            bail!(
                "access key rejected for namespace {:?}: does not match the registered key",
                self.namespace
            );
        }
        Ok(())
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

    /// Serialize entries, re-encrypt, back up the prior container, and write
    /// the new container + updated metadata atomically.
    pub fn save(&mut self) -> Result<()> {
        self.save_internal(true)
    }

    fn save_internal(&mut self, allow_backup: bool) -> Result<()> {
        let doc = envfmt::serialize(&self.entries);
        let salt = self.meta.salt_bytes()?;
        let aes_key = crypto::derive_key(&self.key, &salt)?;
        let container = crypto::seal(&aes_key, doc.as_bytes())?;

        let vault_path = self.dir.join(VAULT_FILE);
        let meta_path = self.dir.join(META_FILE);

        if allow_backup && vault_path.exists() {
            crate::backup::backup_container(&vault_path, &self.namespace)
                .context("failed to back up vault")?;
        }

        write_atomic(&vault_path, &container)?;
        self.meta.updated_at = crate::util::now_iso();
        self.meta.entry_count = self.entries.len();
        let meta_json = serde_json::to_string_pretty(&self.meta)?;
        write_atomic(&meta_path, meta_json.as_bytes())?;
        Ok(())
    }

    /// Re-key the vault: re-encrypt with `new_key` and a fresh salt/fingerprint.
    /// Also re-encrypts the access-key registry with the new key.
    pub fn rekey(&mut self, new_key_path: &Path) -> Result<String> {
        let new_key = crypto::load_private_key(new_key_path)?;
        let new_fp = crypto::ssh_fingerprint(&new_key);

        // Re-encrypt the access-key registry with the new key.
        let access_key = access::read_registry(&self.dir, &self.key)?;
        self.key = new_key;
        let salt = crypto::random_salt();
        self.meta.ssh_fingerprint = new_fp.clone();
        self.meta.kdf_salt = crate::util::base64_encode(&salt);
        self.save()?;
        access::write_registry(&self.dir, &self.key, &access_key)?;
        Ok(new_fp)
    }
}

// ---------- access-key registry (in access.rs); backups in backup.rs ----------

/// Write `data` to `dest` atomically via a temp file + rename.
fn write_atomic(dest: &Path, data: &[u8]) -> Result<()> {
    let dir = dest
        .parent()
        .with_context(|| format!("no parent dir for {}", dest.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        dest.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("dotvault")
    ));
    std::fs::write(&tmp, data).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, dest).with_context(|| format!("failed to install {}", dest.display()))?;
    Ok(())
}

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

    #[test]
    fn namespace_dir_validates_name() {
        assert!(namespace_dir("good-ns").is_ok());
        assert!(namespace_dir("../escape").is_err());
        assert!(namespace_dir("a/b").is_err());
    }

    #[test]
    fn dotvault_home_respects_env() {
        std::env::set_var("DOTVAULT_HOME", "/tmp/dv-test-home");
        assert_eq!(dotvault_home().unwrap(), PathBuf::from("/tmp/dv-test-home"));
        std::env::remove_var("DOTVAULT_HOME");
    }
}
