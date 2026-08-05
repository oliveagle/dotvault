//! Read-only token loading/minting/revocation on `Vault`, split out of
//! `vault.rs` for file-size hygiene.
//!
//! These are extension `impl Vault` methods; the `Vault` struct + its core
//! load/save live in `vault.rs`. The `_lock` field is `pub(crate)` so that the
//! token-loading path here can construct a `Vault` holding the lock.

use anyhow::{bail, Context, Result};

use crate::access::{self, KEYS_FILE};
use crate::crypto;
use crate::envfmt;
use crate::vault::{project_dir, Vault, LOCK_FILE, VAULT_FILE};
use crate::vault_lock::{acquire_lock, release_lock};

impl Vault {
    /// Load and decrypt the vault using a read-only token
    /// (`AGE-SECRET-KEY-1...`) instead of an SSH key. Acquires `.vault.lock`
    /// like `load`. The returned `Vault` has `ssh_key = None`, so callers MUST
    /// reject write commands (the command layer enforces this).
    pub fn load_with_token(token: &str) -> Result<Self> {
        let dir = project_dir()?;
        let vpath = dir.join(VAULT_FILE);
        let lpath = dir.join(LOCK_FILE);
        if !vpath.exists() {
            bail!(
                "no vault at {} (run `dotvault init` first)",
                vpath.display()
            );
        }
        let lock = acquire_lock(&lpath)?;
        let result = (|| {
            if !vpath.exists() {
                bail!(
                    "no vault at {} (it was removed during load)",
                    vpath.display()
                );
            }
            let kpath = dir.join(KEYS_FILE);
            let container = std::fs::read(&vpath)
                .with_context(|| format!("failed to read {}", vpath.display()))?;
            let plaintext = crypto::decrypt_with_token(token, &container)?;
            let entries = envfmt::parse(&String::from_utf8_lossy(&plaintext))
                .context("vault document is corrupted (failed to parse)")?;
            let keys = access::load_keys(&kpath)?;
            Ok(Vault {
                dir: dir.to_path_buf(),
                keys,
                ssh_key: None,
                entries,
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

    /// Create a new read-only token, authorize it (append its `age1...` public
    /// key to `.vault.keys`), re-encrypt the vault so the token can decrypt,
    /// and return the plaintext token secret (`AGE-SECRET-KEY-1...`). The
    /// secret is shown to the caller ONCE and is never stored.
    pub fn add_token(&mut self, label: &str) -> Result<String> {
        if self.keys.find_token(label).is_some() {
            bail!(
                "token {:?} already exists; run `dotvault revoke-token {}` first to replace it",
                label,
                label
            );
        }
        let (secret, pubkey) = crypto::generate_token_keypair();
        let now = crate::util::now_iso();
        let token = access::authorized_token(label, &pubkey, &now)?;
        if !self.keys.add_token(token, &now) {
            // Defensive: add_token returns false on dup; we checked above, but
            // a race or pubkey collision could still land here.
            bail!(
                "token {:?} could not be added (label or key collision)",
                label
            );
        }
        self.save()?;
        Ok(secret)
    }

    /// Revoke a read-only token by label or `age1...` public key. Removes it
    /// from `.vault.keys` and re-encrypts, so the revoked token can no longer
    /// decrypt the CURRENT ciphertext. (Like `remove_key`, this does NOT
    /// revoke access to ciphertext already committed to git history.)
    pub fn remove_token(&mut self, query: &str) -> Result<access::AuthorizedToken> {
        let now = crate::util::now_iso();
        let removed = self
            .keys
            .remove_token(query, &now)
            .with_context(|| format!("no authorized token matches {:?}", query))?;
        self.save()?;
        Ok(removed)
    }
}
