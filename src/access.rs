//! Authorized-public-key registry: the `.vault.keys` file that lists every
//! recipient able to decrypt the project's `.vault`.
//!
//! `.vault.keys` is human-readable JSON, committed to git alongside the
//! (encrypted) `.vault` so the recipient set is auditable. Each entry records
//! the SSH public key (authorized-keys line), its fingerprint, and metadata
//! (label, when added).
//!
//! This is the source of truth for encryption: every `save()` re-seals the
//! vault to the full list in this file. Adding a teammate means appending
//! their public key here and re-encrypting; removing means deleting it and
//! re-encrypting. Note that removal does NOT revoke access to ciphertext
//! already committed to git history (see README — Security).

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;

use crate::crypto;

/// Filename for the authorized-public-key list, in the project root.
pub const KEYS_FILE: &str = ".vault.keys";

/// One authorized recipient: their SSH public key + identifying metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedKey {
    /// OpenSSH public-key fingerprint, `SHA256:base64`. Unique identifier.
    pub fingerprint: String,
    /// Authorized-keys line, e.g. `ssh-ed25519 AAAA... comment`.
    pub public_key: String,
    /// Human-readable label (email, username, or the pubkey comment).
    pub label: String,
    /// ISO-8601 timestamp when this key was added.
    pub added_at: String,
}

/// The full authorized-key registry, serialized to `.vault.keys`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultKeys {
    /// Format version, currently 1.
    pub version: u8,
    /// ISO-8601 timestamp of initial creation.
    pub created_at: String,
    /// ISO-8601 timestamp of the last modification.
    pub updated_at: String,
    /// Authorized recipients. Order is insertion order (stable under edits).
    pub keys: Vec<AuthorizedKey>,
}

impl VaultKeys {
    /// Build a new registry seeded with a single initial recipient.
    pub fn new(initial: AuthorizedKey, now: &str) -> Self {
        Self {
            version: 1,
            created_at: now.to_string(),
            updated_at: now.to_string(),
            keys: vec![initial],
        }
    }

    /// Build an empty registry (version/timestamps only).
    pub fn empty(now: &str) -> Self {
        Self {
            version: 1,
            created_at: now.to_string(),
            updated_at: now.to_string(),
            keys: Vec::new(),
        }
    }

    /// Return the authorized-keys lines (`public_key` fields) for encryption.
    pub fn pubkey_lines(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.public_key.clone()).collect()
    }

    /// Find a key by fingerprint (case-insensitive on the prefix is not done —
    /// fingerprints are canonical).
    pub fn find(&self, fingerprint: &str) -> Option<&AuthorizedKey> {
        self.keys.iter().find(|k| k.fingerprint == fingerprint)
    }

    /// Find a key whose label matches (case-insensitive exact match).
    pub fn find_by_label(&self, label: &str) -> Option<&AuthorizedKey> {
        self.keys
            .iter()
            .find(|k| k.label.eq_ignore_ascii_case(label))
    }

    /// Find a key whose fingerprint OR label matches `query`.
    pub fn find_by_query(&self, query: &str) -> Option<&AuthorizedKey> {
        self.find(query).or_else(|| self.find_by_label(query))
    }

    /// Append a new recipient. Returns `false` if a key with the same
    /// fingerprint already exists (caller should report).
    pub fn add(&mut self, key: AuthorizedKey, now: &str) -> bool {
        if self.find(&key.fingerprint).is_some() {
            return false;
        }
        self.keys.push(key);
        self.updated_at = now.to_string();
        true
    }

    /// Remove the recipient matching `query` (fingerprint or label). Returns
    /// the removed key, or `None` if no match.
    pub fn remove(&mut self, query: &str, now: &str) -> Option<AuthorizedKey> {
        let idx = self
            .keys
            .iter()
            .position(|k| k.fingerprint == query || k.label.eq_ignore_ascii_case(query))?;
        let removed = self.keys.remove(idx);
        self.updated_at = now.to_string();
        Some(removed)
    }

    /// Number of authorized recipients.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the registry has no recipients.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Load and parse a `.vault.keys` file from `path`. Validates that every
/// `public_key` entry is parseable, so a corrupted/merged registry fails fast
/// with a clear error rather than a cryptic failure at encryption time.
pub fn load_keys(path: &Path) -> Result<VaultKeys> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let keys: VaultKeys = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))?;
    if keys.keys.is_empty() {
        bail!(
            "{} has no authorized keys — the vault would be unrecoverable",
            path.display()
        );
    }
    // Validate each public key parses, so a hand-edited/merged-corrupt
    // .vault.keys reports the offending key here, not deep in encryption.
    for (i, k) in keys.keys.iter().enumerate() {
        crypto::parse_pubkey_line(&k.public_key).map_err(|e| {
            anyhow::anyhow!(
                "{} entry #{} (fingerprint {}) has an invalid public_key: {e}",
                path.display(),
                i + 1,
                k.fingerprint
            )
        })?;
    }
    Ok(keys)
}

/// Serialize and atomically write a `VaultKeys` registry to `path`.
pub fn save_keys(path: &Path, keys: &VaultKeys) -> Result<()> {
    let json = serde_json::to_string_pretty(keys)
        .map_err(|e| anyhow::anyhow!("failed to serialize {}: {e}", path.display()))?;
    write_atomic(path, json.as_bytes())
}

/// Build an `AuthorizedKey` from a public-key line (authorized-keys format
/// or `@file` already read into a line), filling fingerprint + default label.
pub fn authorized_key_from_line(pubkey_line: &str) -> Result<AuthorizedKey> {
    let pubkey = crypto::parse_pubkey_line(pubkey_line)?;
    authorized_key_from_pubkey(&pubkey)
}

/// Build an `AuthorizedKey` from a parsed `PublicKey`, deriving the
/// fingerprint and using the key comment (if any non-empty) as the label.
pub fn authorized_key_from_pubkey(pubkey: &PublicKey) -> Result<AuthorizedKey> {
    let fingerprint = crypto::pubkey_fingerprint(pubkey);
    let public_key = crypto::pubkey_to_line(pubkey)?;
    let comment = pubkey.comment().trim();
    let label = if comment.is_empty() {
        fingerprint.clone()
    } else {
        comment.to_string()
    };
    Ok(AuthorizedKey {
        fingerprint,
        public_key,
        label,
        added_at: crate::util::now_iso(),
    })
}

/// Resolve a recipient spec given on the command line.
///
/// Accepts either an `@file` reference (reads the first non-empty line of the
/// file) or a literal authorized-keys line / the basename of an ssh public-key
/// file path.
pub fn resolve_pubkey_spec(spec: &str) -> Result<String> {
    if let Some(path) = spec.strip_prefix('@') {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read public-key file {}", path))?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .context("public-key file is empty")?;
        return Ok(line.to_string());
    }
    // If the spec looks like an existing path to a *.pub file, read it.
    let p = std::path::Path::new(spec);
    if p.is_file() {
        let text = std::fs::read_to_string(p)
            .with_context(|| format!("failed to read public-key file {}", spec))?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .context("public-key file is empty")?;
        return Ok(line.to_string());
    }
    Ok(spec.to_string())
}

/// Validate a label/name used for filesystem paths (e.g. backup filenames).
/// Strict: lowercase alphanumeric, digits, `-`, `_`; must start with alnum;
/// 1–63 chars. Rejects `.`, `..`, `/`, `\`, uppercase, spaces. This is the
/// only defense against path traversal in backup naming.
pub fn validate_label(label: &str) -> Result<()> {
    if label.is_empty() {
        bail!("label is empty");
    }
    if label.len() > 63 {
        bail!(
            "label too long ({} chars, max 63): {:?}",
            label.len(),
            label
        );
    }
    let first = label.as_bytes()[0];
    if !first.is_ascii_alphanumeric() {
        bail!(
            "label must start with alphanumeric, got {:?}",
            first as char
        );
    }
    for c in label.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            bail!(
                "label contains invalid character {:?} (only a-z, 0-9, -, _ allowed)",
                c
            );
        }
    }
    Ok(())
}

/// Write `data` to `dest` atomically via a temp file + rename.
pub fn write_atomic(dest: &Path, data: &[u8]) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_pubkey() -> PublicKey {
        let sk = ssh_key::PrivateKey::random(&mut rand::thread_rng(), ssh_key::Algorithm::Ed25519)
            .unwrap();
        sk.public_key().clone()
    }

    #[test]
    fn add_and_find() {
        let now = "2026-01-01T00:00:00Z";
        let k = gen_pubkey();
        let ak = authorized_key_from_pubkey(&k).unwrap();
        let fp = ak.fingerprint.clone();
        let mut vk = VaultKeys::new(ak, now);
        assert_eq!(vk.len(), 1);
        assert!(vk.find(&fp).is_some());

        let k2 = gen_pubkey();
        let ak2 = authorized_key_from_pubkey(&k2).unwrap();
        let added = vk.add(ak2, now);
        assert!(added);
        assert_eq!(vk.len(), 2);
    }

    #[test]
    fn add_duplicate_fingerprint_rejected() {
        let now = "2026-01-01T00:00:00Z";
        let k = gen_pubkey();
        let ak = authorized_key_from_pubkey(&k).unwrap();
        let mut vk = VaultKeys::new(ak.clone(), now);
        // Same fingerprint again.
        assert!(!vk.add(ak, now));
        assert_eq!(vk.len(), 1);
    }

    #[test]
    fn remove_by_fingerprint_or_label() {
        let now = "2026-01-01T00:00:00Z";
        let k = gen_pubkey();
        let ak = authorized_key_from_pubkey(&k).unwrap();
        let fp = ak.fingerprint.clone();
        let mut vk = VaultKeys::new(ak, now);

        // Remove by fingerprint.
        let removed = vk.remove(&fp, now);
        assert!(removed.is_some());
        assert!(vk.is_empty());

        // Re-add and remove by label.
        let ak2 = authorized_key_from_pubkey(&gen_pubkey()).unwrap();
        let label2 = ak2.label.clone();
        vk.add(ak2, now);
        assert!(vk.remove(&label2, now).is_some());
        assert!(vk.is_empty());
    }

    #[test]
    fn label_validation() {
        assert!(validate_label("good-ns").is_ok());
        assert!(validate_label("../escape").is_err());
        assert!(validate_label("a/b").is_err());
        assert!(validate_label("").is_err());
        assert!(validate_label("BAD UPPER").is_err());
    }

    #[test]
    fn keys_roundtrip_json() {
        let now = "2026-01-01T00:00:00Z";
        let mut vk = VaultKeys::empty(now);
        vk.add(authorized_key_from_pubkey(&gen_pubkey()).unwrap(), now);
        vk.add(authorized_key_from_pubkey(&gen_pubkey()).unwrap(), now);
        let json = serde_json::to_string_pretty(&vk).unwrap();
        let back: VaultKeys = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.version, 1);
    }

    #[test]
    fn load_keys_rejects_corrupt_public_key() {
        // Simulate a .vault.keys whose public_key got mangled (e.g. a bad
        // git merge). load_keys must fail fast with a clear error pointing
        // at the offending entry.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".vault.keys");
        let bad = serde_json::json!({
            "version": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "keys": [{
                "fingerprint": "SHA256:fake",
                "public_key": "this-is-not-a-valid-key",
                "label": "broken",
                "added_at": "2026-01-01T00:00:00Z"
            }]
        });
        std::fs::write(&path, serde_json::to_string_pretty(&bad).unwrap()).unwrap();
        let err = load_keys(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid public_key") || msg.contains("entry #1"),
            "should flag the bad entry, got: {msg}"
        );
    }

    #[test]
    fn load_keys_rejects_empty_registry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".vault.keys");
        let empty = serde_json::json!({
            "version": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "keys": []
        });
        std::fs::write(&path, serde_json::to_string_pretty(&empty).unwrap()).unwrap();
        assert!(load_keys(&path).is_err());
    }
}
