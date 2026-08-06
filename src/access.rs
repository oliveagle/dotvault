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

// Re-export the read-only token type + helpers here so existing callers can
// keep using `access::AuthorizedToken` / `access::authorized_token`; the
// definitions + logic live in `access_token`.
pub use crate::access_token::{authorized_token, AuthorizedToken};

/// The full authorized-key registry, serialized to `.vault.keys`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultKeys {
    /// Format version, currently 1.
    pub version: u8,
    /// ISO-8601 timestamp of initial creation.
    pub created_at: String,
    /// ISO-8601 timestamp of the last modification.
    pub updated_at: String,
    /// Authorized SSH-key recipients. Order is insertion order.
    pub keys: Vec<AuthorizedKey>,
    /// Read-only X25519 tokens (`age1...` public keys). The matching secret
    /// is never stored. `#[serde(default)]` keeps older `.vault.keys` files
    /// (created before tokens existed) loadable as an empty token list.
    #[serde(default)]
    pub tokens: Vec<AuthorizedToken>,
}

impl VaultKeys {
    /// Build a new registry seeded with a single initial recipient.
    pub fn new(initial: AuthorizedKey, now: &str) -> Self {
        Self {
            version: 1,
            created_at: now.to_string(),
            updated_at: now.to_string(),
            keys: vec![initial],
            tokens: Vec::new(),
        }
    }

    /// Build an empty registry (version/timestamps only).
    pub fn empty(now: &str) -> Self {
        Self {
            version: 1,
            created_at: now.to_string(),
            updated_at: now.to_string(),
            keys: Vec::new(),
            tokens: Vec::new(),
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

    /// Number of authorized SSH-key recipients.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the registry has no SSH-key recipients.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    // Token methods (find/add/remove_token, token_count, token_pubkeys) live
    // in `access_token.rs` (extension impl) to keep this file ≤500 lines.
}

/// Strip JSON5-style leading `//` line comments so `load_keys` can parse a
/// `.vault.keys` (which starts with an agent-guidance comment) with strict
/// serde_json. Only full-line comments are stripped — `//` inside a JSON
/// string value is preserved (those lines don't start with `//`).
fn strip_line_comments(text: &str) -> String {
    text.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Load and parse a `.vault.keys` file from `path`. Validates that every
/// `public_key` entry is parseable, so a corrupted/merged registry fails fast
/// with a clear error rather than a cryptic failure at encryption time.
pub fn load_keys(path: &Path) -> Result<VaultKeys> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    // Tolerate the leading `//` agent-guidance comment (see save_keys).
    let body = strip_line_comments(&text);
    let keys: VaultKeys = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))?;
    if keys.keys.is_empty() {
        bail!(
            "{} has no authorized keys — the vault would be unrecoverable",
            path.display()
        );
    }
    // Validate each pubkey parses (fail fast here, not deep in encryption).
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
    // Same for token pubkeys (must parse as age1... recipients).
    for (i, t) in keys.tokens.iter().enumerate() {
        crypto::parse_token_pubkey(&t.public_key).map_err(|e| {
            anyhow::anyhow!(
                "{} token #{} (label {}) has an invalid public_key: {e}",
                path.display(),
                i + 1,
                t.label
            )
        })?;
    }
    Ok(keys)
}

/// The agent-guidance header prepended to every `.vault.keys`. JSON5-style
/// `//` comments (stripped by `strip_line_comments` before serde_json). Replaces
/// the old standalone `.vault.keys.AGENTS.md`.
const KEYS_HEADER: &str = "\
// This project uses dotvault for encrypted secrets (.vault). This file lists
// who can decrypt it (SSH keys + read-only tokens). Run `dotvault --help` for
// the command reference — never hardcode secrets. Fetch: dotvault get <NAME>
";

/// Serialize and atomically write a `VaultKeys` registry to `path`, with the
/// agent-guidance header prepended.
pub fn save_keys(path: &Path, keys: &VaultKeys) -> Result<()> {
    let json = serde_json::to_string_pretty(keys)
        .map_err(|e| anyhow::anyhow!("failed to serialize {}: {e}", path.display()))?;
    let body = format!("{KEYS_HEADER}{json}");
    crate::util::write_atomic(path, body.as_bytes())
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

    // ---------- token (X25519) registry: load_keys behavior ----------
    // (The token CRUD methods themselves are unit-tested in `access_token.rs`.)

    #[test]
    fn serde_defaults_missing_tokens_to_empty() {
        // A .vault.keys written by an older dotvault (no `tokens` field) must
        // still load, with tokens defaulting to empty.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".vault.keys");
        let k = gen_pubkey();
        let ak = authorized_key_from_pubkey(&k).unwrap();
        let legacy = serde_json::json!({
            "version": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "keys": [ak]
        });
        std::fs::write(&path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();
        let vk = load_keys(&path).unwrap();
        assert!(
            vk.tokens.is_empty(),
            "legacy file should yield empty tokens"
        );
        assert_eq!(vk.token_count(), 0);
    }

    #[test]
    fn load_keys_rejects_corrupt_token_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".vault.keys");
        let k = gen_pubkey();
        let ak = authorized_key_from_pubkey(&k).unwrap();
        let bad = serde_json::json!({
            "version": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "keys": [ak],
            "tokens": [{
                "public_key": "not-an-age-key",
                "label": "broken",
                "added_at": "2026-01-01T00:00:00Z"
            }]
        });
        std::fs::write(&path, serde_json::to_string_pretty(&bad).unwrap()).unwrap();
        let err = load_keys(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("token #1") && msg.contains("broken"),
            "should flag the bad token, got: {msg}"
        );
    }

    #[test]
    fn keys_roundtrip_with_comment_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".vault.keys");
        let mut vk = VaultKeys::empty("2026-01-01T00:00:00Z");
        vk.add(
            authorized_key_from_pubkey(&gen_pubkey()).unwrap(),
            "2026-01-01T00:00:00Z",
        );
        save_keys(&path, &vk).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.starts_with("//"),
            "saved file should start with // header"
        );
        assert_eq!(load_keys(&path).unwrap().len(), 1);

        // strip_line_comments must drop full-line // comments but preserve //
        // inside JSON string values (such lines don't start with //).
        let mixed = "// header\n{\n  \"x\": \"// in-string, kept\"\n}\n// trailing\n";
        let stripped = strip_line_comments(mixed);
        assert!(!stripped.contains("header") && !stripped.contains("trailing"));
        assert!(stripped.contains("\"// in-string, kept\""));
    }
}
