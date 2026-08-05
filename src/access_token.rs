//! Read-only token (`age1...` X25519 recipient) support, split out of
//! `access.rs` for file-size hygiene.
//!
//! A token is an age X25519 keypair: the public key (`age1...`) is stored in
//! `.vault.keys` as an extra recipient, and the secret (`AGE-SECRET-KEY-1...`)
//! is shown to the user ONCE at `add-token` time and never stored. The
//! `AuthorizedToken` type and the token-handling methods on `VaultKeys` live
//! here; the `tokens` field itself stays on the `VaultKeys` struct in
//! `access.rs` (Rust allows an extension `impl` in a sibling module).

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::access::VaultKeys;
use crate::crypto;

/// One read-only token: an age X25519 public key (`age1...`) that can decrypt
/// the vault. The corresponding secret (`AGE-SECRET-KEY-1...`) is shown to the
/// user ONCE at `add-token` time and is NOT stored anywhere — only this public
/// half lives in `.vault.keys`. A token grants full read of all secrets; write
/// commands are rejected at runtime when authenticating with `--token`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedToken {
    /// The `age1...` X25519 public-key string. Also serves as the unique id.
    pub public_key: String,
    /// Human-readable label (e.g. "ci-deploy", "staging-runner").
    pub label: String,
    /// ISO-8601 timestamp when this token was added.
    pub added_at: String,
}

/// Token-handling methods on `VaultKeys`, as an extension impl. The `tokens`
/// field lives on the struct in `access.rs`; the logic lives here so each file
/// stays under the 500-line guideline.
impl VaultKeys {
    /// Return the token public keys (`age1...`) for encryption. These are
    /// mixed into the age recipient set alongside the SSH keys.
    pub fn token_pubkeys(&self) -> Vec<String> {
        self.tokens.iter().map(|t| t.public_key.clone()).collect()
    }

    /// Find a token by label (case-insensitive) or public key (exact).
    pub fn find_token(&self, query: &str) -> Option<&AuthorizedToken> {
        self.tokens
            .iter()
            .find(|t| t.label.eq_ignore_ascii_case(query) || t.public_key == query)
    }

    /// Append a new read-only token. Returns `false` if a token with the same
    /// label or public key already exists.
    pub fn add_token(&mut self, token: AuthorizedToken, now: &str) -> bool {
        if self
            .tokens
            .iter()
            .any(|t| t.label.eq_ignore_ascii_case(&token.label) || t.public_key == token.public_key)
        {
            return false;
        }
        self.tokens.push(token);
        self.updated_at = now.to_string();
        true
    }

    /// Remove the token matching `query` (label or public key). Returns the
    /// removed token, or `None` if no match.
    pub fn remove_token(&mut self, query: &str, now: &str) -> Option<AuthorizedToken> {
        let idx = self
            .tokens
            .iter()
            .position(|t| t.label.eq_ignore_ascii_case(query) || t.public_key == query)?;
        let removed = self.tokens.remove(idx);
        self.updated_at = now.to_string();
        Some(removed)
    }

    /// Number of authorized tokens.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }
}

/// Build an `AuthorizedToken` from an `age1...` public-key string and a label.
/// Validates the public key parses. Does NOT set `added_at` (caller does, so a
/// single `now` timestamp is consistent across the registry update).
pub fn authorized_token(label: &str, pubkey: &str, now: &str) -> Result<AuthorizedToken> {
    crypto::parse_token_pubkey(pubkey)?;
    Ok(AuthorizedToken {
        public_key: pubkey.to_string(),
        label: label.to_string(),
        added_at: now.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{authorized_key_from_pubkey, VaultKeys};

    fn gen_pubkey() -> ssh_key::PublicKey {
        let sk = ssh_key::PrivateKey::random(&mut rand::thread_rng(), ssh_key::Algorithm::Ed25519)
            .unwrap();
        sk.public_key().clone()
    }

    fn gen_token_pubkey() -> String {
        let (_secret, pubkey) = crate::crypto::generate_token_keypair();
        pubkey
    }

    #[test]
    fn add_and_find_token() {
        let now = "2026-01-01T00:00:00Z";
        let mut vk = VaultKeys::new(authorized_key_from_pubkey(&gen_pubkey()).unwrap(), now);
        let t = authorized_token("ci-deploy", &gen_token_pubkey(), now).unwrap();
        assert!(vk.add_token(t, now));
        assert_eq!(vk.token_count(), 1);
        assert!(vk.find_token("ci-deploy").is_some());
        assert!(vk.find_token("CI-DEPLOY").is_some()); // case-insensitive label
    }

    #[test]
    fn add_token_rejects_duplicate_label_and_pubkey() {
        let now = "2026-01-01T00:00:00Z";
        let mut vk = VaultKeys::new(authorized_key_from_pubkey(&gen_pubkey()).unwrap(), now);
        let pubkey = gen_token_pubkey();
        assert!(vk.add_token(authorized_token("ci-deploy", &pubkey, now).unwrap(), now));
        // Same label, different key.
        assert!(!vk.add_token(
            authorized_token("ci-deploy", &gen_token_pubkey(), now).unwrap(),
            now
        ));
        // Same key, different label.
        assert!(!vk.add_token(authorized_token("other", &pubkey, now).unwrap(), now));
        assert_eq!(vk.token_count(), 1);
    }

    #[test]
    fn remove_token_by_label_or_pubkey() {
        let now = "2026-01-01T00:00:00Z";
        let mut vk = VaultKeys::new(authorized_key_from_pubkey(&gen_pubkey()).unwrap(), now);
        let pubkey = gen_token_pubkey();
        vk.add_token(authorized_token("ci-deploy", &pubkey, now).unwrap(), now);
        assert_eq!(vk.token_count(), 1);

        // Remove by pubkey.
        assert!(vk.remove_token(&pubkey, now).is_some());
        assert_eq!(vk.token_count(), 0);

        // Re-add, remove by label.
        vk.add_token(authorized_token("ci-deploy", &pubkey, now).unwrap(), now);
        assert!(vk.remove_token("ci-deploy", now).is_some());
        assert_eq!(vk.token_count(), 0);
    }

    #[test]
    fn token_pubkeys_returns_all_for_encryption() {
        let now = "2026-01-01T00:00:00Z";
        let mut vk = VaultKeys::new(authorized_key_from_pubkey(&gen_pubkey()).unwrap(), now);
        let p1 = gen_token_pubkey();
        let p2 = gen_token_pubkey();
        vk.add_token(authorized_token("a", &p1, now).unwrap(), now);
        vk.add_token(authorized_token("b", &p2, now).unwrap(), now);
        let pubkeys = vk.token_pubkeys();
        assert_eq!(pubkeys.len(), 2);
        assert!(pubkeys.contains(&p1));
        assert!(pubkeys.contains(&p2));
    }

    #[test]
    fn authorized_token_rejects_invalid_pubkey() {
        let now = "2026-01-01T00:00:00Z";
        assert!(authorized_token("x", "ssh-ed25519 AAAA", now).is_err());
    }
}
