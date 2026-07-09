//! Cryptographic primitives for dotvault.
//!
//! Design summary (v0.4, multi-recipient):
//! - The `.vault` file is an **age** container encrypted to the SSH public
//!   keys of every authorized recipient. age generates a random file key per
//!   encryption and writes one recipient stanza (key slot) per public key.
//! - Decryption tries the supplied SSH private key (`age::ssh::Identity`)
//!   against the stanzas; any single matching key unwraps the file key.
//! - SSH keys are parsed by the `ssh-key` crate. Passphrase-protected keys
//!   are prompted for interactively via `rpassword`.
//!
//! The authorized public-key list itself lives in `.vault.keys` (JSON) and is
//! the source of truth for who can decrypt — age stanzas only carry short key
//! IDs, insufficient for audit. See `access::VaultKeys`.

use std::io::{Read, Write};
use std::path::Path;

use age::{Decryptor, Encryptor};
use anyhow::{anyhow, bail, Context, Result};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};

/// Encrypt `plaintext` to ALL of the given SSH public keys (one OpenSSH
/// authorized-keys line each, e.g. `ssh-ed25519 AAAA... comment`). Any one of
/// the corresponding private keys will be able to decrypt the result.
///
/// Returns a binary age file (per the age v1 spec). Commits cleanly to git.
pub fn encrypt_to_recipients(pubkey_lines: &[String], plaintext: &[u8]) -> Result<Vec<u8>> {
    if pubkey_lines.is_empty() {
        bail!("cannot encrypt: no recipients (the vault would be unrecoverable)");
    }
    let recipients: Vec<age::ssh::Recipient> = pubkey_lines
        .iter()
        .map(|line| {
            line.parse::<age::ssh::Recipient>()
                .map_err(|e| anyhow!("invalid SSH public key {:?}: {e:?}", line))
        })
        .collect::<Result<_>>()?;
    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
        .map_err(|e| anyhow!("age encryptor setup failed: {e}"))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| anyhow!("age wrap_output failed: {e}"))?;
    writer
        .write_all(plaintext)
        .map_err(|e| anyhow!("age write failed: {e}"))?;
    writer
        .finish()
        .map_err(|e| anyhow!("age finish failed: {e}"))?;
    Ok(out)
}

/// Decrypt an age container using the SSH private key at `privkey_path`.
///
/// Loads the private key (prompting for a passphrase if encrypted), exports
/// it to OpenSSH text, and feeds it to age as an `ssh::Identity`. Returns the
/// plaintext on success.
pub fn decrypt_with_identity(privkey_path: &Path, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let private_key = load_private_key(privkey_path)?;
    decrypt_with_key(&private_key, ciphertext)
}

/// Decrypt an age container using an already-loaded SSH private key.
pub fn decrypt_with_key(private_key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let openssh_text = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow!("failed to encode SSH key to OpenSSH: {e}"))?;
    let cursor = std::io::Cursor::new(ciphertext.to_vec());
    let decryptor =
        Decryptor::new_buffered(cursor).map_err(|e| anyhow!("not an age container: {e}"))?;
    let identity = age::ssh::Identity::from_buffer(
        std::io::Cursor::new(openssh_text.as_bytes().to_vec()),
        Some(privkey_label(private_key)),
    )
    .map_err(|e| anyhow!("failed to parse SSH key for age: {e}"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow!("decryption failed: no matching key (or corrupted vault): {e}"))?;
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| anyhow!("age read failed: {e}"))?;
    Ok(out)
}

/// Load and (if necessary) decrypt an OpenSSH private key.
///
/// If the key is passphrase-protected, the user is prompted interactively via
/// `rpassword` (no echo). Unencrypted keys load directly. Only the OpenSSH
/// private key format (`BEGIN OPENSSH PRIVATE KEY`) is supported — legacy
/// `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` (PEM/PKCS#1/PKCS#8) must
/// first be converted with `ssh-keygen -p -m PEM -f <key>`.
pub fn load_private_key(path: &Path) -> Result<PrivateKey> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read SSH key at {}", path.display()))?;

    // Give a clear error for legacy PEM formats the ssh-key crate can't parse.
    let trimmed = pem.trim_start();
    if trimmed.starts_with("-----BEGIN ")
        && !trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    {
        bail!(
            "key {} is in a legacy PEM format ({}). dotvault only supports the \
             OpenSSH format. Convert it with:\n  ssh-keygen -p -m PEM -f {}",
            path.display(),
            pem.lines().next().unwrap_or("(unknown)"),
            path.display()
        );
    }

    let first = PrivateKey::from_openssh(&pem)
        .map_err(|e| anyhow!("failed to parse SSH key at {}: {e}", path.display()))?;
    // `cipher()` reports "none" for unencrypted keys.
    if first.cipher().as_str() == "none" {
        return Ok(first);
    }
    // Encrypted key: prompt for passphrase and re-parse with it.
    let prompt = format!("Enter passphrase for key {}: ", path.display());
    let passphrase = rpassword::prompt_password(prompt).map_err(|e| {
        anyhow!(
            "failed to read passphrase (key {}): {e}\nhint: a passphrase-protected \
             key requires an interactive terminal (TTY)",
            path.display()
        )
    })?;
    // `decrypt` takes `impl AsRef<[u8]>`; no separate Password type needed.
    let decrypted = first
        .decrypt(passphrase.as_bytes())
        .map_err(|e| anyhow!("failed to decrypt SSH key (wrong passphrase?): {e}"))?;
    Ok(decrypted)
}

/// SHA-256 fingerprint of a key, in OpenSSH `SHA256:base64` form. Used to
/// identify recipients in `.vault.keys` and diagnostics.
pub fn ssh_fingerprint(key: &PrivateKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Fingerprint of a public key (same format as `ssh_fingerprint` for a
/// private key). Works on standalone public keys parsed from authorized-keys
/// lines or `~/.ssh/*.pub`.
pub fn pubkey_fingerprint(pubkey: &PublicKey) -> String {
    pubkey.fingerprint(HashAlg::Sha256).to_string()
}

/// Parse an OpenSSH authorized-keys line (e.g.
/// `ssh-ed25519 AAAA... comment`) into a `PublicKey`.
pub fn parse_pubkey_line(line: &str) -> Result<PublicKey> {
    PublicKey::from_openssh(line.trim())
        .map_err(|e| anyhow!("failed to parse SSH public key {:?}: {e}", line))
}

/// Render a `PublicKey` back to its canonical authorized-keys line.
pub fn pubkey_to_line(pubkey: &PublicKey) -> Result<String> {
    Ok(pubkey.to_openssh()?.to_string())
}

fn privkey_label(key: &PrivateKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_privkey() -> PrivateKey {
        PrivateKey::random(&mut rand::thread_rng(), ssh_key::Algorithm::Ed25519)
            .expect("generate key")
    }

    #[test]
    fn multi_recipient_roundtrip() {
        // Encrypt to two keys; either can decrypt.
        let alice = gen_privkey();
        let bob = gen_privkey();
        let a_pub = pubkey_to_line(&alice.public_key().clone()).unwrap();
        let b_pub = pubkey_to_line(&bob.public_key().clone()).unwrap();
        let pt = b"DB_PASSWORD=s3cret\nAPI_TOKEN=xyz\n";

        let ct = encrypt_to_recipients(&[a_pub, b_pub], pt).unwrap();
        assert_eq!(decrypt_with_key(&alice, &ct).unwrap(), pt);
        assert_eq!(decrypt_with_key(&bob, &ct).unwrap(), pt);
    }

    #[test]
    fn unauthorized_key_cannot_decrypt() {
        let alice = gen_privkey();
        let eve = gen_privkey();
        let a_pub = pubkey_to_line(&alice.public_key().clone()).unwrap();
        let ct = encrypt_to_recipients(&[a_pub], b"secret").unwrap();
        assert!(decrypt_with_key(&eve, &ct).is_err());
    }

    #[test]
    fn no_recipients_errors() {
        assert!(encrypt_to_recipients(&[], b"x").is_err());
    }

    #[test]
    fn single_recipient_roundtrip() {
        let k = gen_privkey();
        let pub_line = pubkey_to_line(&k.public_key().clone()).unwrap();
        let pt = b"hello";
        let ct = encrypt_to_recipients(&[pub_line], pt).unwrap();
        assert_eq!(decrypt_with_key(&k, &ct).unwrap(), pt);
    }

    #[test]
    fn fingerprint_stable_for_same_key() {
        let k = gen_privkey();
        assert_eq!(ssh_fingerprint(&k), ssh_fingerprint(&k));
    }
}
