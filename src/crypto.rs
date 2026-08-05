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

use age::x25519::{Identity as X25519Identity, Recipient as X25519Recipient};

use age::secrecy::ExposeSecret;

/// Encrypt `plaintext` to ALL of the given SSH public keys (one OpenSSH
/// authorized-keys line each, e.g. `ssh-ed25519 AAAA... comment`). Any one of
/// the corresponding private keys will be able to decrypt the result.
///
/// Returns a binary age file (per the age v1 spec). Commits cleanly to git.
pub fn encrypt_to_recipients(pubkey_lines: &[String], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_to_recipients_with_tokens(pubkey_lines, &[], plaintext)
}

/// Encrypt `plaintext` to every SSH public key AND every X25519 token public
/// key (`age1...`). age's multi-recipient model treats X25519 and SSH
/// recipients uniformly — both are standard recipients with arbitrary-string
/// labels, so they can coexist in a single container (unlike scrypt, which
/// age forbids mixing). Any single recipient's private half decrypts.
///
/// `token_pubkeys` are `age1...` strings produced by `generate_token_keypair`.
pub fn encrypt_to_recipients_with_tokens(
    ssh_pubkey_lines: &[String],
    token_pubkeys: &[String],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if ssh_pubkey_lines.is_empty() && token_pubkeys.is_empty() {
        bail!("cannot encrypt: no recipients (the vault would be unrecoverable)");
    }

    // Build a heterogeneous recipient list: SSH recipients + X25519 recipients.
    let ssh_recipients: Vec<age::ssh::Recipient> = ssh_pubkey_lines
        .iter()
        .map(|line| {
            line.parse::<age::ssh::Recipient>()
                .map_err(|e| anyhow!("invalid SSH public key {:?}: {e:?}", line))
        })
        .collect::<Result<_>>()?;
    let token_recipients: Vec<X25519Recipient> = token_pubkeys
        .iter()
        .map(|pk| {
            pk.parse::<X25519Recipient>()
                .map_err(|e| anyhow!("invalid token public key {:?}: {e}", pk))
        })
        .collect::<Result<_>>()?;

    let mut recipients: Vec<&dyn age::Recipient> =
        Vec::with_capacity(ssh_recipients.len() + token_recipients.len());
    for r in &ssh_recipients {
        recipients.push(r);
    }
    for r in &token_recipients {
        recipients.push(r);
    }

    let encryptor = Encryptor::with_recipients(recipients.into_iter())
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

/// Decrypt an age container using a read-only X25519 token
/// (`AGE-SECRET-KEY-1...`). The token must correspond to one of the
/// `age1...` recipients the container was encrypted to.
pub fn decrypt_with_token(token: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let identity = token
        .parse::<X25519Identity>()
        .map_err(|e| anyhow!("invalid token (must be AGE-SECRET-KEY-1...): {e}"))?;
    let cursor = std::io::Cursor::new(ciphertext.to_vec());
    let decryptor =
        Decryptor::new_buffered(cursor).map_err(|e| anyhow!("not an age container: {e}"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow!("decryption failed: no matching key (or corrupted vault): {e}"))?;
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| anyhow!("age read failed: {e}"))?;
    Ok(out)
}

/// Generate a fresh read-only token keypair.
///
/// Returns `(secret, pubkey)` where `secret` is the `AGE-SECRET-KEY-1...`
/// string (the token the user puts in CI) and `pubkey` is the `age1...`
/// recipient string (stored in `.vault.keys`).
pub fn generate_token_keypair() -> (String, String) {
    let identity = X25519Identity::generate();
    let secret = identity.to_string().expose_secret().to_string();
    let pubkey = identity.to_public().to_string();
    (secret, pubkey)
}

/// Validate that `s` is a well-formed `age1...` token public key. Returns the
/// parsed recipient on success (callers usually just want the `Result<()>`).
pub fn parse_token_pubkey(s: &str) -> Result<X25519Recipient> {
    s.parse::<X25519Recipient>()
        .map_err(|e| anyhow!("invalid token public key {:?}: {e}", s))
}

/// Validate that `s` is a well-formed `AGE-SECRET-KEY-1...` token secret.
pub fn parse_token_secret(s: &str) -> Result<X25519Identity> {
    s.parse::<X25519Identity>()
        .map_err(|e| anyhow!("invalid token secret {:?}: {e}", s))
}

// Re-export so other modules can name the type without reaching into age.
pub use age::x25519::Recipient as X25519PubKey;

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

    // ---------- X25519 token recipient tests ----------

    #[test]
    fn generate_token_keypair_format() {
        let (secret, pubkey) = generate_token_keypair();
        assert!(
            secret.starts_with("AGE-SECRET-KEY-1"),
            "token secret must be AGE-SECRET-KEY-1..., got: {secret}"
        );
        assert!(
            pubkey.starts_with("age1"),
            "pubkey must be age1..., got: {pubkey}"
        );
        // Round-trip parse.
        assert!(parse_token_secret(&secret).is_ok());
        assert!(parse_token_pubkey(&pubkey).is_ok());
    }

    #[test]
    fn token_secret_derives_pubkey() {
        // The secret's public half must equal the pubkey we hand the caller.
        let (secret, pubkey) = generate_token_keypair();
        let id = parse_token_secret(&secret).unwrap();
        assert_eq!(id.to_public().to_string(), pubkey);
    }

    #[test]
    fn ssh_and_token_mix_in_one_container() {
        // The core age capability dotvault relies on: a single container
        // encrypted to BOTH an SSH key AND an X25519 token, decryptable by
        // either. (scrypt cannot do this; X25519 can.)
        let k = gen_privkey();
        let ssh_pub = pubkey_to_line(&k.public_key().clone()).unwrap();
        let (_tok_secret, tok_pub) = generate_token_keypair();
        let pt = b"DB_PASSWORD=s3cret\n";

        let ct = encrypt_to_recipients_with_tokens(&[ssh_pub], &[tok_pub], pt).unwrap();
        // SSH key decrypts.
        assert_eq!(decrypt_with_key(&k, &ct).unwrap(), pt);
        // ... and so does the token.
        assert_eq!(decrypt_with_token(&_tok_secret, &ct).unwrap(), pt);
    }

    #[test]
    fn token_only_container_decrypts_with_token() {
        // A container with ONLY a token recipient (no SSH keys): the token
        // decrypts, an unrelated SSH key cannot.
        let (_tok_secret, tok_pub) = generate_token_keypair();
        let pt = b"secret";
        let ct = encrypt_to_recipients_with_tokens(&[], &[tok_pub], pt).unwrap();
        assert_eq!(decrypt_with_token(&_tok_secret, &ct).unwrap(), pt);
        // An unrelated SSH key cannot.
        let other = gen_privkey();
        assert!(decrypt_with_key(&other, &ct).is_err());
    }

    #[test]
    fn unauthorized_token_cannot_decrypt() {
        // Encrypt to an SSH key + token A; token B (not a recipient) fails.
        let k = gen_privkey();
        let ssh_pub = pubkey_to_line(&k.public_key().clone()).unwrap();
        let (_tok_a, tok_pub_a) = generate_token_keypair();
        let (tok_b, _tok_pub_b) = generate_token_keypair();
        let ct = encrypt_to_recipients_with_tokens(&[ssh_pub], &[tok_pub_a], b"x").unwrap();
        assert!(decrypt_with_token(&tok_b, &ct).is_err());
    }

    #[test]
    fn no_recipients_at_all_errors() {
        assert!(encrypt_to_recipients_with_tokens(&[], &[], b"x").is_err());
    }

    #[test]
    fn invalid_token_strings_rejected() {
        assert!(parse_token_secret("not-a-token").is_err());
        assert!(parse_token_pubkey("not-a-pubkey").is_err());
        // An SSH pubkey line is not an age1 token pubkey.
        assert!(parse_token_pubkey("ssh-ed25519 AAAA").is_err());
    }
}
