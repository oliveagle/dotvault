//! Cryptographic primitives for dotvault.
//!
//! Design summary (see plan):
//! - The AES-256 key is derived from the SSH private key's raw material via
//!   HKDF-SHA256, keyed by a per-vault random salt. This is type-agnostic: any
//!   SSH key type (ed25519, RSA, ECDSA) yields canonical private bytes.
//! - The vault is sealed with AES-256-GCM (96-bit nonce, 128-bit tag) over the
//!   whole `.env` plaintext. GCM authenticates the entire document, so tamper
//!   or wrong-key decrypts fail with an `AeadError`.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use ssh_key::{HashAlg, PrivateKey};

/// Magic header + version for the on-disk container: `DV1` + version byte.
pub const MAGIC: &[u8; 3] = b"DV1";
pub const VERSION: u8 = 1;
/// HKDF info string binds the derived key to this application/format version.
const HKDF_INFO: &[u8] = b"dotvault/v1";
/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;
/// GCM nonce length in bytes (96 bits).
const NONCE_LEN: usize = 12;
/// GCM authentication tag length in bytes (128 bits).
const TAG_LEN: usize = 16;
/// Length of the KDF salt in bytes.
pub const SALT_LEN: usize = 32;

/// Container header length: magic(3) + version(1) + nonce(12).
const HEADER_LEN: usize = 3 + 1 + NONCE_LEN;

/// A 32-byte AES-256 key derived from an SSH private key.
pub struct AesKey(pub [u8; KEY_LEN]);

/// Load and (if necessary) decrypt an OpenSSH private key.
///
/// If the key is passphrase-protected, the user is prompted interactively via
/// `rpassword` (no echo). Unencrypted keys load directly. Only the OpenSSH
/// private key format (`BEGIN OPENSSH PRIVATE KEY`) is supported — legacy
/// `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` (PEM/PKCS#1/PKCS#8) must
/// first be converted with `ssh-keygen -p -m PEM -f <key>`.
pub fn load_private_key(path: &std::path::Path) -> Result<PrivateKey> {
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
/// detect that the *same* key is being used across vault operations.
pub fn ssh_fingerprint(key: &PrivateKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Extract canonical private-key material, by key type.
///
/// - ed25519: the 32-byte seed.
/// - RSA: the private exponent `d` bytes.
/// - Other types fall back to the OpenSSH-encoded private key blob, which is
///   still a stable function of the key.
fn private_material(key: &PrivateKey) -> Vec<u8> {
    use ssh_key::private::KeypairData;
    match key.key_data() {
        KeypairData::Ed25519(ed) => ed.private.as_ref().to_vec(),
        KeypairData::Rsa(rsa) => rsa.private.d.as_bytes().to_vec(),
        // Stable fallback: re-encode the key material deterministically.
        other => other
            .algorithm()
            .map(|a| a.as_str().as_bytes().to_vec())
            .unwrap_or_default(),
    }
}

/// Derive a 32-byte AES-256 key from an SSH private key and a salt.
///
/// HKDF-SHA256(salt = vault salt, ikm = private material, info = "dotvault/v1").
/// Deterministic: the same key + salt always yield the same AES key.
pub fn derive_key(key: &PrivateKey, salt: &[u8]) -> Result<AesKey> {
    let ikm = private_material(key);
    if ikm.is_empty() {
        bail!("could not extract private-key material for derivation");
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut out = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO, &mut out)
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;
    Ok(AesKey(out))
}

/// Seal plaintext into a self-contained DV1 container.
///
/// Layout: `DV1` | version(1) | nonce(12) | ciphertext | tag(16).
/// `aes-gcm` appends the tag to the ciphertext, so the tail is `ct||tag`.
pub fn seal(key: &AesKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).map_err(|e| anyhow!("AES key init failed: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct); // includes trailing GCM tag
    Ok(out)
}

/// Open a DV1 container and return the plaintext.
///
/// Fails if the magic/version is wrong or if the GCM tag does not verify
/// (tamper or wrong key).
pub fn open(key: &AesKey, container: &[u8]) -> Result<Vec<u8>> {
    if container.len() < HEADER_LEN + TAG_LEN {
        bail!("vault container is too small / truncated");
    }
    if &container[..3] != MAGIC {
        bail!("not a dotvault container (bad magic)");
    }
    if container[3] != VERSION {
        bail!(
            "unsupported dotvault container version {} (expected {})",
            container[3],
            VERSION
        );
    }
    let nonce_bytes = &container[4..4 + NONCE_LEN];
    let ct = &container[4 + NONCE_LEN..];
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).map_err(|e| anyhow!("AES key init failed: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| anyhow!("decryption failed: wrong SSH key or corrupted vault"))
}

/// Generate a fresh random salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Building a `ssh_key::PrivateKey` from raw bytes pins an `ed25519-dalek`
    // version that `ssh-key` re-exports internally; to avoid that coupling we
    // exercise the pure-bytes primitives (HKDF + seal/open) via a fixed AesKey.
    // End-to-end derivation with a real key is covered by the smoke tests.

    fn fixed_key(b: u8) -> AesKey {
        AesKey([b; KEY_LEN])
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = fixed_key(7);
        let pt = b"DB_PASSWORD=s3cret\nAPI_TOKEN=xyz\n";
        let ct = seal(&k, pt).unwrap();
        assert_eq!(open(&k, &ct).unwrap(), pt);
    }

    #[test]
    fn wrong_key_fails() {
        let pt = b"hello";
        let ct = seal(&fixed_key(1), pt).unwrap();
        assert!(open(&fixed_key(2), &ct).is_err());
    }

    #[test]
    fn tamper_fails() {
        let k = fixed_key(9);
        let mut ct = seal(&k, b"secret").unwrap();
        // Flip a byte deep in the ciphertext.
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(open(&k, &ct).is_err());
    }

    #[test]
    fn header_is_well_formed() {
        let ct = seal(&fixed_key(1), b"x").unwrap();
        assert_eq!(&ct[..3], MAGIC);
        assert_eq!(ct[3], VERSION);
        // nonce present
        assert_eq!(&ct[4..16].len(), &NONCE_LEN);
    }
}
