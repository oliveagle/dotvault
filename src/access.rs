//! Per-project access keys: the `.dotvault_key` file that binds a project to a
//! namespace.
//!
//! Model (see plan): the SSH key decrypts every namespace's vault; the
//! access_key is a **namespace selector plus authorization token**. It is
//! stored in plaintext at the project root (`.dotvault_key`) AND, encrypted by
//! the SSH key, in the namespace's registry file. On each operation we read the
//! project file, then verify its access_key matches the registered (decrypted)
//! one — so a project can't impersonate another namespace by editing its file.
//!
//! `.dotvault_key` format (two plaintext lines):
//! ```text
//! <namespace-name>
//! <64 hex chars = 32 random bytes>
//! ```

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::RngCore;

/// 32-byte random access key (256 bits).
pub const ACCESS_KEY_LEN: usize = 32;

/// A namespace binding read from / written to a project's `.dotvault_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKey {
    pub namespace: String,
    pub key: [u8; ACCESS_KEY_LEN],
}

impl AccessKey {
    /// Generate a fresh random access key bound to `namespace`.
    /// `namespace` is validated first (see [`validate_namespace`]).
    pub fn generate(namespace: &str) -> Result<Self> {
        validate_namespace(namespace)?;
        let mut key = [0u8; ACCESS_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(Self {
            namespace: namespace.to_string(),
            key,
        })
    }

    /// Hex-encode the key bytes (lowercase, 64 chars).
    pub fn key_hex(&self) -> String {
        hex_encode(&self.key)
    }

    /// Default project path for the access-key file, relative to CWD.
    pub const PROJECT_FILE: &'static str = ".dotvault_key";
    /// Name of the global access-key file inside ~/.dotvault/.
    pub const GLOBAL_FILE: &'static str = "access_key";

    /// Resolve the project access-key file path:
    /// `DOTVAULT_KEY_FILE` env → `./.dotvault_key`.
    pub fn project_path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("DOTVAULT_KEY_FILE") {
            return Ok(PathBuf::from(p));
        }
        Ok(PathBuf::from(Self::PROJECT_FILE))
    }

    /// Resolve the global access-key file path (the `global` namespace):
    /// `DOTVAULT_GLOBAL_KEY_FILE` env → `~/.dotvault/access_key`.
    pub fn global_path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("DOTVAULT_GLOBAL_KEY_FILE") {
            return Ok(PathBuf::from(p));
        }
        Ok(crate::vault::dotvault_home()?.join(Self::GLOBAL_FILE))
    }

    /// Read and parse a `.dotvault_key` file.
    pub fn read_from_project(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read access key at {}", path.display()))?;
        Self::parse(&text)
    }

    /// Parse the two-line format. Trims whitespace; blank/comment lines ignored.
    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let namespace = lines
            .next()
            .context("access key file is empty (expected <namespace> on line 1)")?;
        let key_hex = lines
            .next()
            .context("access key file missing key (expected <hex> on line 2)")?;
        validate_namespace(namespace)?;
        let key = hex_decode(key_hex).context("access key is not valid hex")?;
        if key.len() != ACCESS_KEY_LEN {
            bail!(
                "access key must be {} bytes ({} hex chars), got {} bytes",
                ACCESS_KEY_LEN,
                ACCESS_KEY_LEN * 2,
                key.len()
            );
        }
        let mut arr = [0u8; ACCESS_KEY_LEN];
        arr.copy_from_slice(&key);
        Ok(Self {
            namespace: namespace.to_string(),
            key: arr,
        })
    }

    /// Write the access key to a project file (plaintext, two lines).
    pub fn write_to_project(&self, path: &Path) -> Result<()> {
        let content = format!("{}\n{}\n", self.namespace, self.key_hex());
        std::fs::write(path, content.as_bytes())
            .with_context(|| format!("failed to write access key to {}", path.display()))?;
        // Restrictive perms on Unix (it identifies the namespace).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Validate a namespace name. This is the **only** defense against path
/// traversal (namespace → directory under `~/.dotvault/namespaces/`), so it is
/// strict: lowercase alphanumeric, digits, `-`, `_`; must start with alnum;
/// 1–63 chars. Rejects `.`, `..`, `/`, `\`, uppercase, spaces.
pub fn validate_namespace(ns: &str) -> Result<()> {
    if ns.is_empty() {
        bail!("namespace name is empty");
    }
    if ns.len() > 63 {
        bail!("namespace name too long ({} > 63 chars)", ns.len());
    }
    let mut chars = ns.chars();
    let first = chars.next().expect("non-empty");
    // Lowercase-only: keeps names stable on case-insensitive filesystems and
    // matches DNS-style identifiers.
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        bail!(
            "namespace {:?} must start with a lowercase letter or digit (allowed: [a-z0-9][a-z0-9-_]*)",
            ns
        );
    }
    for c in chars {
        let ok = (c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
            && !c.is_ascii_uppercase();
        if !ok {
            bail!(
                "namespace {:?} contains invalid character {:?}; allowed: [a-z0-9-_] (lowercase)",
                ns,
                c
            );
        }
    }
    // Reject the two dangerous path components even though the charset already
    // bans `.` — belt and suspenders.
    if ns == "." || ns == ".." {
        bail!("namespace name {:?} is reserved", ns);
    }
    Ok(())
}

/// Registry file: the namespace's access_key, encrypted by the SSH key. Used
/// to verify a project's `.dotvault_key` actually owns this namespace.
pub const ACCESS_REGISTRY_FILE: &str = ".access_key.enc";

/// Encrypt the access_key with the SSH key and store it in the namespace dir.
/// The salt is prefixed to the blob so the same key can be re-derived on read.
pub fn write_registry(dir: &Path, key: &ssh_key::PrivateKey, ak: &AccessKey) -> Result<()> {
    let payload = format!("{}\n{}", ak.namespace, ak.key_hex());
    let salt = crate::crypto::random_salt();
    let aes_key = crate::crypto::derive_key(key, &salt)?;
    let sealed = crate::crypto::seal(&aes_key, payload.as_bytes())?;
    let mut blob = Vec::with_capacity(salt.len() + sealed.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&sealed);
    write_atomic(&dir.join(ACCESS_REGISTRY_FILE), &blob)
}

/// Decrypt and return the registered access_key for the namespace in `dir`.
pub fn read_registry(dir: &Path, key: &ssh_key::PrivateKey) -> Result<AccessKey> {
    let path = dir.join(ACCESS_REGISTRY_FILE);
    let blob = std::fs::read(&path)
        .with_context(|| format!("failed to read access registry {}", path.display()))?;
    let salt_len = crate::crypto::SALT_LEN;
    if blob.len() < salt_len {
        bail!("access registry is truncated");
    }
    let (salt, sealed) = blob.split_at(salt_len);
    let aes_key = crate::crypto::derive_key(key, salt)?;
    let plaintext = crate::crypto::open(&aes_key, sealed)?;
    AccessKey::parse(&String::from_utf8_lossy(&plaintext))
}

/// Atomic write: temp file in the same dir, then rename.
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

// ---------- hex (lowercase) ----------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_nibble(b >> 4));
        out.push(hex_nibble(b & 0x0f));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + (n - 10)) as char
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        bail!("odd-length hex string");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => bail!("invalid hex character {:?}", c as char),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_validation_accepts_valid() {
        assert!(validate_namespace("app").is_ok());
        assert!(validate_namespace("my-app-prod").is_ok());
        assert!(validate_namespace("ns_1").is_ok());
        assert!(validate_namespace("a").is_ok());
    }

    #[test]
    fn namespace_validation_rejects_dangerous() {
        // Path traversal attempts.
        assert!(validate_namespace(".").is_err());
        assert!(validate_namespace("..").is_err());
        assert!(validate_namespace("a/b").is_err());
        assert!(validate_namespace("a\\b").is_err());
        assert!(validate_namespace("../x").is_err());
        assert!(validate_namespace("").is_err());
    }

    #[test]
    fn namespace_validation_rejects_bad_charset() {
        assert!(validate_namespace("App").is_err()); // uppercase
        assert!(validate_namespace("-leading").is_err()); // leading dash
        assert!(validate_namespace("has space").is_err());
        assert!(validate_namespace("dot.test").is_err()); // dot
    }

    #[test]
    fn namespace_length_limits() {
        let too_long = "a".repeat(64);
        assert!(validate_namespace(&too_long).is_err());
        let max = "a".repeat(63);
        assert!(validate_namespace(&max).is_ok());
    }

    #[test]
    fn access_key_round_trip() {
        let ak = AccessKey::generate("my-ns").unwrap();
        assert_eq!(ak.namespace, "my-ns");
        assert_eq!(ak.key_hex().len(), 64);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".dotvault_key");
        ak.write_to_project(&path).unwrap();
        let back = AccessKey::read_from_project(&path).unwrap();
        assert_eq!(ak, back);
    }

    #[test]
    fn parse_rejects_short_key() {
        let bad = "myns\nabcd\n"; // 2 bytes, not 32
        assert!(AccessKey::parse(bad).is_err());
    }

    #[test]
    fn parse_rejects_missing_second_line() {
        assert!(AccessKey::parse("myns\n").is_err());
        assert!(AccessKey::parse("").is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0x00, 0xff, 0x1a, 0x80, 0xab];
        assert_eq!(hex_encode(&bytes), "00ff1a80ab");
        assert_eq!(hex_decode("00ff1a80ab").unwrap(), bytes);
        // uppercase input accepted on decode.
        assert_eq!(hex_decode("00FF1A80AB").unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_garbage() {
        assert!(hex_decode("xyz").is_err()); // odd + bad
        assert!(hex_decode("zz").is_err()); // bad char
    }
}
