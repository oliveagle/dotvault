//! Shared test helpers for integration tests.
//!
//! Generates ephemeral OpenSSH ed25519 keypairs into temp files so tests
//! never depend on the user's real `~/.ssh`.

use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::path::PathBuf;

/// A throwaway SSH key on disk (unencrypted, OpenSSH format) + its temp dir.
/// The dir is cleaned up when this is dropped.
#[allow(dead_code)]
pub struct TestKey {
    pub path: PathBuf,
    pub pubkey_path: PathBuf,
    _dir: tempfile::TempDir,
}

#[allow(dead_code)]
impl TestKey {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_ed25519");
        let pubkey_path = dir.path().join("test_ed25519.pub");
        let mut rng = rand::rngs::OsRng;
        let kp = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("generate key");
        let pem = kp.to_openssh(LineEnding::LF).expect("encode key");
        std::fs::write(&path, pem.as_str().as_bytes()).expect("write key");
        // Write the matching public-key file (authorized-keys line), so the
        // vault's initial recipient can be derived from `*.pub` like in prod.
        let pub_line = kp.public_key().to_openssh().expect("encode pubkey");
        std::fs::write(&pubkey_path, pub_line.as_bytes()).expect("write pubkey");
        // Restrictive perms, like a real private key (not strictly required
        // for tests, but mirrors reality).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
        Self {
            path,
            pubkey_path,
            _dir: dir,
        }
    }

    /// The authorized-keys line for this key's public half.
    pub fn pubkey_line(&self) -> String {
        std::fs::read_to_string(&self.pubkey_path)
            .expect("read pubkey")
            .trim()
            .to_string()
    }
}

/// Create a fresh empty working directory for a test vault + its tempdir.
#[allow(dead_code)]
pub fn sandbox() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}
