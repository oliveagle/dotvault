//! Shared test helpers for integration tests.
//!
//! Generates an ephemeral OpenSSH ed25519 keypair into a temp file so tests
//! never depend on the user's real `~/.ssh`.

use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::path::PathBuf;

/// A throwaway SSH key on disk (unencrypted, OpenSSH format) + its temp dir.
/// The dir is cleaned up when this is dropped.
pub struct TestKey {
    pub path: PathBuf,
    _dir: tempfile::TempDir,
}

impl TestKey {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_ed25519");
        let mut rng = rand::rngs::OsRng;
        let kp = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("generate key");
        let pem = kp.to_openssh(LineEnding::LF).expect("encode key");
        std::fs::write(&path, pem.as_str().as_bytes()).expect("write key");
        // Restrictive perms, like a real private key (not strictly required
        // for tests, but mirrors reality).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
        Self { path, _dir: dir }
    }
}

/// Create a fresh empty working directory for a test vault + its tempdir.
#[allow(dead_code)]
pub fn sandbox() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}
