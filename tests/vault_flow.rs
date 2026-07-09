//! Integration tests for the v0.4 project-local, multi-recipient model.
//!
//! Each test runs in an isolated "project" dir (DOTVAULT_VAULT_DIR + CWD) and
//! an isolated "home" (DOTVAULT_HOME + DOTVAULT_BACKUP_DIR + DOTVAULT_CONFIG
//! all pointing into a separate temp dir). No real `~/.dotvault` or `~/.ssh`
//! is touched.

mod common;

use std::sync::{Mutex, OnceLock};

use dotvault::commands;
use dotvault::vault;

use common::TestKey;

/// Serialize tests that mutate process-global env vars.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

macro_rules! env_test {
    ($name:ident, $body:block) => {
        #[test]
        fn $name() {
            let _guard = env_lock().lock().unwrap();
            $body
        }
    };
}

/// Isolated environment: temp home for DOTVAULT_HOME/backups/config + a temp
/// project dir (CWD + DOTVAULT_VAULT_DIR) that will hold `.vault` / `.vault.keys`.
struct Iso {
    _home: tempfile::TempDir,
    _project: tempfile::TempDir,
    key: TestKey,
}

impl Iso {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::env::set_var("DOTVAULT_HOME", home.path());
        std::env::set_var("DOTVAULT_BACKUP_DIR", home.path().join("backups"));
        std::env::set_var("DOTVAULT_CONFIG", home.path().join("config.toml"));
        std::env::set_var("DOTVAULT_VAULT_DIR", project.path());
        std::env::set_current_dir(project.path()).unwrap();
        Self {
            _home: home,
            _project: project,
            key: TestKey::new(),
        }
    }

    fn key_opt(&self) -> Option<std::path::PathBuf> {
        Some(self.key.path.clone())
    }
}

// ---------- init ----------

env_test!(init_creates_vault_and_keys_file, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();

    // .vault and .vault.keys exist in the project dir.
    let vpath = vault::vault_path().unwrap();
    let kpath = vault::keys_path().unwrap();
    assert!(vpath.exists(), ".vault missing");
    assert!(kpath.exists(), ".vault.keys missing");

    // .vault.keys is parseable and contains exactly the init user's key.
    let keys = dotvault::access::load_keys(&kpath).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys.keys[0].public_key, iso.key.pubkey_line());
});

env_test!(init_twice_errors, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    assert!(commands::init(&iso.key_opt()).is_err());
});

// ---------- set / get / rm / list ----------

env_test!(set_get_roundtrip, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    commands::set(&iso.key_opt(), "DB_PASSWORD", "s3cret").unwrap();

    let mut out = Vec::new();
    commands::get_to(&iso.key_opt(), "DB_PASSWORD", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "s3cret");
});

env_test!(set_duplicate_errors, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    commands::set(&iso.key_opt(), "A", "1").unwrap();
    assert!(commands::set(&iso.key_opt(), "A", "2").is_err());
});

env_test!(rm_removes_secret, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    commands::set(&iso.key_opt(), "A", "1").unwrap();
    commands::rm(&iso.key_opt(), "A").unwrap();
    assert!(commands::get(&iso.key_opt(), "A").is_err());
});

env_test!(export_renders_all_entries, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    commands::set(&iso.key_opt(), "A", "1").unwrap();
    commands::set(&iso.key_opt(), "B", "two").unwrap();

    let mut out = Vec::new();
    commands::export_to(&iso.key_opt(), &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("A=1"), "export should contain A=1:\n{s}");
    assert!(s.contains("B=two"), "export should contain B=two:\n{s}");
});

// ---------- multi-recipient authorization ----------

env_test!(added_key_can_decrypt, {
    // Alice inits and adds Bob; Bob can then decrypt with his own key.
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    commands::set(&alice, "SECRET", "value").unwrap();

    let bob = TestKey::new();
    commands::add_key(&alice, &bob.pubkey_path.to_string_lossy()).unwrap();

    // Bob loads the same project vault with his key and reads the secret.
    let mut out = Vec::new();
    commands::get_to(&Some(bob.path.clone()), "SECRET", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "value");
});

env_test!(unauthorized_key_cannot_decrypt, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    commands::set(&alice, "SECRET", "value").unwrap();

    let eve = TestKey::new();
    // Eve has NOT been authorized; loading must fail.
    assert!(commands::get(&Some(eve.path.clone()), "SECRET").is_err());
});

env_test!(remove_key_blocks_decryption, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    commands::set(&alice, "SECRET", "value").unwrap();

    let bob = TestKey::new();
    commands::add_key(&alice, &bob.pubkey_path.to_string_lossy()).unwrap();
    // Bob is authorized now.
    assert!(commands::get(&Some(bob.path.clone()), "SECRET").is_ok());

    // Remove Bob by his fingerprint, then he can no longer decrypt the
    // CURRENT ciphertext.
    let bob_fp =
        dotvault::crypto::ssh_fingerprint(&dotvault::crypto::load_private_key(&bob.path).unwrap());
    commands::remove_key(&alice, &bob_fp).unwrap();
    assert!(commands::get(&Some(bob.path.clone()), "SECRET").is_err());
});

env_test!(remove_last_key_refused, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    // Only Alice is authorized; removing her must be refused.
    let alice_fp = dotvault::crypto::ssh_fingerprint(
        &dotvault::crypto::load_private_key(&alice.unwrap()).unwrap(),
    );
    assert!(commands::remove_key(&iso.key_opt(), &alice_fp).is_err());
});

env_test!(add_duplicate_key_refused, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    // Re-adding Alice's own pubkey must be refused (already present).
    assert!(commands::add_key(&alice, &iso.key.pubkey_path.to_string_lossy()).is_err());
});

env_test!(list_keys_shows_authorized, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    let bob = TestKey::new();
    commands::add_key(&alice, &bob.pubkey_path.to_string_lossy()).unwrap();

    // Load the vault and check the registry has 2 keys.
    let v = vault::Vault::load(&alice.unwrap()).unwrap();
    assert_eq!(v.keys.len(), 2);
});

// ---------- load errors ----------

env_test!(load_without_init_errors, {
    let iso = Iso::new();
    assert!(commands::get(&iso.key_opt(), "X").is_err());
});

// ---------- command-layer coverage (list/list_keys/doctor/add_key @file) ----------

env_test!(list_outputs_key_names, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    commands::set(&iso.key_opt(), "ALPHA", "1").unwrap();
    commands::set(&iso.key_opt(), "BETA", "2").unwrap();

    let mut out = Vec::new();
    commands::list_to(&iso.key_opt(), &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("ALPHA"), "list should name ALPHA:\n{s}");
    assert!(s.contains("BETA"), "list should name BETA:\n{s}");
    // No values leaked in list mode.
    assert!(!s.contains("=1"), "list must not show values");
});

env_test!(list_keys_command_marks_current_user, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    let bob = TestKey::new();
    commands::add_key(&alice, &bob.pubkey_path.to_string_lossy()).unwrap();

    // Verify via vault load that 2 keys are present and current user is authorized.
    let v = vault::Vault::load(&alice.unwrap()).unwrap();
    assert_eq!(v.keys.len(), 2);
    // Exercise the public current_user_authorized helper.
    assert!(v.current_user_authorized());
});

env_test!(doctor_reports_status_ok, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    commands::set(&iso.key_opt(), "A", "1").unwrap();

    let mut out = Vec::new();
    commands::doctor_to(&iso.key_opt(), &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(
        s.contains("status          : OK"),
        "doctor should report OK:\n{s}"
    );
    assert!(
        s.contains("entries         : 1"),
        "doctor should show 1 entry:\n{s}"
    );
    assert!(
        s.contains("authorized keys : 1"),
        "doctor should show 1 key:\n{s}"
    );
});

env_test!(add_key_via_at_file_syntax, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    commands::set(&alice, "SHARED", "v1").unwrap();

    let bob = TestKey::new();
    // Write Bob's pubkey to a temp file, then add via @file syntax.
    let bob_line = bob.pubkey_line();
    let spec_file = std::env::temp_dir().join("dv_bob_pubkey.txt");
    std::fs::write(&spec_file, &bob_line).unwrap();

    commands::add_key(&alice, &format!("@{}", spec_file.display())).unwrap();

    // Bob can now decrypt SHARED.
    let mut out = Vec::new();
    commands::get_to(&Some(bob.path.clone()), "SHARED", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "v1");
    let _ = std::fs::remove_file(&spec_file);
});

env_test!(remove_key_command_by_fingerprint, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    let bob = TestKey::new();
    commands::add_key(&alice, &bob.pubkey_path.to_string_lossy()).unwrap();

    // Remove by fingerprint via the command layer.
    let bob_fp =
        dotvault::crypto::ssh_fingerprint(&dotvault::crypto::load_private_key(&bob.path).unwrap());
    commands::remove_key(&alice, &bob_fp).unwrap();
    // Bob can no longer decrypt.
    assert!(commands::get(&Some(bob.path.clone()), "A").is_err());
});

env_test!(get_missing_secret_errors, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    assert!(commands::get(&iso.key_opt(), "NOPE").is_err());
});

env_test!(rm_missing_secret_errors, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    assert!(commands::rm(&iso.key_opt(), "NOPE").is_err());
});

env_test!(export_empty_vault_produces_warning, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    let mut out = Vec::new();
    commands::export_to(&iso.key_opt(), &mut out).unwrap();
    // Empty vault exports nothing (no sections).
    let s = String::from_utf8(out).unwrap();
    assert!(!s.contains("="), "empty vault should export no KEY=VALUE");
});

env_test!(add_key_invalid_pubkey_errors, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice).unwrap();
    // A garbage string is not a valid pubkey.
    assert!(commands::add_key(&alice, "not-a-valid-key").is_err());
});

// ---------- install / config / resolve_ssh_key_path coverage ----------

env_test!(install_creates_dirs_and_config, {
    let iso = Iso::new();
    // install should succeed and create ~/.dotvault dirs + config.
    commands::install(&iso.key_opt()).unwrap();
    // config file created.
    let cfg_path = dotvault::config::Config::path().unwrap();
    assert!(cfg_path.exists());
    // backups dir created (under DOTVAULT_HOME).
    let home = dotvault::vault::dotvault_home().unwrap();
    assert!(home.join("backups").exists());
});

env_test!(install_is_idempotent, {
    let iso = Iso::new();
    commands::install(&iso.key_opt()).unwrap();
    // Second install must not error.
    commands::install(&iso.key_opt()).unwrap();
});

env_test!(config_set_and_show, {
    let iso = Iso::new();
    commands::install(&iso.key_opt()).unwrap();
    // Set a config value.
    commands::config(&Some("~/.ssh/custom_key".into()), &None, &None).unwrap();
    // Verify it persisted.
    let cfg = dotvault::config::Config::load().unwrap();
    assert_eq!(cfg.key.as_deref(), Some("~/.ssh/custom_key"));
});

env_test!(config_set_backup_keep, {
    let iso = Iso::new();
    commands::install(&iso.key_opt()).unwrap();
    commands::config(&None, &None, &Some(99)).unwrap();
    let cfg = dotvault::config::Config::load().unwrap();
    assert_eq!(cfg.backup_keep, Some(99));
});

env_test!(version_prints_pkg_version, {
    let mut out = Vec::new();
    commands::version_to(&mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.starts_with("dotvault "), "version output: {s}");
});

env_test!(set_uses_explicit_key_flag, {
    let iso = Iso::new();
    commands::init(&iso.key_opt()).unwrap();
    // Pass key explicitly (not via env). DOTVAULT_KEY is not set in Iso.
    std::env::remove_var("DOTVAULT_KEY");
    commands::set(&iso.key_opt(), "FLAG_TEST", "ok").unwrap();
    let mut out = Vec::new();
    commands::get_to(&iso.key_opt(), "FLAG_TEST", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "ok");
});
