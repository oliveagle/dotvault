//! Integration tests for the read-only token (X25519 age recipient) mode,
//! split out of `vault_flow.rs` for file-size hygiene.
//!
//! Each test runs in an isolated "project" dir (DOTVAULT_VAULT_DIR + CWD) and
//! an isolated "home" (DOTVAULT_HOME + DOTVAULT_BACKUP_DIR + DOTVAULT_CONFIG
//! all pointing into a separate temp dir). No real `~/.dotvault` or `~/.ssh`
//! is touched.

mod common;

use std::sync::{Mutex, OnceLock};

use dotvault::vault;
use dotvault::{commands, commands_auth};

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

/// Isolated environment (mirrors `vault_flow::Iso`): temp home for
/// DOTVAULT_HOME/backups/config + a temp project dir.
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

env_test!(add_token_grants_read_access, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice, &None).unwrap();
    commands::set(&alice, &None, "DB_PASSWORD", "s3cret").unwrap();

    // Alice authorizes a read-only token (via the vault layer so we capture
    // the secret directly, rather than scraping stdout).
    let token = {
        let mut v = vault::Vault::load(&alice.clone().unwrap()).unwrap();
        v.add_token("ci-deploy").unwrap()
    }; // v dropped here, releasing .vault.lock

    // The token is an age secret key string.
    assert!(token.starts_with("AGE-SECRET-KEY-1"), "token: {token}");

    // CI uses the token to read — get + export both work.
    let mut out = Vec::new();
    commands::get_to(&None, &Some(token.clone()), "DB_PASSWORD", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "s3cret");

    let mut exp = Vec::new();
    commands::export_to(&None, &Some(token.clone()), &mut exp).unwrap();
    assert!(String::from_utf8(exp)
        .unwrap()
        .contains("DB_PASSWORD=s3cret"));
});

env_test!(token_and_ssh_coexist_same_vault, {
    // Both an SSH key and a token can decrypt the SAME .vault after the token
    // is added (the core age mixed-recipient guarantee).
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice, &None).unwrap();
    commands::set(&alice, &None, "SECRET", "v1").unwrap();

    let token = {
        let mut v = vault::Vault::load(&alice.clone().unwrap()).unwrap();
        v.add_token("ci").unwrap()
    };

    // SSH key still decrypts.
    let mut out_ssh = Vec::new();
    commands::get_to(&alice, &None, "SECRET", &mut out_ssh).unwrap();
    assert_eq!(String::from_utf8(out_ssh).unwrap(), "v1");
    // Token also decrypts.
    let mut out_tok = Vec::new();
    commands::get_to(&None, &Some(token), "SECRET", &mut out_tok).unwrap();
    assert_eq!(String::from_utf8(out_tok).unwrap(), "v1");
});

env_test!(token_cannot_decrypt_after_revoke, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice, &None).unwrap();
    commands::set(&alice, &None, "SECRET", "v1").unwrap();

    let token = {
        let mut v = vault::Vault::load(&alice.clone().unwrap()).unwrap();
        v.add_token("ci").unwrap()
    };
    // Token works before revoke.
    assert!(commands::get(&None, &Some(token.clone()), "SECRET").is_ok());

    // Revoke (re-encrypts without the token as a recipient).
    commands_auth::revoke_token(&alice, &None, "ci").unwrap();
    // Token can no longer decrypt the CURRENT ciphertext.
    assert!(
        commands::get(&None, &Some(token), "SECRET").is_err(),
        "revoked token must not decrypt the re-encrypted vault"
    );
});

env_test!(token_rejected_for_write_commands, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice, &None).unwrap();
    commands::set(&alice, &None, "A", "1").unwrap();

    let token = {
        let mut v = vault::Vault::load(&alice.clone().unwrap()).unwrap();
        v.add_token("ci").unwrap()
    };
    let tok = Some(token);

    // Every write command must reject a token.
    assert!(commands::set(&None, &tok, "B", "2").is_err());
    assert!(commands::rm(&None, &tok, "A").is_err());
    assert!(commands::add_key(&None, &tok, "ssh-ed25519 AAAA").is_err());
    assert!(commands::remove_key(&None, &tok, "x").is_err());
    assert!(commands_auth::add_token(&None, &tok, "evil").is_err());
    assert!(commands_auth::revoke_token(&None, &tok, "ci").is_err());
});

env_test!(add_token_requires_ssh_key, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice, &None).unwrap();

    // Minting a token with another token must be refused.
    let token = {
        let mut v = vault::Vault::load(&alice.clone().unwrap()).unwrap();
        v.add_token("first").unwrap()
    };
    assert!(
        commands_auth::add_token(&None, &Some(token), "second").is_err(),
        "a token must not be able to mint more tokens"
    );
});

env_test!(unauthorized_token_cannot_decrypt, {
    // A random token (not added to the vault) cannot decrypt someone else's vault.
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice, &None).unwrap();
    commands::set(&alice, &None, "SECRET", "v1").unwrap();

    let (bogus_token, _) = dotvault::crypto::generate_token_keypair();
    assert!(
        commands::get(&None, &Some(bogus_token), "SECRET").is_err(),
        "an un-authorized token must not decrypt"
    );
});

env_test!(list_tokens_shows_pubkey_not_secret, {
    let iso = Iso::new();
    let alice = iso.key_opt();
    commands::init(&alice, &None).unwrap();
    commands::set(&alice, &None, "A", "1").unwrap();

    let (secret, keys) = {
        let mut v = vault::Vault::load(&alice.clone().unwrap()).unwrap();
        let s = v.add_token("ci-deploy").unwrap();
        (s, v.keys.clone())
    };

    // list-tokens shows age1... public keys + labels, never the AGE-SECRET-KEY.
    assert_eq!(keys.token_count(), 1);
    assert!(keys.tokens[0].public_key.starts_with("age1"));
    assert_eq!(keys.tokens[0].label, "ci-deploy");
    // The secret must NOT appear anywhere in the registry.
    let registry_json = serde_json::to_string(&keys).unwrap();
    assert!(
        !registry_json.contains(&secret),
        "token secret must never be stored in .vault.keys"
    );
});

env_test!(serde_backward_compat_no_tokens_field, {
    // A .vault.keys written before tokens existed (no `tokens` field) must
    // still load, with tokens defaulting to empty.
    let iso = Iso::new();
    commands::init(&iso.key_opt(), &None).unwrap();
    let kpath = vault::keys_path().unwrap();
    let legacy = serde_json::json!({
        "version": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "keys": [{
            "fingerprint": dotvault::crypto::ssh_fingerprint(
                &dotvault::crypto::load_private_key(&iso.key.path).unwrap()
            ),
            "public_key": iso.key.pubkey_line(),
            "label": "owner",
            "added_at": "2026-01-01T00:00:00Z"
        }]
    });
    std::fs::write(&kpath, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();
    let keys = dotvault::access::load_keys(&kpath).unwrap();
    assert!(
        keys.tokens.is_empty(),
        "legacy .vault.keys must yield empty tokens"
    );
});
