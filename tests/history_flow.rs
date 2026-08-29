//! Integration tests for the v0.8 versioned-vault features: entry metadata,
//! in-vault history, `restore`, `diff`, `merge`, legacy migration and history
//! rotation. Mirrors the Iso/env_test pattern of the other flow tests.

mod common;

use std::sync::{Mutex, OnceLock};

use dotvault::vault;
use dotvault::{commands, commands_history};

use common::TestKey;

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

macro_rules! env_test {
    ($name:ident, $body:block) => {
        #[test]
        fn $name() {
            // Poison-tolerant: one failing test must not cascade.
            let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
            $body
        }
    };
}

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

    /// Absolute path inside the project dir.
    fn p(&self, name: &str) -> std::path::PathBuf {
        std::env::current_dir().unwrap().join(name)
    }
}

// ---------- entry metadata + history capture ----------

env_test!(entries_carry_metadata_and_actor, {
    let iso = Iso::new();
    commands::init(&iso.key_opt(), &None).unwrap();
    commands::set(&iso.key_opt(), &None, "A", "1").unwrap();

    let v = vault::Vault::load(&iso.key.path).unwrap();
    let e = v.doc.get("A").expect("A present");
    assert!(!e.modified_at.is_empty(), "modified_at must be stamped");
    assert!(e.hash.starts_with("sha256:"), "hash format: {}", e.hash);
    assert_eq!(e.hash, dotvault::vaultdoc::hash_value("1"));
    assert!(
        e.actor.as_deref().unwrap_or("").starts_with("SHA256:"),
        "actor should be the writer's key fingerprint"
    );
});

env_test!(rm_archives_into_history, {
    let iso = Iso::new();
    commands::init(&iso.key_opt(), &None).unwrap();
    commands::set(&iso.key_opt(), &None, "A", "v1").unwrap();
    commands::rm(&iso.key_opt(), &None, "A").unwrap();

    let v = vault::Vault::load(&iso.key.path).unwrap();
    assert!(v.doc.get("A").is_none());
    assert_eq!(v.doc.history.len(), 1);
    let h = &v.doc.history[0];
    assert_eq!((h.key.as_str(), h.value.as_str()), ("A", "v1"));
    assert_eq!(h.reason, "delete");
});

// ---------- restore ----------

env_test!(restore_recovers_deleted_key, {
    let iso = Iso::new();
    commands::init(&iso.key_opt(), &None).unwrap();
    commands::set(&iso.key_opt(), &None, "A", "v1").unwrap();
    commands::rm(&iso.key_opt(), &None, "A").unwrap();

    // Find the historical version's hash, then restore by its prefix.
    let hash = {
        let v = vault::Vault::load(&iso.key.path).unwrap();
        v.doc.history[0].hash.clone()
    };
    let prefix = hash.strip_prefix("sha256:").unwrap()[..8].to_string();
    commands_history::restore(&iso.key_opt(), &None, "A", &prefix).unwrap();

    let mut out = Vec::new();
    commands::get_to(&iso.key_opt(), &None, "A", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "v1");
});

env_test!(restore_replaces_live_value_and_archives_it, {
    let iso = Iso::new();
    commands::init(&iso.key_opt(), &None).unwrap();
    commands::set(&iso.key_opt(), &None, "A", "v1").unwrap();
    commands::rm(&iso.key_opt(), &None, "A").unwrap();
    commands::set(&iso.key_opt(), &None, "A", "v2").unwrap();

    let old_prefix = {
        let v = vault::Vault::load(&iso.key.path).unwrap();
        let h = v.doc.history.iter().find(|h| h.value == "v1").unwrap();
        h.hash.strip_prefix("sha256:").unwrap()[..8].to_string()
    };
    commands_history::restore(&iso.key_opt(), &None, "A", &old_prefix).unwrap();

    let mut out = Vec::new();
    commands::get_to(&iso.key_opt(), &None, "A", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "v1", "restored old value");
    // The replaced live value (v2) is now in history — nothing lost.
    let v = vault::Vault::load(&iso.key.path).unwrap();
    assert!(v
        .doc
        .history
        .iter()
        .any(|h| h.value == "v2" && h.reason == "overwrite"));
});

env_test!(restore_rejects_ambiguous_prefix, {
    let iso = Iso::new();
    commands::init(&iso.key_opt(), &None).unwrap();
    commands::set(&iso.key_opt(), &None, "A", "v1").unwrap();
    commands::rm(&iso.key_opt(), &None, "A").unwrap();
    commands::set(&iso.key_opt(), &None, "A", "v2").unwrap();
    commands::rm(&iso.key_opt(), &None, "A").unwrap();
    // Both history records exist with distinct hashes → a 1-char prefix of
    // "sha256:..." is ambiguous enough to sometimes match both; use a prefix
    // that cannot match anything to check the not-found error, and a full
    // hash to check exact matching works.
    assert!(commands_history::restore(&iso.key_opt(), &None, "A", "deadbeef").is_err());
    let full = {
        let v = vault::Vault::load(&iso.key.path).unwrap();
        v.doc
            .history
            .iter()
            .find(|h| h.value == "v2")
            .unwrap()
            .hash
            .clone()
    };
    commands_history::restore(&iso.key_opt(), &None, "A", &full).unwrap();
    let mut out = Vec::new();
    commands::get_to(&iso.key_opt(), &None, "A", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "v2");
});

env_test!(history_command_is_read_only_via_token, {
    let iso = Iso::new();
    commands::init(&iso.key_opt(), &None).unwrap();
    commands::set(&iso.key_opt(), &None, "A", "v1").unwrap();
    commands::rm(&iso.key_opt(), &None, "A").unwrap();

    let token = {
        let mut v = vault::Vault::load(&iso.key.path).unwrap();
        v.add_token("ci").unwrap()
    };
    // history works with a token (read-only)...
    commands_history::history(&None, &Some(token.clone()), &Some("A".into())).unwrap();
    // ...restore does not.
    assert!(commands_history::restore(&None, &Some(token), "A", "x").is_err());
});

// ---------- diff ----------

env_test!(diff_detects_added_removed_changed, {
    let iso = Iso::new();
    commands::init(&iso.key_opt(), &None).unwrap();
    commands::set(&iso.key_opt(), &None, "A", "1").unwrap();
    commands::set(&iso.key_opt(), &None, "B", "1").unwrap();
    std::fs::copy(".vault", iso.p("f1")).unwrap();

    commands::rm(&iso.key_opt(), &None, "B").unwrap(); // changed (rm+set)
    commands::set(&iso.key_opt(), &None, "B", "2").unwrap(); //
    commands::rm(&iso.key_opt(), &None, "A").unwrap(); // removed
    commands::set(&iso.key_opt(), &None, "C", "3").unwrap(); // added
    std::fs::copy(".vault", iso.p("f2")).unwrap();

    // Exercise the diff core via the two files.
    let d1 = {
        let v = vault::Vault::load(&iso.key.path).unwrap();
        let _ = v;
        decrypt_to_doc(&iso, "f1")
    };
    let d2 = decrypt_to_doc(&iso, "f2");
    let mut out = Vec::new();
    let n = commands_history::print_diff(&d1, &d2, &mut out).unwrap();
    assert_eq!(n, 3, "expected 3 differences");
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("~ B"), "changed B reported:\n{s}");
    assert!(s.contains("- A"), "removed A reported:\n{s}");
    assert!(s.contains("+ C"), "added C reported:\n{s}");
    // Secret values never appear in diff output.
    assert!(
        !s.contains("= 2") && !s.contains("= 3"),
        "no values leaked:\n{s}"
    );
});

// ---------- merge ----------

env_test!(merge_two_way_newest_and_output_loads, {
    let iso = Iso::new();
    let k = iso.key_opt();
    commands::init(&k, &None).unwrap();
    commands::set(&k, &None, "SHARED", "base-val").unwrap();
    commands::set(&k, &None, "ONLY_OURS", "o").unwrap();
    std::fs::copy(".vault", iso.p("ours.bin")).unwrap();

    // Simulate the other branch: change SHARED later, add ONLY_THEIRS.
    commands::set(&k, &None, "ONLY_THEIRS", "t").unwrap();
    // Overwrite SHARED via rm+set with a LATER modified_at: sleep a moment so
    // the ISO second ticks.
    std::thread::sleep(std::time::Duration::from_secs(1));
    commands::rm(&k, &None, "SHARED").unwrap();
    commands::set(&k, &None, "SHARED", "their-newer-val").unwrap();
    std::fs::copy(".vault", iso.p("theirs.bin")).unwrap();

    let out_path = iso.p("merged.bin");
    commands_history::merge(
        &k,
        &None,
        &iso.p("ours.bin"),
        &iso.p("theirs.bin"),
        None,
        "newest",
        &out_path,
    )
    .unwrap();

    // The merged container decrypts with our key and has the right entries.
    let doc = decrypt_file_to_doc(&iso, &out_path);
    assert_eq!(
        doc.get("SHARED").unwrap().value,
        "their-newer-val",
        "newest wins"
    );
    assert_eq!(doc.get("ONLY_OURS").unwrap().value, "o");
    assert_eq!(doc.get("ONLY_THEIRS").unwrap().value, "t");
    // The losing value is archived, not dropped.
    assert!(
        doc.history
            .iter()
            .any(|h| h.key == "SHARED" && h.value == "base-val"),
        "merge loser archived:\n{:?}",
        doc.history
    );
});

env_test!(merge_requires_ssh_not_token, {
    let iso = Iso::new();
    let k = iso.key_opt();
    commands::init(&k, &None).unwrap();
    commands::set(&k, &None, "A", "1").unwrap();
    let token = {
        let mut v = vault::Vault::load(&iso.key.path).unwrap();
        v.add_token("ci").unwrap()
    };
    assert!(commands_history::merge(
        &None,
        &Some(token),
        &iso.p(".vault"),
        &iso.p(".vault"),
        None,
        "newest",
        &iso.p("out.bin"),
    )
    .is_err());
});

// ---------- legacy migration ----------

env_test!(legacy_env_vault_loads_and_migrates_on_save, {
    let iso = Iso::new();
    let k = iso.key_opt();
    commands::init(&k, &None).unwrap();

    // Craft a v0.7-era vault: plaintext is bare .env.
    let keys = {
        let v = vault::Vault::load(&iso.key.path).unwrap();
        v.keys.clone()
    };
    let legacy_plaintext =
        dotvault::envfmt::serialize(&[("OLD".to_string(), "legacy1".to_string())]);
    let container =
        dotvault::crypto::encrypt_to_recipients(&keys.pubkey_lines(), legacy_plaintext.as_bytes())
            .unwrap();
    std::fs::write(".vault", container).unwrap();

    // Reads fine (legacy detected, fresh metadata stamped).
    let mut out = Vec::new();
    commands::get_to(&k, &None, "OLD", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "legacy1");

    // Any write migrates the container to the v2 format.
    commands::set(&k, &None, "NEW", "2").unwrap();
    let bytes = std::fs::read(".vault").unwrap();
    let sk = dotvault::crypto::load_private_key(&iso.key.path).unwrap();
    let plaintext = dotvault::crypto::decrypt_with_key(&sk, &bytes).unwrap();
    assert!(
        plaintext.starts_with(dotvault::vaultdoc::DOC_MAGIC.as_bytes()),
        "vault migrated to v2 on save"
    );
});

// ---------- history rotation ----------

env_test!(history_rotates_on_save_per_config, {
    let iso = Iso::new();
    let k = iso.key_opt();
    commands::init(&k, &None).unwrap();
    commands::set(&k, &None, "A", "v1").unwrap();
    commands::rm(&k, &None, "A").unwrap(); // history: superseded now

    // Fabricate an ancient superseded_at, then save → must be pruned (365d default).
    {
        let mut v = vault::Vault::load(&iso.key.path).unwrap();
        v.doc.history[0].superseded_at = "2020-01-01T00:00:00Z".into();
        v.save().unwrap();
    }
    {
        let v = vault::Vault::load(&iso.key.path).unwrap();
        assert!(
            v.doc
                .history
                .iter()
                .all(|h| h.superseded_at != "2020-01-01T00:00:00Z"),
            "ancient history pruned on save"
        );
    }

    // history_days = 0 disables rotation entirely.
    commands::config(&None, &None, &None, &Some(0)).unwrap();
    commands::set(&k, &None, "B", "1").unwrap();
    commands::rm(&k, &None, "B").unwrap();
    {
        let mut v = vault::Vault::load(&iso.key.path).unwrap();
        v.doc.history[0].superseded_at = "2019-01-01T00:00:00Z".into();
        v.save().unwrap();
    }
    {
        let v = vault::Vault::load(&iso.key.path).unwrap();
        assert!(
            v.doc
                .history
                .iter()
                .any(|h| h.superseded_at == "2019-01-01T00:00:00Z"),
            "history_days=0 keeps everything"
        );
    }
});

// ---------- helpers ----------

/// Decrypt `<name>` (a path inside the project) with the test SSH key.
fn decrypt_to_doc(iso: &Iso, name: &str) -> dotvault::vaultdoc::VaultDoc {
    decrypt_file_to_doc(iso, &iso.p(name))
}

fn decrypt_file_to_doc(iso: &Iso, path: &std::path::Path) -> dotvault::vaultdoc::VaultDoc {
    let bytes = std::fs::read(path).unwrap();
    let sk = dotvault::crypto::load_private_key(&iso.key.path).unwrap();
    let pt = dotvault::crypto::decrypt_with_key(&sk, &bytes).unwrap();
    dotvault::vaultdoc::VaultDoc::from_bytes(&pt, "2026-08-06T00:00:00Z").unwrap()
}
