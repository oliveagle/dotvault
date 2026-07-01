//! Integration tests for the v0.2 namespaced model.
//!
//! Each test runs in an isolated "home" (DOTVAULT_HOME + DOTVAULT_BACKUP_DIR +
//! DOTVAULT_CONFIG all pointing into a temp dir) and a temp project dir that
//! holds the `.dotvault_key`. No real `~/.dotvault` or `~/.ssh` is touched.

mod common;

use std::sync::{Mutex, OnceLock};

use dotvault::access::AccessKey;
use dotvault::commands;
use dotvault::vault;

use common::{sandbox, TestKey};

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
/// project dir (CWD) that will hold `.dotvault_key`.
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
        std::env::set_current_dir(project.path()).unwrap();
        std::env::set_var("DOTVAULT_KEY_FILE", project.path().join(".dotvault_key"));
        Self {
            _home: home,
            _project: project,
            key: TestKey::new(),
        }
    }
}

fn key_opt(iso: &Iso) -> Option<std::path::PathBuf> {
    Some(iso.key.path.clone())
}

// ---------- init + access-key binding ----------

env_test!(init_creates_namespace_and_key_file, {
    let iso = Iso::new();
    commands::init("myapp", &key_opt(&iso)).unwrap();

    let ak = AccessKey::read_from_project(std::path::Path::new(
        &std::env::var("DOTVAULT_KEY_FILE").unwrap(),
    ))
    .unwrap();
    assert_eq!(ak.namespace, "myapp");
    assert_eq!(ak.key_hex().len(), 64);

    let names = vault::list_namespaces().unwrap();
    assert_eq!(names, vec!["myapp".to_string()]);
});

env_test!(init_twice_same_namespace_errors, {
    let iso = Iso::new();
    commands::init("ns1", &key_opt(&iso)).unwrap();
    let err = commands::init("ns1", &key_opt(&iso)).err().unwrap();
    assert!(format!("{err}").contains("already exists"));
});

env_test!(init_rejects_invalid_namespace, {
    let iso = Iso::new();
    let err = commands::init("../escape", &key_opt(&iso)).err().unwrap();
    assert!(format!("{err}").contains("invalid") || format!("{err}").contains("must start"));
});

// ---------- set/get/list/export roundtrip ----------

env_test!(set_get_list_export_roundtrip, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    let k = key_opt(&iso);
    commands::set(&k, "A", "1").unwrap();
    commands::set(&k, "B", "two words").unwrap();
    commands::set(&k, "C", "3").unwrap();

    // Verify via a short-lived load (the lock must be released before the
    // command-layer calls below, which each load again — holding both would
    // self-deadlock on the namespace lock).
    {
        let v = vault::Vault::load("app", &iso.key.path).unwrap();
        assert_eq!(v.get("B"), Some("two words"));
    } // v dropped → lock released

    let mut out = Vec::new();
    commands::export_to(&k, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "A=1\nB=two words\nC=3\n");

    let mut out = Vec::new();
    commands::list_to(&k, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "A\nB\nC\n");

    let mut out = Vec::new();
    commands::get_to(&k, "A", &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "1");
});

// ---------- fail-fast behaviors ----------

env_test!(set_existing_key_errors, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    let k = key_opt(&iso);
    commands::set(&k, "K", "v1").unwrap();
    let err = commands::set(&k, "K", "v2").err().unwrap();
    assert!(format!("{err}").contains("already exists"));
});

env_test!(get_missing_key_errors, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    let err = commands::get(&key_opt(&iso), "NOPE").err().unwrap();
    assert!(format!("{err}").contains("no such secret"));
});

env_test!(rm_missing_key_errors, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    let err = commands::rm(&key_opt(&iso), "NOPE").err().unwrap();
    assert!(format!("{err}").contains("no such secret"));
});

env_test!(operation_without_key_file_errors, {
    let iso = Iso::new();
    let err = commands::set(&key_opt(&iso), "X", "1").err().unwrap();
    assert!(format!("{err}").contains("no access key"));
});

// ---------- namespace isolation ----------

env_test!(two_namespaces_are_isolated, {
    let iso = Iso::new();
    commands::init("ns-a", &key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), "SHARED", "from-a").unwrap();
    let ak_a = std::fs::read_to_string(std::env::var("DOTVAULT_KEY_FILE").unwrap()).unwrap();

    commands::init("ns-b", &key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), "SHARED", "from-b").unwrap();

    let v_b = vault::Vault::load("ns-b", &iso.key.path).unwrap();
    assert_eq!(v_b.get("SHARED"), Some("from-b"));

    // Restore ns-a's key file and verify isolation.
    std::fs::write(std::env::var("DOTVAULT_KEY_FILE").unwrap(), ak_a).unwrap();
    let v_a = vault::Vault::load("ns-a", &iso.key.path).unwrap();
    assert_eq!(v_a.get("SHARED"), Some("from-a"));
});

env_test!(access_key_mismatch_is_rejected, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    let path = std::env::var("DOTVAULT_KEY_FILE").unwrap();
    // Same namespace, all-zero key → must not match the registered random key.
    std::fs::write(
        &path,
        "app\n0000000000000000000000000000000000000000000000000000000000000000\n",
    )
    .unwrap();
    let err = commands::set(&key_opt(&iso), "X", "1").err().unwrap();
    assert!(
        format!("{err}").contains("rejected") || format!("{err}").contains("does not match"),
        "got: {err}"
    );
});

env_test!(wrong_namespace_in_key_file_is_rejected, {
    let iso = Iso::new();
    commands::init("real", &key_opt(&iso)).unwrap();
    let path = std::env::var("DOTVAULT_KEY_FILE").unwrap();
    let ak = AccessKey::read_from_project(std::path::Path::new(&path)).unwrap();
    std::fs::write(&path, format!("other\n{}\n", ak.key_hex())).unwrap();
    let err = commands::set(&key_opt(&iso), "X", "1").err().unwrap();
    assert!(format!("{err}").contains("no vault") || format!("{err}").contains("does not exist"));
});

// ---------- wrong SSH key ----------

env_test!(wrong_ssh_key_is_rejected, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    let other = TestKey::new();
    let err = commands::set(&Some(other.path), "X", "1").err().unwrap();
    assert!(format!("{err}").contains("mismatch"));
});

// ---------- ns list / remove ----------

env_test!(ns_list_and_remove, {
    let iso = Iso::new();
    commands::init("alpha", &key_opt(&iso)).unwrap();
    commands::init("beta", &key_opt(&iso)).unwrap();
    let names = vault::list_namespaces().unwrap();
    assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);

    commands::ns_remove("alpha", &key_opt(&iso)).unwrap();
    let names = vault::list_namespaces().unwrap();
    assert_eq!(names, vec!["beta".to_string()]);
});

env_test!(ns_remove_requires_correct_key, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    let other = TestKey::new();
    let err = commands::ns_remove("app", &Some(other.path)).err().unwrap();
    assert!(format!("{err}").contains("mismatch"));
});

// ---------- tamper detection ----------

env_test!(tampered_container_is_rejected, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), "A", "1").unwrap();

    let bin = vault::namespace_dir("app").unwrap().join("vault.bin");
    let mut data = std::fs::read(&bin).unwrap();
    let i = data.len() - 1;
    data[i] ^= 0xff;
    std::fs::write(&bin, data).unwrap();

    let err = commands::get(&key_opt(&iso), "A").err().unwrap();
    assert!(format!("{err}").contains("decryption failed"));
});

// ---------- rekey ----------

env_test!(rekey_all_namespaces, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), "SECRET", "hush").unwrap();

    let new_key = TestKey::new();
    commands::rekey(&key_opt(&iso), &new_key.path).unwrap();

    let err = commands::get(&key_opt(&iso), "SECRET").err().unwrap();
    assert!(format!("{err}").contains("mismatch"));
    let v = vault::Vault::load("app", &new_key.path).unwrap();
    assert_eq!(v.get("SECRET"), Some("hush"));
});

// ---------- doctor ----------

env_test!(doctor_reports_ok, {
    let iso = Iso::new();
    commands::init("app", &key_opt(&iso)).unwrap();
    let mut out = Vec::new();
    commands::doctor_to(&key_opt(&iso), &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("status          : OK"));
    assert!(s.contains("namespace       : app"));
});

env_test!(doctor_fails_without_key_file, {
    let iso = Iso::new();
    let err = commands::doctor(&key_opt(&iso)).err().unwrap();
    assert!(format!("{err}").contains("no access key"));
});

// ---------- install ----------

env_test!(install_creates_global_dirs_and_config, {
    let iso = Iso::new();
    commands::install(&key_opt(&iso)).unwrap();
    let home = std::env::var("DOTVAULT_HOME").unwrap();
    assert!(std::path::Path::new(&home).join("namespaces").exists());
    assert!(std::path::Path::new(&home).join("backups").exists());
    assert!(std::path::Path::new(&home).join("config.toml").exists());
});

env_test!(install_does_not_overwrite_config, {
    let iso = Iso::new();
    let cfg_path = std::env::var("DOTVAULT_CONFIG").unwrap();
    std::fs::write(&cfg_path, "backup_keep = 7\n").unwrap();
    commands::install(&key_opt(&iso)).unwrap();
    let after = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(after.contains("backup_keep = 7"));
    assert!(!after.contains("backup_keep = 50"));
});

// ---------- skill install ----------

env_test!(install_writes_skill_and_symlinks, {
    // Control HOME so the ~/.agents/skills symlink target is isolated too.
    let home = tempfile::tempdir().unwrap();
    let old_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home.path());
    let iso = Iso::new();

    commands::install(&key_opt(&iso)).unwrap();

    // SKILL.md written under ~/.dotvault/skill/.
    let dv_home = std::env::var("DOTVAULT_HOME").unwrap();
    let skill_file = std::path::Path::new(&dv_home)
        .join("skill")
        .join("SKILL.md");
    assert!(skill_file.exists(), "skill file should be written");
    let body = std::fs::read_to_string(&skill_file).unwrap();
    assert!(body.contains("name: dotvault"), "skill has wrong name");

    // Symlink created under ~/.agents/skills/dotvault pointing at it.
    let link = home.path().join(".agents").join("skills").join("dotvault");
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "skill symlink should exist"
    );
    // Reading through the link yields the skill content.
    let via_link = std::fs::read_to_string(link.join("SKILL.md")).unwrap();
    assert!(via_link.contains("name: dotvault"));

    std::env::remove_var("DOTVAULT_HOME");
    match old_home {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
});

env_test!(install_skill_does_not_overwrite_existing, {
    let home = tempfile::tempdir().unwrap();
    let old_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home.path());
    let iso = Iso::new();
    let dv_home = std::env::var("DOTVAULT_HOME").unwrap();
    let skill_file = std::path::Path::new(&dv_home)
        .join("skill")
        .join("SKILL.md");
    std::fs::create_dir_all(skill_file.parent().unwrap()).unwrap();
    std::fs::write(&skill_file, "# my custom skill edits\nname: dotvault\n").unwrap();

    commands::install(&key_opt(&iso)).unwrap();

    // User's custom content preserved, not overwritten by the embedded version.
    let after = std::fs::read_to_string(&skill_file).unwrap();
    assert!(
        after.contains("my custom skill edits"),
        "skill was overwritten"
    );
    assert!(
        !after.contains("用 dotvault 管理项目"),
        "embedded skill overwrote custom"
    );

    std::env::remove_var("DOTVAULT_HOME");
    match old_home {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
});

// Keep `sandbox` referenced (used by install tests indirectly via Iso);
// suppress dead-code warning if it's otherwise unused here.
#[allow(dead_code)]
fn _ensure_sandbox_used() -> tempfile::TempDir {
    sandbox()
}
