//! Tests for merged export/list (global + project with comment sections).

mod common;

use std::sync::{Mutex, OnceLock};

use common::TestKey;
use dotvault::commands;

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

env_test!(export_merges_global_and_project_with_sections, {
    let iso = Iso::new();
    commands::install(&key_opt(&iso)).unwrap();
    // global has A and SHARED; project has SHARED (override) and B.
    commands::set(&key_opt(&iso), true, "A", "ga").unwrap();
    commands::set(&key_opt(&iso), true, "SHARED", "g-shared").unwrap();
    commands::init("proj", &key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), false, "SHARED", "p-shared").unwrap();
    commands::set(&key_opt(&iso), false, "B", "pb").unwrap();

    let mut out = Vec::new();
    commands::export_to(&key_opt(&iso), false, &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(
        s.contains("# === global ==="),
        "missing global section: {s}"
    );
    assert!(
        s.contains("# === namespace: proj ==="),
        "missing project section: {s}"
    );
    assert!(s.contains("A=ga"));
    assert!(
        s.contains("SHARED=p-shared"),
        "project version must win: {s}"
    );
    assert!(s.contains("B=pb"));
    // global's SHARED value must NOT be active (project wins), but the key
    // is shown as a commented-out, overridden marker for debuggability.
    assert!(
        !s.contains("SHARED=g-shared"),
        "global SHARED value must not appear active: {s}"
    );
    assert!(
        s.contains("# SHARED  # overridden by project"),
        "overridden global key should be shown as a comment marker: {s}"
    );
});

env_test!(export_global_only_when_no_project, {
    let iso = Iso::new();
    commands::install(&key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), true, "G", "gv").unwrap();
    // No project .dotvault_key → only global section.
    let mut out = Vec::new();
    commands::export_to(&key_opt(&iso), false, &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("# === global ==="));
    assert!(s.contains("G=gv"));
    assert!(!s.contains("# === namespace"));
});

env_test!(export_global_flag_does_not_merge, {
    let iso = Iso::new();
    commands::install(&key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), true, "G", "gv").unwrap();
    commands::init("proj", &key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), false, "P", "pv").unwrap();
    // --global → only global, no project section even though project exists.
    let mut out = Vec::new();
    commands::export_to(&key_opt(&iso), true, &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("# === global ==="));
    assert!(s.contains("G=gv"));
    assert!(!s.contains("# === namespace"));
    assert!(!s.contains("P=pv"));
});

env_test!(list_merges_with_sections, {
    let iso = Iso::new();
    commands::install(&key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), true, "GA", "1").unwrap();
    commands::init("proj", &key_opt(&iso)).unwrap();
    commands::set(&key_opt(&iso), false, "PB", "2").unwrap();
    let mut out = Vec::new();
    commands::list_to(&key_opt(&iso), false, &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("# === global ==="));
    assert!(s.contains("GA"));
    assert!(s.contains("# === namespace: proj ==="));
    assert!(s.contains("PB"));
});
