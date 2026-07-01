//! Tests for the `version` command output and version comparison.

use std::sync::{Mutex, OnceLock};

fn lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

/// Isolate DOTVAULT_HOME so the online-check cache doesn't touch the real
/// ~/.dotvault, and so tests are deterministic.
fn with_iso_home<T>(f: impl FnOnce() -> T) -> T {
    let _g = lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("DOTVAULT_HOME", dir.path());
    let r = f();
    std::env::remove_var("DOTVAULT_HOME");
    r
}

#[test]
fn version_prints_all_fields() {
    with_iso_home(|| {
        let mut out = Vec::new();
        dotvault::commands::version_to(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.starts_with("dotvault "),
            "first line must be version: {s}"
        );
        assert!(s.contains("commit: "), "missing commit line: {s}");
        assert!(s.contains("built:  "), "missing built line: {s}");
        assert!(s.contains("rustc:  "), "missing rustc line: {s}");
        assert!(s.contains("target: "), "missing target line: {s}");
    })
}

#[test]
fn version_starts_with_pkg_version() {
    with_iso_home(|| {
        let mut out = Vec::new();
        dotvault::commands::version_to(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        let pkg = env!("CARGO_PKG_VERSION");
        assert!(
            s.starts_with(&format!("dotvault {pkg}")),
            "version line must match Cargo.toml ({pkg}): {s}"
        );
    })
}

#[test]
fn is_newer_semantic_comparison() {
    use dotvault::update::is_newer;
    // Strictly newer.
    assert!(is_newer("v0.3.0", "0.2.0"));
    assert!(is_newer("0.2.1", "0.2.0"));
    assert!(is_newer("1.0.0", "0.99.99"));
    // Multi-digit components must compare numerically, not lexically.
    assert!(is_newer("0.10.0", "0.9.0"));
    // Equal or older → false.
    assert!(!is_newer("v0.2.0", "0.2.0"));
    assert!(!is_newer("0.1.5", "0.2.0"));
    assert!(!is_newer("0.2.0", "0.2.1"));
    // v-prefix on local side handled too.
    assert!(is_newer("0.3.0", "v0.2.0"));
}
