//! Test for the `version` command output.

use std::sync::{Mutex, OnceLock};

fn lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

#[test]
fn version_prints_all_fields() {
    // The version command touches no env/state, but keep it isolated anyway.
    let _g = lock().lock().unwrap();
    let mut out = Vec::new();
    dotvault::commands::version_to(&mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    // Required lines, each with its label.
    assert!(
        s.starts_with("dotvault "),
        "first line must be the version: {s}"
    );
    assert!(s.contains("commit: "), "missing commit line: {s}");
    assert!(s.contains("built:  "), "missing built line: {s}");
    assert!(s.contains("rustc:  "), "missing rustc line: {s}");
    assert!(s.contains("target: "), "missing target line: {s}");
}

#[test]
fn version_starts_with_pkg_version() {
    let _g = lock().lock().unwrap();
    let mut out = Vec::new();
    dotvault::commands::version_to(&mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    let pkg = env!("CARGO_PKG_VERSION");
    assert!(
        s.starts_with(&format!("dotvault {pkg}")),
        "version line must match Cargo.toml ({pkg}): {s}"
    );
}
