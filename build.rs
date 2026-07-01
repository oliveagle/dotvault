//! Build script: inject build metadata (git hash, build time, rustc, target)
//! at compile time via `cargo:rustc-env`, consumed by `env!` in the `version`
//! command. All values degrade gracefully to "unknown" when git is unavailable
//! (e.g. a tarball checkout without .git).

use std::process::Command;

fn main() {
    // Re-run if HEAD or the working tree changes so the hash stays accurate.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    set_env("DOTVAULT_GIT_HASH", git_short_hash);
    set_env("DOTVAULT_GIT_DIRTY", || git_dirty().to_string());
    set_env("DOTVAULT_BUILD_TIME", || {
        // RFC3339 UTC, second precision, no extra crates.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format_unix_utc(secs)
    });
    set_env("DOTVAULT_RUSTC", rustc_version);
    set_env("DOTVAULT_TARGET", || {
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    });
}

/// Set a rustc env var from a thunk; if the thunk returns empty, emit nothing
/// (env! at the call site will use the literal default instead).
fn set_env<F: FnOnce() -> String>(name: &str, f: F) {
    let val = f();
    if !val.is_empty() {
        println!("cargo:rustc-env={name}={val}");
    }
}

fn git_short_hash() -> String {
    out_of(Command::new("git").args(["rev-parse", "--short=10", "HEAD"]))
}

fn git_dirty() -> bool {
    // `git describe --dirty` appends "-dirty" when there are uncommitted changes.
    match Command::new("git")
        .args(["describe", "--always", "--dirty", "--tags"])
        .output()
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            s.contains("-dirty")
        }
        Err(_) => false,
    }
}

fn rustc_version() -> String {
    out_of(Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into())).arg("--version"))
        // "rustc 1.96.0 (...) " → keep just the version token line, trimmed.
        .trim()
        .to_string()
}

/// Run a command, return its trimmed stdout, or empty on failure.
fn out_of(cmd: &mut Command) -> String {
    match cmd.output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    }
}

/// RFC3339-ish UTC from Unix seconds (std-only, matches util.rs logic).
fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = (y + if m <= 2 { 1 } else { 0 }) as u32;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}
