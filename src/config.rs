//! Global configuration at `~/.dotvault/config.toml`.
//!
//! All fields are optional (`None` means "unset" — fall through to the next
//! layer in the resolution chain). The file itself is optional too: if it does
//! not exist, dotvault behaves exactly as before (pure CLI/env/defaults).
//!
//! Resolution priority, highest first:
//!   1. command-line flag (`--key`, `--vault`)
//!   2. environment variable (`DOTVAULT_KEY`, `DOTVAULT_BACKUP_DIR`)
//!   3. this config file
//!   4. hardcoded default

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Persisted global config. Every field is optional so an absent key in the
/// file means "not configured" rather than "empty string".
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Default SSH private key path (may start with `~`).
    pub key: Option<String>,
    /// Backup directory (may start with `~`).
    pub backup_dir: Option<String>,
    /// How many recent backups to keep; 0 = unlimited (no rotation).
    pub backup_keep: Option<usize>,
}

impl Config {
    /// Path of the config file. Defaults to `~/.dotvault/config.toml`, but can
    /// be overridden via the `DOTVAULT_CONFIG` env var (useful for tests).
    pub fn path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("DOTVAULT_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        let home = home_dir().context("could not determine home directory for config")?;
        Ok(home.join(".dotvault").join("config.toml"))
    }

    /// Load config from `~/.dotvault/config.toml`. Returns an empty `Config`
    /// (all fields `None`) if the file does not exist — never an error for
    /// a missing file.
    pub fn load() -> Result<Config> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let cfg: Config = toml::from_str(&text)
                    .with_context(|| format!("failed to parse config at {}", path.display()))?;
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    /// Write config to its path, creating parent dirs. Atomic (temp + rename).
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("failed to serialize config")?;
        write_atomic(&path, text.as_bytes())
    }

    /// Effective backup keep count: config value, else 0 (no rotation).
    /// This is the single source of truth for rotation behavior.
    pub fn backup_keep(&self) -> usize {
        self.backup_keep.unwrap_or(0)
    }

    /// Effective key path (tilde-expanded), or `None` if unset.
    pub fn key_path(&self) -> Option<PathBuf> {
        self.key.as_deref().map(expand_tilde)
    }

    /// Effective backup dir (tilde-expanded), or `None` if unset.
    pub fn backup_dir_path(&self) -> Option<PathBuf> {
        self.backup_dir.as_deref().map(expand_tilde)
    }
}

/// Expand a leading `~` (or `~user`) to the home directory. Falls back to the
/// original path if HOME cannot be determined.
pub fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~") {
        // Only handle bare `~` or `~/...`; leave `~user` untouched.
        if rest.is_empty() || rest.starts_with('/') {
            if let Some(home) = home_dir() {
                return home.join(rest.trim_start_matches('/'));
            }
        }
    }
    PathBuf::from(s)
}

/// Resolve the user's home directory. `HOME` is checked first (it's the
/// authority on Unix and is honored when set by Cygwin/MSYS/test harnesses);
/// Windows falls back to `USERPROFILE` when `HOME` is unset.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// Atomic write: temp file in the same dir, then rename.
fn write_atomic(dest: &Path, data: &[u8]) -> Result<()> {
    let dir = dest
        .parent()
        .with_context(|| format!("no parent dir for {}", dest.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        dest.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("dotvault")
    ));
    std::fs::write(&tmp, data).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, dest).with_context(|| format!("failed to install {}", dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// Serialize tests that mutate process-global env vars (HOME,
    /// DOTVAULT_CONFIG). Parallel env mutation makes tests flaky; this guard
    /// ensures only one env-touching test runs at a time within this binary.
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

    env_test!(expand_tilde_bare_and_slash, {
        let old = std::env::var_os("HOME");
        std::env::set_var("HOME", "/home/test");
        assert_eq!(expand_tilde("~"), PathBuf::from("/home/test"));
        assert_eq!(
            expand_tilde("~/foo/bar"),
            PathBuf::from("/home/test/foo/bar")
        );
        // Restore HOME so we don't poison other tests.
        match old {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    });

    #[test]
    fn expand_tilde_no_tilde_left_untouched() {
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
        assert_eq!(
            expand_tilde("relative/path"),
            PathBuf::from("relative/path")
        );
    }

    #[test]
    fn expand_tilde_user_not_expanded() {
        // ~user is not expanded (would need getpwuid); left as-is.
        assert_eq!(expand_tilde("~root/x"), PathBuf::from("~root/x"));
    }

    #[test]
    fn default_config_has_nothing_set() {
        let c = Config::default();
        assert_eq!(c.key, None);
        assert_eq!(c.backup_dir, None);
        assert_eq!(c.backup_keep, None);
        assert_eq!(c.backup_keep(), 0); // 0 = no rotation
    }

    #[test]
    fn toml_round_trip() {
        let c = Config {
            key: Some("~/ssh/key".into()),
            backup_dir: Some("~/.dotvault/backups".into()),
            backup_keep: Some(25),
        };
        let text = toml::to_string_pretty(&c).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(c, back);
    }

    env_test!(load_missing_file_returns_empty, {
        // Point config at a path that doesn't exist; load must not error.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        std::env::set_var("DOTVAULT_CONFIG", &missing);
        let cfg = Config::load().unwrap();
        assert_eq!(cfg, Config::default());
        std::env::remove_var("DOTVAULT_CONFIG");
    });

    env_test!(save_then_load_round_trip_on_disk, {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::env::set_var("DOTVAULT_CONFIG", &path);

        let c = Config {
            key: Some("~/.ssh/id_rsa".into()),
            backup_dir: Some("~/.dotvault/backups".into()),
            backup_keep: Some(10),
        };
        c.save().unwrap();
        assert!(path.exists(), "save should create the file");
        let loaded = Config::load().unwrap();
        assert_eq!(loaded, c);

        std::env::remove_var("DOTVAULT_CONFIG");
    });

    env_test!(load_malformed_file_errors, {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, b"this is = = not toml").unwrap();
        std::env::set_var("DOTVAULT_CONFIG", &path);
        let err = Config::load().unwrap_err();
        assert!(format!("{err}").contains("failed to parse"));
        std::env::remove_var("DOTVAULT_CONFIG");
    });
}
