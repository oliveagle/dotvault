//! Per-subcommand logic (v0.4: project-local, multi-recipient vault).

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::access::{self};
use crate::vault;

/// Resolve and load the SSH key path from explicit flag / env / default.
/// Warns on stderr when the default key is used implicitly.
fn key_path(explicit: Option<&Path>) -> Result<PathBuf> {
    let (path, used_default) = resolve_ssh_key_path(explicit)?;
    if used_default {
        eprintln!(
            "warning: no --key given and DOTVAULT_KEY unset; using default key {}",
            path.display()
        );
    }
    Ok(path)
}

/// Resolve the SSH key path: `--key` flag → `DOTVAULT_KEY` env → config →
/// default `~/.ssh/id_ed25519`. Returns the path + whether the default was
/// used implicitly (for a warning).
fn resolve_ssh_key_path(explicit: Option<&Path>) -> Result<(PathBuf, bool)> {
    if let Some(p) = explicit {
        return Ok((p.to_path_buf(), false));
    }
    if let Some(p) = std::env::var_os("DOTVAULT_KEY") {
        return Ok((PathBuf::from(p), false));
    }
    if let Ok(cfg) = crate::config::Config::load() {
        if let Some(p) = cfg.key_path() {
            return Ok((p, false));
        }
    }
    // Default.
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("HOME not set; cannot locate default SSH key")?;
    Ok((home.join(".ssh").join("id_ed25519"), true))
}

/// Derive the public-key line for the initial recipient during `init`.
/// Reads `<ssh_key_path>.pub` if it exists; otherwise derives the public key
/// from the private key.
fn pubkey_line_for(ssh_key_path: &Path) -> Result<String> {
    let pub_path = ssh_key_path.with_extension("pub");
    if pub_path.is_file() {
        let text = std::fs::read_to_string(&pub_path)
            .with_context(|| format!("failed to read {}", pub_path.display()))?;
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .context("public key file is empty")?;
        return Ok(line.to_string());
    }
    // Derive from the private key.
    let sk = crate::crypto::load_private_key(ssh_key_path)?;
    crate::crypto::pubkey_to_line(sk.public_key())
}

/// Initialize a new project vault: write `.vault` (empty) + `.vault.keys`
/// seeded with the current user's public key.
pub fn init(key: &Option<PathBuf>) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let pubkey_line = pubkey_line_for(&kp)?;
    let v = vault::Vault::init(&kp, &pubkey_line)?;
    let fp = crate::crypto::ssh_fingerprint(&v.ssh_key);
    eprintln!(
        "Initialized project vault at {} ({} authorized key)",
        v.dir.join(vault::VAULT_FILE).display(),
        v.keys.len()
    );
    eprintln!("  your key: {}", fp);
    eprintln!();
    eprintln!("Next: `dotvault set NAME VALUE` to add a secret.");
    eprintln!("      `dotvault add-key <PUBKEY>` to authorize a teammate.");
    Ok(())
}

/// `dotvault install` — global environment setup: create `~/.dotvault` +
/// default config + install the agent skill. Idempotent; no secrets stored.
pub fn install(key: &Option<PathBuf>) -> Result<()> {
    println!("dotvault install — environment setup\n");

    let global_dir = vault::dotvault_home()?;
    ensure_dir(&global_dir, "global dir")?;
    ensure_dir(&global_dir.join("backups"), "backups")?;

    let cfg_path = crate::config::Config::path()?;
    println!("\n[config]");
    if cfg_path.exists() {
        println!("  exists, left untouched: {}", cfg_path.display());
        print_effective_config(&crate::config::Config::load()?);
    } else {
        let cfg = crate::config::Config {
            key: Some("~/.ssh/id_ed25519".to_string()),
            backup_dir: Some("~/.dotvault/backups".to_string()),
            backup_keep: Some(50),
        };
        cfg.save()?;
        println!("  created with defaults: {}", cfg_path.display());
        print_effective_config(&cfg);
    }

    println!("\n[ssh key]");
    check_default_ssh_key();

    println!("\n[project vault]");
    let vpath = vault::vault_path()?;
    if vpath.exists() {
        println!("  bound: {}", vpath.display());
    } else {
        println!("  no vault in this project");
        println!("  hint: run `dotvault init` to create one");
    }

    println!("\n[skill]");
    crate::skill::install(&global_dir)?;

    println!("\nDone. Next: `dotvault init` then `dotvault set NAME VALUE`.");
    let _ = key;
    Ok(())
}

pub fn set(key: &Option<PathBuf>, name: &str, value: &str) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let mut v = vault::Vault::load(&kp)?;
    v.set(name, value)?;
    v.save()?;
    eprintln!("Set {}", name);
    Ok(())
}

pub fn get(key: &Option<PathBuf>, name: &str) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    get_to(key, name, &mut lock)
}

pub fn get_to<W: Write>(key: &Option<PathBuf>, name: &str, out: &mut W) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let v = vault::Vault::load(&kp)?;
    match v.get(name) {
        Some(val) => {
            out.write_all(val.as_bytes())?;
            Ok(())
        }
        None => bail!("no such secret: {}", name),
    }
}

pub fn rm(key: &Option<PathBuf>, name: &str) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let mut v = vault::Vault::load(&kp)?;
    if !v.remove(name) {
        bail!("no such secret: {}", name);
    }
    v.save()?;
    eprintln!("Removed {}", name);
    Ok(())
}

pub fn list(key: &Option<PathBuf>) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    list_to(key, &mut lock)
}

pub fn list_to<W: Write>(key: &Option<PathBuf>, out: &mut W) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let v = vault::Vault::load(&kp)?;
    let sections = crate::export_render::collect_sections(&v);
    if sections.is_empty() {
        eprintln!("(vault is empty)");
    }
    crate::export_render::render_keys(out, &sections)
}

pub fn export(key: &Option<PathBuf>) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    export_to(key, &mut lock)
}

pub fn export_to<W: Write>(key: &Option<PathBuf>, out: &mut W) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let v = vault::Vault::load(&kp)?;
    let sections = crate::export_render::collect_sections(&v);
    crate::export_render::render_kv(out, &sections)
}

/// Add a recipient's public key to the vault and re-encrypt so they can
/// decrypt. `spec` is an authorized-keys line, a `*.pub` file path, or
/// `@file` reference.
pub fn add_key(key: &Option<PathBuf>, spec: &str) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let pubkey_line = access::resolve_pubkey_spec(spec)?;
    let mut v = vault::Vault::load(&kp)?;
    let fp = v.add_key(&pubkey_line)?;
    println!("Added key {} (now {} authorized)", fp, v.keys.len());
    Ok(())
}

/// Remove a recipient by fingerprint or label and re-encrypt.
pub fn remove_key(key: &Option<PathBuf>, query: &str) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let mut v = vault::Vault::load(&kp)?;
    let removed = v.remove_key(query)?;
    println!(
        "Removed key {} ({}) — {} authorized remain",
        removed.fingerprint,
        removed.label,
        v.keys.len()
    );
    eprintln!("note: this does NOT revoke access to ciphertext already in git history;");
    eprintln!("      rotate secret values if a true revocation is required.");
    Ok(())
}

/// List the authorized recipients.
pub fn list_keys(key: &Option<PathBuf>) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let v = vault::Vault::load(&kp)?;
    let my_fp = crate::crypto::ssh_fingerprint(&v.ssh_key);
    if v.keys.is_empty() {
        eprintln!("(no authorized keys)");
    }
    for k in &v.keys.keys {
        let mark = if k.fingerprint == my_fp { " *" } else { "  " };
        println!("{}{}  {}", mark, k.fingerprint, k.label);
    }
    eprintln!("\n(*) = matches the key used for this command");
    Ok(())
}

/// `dotvault version` — print build details.
pub fn version() -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    version_to(&mut lock)
}

pub fn version_to<W: Write>(out: &mut W) -> Result<()> {
    let ver = env!("CARGO_PKG_VERSION");
    let hash = option_env!("DOTVAULT_GIT_HASH").unwrap_or("unknown");
    let dirty = option_env!("DOTVAULT_GIT_DIRTY").unwrap_or("false") == "true";
    let built = option_env!("DOTVAULT_BUILD_TIME").unwrap_or("unknown");
    let rustc = option_env!("DOTVAULT_RUSTC").unwrap_or("unknown");
    let target = option_env!("DOTVAULT_TARGET").unwrap_or("unknown");
    let hash_disp = if dirty {
        format!("{hash} (dirty)")
    } else {
        hash.to_string()
    };
    writeln!(out, "dotvault {ver}")?;
    writeln!(out, "commit: {hash_disp}")?;
    writeln!(out, "built:  {built}")?;
    writeln!(out, "rustc:  {rustc}")?;
    writeln!(out, "target: {target}")?;

    if let Some(latest) = crate::update::cached_latest_release_tag() {
        if crate::update::is_newer(&latest, ver) {
            eprintln!("update: {latest} available");
        }
    }
    Ok(())
}

/// Verify the project vault: decrypt, report entries + authorized keys.
pub fn doctor(key: &Option<PathBuf>) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    doctor_to(key, &mut lock)
}

pub fn doctor_to<W: Write>(key: &Option<PathBuf>, out: &mut W) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let v = match vault::Vault::load(&kp) {
        Ok(v) => v,
        Err(e) => bail!("doctor: could not open vault: {e:#}"),
    };
    let my_fp = crate::crypto::ssh_fingerprint(&v.ssh_key);
    writeln!(
        out,
        "vault           : {}",
        v.dir.join(vault::VAULT_FILE).display()
    )?;
    writeln!(out, "entries         : {}", v.entries.len())?;
    writeln!(out, "authorized keys : {}", v.keys.len())?;
    for k in &v.keys.keys {
        let mark = if k.fingerprint == my_fp { "*" } else { " " };
        writeln!(out, "  {mark} {}  {}", k.fingerprint, k.label)?;
    }
    writeln!(out, "status          : OK")?;
    Ok(())
}

pub fn config(
    set_key: &Option<String>,
    set_backup_dir: &Option<String>,
    set_backup_keep: &Option<usize>,
) -> Result<()> {
    let path = crate::config::Config::path()?;
    let mut cfg = crate::config::Config::load()?;
    let mut changed = false;
    if let Some(k) = set_key {
        cfg.key = Some(normalize_path_value(k));
        changed = true;
    }
    if let Some(d) = set_backup_dir {
        cfg.backup_dir = Some(normalize_path_value(d));
        changed = true;
    }
    if let Some(n) = set_backup_keep {
        cfg.backup_keep = Some(*n);
        changed = true;
    }
    if changed {
        cfg.save()?;
        eprintln!("Updated config at {}", path.display());
    }
    println!("# {}", path.display());
    if cfg == crate::config::Config::default() {
        println!("# (empty — all fields unset; dotvault uses built-in defaults)");
    } else {
        print!("{}", toml::to_string_pretty(&cfg).unwrap_or_default());
    }
    Ok(())
}

// ---------- helpers ----------

fn ensure_dir(dir: &Path, label: &str) -> Result<()> {
    if dir.exists() {
        println!("  {label}: exists, left untouched");
    } else {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        println!("  {label}: created");
    }
    Ok(())
}

fn print_effective_config(cfg: &crate::config::Config) {
    match &cfg.key {
        Some(k) => println!("    key = {k}"),
        None => println!("    # key unset"),
    }
    match &cfg.backup_dir {
        Some(d) => println!("    backup_dir = {d}"),
        None => println!("    # backup_dir unset"),
    }
    let keep = cfg.backup_keep.unwrap_or(0);
    let desc = if keep == 0 {
        "0 (unlimited)".to_string()
    } else {
        keep.to_string()
    };
    println!("    backup_keep = {desc}");
}

fn check_default_ssh_key() {
    let home = match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        Some(h) => PathBuf::from(h),
        None => {
            println!("  HOME unset; cannot locate default key");
            return;
        }
    };
    let default_key = home.join(".ssh").join("id_ed25519");
    if !default_key.exists() {
        println!("  default key not found: {}", default_key.display());
        println!("  hint: pass --key <path> or run `dotvault config --set-key <path>`");
        return;
    }
    println!("  found: {}", default_key.display());
    match std::fs::read_to_string(&default_key) {
        Ok(pem) => {
            if pem
                .trim_start()
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
            {
                println!("  format: OpenSSH (good)");
            } else if pem.trim_start().starts_with("-----BEGIN ") {
                println!(
                    "  format: legacy PEM — convert with ssh-keygen -p -m PEM -f {}",
                    default_key.display()
                );
            } else {
                println!("  format: unrecognized");
            }
        }
        Err(e) => println!("  could not read key: {e}"),
    }
    let pub_key = default_key.with_extension("pub");
    if pub_key.exists() {
        println!(
            "  pubkey: {} (used as the initial recipient)",
            pub_key.display()
        );
    } else {
        println!("  pubkey: not found — `dotvault init` will derive it from the private key");
    }
}

fn normalize_path_value(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed == "~" {
        return "~".to_string();
    }
    trimmed.trim_end_matches('/').to_string()
}
