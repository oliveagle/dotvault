//! Per-subcommand logic (v0.2: centralized, namespaced storage).

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::access::AccessKey;
use crate::vault;

/// Resolve and load the SSH key path from explicit flag / env / default.
/// Warns on stderr when the default key is used implicitly.
fn key_path(explicit: Option<&Path>) -> Result<PathBuf> {
    let (path, used_default) = vault::Vault::resolve_key_path(explicit)?;
    if used_default {
        eprintln!(
            "warning: no --key given and DOTVAULT_KEY unset; using default key {}",
            path.display()
        );
    }
    Ok(path)
}

/// Read the project's `.dotvault_key`, load the named namespace, and verify the
/// Resolve which access-key file to read. Priority:
///   `--global` flag  →  ~/.dotvault/access_key (the global namespace)
///   else project has .dotvault_key  →  use it
///   else (fallback)  →  ~/.dotvault/access_key (global)
/// Returns the path to read + a label for diagnostics.
fn resolve_key_file(use_global: bool) -> Result<(PathBuf, &'static str)> {
    if use_global {
        return Ok((AccessKey::global_path()?, "global"));
    }
    let project = AccessKey::project_path()?;
    if project.exists() {
        Ok((project, "project"))
    } else {
        // Auto-fallback to global when no project binding.
        Ok((AccessKey::global_path()?, "global (fallback)"))
    }
}

/// Read the access-key file, load the named namespace, and verify the
/// access key authorizes it. Returns the loaded vault + the presented key.
fn load_authorized(key: &Option<PathBuf>, use_global: bool) -> Result<(vault::Vault, AccessKey)> {
    let kp = key_path(key.as_deref())?;
    let (key_file, _source) = resolve_key_file(use_global)?;
    let presented = AccessKey::read_from_project(&key_file).with_context(|| {
        format!(
            "no access key at {} (run `dotvault init <namespace>` or `dotvault install` to set up the global namespace)",
            key_file.display()
        )
    })?;
    let v = vault::Vault::load(&presented.namespace, &kp)?;
    v.verify_access_key(&presented)?;
    Ok((v, presented))
}

pub fn init(namespace: &str, key: &Option<PathBuf>) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let (v, access_key) = vault::Vault::init(namespace, &kp)?;
    let key_file = AccessKey::project_path()?;
    access_key.write_to_project(&key_file)?;
    eprintln!(
        "Initialized namespace {:?} (key {}) — wrote {}",
        namespace,
        v.meta.ssh_fingerprint,
        key_file.display()
    );
    Ok(())
}

pub fn install(key: &Option<PathBuf>) -> Result<()> {
    println!("dotvault install — environment setup\n");

    let global_dir = vault::dotvault_home()?;
    ensure_dir(&global_dir, "global dir")?;
    ensure_dir(&global_dir.join("backups"), "backups")?;
    ensure_dir(&global_dir.join("namespaces"), "namespaces")?;

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

    println!("\n[access keys]");
    let key_file = AccessKey::project_path()?;
    if key_file.exists() {
        let ak = AccessKey::read_from_project(&key_file)?;
        println!("  project bound to namespace {:?}", ak.namespace);
    } else {
        println!("  no .dotvault_key in this project");
        println!("  hint: run `dotvault init <namespace>` to bind one");
    }

    println!("\n[global namespace]");
    ensure_global_namespace(key)?;

    println!("\n[skill]");
    crate::skill::install(&global_dir)?;

    println!("\nDone. Next: `dotvault init <namespace>` then `dotvault set NAME VALUE`.");
    let _ = key;
    Ok(())
}

/// Create the `global` namespace + write ~/.dotvault/access_key, unless it
/// already exists. Idempotent. Best-effort: if the SSH key can't be resolved/
/// loaded, warn and skip (the rest of install still ran). This is the only
/// namespace `install` creates.
fn ensure_global_namespace(key: &Option<PathBuf>) -> Result<()> {
    let global_key_file = AccessKey::global_path()?;
    if global_key_file.exists() {
        println!("  exists, left untouched: {}", global_key_file.display());
        return Ok(());
    }
    // Creating a namespace needs the SSH key to encrypt the registry.
    let kp = match key_path(key.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            println!("  skipped (could not resolve SSH key: {e})");
            println!("  hint: pass --key <path> or set it via `dotvault config --set-key`");
            return Ok(());
        }
    };
    match vault::Vault::init(crate::vault::GLOBAL_NAMESPACE, &kp) {
        Ok((_v, ak)) => {
            ak.write_to_project(&global_key_file)?;
            println!(
                "  created namespace {:?} + wrote {}",
                crate::vault::GLOBAL_NAMESPACE,
                global_key_file.display()
            );
        }
        Err(e) => {
            // e.g. namespace dir already exists without the key file (partial state).
            println!("  could not create global namespace: {e:#}");
        }
    }
    Ok(())
}

pub fn ns_list() -> Result<()> {
    let names = vault::list_namespaces()?;
    if names.is_empty() {
        eprintln!("no namespaces yet");
    } else {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        for n in names {
            writeln!(lock, "{n}")?;
        }
    }
    Ok(())
}

pub fn ns_remove(namespace: &str, key: &Option<PathBuf>) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let removed = vault::remove_namespace(namespace, &kp)?;
    if removed {
        eprintln!("Removed namespace {:?}", namespace);
    } else {
        eprintln!("namespace {:?} did not exist", namespace);
    }
    Ok(())
}

pub fn set(key: &Option<PathBuf>, global: bool, name: &str, value: &str) -> Result<()> {
    let (mut v, _) = load_authorized(key, global)?;
    v.set(name, value)?;
    v.save()?;
    eprintln!("Set {} (namespace {:?})", name, v.namespace);
    Ok(())
}

pub fn get(key: &Option<PathBuf>, global: bool, name: &str) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    get_to(key, global, name, &mut lock)
}

pub fn get_to<W: Write>(
    key: &Option<PathBuf>,
    global: bool,
    name: &str,
    out: &mut W,
) -> Result<()> {
    let (v, _) = load_authorized(key, global)?;
    match v.get(name) {
        Some(val) => {
            out.write_all(val.as_bytes())?;
            Ok(())
        }
        None => anyhow::bail!("no such secret: {}", name),
    }
}

pub fn rm(key: &Option<PathBuf>, global: bool, name: &str) -> Result<()> {
    let (mut v, _) = load_authorized(key, global)?;
    if !v.remove(name) {
        anyhow::bail!("no such secret: {}", name);
    }
    v.save()?;
    eprintln!("Removed {} (namespace {:?})", name, v.namespace);
    Ok(())
}

pub fn list(key: &Option<PathBuf>, global: bool) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    list_to(key, global, &mut lock)
}

pub fn list_to<W: Write>(key: &Option<PathBuf>, global: bool, out: &mut W) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let sections = crate::export_render::collect_sections(&kp, global)?;
    crate::export_render::render_keys(out, &sections)
}

pub fn export(key: &Option<PathBuf>, global: bool) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    export_to(key, global, &mut lock)
}

pub fn export_to<W: Write>(key: &Option<PathBuf>, global: bool, out: &mut W) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let sections = crate::export_render::collect_sections(&kp, global)?;
    crate::export_render::render_kv(out, &sections)
}

pub fn rekey(key: &Option<PathBuf>, new_key: &Path) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let namespaces = vault::list_namespaces()?;
    if namespaces.is_empty() {
        anyhow::bail!("no namespaces to re-key");
    }
    for ns in &namespaces {
        let mut v = vault::Vault::load(ns, &kp)?;
        let new_fp = v.rekey(new_key)?;
        println!("Re-keyed namespace {:?} → {}", ns, new_fp);
    }
    eprintln!("Done. Remember to update your projects' SSH key access.");
    Ok(())
}

pub fn doctor(key: &Option<PathBuf>, global: bool) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    doctor_to(key, global, &mut lock)
}

/// `dotvault version` — print build details (version, git hash, build time,
/// rustc, target). The values are injected at compile time by build.rs.
pub fn version() -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    version_to(&mut lock)
}

pub fn version_to<W: Write>(out: &mut W) -> Result<()> {
    // env! reads values injected by build.rs; the fallback literal is used
    // when git wasn't available at build time.
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

    // Online update check (best-effort, cached 1h, never blocks/fails).
    // Goes to stderr so stdout stays parseable.
    if let Some(latest) = crate::update::cached_latest_release_tag() {
        if crate::update::is_newer(&latest, ver) {
            eprintln!("update: {latest} available (run: scripts/upgrade.sh or curl ... | bash)");
        }
    }
    Ok(())
}

pub fn doctor_to<W: Write>(key: &Option<PathBuf>, global: bool, out: &mut W) -> Result<()> {
    let kp = key_path(key.as_deref())?;
    let (key_file, source) = resolve_key_file(global)?;
    if !key_file.exists() {
        anyhow::bail!(
            "doctor: no access key at {} (run `dotvault init <namespace>` or `dotvault install`)",
            key_file.display()
        );
    }
    let ak = AccessKey::read_from_project(&key_file)?;
    let v = vault::Vault::load(&ak.namespace, &kp)?;
    v.verify_access_key(&ak)?;
    writeln!(out, "namespace       : {}", v.namespace)?;
    writeln!(out, "source          : {source}")?;
    writeln!(out, "entries         : {}", v.entries.len())?;
    writeln!(out, "ssh fingerprint : {}", v.meta.ssh_fingerprint)?;
    writeln!(out, "created         : {}", v.meta.created_at)?;
    writeln!(out, "updated         : {}", v.meta.updated_at)?;
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
}

fn normalize_path_value(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed == "~" {
        return "~".to_string();
    }
    trimmed.trim_end_matches('/').to_string()
}
