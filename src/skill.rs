//! Installing the dotvault ZCode skill: write SKILL.md to ~/.dotvault/skill/
//! and symlink it into ~/.agents/skills/dotvault so the agent discovers it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Install the skill: write SKILL.md to `<global_dir>/skill/` (idempotent —
/// never overwrites an existing file) and symlink `~/.agents/skills/dotvault`
/// at it (best-effort; skipped where symlinks aren't permitted).
pub fn install(global_dir: &Path) -> Result<()> {
    let skill_dir = global_dir.join("skill");
    let skill_file = skill_dir.join("SKILL.md");
    let embedded = include_str!("../skill/SKILL.md");

    std::fs::create_dir_all(&skill_dir)
        .with_context(|| format!("failed to create {}", skill_dir.display()))?;
    if skill_file.exists() {
        println!("  exists, left untouched: {}", skill_file.display());
    } else {
        std::fs::write(&skill_file, embedded.as_bytes())
            .with_context(|| format!("failed to write {}", skill_file.display()))?;
        println!("  wrote: {}", skill_file.display());
    }

    if let Some(agents_dir) = agents_skills_dir() {
        let link = agents_dir.join("dotvault");
        std::fs::create_dir_all(&agents_dir).ok();
        if link.exists() || symlink_exists(&link) {
            if let Ok(meta) = std::fs::symlink_metadata(&link) {
                if meta.file_type().is_symlink() {
                    let _ = std::fs::remove_file(&link);
                }
            }
        }
        if !link.exists() && !symlink_exists(&link) {
            match symlink(&skill_dir, &link) {
                Ok(()) => println!("  linked: {} -> {}", link.display(), skill_dir.display()),
                Err(e) => println!(
                    "  warning: could not link {} (skill is at {}): {e}",
                    link.display(),
                    skill_dir.display()
                ),
            }
        } else {
            println!("  link exists: {}", link.display());
        }
    } else {
        println!(
            "  (could not locate ~/.agents/skills; skill written to {} only)",
            skill_dir.display()
        );
    }
    Ok(())
}

/// Resolve `~/.agents/skills` (HOME/USERPROFILE based).
fn agents_skills_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".agents").join("skills"))
}

/// Whether a path is a symlink (cross-platform).
fn symlink_exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Create a symlink dir→target. On Unix this is std; on Windows it needs
/// elevated rights or dev mode, so we skip gracefully there.
#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}
#[cfg(not(unix))]
fn symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink not created on Windows automatically",
    ))
}
