//! `dotvault render` command, split out of `commands.rs` for file-size hygiene.
//!
//! Renders a template file by substituting `{{KEY}}` placeholders with secret
//! values from the vault. See `crate::template` for the substitution rules.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use std::path::PathBuf;

use crate::commands_auth::load_vault;

/// Load the vault, read the template file, and substitute every `{{KEY}}`
/// with the matching secret value. Returns the fully-rendered document.
///
/// Hard-fails (no half-rendered output) when a placeholder names a secret not
/// in the vault, or when the template has malformed `{{...}}` syntax. See
/// `crate::template`.
fn render_core(key: &Option<PathBuf>, token: &Option<String>, template: &Path) -> Result<String> {
    let tmpl = std::fs::read_to_string(template)
        .with_context(|| format!("failed to read template {}", template.display()))?;
    let v = load_vault(key, token)?;
    crate::template::render(&tmpl, &v.doc.kv_pairs())
}

/// Render `template` and write the result to `out`. Used by tests; the CLI
/// entry point is `render`.
pub fn render_to<W: Write>(
    key: &Option<PathBuf>,
    token: &Option<String>,
    template: &Path,
    out: &mut W,
) -> Result<()> {
    let rendered = render_core(key, token, template)?;
    out.write_all(rendered.as_bytes())?;
    Ok(())
}

/// `dotvault render`: render a template by substituting `{{KEY}}` placeholders
/// with secret values from the vault.
///
/// With `out = None`, the rendered document goes to stdout (raw bytes, no
/// appended newline) so it can be redirected. With `out = Some(path)`, it is
/// written atomically to `path` with mode `0600` (it contains secrets) and a
/// short confirmation is printed to stderr.
pub fn render(
    key: &Option<PathBuf>,
    token: &Option<String>,
    template: &Path,
    out: Option<&Path>,
) -> Result<()> {
    match out {
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            render_to(key, token, template, &mut lock)
        }
        Some(dest) => {
            let rendered = render_core(key, token, template)?;
            crate::util::write_secret_file(dest, rendered.as_bytes())?;
            eprintln!("Rendered {} → {}", template.display(), dest.display());
            #[cfg(unix)]
            eprintln!("  mode: 0600");
            Ok(())
        }
    }
}
