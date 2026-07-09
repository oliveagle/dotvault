//! Export/list rendering: collect the single project vault's entries and
//! render them as `.env`-compatible output with a `# === <label> ===` header.
//!
//! (Pre-v0.4 this module merged a global namespace with the project's; that
//! global/override model was removed when storage became project-local.)

use std::io::Write;

use anyhow::Result;

use crate::vault::Vault;

/// One entry: key, value.
#[derive(Clone)]
pub struct Entry {
    pub key: String,
    pub value: String,
}

/// A rendered section: label + its entries.
pub type Sections = Vec<(String, Vec<Entry>)>;

/// Collect a single section from the loaded vault. The label is derived from
/// the project directory name (falling back to "project").
pub fn collect_sections(vault: &Vault) -> Sections {
    let label = vault
        .dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("project")
        .to_string();
    let entries: Vec<Entry> = vault
        .entries
        .iter()
        .map(|(k, v)| Entry {
            key: k.clone(),
            value: v.clone(),
        })
        .collect();
    if entries.is_empty() {
        Vec::new()
    } else {
        vec![(label, entries)]
    }
}

/// Render sections as `KEY=VALUE` lines with `# === label ===` headers (export).
pub fn render_kv<W: Write>(out: &mut W, sections: &Sections) -> Result<()> {
    for (label, entries) in sections {
        writeln!(out, "# === {label} ===")?;
        for e in entries {
            writeln!(out, "{}={}", e.key, e.value)?;
        }
        writeln!(out)?;
    }
    Ok(())
}

/// Render sections as KEY names only with `# === label ===` headers (list).
pub fn render_keys<W: Write>(out: &mut W, sections: &Sections) -> Result<()> {
    for (label, entries) in sections {
        writeln!(out, "# === {label} ===")?;
        for e in entries {
            writeln!(out, "{}", e.key)?;
        }
        writeln!(out)?;
    }
    Ok(())
}
