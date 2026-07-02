//! Merged export/list rendering: collect global + project sections and render
//! them with `# === <ns> ===` comment headers (`.env`-compatible).
//!
//! A key defined in both global and project is "overridden": the project's
//! value wins, and in the global section the overridden key is shown as a
//! commented-out line (`# KEY  # overridden by project`) for debuggability
//! — it's invisible to `.env` tools but visible to humans.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use anyhow::Result;

use crate::access::AccessKey;
use crate::vault;

/// One entry: key, value, and whether it was overridden (only meaningful in
/// the global section, where project keys shadow it).
#[derive(Clone)]
pub struct Entry {
    pub key: String,
    pub value: String,
    pub overridden: bool,
}

/// A rendered section: namespace label + its entries.
pub type Sections = Vec<(String, Vec<Entry>)>;

/// Collect (namespace_label, entries) sections for merged output.
///
/// When `use_global` is set, only the global section is returned. Otherwise:
/// - global section always (if it exists); keys overridden by the project are
///   kept but marked `overridden = true` (rendered as comments)
/// - project section (if a `.dotvault_key` exists), with all its keys active
pub fn collect_sections(kp: &Path, use_global: bool) -> Result<Sections> {
    let global_v = load_ns_by_keyfile(kp, &AccessKey::global_path()?)?;
    let project_v = if !use_global {
        let proj_path = AccessKey::project_path()?;
        if proj_path.exists() {
            load_ns_by_keyfile(kp, &proj_path)?
        } else {
            None
        }
    } else {
        None
    };

    let project_keys: HashSet<&String> = project_v
        .iter()
        .flat_map(|v| v.entries.iter().map(|(k, _)| k))
        .collect();

    let mut sections = Vec::new();
    if let Some(gv) = &global_v {
        let entries: Vec<Entry> = gv
            .entries
            .iter()
            .map(|(k, v)| Entry {
                key: k.clone(),
                value: v.clone(),
                overridden: project_keys.contains(k),
            })
            .filter(|e| !e.overridden || !use_global) // hide overridden when --global-only
            .collect();
        if !entries.is_empty() {
            sections.push(("global".to_string(), entries));
        }
    }
    if let Some(pv) = &project_v {
        let entries: Vec<Entry> = pv
            .entries
            .iter()
            .map(|(k, v)| Entry {
                key: k.clone(),
                value: v.clone(),
                overridden: false,
            })
            .collect();
        if !entries.is_empty() {
            sections.push((format!("namespace: {}", pv.namespace), entries));
        }
    }
    Ok(sections)
}

/// Render sections as KEY=VALUE with `# === ns ===` headers (export).
/// Overridden entries appear as `# KEY  # overridden by project`.
pub fn render_kv<W: Write>(out: &mut W, sections: &Sections) -> Result<()> {
    for (ns, entries) in sections {
        writeln!(out, "# === {ns} ===")?;
        for e in entries {
            if e.overridden {
                writeln!(out, "# {}  # overridden by project", e.key)?;
            } else {
                writeln!(out, "{}={}", e.key, e.value)?;
            }
        }
        writeln!(out)?;
    }
    Ok(())
}

/// Render sections as KEY names only with `# === ns ===` headers (list).
pub fn render_keys<W: Write>(out: &mut W, sections: &Sections) -> Result<()> {
    for (ns, entries) in sections {
        writeln!(out, "# === {ns} ===")?;
        for e in entries {
            if e.overridden {
                writeln!(out, "# {}  # overridden by project", e.key)?;
            } else {
                writeln!(out, "{}", e.key)?;
            }
        }
        writeln!(out)?;
    }
    Ok(())
}

/// Load the namespace named by an access-key file. Returns None if the file
/// doesn't exist; errors on a real load/verify failure.
fn load_ns_by_keyfile(kp: &Path, key_file: &Path) -> Result<Option<vault::Vault>> {
    if !key_file.exists() {
        return Ok(None);
    }
    let presented = AccessKey::read_from_project(key_file)?;
    let v = vault::Vault::load(&presented.namespace, kp)?;
    v.verify_access_key(&presented)?;
    Ok(Some(v))
}
