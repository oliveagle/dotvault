//! Merged export/list rendering: collect global + project sections and render
//! them with `# === <ns> ===` comment headers (`.env`-compatible).

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use anyhow::Result;

use crate::access::AccessKey;
use crate::vault;

/// A rendered section: namespace label + its (key, value) entries.
pub type Sections = Vec<(String, Vec<(String, String)>)>;

/// Collect (namespace_label, entries) sections for merged output.
///
/// When `use_global` is set, only the global section is returned. Otherwise:
/// - global section always (if it exists), with project-overridden keys dropped
/// - project section (if a `.dotvault_key` exists), with all its keys
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
        let entries: Vec<(String, String)> = gv
            .entries
            .iter()
            .filter(|(k, _)| !project_keys.contains(k))
            .cloned()
            .collect();
        if !entries.is_empty() {
            sections.push(("global".to_string(), entries));
        }
    }
    if let Some(pv) = &project_v {
        if !pv.entries.is_empty() {
            sections.push((format!("namespace: {}", pv.namespace), pv.entries.clone()));
        }
    }
    Ok(sections)
}

/// Render sections as KEY=VALUE with `# === ns ===` headers (export).
pub fn render_kv<W: Write>(out: &mut W, sections: &Sections) -> Result<()> {
    for (ns, entries) in sections {
        writeln!(out, "# === {ns} ===")?;
        for (k, v) in entries {
            writeln!(out, "{k}={v}")?;
        }
        writeln!(out)?;
    }
    Ok(())
}

/// Render sections as KEY names only with `# === ns ===` headers (list).
pub fn render_keys<W: Write>(out: &mut W, sections: &Sections) -> Result<()> {
    for (ns, entries) in sections {
        writeln!(out, "# === {ns} ===")?;
        for (k, _) in entries {
            writeln!(out, "{k}")?;
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
