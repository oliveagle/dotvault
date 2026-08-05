//! `{{KEY}}` template rendering.
//!
//! A minimal mustache-style substitution: every `{{KEY}}` (with optional
//! inner whitespace, e.g. `{{ KEY }}`) is replaced by the value of the secret
//! named `KEY` from the vault. Names follow the same `[A-Za-z_][A-Za-z0-9_]*`
//! rule as `set`, so a template can never reference a key that `.env` export
//! itself couldn't represent.
//!
//! Semantics (fail-fast, matching the rest of dotvault):
//!
//! - A placeholder whose name is NOT in the vault is a hard error — we never
//!   emit a half-rendered file with a dangling placeholder or an empty hole.
//! - `{{` without a matching `}}`, or a placeholder whose inner text is not a
//!   valid name, is a malformed-template error.
//! - Matching is exact (whole name), so `{{DB}}` never accidentally substitutes
//!   the value of `DB_PASSWORD`.
//! - Non-placeholder `{` / `}` characters pass through untouched, so templates
//!   may contain JSON / YAML / Go templates / shell `${VAR}` literals freely.

use std::collections::HashMap;

use anyhow::{bail, Result};

/// Render `template` by substituting every `{{KEY}}` with the matching value
/// from `entries`. See the module docs for the exact rules.
pub fn render(template: &str, entries: &[(String, String)]) -> Result<String> {
    // Build an exact-match lookup so `{{DB}}` can't match `DB_PASSWORD`.
    let mut map: HashMap<&str, &str> = HashMap::with_capacity(entries.len());
    for (k, v) in entries {
        map.insert(k.as_str(), v.as_str());
    }

    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'{' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let start = i; // index of the opening `{{`
                           // Find the closing `}}`.
            let mut j = i + 2;
            let mut closed = false;
            while j + 1 < bytes.len() {
                if bytes[j] == b'}' && bytes[j + 1] == b'}' {
                    closed = true;
                    break;
                }
                j += 1;
            }
            if !closed {
                bail!(
                    "malformed template: unclosed `{{{{` at line {} (no matching `}}}}`)",
                    line_of(template, start)
                );
            }
            let inner = &template[i + 2..j];
            let name = inner.trim();
            if !is_valid_name(name) {
                bail!(
                    "malformed placeholder `{{{{{} }}}}` at line {} (must match [A-Za-z_][A-Za-z0-9_]*)",
                    inner,
                    line_of(template, start)
                );
            }
            match map.get(name) {
                Some(val) => out.push_str(val),
                None => bail!(
                    "template references unknown secret {:?} (line {})\n  hint: run `dotvault set {} <value>`",
                    name,
                    line_of(template, start),
                    name
                ),
            }
            i = j + 2; // skip past `}}`
        } else {
            // Copy the whole UTF-8 char starting at `i`. `{` and `}` are
            // single-byte ASCII, so they never appear as UTF-8 continuation
            // bytes — landing here on a non-`{` lead byte means the rest of
            // the char is safe to copy wholesale (fixes multi-byte corruption
            // from a naive byte-by-byte copy).
            let ch_end = next_char_boundary(template, i);
            out.push_str(&template[i..ch_end]);
            i = ch_end;
        }
    }
    Ok(out)
}

/// 1-based line number of the byte `offset` within `template`.
fn line_of(template: &str, offset: usize) -> usize {
    template[..offset.min(template.len())].matches('\n').count() + 1
}

/// End byte index of the UTF-8 char that starts at `start`. `start` MUST be a
/// char boundary. Derived from the lead byte's prefix-one count (RFC 3629).
fn next_char_boundary(s: &str, start: usize) -> usize {
    let b = s.as_bytes()[start];
    let len = if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    };
    (start + len).min(s.len())
}

/// Same `[A-Za-z_][A-Za-z0-9_]*` rule as secret names (`src/main.rs`).
fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(String, String)> {
        vec![
            ("DB_PASSWORD".to_string(), "s3cret".to_string()),
            ("API_TOKEN".to_string(), "ghp_xxx".to_string()),
            ("PORT".to_string(), "5432".to_string()),
        ]
    }

    #[test]
    fn basic_substitution() {
        let out = render("password: {{DB_PASSWORD}}", &entries()).unwrap();
        assert_eq!(out, "password: s3cret");
    }

    #[test]
    fn whitespace_inside_braces() {
        let out = render("{{  DB_PASSWORD  }}", &entries()).unwrap();
        assert_eq!(out, "s3cret");
    }

    #[test]
    fn multiple_placeholders() {
        let tmpl = "db={{DB_PASSWORD}} token={{API_TOKEN}} port={{PORT}}";
        let out = render(tmpl, &entries()).unwrap();
        assert_eq!(out, "db=s3cret token=ghp_xxx port=5432");
    }

    #[test]
    fn same_placeholder_repeated() {
        let out = render("a={{PORT}} b={{PORT}}", &entries()).unwrap();
        assert_eq!(out, "a=5432 b=5432");
    }

    #[test]
    fn exact_name_match_no_false_substring() {
        // `DB` is NOT a key (only `DB_PASSWORD` is) → hard error.
        let err = render("{{DB}}", &entries()).unwrap_err();
        assert!(format!("{err}").contains("unknown secret"), "{err}");
    }

    #[test]
    fn unknown_key_errors_with_line_and_hint() {
        let tmpl = "line1\nline2: {{MISSING}}";
        let err = render(tmpl, &entries()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown secret"), "{msg}");
        assert!(msg.contains("\"MISSING\""), "{msg}");
        assert!(msg.contains("line 2"), "{msg}");
        assert!(msg.contains("dotvault set MISSING"), "{msg}");
    }

    #[test]
    fn unclosed_braces_error() {
        let err = render("hello {{DB_PASSWORD", &entries()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unclosed"), "{msg}");
        assert!(msg.contains("line 1"), "{msg}");
    }

    #[test]
    fn malformed_placeholder_name_error() {
        // Empty + digit-leading names are not valid.
        let err = render("{{}}", &entries()).unwrap_err();
        assert!(
            format!("{err}").contains("malformed placeholder"),
            "got: {err}"
        );
        let err = render("{{1bad}}", &entries()).unwrap_err();
        assert!(
            format!("{err}").contains("malformed placeholder"),
            "got: {err}"
        );
    }

    #[test]
    fn no_placeholders_pass_through_unchanged() {
        let tmpl = "just some { text } with single braces and $VAR";
        let out = render(tmpl, &entries()).unwrap();
        assert_eq!(out, tmpl);
    }

    #[test]
    fn single_braces_pass_through() {
        // A lone `{` or `}` (not doubled) is literal text.
        let out = render("{ not a placeholder }", &entries()).unwrap();
        assert_eq!(out, "{ not a placeholder }");
    }

    #[test]
    fn value_with_braces_and_dollars_passes_through_literally() {
        // A secret value that itself contains `${...}` or `{` must be inserted
        // verbatim — we never re-scan substituted text for placeholders.
        let entries = vec![("X".to_string(), "${env.INJECT}".to_string())];
        let out = render("v={{X}}", &entries).unwrap();
        assert_eq!(out, "v=${env.INJECT}");
    }

    #[test]
    fn empty_template_ok() {
        let out = render("", &entries()).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn empty_vault_with_placeholder_errors() {
        // No entries at all → any placeholder is unknown.
        let err = render("{{X}}", &[]).unwrap_err();
        assert!(format!("{err}").contains("unknown secret"), "{err}");
    }

    #[test]
    fn empty_vault_no_placeholders_ok() {
        let out = render("plain text, no refs", &[]).unwrap();
        assert_eq!(out, "plain text, no refs");
    }

    #[test]
    fn adjacent_placeholders() {
        let out = render("{{PORT}}{{PORT}}", &entries()).unwrap();
        assert_eq!(out, "54325432");
    }

    #[test]
    fn unicode_in_template_text_passes_through() {
        let out = render("密码: {{DB_PASSWORD}} ✓", &entries()).unwrap();
        assert_eq!(out, "密码: s3cret ✓");
    }
}
