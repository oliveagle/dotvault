//! Minimal `.env`-compatible document format.
//!
//! Each line is `KEY=VALUE`. Blank lines and lines starting with `#` (after
//! optional leading whitespace) are comments and skipped. Lines without an `=`
//! or with an empty key are also skipped (treated as comments). Values are raw
//! (no quoting/unquoting): whatever bytes follow the first `=` until end-of-line
//! are the value.
//!
//! Duplicate keys are an error: a vault document must have at most one entry
//! per key, so ambiguity can never sneak in silently.

use anyhow::{anyhow, Result};

/// Parse a `.env`-style document into an ordered list of `(key, value)` entries.
///
/// Comments, blank lines, and malformed lines (no `=` or empty key) are
/// skipped. Returns an error if the same key appears more than once — there is
/// no silent last-write-wins merge.
pub fn parse(doc: &str) -> Result<Vec<(String, String)>> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for (lineno, line) in doc.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(eq) = line.find('=') else {
            // No '=': skip silently as a comment-style line.
            continue;
        };
        let key = line[..eq].trim().to_string();
        if key.is_empty() {
            // Empty key (e.g. "=value"): skip silently.
            continue;
        }
        if entries.iter().any(|(k, _)| k == &key) {
            return Err(anyhow!(
                "duplicate key {:?} at line {} — vault document is ambiguous",
                key,
                lineno + 1
            ));
        }
        let value = line[eq + 1..].to_string();
        entries.push((key, value));
    }
    Ok(entries)
}

/// Serialize entries back to a `.env` document, one `KEY=VALUE` per line.
///
/// Output is always terminated with a trailing newline so concatenation and
/// redirection (`dotvault export > .env`) produce a clean file.
pub fn serialize(entries: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in entries {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_basic() {
        let doc = "A=1\nB=two words\nC=3\n";
        let entries = parse(doc).unwrap();
        assert_eq!(
            entries,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two words".into()),
                ("C".into(), "3".into()),
            ]
        );
        assert_eq!(serialize(&entries), doc);
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let doc = "# a comment\n\nKEY=val\n";
        let entries = parse(doc).unwrap();
        assert_eq!(entries, vec![("KEY".into(), "val".into())]);
    }

    #[test]
    fn value_can_contain_equals() {
        // First '=' splits; the rest is the value, untouched.
        let entries = parse("CONN=a=b=c\n").unwrap();
        assert_eq!(entries, vec![("CONN".into(), "a=b=c".into())]);
    }

    #[test]
    fn duplicate_keys_error() {
        // Duplicate keys must error, not silently merge.
        let err = parse("X=1\nX=2\n").unwrap_err();
        assert!(format!("{err}").contains("duplicate key"));
    }

    #[test]
    fn empty_value() {
        let entries = parse("EMPTY=\n").unwrap();
        assert_eq!(entries, vec![("EMPTY".into(), "".into())]);
    }

    #[test]
    fn lines_without_equals_are_skipped() {
        // No '=' and empty key lines are skipped (treated as comments), not errors.
        let entries = parse("not a kv line\n=value\nK=1\n").unwrap();
        assert_eq!(entries, vec![("K".into(), "1".into())]);
    }
}
