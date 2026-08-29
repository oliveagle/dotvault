//! The decrypted document format inside `.vault` (v2).
//!
//! Historically the plaintext was a bare `.env` document (`KEY=VALUE` lines).
//! That format cannot carry per-entry metadata or history, so v0.8 upgraded
//! the internal format to a TOML document (with a magic first line
//! `# dotvault-doc-v2`) holding:
//!
//! - `[[entries]]` — the live secrets, each with `value`, `modified_at`
//!   (ISO-8601), `hash` (sha256 of the value — identifies a version without
//!   revealing it), and `actor` (SSH-key fingerprint of the writer, if known).
//! - `[[history]]` — superseded versions (overwritten / deleted / lost a
//!   merge), each with the same fields plus `superseded_at` and a `reason`.
//!   This is what makes a clobbered key recoverable (`dotvault history` +
//!   `dotvault restore`) and is pruned by age on every save (default 365
//!   days, see `config --set-history-days`).
//!
//! Backward compatibility: a plaintext WITHOUT the magic line parses as the
//! legacy `.env` format (entries get fresh metadata stamped at load time) and
//! is rewritten in v2 on the next save. NOTE: the reverse is not true —
//! dotvault ≤0.7 misreads v2 vaults, so a team must upgrade before anyone
//! writes v2.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::envfmt;
use crate::util;

/// Magic first line marking a v2 vault document (a TOML comment, so the doc
/// stays valid TOML).
pub const DOC_MAGIC: &str = "# dotvault-doc-v2";

/// sha256 of a secret value, `sha256:<hex>`. Identifies a version in diffs,
/// history listings and restore lookups without exposing the value.
pub fn hash_value(v: &str) -> String {
    let mut h = Sha256::new();
    h.update(v.as_bytes());
    let digest = h.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("sha256:{hex}")
}

/// One live entry: the secret plus its audit metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EntryRecord {
    pub key: String,
    pub value: String,
    /// ISO-8601 UTC when this version of the value was written.
    pub modified_at: String,
    /// [`hash_value`] of `value`.
    pub hash: String,
    /// SSH-key fingerprint of the writer, when known (token writes are
    /// rejected, so this is effectively always present for real writes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

/// One superseded version kept for recovery. `modified_at` is when that
/// version was created; `superseded_at` is when it stopped being live.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HistoryRecord {
    pub key: String,
    pub value: String,
    pub modified_at: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    pub superseded_at: String,
    /// Why it was superseded: "delete" | "overwrite" | "merge" | "restore".
    #[serde(default)]
    pub reason: String,
}

/// The full decrypted document.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct VaultDoc {
    #[serde(default)]
    pub entries: Vec<EntryRecord>,
    #[serde(default)]
    pub history: Vec<HistoryRecord>,
}

impl VaultDoc {
    /// Build a doc from legacy `(key, value)` pairs, stamping fresh metadata
    /// (`modified_at` = now, no actor — the original write time is unknowable
    /// from the ciphertext alone).
    pub fn from_legacy_pairs(pairs: Vec<(String, String)>, now: &str) -> Self {
        let entries = pairs
            .into_iter()
            .map(|(key, value)| EntryRecord {
                hash: hash_value(&value),
                key,
                value,
                modified_at: now.to_string(),
                actor: None,
            })
            .collect();
        Self {
            entries,
            history: Vec::new(),
        }
    }

    /// Serialize to the v2 TOML plaintext (magic line first).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("failed to serialize vault document: {e}"))?;
        Ok(format!("{DOC_MAGIC}\n{body}").into_bytes())
    }

    /// Parse a decrypted plaintext: v2 if it starts with the magic line,
    /// otherwise the legacy `.env` format (auto-migration source).
    pub fn from_bytes(plaintext: &[u8], now: &str) -> Result<Self> {
        let text = String::from_utf8_lossy(plaintext);
        if text.trim_start().starts_with(DOC_MAGIC) {
            let body = text.trim_start().strip_prefix(DOC_MAGIC).unwrap_or("");
            let doc: VaultDoc = toml::from_str(body)
                .map_err(|e| anyhow!("vault document is corrupted (v2 parse failed): {e}"))?;
            return Ok(doc);
        }
        let pairs =
            envfmt::parse(&text).context("vault document is corrupted (failed to parse)")?;
        Ok(Self::from_legacy_pairs(pairs, now))
    }

    // ---------- entry access ----------

    pub fn get(&self, key: &str) -> Option<&EntryRecord> {
        self.entries.iter().find(|e| e.key == key)
    }

    /// Live entries as plain `(key, value)` pairs (for export/render).
    pub fn kv_pairs(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect()
    }

    /// Insert a NEW entry (errors if the key exists — same fail-fast contract
    /// as `dotvault set`).
    pub fn insert(&mut self, key: &str, value: &str, now: &str, actor: Option<&str>) -> Result<()> {
        if self.get(key).is_some() {
            return Err(anyhow!(
                "secret {:?} already exists; run `dotvault rm {}` first to replace it",
                key,
                key
            ));
        }
        self.entries.push(EntryRecord {
            key: key.to_string(),
            value: value.to_string(),
            modified_at: now.to_string(),
            hash: hash_value(value),
            actor: actor.map(str::to_string),
        });
        Ok(())
    }

    /// Remove an entry, archiving the current version into history
    /// (`reason = "delete"`). Returns `false` if the key was absent.
    pub fn remove(&mut self, key: &str, now: &str, actor: Option<&str>) -> bool {
        let Some(pos) = self.entries.iter().position(|e| e.key == key) else {
            return false;
        };
        let rec = self.entries.remove(pos);
        self.archive(rec, now, "delete", actor);
        true
    }

    /// Replace an entry's value, archiving the prior version into history
    /// (`reason = "overwrite"`). Used by `restore` and any explicit
    /// overwrite path.
    pub fn overwrite(
        &mut self,
        key: &str,
        value: &str,
        now: &str,
        actor: Option<&str>,
    ) -> Result<()> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.key == key)
            .with_context(|| format!("no such secret: {key}"))?;
        let old = self.entries.remove(pos);
        self.archive(old, now, "overwrite", actor);
        self.entries.push(EntryRecord {
            key: key.to_string(),
            value: value.to_string(),
            modified_at: now.to_string(),
            hash: hash_value(value),
            actor: actor.map(str::to_string),
        });
        Ok(())
    }

    fn archive(&mut self, rec: EntryRecord, now: &str, reason: &str, actor: Option<&str>) {
        self.history.push(HistoryRecord {
            key: rec.key,
            value: rec.value,
            modified_at: rec.modified_at,
            hash: rec.hash,
            actor: rec.actor.or_else(|| actor.map(str::to_string)),
            superseded_at: now.to_string(),
            reason: reason.to_string(),
        });
    }

    /// Find history versions of `key` whose hash starts with `hash_prefix`
    /// (with or without the `sha256:` prefix). Returns them newest-first by
    /// `superseded_at`. Errors if the prefix matches nothing; the caller
    /// decides what to do with multiple distinct values.
    pub fn find_history(&self, key: &str, hash_prefix: &str) -> Result<Vec<&HistoryRecord>> {
        let want = hash_prefix
            .strip_prefix("sha256:")
            .unwrap_or(hash_prefix)
            .to_lowercase();
        let mut hits: Vec<&HistoryRecord> = self
            .history
            .iter()
            .filter(|h| {
                h.key == key
                    && h.hash
                        .strip_prefix("sha256:")
                        .unwrap_or(&h.hash)
                        .starts_with(&want)
            })
            .collect();
        if hits.is_empty() {
            return Err(anyhow!(
                "no history version of {:?} matches hash prefix {:?} (see `dotvault history {key}`)",
                key,
                hash_prefix
            ));
        }
        hits.sort_by(|a, b| b.superseded_at.cmp(&a.superseded_at));
        Ok(hits)
    }

    // ---------- history rotation ----------

    /// Drop history records whose `superseded_at` is older than `keep_days`
    /// days before `now` (ISO stamps). `keep_days == 0` keeps everything.
    /// Records with an unparseable stamp are kept (fail-safe).
    pub fn prune_history(&mut self, keep_days: u64, now: &str) {
        if keep_days == 0 {
            return;
        }
        let cutoff = util::parse_iso_to_unix(now).map(|t| t - (keep_days as i64) * 86_400);
        let Some(cutoff) = cutoff else {
            return; // can't establish "now" — keep everything
        };
        self.history
            .retain(|h| match util::parse_iso_to_unix(&h.superseded_at) {
                Some(t) => t >= cutoff,
                None => true,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-08-06T12:00:00Z";

    #[test]
    fn hash_value_is_stable_and_prefixed() {
        assert_eq!(hash_value("x"), hash_value("x"));
        assert_ne!(hash_value("x"), hash_value("y"));
        assert!(hash_value("x").starts_with("sha256:"));
    }

    #[test]
    fn v2_roundtrip() {
        let mut doc = VaultDoc::default();
        doc.insert("A", "1", NOW, Some("SHA256:actor1")).unwrap();
        doc.insert("B", "two words", NOW, None).unwrap();
        doc.remove("A", "2026-08-07T00:00:00Z", Some("SHA256:actor1"));

        let bytes = doc.to_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("# dotvault-doc-v2"), "magic line first");

        let back = VaultDoc::from_bytes(&bytes, NOW).unwrap();
        assert_eq!(back, doc);
        assert_eq!(back.kv_pairs(), vec![("B".into(), "two words".into())]);
    }

    #[test]
    fn legacy_env_parses_and_gets_fresh_metadata() {
        let legacy = b"A=1\nB=two words\n";
        let doc = VaultDoc::from_bytes(legacy, NOW).unwrap();
        assert_eq!(doc.kv_pairs().len(), 2);
        let a = doc.get("A").unwrap();
        assert_eq!(a.modified_at, NOW);
        assert_eq!(a.hash, hash_value("1"));
        assert!(a.actor.is_none());
        assert!(doc.history.is_empty());
    }

    #[test]
    fn insert_refuses_duplicate() {
        let mut doc = VaultDoc::default();
        doc.insert("A", "1", NOW, None).unwrap();
        assert!(doc.insert("A", "2", NOW, None).is_err());
    }

    #[test]
    fn remove_archives_into_history() {
        let mut doc = VaultDoc::default();
        doc.insert("A", "v1", "2026-08-01T00:00:00Z", Some("SHA256:act"))
            .unwrap();
        assert!(doc.remove("A", NOW, Some("SHA256:act")));
        assert!(doc.get("A").is_none());
        assert_eq!(doc.history.len(), 1);
        let h = &doc.history[0];
        assert_eq!(h.key, "A");
        assert_eq!(h.value, "v1");
        assert_eq!(h.reason, "delete");
        assert_eq!(h.superseded_at, NOW);
        // Removing an absent key is a no-op (false), no history pollution.
        assert!(!doc.remove("A", NOW, None));
        assert_eq!(doc.history.len(), 1);
    }

    #[test]
    fn overwrite_archives_prior_version() {
        let mut doc = VaultDoc::default();
        doc.insert("A", "v1", "2026-08-01T00:00:00Z", None).unwrap();
        doc.overwrite("A", "v2", NOW, Some("SHA256:act")).unwrap();
        assert_eq!(doc.get("A").unwrap().value, "v2");
        assert_eq!(doc.history.len(), 1);
        assert_eq!(doc.history[0].reason, "overwrite");
        assert_eq!(doc.history[0].value, "v1");
        // Overwriting a missing key errors.
        assert!(doc.overwrite("NOPE", "x", NOW, None).is_err());
    }

    #[test]
    fn find_history_by_prefix() {
        let mut doc = VaultDoc::default();
        doc.insert("A", "v1", "2026-08-01T00:00:00Z", None).unwrap();
        doc.overwrite("A", "v2", "2026-08-02T00:00:00Z", None)
            .unwrap();
        doc.overwrite("A", "v3", "2026-08-03T00:00:00Z", None)
            .unwrap();

        let full = hash_value("v1");
        let prefix = full.strip_prefix("sha256:").unwrap()[..8].to_string();
        let hits = doc.find_history("A", &prefix).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, "v1");
        // sha256: prefix accepted too.
        assert_eq!(doc.find_history("A", &full).unwrap().len(), 1);
        // Wrong key / unknown prefix error out.
        assert!(doc.find_history("B", &prefix).is_err());
        assert!(doc.find_history("A", "deadbeef").is_err());
    }

    #[test]
    fn prune_keeps_recent_and_unparseable() {
        let mut doc = VaultDoc::default();
        doc.insert("A", "v1", "2025-01-01T00:00:00Z", None).unwrap();
        doc.overwrite("A", "v2", "2026-08-06T00:00:00Z", None)
            .unwrap();
        // history[0]: superseded 2026-08-06 (recent) → kept with 365d cutoff.
        doc.prune_history(365, NOW);
        assert_eq!(doc.history.len(), 1);

        // Now fabricate an old superseded_at (2 years back) + an unparseable one.
        doc.history[0].superseded_at = "2024-01-01T00:00:00Z".into();
        doc.history.push(HistoryRecord {
            key: "X".into(),
            value: "junk".into(),
            modified_at: NOW.into(),
            hash: hash_value("junk"),
            actor: None,
            superseded_at: "garbage".into(),
            reason: "delete".into(),
        });
        doc.prune_history(365, NOW);
        // The old one is gone; the unparseable one is kept (fail-safe).
        assert_eq!(doc.history.len(), 1);
        assert_eq!(doc.history[0].key, "X");

        // keep_days == 0 keeps everything.
        doc.history[0].superseded_at = "2020-01-01T00:00:00Z".into();
        doc.prune_history(0, NOW);
        assert_eq!(doc.history.len(), 1);
    }
}
