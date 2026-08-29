//! Entry-level diff and merge over two (or three) decrypted vault documents.
//!
//! `.vault` is an encrypted binary, so git cannot diff or merge it natively.
//! These pure functions operate on [`VaultDoc`]s so a git conflict is resolved
//! by decrypting both sides (`git show :2:.vault` / `git show :3:.vault`) and
//! merging at entry granularity:
//!
//! - keys live on only one side are kept;
//! - with a merge base (3-way, `git show :1:.vault`), a key changed on one
//!   side and untouched on the other takes the changed version;
//! - divergent keys (changed on both sides, or changed-vs-deleted) are
//!   resolved by the [`MergeStrategy`] — `newest` (default, uses the entries'
//!   `modified_at` metadata), `ours`, or `theirs`.
//!
//! Nothing is silently lost: whenever merge picks a winner, the losing value
//! is archived into the merged doc's history (`reason = "merge"`), so it stays
//! recoverable via `dotvault history` / `dotvault restore`.

use anyhow::{bail, Result};

use crate::util;
use crate::vaultdoc::{EntryRecord, VaultDoc};

// ---------- diff ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffKind {
    /// Key only in B (the "new" side).
    Added,
    /// Key only in A.
    Removed,
    /// Key in both with different hashes.
    Changed,
}

#[derive(Clone, Debug)]
pub struct DiffEntry {
    pub kind: DiffKind,
    pub key: String,
    pub a: Option<EntryRecord>,
    pub b: Option<EntryRecord>,
}

/// Compare the live entries of two docs. Keys are reported in sorted order so
/// output is deterministic.
pub fn diff_docs(a: &VaultDoc, b: &VaultDoc) -> Vec<DiffEntry> {
    let mut keys: Vec<&str> = a
        .entries
        .iter()
        .map(|e| e.key.as_str())
        .chain(b.entries.iter().map(|e| e.key.as_str()))
        .collect();
    keys.sort_unstable();
    keys.dedup();

    keys.into_iter()
        .filter_map(|k| {
            let ea = a.get(k);
            let eb = b.get(k);
            match (ea, eb) {
                (Some(x), Some(y)) if x.hash == y.hash => None, // identical
                (Some(x), Some(y)) => Some(DiffEntry {
                    kind: DiffKind::Changed,
                    key: k.to_string(),
                    a: Some(x.clone()),
                    b: Some(y.clone()),
                }),
                (None, Some(y)) => Some(DiffEntry {
                    kind: DiffKind::Added,
                    key: k.to_string(),
                    a: None,
                    b: Some(y.clone()),
                }),
                (Some(x), None) => Some(DiffEntry {
                    kind: DiffKind::Removed,
                    key: k.to_string(),
                    a: Some(x.clone()),
                    b: None,
                }),
                (None, None) => None, // unreachable: k came from one of the docs
            }
        })
        .collect()
}

// ---------- merge ----------

/// How divergent keys (changed on both sides) are resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeStrategy {
    /// Take the version with the later `modified_at` (ties are an error).
    Newest,
    /// Always take our side.
    Ours,
    /// Always take their side.
    Theirs,
}

impl MergeStrategy {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "newest" => Ok(Self::Newest),
            "ours" => Ok(Self::Ours),
            "theirs" => Ok(Self::Theirs),
            _ => bail!("unknown merge strategy {s:?} (expected newest|ours|theirs)"),
        }
    }
}

/// One line of the merge report: what happened to a key that needed deciding.
#[derive(Clone, Debug)]
pub struct MergeDecision {
    pub key: String,
    /// e.g. "took ours (theirs changed, ours untouched)",
    /// "newest → theirs (2026-08-07 > 2026-08-06)",
    /// "conflict (both changed) → ours by strategy",
    /// "dropped (changed here, deleted there)".
    pub note: String,
}

/// Union-deduplicate history records from all inputs by
/// (key, hash, superseded_at) — same version superseded identically on both
/// branches appears once.
fn union_history(parts: &[&VaultDoc]) -> Vec<crate::vaultdoc::HistoryRecord> {
    let mut out: Vec<crate::vaultdoc::HistoryRecord> = Vec::new();
    for doc in parts {
        for h in &doc.history {
            let dup = out
                .iter()
                .any(|x| x.key == h.key && x.hash == h.hash && x.superseded_at == h.superseded_at);
            if !dup {
                out.push(h.clone());
            }
        }
    }
    out
}

fn newer(rec: &EntryRecord, other: &EntryRecord, key: &str) -> Result<bool> {
    let (a, b) = (
        util::parse_iso_to_unix(&rec.modified_at),
        util::parse_iso_to_unix(&other.modified_at),
    );
    match (a, b) {
        (Some(a), Some(b)) if a != b => Ok(a > b),
        _ => bail!(
            "cannot order versions of {key:?} by modified_at ({:?} vs {:?}); \
             use --strategy ours|theirs",
            rec.modified_at,
            other.modified_at
        ),
    }
}

/// Merge two vault docs, optionally 3-way against `base`.
///
/// Returns the merged doc (loser values archived in history, reason "merge")
/// plus a human-readable decision log. `now` stamps the archive entries.
pub fn merge_docs(
    ours: &VaultDoc,
    theirs: &VaultDoc,
    base: Option<&VaultDoc>,
    strategy: MergeStrategy,
    now: &str,
) -> Result<(VaultDoc, Vec<MergeDecision>)> {
    let mut merged = VaultDoc::default();
    let mut decisions = Vec::new();
    // (loser record to archive, note) — archived after entry insertion.
    let mut losers: Vec<(EntryRecord, String)> = Vec::new();

    let mut keys: Vec<&str> = ours
        .entries
        .iter()
        .map(|e| e.key.as_str())
        .chain(theirs.entries.iter().map(|e| e.key.as_str()))
        .collect();
    keys.sort_unstable();
    keys.dedup();

    for key in keys {
        let o = ours.get(key);
        let t = theirs.get(key);
        let b = base.and_then(|d| d.get(key));

        // Pick the winner (win) among (Some(rec), loser_opt, note).
        let (win, loser, note): (Option<EntryRecord>, Option<EntryRecord>, String) = match (o, t) {
            (Some(o), Some(t)) if o.hash == t.hash => (Some(o.clone()), None, String::new()),
            (Some(o), None) => {
                // Only ours: either we added it, or they deleted it.
                match b {
                    // They deleted (base had it); if we ALSO changed it,
                    // that's change-vs-delete — resolve by strategy.
                    Some(b) if o.hash != b.hash => match strategy {
                        MergeStrategy::Theirs => (
                            None,
                            Some(o.clone()),
                            "changed here, deleted there → dropped by strategy".into(),
                        ),
                        _ => (
                            Some(o.clone()),
                            None,
                            "kept ours (changed here, deleted there)".into(),
                        ),
                    },
                    // Untouched on our side; their deletion wins.
                    Some(_) => (None, None, "deleted on their side".into()),
                    None => (Some(o.clone()), None, String::new()), // our add
                }
            }
            (None, Some(t)) => match b {
                // We deleted, they changed it.
                Some(b) if t.hash != b.hash => match strategy {
                    MergeStrategy::Ours => (
                        None,
                        Some(t.clone()),
                        "changed there, deleted here → dropped by strategy".into(),
                    ),
                    _ => (
                        Some(t.clone()),
                        None,
                        "kept theirs (changed there, deleted here)".into(),
                    ),
                },
                Some(_) => (None, None, "deleted on our side".into()),
                None => (Some(t.clone()), None, String::new()), // their add
            },
            (Some(o), Some(t)) => {
                // Present on both sides with different values.
                let ours_changed = b.map(|b| o.hash != b.hash).unwrap_or(true);
                let theirs_changed = b.map(|b| t.hash != b.hash).unwrap_or(true);
                if ours_changed && !theirs_changed {
                    (
                        Some(o.clone()),
                        None,
                        "took ours (only ours changed)".into(),
                    )
                } else if !ours_changed && theirs_changed {
                    (
                        Some(t.clone()),
                        None,
                        "took theirs (only theirs changed)".into(),
                    )
                } else {
                    // True conflict: both changed (or no base to tell).
                    match strategy {
                        MergeStrategy::Ours => (
                            Some(o.clone()),
                            Some(t.clone()),
                            "conflict (both changed) → ours by strategy".into(),
                        ),
                        MergeStrategy::Theirs => (
                            Some(t.clone()),
                            Some(o.clone()),
                            "conflict (both changed) → theirs by strategy".into(),
                        ),
                        MergeStrategy::Newest => {
                            if newer(t, o, key)? {
                                (
                                    Some(t.clone()),
                                    Some(o.clone()),
                                    format!(
                                        "newest → theirs ({} > {})",
                                        t.modified_at, o.modified_at
                                    ),
                                )
                            } else {
                                (
                                    Some(o.clone()),
                                    Some(t.clone()),
                                    format!(
                                        "newest → ours ({} > {})",
                                        o.modified_at, t.modified_at
                                    ),
                                )
                            }
                        }
                    }
                }
            }
            (None, None) => continue, // unreachable
        };

        if let Some(rec) = win {
            merged.entries.push(rec);
        }
        if let Some(l) = loser {
            losers.push((l, note.clone()));
        }
        if !note.is_empty() {
            decisions.push(MergeDecision {
                key: key.to_string(),
                note,
            });
        }
    }

    // Archive the losers so a merge never silently destroys a value.
    for (l, _) in losers {
        merged.history.push(crate::vaultdoc::HistoryRecord {
            key: l.key,
            value: l.value,
            modified_at: l.modified_at,
            hash: l.hash,
            actor: l.actor,
            superseded_at: now.to_string(),
            reason: "merge".to_string(),
        });
    }

    // Union history from all inputs (their deletes/overwrites are already
    // recorded there and must survive the merge).
    let parts: Vec<&VaultDoc> = base.iter().copied().chain([ours, theirs]).collect();
    merged.history.extend(union_history(&parts));
    // Drop duplicates we may have just created (loser archived above AND
    // already present via a side's history for identical (key,hash,stamp)).
    let mut seen: Vec<(String, String, String)> = Vec::new();
    merged.history.retain(|h| {
        let id = (h.key.clone(), h.hash.clone(), h.superseded_at.clone());
        if seen.contains(&id) {
            false
        } else {
            seen.push(id);
            true
        }
    });

    Ok((merged, decisions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vaultdoc::VaultDoc;

    const T1: &str = "2026-08-01T00:00:00Z";
    const T2: &str = "2026-08-02T00:00:00Z";
    const T3: &str = "2026-08-03T00:00:00Z";

    fn doc(pairs: &[(&str, &str, &str)], now: &str) -> VaultDoc {
        // (key, value, modified_at)
        let mut d = VaultDoc::default();
        for (k, v, t) in pairs {
            d.insert(k, v, t, None).unwrap();
        }
        let _ = now;
        d
    }

    #[test]
    fn diff_reports_add_remove_change() {
        let a = doc(&[("A", "1", T1), ("B", "1", T1), ("C", "1", T1)], T1);
        let b = doc(&[("A", "1", T1), ("B", "2", T2), ("D", "1", T2)], T2);
        let d = diff_docs(&a, &b);
        let kinds: Vec<(&str, DiffKind)> = d.iter().map(|e| (e.key.as_str(), e.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                ("B", DiffKind::Changed),
                ("C", DiffKind::Removed),
                ("D", DiffKind::Added),
            ]
        );
        // Identical docs → empty diff.
        assert!(diff_docs(&a, &a).is_empty());
    }

    #[test]
    fn merge_two_way_newest_picks_later_change() {
        let ours = doc(&[("SHARED", "ours-val", T2), ("ONLY_OURS", "x", T1)], T2);
        let theirs = doc(
            &[("SHARED", "theirs-val", T3), ("ONLY_THEIRS", "y", T1)],
            T3,
        );
        let (m, dec) = merge_docs(&ours, &theirs, None, MergeStrategy::Newest, T3).unwrap();
        // Newest wins (theirs at T3).
        assert_eq!(m.get("SHARED").unwrap().value, "theirs-val");
        // Single-sided keys survive.
        assert_eq!(m.get("ONLY_OURS").unwrap().value, "x");
        assert_eq!(m.get("ONLY_THEIRS").unwrap().value, "y");
        // The loser was archived.
        assert!(m
            .history
            .iter()
            .any(|h| h.key == "SHARED" && h.value == "ours-val" && h.reason == "merge"));
        assert!(dec
            .iter()
            .any(|d| d.key == "SHARED" && d.note.contains("theirs")));
    }

    #[test]
    fn merge_two_way_unorderable_errors() {
        let ours = doc(&[("K", "a", T2)], T2);
        let theirs = doc(&[("K", "b", T2)], T2); // same timestamp, different value
        assert!(merge_docs(&ours, &theirs, None, MergeStrategy::Newest, T3).is_err());
        // Explicit strategy still resolves it.
        let (m, _) = merge_docs(&ours, &theirs, None, MergeStrategy::Ours, T3).unwrap();
        assert_eq!(m.get("K").unwrap().value, "a");
    }

    #[test]
    fn merge_three_way_takes_single_sided_change() {
        let base = doc(
            &[("K1", "old", T1), ("K2", "old", T1), ("K3", "old", T1)],
            T1,
        );
        // ours: K1 changed; K2 deleted. theirs: K2 changed; K3 deleted.
        let mut ours = base.clone();
        ours.overwrite("K1", "ours-new", T2, None).unwrap();
        ours.remove("K2", T2, None);
        let mut theirs = base.clone();
        theirs.overwrite("K2", "theirs-new", T3, None).unwrap();
        theirs.remove("K3", T3, None);

        let (m, _) = merge_docs(&ours, &theirs, Some(&base), MergeStrategy::Newest, T3).unwrap();
        assert_eq!(m.get("K1").unwrap().value, "ours-new"); // only ours changed
        assert_eq!(m.get("K2").unwrap().value, "theirs-new"); // only theirs changed
        assert!(m.get("K3").is_none()); // both agree on deleting
                                        // History from both sides survived the union.
        assert!(m.history.iter().any(|h| h.key == "K1" && h.value == "old"));
        assert!(m.history.iter().any(|h| h.key == "K2" && h.value == "old"));
    }

    #[test]
    fn merge_change_vs_delete_defaults_to_keep() {
        let base = doc(&[("K", "old", T1)], T1);
        let mut ours = base.clone();
        ours.overwrite("K", "edited", T2, None).unwrap(); // we changed it
        let mut theirs = base.clone();
        theirs.remove("K", T2, None); // they deleted it
        let (m, dec) = merge_docs(&ours, &theirs, Some(&base), MergeStrategy::Newest, T3).unwrap();
        // Default (newest/ours) keeps the edited value; recoverable either way.
        assert_eq!(m.get("K").unwrap().value, "edited");
        assert!(dec[0].note.contains("deleted there"));
        // strategy=theirs drops it (and their delete already archived it).
        let (m2, _) = merge_docs(&ours, &theirs, Some(&base), MergeStrategy::Theirs, T3).unwrap();
        assert!(m2.get("K").is_none());
        assert!(m2
            .history
            .iter()
            .any(|h| h.key == "K" && h.value == "edited"));
    }

    #[test]
    fn strategy_parse() {
        assert_eq!(
            MergeStrategy::parse("newest").unwrap(),
            MergeStrategy::Newest
        );
        assert!(MergeStrategy::parse("bogus").is_err());
    }
}
