//! Diff / merge / history / restore — the entry-level tooling for vault
//! versions, split out of `commands.rs` for file-size hygiene.
//!
//! `.vault` is an encrypted binary, so git can neither diff nor merge it.
//! The workflow for a conflict:
//!
//! ```sh
//! git show :2:.vault > .vault.ours    # our stage
//! git show :3:.vault > .vault.theirs  # their stage
//! git show :1:.vault > .vault.base    # merge base (optional, 3-way)
//! dotvault diff .vault.ours .vault.theirs
//! dotvault merge .vault.ours .vault.theirs --base .vault.base -o .vault
//! ```
//!
//! `history` lists superseded versions recorded inside `.vault` (with
//! timestamps, hashes and the writer's key fingerprint — never the values);
//! `restore` brings one back by hash prefix.

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::commands_auth::{load_vault, require_ssh, resolve_auth, AuthMethod};
use crate::merge::{diff_docs, merge_docs, DiffKind, MergeStrategy};
use crate::vaultdoc::VaultDoc;

/// Decrypt an arbitrary vault FILE (not the project `.vault`) with whichever
/// auth method applies, returning its document.
fn decrypt_file(
    path: &Path,
    key: &Option<std::path::PathBuf>,
    token: &Option<String>,
) -> Result<VaultDoc> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let plaintext = match resolve_auth(key, token)? {
        AuthMethod::Token(t) => crate::crypto::decrypt_with_token(&t, &bytes)?,
        AuthMethod::Ssh(kp) => {
            let sk = crate::crypto::load_private_key(&kp)?;
            crate::crypto::decrypt_with_key(&sk, &bytes)?
        }
    };
    VaultDoc::from_bytes(&plaintext, &crate::util::now_iso())
}

/// Short display form of a `sha256:<hex>` hash (first 12 hex chars).
fn short_hash(h: &str) -> &str {
    let bare = h.strip_prefix("sha256:").unwrap_or(h);
    &bare[..bare.len().min(12)]
}

/// `dotvault diff A B`: entry-level comparison of two vault files. Values are
/// never printed — changes are identified by hash + timestamp. Exits with
/// code 1 when the documents differ (diff(1) convention), 0 when identical.
pub fn diff(
    key: &Option<std::path::PathBuf>,
    token: &Option<String>,
    a: &Path,
    b: &Path,
) -> Result<()> {
    let da = decrypt_file(a, key, token)?;
    let db = decrypt_file(b, key, token)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let n = print_diff(&da, &db, &mut out)?;
    if n > 0 {
        eprintln!("{n} difference(s)");
        std::process::exit(1);
    }
    Ok(())
}

/// Render an entry-level diff of two docs to `out`. Returns the number of
/// differences. (Split from `diff` so tests can exercise it without the
/// process exit.)
pub fn print_diff<W: Write>(da: &VaultDoc, db: &VaultDoc, out: &mut W) -> Result<usize> {
    let diffs = diff_docs(da, db);
    if diffs.is_empty() {
        writeln!(out, "vaults are identical ({} entries)", da.entries.len())?;
        return Ok(0);
    }
    for d in &diffs {
        match d.kind {
            DiffKind::Added => {
                let e = d.b.as_ref().expect("added has b");
                writeln!(
                    out,
                    "+ {:<24} added      {}  sha256:{}  actor={}",
                    d.key,
                    e.modified_at,
                    short_hash(&e.hash),
                    e.actor.as_deref().unwrap_or("?")
                )?;
            }
            DiffKind::Removed => {
                let e = d.a.as_ref().expect("removed has a");
                writeln!(
                    out,
                    "- {:<24} removed    {}  sha256:{}  actor={}",
                    d.key,
                    e.modified_at,
                    short_hash(&e.hash),
                    e.actor.as_deref().unwrap_or("?")
                )?;
            }
            DiffKind::Changed => {
                let (ea, eb) = (
                    d.a.as_ref().expect("changed has a"),
                    d.b.as_ref().expect("changed has b"),
                );
                writeln!(
                    out,
                    "~ {:<24} {} → {}  sha256:{} → {}",
                    d.key,
                    ea.modified_at,
                    eb.modified_at,
                    short_hash(&ea.hash),
                    short_hash(&eb.hash)
                )?;
            }
        }
    }
    Ok(diffs.len())
}

/// `dotvault merge OURS THEIRS [--base BASE] -o OUT`: entry-level merge of two
/// decrypted vault docs, re-encrypted to the project's current recipients and
/// written to OUT. Losers of divergent keys are archived into history.
pub fn merge(
    key: &Option<std::path::PathBuf>,
    token: &Option<String>,
    ours: &Path,
    theirs: &Path,
    base: Option<&Path>,
    strategy: &str,
    out: &Path,
) -> Result<()> {
    let auth = resolve_auth(key, token)?;
    require_ssh(&auth, "merge")?; // merge produces a new vault → SSH only
    let strategy = MergeStrategy::parse(strategy)?;

    let d_ours = decrypt_file(ours, key, token)?;
    let d_theirs = decrypt_file(theirs, key, token)?;
    let d_base = match base {
        Some(p) => Some(decrypt_file(p, key, token)?),
        None => None,
    };

    let now = crate::util::now_iso();
    let (merged, decisions) = merge_docs(&d_ours, &d_theirs, d_base.as_ref(), strategy, &now)?;

    // Re-encrypt to the project's CURRENT recipients (from .vault.keys).
    let kpath = crate::vault::keys_path()?;
    let keys = crate::access::load_keys(&kpath)?;
    let plaintext = merged.to_bytes()?;
    let container = crate::crypto::encrypt_to_recipients_with_tokens(
        &keys.pubkey_lines(),
        &keys.token_pubkeys(),
        &plaintext,
    )?;
    crate::util::write_atomic(out, &container)?;

    println!(
        "Merged {} + {} entries → {} ({} entries, {} history records)",
        d_ours.entries.len(),
        d_theirs.entries.len(),
        out.display(),
        merged.entries.len(),
        merged.history.len()
    );
    for d in &decisions {
        println!("  {:<24} {}", d.key, d.note);
    }
    if decisions.is_empty() {
        println!("  (no conflicts: all changes were single-sided or identical)");
    }
    eprintln!("note: history is rotated to the configured retention on the next save.");
    Ok(())
}

/// `dotvault history [KEY]`: list superseded versions recorded inside the
/// vault — never the values. Read-only (works with a token).
pub fn history(
    key: &Option<std::path::PathBuf>,
    token: &Option<String>,
    filter: &Option<String>,
) -> Result<()> {
    let v = load_vault(key, token)?;
    let records: Vec<&crate::vaultdoc::HistoryRecord> = match filter {
        Some(k) => {
            if v.doc.get(k).is_none() && !v.doc.history.iter().any(|h| &h.key == k) {
                bail!("no such secret: {k}");
            }
            v.doc.history.iter().filter(|h| &h.key == k).collect()
        }
        None => v.doc.history.iter().collect(),
    };
    if records.is_empty() {
        eprintln!(
            "(no history records{})",
            filter
                .as_deref()
                .map(|k| format!(" for {k}"))
                .unwrap_or_default()
        );
        return Ok(());
    }
    for h in records {
        println!(
            "{:<24} sha256:{:<13} {:<9} written {}  superseded {}  actor={}",
            h.key,
            short_hash(&h.hash),
            h.reason,
            h.modified_at,
            h.superseded_at,
            h.actor.as_deref().unwrap_or("?")
        );
    }
    eprintln!();
    eprintln!("recover a version: dotvault restore <KEY> <hash-prefix>");
    Ok(())
}

/// `dotvault restore KEY HASH_PREFIX`: bring a historical version back as the
/// live value (the current value is archived first). SSH-only (it writes).
pub fn restore(
    key: &Option<std::path::PathBuf>,
    token: &Option<String>,
    name: &str,
    hash: &str,
) -> Result<()> {
    let auth = resolve_auth(key, token)?;
    require_ssh(&auth, "restore")?;
    let mut v = load_vault(key, token)?;

    // Extract owned data first — find_history borrows v.doc immutably, and we
    // mutate the doc right after.
    let (value, hit_hash, hit_modified) = {
        let hits = v.doc.find_history(name, hash)?;
        let mut distinct: Vec<&str> = hits.iter().map(|h| h.value.as_str()).collect();
        distinct.dedup();
        if distinct.len() > 1 {
            bail!(
                "hash prefix {:?} matches {} DIFFERENT values for {:?}; use a longer prefix",
                hash,
                distinct.len(),
                name
            );
        }
        (
            distinct[0].to_string(),
            hits[0].hash.clone(),
            hits[0].modified_at.clone(),
        )
    };
    let actor = v.ssh_key.as_ref().map(crate::crypto::ssh_fingerprint);
    let now = crate::util::now_iso();
    let was_live = v.doc.get(name).is_some();
    if was_live {
        // Live value exists → archive it, then replace.
        v.doc
            .overwrite(name, &value, &now, actor.as_deref())
            .context("restore failed")?;
    } else {
        // The key was removed entirely → just bring the version back.
        v.doc
            .insert(name, &value, &now, actor.as_deref())
            .context("restore failed")?;
    }
    v.save()?;
    eprintln!(
        "Restored {} to version sha256:{} (written {})",
        name,
        short_hash(&hit_hash),
        hit_modified
    );
    if was_live {
        eprintln!("the previous value was archived into history.");
    }
    Ok(())
}
