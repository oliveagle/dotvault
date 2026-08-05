//! Auth-method dispatch + read-only token commands, split out of `commands.rs`
//! for file-size hygiene.
//!
//! `AuthMethod` decides whether the caller authenticates with an SSH key (full
//! read+write) or a read-only X25519 token. Write commands call `require_ssh`
//! to reject token auth. The three token-management subcommands
//! (`add-token` / `list-tokens` / `revoke-token`) live here too.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::vault;

/// How the caller is authenticating to the vault.
#[derive(Clone)]
pub(crate) enum AuthMethod {
    /// SSH private key at this path — full access (read + write).
    Ssh(PathBuf),
    /// Read-only X25519 token (`AGE-SECRET-KEY-1...`) — read access only.
    Token(String),
}

/// Reject write commands when authenticating with a token. Read commands call
/// this as a guard; it's a no-op for SSH auth. The `action` noun appears in the
/// error so users know what was blocked.
pub(crate) fn require_ssh(auth: &AuthMethod, action: &str) -> Result<()> {
    match auth {
        AuthMethod::Ssh(_) => Ok(()),
        AuthMethod::Token(_) => bail!(
            "tokens are read-only: `{action}` requires an SSH key (--key). \
             Use a teammate's SSH key for write operations."
        ),
    }
}

/// Load the vault using whichever auth method applies. `token` wins if both
/// are given (the CLI rejects that combination, but defense-in-depth here).
pub(crate) fn load_vault(key: &Option<PathBuf>, token: &Option<String>) -> Result<vault::Vault> {
    match resolve_auth(key, token)? {
        AuthMethod::Token(t) => vault::Vault::load_with_token(&t),
        AuthMethod::Ssh(kp) => vault::Vault::load(&kp),
    }
}

/// Decide the auth method from the CLI flags. Validates mutual exclusivity and
/// resolves the SSH key path (with the default-key warning) when applicable.
pub(crate) fn resolve_auth(key: &Option<PathBuf>, token: &Option<String>) -> Result<AuthMethod> {
    match (key, token) {
        (Some(_), Some(_)) => bail!("--key and --token are mutually exclusive; pass only one"),
        (None, Some(t)) => Ok(AuthMethod::Token(t.clone())),
        (kp, None) => {
            // Also honor DOTVAULT_TOKEN when no explicit flag is given.
            if let Some(t) = std::env::var_os("DOTVAULT_TOKEN") {
                return Ok(AuthMethod::Token(t.to_string_lossy().into_owned()));
            }
            Ok(AuthMethod::Ssh(crate::commands::key_path(kp.as_deref())?))
        }
    }
}

// ---------- read-only token commands (X25519) ----------

/// `dotvault add-token`: generate a new read-only token, authorize it
/// (append its `age1...` public key to `.vault.keys` and re-encrypt the vault
/// so the token can decrypt), and print the token SECRET to stdout ONCE.
///
/// The secret (`AGE-SECRET-KEY-1...`) is what goes into a CI environment
/// variable. It is never stored by dotvault — copy it now or regenerate.
pub fn add_token(key: &Option<PathBuf>, token: &Option<String>, label: &str) -> Result<()> {
    let auth = resolve_auth(key, token)?;
    require_ssh(&auth, "add-token")?;
    let mut v = load_vault(key, token)?;
    let secret = v.add_token(label)?;
    // The secret goes to stdout (so it can be captured/redirected); everything
    // else to stderr so it never mixes into a capture.
    eprintln!(
        "Authorized token {:?} ({} token{} now).",
        label,
        v.keys.token_count(),
        if v.keys.token_count() == 1 { "" } else { "s" }
    );
    eprintln!("⚠  This token is shown ONCE. Store it in your CI secret store now.");
    eprintln!("   If lost, revoke and re-add it.");
    eprintln!();
    eprintln!("Use it in CI with:");
    eprintln!("  dotvault --token \"$DOTVAULT_TOKEN\" get NAME");
    // The secret itself — raw, no trailing newline, so it captures cleanly.
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(secret.as_bytes())?;
    Ok(())
}

/// `dotvault list-tokens`: list authorized read-only tokens (label + public
/// key). The secret is never shown (it isn't stored).
pub fn list_tokens(key: &Option<PathBuf>, token: &Option<String>) -> Result<()> {
    let v = load_vault(key, token)?;
    if v.keys.token_count() == 0 {
        eprintln!("(no authorized tokens)");
    }
    for t in &v.keys.tokens {
        println!("{}  {}", t.public_key, t.label);
    }
    eprintln!();
    eprintln!("To use a token in CI: dotvault --token \"$DOTVAULT_TOKEN\" export > .env");
    Ok(())
}

/// `dotvault revoke-token`: remove a token by label or `age1...` public key
/// and re-encrypt, so the revoked token can no longer decrypt the CURRENT
/// vault.
pub fn revoke_token(key: &Option<PathBuf>, token: &Option<String>, query: &str) -> Result<()> {
    let auth = resolve_auth(key, token)?;
    require_ssh(&auth, "revoke-token")?;
    let mut v = load_vault(key, token)?;
    let removed = v.remove_token(query)?;
    println!(
        "Revoked token {} ({}) — {} token{} remain",
        removed.label,
        removed.public_key,
        v.keys.token_count(),
        if v.keys.token_count() == 1 { "" } else { "s" }
    );
    eprintln!("note: this does NOT revoke access to ciphertext already in git history;");
    eprintln!("      rotate secret values if a true revocation is required.");
    Ok(())
}
