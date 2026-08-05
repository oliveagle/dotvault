//! dotvault — SSH-key encrypted, multi-recipient secret vault with `.env` export.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use dotvault::{commands, commands_auth, commands_render};

#[derive(Parser, Debug)]
#[command(
    name = "dotvault",
    version,
    about = "SSH-key encrypted, multi-recipient secret vault with .env export"
)]
struct Cli {
    /// Path to the SSH private key used to decrypt the vault.
    /// Default: ~/.ssh/id_ed25519. Env: DOTVAULT_KEY.
    ///
    /// Top-level option; must precede the subcommand, e.g.
    /// `dotvault --key ~/.ssh/id_ed25519 set A 1`.
    #[arg(long)]
    key: Option<PathBuf>,

    /// Read-only access token (`AGE-SECRET-KEY-1...`) for CI / automation.
    /// Env: DOTVAULT_TOKEN. Mutually exclusive with --key. Grants read access
    /// only; write commands (set/rm/add-key/remove-key/add-token/revoke-token/
    /// init) require an SSH key.
    #[arg(long, env = "DOTVAULT_TOKEN", value_name = "TOKEN")]
    token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// One-shot environment setup: create global dirs + default config.
    /// Idempotent — never overwrites existing config.
    Install,
    /// Create a project vault (`.vault` + `.vault.keys`) in the current
    /// directory, seeded with your public key.
    Init,
    /// Set (or overwrite) a secret in the project vault.
    Set {
        /// Secret name. Must match `[A-Za-z_][A-Za-z0-9_]*`.
        key: String,
        /// Secret value. Everything after the name is taken literally.
        value: String,
    },
    /// Read a single secret value to stdout (no trailing newline).
    Get { key: String },
    /// Remove a secret.
    Rm { key: String },
    /// List secret names in the project vault, one per line.
    List,
    /// Export all secrets as `KEY=VALUE` lines to stdout.
    Export,
    /// Render a template file: substitute `{{KEY}}` placeholders with secret
    /// values from the vault → stdout, or `--out` FILE (mode 0600). A
    /// placeholder for a secret not in the vault is a hard error.
    Render {
        /// Path to the template file (e.g. `config.yaml.tmpl`).
        template: PathBuf,
        /// Write the rendered output to this file (mode 0600) instead of
        /// stdout. Useful when the result contains secrets.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Authorize a teammate: add their SSH public key and re-encrypt so they
    /// can decrypt. Accepts an authorized-keys line, a `*.pub` path, or `@file`.
    AddKey {
        /// Public key spec: `ssh-ed25519 AAAA...`, `~/.ssh/id_ed25519.pub`, or `@keys.txt`.
        pubkey: String,
    },
    /// Revoke a teammate's access: remove their key and re-encrypt. Note this
    /// does NOT revoke access to ciphertext already committed to git history.
    RemoveKey {
        /// Fingerprint (`SHA256:...`) or label of the key to remove.
        query: String,
    },
    /// Generate a read-only token for CI / automation. Prints the token
    /// secret (AGE-SECRET-KEY-1...) to stdout ONCE; store it in your CI secret
    /// store. Requires an SSH key (tokens cannot mint tokens).
    AddToken {
        /// Human-readable label for the token (e.g. "ci-deploy").
        label: String,
    },
    /// List authorized read-only tokens (label + age1... public key). The
    /// secret is never shown.
    ListTokens,
    /// Revoke a read-only token by label or `age1...` public key. Re-encrypts
    /// so the token can no longer decrypt the current vault. Requires an SSH key.
    RevokeToken {
        /// Label or `age1...` public key of the token to revoke.
        query: String,
    },
    /// List the authorized recipients (fingerprints + labels).
    ListKeys,
    /// Show or set global config (~/.dotvault/config.toml).
    Config {
        /// Set the default SSH key path.
        #[arg(long, value_name = "PATH")]
        set_key: Option<String>,
        /// Set the backup directory.
        #[arg(long, value_name = "DIR")]
        set_backup_dir: Option<String>,
        /// Set how many backups to keep (0 = unlimited).
        #[arg(long, value_name = "N")]
        set_backup_keep: Option<usize>,
    },
    /// Verify the project vault integrity + list authorized keys.
    Doctor,
    /// Print version + build details (git hash, build time, rustc, target).
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // --key and --token are mutually exclusive (the commands layer also
    // re-checks, but failing here gives clap-style clarity before dispatch).
    if cli.key.is_some() && cli.token.is_some() {
        bail!("--key and --token are mutually exclusive; pass only one");
    }
    // Validate the secret name for set, to keep export safe for shells.
    if let Command::Set { key, .. } = &cli.command {
        if !is_valid_env_name(key) {
            bail!(
                "invalid secret name {:?}: must match [A-Za-z_][A-Za-z0-9_]*",
                key
            );
        }
    }
    match cli.command {
        // install/init are SSH-only (token can't bootstrap or write).
        Command::Install => {
            if cli.token.is_some() {
                bail!("tokens are read-only: `install` requires no token (it sets up global env, not a vault)");
            }
            commands::install(&cli.key)
        }
        Command::Init => commands::init(&cli.key, &cli.token),
        Command::Set { key, value } => commands::set(&cli.key, &cli.token, &key, &value),
        Command::Get { key } => commands::get(&cli.key, &cli.token, &key),
        Command::Rm { key } => commands::rm(&cli.key, &cli.token, &key),
        Command::List => commands::list(&cli.key, &cli.token),
        Command::Export => commands::export(&cli.key, &cli.token),
        Command::Render { template, out } => {
            commands_render::render(&cli.key, &cli.token, &template, out.as_deref())
        }
        Command::AddKey { pubkey } => commands::add_key(&cli.key, &cli.token, &pubkey),
        Command::RemoveKey { query } => commands::remove_key(&cli.key, &cli.token, &query),
        Command::AddToken { label } => commands_auth::add_token(&cli.key, &cli.token, &label),
        Command::ListTokens => commands_auth::list_tokens(&cli.key, &cli.token),
        Command::RevokeToken { query } => commands_auth::revoke_token(&cli.key, &cli.token, &query),
        Command::ListKeys => commands::list_keys(&cli.key, &cli.token),
        Command::Config {
            set_key,
            set_backup_dir,
            set_backup_keep,
        } => commands::config(&set_key, &set_backup_dir, &set_backup_keep),
        Command::Doctor => commands::doctor(&cli.key, &cli.token),
        Command::Version => commands::version(),
    }
}

/// Restrict names to a shell-safe subset so `KEY=VALUE` exports are valid.
pub fn is_valid_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::is_valid_env_name;

    #[test]
    fn valid_env_names() {
        assert!(is_valid_env_name("A"));
        assert!(is_valid_env_name("KEY"));
        assert!(is_valid_env_name("_foo"));
        assert!(is_valid_env_name("A1_B2"));
        assert!(is_valid_env_name("API_TOKEN"));
    }

    #[test]
    fn invalid_env_names() {
        assert!(!is_valid_env_name(""));
        assert!(!is_valid_env_name("1abc")); // leading digit
        assert!(!is_valid_env_name("bad-name")); // hyphen
        assert!(!is_valid_env_name("has space"));
        assert!(!is_valid_env_name("K=v")); // equals
        assert!(!is_valid_env_name("dollar$"));
    }
}
