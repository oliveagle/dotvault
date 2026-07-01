//! dotvault — SSH-key encrypted, namespaced secret vault with `.env` export.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use dotvault::commands;

#[derive(Parser, Debug)]
#[command(
    name = "dotvault",
    version,
    about = "SSH-key encrypted, namespaced secret vault with .env export"
)]
struct Cli {
    /// Path to the SSH private key used for encryption.
    /// Default: ~/.ssh/id_ed25519. Env: DOTVAULT_KEY.
    ///
    /// Top-level option; must precede the subcommand, e.g.
    /// `dotvault --key ~/.ssh/id_ed25519 set A 1`.
    #[arg(long)]
    key: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// One-shot environment setup: create global dirs + default config.
    /// Idempotent — never overwrites existing config.
    Install,
    /// Create a namespace and bind this project to it (writes ./.dotvault_key).
    Init {
        /// Namespace name. Must match `[a-z0-9][a-z0-9-_]*`.
        namespace: String,
    },
    /// Set (or overwrite) a secret in the current namespace.
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
    /// List secret names in the current namespace, one per line.
    List,
    /// Export all secrets as `KEY=VALUE` lines to stdout.
    Export,
    /// Re-encrypt all namespaces with a different SSH key.
    Rekey {
        /// Path to the NEW SSH private key to adopt.
        #[arg(long)]
        new_key: PathBuf,
    },
    /// Manage namespaces.
    Ns {
        #[command(subcommand)]
        cmd: NsCmd,
    },
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
    /// Verify the current namespace's vault integrity + access key.
    Doctor,
}

#[derive(Subcommand, Debug)]
enum NsCmd {
    /// List all namespaces.
    List,
    /// Remove a namespace (requires the SSH key to authorize).
    Remove { namespace: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
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
        Command::Install => commands::install(&cli.key),
        Command::Init { namespace } => commands::init(&namespace, &cli.key),
        Command::Set { key, value } => commands::set(&cli.key, &key, &value),
        Command::Get { key } => commands::get(&cli.key, &key),
        Command::Rm { key } => commands::rm(&cli.key, &key),
        Command::List => commands::list(&cli.key),
        Command::Export => commands::export(&cli.key),
        Command::Rekey { new_key } => commands::rekey(&cli.key, &new_key),
        Command::Ns { cmd } => match cmd {
            NsCmd::List => commands::ns_list(),
            NsCmd::Remove { namespace } => commands::ns_remove(&namespace, &cli.key),
        },
        Command::Config {
            set_key,
            set_backup_dir,
            set_backup_keep,
        } => commands::config(&set_key, &set_backup_dir, &set_backup_keep),
        Command::Doctor => commands::doctor(&cli.key),
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
