//! dotvault — SSH-key encrypted, multi-recipient secret vault with `.env`
//! export. (library)
//!
//! Secrets live in a project-local `.vault` file (an age container encrypted
//! to every authorized SSH public key in `.vault.keys`). Any single
//! authorized private key can decrypt. Both files are committed to git so a
//! team shares secrets. This crate exposes the vault logic so it can be reused
//! by the CLI binary and by integration tests.

pub mod access;
pub mod access_token;
pub mod backup;
pub mod commands;
pub mod commands_auth;
pub mod commands_render;
pub mod config;
pub mod crypto;
pub mod envfmt;
pub mod export_render;
pub mod template;
pub mod update;
pub mod util;
pub mod vault;
pub mod vault_lock;
pub mod vault_token;
