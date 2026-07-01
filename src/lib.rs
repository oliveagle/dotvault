//! dotvault — SSH-key encrypted secret vault with `.env` export. (library)
//!
//! Secrets live in a single AES-256-GCM container under a vault directory,
//! encrypted with a key derived (HKDF-SHA256) from an SSH private key. This
//! crate exposes the vault logic so it can be reused by the CLI binary and by
//! integration tests.

pub mod access;
pub mod backup;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod envfmt;
pub mod skill;
pub mod util;
pub mod vault;
