//! agyx-core — cross-platform multi-account AGY credential manager.
//!
//! # Safety model
//! - AGY credential blobs are treated as **opaque bytes** at all times.
//!   The ONLY permitted parsing is a read-only decode of the OIDC `id_token`
//!   payload to extract `sub` and `email` for identification purposes.
//!   That decoded copy is never persisted, never encrypted into the store, and
//!   never written to the credential manager.
//! - JWT signatures are **not** verified. `sub`/`email` are identifiers, not
//!   cryptographic proof of identity; do not use them as security boundaries.
//! - Tokens (access, refresh, id_token) are never printed or logged.

pub mod adapter;
pub mod config;
pub mod credential_store;
pub mod doctor;
pub mod errors;
pub mod identity;
pub mod journal;
pub mod lock;
pub mod process_manager;
pub mod sessions;
pub mod switcher;

pub use errors::AgyxError;
