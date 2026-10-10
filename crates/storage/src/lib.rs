// SPDX-License-Identifier: Apache-2.0

//! QSL storage layer.
//!
//! Hosts the [`DbConn`] trait, the migration runner, the repository layer,
//! and the blob store for raw `.eml` bodies. Callers above this crate
//! depend on the trait surface; the Turso-backed implementation lives in
//! [`turso_conn`].
//!
//! # Module layout
//!
//! - [`conn`] — `DbConn` and `Tx` traits, plus `Params`, `Value`, `Row`.
//! - [`turso_conn`] — `TursoConn` implementation over `turso::Connection`.
//! - [`migrations`] — file-based migration runner and `_schema_version`
//!   bookkeeping.
//! - [`blobs`] — on-disk blob store with default-on zstd compression.
//! - [`repos`] — one module per domain type, each exposing CRUD functions
//!   that take `&dyn DbConn`.

pub mod blobs;
pub mod conn;
pub mod migrations;
pub mod repos;
pub mod turso_conn;

pub use blobs::BlobStore;
pub use conn::{DbConn, OwnedValue, Params, Row, Tx, Value};
pub use migrations::{ensure_fts_index, run_migrations, FTS_INDEX_DDL, MIGRATIONS};
pub use turso_conn::TursoConn;
