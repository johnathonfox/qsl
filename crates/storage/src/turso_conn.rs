// SPDX-License-Identifier: Apache-2.0

//! Turso-backed implementation of [`DbConn`].
//!
//! This module is the one place in `qsl-storage` that knows about
//! `turso::*` types. Everything above it sees only the trait surface in
//! [`crate::conn`].
//!
//! # A note on transactions
//!
//! Turso 0.5.3 ships `pub struct Transaction {}` as an empty placeholder —
//! no `commit`, no `rollback`, no `execute`. The real transaction API is a
//! planned-but-unimplemented feature upstream. We work around this by
//! issuing raw `BEGIN` / `COMMIT` / `ROLLBACK` statements on the same
//! connection, which is the SQLite-level behavior regardless of whether a
//! higher-level API wraps it. Tracked in `docs/dependencies/turso.md`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use qsl_telemetry::{slow::limits, time_op};
use turso::params::params_from_iter;

use qsl_core::StorageError;

use crate::conn::{DbConn, OwnedValue, Params, Row, Tx, Value};

/// Truncate a SQL string for logging. The full text is kept private
/// because parameter bindings can contain user data (subjects,
/// addresses) that we don't want dumped into stderr.
fn sql_head(sql: &str) -> &str {
    const MAX: usize = 80;
    if sql.len() <= MAX {
        sql
    } else {
        // Find the longest valid char boundary <= MAX so we never
        // panic on a multi-byte split.
        let mut end = MAX;
        while end > 0 && !sql.is_char_boundary(end) {
            end -= 1;
        }
        &sql[..end]
    }
}

/// A live handle to a Turso database.
pub struct TursoConn {
    conn: turso::Connection,
    /// Set by [`TursoTx::drop`] when a transaction is dropped without
    /// `commit()` / `rollback()`. The next [`begin`] call observes the
    /// flag, issues a recovery `ROLLBACK` to clear the in-flight
    /// transaction, then proceeds with a fresh `BEGIN`. Without this
    /// the connection is wedged: every subsequent operation runs
    /// inside the orphaned transaction, and the next `BEGIN` errors.
    /// `Arc<AtomicBool>` so each live `TursoTx` shares the same
    /// flag with the parent `TursoConn` regardless of which path
    /// drops it.
    poisoned: Arc<AtomicBool>,
}

impl TursoConn {
    /// Wrap an already-built `turso::Connection`.
    pub fn new(conn: turso::Connection) -> Self {
        Self {
            conn,
            poisoned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Open an in-memory database. Primarily used by tests.
    pub async fn in_memory() -> Result<Self, StorageError> {
        let db = turso::Builder::new_local(":memory:")
            .experimental_index_method(true)
            .build()
            .await
            .map_err(err_db)?;
        let conn = db.connect().map_err(err_db)?;
        let this = Self::new(conn);
        // Mirror `open` — keep test fixtures honest about FK
        // enforcement so cascade-dependent behavior fails in tests if
        // a future change forgets the pragma. WAL / synchronous /
        // busy_timeout are no-ops on `:memory:` so they're skipped.
        // `cache_size` and `temp_store` aren't strictly needed for
        // `:memory:` (everything is RAM-resident anyway) but we set
        // them so the test fixture's plan choices match production —
        // otherwise EXPLAIN tests could diverge from real-world
        // behavior on the same query.
        let _ = this
            .query("PRAGMA foreign_keys=ON", crate::conn::Params::empty())
            .await;
        let _ = this
            .query("PRAGMA cache_size=-256000", crate::conn::Params::empty())
            .await;
        let _ = this
            .query("PRAGMA temp_store=MEMORY", crate::conn::Params::empty())
            .await;
        Ok(this)
    }

    /// Open (or create) a database file at `path`. Enables WAL mode
    /// so multiple connections to the same file can read concurrently
    /// while a writer is in flight — required for the desktop app's
    /// split between the IPC connection (`AppState::db`) and the sync
    /// engine's connection (`AppState::sync_db`). The pragmas are
    /// idempotent: WAL mode persists in the file header, so calling
    /// the toggle on every open is a cheap no-op once set.
    ///
    /// Also sets `synchronous=NORMAL` (durable on checkpoint, not
    /// per-commit — the libSQL/Turso default mirrors SQLite's `FULL`,
    /// which is overkill for a single-host email cache where a power
    /// loss can be reconciled from the server) and `busy_timeout=5000`
    /// (the WAL split between IPC and sync handles can occasionally
    /// race; better to wait 5 s than return SQLITE_BUSY immediately).
    /// Whether Turso's libSQL fork honors these depends on the
    /// engine version's PRAGMA support; if not, the queries are
    /// no-ops and the call still succeeds.
    pub async fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, StorageError> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| StorageError::Db("db path is not valid UTF-8".into()))?;
        let db = turso::Builder::new_local(path)
            // `experimental_index_method` opts into the Tantivy-backed
            // FTS feature shipped behind a runtime flag in Turso 0.5.3.
            // Migration 0005 creates a `USING fts(...)` index on the
            // messages table; the engine refuses the DDL without this
            // toggle. Both `open` and `in_memory` set it so the test
            // suite (in-memory) and real binaries (file-backed) agree.
            .experimental_index_method(true)
            .build()
            .await
            .map_err(err_db)?;
        let conn = db.connect().map_err(err_db)?;
        let this = Self::new(conn);
        // PRAGMAs accept no params and return a single row when they
        // succeed; we don't actually inspect the response, but do
        // wait for the call to complete so the file header is
        // updated before the migrations runner touches it.
        let _ = this
            .query("PRAGMA journal_mode=WAL", crate::conn::Params::empty())
            .await?;
        // Tolerate engines that don't recognize either pragma — the
        // pragmas are an optimization, not a correctness requirement.
        let _ = this
            .query("PRAGMA synchronous=NORMAL", crate::conn::Params::empty())
            .await;
        let _ = this
            .query("PRAGMA busy_timeout=5000", crate::conn::Params::empty())
            .await;
        // Bump the per-connection page cache to 256 MB
        // (negative value = absolute KB). Default is 2 MB / 2000 KB,
        // which is dwarfed by the messages table + indexes once the
        // local cache reaches a few thousand rows. Without this every
        // `messages_list` re-reads index + heap pages off disk on
        // each click — measured as a steady ~2.6s freeze on
        // `[Gmail]/All Mail` (telemetry 2026-05-07). 256 MB lets the
        // entire active working set stay resident in process memory
        // for the maintainer's mailbox sizes; consumers with smaller
        // caches still benefit from the pages they do hold.
        // Verified TAKEN by Turso 0.5.3 in
        // `tests/explain_plans.rs::PRAGMA write verification`.
        let _ = this
            .query("PRAGMA cache_size=-256000", crate::conn::Params::empty())
            .await;
        // Force the SORTER and any temp B-tree to live in RAM rather
        // than an on-disk temp file. Turso 0.5.3's planner adds a
        // mandatory `USE SORTER FOR ORDER BY` on every `ORDER BY`
        // (see `tests/explain_plans.rs`); with the default
        // `temp_store=0` the sort spills to disk — the dominant cost
        // on the 30k-row `messages_list` slow events.
        let _ = this
            .query("PRAGMA temp_store=MEMORY", crate::conn::Params::empty())
            .await;
        // Enable FK enforcement so the schema's `ON DELETE CASCADE`
        // clauses actually fire. SQLite ships with foreign-key
        // enforcement OFF by default — until this lands, every
        // `accounts.delete` left orphaned rows in folders / messages /
        // threads / outbox / contacts / drafts. The pragma is
        // per-connection, so both `db` and `sync_db` need to go
        // through `open`.
        let _ = this
            .query("PRAGMA foreign_keys=ON", crate::conn::Params::empty())
            .await;
        Ok(this)
    }

    /// Borrow the underlying `turso::Connection` for Turso-specific
    /// operations (PRAGMAs, cache flush). Avoid if possible — going through
    /// [`DbConn`] keeps the abstraction intact.
    pub fn inner(&self) -> &turso::Connection {
        &self.conn
    }
}

impl TursoConn {
    /// If a previous [`TursoTx`] was dropped without `commit()` /
    /// `rollback()`, the connection still has its `BEGIN` open. Clear
    /// it with a `ROLLBACK` *before* running the caller's statement.
    ///
    /// This must run on every entry point, not just `begin()`: an
    /// autocommit `execute` issued while the orphan is open silently
    /// joins that transaction and is then discarded by the eventual
    /// recovery rollback. The concrete failure was the outbox drain
    /// deleting a just-sent row "inside" a poisoned transaction, the
    /// next `apply_chunk` rolling it back, and the message being sent
    /// a second time.
    async fn recover_orphan_tx(&self) {
        if self.poisoned.swap(false, Ordering::AcqRel) {
            tracing::warn!(
                target: "qsl_storage::tx",
                "TursoConn: clearing orphan BEGIN from a previously-dropped TursoTx"
            );
            let _ = self
                .conn
                .execute(
                    "ROLLBACK",
                    turso::params::IntoParams::into_params(()).unwrap(),
                )
                .await;
        }
    }
}

#[async_trait]
impl DbConn for TursoConn {
    async fn execute(&self, sql: &str, params: Params<'_>) -> Result<u64, StorageError> {
        self.recover_orphan_tx().await;
        let r = time_op!(
            target: "qsl::slow::db",
            limit_ms: limits::DB_QUERY_MS,
            op: "execute",
            fields: { sql = %sql_head(sql) },
            self.conn
                .execute(sql, params_from_iter(to_turso_values(params)))
        );
        r.map_err(err_db)
    }

    async fn query(&self, sql: &str, params: Params<'_>) -> Result<Vec<Row>, StorageError> {
        self.recover_orphan_tx().await;
        let r: Result<Vec<Row>, StorageError> = time_op!(
            target: "qsl::slow::db",
            limit_ms: limits::DB_QUERY_MS,
            op: "query",
            fields: { sql = %sql_head(sql) },
            async {
                let mut rows = self
                    .conn
                    .query(sql, params_from_iter(to_turso_values(params)))
                    .await
                    .map_err(err_db)?;
                materialize_rows(&mut rows).await
            }
        );
        r
    }

    async fn query_one(&self, sql: &str, params: Params<'_>) -> Result<Row, StorageError> {
        let mut rows = self.query(sql, params).await?;
        match rows.len() {
            0 => Err(StorageError::NotFound),
            1 => Ok(rows.remove(0)),
            n => Err(StorageError::Db(format!(
                "query_one expected 1 row, got {n}"
            ))),
        }
    }

    async fn query_opt(&self, sql: &str, params: Params<'_>) -> Result<Option<Row>, StorageError> {
        let mut rows = self.query(sql, params).await?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows.remove(0))),
            n => Err(StorageError::Db(format!(
                "query_opt expected 0 or 1 rows, got {n}"
            ))),
        }
    }

    async fn begin<'a>(&'a self) -> Result<Box<dyn Tx + 'a>, StorageError> {
        // See module docs — Turso 0.5.3 doesn't implement its Transaction
        // wrapper yet, so we drive the transaction at the SQL level.
        //
        // Recovery path: if the previous `TursoTx` was dropped without
        // `commit()` / `rollback()` (e.g. an early `?` return on a
        // sibling fallible call inside the transaction body), the
        // connection still has a `BEGIN` in flight. The poisoned flag
        // is set by `TursoTx::drop`. Issue a `ROLLBACK` to clear that
        // orphan transaction before opening a new one. The rollback
        // returning an error is tolerated — some engines treat
        // `ROLLBACK` outside a transaction as a no-op error, which is
        // exactly the recovered state we want. (`execute` / `query`
        // run the same recovery so autocommit writes never land
        // inside the orphan.)
        self.recover_orphan_tx().await;
        self.conn
            .execute("BEGIN", turso::params::IntoParams::into_params(()).unwrap())
            .await
            .map_err(err_db)?;
        Ok(Box::new(TursoTx {
            conn: &self.conn,
            finished: false,
            poisoned: Arc::clone(&self.poisoned),
        }))
    }
}

/// Transaction handle that dispatches through the shared connection.
///
/// Because Turso's `Connection` is serialized internally, intermixing direct
/// `DbConn::execute` calls on the parent handle with calls on an active
/// `TursoTx` will route them all through the same in-flight transaction.
/// Callers should treat `Tx::execute` as the canonical path while a tx is
/// open.
struct TursoTx<'a> {
    conn: &'a turso::Connection,
    finished: bool,
    /// Shared with the parent [`TursoConn`]. Set in [`Drop`] when this
    /// transaction is abandoned without `commit()` / `rollback()`; the
    /// next `begin()` consults the flag and issues a recovery
    /// `ROLLBACK` so the connection isn't wedged.
    poisoned: Arc<AtomicBool>,
}

#[async_trait]
impl<'a> Tx for TursoTx<'a> {
    async fn execute(&mut self, sql: &str, params: Params<'_>) -> Result<u64, StorageError> {
        let r = time_op!(
            target: "qsl::slow::db",
            limit_ms: limits::DB_QUERY_MS,
            op: "tx_execute",
            fields: { sql = %sql_head(sql) },
            self.conn
                .execute(sql, params_from_iter(to_turso_values(params)))
        );
        r.map_err(err_db)
    }

    async fn query(&mut self, sql: &str, params: Params<'_>) -> Result<Vec<Row>, StorageError> {
        let r: Result<Vec<Row>, StorageError> = time_op!(
            target: "qsl::slow::db",
            limit_ms: limits::DB_QUERY_MS,
            op: "tx_query",
            fields: { sql = %sql_head(sql) },
            async {
                let mut rows = self
                    .conn
                    .query(sql, params_from_iter(to_turso_values(params)))
                    .await
                    .map_err(err_db)?;
                materialize_rows(&mut rows).await
            }
        );
        r
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StorageError> {
        let r = time_op!(
            target: "qsl::slow::db",
            limit_ms: limits::TX_COMMIT_MS,
            op: "tx_commit",
            self.conn.execute(
                "COMMIT",
                turso::params::IntoParams::into_params(()).unwrap(),
            )
        );
        r.map_err(err_db)?;
        self.finished = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> Result<(), StorageError> {
        let r = time_op!(
            target: "qsl::slow::db",
            limit_ms: limits::TX_COMMIT_MS,
            op: "tx_rollback",
            self.conn.execute(
                "ROLLBACK",
                turso::params::IntoParams::into_params(()).unwrap(),
            )
        );
        r.map_err(err_db)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for TursoTx<'_> {
    fn drop(&mut self) {
        // Sync `Drop` can't await, so we can't issue ROLLBACK from
        // here directly. Instead, set the poison flag the parent
        // `TursoConn` shares with us — the next `begin()` observes it
        // and issues a recovery `ROLLBACK` to clear the orphaned
        // transaction before starting a new one. Without this the
        // connection is wedged: every subsequent statement runs
        // inside the dangling BEGIN until the process restarts.
        //
        // Still log the abandon — it almost always indicates a
        // missing `?`-aware commit / rollback site or an early-return
        // path that forgot to finalize the transaction.
        if !self.finished {
            self.poisoned.store(true, Ordering::Release);
            tracing::warn!(
                target: "qsl_storage::tx",
                "TursoTx dropped without commit() or rollback(); the next begin() \
                 will issue a recovery ROLLBACK. This is a storage-layer bug — \
                 audit callers for an early-return path that skipped finalize."
            );
        }
    }
}

fn to_turso_values(params: Params<'_>) -> Vec<turso::Value> {
    params.0.into_iter().map(to_turso_value).collect()
}

fn to_turso_value(v: Value<'_>) -> turso::Value {
    match v {
        Value::Null => turso::Value::Null,
        Value::Integer(i) => turso::Value::Integer(i),
        Value::Real(f) => turso::Value::Real(f),
        Value::Text(s) => turso::Value::Text(s.to_string()),
        Value::OwnedText(s) => turso::Value::Text(s),
        Value::Blob(b) => turso::Value::Blob(b.to_vec()),
        Value::OwnedBlob(b) => turso::Value::Blob(b),
    }
}

async fn materialize_rows(rows: &mut turso::Rows) -> Result<Vec<Row>, StorageError> {
    let column_names = rows.column_names();
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(err_db)? {
        let mut cols = Vec::with_capacity(column_names.len());
        for (i, name) in column_names.iter().enumerate() {
            let v = row.get_value(i).map_err(err_db)?;
            cols.push((name.clone(), owned_from_turso(v)));
        }
        out.push(Row::from_columns(cols));
    }
    Ok(out)
}

fn owned_from_turso(v: turso::Value) -> OwnedValue {
    match v {
        turso::Value::Null => OwnedValue::Null,
        turso::Value::Integer(i) => OwnedValue::Integer(i),
        turso::Value::Real(f) => OwnedValue::Real(f),
        turso::Value::Text(s) => OwnedValue::Text(s),
        turso::Value::Blob(b) => OwnedValue::Blob(b),
    }
}

fn err_db<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::Db(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Params;

    /// Smoke: a `Tx` dropped without commit/rollback (the early-`?`
    /// path the audit flagged) must not wedge the connection.
    /// Concrete reproduction: open a Tx, write something inside it,
    /// drop the box without finalizing — then a fresh `begin()` on
    /// the same `TursoConn` must succeed and the orphaned write must
    /// not be visible.
    #[tokio::test]
    async fn dropped_tx_does_not_wedge_connection() {
        let conn = TursoConn::in_memory().await.expect("open in-memory");
        conn.execute(
            "CREATE TABLE poison_probe (id INTEGER PRIMARY KEY, v TEXT)",
            Params::empty(),
        )
        .await
        .expect("create table");

        // Open a transaction, write something, drop without commit.
        {
            let mut tx = conn.begin().await.expect("first begin");
            tx.execute(
                "INSERT INTO poison_probe (id, v) VALUES (?, ?)",
                Params::from([Value::Integer(1), Value::OwnedText("orphan".into())]),
            )
            .await
            .expect("insert inside tx");
            // drop tx here — no commit, no rollback.
        }

        // Without the recovery path, the next begin() would error
        // (connection still has BEGIN in flight). With it, this
        // succeeds and the orphan insert is rolled back.
        let mut tx2 = conn.begin().await.expect("second begin recovered");
        tx2.execute(
            "INSERT INTO poison_probe (id, v) VALUES (?, ?)",
            Params::from([Value::Integer(2), Value::OwnedText("clean".into())]),
        )
        .await
        .expect("insert in recovered tx");
        tx2.commit().await.expect("commit recovered tx");

        // Verify only the committed row landed.
        let rows = conn
            .query("SELECT id FROM poison_probe ORDER BY id", Params::empty())
            .await
            .expect("select rows");
        let ids: Vec<i64> = rows
            .iter()
            .map(|r| r.get_i64("id").expect("id is integer"))
            .collect();
        assert_eq!(
            ids,
            vec![2],
            "orphan row from dropped tx should have been rolled back"
        );
    }

    /// A clean commit/rollback cycle must not leave the poison flag
    /// set — otherwise the *next* begin would issue a spurious
    /// ROLLBACK and warn-log on every transaction.
    #[tokio::test]
    async fn clean_commit_does_not_poison_connection() {
        let conn = TursoConn::in_memory().await.expect("open in-memory");
        conn.execute(
            "CREATE TABLE clean_probe (id INTEGER PRIMARY KEY)",
            Params::empty(),
        )
        .await
        .expect("create");

        let tx = conn.begin().await.expect("begin");
        tx.commit().await.expect("commit");
        // After a clean commit, the flag should be false.
        assert!(
            !conn.poisoned.load(Ordering::Acquire),
            "poison flag set after a clean commit"
        );

        let tx = conn.begin().await.expect("begin 2");
        tx.rollback().await.expect("rollback");
        assert!(
            !conn.poisoned.load(Ordering::Acquire),
            "poison flag set after a clean rollback"
        );
    }
}
