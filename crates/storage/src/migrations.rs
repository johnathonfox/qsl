// SPDX-License-Identifier: Apache-2.0

//! Forward-only SQL migration runner.
//!
//! Migrations live under `crates/storage/migrations/` as files named
//! `NNNN_name.sql` where `NNNN` is a zero-padded integer. The runner applies
//! any unapplied migrations in order, each inside its own transaction, and
//! records applied versions in a `_schema_version` bookkeeping table.
//!
//! Migrations are **forward-only**. There is no `down.sql`; a mistake in a
//! migration is corrected by a new migration, not by rolling back.
//!
//! Migration files are bundled into the binary at build time via
//! [`include_str!`], so there is no runtime filesystem dependency and the
//! `mailcli` / desktop binaries can't drift out of sync with their
//! migrations.

use qsl_core::StorageError;
use tracing::{debug, info};

use crate::conn::{DbConn, Params, Value};

/// One migration step.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Monotonically increasing version. Must match the filename prefix.
    pub version: i64,
    /// Human-readable name drawn from the filename.
    pub name: &'static str,
    /// The SQL to apply. Multiple statements separated by `;` are allowed.
    pub sql: &'static str,
}

/// All migrations known to this binary, in order. Keep this list sorted by
/// `version` with no gaps.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial",
        sql: include_str!("../migrations/0001_initial.sql"),
    },
    Migration {
        version: 2,
        name: "remote_content_opt_ins",
        sql: include_str!("../migrations/0002_remote_content_opt_ins.sql"),
    },
    Migration {
        version: 3,
        name: "threading_columns",
        sql: include_str!("../migrations/0003_threading_columns.sql"),
    },
    Migration {
        version: 4,
        name: "drafts",
        sql: include_str!("../migrations/0004_drafts.sql"),
    },
    Migration {
        version: 5,
        name: "search_fts",
        sql: include_str!("../migrations/0005_search_fts.sql"),
    },
    Migration {
        version: 6,
        name: "contacts",
        sql: include_str!("../migrations/0006_contacts.sql"),
    },
    Migration {
        version: 7,
        name: "app_settings",
        sql: include_str!("../migrations/0007_app_settings.sql"),
    },
    Migration {
        version: 8,
        name: "outbox_dedup",
        sql: include_str!("../migrations/0008_outbox_dedup.sql"),
    },
    Migration {
        version: 9,
        name: "drafts_server_id",
        sql: include_str!("../migrations/0009_drafts_server_id.sql"),
    },
    Migration {
        version: 10,
        name: "history_sync",
        sql: include_str!("../migrations/0010_history_sync.sql"),
    },
    Migration {
        version: 11,
        name: "account_cascade_repair",
        sql: include_str!("../migrations/0011_account_cascade_repair.sql"),
    },
    Migration {
        version: 12,
        name: "restore_fts",
        sql: include_str!("../migrations/0012_restore_fts.sql"),
    },
    Migration {
        version: 13,
        name: "unread_column",
        sql: include_str!("../migrations/0013_unread_column.sql"),
    },
    Migration {
        version: 14,
        name: "messages_id_thread_index",
        sql: include_str!("../migrations/0014_messages_id_thread_index.sql"),
    },
    Migration {
        version: 15,
        name: "messages_folder_id_covering",
        sql: include_str!("../migrations/0015_messages_folder_id_covering.sql"),
    },
    Migration {
        version: 16,
        name: "apply_chunk_wide_covering",
        sql: include_str!("../migrations/0016_apply_chunk_wide_covering.sql"),
    },
    Migration {
        version: 17,
        name: "replace_folder_id_with_folder_date_id",
        sql: include_str!("../migrations/0017_replace_folder_id_with_folder_date_id.sql"),
    },
    Migration {
        version: 18,
        name: "messages_account_rfc822_thread_covering",
        sql: include_str!("../migrations/0018_messages_account_rfc822_thread_covering.sql"),
    },
    Migration {
        version: 19,
        name: "account_scoped_folder_ids",
        sql: include_str!("../migrations/0019_account_scoped_folder_ids.sql"),
    },
];

/// Bookkeeping table. Created lazily by [`run_migrations`] on first run.
const SCHEMA_VERSION_DDL: &str = "\
CREATE TABLE IF NOT EXISTS _schema_version (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    applied_at  INTEGER NOT NULL
)";

/// DDL for the messages full-text index. Shared by migrations 0005 /
/// 0012, the history-sync drop/recreate cycle, and the startup repair
/// in [`ensure_fts_index`] so the four never drift apart.
pub const FTS_INDEX_DDL: &str = "CREATE INDEX IF NOT EXISTS messages_fts_idx ON messages \
     USING fts (subject, from_json, to_json, snippet)";

/// Recreate the messages FTS index if it is missing.
///
/// `pull_history` drops the index for the duration of a bulk pull and
/// rebuilds it at the end. If the process dies in between (crash,
/// kill, power loss) the index is simply gone: migration 0005/0012
/// are already recorded as applied, so nothing would ever bring it
/// back and every search fails until `mailcli doctor --rebuild-fts`.
/// Run this once at startup after [`run_migrations`]; it is a cheap
/// no-op when the index exists.
pub async fn ensure_fts_index(conn: &dyn DbConn) -> Result<(), StorageError> {
    conn.execute(FTS_INDEX_DDL, Params::empty())
        .await
        .map(|_| ())
}

/// Apply any missing migrations from [`MIGRATIONS`] in order.
///
/// - Creates `_schema_version` if it doesn't exist.
/// - Computes the highest applied version.
/// - For every migration with a higher version, opens a transaction, applies
///   its SQL, records the row in `_schema_version`, commits.
/// - On failure, the transaction rolls back and the error is returned —
///   subsequent runs will retry.
pub async fn run_migrations(conn: &dyn DbConn) -> Result<(), StorageError> {
    conn.execute(SCHEMA_VERSION_DDL, Params::empty()).await?;

    let current = current_version(conn).await?;
    debug!(current_version = current, "schema version loaded");

    // Sanity-check the contiguity of versions at build time, not at runtime;
    // keep this as a debug_assert.
    #[cfg(debug_assertions)]
    {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            let expected = i64::try_from(i + 1).unwrap();
            debug_assert_eq!(
                m.version, expected,
                "MIGRATIONS must be contiguous starting at 1 (gap at index {i})",
            );
        }
    }

    for m in MIGRATIONS.iter().filter(|m| m.version > current) {
        info!(version = m.version, name = m.name, "applying migration");
        apply_one(conn, m).await?;
    }
    Ok(())
}

async fn apply_one(conn: &dyn DbConn, m: &Migration) -> Result<(), StorageError> {
    qsl_telemetry::time_op!(
        target: "qsl::slow::db",
        limit_ms: qsl_telemetry::slow::limits::TX_COMMIT_MS,
        op: "migration::apply_one",
        fields: { version = m.version, name = %m.name },
        async {
            let mut tx = conn.begin().await?;

            // Turso 0.5.3 executes only the first statement of a multi-statement
            // string when called inside a transaction (see
            // docs/dependencies/turso.md). Split naively on `;` — our migration
            // files never embed a `;` inside a string literal — and apply each
            // statement separately. Every DDL in the shipped migrations uses
            // `IF NOT EXISTS` so a retry after a partial failure is safe.
            for statement in split_statements(m.sql) {
                tx.execute(&statement, Params::empty()).await.map_err(|e| {
                    StorageError::Migration(format!(
                        "migration {:04} {}: {e}",
                        m.version, m.name
                    ))
                })?;
            }

            let applied_at = chrono::Utc::now().timestamp();
            tx.execute(
                "INSERT INTO _schema_version (version, name, applied_at) VALUES (?1, ?2, ?3)",
                Params(vec![
                    Value::Integer(m.version),
                    Value::OwnedText(m.name.to_string()),
                    Value::Integer(applied_at),
                ]),
            )
            .await?;

            tx.commit().await
        }
    )
}

/// Split a multi-statement SQL file into individual executable statements.
///
/// Assumptions (enforced by convention, not validated):
///
/// - `--` line comments are the only comment style used.
/// - No `;` inside string literals. (A `;` inside a `--` comment is fine
///   because we strip whole comment lines *before* splitting.)
///
/// Violating these is a migration-file bug, not a runtime one — the test
/// suite runs every shipped migration end-to-end, so any new migration
/// that breaks these assumptions fails CI loudly.
fn split_statements(sql: &str) -> Vec<String> {
    // Strip whole-line `--` comments first so that any `;` embedded inside
    // comment prose doesn't fool the `.split(';')` below.
    let cleaned: String = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");

    cleaned
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn current_version(conn: &dyn DbConn) -> Result<i64, StorageError> {
    let row = conn
        .query_opt(
            "SELECT COALESCE(MAX(version), 0) AS v FROM _schema_version",
            Params::empty(),
        )
        .await?;
    row.map(|r| r.get_i64("v")).transpose()?.map_or(Ok(0), Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_contiguous_starting_at_1() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.version, i64::try_from(i + 1).unwrap());
        }
    }

    #[test]
    fn split_statements_drops_comments_and_empties() {
        let sql = "
            -- leading
            CREATE TABLE a (id INT);
            -- middle
            CREATE TABLE b (id INT);
            -- trailing
        ";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].starts_with("CREATE TABLE a"));
        assert!(stmts[1].starts_with("CREATE TABLE b"));
    }
}
