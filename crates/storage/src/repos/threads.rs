// SPDX-License-Identifier: Apache-2.0

//! Thread persistence + assembly helpers.
//!
//! The schema is per `DESIGN.md` §4.4 — one `threads` row per
//! conversation, with `messages.thread_id` foreign-keyed in.
//! Phase 1 Week 13 wires the assembly pipeline that
//! `qsl-sync::sync_folder` calls after each message insert.
//!
//! The assembly resolver lives over in `qsl-sync` because it
//! needs cross-repo coordination (`messages_repo::find_by_message_id`,
//! `threads_repo::insert`, etc.). This module just owns the
//! per-thread CRUD.

use chrono::{DateTime, TimeZone, Utc};

use qsl_core::{AccountId, MessageId, StorageError, ThreadId};

use crate::conn::{DbConn, Params, Row, Tx, Value};

/// One thread row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    pub id: ThreadId,
    pub account_id: AccountId,
    pub root_message_id: Option<MessageId>,
    /// Subject normalized for the lexical-fallback assembly path
    /// (see `qsl_sync::threading::normalize_subject`). Stored
    /// once at thread creation so the lookup query stays a simple
    /// indexed equality check; rebuilding when subjects diverge is
    /// not worth it.
    pub subject_normalized: String,
    pub last_date: DateTime<Utc>,
    pub message_count: u32,
}

const INSERT: &str = "
    INSERT INTO threads (id, account_id, root_message_id, subject_normalized, last_date, message_count)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)
";

const SELECT_BY_ID: &str = "
    SELECT id, account_id, root_message_id, subject_normalized, last_date, message_count
      FROM threads
     WHERE id = ?1
";

/// Look up the thread that contains a given Message-ID. The
/// assembly pipeline uses this in two places:
///
/// 1. After parsing `In-Reply-To`, find the thread that already
///    holds the referenced message.
/// 2. While walking `References` in reverse, find the first thread
///    whose root or member matches.
///
/// Implemented as a JOIN against the `messages` table on
/// `rfc822_message_id` so we don't need a separate `thread_messages`
/// pivot table — a message's thread is whichever thread its row
/// points to.
const SELECT_BY_MESSAGE_ID: &str = "
    SELECT t.id, t.account_id, t.root_message_id, t.subject_normalized, t.last_date, t.message_count
      FROM threads t
      JOIN messages m ON m.thread_id = t.id
     WHERE m.account_id = ?1 AND m.rfc822_message_id = ?2
     LIMIT 1
";

/// Match an existing thread by normalized subject within an
/// account, restricted to threads whose `last_date` falls in the
/// supplied window. The 30-day window from the spec keeps us from
/// re-attaching old "Re: lunch?" threads to unrelated new ones.
const SELECT_BY_SUBJECT_RECENT: &str = "
    SELECT id, account_id, root_message_id, subject_normalized, last_date, message_count
      FROM threads
     WHERE account_id = ?1
       AND subject_normalized = ?2
       AND last_date >= ?3
     ORDER BY last_date DESC
     LIMIT 1
";

const TOUCH_FOR_MESSAGE: &str = "
    UPDATE threads
       SET message_count = message_count + 1,
           last_date     = MAX(last_date, ?2)
     WHERE id = ?1
";

const ATTACH_MESSAGE: &str = "UPDATE messages SET thread_id = ?2 WHERE id = ?1";

/// Insert a new thread row. The caller is responsible for
/// generating the id (the assembly pipeline mints `t-<random>` ids
/// to avoid leaking the root message's sometimes-renamed
/// rfc822_message_id into a primary key).
pub async fn insert(conn: &dyn DbConn, t: &Thread) -> Result<(), StorageError> {
    conn.execute(
        INSERT,
        Params(vec![
            Value::Text(&t.id.0),
            Value::Text(&t.account_id.0),
            t.root_message_id
                .as_ref()
                .map(|m| Value::Text(&m.0))
                .unwrap_or(Value::Null),
            Value::Text(&t.subject_normalized),
            Value::Integer(t.last_date.timestamp()),
            Value::Integer(t.message_count.into()),
        ]),
    )
    .await
    .map(|_| ())
}

/// Pull the `message_count` for a batch of thread ids in a single
/// query. Drives the message-list "this thread has N messages"
/// badge: the list view JOINs each row's `thread_id` against this
/// map and renders the count when greater than 1.
pub async fn counts_by_ids(
    conn: &dyn DbConn,
    ids: &[ThreadId],
) -> Result<std::collections::HashMap<ThreadId, u32>, StorageError> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let placeholders: String = (1..=ids.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT id, message_count FROM threads WHERE id IN ({placeholders})");
    let params: Vec<Value> = ids.iter().map(|t| Value::Text(&t.0)).collect();
    let rows = conn.query(&sql, Params(params)).await?;
    let mut out = std::collections::HashMap::with_capacity(rows.len());
    for r in &rows {
        let id = ThreadId(r.get_str("id")?.to_string());
        let count = u32::try_from(r.get_i64("message_count")?)
            .map_err(|e| StorageError::Db(format!("message_count out of range: {e}")))?;
        out.insert(id, count);
    }
    Ok(out)
}

pub async fn get(conn: &dyn DbConn, id: &ThreadId) -> Result<Thread, StorageError> {
    let row = conn
        .query_one(SELECT_BY_ID, Params(vec![Value::Text(&id.0)]))
        .await?;
    row_to_thread(&row)
}

pub async fn find_by_message_id(
    conn: &dyn DbConn,
    account: &AccountId,
    rfc822_message_id: &str,
) -> Result<Option<Thread>, StorageError> {
    conn.query_opt(
        SELECT_BY_MESSAGE_ID,
        Params(vec![
            Value::Text(&account.0),
            Value::OwnedText(rfc822_message_id.to_string()),
        ]),
    )
    .await?
    .map(|r| row_to_thread(&r))
    .transpose()
}

pub async fn find_recent_by_subject(
    conn: &dyn DbConn,
    account: &AccountId,
    subject_normalized: &str,
    since: DateTime<Utc>,
) -> Result<Option<Thread>, StorageError> {
    conn.query_opt(
        SELECT_BY_SUBJECT_RECENT,
        Params(vec![
            Value::Text(&account.0),
            Value::OwnedText(subject_normalized.to_string()),
            Value::Integer(since.timestamp()),
        ]),
    )
    .await?
    .map(|r| row_to_thread(&r))
    .transpose()
}

/// Bump a thread's `message_count` and `last_date` to reflect a
/// newly-attached message, then point that message's `thread_id`
/// at this thread. Two updates rather than one transaction; the
/// engine's per-message attach is idempotent (same message_id
/// re-attached produces a no-op touch then a no-op update).
pub async fn attach_message(
    conn: &dyn DbConn,
    thread: &ThreadId,
    message: &MessageId,
    message_date: DateTime<Utc>,
) -> Result<(), StorageError> {
    conn.execute(
        TOUCH_FOR_MESSAGE,
        Params(vec![
            Value::Text(&thread.0),
            Value::Integer(message_date.timestamp()),
        ]),
    )
    .await?;
    conn.execute(
        ATTACH_MESSAGE,
        Params(vec![Value::Text(&message.0), Value::Text(&thread.0)]),
    )
    .await?;
    Ok(())
}

/// Tx-bound counterpart to [`insert`].
pub async fn insert_in_tx(tx: &mut dyn Tx, t: &Thread) -> Result<(), StorageError> {
    tx.execute(
        INSERT,
        Params(vec![
            Value::Text(&t.id.0),
            Value::Text(&t.account_id.0),
            t.root_message_id
                .as_ref()
                .map(|m| Value::Text(&m.0))
                .unwrap_or(Value::Null),
            Value::Text(&t.subject_normalized),
            Value::Integer(t.last_date.timestamp()),
            Value::Integer(t.message_count.into()),
        ]),
    )
    .await
    .map(|_| ())
}

/// Tx-bound counterpart to the touch step inside [`attach_message`].
/// The `UPDATE messages SET thread_id` step is not included here —
/// `sync_folder`'s batched path bakes `thread_id` into the message
/// INSERT directly, so the redundant attach UPDATE is dropped.
pub async fn touch_for_message_in_tx(
    tx: &mut dyn Tx,
    thread: &ThreadId,
    message_date: DateTime<Utc>,
) -> Result<(), StorageError> {
    tx.execute(
        TOUCH_FOR_MESSAGE,
        Params(vec![
            Value::Text(&thread.0),
            Value::Integer(message_date.timestamp()),
        ]),
    )
    .await
    .map(|_| ())
}

/// Tx-bound counterpart to the second statement of [`attach_message`].
/// Used by the heal-on-update path where an existing row had no
/// thread_id and we need to assign one inside the same chunk tx.
pub async fn set_message_thread_id_in_tx(
    tx: &mut dyn Tx,
    message: &MessageId,
    thread: &ThreadId,
) -> Result<(), StorageError> {
    tx.execute(
        ATTACH_MESSAGE,
        Params(vec![Value::Text(&message.0), Value::Text(&thread.0)]),
    )
    .await
    .map(|_| ())
}

/// Mint a new opaque thread id: `t-<32 hex chars>` (128 random bits).
///
/// The previous 32-bit form had a ~25 % cumulative birthday-collision
/// chance by 50k threads, and a collision is not benign — the PK
/// violation aborts the whole `apply_chunk` transaction and poisons
/// the connection. 128 bits makes collisions a non-event for any
/// mailbox size.
pub fn new_id() -> ThreadId {
    let n: u128 = rand::random();
    ThreadId(format!("t-{n:032x}"))
}

fn row_to_thread(row: &Row) -> Result<Thread, StorageError> {
    Ok(Thread {
        id: ThreadId(row.get_str("id")?.to_string()),
        account_id: AccountId(row.get_str("account_id")?.to_string()),
        root_message_id: row
            .get_optional_str("root_message_id")?
            .map(|s| MessageId(s.to_string())),
        subject_normalized: row.get_str("subject_normalized")?.to_string(),
        last_date: Utc
            .timestamp_opt(row.get_i64("last_date")?, 0)
            .single()
            .ok_or_else(|| StorageError::Db("invalid thread last_date".into()))?,
        message_count: u32::try_from(row.get_i64("message_count")?)
            .map_err(|e| StorageError::Db(format!("message_count out of range: {e}")))?,
    })
}
