// SPDX-License-Identifier: Apache-2.0

//! Local draft persistence. One row per outgoing message-in-progress.
//!
//! Phase 2 Week 17 introduces this repo as a pure local store; the
//! `save_draft` outbox op that mirrors rows up to the server's
//! Drafts mailbox lands in Week 20. The schema is in
//! `migrations/0004_drafts.sql`.

use chrono::{TimeZone, Utc};

use qsl_core::{
    AccountId, Draft, DraftAttachment, DraftBodyKind, DraftId, EmailAddress, MessageId,
    StorageError,
};

use super::json;
use crate::conn::{DbConn, Params, Row, Value};

const INSERT: &str = "
    INSERT INTO drafts
        (id, account_id, in_reply_to, references_json,
         to_json, cc_json, bcc_json,
         subject, body, body_kind, attachments_json,
         created_at, updated_at)
    VALUES
        (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
";

const UPDATE: &str = "
    UPDATE drafts
       SET account_id = ?2,
           in_reply_to = ?3,
           references_json = ?4,
           to_json = ?5,
           cc_json = ?6,
           bcc_json = ?7,
           subject = ?8,
           body = ?9,
           body_kind = ?10,
           attachments_json = ?11,
           updated_at = ?12
     WHERE id = ?1
";

const SELECT_BY_ID: &str = "SELECT id, account_id, in_reply_to, references_json, \
                            to_json, cc_json, bcc_json, \
                            subject, body, body_kind, attachments_json, \
                            created_at, updated_at \
                            FROM drafts WHERE id = ?1";

const SELECT_BY_ACCOUNT: &str = "SELECT id, account_id, in_reply_to, references_json, \
                                 to_json, cc_json, bcc_json, \
                                 subject, body, body_kind, attachments_json, \
                                 created_at, updated_at \
                                 FROM drafts WHERE account_id = ?1 \
                                 ORDER BY updated_at DESC";

const DELETE_BY_ID: &str = "DELETE FROM drafts WHERE id = ?1";

/// Insert a brand-new draft. Caller is responsible for minting a
/// fresh [`DraftId`] (see [`new_id`]).
pub async fn insert(conn: &dyn DbConn, draft: &Draft) -> Result<(), StorageError> {
    conn.execute(INSERT, to_params(draft)?).await.map(|_| ())
}

/// Update an existing draft in place. Returns
/// [`StorageError::NotFound`] if no row matches `draft.id` so callers
/// can fall through to `insert` in upsert flows.
pub async fn update(conn: &dyn DbConn, draft: &Draft) -> Result<(), StorageError> {
    let affected = conn.execute(UPDATE, update_params(draft)?).await?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

/// Upsert: update if present, insert if not. The Tauri command path
/// uses this so the auto-save tick on the compose pane doesn't have
/// to know whether the draft has been persisted yet.
pub async fn save(conn: &dyn DbConn, draft: &Draft) -> Result<(), StorageError> {
    match update(conn, draft).await {
        Ok(()) => Ok(()),
        Err(StorageError::NotFound) => insert(conn, draft).await,
        Err(e) => Err(e),
    }
}

/// Fetch a single draft by id. Returns [`StorageError::NotFound`]
/// when the row is absent (e.g. concurrent delete).
pub async fn get(conn: &dyn DbConn, id: &DraftId) -> Result<Draft, StorageError> {
    let row = conn
        .query_opt(SELECT_BY_ID, Params(vec![Value::Text(&id.0)]))
        .await?;
    match row {
        Some(r) => row_to_draft(&r),
        None => Err(StorageError::NotFound),
    }
}

/// Optional variant of [`get`] for callers that want to distinguish
/// "missing" from a real error.
pub async fn find(conn: &dyn DbConn, id: &DraftId) -> Result<Option<Draft>, StorageError> {
    let row = conn
        .query_opt(SELECT_BY_ID, Params(vec![Value::Text(&id.0)]))
        .await?;
    row.as_ref().map(row_to_draft).transpose()
}

/// Every draft for one account, newest-edited first.
pub async fn list_by_account(
    conn: &dyn DbConn,
    account: &AccountId,
) -> Result<Vec<Draft>, StorageError> {
    let rows = conn
        .query(SELECT_BY_ACCOUNT, Params(vec![Value::Text(&account.0)]))
        .await?;
    rows.iter().map(row_to_draft).collect()
}

/// Delete a draft. Missing rows are treated as success (idempotent
/// for the auto-save / discard race).
pub async fn delete(conn: &dyn DbConn, id: &DraftId) -> Result<(), StorageError> {
    conn.execute(DELETE_BY_ID, Params(vec![Value::Text(&id.0)]))
        .await
        .map(|_| ())
}

/// Look up the canonical server-side id for this draft. `Some` once
/// at least one upstream sync has succeeded; the next save_draft pass
/// destroys this id after the new APPEND / Email/import lands so the
/// server's Drafts mailbox doesn't accumulate every intermediate
/// version.
pub async fn get_server_id(
    conn: &dyn DbConn,
    id: &DraftId,
) -> Result<Option<MessageId>, StorageError> {
    let row = conn
        .query_opt(
            "SELECT server_id FROM drafts WHERE id = ?1",
            Params(vec![Value::Text(&id.0)]),
        )
        .await?;
    match row {
        Some(r) => Ok(r
            .get_optional_str("server_id")?
            .map(|s| MessageId(s.to_string()))),
        None => Ok(None),
    }
}

/// Persist the canonical server-side id for this draft. Called by
/// the outbox drain on a successful `save_draft` so the next cycle
/// can look it up via [`get_server_id`] and pass it in as the
/// `replace` argument.
///
/// Returns `Ok(())` even if the draft row no longer exists — the
/// user may have discarded the local draft while its outbox row was
/// in flight; persisting the server id then would either need the
/// row to be re-created (silently surprising) or the value dropped.
/// Dropping is the right move here: the server-side copy will
/// eventually be deleted manually or get cleaned up by a future
/// orphan sweep.
pub async fn set_server_id(
    conn: &dyn DbConn,
    id: &DraftId,
    server_id: &MessageId,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE drafts SET server_id = ?2 WHERE id = ?1",
        Params(vec![Value::Text(&id.0), Value::Text(&server_id.0)]),
    )
    .await
    .map(|_| ())
}

/// Mint a fresh [`DraftId`]. Format is `dr-<16-hex>` mirroring the
/// outbox repo's `ob-` prefix; the random byte block keeps the id
/// human-distinguishable from message ids and stable as a primary
/// key.
pub fn new_id() -> DraftId {
    let r = rand::random::<u64>();
    DraftId(format!("dr-{r:016x}"))
}

fn update_params(d: &Draft) -> Result<Params<'_>, StorageError> {
    let to_json = json::encode(&d.to)?;
    let cc_json = json::encode(&d.cc)?;
    let bcc_json = json::encode(&d.bcc)?;
    let refs_json = json::encode(&d.references)?;
    let attachments_json = json::encode(&d.attachments)?;
    let body_kind = d.body_kind.as_str().to_string();
    Ok(Params(vec![
        Value::OwnedText(d.id.0.clone()),
        Value::OwnedText(d.account_id.0.clone()),
        match &d.in_reply_to {
            Some(s) => Value::OwnedText(s.clone()),
            None => Value::Null,
        },
        Value::OwnedText(refs_json),
        Value::OwnedText(to_json),
        Value::OwnedText(cc_json),
        Value::OwnedText(bcc_json),
        Value::OwnedText(d.subject.clone()),
        Value::OwnedText(d.body.clone()),
        Value::OwnedText(body_kind),
        Value::OwnedText(attachments_json),
        Value::Integer(d.updated_at.timestamp()),
    ]))
}

fn to_params(d: &Draft) -> Result<Params<'_>, StorageError> {
    let to_json = json::encode(&d.to)?;
    let cc_json = json::encode(&d.cc)?;
    let bcc_json = json::encode(&d.bcc)?;
    let refs_json = json::encode(&d.references)?;
    let attachments_json = json::encode(&d.attachments)?;
    let body_kind = d.body_kind.as_str().to_string();
    Ok(Params(vec![
        Value::OwnedText(d.id.0.clone()),
        Value::OwnedText(d.account_id.0.clone()),
        match &d.in_reply_to {
            Some(s) => Value::OwnedText(s.clone()),
            None => Value::Null,
        },
        Value::OwnedText(refs_json),
        Value::OwnedText(to_json),
        Value::OwnedText(cc_json),
        Value::OwnedText(bcc_json),
        Value::OwnedText(d.subject.clone()),
        Value::OwnedText(d.body.clone()),
        Value::OwnedText(body_kind),
        Value::OwnedText(attachments_json),
        Value::Integer(d.created_at.timestamp()),
        Value::Integer(d.updated_at.timestamp()),
    ]))
}

fn row_to_draft(row: &Row) -> Result<Draft, StorageError> {
    let to: Vec<EmailAddress> = json::decode(row.get_str("to_json")?)?;
    let cc: Vec<EmailAddress> = json::decode(row.get_str("cc_json")?)?;
    let bcc: Vec<EmailAddress> = json::decode(row.get_str("bcc_json")?)?;
    let references: Vec<String> = json::decode(row.get_str("references_json")?)?;
    let attachments: Vec<DraftAttachment> = json::decode(row.get_str("attachments_json")?)?;
    let body_kind = match row.get_str("body_kind")? {
        "markdown" => DraftBodyKind::Markdown,
        _ => DraftBodyKind::Plain,
    };
    let in_reply_to = row.get_optional_str("in_reply_to")?.map(|s| s.to_string());
    Ok(Draft {
        id: DraftId(row.get_str("id")?.to_string()),
        account_id: AccountId(row.get_str("account_id")?.to_string()),
        in_reply_to,
        references,
        to,
        cc,
        bcc,
        subject: row.get_str("subject")?.to_string(),
        body: row.get_str("body")?.to_string(),
        body_kind,
        attachments,
        created_at: Utc.timestamp_opt(row.get_i64("created_at")?, 0).unwrap(),
        updated_at: Utc.timestamp_opt(row.get_i64("updated_at")?, 0).unwrap(),
    })
}
