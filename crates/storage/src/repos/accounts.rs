// SPDX-License-Identifier: Apache-2.0

//! Account persistence. One row per configured account.

use chrono::{DateTime, TimeZone, Utc};

use qsl_core::{Account, AccountId, BackendKind, StorageError};

use crate::conn::{DbConn, Params, Row, Value};

const INSERT: &str = "
    INSERT INTO accounts (id, kind, display_name, email_address, created_at, signature, notify_enabled)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
";

const UPDATE: &str = "
    UPDATE accounts
       SET kind = ?2,
           display_name = ?3,
           email_address = ?4,
           signature = ?5,
           notify_enabled = ?6
     WHERE id = ?1
";

const SELECT_BY_ID: &str = "
    SELECT id, kind, display_name, email_address, created_at, signature, notify_enabled
      FROM accounts
     WHERE id = ?1
";

const SELECT_ALL: &str = "
    SELECT id, kind, display_name, email_address, created_at, signature, notify_enabled
      FROM accounts
     ORDER BY created_at ASC
";

const DELETE_BY_ID: &str = "DELETE FROM accounts WHERE id = ?1";

const UPDATE_DISPLAY_NAME: &str = "UPDATE accounts SET display_name = ?2 WHERE id = ?1";
const UPDATE_SIGNATURE: &str = "UPDATE accounts SET signature = ?2 WHERE id = ?1";
const UPDATE_NOTIFY_ENABLED: &str = "UPDATE accounts SET notify_enabled = ?2 WHERE id = ?1";

/// Insert a new account. Returns [`StorageError::Conflict`] if the id or
/// email address is already taken.
pub async fn insert(conn: &dyn DbConn, account: &Account) -> Result<(), StorageError> {
    conn.execute(INSERT, to_params(account)).await.map(|_| ())
}

/// Overwrite an existing account by id. Returns [`StorageError::NotFound`]
/// if no row matched.
pub async fn update(conn: &dyn DbConn, account: &Account) -> Result<(), StorageError> {
    let affected = conn.execute(UPDATE, update_params(account)).await?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

/// Fetch by id; [`StorageError::NotFound`] if missing.
pub async fn get(conn: &dyn DbConn, id: &AccountId) -> Result<Account, StorageError> {
    let row = conn
        .query_one(SELECT_BY_ID, Params(vec![Value::Text(&id.0)]))
        .await?;
    row_to_account(&row)
}

/// Fetch by id, or `None` if missing.
pub async fn find(conn: &dyn DbConn, id: &AccountId) -> Result<Option<Account>, StorageError> {
    let maybe = conn
        .query_opt(SELECT_BY_ID, Params(vec![Value::Text(&id.0)]))
        .await?;
    maybe.map(|r| row_to_account(&r)).transpose()
}

/// Return all accounts ordered by `created_at`.
pub async fn list(conn: &dyn DbConn) -> Result<Vec<Account>, StorageError> {
    let rows = conn.query(SELECT_ALL, Params::empty()).await?;
    rows.iter().map(row_to_account).collect()
}

/// Delete by id. A missing id is treated as success. The schema's
/// `ON DELETE CASCADE` on `folders.account_id` (and the cascade
/// chain through messages / threads / outbox / contacts) does the
/// rest of the cleanup.
pub async fn delete(conn: &dyn DbConn, id: &AccountId) -> Result<(), StorageError> {
    conn.execute(DELETE_BY_ID, Params(vec![Value::Text(&id.0)]))
        .await
        .map(|_| ())
}

/// Patch just the display name. Cheaper than a full `update` round
/// trip and the only field the Settings → Accounts tab edits at the
/// row level.
pub async fn set_display_name(
    conn: &dyn DbConn,
    id: &AccountId,
    name: &str,
) -> Result<(), StorageError> {
    let affected = conn
        .execute(
            UPDATE_DISPLAY_NAME,
            Params(vec![Value::Text(&id.0), Value::Text(name)]),
        )
        .await?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

/// Patch the signature. `None` clears it (sets the column to SQL
/// NULL); `Some("")` is treated as `None` so we don't store empty
/// strings as a distinct state.
pub async fn set_signature(
    conn: &dyn DbConn,
    id: &AccountId,
    signature: Option<&str>,
) -> Result<(), StorageError> {
    let value = match signature {
        Some(s) if !s.is_empty() => Value::Text(s),
        _ => Value::Null,
    };
    let affected = conn
        .execute(UPDATE_SIGNATURE, Params(vec![Value::Text(&id.0), value]))
        .await?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

/// Toggle the per-account notification gate.
pub async fn set_notify_enabled(
    conn: &dyn DbConn,
    id: &AccountId,
    enabled: bool,
) -> Result<(), StorageError> {
    let affected = conn
        .execute(
            UPDATE_NOTIFY_ENABLED,
            Params(vec![Value::Text(&id.0), Value::Integer(i64::from(enabled))]),
        )
        .await?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

fn update_params(a: &Account) -> Params<'_> {
    Params(vec![
        Value::Text(&a.id.0),
        Value::OwnedText(backend_kind_str(&a.kind).into()),
        Value::Text(&a.display_name),
        Value::Text(&a.email_address),
        match a.signature.as_deref() {
            Some(s) if !s.is_empty() => Value::Text(s),
            _ => Value::Null,
        },
        Value::Integer(i64::from(a.notify_enabled)),
    ])
}

fn to_params(a: &Account) -> Params<'_> {
    Params(vec![
        Value::Text(&a.id.0),
        Value::OwnedText(backend_kind_str(&a.kind).into()),
        Value::Text(&a.display_name),
        Value::Text(&a.email_address),
        Value::Integer(a.created_at.timestamp()),
        match a.signature.as_deref() {
            Some(s) if !s.is_empty() => Value::Text(s),
            _ => Value::Null,
        },
        Value::Integer(i64::from(a.notify_enabled)),
    ])
}

fn row_to_account(row: &Row) -> Result<Account, StorageError> {
    // `signature` is a nullable column; treat any get-error as "not
    // present" so post-migration rows that haven't been touched
    // since the ALTER deserialize cleanly. `notify_enabled` defaults
    // to 1 in the migration, so a missing read is also treated as
    // the on-by-default state.
    let signature = row
        .get_str("signature")
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let notify_enabled = row.get_i64("notify_enabled").unwrap_or(1) != 0;
    Ok(Account {
        id: AccountId(row.get_str("id")?.to_string()),
        kind: backend_kind_from_str(row.get_str("kind")?)?,
        display_name: row.get_str("display_name")?.to_string(),
        email_address: row.get_str("email_address")?.to_string(),
        created_at: timestamp_to_utc(row.get_i64("created_at")?)?,
        signature,
        notify_enabled,
    })
}

fn backend_kind_str(kind: &BackendKind) -> &'static str {
    // `BackendKind` is `#[non_exhaustive]`; the wildcard exists to keep the
    // storage crate compiling if a future variant is added without a migration.
    match kind {
        BackendKind::ImapSmtp => "imap_smtp",
        BackendKind::Jmap => "jmap",
        _ => "unknown",
    }
}

fn backend_kind_from_str(s: &str) -> Result<BackendKind, StorageError> {
    match s {
        "imap_smtp" => Ok(BackendKind::ImapSmtp),
        "jmap" => Ok(BackendKind::Jmap),
        other => Err(StorageError::Db(format!("unknown backend kind: {other}"))),
    }
}

fn timestamp_to_utc(secs: i64) -> Result<DateTime<Utc>, StorageError> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .ok_or_else(|| StorageError::Db(format!("invalid timestamp: {secs}")))
}
