// SPDX-License-Identifier: Apache-2.0

//! `drafts_*` Tauri commands. Phase 2 Week 17 + Week 20.
//!
//! Local-first persistence for outgoing messages-in-progress, plus
//! best-effort upstream sync to the account's Drafts mailbox via the
//! outbox. The compose pane calls `drafts_save` on every
//! keystroke-debounced auto-save tick and on manual Save / Discard;
//! every save persists locally and (when the draft has at least one
//! recipient and a from-able account) enqueues a coalescing
//! `OP_SAVE_DRAFT` outbox row keyed by the local draft id, so a
//! flurry of typing doesn't generate a flurry of server APPENDs.
//! The drain dispatches each row to `MailBackend::save_draft`.

use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine as _;
use chrono::Utc;

use qsl_core::{Draft, DraftAttachment, DraftBodyKind, EmailAddress};
use qsl_ipc::{AccountId, DraftId, IpcResult};
use qsl_mime::compose::build_rfc5322;
use qsl_storage::repos::{accounts as accounts_repo, drafts as drafts_repo, outbox as outbox_repo};
use serde::Deserialize;
use tauri::State;

use crate::state::AppState;

/// Wire-shape draft sent up by the compose pane. Mirrors [`Draft`]
/// minus the timestamps (assigned server-side) and with `id` made
/// optional so a fresh compose can be saved without the UI inventing
/// an id first.
#[derive(Debug, Deserialize)]
pub struct DraftInput {
    #[serde(default)]
    pub id: Option<DraftId>,
    pub account_id: AccountId,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub to: Vec<EmailAddress>,
    #[serde(default)]
    pub cc: Vec<EmailAddress>,
    #[serde(default)]
    pub bcc: Vec<EmailAddress>,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub body_kind: DraftBodyKind,
    #[serde(default)]
    pub attachments: Vec<DraftAttachment>,
}

#[derive(Debug, Deserialize)]
pub struct DraftsSaveInput {
    pub draft: DraftInput,
}

/// `drafts_save` — upsert a draft. Returns the draft's id (newly
/// minted on first save) so the UI can swap from "unsaved" state
/// into "saved-with-id" without a follow-up round-trip.
#[tauri::command]
pub async fn drafts_save(state: State<'_, AppState>, input: DraftsSaveInput) -> IpcResult<DraftId> {
    let DraftsSaveInput { draft } = input;
    tracing::debug!(
        existing_id = draft.id.as_ref().map(|id| id.0.as_str()).unwrap_or("(new)"),
        "ipc: drafts_save"
    );
    let now = Utc::now();

    let db = state.db.lock().await;
    let (id, created_at, prior_attachments): (
        DraftId,
        chrono::DateTime<chrono::Utc>,
        Vec<DraftAttachment>,
    ) = match draft.id {
        Some(existing_id) => {
            // Preserve the original `created_at` if the draft was
            // already in the table, otherwise this is a UI-issued
            // id we've never seen — treat the save as create.
            match drafts_repo::find(&*db, &existing_id).await? {
                Some(existing) => (existing_id, existing.created_at, existing.attachments),
                None => (existing_id, now, Vec::new()),
            }
        }
        None => (drafts_repo::new_id(), now, Vec::new()),
    };

    // Attachment paths are read from disk by `build_rfc5322` and the
    // bytes end up in the outbox and on the server. Only accept paths
    // the user actually chose through the native picker this session,
    // or that were already persisted on this draft by an earlier
    // validated save (drafts survive restarts). Anything else is a
    // webview naming an arbitrary local file.
    {
        let picked = state.picked_attachment_paths.lock().await;
        for att in &draft.attachments {
            let path = std::path::Path::new(&att.path);
            let allowed =
                picked.contains(path) || prior_attachments.iter().any(|p| p.path == att.path);
            if !allowed {
                return Err(qsl_ipc::IpcError::new(
                    qsl_ipc::IpcErrorKind::Permission,
                    format!(
                        "drafts_save: attachment {:?} was not chosen through the file picker",
                        att.filename
                    ),
                ));
            }
        }
    }

    let row = Draft {
        id: id.clone(),
        account_id: draft.account_id,
        in_reply_to: draft.in_reply_to,
        references: draft.references,
        to: draft.to,
        cc: draft.cc,
        bcc: draft.bcc,
        subject: draft.subject,
        body: draft.body,
        body_kind: draft.body_kind,
        attachments: draft.attachments,
        created_at,
        updated_at: now,
    };
    drafts_repo::save(&*db, &row).await?;

    // Best-effort upstream sync. We only enqueue when:
    //   1. The draft has at least one recipient — `build_rfc5322`
    //      rejects empty-recipient messages, and a freshly opened
    //      compose with no To/Cc/Bcc set yet would just bounce off
    //      that check and DLQ. Skipping silently here keeps the
    //      auto-save tick noise-free until the user starts typing
    //      addresses.
    //   2. The account is still around — accounts_repo::find returns
    //      None mid-removal, in which case there's nothing to APPEND
    //      to.
    //
    // Failure to enqueue is logged-and-swallowed: the local draft is
    // already persisted, that's the source of truth. The user will
    // see their draft locally regardless of whether the server-side
    // copy ever lands.
    if !row.to.is_empty() || !row.cc.is_empty() || !row.bcc.is_empty() {
        if let Some(account) = accounts_repo::find(&*db, &row.account_id).await? {
            let from = EmailAddress {
                address: account.email_address.clone(),
                display_name: Some(account.display_name.clone()),
            };
            match build_rfc5322(&row, &from) {
                Ok(built) => {
                    let payload = serde_json::json!({
                        "draft_id": id.0,
                        "raw_b64": base64_engine.encode(&built.bytes),
                    });
                    if let Err(e) = outbox_repo::enqueue_dedup(
                        &*db,
                        &row.account_id,
                        qsl_sync::outbox_drain::OP_SAVE_DRAFT,
                        &payload.to_string(),
                        &id.0,
                    )
                    .await
                    {
                        tracing::warn!(
                            id = %id.0,
                            "drafts_save: outbox enqueue failed: {e}"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        id = %id.0,
                        "drafts_save: skipping upstream sync (build_rfc5322: {e})"
                    );
                }
            }
        }
    }
    drop(db);

    tracing::debug!(id = %id.0, "drafts_save");
    Ok(id)
}

#[derive(Debug, Deserialize)]
pub struct DraftsLoadInput {
    pub id: DraftId,
}

/// `drafts_load` — fetch a single draft. Used when the user
/// re-opens compose from the sidebar's Drafts entry or after
/// process restart.
#[tauri::command]
pub async fn drafts_load(state: State<'_, AppState>, input: DraftsLoadInput) -> IpcResult<Draft> {
    let db = state.db.lock().await;
    Ok(drafts_repo::get(&*db, &input.id).await?)
}

#[derive(Debug, Deserialize)]
pub struct DraftsListInput {
    pub account_id: AccountId,
}

/// `drafts_list` — every draft for one account, newest-edited first.
/// Sized so the entire result set fits in a single IPC payload — no
/// pagination today; if the working set grows past hundreds of
/// drafts we'll add an offset/limit shape mirroring `messages_list`.
#[tauri::command]
pub async fn drafts_list(
    state: State<'_, AppState>,
    input: DraftsListInput,
) -> IpcResult<Vec<Draft>> {
    let db = state.db.lock().await;
    Ok(drafts_repo::list_by_account(&*db, &input.account_id).await?)
}

#[derive(Debug, Deserialize)]
pub struct DraftsDeleteInput {
    pub id: DraftId,
}

/// `drafts_delete` — discard a draft. Idempotent: deleting a
/// non-existent id returns `Ok(())`.
#[tauri::command]
pub async fn drafts_delete(state: State<'_, AppState>, input: DraftsDeleteInput) -> IpcResult<()> {
    tracing::debug!(id = %input.id.0, "ipc: drafts_delete");
    let db = state.db.lock().await;
    drafts_repo::delete(&*db, &input.id).await?;
    Ok(())
}
