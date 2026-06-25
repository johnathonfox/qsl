// SPDX-License-Identifier: Apache-2.0

//! QSL sync engine.
//!
//! Owns the top-level sync loop. Phase 1 Week 9 lands the per-folder
//! header sync orchestrator extracted from `mailcli`; subsequent weeks
//! grow it into a multi-folder daemon (one task per folder, one mpsc
//! event channel) plus the lazy-body-fetch path that `messages_get`
//! triggers when a reader-pane request arrives for a header-only row.
//!
//! The crate depends on `qsl-storage` and the `MailBackend` trait
//! from `qsl-core`. It deliberately knows nothing about IMAP- or
//! JMAP-specific quirks: a backend either returns the right shape or
//! it raises a `MailError` the caller can act on.

pub mod history;
pub mod outbox_drain;
pub mod threading;

use thiserror::Error;
use tracing::{debug, instrument, warn};

use std::collections::HashMap;

use qsl_core::{Folder, MailBackend, MailError, MessageHeaders, MessageId, StorageError, ThreadId};
use qsl_storage::{
    repos::{contacts, folders, messages, sync_states, threads as threads_repo},
    BlobStore, DbConn,
};

/// Outcome of a single [`sync_folder`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Headers newly inserted this cycle.
    pub added: usize,
    /// Already-known headers re-fetched and updated in place
    /// (full re-fetch path on a non-CONDSTORE response, or a header
    /// whose envelope changed).
    pub updated: usize,
    /// Already-known messages whose flags moved per the CONDSTORE
    /// `CHANGEDSINCE` pass. Distinct from `updated` because a flag
    /// update only touches the `flags_json` column — no full
    /// header re-fetch is required, so the engine applies them via
    /// `messages::update_flags`.
    pub flag_updates: usize,
    /// Server-side deletions the backend reported via `removed`.
    pub removed: usize,
    /// Bodies successfully fetched + persisted to the blob store this
    /// cycle. Always `<= added` since the body-fetch pass only runs
    /// for newly-inserted headers.
    pub bodies_fetched: usize,
    /// Body fetches that failed and were logged + skipped (transient
    /// network blip, UIDVALIDITY mismatch, parse failure on this
    /// specific message). Failed bodies are retried on the next
    /// `sync_folder` cycle that sees the message again, so this is
    /// non-fatal.
    pub bodies_failed: usize,
}

/// Errors from the sync engine. `MailError` covers protocol /
/// transport failures from the backend; `StorageError` covers local
/// persistence failures. The engine doesn't introduce new error
/// variants of its own — every failure mode already has a home in
/// one of the two layers it sits between.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Mail(#[from] MailError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Run one delta-sync cycle for `folder` against `backend`, persisting
/// the headers and the new sync cursor through `conn`. When `blobs`
/// is `Some`, also runs a body-fetch pass for newly-inserted
/// messages: `MailBackend::fetch_raw_message` → `BlobStore::put` →
/// `messages::set_body_path`.
///
/// The flow:
/// 1. Upsert the folder row so `sync_states` has somewhere to hang
///    its FK.
/// 2. Read the prior sync cursor (`None` on first run → full fetch
///    bounded by `limit`).
/// 3. Ask the backend for the delta. The IMAP adapter raises a
///    `MailError::Protocol` on UIDVALIDITY mismatch; that surfaces
///    here as `SyncError::Mail` and the caller decides whether to
///    clear the cursor and retry.
/// 4. Upsert each returned header and persist the new cursor.
/// 5. Apply the CONDSTORE `flag_updates` deltas via
///    `messages::update_flags`. Updates targeting an unknown ID
///    (cache out of sync) are logged and skipped rather than
///    failing the cycle.
/// 6. If `blobs` is `Some`, fetch raw bytes for each newly-inserted
///    header and stash them in the blob store. Per-message failures
///    here are logged + counted (`bodies_failed`) but don't fail the
///    cycle — the next `sync_folder` call retries any header without
///    a `body_path`.
#[instrument(skip_all, fields(folder = %folder.id.0))]
pub async fn sync_folder(
    conn: &dyn DbConn,
    backend: &dyn MailBackend,
    blobs: Option<&BlobStore>,
    folder: &Folder,
    limit: Option<u32>,
) -> Result<SyncReport, SyncError> {
    match folders::find(conn, &folder.id).await? {
        Some(_) => folders::update(conn, folder).await?,
        None => folders::insert(conn, folder).await?,
    }

    let prior = sync_states::get(conn, &folder.id).await?;

    // UIDVALIDITY-changed recovery: if the backend reports the cached
    // cursor's uidvalidity no longer matches what the server SELECT
    // returned, the cached UIDs are meaningless. Clear the cursor and
    // re-call list_messages with `prior = None` (the bounded
    // initial-sync path). The reconciliation pass below still runs
    // because `prior.is_some()` was true *before* recovery — exactly
    // what we want, since `list_known_ids` will return UIDs under the
    // *new* uidvalidity and the diff will prune every stale-UV row
    // that's still hanging around in the local cache. Without this
    // recovery the cursor stays poisoned and every subsequent sync
    // cycle re-errors on the same mismatch, leaving the folder
    // permanently stuck.
    let result = match backend
        .list_messages(&folder.id, prior.as_ref(), limit)
        .await
    {
        Ok(r) => r,
        Err(MailError::UidValidityChanged {
            folder: changed_folder,
            cached,
            observed,
        }) => {
            warn!(
                folder = %changed_folder,
                cached_uidvalidity = cached,
                observed_uidvalidity = observed,
                "UIDVALIDITY changed; clearing sync cursor and refetching from scratch"
            );
            sync_states::clear(conn, &folder.id).await?;
            backend.list_messages(&folder.id, None, limit).await?
        }
        Err(e) => return Err(e.into()),
    };

    let mut report = SyncReport::default();
    let mut new_headers: Vec<MessageHeaders> = Vec::new();
    apply_chunk(conn, &result.messages, &mut report, &mut new_headers).await?;
    // Apply backend-reported deletions (JMAP's `Email/changes.destroyed`
    // is the only path that hits this today — IMAP's adapter can't
    // surface VANISHED responses through async-imap, so it falls
    // through to the reconciliation pass below).
    for id in &result.removed {
        match messages::delete(conn, id).await {
            Ok(()) => report.removed += 1,
            Err(StorageError::NotFound) => {
                debug!(message = %id.0, "delete for unknown message — skipping");
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Reconciliation pass: ask the backend for the full live id set
    // for the folder and prune anything in storage that isn't in it.
    // Catches deletes IMAP-without-QRESYNC can't otherwise observe
    // (Gmail) and serves as a belt-and-braces correctness check
    // against JMAP's `Email/changes` (which can miss destroys past a
    // server's state-history retention window).
    //
    // Skipped on the very first sync (`prior` is `None`) — there's
    // nothing local to prune yet, and the bounded initial fetch
    // intentionally leaves history we don't want to misclassify as
    // server-side deletions.
    let mut pruned = 0u32;
    if prior.is_some() {
        match backend.list_known_ids(&folder.id).await {
            Ok(live_ids) if live_ids.is_empty() => {
                // Backend opted out (default impl returns empty) — we
                // can't safely diff against an "empty" set or we'd
                // wipe the whole folder. Skip silently.
            }
            Ok(live_ids) => {
                use std::collections::HashSet;
                let live: HashSet<&str> = live_ids.iter().map(|id| id.0.as_str()).collect();
                let local = messages::list_ids_by_folder(conn, &folder.id).await?;
                let local_count = local.len();
                for id in local {
                    if live.contains(id.0.as_str()) {
                        continue;
                    }
                    match messages::delete(conn, &id).await {
                        Ok(()) => {
                            report.removed += 1;
                            pruned += 1;
                        }
                        Err(StorageError::NotFound) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if pruned > 0 {
                    tracing::info!(
                        folder = %folder.id.0,
                        live = live.len(),
                        local = local_count,
                        pruned = pruned,
                        "sync_folder reconcile pruned server-deleted messages"
                    );
                }
            }
            Err(e) => {
                warn!(folder = %folder.id.0, "list_known_ids failed; skipping reconcile: {e}");
            }
        }
    }

    for (id, flags) in &result.flag_updates {
        match messages::update_flags(conn, id, flags).await {
            Ok(()) => report.flag_updates += 1,
            Err(StorageError::NotFound) => {
                // The CONDSTORE pass covers UIDs 1..uidnext-1, but the
                // local cache may not have every one of them — earlier
                // bounded syncs only pulled the most recent N. Log
                // and skip; it's not a sync failure.
                debug!(
                    message = %id.0,
                    "flag update for unknown message — skipping"
                );
            }
            Err(e) => return Err(e.into()),
        }
    }

    let mut new_state = result.new_state.clone();
    if pruned > 0 {
        if let Ok(Some(refreshed)) = backend.refresh_folder_state(&folder.id).await {
            new_state.backend_state = refreshed;
        }
    }
    sync_states::put(conn, &new_state).await?;

    if let Some(blobs) = blobs {
        for h in &new_headers {
            match fetch_and_store_body(conn, backend, blobs, h).await {
                Ok(()) => report.bodies_fetched += 1,
                Err(e) => {
                    warn!(
                        message = %h.id.0,
                        "body fetch failed: {e}"
                    );
                    report.bodies_failed += 1;
                }
            }
        }
    }

    debug!(
        added = report.added,
        updated = report.updated,
        flag_updates = report.flag_updates,
        removed = report.removed,
        bodies_fetched = report.bodies_fetched,
        bodies_failed = report.bodies_failed,
        "sync_folder cycle complete"
    );
    Ok(report)
}

/// Apply one fetch chunk's messages — find/insert/update + thread
/// assembly + contacts upserts — inside a single transaction.
///
/// **Why batched.** Turso 0.5.3's experimental Tantivy-backed FTS
/// rebuilds the `messages_fts_idx` directory on every implicit commit
/// of the `messages` table. Per-row writes (the prior shape: one
/// `messages::insert` + one `threads::attach_message` per header) had
/// the indexer running ~14 commits + GC passes per second on a busy
/// folder, which both wastes wall-clock and floods the log. One tx
/// per chunk collapses that to one rebuild. See
/// `docs/dependencies/turso.md` and `feedback_turso_quirks.md`.
///
/// **Two-phase shape.** Step 1 is read-only on `conn` and computes
/// every thread resolution (with chunk-local visibility so an
/// in-chunk back-reference still finds the thread its peer minted).
/// Step 2 opens a tx, mints the new threads, INSERTs / UPDATEs every
/// message with `thread_id` baked in, bumps thread message_count and
/// last_date, and upserts contacts — all in one commit.
async fn apply_chunk(
    conn: &dyn DbConn,
    headers: &[MessageHeaders],
    report: &mut SyncReport,
    new_headers: &mut Vec<MessageHeaders>,
) -> Result<(), SyncError> {
    if headers.is_empty() {
        return Ok(());
    }

    // Phase 1: read-only pre-pass on `conn`. No FTS-triggering writes.
    let existing = batch_find_existing(conn, headers).await?;

    let mut chunk_local: HashMap<String, ThreadId> = HashMap::new();
    let mut new_resolutions: HashMap<MessageId, threading::ThreadAttachment> = HashMap::new();
    let mut heal_resolutions: HashMap<MessageId, threading::ThreadAttachment> = HashMap::new();

    for h in headers {
        match existing.get(&h.id) {
            None => {
                let res = threading::resolve_with_chunk_local(conn, h, &chunk_local).await?;
                if let Some(rfc) = h.rfc822_message_id.as_deref() {
                    chunk_local.insert(rfc.to_string(), res.thread_id.clone());
                }
                new_resolutions.insert(h.id.clone(), res);
            }
            Some(ex) if ex.thread_id.is_none() => {
                // Heal-on-update: existing row has no thread_id — resolve and
                // attach it inside this chunk's tx. Same chunk-local
                // visibility rules as the new-row path.
                let res = threading::resolve_with_chunk_local(conn, h, &chunk_local).await?;
                if let Some(rfc) = h.rfc822_message_id.as_deref() {
                    chunk_local.insert(rfc.to_string(), res.thread_id.clone());
                }
                heal_resolutions.insert(h.id.clone(), res);
            }
            Some(ex) => {
                // Existing row already has a thread; chunk_local still gets
                // it so back-refs from later headers in this chunk land on
                // the right thread.
                if let (Some(rfc), Some(t)) =
                    (h.rfc822_message_id.as_deref(), ex.thread_id.as_ref())
                {
                    chunk_local.insert(rfc.to_string(), t.clone());
                }
            }
        }
    }

    // Phase 2: bucket headers into the three write paths so the
    // batch helpers can run in tight per-shape loops. The cross-row
    // chunk_local visibility is already settled by Phase 1 and lives
    // in the `*_resolutions` maps; here we only need stable ordering
    // (we walk `headers` so back-references inside one chunk land
    // before their dependents).
    let mut new_to_insert: Vec<MessageHeaders> = Vec::with_capacity(new_resolutions.len());
    let mut to_update_plain: Vec<MessageHeaders> = Vec::new();
    let mut to_update_heal: Vec<MessageHeaders> = Vec::with_capacity(heal_resolutions.len());
    let mut skipped_unchanged: usize = 0;
    for h in headers {
        if let Some(res) = new_resolutions.get(&h.id) {
            let mut h_with_thread = h.clone();
            h_with_thread.thread_id = Some(res.thread_id.clone());
            new_to_insert.push(h_with_thread);
        } else if heal_resolutions.contains_key(&h.id) {
            to_update_heal.push(h.clone());
        } else if let Some(ex) = existing.get(&h.id) {
            // Plain-update bucket — existing row already attached to a
            // thread. Skip the UPDATE entirely if the only mutable
            // fields (folder_id + flags + Gmail labels) match what we
            // already store. CONDSTORE/QRESYNC narrows the chunk
            // server-side, but folders without those extensions still
            // re-deliver every header on every poll, and even with
            // them the small steady-state deltas frequently re-shape
            // unchanged rows. Skipping here eliminates a per-row
            // UPDATE that touches FTS + every secondary index — the
            // dominant `slow_tx_execute` source after PR #144.
            //
            // Narrow comparison only — server-immutable fields
            // (subject, from, references, ...) aren't checked, so a
            // server that retroactively rewrites those would have its
            // change silently dropped. That's a pathological case in
            // practice; documented here so a future maintainer can
            // widen the comparison if it ever bites.
            let incoming_flags =
                serde_json::to_string(&h.flags).map_err(|e| StorageError::Serde(e.to_string()))?;
            let incoming_labels =
                serde_json::to_string(&h.labels).map_err(|e| StorageError::Serde(e.to_string()))?;
            if ex.folder_id == h.folder_id
                && ex.flags_json == incoming_flags
                && ex.labels_json == incoming_labels
            {
                skipped_unchanged += 1;
                continue;
            }
            to_update_plain.push(h.clone());
        } else {
            // Defensive: if `existing` doesn't have this id but
            // we're in the else branch (not new, not heal), the row
            // was deleted between Phase 1 and Phase 2. Treat as a
            // plain UPDATE; the UPDATE will affect 0 rows and
            // `batch_update_in_tx` already silently tolerates that.
            to_update_plain.push(h.clone());
        }
    }
    if skipped_unchanged > 0 {
        debug!(
            skipped = skipped_unchanged,
            chunk_size = headers.len(),
            "apply_chunk: skipped UPDATEs for unchanged rows"
        );
    }

    // Phase 3: one tx per chunk wrapping every write — preserves
    // the one-Tantivy-commit-per-chunk shape that was the whole
    // point of the prior single-tx structure. Inside the tx we
    // collapse the per-row INSERT loop into a single multi-row
    // INSERT OR IGNORE (saves N-1 statement dispatches), and the
    // per-row UPDATE loop into one batched call. Per-thread and
    // per-address writes stay row-by-row because they reference
    // cross-row state that the batch helpers don't carry.
    let mut tx = conn.begin().await?;

    // Mint all new threads first so the FK constraint on
    // messages.thread_id is satisfied when the message INSERTs land.
    for r in new_resolutions.values().chain(heal_resolutions.values()) {
        if let Some(mint) = &r.mint {
            threads_repo::insert_in_tx(&mut *tx, mint).await?;
        }
    }

    // Multi-row INSERT for new headers, then per-thread touch +
    // per-address contact upsert. Each new chunk-local header has
    // its `thread_id` baked in by the bucket loop above so the row
    // lands fully attached.
    let now = chrono::Utc::now().timestamp();
    if !new_to_insert.is_empty() {
        messages::batch_insert_skip_existing_in_tx(&mut *tx, &new_to_insert).await?;
        for h in &new_to_insert {
            // h.thread_id is Some(_) by construction — set in bucket.
            if let Some(tid) = h.thread_id.as_ref() {
                threads_repo::touch_for_message_in_tx(&mut *tx, tid, h.date).await?;
            }
            for addr in &h.from {
                contacts::upsert_seen_in_tx(
                    &mut *tx,
                    &addr.address,
                    addr.display_name.as_deref(),
                    contacts::Source::Inbound,
                    now,
                )
                .await?;
            }
        }
        report.added += new_to_insert.len();
        // Strip the synthesised thread_id from the announce vec so
        // downstream consumers see the original wire-shape header.
        for h in &new_to_insert {
            let mut announce = h.clone();
            announce.thread_id = None;
            new_headers.push(announce);
        }
    }

    // Heal-on-update: batch UPDATE the messages (UPDATE clause
    // intentionally excludes thread_id), then per-row attach the
    // newly-resolved thread_id + touch the thread.
    if !to_update_heal.is_empty() {
        messages::batch_update_in_tx(&mut *tx, &to_update_heal).await?;
        for h in &to_update_heal {
            if let Some(res) = heal_resolutions.get(&h.id) {
                threads_repo::set_message_thread_id_in_tx(&mut *tx, &h.id, &res.thread_id).await?;
                threads_repo::touch_for_message_in_tx(&mut *tx, &res.thread_id, h.date).await?;
            }
        }
        report.updated += to_update_heal.len();
    }

    // Plain UPDATE — existing rows that already had a thread_id.
    if !to_update_plain.is_empty() {
        messages::batch_update_in_tx(&mut *tx, &to_update_plain).await?;
        report.updated += to_update_plain.len();
    }

    tx.commit().await?;
    Ok(())
}

/// One row's worth of "what's already in storage" state, used by
/// [`apply_chunk`] to decide both threading attachment and whether
/// an incoming server-row actually differs from what we have.
///
/// The equality check is intentionally narrow — only the fields
/// that can legitimately change between syncs (location + mutable
/// flags + Gmail labels) are compared — so the rest of the UPDATE
/// path stays trustworthy on the rare edge case where a server
/// amends an "immutable" header.
pub(crate) struct ExistingRow {
    pub thread_id: Option<ThreadId>,
    pub folder_id: qsl_core::FolderId,
    /// Wire-encoded `MessageFlags` exactly as stored in
    /// `messages.flags_json`. Comparing the encoded form lets us
    /// skip a JSON parse per row.
    pub flags_json: String,
    /// Wire-encoded labels (`Vec<String>`) exactly as stored in
    /// `messages.labels_json`. Same shape as `flags_json`.
    pub labels_json: String,
}

/// Probe storage for which message ids in `headers` already exist,
/// returning a map from id → existing row state. Used both to drive
/// threading attachment in [`apply_chunk`]'s Phase 1 and to gate the
/// plain-update bucket in Phase 2 — a re-synced row whose
/// `(folder_id, flags_json, labels_json)` already match the
/// incoming wire-shape produces no DB write at all, eliminating the
/// FTS+secondary-index churn that was the dominant remaining
/// `slow_tx_execute` source after PR #144 silenced the count
/// cascade.
async fn batch_find_existing(
    conn: &dyn DbConn,
    headers: &[MessageHeaders],
) -> Result<HashMap<MessageId, ExistingRow>, StorageError> {
    if headers.is_empty() {
        return Ok(HashMap::new());
    }
    use qsl_storage::{Params as StorageParams, Value as StorageValue};
    // `UNION ALL` of single-id `WHERE id = ?` branches forces a PK
    // index seek (point lookup) per branch. `WHERE id IN (?, ?, …)`
    // over the PK plans as a full-table SCAN with an in-memory filter
    // set on Turso 0.5.3, which costs ~575-611 ms on a 30k-row
    // messages table (telemetry 2026-05-08, /tmp/qsl.log). The
    // UNION-ALL shape is still one query (one parse, one round-trip)
    // and the planner does the right thing per-branch.
    let mut sql = String::with_capacity(headers.len() * 96);
    for i in 1..=headers.len() {
        if i > 1 {
            sql.push_str(" UNION ALL ");
        }
        sql.push_str(
            "SELECT id, thread_id, folder_id, flags_json, labels_json FROM messages WHERE id = ?",
        );
        sql.push_str(&i.to_string());
    }
    let storage_params: Vec<StorageValue> = headers
        .iter()
        .map(|h| StorageValue::Text(&h.id.0))
        .collect();
    let rows = conn.query(&sql, StorageParams(storage_params)).await?;

    let mut out: HashMap<MessageId, ExistingRow> = HashMap::with_capacity(rows.len());
    for r in &rows {
        let id = MessageId(r.get_str("id")?.to_string());
        let thread_id = r
            .get_optional_str("thread_id")?
            .map(|s| ThreadId(s.to_string()));
        let folder_id = qsl_core::FolderId(r.get_str("folder_id")?.to_string());
        let flags_json = r.get_str("flags_json")?.to_string();
        let labels_json = r.get_str("labels_json")?.to_string();
        out.insert(
            id,
            ExistingRow {
                thread_id,
                folder_id,
                flags_json,
                labels_json,
            },
        );
    }
    Ok(out)
}

/// One folder's slice of a [`sync_account`] cycle.
#[derive(Debug)]
pub struct FolderSyncOutcome {
    pub folder_id: qsl_core::FolderId,
    pub result: Result<SyncReport, SyncError>,
}

/// Run [`sync_folder`] across every folder the backend advertises.
///
/// One-shot multi-folder cycle: discovers folders via
/// `list_folders`, then drives `sync_folder` on each in sequence
/// (the backends serialize on a single connection anyway). Per-
/// folder failures are captured in [`FolderSyncOutcome::result`]
/// rather than aborting the whole cycle — a UIDVALIDITY mismatch on
/// one folder shouldn't take down sync for the rest.
///
/// Returns one outcome per folder in the order the backend returned
/// them. The desktop app's bootstrap calls this on launch; the live
/// sync engine (Week 10) drives it again on each `BackendEvent`
/// (or on a polling timer for backends without push).
#[instrument(skip_all)]
pub async fn sync_account(
    conn: &dyn DbConn,
    backend: &dyn MailBackend,
    blobs: Option<&BlobStore>,
    limit_per_folder: Option<u32>,
) -> Result<Vec<FolderSyncOutcome>, SyncError> {
    let folders = backend.list_folders().await?;
    let mut outcomes = Vec::with_capacity(folders.len());
    for folder in folders {
        let folder_id = folder.id.clone();
        let result = sync_folder(conn, backend, blobs, &folder, limit_per_folder).await;
        if let Err(e) = &result {
            warn!(folder = %folder_id.0, "sync_folder failed: {e}");
        }
        outcomes.push(FolderSyncOutcome { folder_id, result });
    }
    Ok(outcomes)
}

/// Fetch the raw bytes of a single message and persist them via the
/// blob store + `body_path` column. Pulled out of [`sync_folder`] so
/// the per-message error path is isolated and the engine can keep
/// going after a single bad fetch.
async fn fetch_and_store_body(
    conn: &dyn DbConn,
    backend: &dyn MailBackend,
    blobs: &BlobStore,
    header: &MessageHeaders,
) -> Result<(), SyncError> {
    let raw = qsl_telemetry::time_op!(
        target: "qsl::slow::imap",
        limit_ms: qsl_telemetry::slow::limits::IMAP_CMD_MS,
        op: "fetch_raw_message",
        fields: { account = %header.account_id.0, folder = %header.folder_id.0, message = %header.id.0 },
        backend.fetch_raw_message(&header.id)
    )?;
    let bytes = raw.len() as u64;
    let path = qsl_telemetry::time_op!(
        target: "qsl::slow::db",
        limit_ms: qsl_telemetry::slow::limits::DB_QUERY_MS,
        op: "blob_put",
        fields: { account = %header.account_id.0, folder = %header.folder_id.0, bytes = bytes },
        blobs.put(&header.account_id, &header.folder_id, &header.id, &raw)
    )?;
    messages::set_body_path(conn, &header.id, Some(&path.to_string_lossy())).await?;
    Ok(())
}
