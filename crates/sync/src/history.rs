// SPDX-License-Identifier: Apache-2.0

//! Full-archive history backfill driver.
//!
//! `pull_history` walks one (account, folder) pair from where the
//! bootstrap sync left off and pages every older message in via the
//! backend's [`MailBackend::pull_history_chunk`] method. State is
//! persisted to `history_sync_state` after every chunk so the work
//! is resumable across app restarts.
//!
//! Wired up by `apps/desktop/src-tauri/src/commands/history_sync.rs`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use qsl_core::{AccountId, FolderId, HistoryChunk, MailBackend, MessageHeaders};
use qsl_storage::{
    repos::{
        history_sync as history_repo, history_sync::HistorySyncStatus as RepoStatus, messages,
    },
    DbConn, Params, TursoConn,
};

use crate::SyncError;

/// How many headers to ask the backend for per chunk.
///
/// 1500 maximizes per-chunk throughput on the post-multi-row-INSERT
/// hot path (`messages::batch_insert_skip_existing` collapses 1500
/// rows into one SQL statement, the largest size that still fits
/// SQLite's 32766-placeholder limit at 20 cols/row). At chunk index
/// ≥ 2 the per-chunk wall-clock is dominated by Gmail's UID FETCH
/// — so amortizing more rows per FETCH cuts total backfill time
/// roughly proportionally.
///
/// Trade-off: the first chunk's wall-clock scales with chunk size
/// (Gmail returns a single big UID FETCH response). At 500 the user
/// saw a progress tick within ~10s; at 1500 that becomes ~30-45s
/// before the bar moves. Acceptable for full-history backfills (the
/// total saving more than offsets the start delay) but the
/// responsiveness hit was the reason 1000 was rolled back earlier
/// — revisit if users complain that "Pulling history" looks frozen
/// at the start.
pub const HISTORY_CHUNK_SIZE: u32 = 1500;

/// Sleep between chunks in the consumer. Two competing pressures:
///   - Network connection should stay hot (Gmail's "Too many
///     simultaneous connections" gate trips on concurrent IMAP
///     sessions, not on a single session's request rate).
///   - The bulk insert path holds the SQLite WAL writer for
///     ~500ms-1s per chunk. With the pipeline (depth-1) producer
///     fetching ahead, chunks land every ~1.5s — without this
///     pause the writer is held nearly continuously and concurrent
///     IPC reads (Settings, message-list refresh, message-get)
///     stall. 250ms gives readers a predictable acquire window
///     every chunk while costing only ~15% throughput on the
///     dominant Gmail-fetch wall-clock.
///
/// Errors-with-backoff still use the longer [`THROTTLE_RECOVERY_MS`].
pub const INTER_CHUNK_DELAY_MS: u64 = 250;

/// Wait this long after a chunk fails before retrying. Compounds with
/// the [`MAX_CHUNK_RETRIES`] cap below.
pub const THROTTLE_RECOVERY_MS: u64 = 30_000;

/// Stop trying after this many consecutive chunk failures and move
/// the row to `error` so the user can decide to restart. Fewer means
/// less wasted bandwidth on a flat-out broken connection; more means
/// we tolerate longer transient outages without the user noticing.
/// 5 covers a multi-minute Wi-Fi flap with the 30-second recovery
/// delay.
pub const MAX_CHUNK_RETRIES: u32 = 5;

/// Reported back to the caller after every chunk. The Tauri shell
/// turns these into `SyncEvent::HistorySyncProgress` events for the
/// UI.
#[derive(Debug, Clone)]
pub struct HistoryProgress {
    pub fetched_total: u32,
    pub anchor_uid: i64,
    pub total_estimate: Option<i64>,
    pub finished: bool,
}

/// Drive a full-history pull for `(account, folder)` against
/// `backend`, persisting headers as they arrive.
///
/// `start_anchor` is the UID strictly above which to fetch. The
/// caller is responsible for picking it: usually `min(local UIDs in
/// folder)` for a fresh start, or the persisted `anchor_uid` for a
/// resume. `total_estimate` is the upper bound for progress display
/// (usually `uidnext - 1` captured at start).
///
/// `db` is locked **per-chunk**, not for the whole pull, so the live
/// sync engine and other commands can keep using the same connection
/// while the IMAP fetch is in flight (which can take seconds per
/// chunk). The IMAP backend has its own per-session mutex so
/// concurrent commands queue cleanly there.
///
/// `cancel` flips when the user clicks cancel from the UI; checked
/// between chunks. `progress` is invoked at start and on every chunk
/// so the UI can render percent-complete; the start invocation gives
/// the user immediate "it's running" feedback before the first chunk
/// returns.
///
/// Returns when the historical tail is exhausted, the cancel flag
/// flips, or an unrecoverable error trips the retry budget. The
/// `history_sync_state` row reflects the terminal status either way.
#[allow(clippy::too_many_arguments)]
pub async fn pull_history<F>(
    db: Arc<Mutex<TursoConn>>,
    backend: &dyn MailBackend,
    account: &AccountId,
    folder: &FolderId,
    start_anchor: u64,
    total_estimate: Option<u64>,
    cancel: Arc<AtomicBool>,
    mut progress: F,
) -> Result<(), SyncError>
where
    F: FnMut(HistoryProgress),
{
    let pull_started_at = Instant::now();
    info!(
        account = %account.0,
        folder = %folder.0,
        start_anchor,
        total_estimate = ?total_estimate,
        "history sync starting"
    );

    // Persist the running row up front. Brief lock; release so the
    // sync engine can use the connection while we wait on IMAP.
    {
        let conn = db.lock().await;
        history_repo::start(
            &*conn,
            account,
            folder,
            start_anchor as i64,
            total_estimate.map(|v| v as i64),
        )
        .await?;
    }

    // Emit a starting progress event so the UI shows "0 fetched"
    // immediately on click rather than waiting tens of seconds for
    // the first chunk to land.
    progress(HistoryProgress {
        fetched_total: 0,
        anchor_uid: start_anchor as i64,
        total_estimate: total_estimate.map(|v| v as i64),
        finished: false,
    });

    // FTS index lifecycle. Turso 0.5.3's experimental `USING fts`
    // index commits Tantivy on every INSERT at ~250ms/row, which
    // dominates the bulk insert cost. Drop the index for the
    // duration of the pull and rebuild it once over the final
    // table. Both calls are best-effort: if the drop fails (e.g.
    // index never existed on this DB) we proceed; if the recreate
    // fails the user can run `mailcli doctor --rebuild-fts`.
    if let Err(e) = drop_fts_index(&db).await {
        warn!("FTS drop failed (continuing without dropping): {e}");
    }

    // Pipeline: producer fetches chunks, consumer inserts them. With
    // a depth-1 mpsc buffer the IMAP fetch for chunk N+1 overlaps
    // with the SQL insert for chunk N — IMAP is network-bound, the
    // insert is disk/CPU-bound, so the two costs were previously
    // serialised end-to-end. Both halves run on the same task via
    // `tokio::join!`, so the producer can borrow `&dyn MailBackend`
    // without a `'static` bound.
    let pipeline_outcome = {
        let (tx, rx) = mpsc::channel::<FetchOutcome>(1);

        let producer = run_producer(backend, folder, start_anchor, cancel.clone(), tx);
        let consumer = run_consumer(
            db.clone(),
            account,
            folder,
            start_anchor,
            total_estimate,
            cancel,
            rx,
            &mut progress,
            pull_started_at,
        );

        let (_, consumer_outcome) = tokio::join!(producer, consumer);
        consumer_outcome
    };

    // Recreate the FTS index over the now-final table. Single
    // build vs the per-INSERT commits we just avoided. Best-effort
    // so a failure here doesn't mask a successful pull — the
    // `pipeline_outcome` is what callers care about.
    if let Err(e) = create_fts_index(&db).await {
        warn!("FTS recreate failed (run `mailcli doctor --rebuild-fts`): {e}");
    }

    pipeline_outcome
}

/// Drop the messages full-text index. No-op if the index doesn't
/// exist. See [`pull_history`] for the lifecycle rationale.
async fn drop_fts_index(db: &Mutex<TursoConn>) -> Result<(), SyncError> {
    let conn = db.lock().await;
    conn.execute("DROP INDEX IF EXISTS messages_fts_idx", Params::empty())
        .await?;
    Ok(())
}

/// (Re)create the messages full-text index. No-op if it already
/// exists. The build runs over the entire `messages` table so it
/// scales with table size — the price for never paying the per-row
/// commit cost during the pull.
async fn create_fts_index(db: &Mutex<TursoConn>) -> Result<(), SyncError> {
    let conn = db.lock().await;
    conn.execute(qsl_storage::FTS_INDEX_DDL, Params::empty())
        .await?;
    Ok(())
}

/// Internal pipeline message. Producer sends one of these per fetch
/// attempt; consumer dispatches based on variant.
enum FetchOutcome {
    Chunk(HistoryChunk),
    /// Producer exhausted its retry budget on this chunk. Consumer
    /// flips the row to `Error` and returns.
    Failed(SyncError),
}

/// Producer half of the pipeline. Loops fetching chunks from the
/// backend and pushing them onto `tx`. Stops on cancel, on
/// `anchor <= 1`, on a stuck-and-empty chunk, on retry budget
/// exhaustion, or when the consumer drops the receiver.
async fn run_producer(
    backend: &dyn MailBackend,
    folder: &FolderId,
    start_anchor: u64,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<FetchOutcome>,
) {
    let mut anchor = start_anchor;
    let mut consecutive_failures: u32 = 0;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        if anchor <= 1 {
            return;
        }

        match backend
            .pull_history_chunk(folder, anchor, HISTORY_CHUNK_SIZE)
            .await
        {
            Ok(chunk) => {
                consecutive_failures = 0;
                let stuck_and_empty = chunk.next_anchor >= anchor && chunk.headers.is_empty();
                anchor = chunk.next_anchor;

                // Bounded send. If the consumer has dropped the
                // receiver (cancel or terminal error path), bail.
                if tx.send(FetchOutcome::Chunk(chunk)).await.is_err() {
                    return;
                }

                if stuck_and_empty {
                    return;
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                warn!(
                    folder = %folder.0,
                    anchor,
                    failures = consecutive_failures,
                    "history sync chunk failed: {e}"
                );
                if consecutive_failures >= MAX_CHUNK_RETRIES {
                    let _ = tx.send(FetchOutcome::Failed(e.into())).await;
                    return;
                }
                tokio::time::sleep(Duration::from_millis(THROTTLE_RECOVERY_MS)).await;
            }
        }
    }
}

/// Consumer half of the pipeline. Pulls chunks off `rx`, inserts
/// them, persists progress, and emits UI events. Sets the terminal
/// `history_sync_state` status before returning regardless of
/// which side closed the pipeline.
#[allow(clippy::too_many_arguments)]
async fn run_consumer<F>(
    db: Arc<Mutex<TursoConn>>,
    account: &AccountId,
    folder: &FolderId,
    start_anchor: u64,
    total_estimate: Option<u64>,
    cancel: Arc<AtomicBool>,
    mut rx: mpsc::Receiver<FetchOutcome>,
    progress: &mut F,
    pull_started_at: Instant,
) -> Result<(), SyncError>
where
    F: FnMut(HistoryProgress),
{
    let mut fetched_total: u32 = 0;
    let mut last_anchor = start_anchor;
    let mut chunks_processed: u32 = 0;
    // True once we hit a chunk that didn't advance the anchor and
    // had no headers — same exhaustion signal the pre-pipeline
    // version detected after persisting.
    let mut stuck_and_empty = false;

    while let Some(outcome) = rx.recv().await {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match outcome {
            FetchOutcome::Chunk(HistoryChunk {
                headers,
                next_anchor,
            }) => {
                let chunk_started_at = Instant::now();
                let inserted = {
                    let conn = db.lock().await;
                    let inserted = persist_chunk(&*conn, &headers).await?;
                    history_repo::update_progress(
                        &*conn,
                        account,
                        folder,
                        next_anchor as i64,
                        inserted,
                    )
                    .await?;
                    inserted
                };
                fetched_total = fetched_total.saturating_add(inserted);
                let advanced = next_anchor < last_anchor;
                last_anchor = next_anchor;
                chunks_processed = chunks_processed.saturating_add(1);

                progress(HistoryProgress {
                    fetched_total,
                    anchor_uid: next_anchor as i64,
                    total_estimate: total_estimate.map(|v| v as i64),
                    finished: false,
                });

                // Consumer-side wall-clock for this iteration: the
                // persist + update_progress under the db lock.
                // Producer-side fetch wall-clock is overlapped with
                // the previous chunk's persist by the depth-1
                // pipeline, so a slow consumer is what throttles
                // throughput once steady-state. Threshold at
                // IMAP_CMD_MS so the warn message stays in the same
                // shape the pre-pipeline version emitted.
                let chunk_ms = chunk_started_at.elapsed().as_millis() as u64;
                if chunk_ms >= qsl_telemetry::slow::limits::IMAP_CMD_MS {
                    warn!(
                        target: "qsl::slow::sync",
                        op = "history_chunk",
                        account = %account.0,
                        folder = %folder.0,
                        anchor = next_anchor,
                        inserted,
                        fetched_total,
                        chunk_index = chunks_processed,
                        elapsed_ms = chunk_ms,
                        limit_ms = qsl_telemetry::slow::limits::IMAP_CMD_MS,
                        "slow history chunk"
                    );
                } else {
                    info!(
                        account = %account.0,
                        folder = %folder.0,
                        anchor = next_anchor,
                        inserted,
                        fetched_total,
                        chunk_index = chunks_processed,
                        chunk_ms,
                        "history chunk persisted"
                    );
                }

                if !advanced && headers.is_empty() {
                    stuck_and_empty = true;
                    break;
                }

                tokio::time::sleep(Duration::from_millis(INTER_CHUNK_DELAY_MS)).await;
            }
            FetchOutcome::Failed(e) => {
                let msg = format!("{MAX_CHUNK_RETRIES} consecutive failures: {e}");
                tracing::error!(
                    account = %account.0,
                    folder = %folder.0,
                    anchor = last_anchor,
                    chunks = chunks_processed,
                    wall_clock_ms = pull_started_at.elapsed().as_millis() as u64,
                    "history sync giving up: {msg}"
                );
                let conn = db.lock().await;
                history_repo::set_status(&*conn, account, folder, RepoStatus::Error, Some(&msg))
                    .await?;
                drop(conn);
                progress(HistoryProgress {
                    fetched_total,
                    anchor_uid: last_anchor as i64,
                    total_estimate: total_estimate.map(|v| v as i64),
                    finished: true,
                });
                return Err(e);
            }
        }
    }

    // Channel closed without a Failed outcome. Pick the right
    // terminal status from the cancel flag and the local
    // progress: tail-exhausted if we either drained to anchor <= 1
    // or hit a stuck-and-empty chunk.
    let canceled = cancel.load(Ordering::Relaxed);
    let exhausted = last_anchor <= 1 || stuck_and_empty;
    let final_status = if canceled {
        RepoStatus::Canceled
    } else if exhausted {
        RepoStatus::Completed
    } else {
        // Producer dropped without exhausting and without setting
        // Failed — shouldn't happen in practice, but treat as a
        // canceled-ish state so the UI doesn't lie about completion.
        RepoStatus::Canceled
    };
    let conn = db.lock().await;
    history_repo::set_status(&*conn, account, folder, final_status, None).await?;
    drop(conn);

    info!(
        account = %account.0,
        folder = %folder.0,
        fetched = fetched_total,
        chunks = chunks_processed,
        wall_clock_ms = pull_started_at.elapsed().as_millis() as u64,
        ?final_status,
        "history sync finished"
    );

    progress(HistoryProgress {
        fetched_total,
        anchor_uid: if matches!(final_status, RepoStatus::Completed) {
            0
        } else {
            last_anchor as i64
        },
        total_estimate: total_estimate.map(|v| v as i64),
        finished: true,
    });
    Ok(())
}

/// Persist one chunk of headers — insert if new, skip silently if
/// already known. Returns the count of newly-inserted rows.
///
/// Wraps every chunk's inserts in a single transaction via
/// [`messages::batch_insert_skip_existing`]. Without that, Turso's
/// experimental FTS index (`messages_fts_idx`) rebuilds at every
/// implicit commit, which made a 500-row chunk take 3-6 minutes
/// against a real Gmail account during v0.1 history pulls. Batched
/// commits drop that to seconds, matching what the IMAP-side fetch
/// budget actually deserves.
///
/// Threading and contacts upserts are deliberately skipped on the
/// history-pull hot path: each `attach_to_thread` runs ~3 SQL
/// queries per message, which makes a 100k-message pull spend most
/// of its wall-clock time in serial round-trips for archival mail
/// nobody reads as a thread anyway. The recent-mail threading the
/// user actually sees comes from the bootstrap + live-sync paths,
/// both of which still run threading inline. Pulled-history
/// messages will lack `thread_id` until either a re-sync of the
/// folder triggers `sync_folder`'s heal-on-update path, or a
/// future "rethread historical mail" action runs.
async fn persist_chunk(conn: &dyn DbConn, headers: &[MessageHeaders]) -> Result<u32, SyncError> {
    Ok(messages::batch_insert_skip_existing(conn, headers).await?)
}
