// SPDX-License-Identifier: Apache-2.0

//! Background sync engine for the desktop shell.
//!
//! Phase 1 Week 10 PR 7a (startup pass) + PR 7b (live IDLE).
//!
//! On app start, [`spawn`] kicks off a tokio task that:
//!
//! 1. Bootstrap pass: walks every account, runs
//!    [`qsl_sync::sync_account`], emits
//!    [`SyncEvent::FolderSynced`] per folder.
//! 2. For each IMAP account, spawns one
//!    [`crate::imap_idle::spawn_watcher`] per discovered folder.
//!    Watchers send [`BackendEvent`]s back over an internal mpsc.
//! 3. Reactive loop: consumes the internal mpsc, debounces 500ms
//!    of activity per (account, folder), then runs
//!    [`qsl_sync::sync_folder`] for the changed folder and
//!    emits [`SyncEvent::FolderSynced`].
//!
//! JMAP accounts get the bootstrap pass but no live watcher; their
//! EventSource push lands in Phase 1 Week 11.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use qsl_core::{Account, AccountId, BackendEvent, BackendKind, Folder, FolderId, FolderRole};
use qsl_ipc::SyncEvent;
use qsl_storage::{repos, BlobStore};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::backend_factory;
use crate::imap_idle;
use crate::jmap_push;
use crate::state::AppState;

/// Tauri event name the engine emits on. The UI subscribes via
/// `tauri::event::listen("sync_event", …)`.
pub const SYNC_EVENT: &str = "sync_event";

/// How long the reactive loop coalesces a burst of `BackendEvent`s
/// before triggering a sync. A flag-flip on a marketing newsletter
/// can produce three FETCHes inside ~50ms; debouncing collapses
/// them into a single `sync_folder` call.
const DEBOUNCE: Duration = Duration::from_millis(500);

/// Buffer size for the internal `BackendEvent` channel. One value
/// per watcher per debounce window is plenty; the larger we make
/// this the longer a backed-up engine can stall a watcher's
/// `tx.send`.
const EVENT_CHANNEL_BUFFER: usize = 64;

/// Cap on simultaneous IMAP IDLE connections per account. Gmail
/// rejects past ~15, Outlook/Yahoo around 16, iCloud as low as 5;
/// 10 is the safe ceiling that leaves headroom for the cached
/// foreground sync connection (`backend_factory::get_or_open`)
/// and a transient outbox-drain dial. Folders past the cap fall
/// back to the [`POLL_INTERVAL`] poller below. Priority is by
/// [`FolderRole`] (Inbox / All / Sent / Drafts / Trash / Spam …)
/// so well-known roles always get push.
const MAX_IMAP_WATCHERS_PER_ACCOUNT: usize = 10;

/// Cadence of the per-account poller for folders that didn't fit
/// inside the watcher pool. 2 minutes balances responsiveness for
/// label-only changes against IMAP server politeness — a SELECT +
/// CONDSTORE pass on 20 folders every 2 min is well under any
/// throttle threshold we've seen in practice.
const POLL_INTERVAL: Duration = Duration::from_secs(120);

/// Per-call ceiling on `MailBackend::list_messages` for incremental
/// sync. Each call's headers are applied in a single `apply_chunk`
/// transaction; that transaction's wall time is what holds the WAL
/// writer lock and (under Turso 0.5.3) stalls reads on `state.db`.
/// 200 produced 488-726 ms tx_execute INSERTs that pushed the IPC
/// `messages_list` query past 1.6 s — telemetry 2026-05-07. 50 caps
/// the writer-hold around 125-180 ms, below the 250 ms slow_query
/// threshold, at the cost of more IMAP round-trips on big initial
/// pulls. The next IDLE / poll cycle picks up anything past the cap,
/// so freshness still converges in seconds.
const SYNC_FETCH_LIMIT: u32 = 50;

/// Spawn the engine task. Returns immediately; the task runs in the
/// background until the app exits.
///
/// Uses `tauri::async_runtime::spawn` rather than `tokio::spawn`
/// because this function runs inside Tauri's synchronous `setup`
/// closure — there is no ambient tokio runtime there. Tauri's
/// runtime is tokio-backed, so once the engine task is running
/// inside it the inner `tokio::spawn` / `tokio::select` calls in
/// the watchers and reactive loop work normally.
pub fn spawn(app: AppHandle) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        if let Err(e) = run(&app).await {
            warn!("sync engine fatal: {e}");
        }
    })
}

/// Hard ceiling on the wait for `ui_ready`. Without this, a panic in
/// the wasm bundle (or a missing `ui_ready` invoke) would silently
/// disable sync forever. 10s comfortably covers a cold Dioxus mount
/// even on a slow box; well past that the user is staring at a
/// failed UI anyway and we should at least keep mail moving.
const UI_READY_TIMEOUT: Duration = Duration::from_secs(10);

async fn run(app: &AppHandle) -> Result<(), String> {
    // Wait for the Dioxus app to signal it has mounted before doing
    // any IMAP / JMAP work. Sync was launching CONNECT + LIST +
    // SELECT on every folder before the webview had even painted,
    // which made the first frame take 2-5s on accounts with many
    // folders. The UI calls the `ui_ready` IPC command from a
    // top-level `use_hook`, which fires `state.ui_ready.notify_one()`
    // here.
    let notify = {
        let state: tauri::State<'_, AppState> = app.state();
        state.ui_ready.clone()
    };
    info!("sync engine: waiting for ui_ready signal");
    match tokio::time::timeout(UI_READY_TIMEOUT, notify.notified()).await {
        Ok(()) => info!("sync engine: ui_ready received, starting bootstrap"),
        Err(_) => warn!(
            timeout_ms = UI_READY_TIMEOUT.as_millis() as u64,
            "sync engine: ui_ready timeout — starting bootstrap anyway"
        ),
    }

    // Spawn the outbox drain on a periodic timer, unconditionally and
    // before account discovery. It used to be spawned only after the
    // watcher pool was built, which meant a fresh install (add
    // account → compose → Send) or an offline boot had *no* drain at
    // all until the next restart: mark-read, moves, deletes, draft
    // uploads and sends sat in the outbox forever. Decoupled from the
    // watcher reactive loop so a wedged STORE doesn't stall sync
    // events. 5 seconds is short enough that a "mark read" click
    // visibly propagates ("within seconds" per the spec exit
    // criterion) and long enough that an idle queue costs nothing.
    {
        let app_for_drain = app.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if let Err(e) = drain_outbox_once(&app_for_drain).await {
                    warn!("outbox drain: {e}");
                }
            }
        });
    }

    // Discovery + watcher pool, re-run whenever the account set
    // changes (or nothing was watchable and a retry is due). Each
    // pass owns its own event channel; returning from `run_once`
    // drops the receiver, which makes every watcher/poller task from
    // that pass exit on its next send.
    let accounts_changed = {
        let state: tauri::State<'_, AppState> = app.state();
        state.accounts_changed.clone()
    };
    loop {
        match run_once(app, &accounts_changed).await {
            Ok(PassOutcome::AccountsChanged) => {
                info!("sync engine: account set changed — rebuilding watcher pool");
            }
            Ok(PassOutcome::NothingToWatch) => {
                info!(
                    retry_secs = NOTHING_TO_WATCH_RETRY.as_secs(),
                    "sync engine: nothing to watch — waiting for an account"
                );
                // Wake early when an account is added; otherwise retry
                // on a timer so a boot-time bootstrap failure (offline
                // laptop) self-heals once the network is back.
                let _ =
                    tokio::time::timeout(NOTHING_TO_WATCH_RETRY, accounts_changed.notified()).await;
            }
            Ok(PassOutcome::WatchersExited) => {
                warn!("sync engine: all watchers exited — rebuilding watcher pool");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Err(e) => {
                warn!("sync engine pass failed: {e}; retrying");
                let _ =
                    tokio::time::timeout(NOTHING_TO_WATCH_RETRY, accounts_changed.notified()).await;
            }
        }
    }
}

/// How long `run` waits between discovery passes when no account
/// produced a watchable folder set (no accounts yet, or every
/// bootstrap failed). An `accounts_changed` ping cuts the wait short.
const NOTHING_TO_WATCH_RETRY: Duration = Duration::from_secs(60);

/// Why one `run_once` pass returned.
enum PassOutcome {
    /// No account yielded folders to watch (fresh install, or every
    /// bootstrap failed).
    NothingToWatch,
    /// `AppState::accounts_changed` fired; the caller rebuilds.
    AccountsChanged,
    /// Every watcher dropped its sender.
    WatchersExited,
}

async fn run_once(
    app: &AppHandle,
    accounts_changed: &Arc<tokio::sync::Notify>,
) -> Result<PassOutcome, String> {
    let accounts = list_accounts(app).await?;
    info!(count = accounts.len(), "sync engine: bootstrap pass");

    // Bootstrap sync + collect watch targets. IMAP accounts get a
    // capped watcher pool plus a poller for the rest; JMAP accounts
    // get one EventSource watcher per account (AccountChanged
    // events).
    let mut imap_accounts: Vec<(AccountId, Vec<Folder>)> = Vec::new();
    let mut jmap_accounts: Vec<(AccountId, Vec<Folder>)> = Vec::new();
    for account in &accounts {
        match bootstrap_account(app, account).await {
            Ok(folders) => match account.kind {
                BackendKind::ImapSmtp => {
                    imap_accounts.push((account.id.clone(), folders));
                }
                BackendKind::Jmap => {
                    jmap_accounts.push((account.id.clone(), folders));
                }
                _ => {
                    debug!(account = %account.id.0, kind = ?account.kind, "no live watcher for backend kind");
                }
            },
            Err(e) => {
                warn!(account = %account.id.0, "bootstrap failed: {e}");
            }
        }
    }

    // Resume any history-sync ("Pull full mail history") jobs that
    // were running at the previous app exit. Done here, after
    // bootstrap, so the resumed pulls don't compete with the
    // bootstrap pass for the shared backend connection but do start
    // before the live watcher loop kicks in.
    crate::commands::history_sync::resume_running_jobs(app).await;

    let any_imap = imap_accounts.iter().any(|(_, fs)| !fs.is_empty());
    if !any_imap && jmap_accounts.is_empty() {
        return Ok(PassOutcome::NothingToWatch);
    }

    // Single shared mpsc for IMAP watchers, IMAP pollers, and JMAP
    // EventSource watchers. Each forwarder tags BackendEvents with
    // the source account_id so the reactive loop can dispatch.
    let (tx, mut rx) = mpsc::channel::<(AccountId, BackendEvent)>(EVENT_CHANNEL_BUFFER);
    let mut watcher_count = 0usize;
    let mut polled_folder_count = 0usize;

    // Per-account: pick top-N priority folders for live IDLE,
    // hand the rest to a polling task. All folders end up in
    // `folder_by_id` so the reactive loop can resolve either kind
    // of FolderChanged event.
    let mut all_imap_folders: Vec<(AccountId, Folder)> = Vec::new();
    let mut watched_ids: Vec<FolderId> = Vec::new();
    for (account_id, folders) in imap_accounts {
        let total = folders.len();
        for f in &folders {
            all_imap_folders.push((account_id.clone(), f.clone()));
        }
        let (active, polled) = prioritize_imap_folders(folders);

        for folder in &active {
            let forward_tx = spawn_forwarder(account_id.clone(), tx.clone());
            let _handle = imap_idle::spawn_watcher(
                app.clone(),
                account_id.clone(),
                folder.id.clone(),
                forward_tx,
            );
            watched_ids.push(folder.id.clone());
            watcher_count += 1;
        }
        if !polled.is_empty() {
            let forward_tx = spawn_forwarder(account_id.clone(), tx.clone());
            let polled_ids: Vec<FolderId> = polled.iter().map(|f| f.id.clone()).collect();
            polled_folder_count += polled_ids.len();
            let _handle = spawn_imap_poller(account_id.clone(), polled_ids, forward_tx);
        }
        debug!(
            account = %account_id.0,
            total_folders = total,
            watchers = active.len(),
            polled = polled.len(),
            "imap watcher pool sized"
        );
    }
    for (account_id, folders) in &jmap_accounts {
        let forward_tx = spawn_forwarder(account_id.clone(), tx.clone());
        let _handle = jmap_push::spawn_watcher(app.clone(), account_id.clone(), forward_tx);
        watcher_count += 1;
        // JMAP push covers every folder on the account, so all of them
        // qualify as "watched" for the on-click skip.
        for f in folders {
            watched_ids.push(f.id.clone());
        }
    }
    {
        let state: tauri::State<'_, AppState> = app.state();
        let mut set = state.watched_folders.lock().await;
        for id in watched_ids {
            set.insert(id);
        }
    }

    // Drop the engine's copy of `tx` so `rx.recv()` returns `None`
    // when every watcher exits — otherwise the loop would hang
    // forever.
    drop(tx);
    info!(
        watchers = watcher_count,
        imap_folders_watched = all_imap_folders.len() - polled_folder_count,
        imap_folders_polled = polled_folder_count,
        jmap_accounts = jmap_accounts.len(),
        "sync engine: live watchers spawned"
    );
    info!("sync engine: entering reactive loop");

    let folder_by_id: HashMap<(AccountId, FolderId), Folder> = all_imap_folders
        .into_iter()
        .map(|(acct, folder)| ((acct, folder.id.clone()), folder))
        .collect();

    // Two debounce maps: per-folder for IMAP FolderChanged, per-account
    // for JMAP AccountChanged. Sharing one map would force a
    // sentinel "all folders" key which makes the dispatch logic
    // muddier than it has to be.
    let mut folder_pending: HashMap<(AccountId, FolderId), tokio::time::Instant> = HashMap::new();
    let mut account_pending: HashMap<AccountId, tokio::time::Instant> = HashMap::new();
    let blobs = {
        let state: tauri::State<'_, AppState> = app.state();
        BlobStore::new(state.data_dir.join("blobs"))
    };

    loop {
        let next_deadline = folder_pending
            .values()
            .chain(account_pending.values())
            .min()
            .copied();
        let timeout_fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
            match next_deadline {
                Some(t) => Box::pin(tokio::time::sleep_until(t)),
                None => Box::pin(std::future::pending::<()>()),
            };

        tokio::select! {
            _ = accounts_changed.notified() => {
                // Clear the watched set: the caller rebuilds it on
                // the next pass, and a stale entry would make
                // `messages_refresh_folder` skip on-click syncs for
                // a folder nobody is watching any more.
                let state: tauri::State<'_, AppState> = app.state();
                state.watched_folders.lock().await.clear();
                return Ok(PassOutcome::AccountsChanged);
            }
            evt = rx.recv() => {
                match evt {
                    None => {
                        let state: tauri::State<'_, AppState> = app.state();
                        state.watched_folders.lock().await.clear();
                        return Ok(PassOutcome::WatchersExited);
                    }
                    Some((account_id, BackendEvent::FolderChanged { folder })) => {
                        let key = (account_id, folder);
                        folder_pending.insert(key, tokio::time::Instant::now() + DEBOUNCE);
                    }
                    Some((account_id, BackendEvent::AccountChanged)) => {
                        account_pending.insert(account_id, tokio::time::Instant::now() + DEBOUNCE);
                    }
                    Some((account_id, BackendEvent::ConnectionLost)) => {
                        debug!(account = %account_id.0, "watcher reports ConnectionLost");
                    }
                    Some((account_id, BackendEvent::ConnectionRestored)) => {
                        debug!(account = %account_id.0, "watcher reports ConnectionRestored");
                    }
                    Some((_, other)) => {
                        debug!(event = ?other, "ignoring unhandled BackendEvent");
                    }
                }
            }
            _ = timeout_fut => {
                let now = tokio::time::Instant::now();

                let due_folders: Vec<_> = folder_pending
                    .iter()
                    .filter(|(_, t)| **t <= now)
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in due_folders {
                    folder_pending.remove(&key);
                    let (account_id, _folder_id) = &key;
                    let Some(folder) = folder_by_id.get(&key) else { continue; };
                    sync_one_folder(app, &blobs, account_id, folder).await;
                }

                let due_accounts: Vec<_> = account_pending
                    .iter()
                    .filter(|(_, t)| **t <= now)
                    .map(|(k, _)| k.clone())
                    .collect();
                for account_id in due_accounts {
                    account_pending.remove(&account_id);
                    sync_one_account(app, &blobs, &account_id).await;
                }
            }
        }
    }
}

/// Sort `folders` by [`FolderRole`] priority and split into
/// `(active, polled)` at [`MAX_IMAP_WATCHERS_PER_ACCOUNT`].
///
/// Active folders get a live IDLE connection. Polled folders share a
/// single per-account [`spawn_imap_poller`] task. Priority bands:
///
/// 1. Inbox — always live; new mail UX hinges on it.
/// 2. All — Gmail's All Mail mirrors every label change, so one
///    IDLE here covers most of the account regardless of the cap.
/// 3. Sent / Drafts / Trash / Spam — touched on every send / move
///    cycle; visible in default Sidebar groupings.
/// 4. Important / Archive / Flagged — secondary built-in roles.
/// 5. Untagged user folders — alphabetical so the assignment is
///    stable across runs.
///
/// This is a free function (no `&self`) so it stays trivially
/// testable with synthetic [`Folder`] vectors.
fn prioritize_imap_folders(mut folders: Vec<Folder>) -> (Vec<Folder>, Vec<Folder>) {
    fn band(role: &Option<FolderRole>) -> u8 {
        match role {
            Some(FolderRole::Inbox) => 0,
            Some(FolderRole::All) => 1,
            Some(FolderRole::Sent) => 2,
            Some(FolderRole::Drafts) => 3,
            Some(FolderRole::Trash) => 4,
            Some(FolderRole::Spam) => 5,
            Some(FolderRole::Important) => 6,
            Some(FolderRole::Archive) => 7,
            Some(FolderRole::Flagged) => 8,
            // Untagged folders: deterministic alphabetical, but
            // ranked below every well-known role.
            None => 100,
            // `_` covers any future variant of the
            // `#[non_exhaustive]` enum.
            Some(_) => 99,
        }
    }
    folders.sort_by(|a, b| {
        band(&a.role)
            .cmp(&band(&b.role))
            .then_with(|| a.path.cmp(&b.path))
    });
    if folders.len() <= MAX_IMAP_WATCHERS_PER_ACCOUNT {
        (folders, Vec::new())
    } else {
        let polled = folders.split_off(MAX_IMAP_WATCHERS_PER_ACCOUNT);
        (folders, polled)
    }
}

/// Spawn one polling task that periodically emits
/// [`BackendEvent::FolderChanged`] for each folder in `folders`.
/// The reactive loop debounces these the same way as IDLE-driven
/// events, so the existing [`sync_one_folder`] pipeline handles
/// them — no separate poll-side sync code path.
///
/// Used for folders that didn't fit inside the IDLE pool. Cadence
/// is [`POLL_INTERVAL`]. Tasks exit when the receiver is dropped.
fn spawn_imap_poller(
    account: AccountId,
    folders: Vec<FolderId>,
    tx: mpsc::Sender<BackendEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if folders.is_empty() {
            return;
        }
        info!(
            account = %account.0,
            folder_count = folders.len(),
            interval_secs = POLL_INTERVAL.as_secs(),
            "spawning IMAP poll loop for un-watched folders"
        );
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        // First tick fires immediately by default; skip it so the
        // bootstrap pass we just finished isn't followed by a
        // redundant full re-sync.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            for folder in &folders {
                let event = BackendEvent::FolderChanged {
                    folder: folder.clone(),
                };
                if tx.send(event).await.is_err() {
                    debug!(account = %account.0, "poll loop: receiver dropped, exiting");
                    return;
                }
            }
        }
    })
}

/// Spawn a small forwarder task that re-broadcasts `BackendEvent`
/// from a single watcher onto the engine's shared `(AccountId,
/// BackendEvent)` channel. Returns the per-watcher sender end.
fn spawn_forwarder(
    account: AccountId,
    engine_tx: mpsc::Sender<(AccountId, BackendEvent)>,
) -> mpsc::Sender<BackendEvent> {
    let (forward_tx, mut forward_rx) = mpsc::channel::<BackendEvent>(8);
    tokio::spawn(async move {
        while let Some(ev) = forward_rx.recv().await {
            if engine_tx.send((account.clone(), ev)).await.is_err() {
                return;
            }
        }
    });
    forward_tx
}

async fn list_accounts(app: &AppHandle) -> Result<Vec<Account>, String> {
    let state: tauri::State<'_, AppState> = app.state();
    let db = state.sync_db.lock().await;
    repos::accounts::list(&*db)
        .await
        .map_err(|e| format!("list accounts: {e}"))
}

/// Run the initial sync pass for one account and emit the
/// per-folder events. Returns the list of folders that synced
/// successfully — preserving server-reported [`FolderRole`] so
/// the watcher-pool prioritizer can pick the right ones to push.
///
/// We list folders ourselves (rather than relying on
/// [`qsl_sync::sync_account`]'s flat outcome list) so the
/// returned [`Folder`] structs keep their roles, names, and paths
/// for downstream prioritization. The per-folder sync is otherwise
/// identical to what `sync_account` would do.
async fn bootstrap_account(app: &AppHandle, account: &Account) -> Result<Vec<Folder>, String> {
    info!(account = %account.id.0, kind = ?account.kind, "bootstrap account: opening backend");
    let state: tauri::State<'_, AppState> = app.state();
    let backend = backend_factory::get_or_open(&state, &account.id)
        .await
        .map_err(|e| format!("open backend: {e}"))?;

    info!(account = %account.id.0, "bootstrap account: listing folders");
    let folders = backend
        .list_folders()
        .await
        .map_err(|e| format!("list_folders: {e}"))?;
    info!(
        account = %account.id.0,
        count = folders.len(),
        "bootstrap account: syncing folders"
    );

    let blobs = BlobStore::new(state.data_dir.join("blobs"));

    // Per-folder loop: emit FolderStarted before each sync_folder so
    // the status bar can show "Syncing INBOX…" / "Syncing Sent…"
    // during bootstrap, then sync, then emit FolderSynced. Re-takes
    // sync_db.lock() per folder so the UI can read in between
    // (state.db is a separate handle but Turso 0.5.3's WAL
    // contention can stall reads behind a long-held writer lock).
    let mut succeeded = Vec::with_capacity(folders.len());
    let mut failed = 0usize;
    for folder in folders {
        emit_folder_started(app, &account.id, &folder.id);
        let result = {
            let db = state.sync_db.lock().await;
            qsl_sync::sync_folder(
                &*db,
                backend.as_ref(),
                Some(&blobs),
                &folder,
                Some(SYNC_FETCH_LIMIT),
            )
            .await
        };
        if let Err(e) = &result {
            warn!(folder = %folder.id.0, "bootstrap sync_folder failed: {e}");
        }
        emit_folder_outcome(
            app,
            &account.id,
            &folder.id,
            &result,
            /* live = */ false,
        )
        .await;
        if result.is_ok() {
            succeeded.push(folder);
        } else {
            failed += 1;
        }
    }
    info!(
        account = %account.id.0,
        ok = succeeded.len(),
        failed,
        "bootstrap account: done"
    );
    Ok(succeeded)
}

/// Re-sync a single folder in response to a debounced
/// `FolderChanged` event, then emit `SyncEvent::FolderSynced`.
///
/// Also reachable from the `messages_refresh_folder` Tauri command,
/// which the UI calls when the user opens a folder so newly-arrived
/// IMAP messages show up without waiting for the next IDLE wake-up
/// or 2-minute poll.
pub async fn sync_one_folder(
    app: &AppHandle,
    blobs: &BlobStore,
    account_id: &AccountId,
    folder: &Folder,
) {
    let state: tauri::State<'_, AppState> = app.state();
    let backend = match backend_factory::get_or_open(&state, account_id).await {
        Ok(b) => b,
        Err(e) => {
            warn!(account = %account_id.0, "open backend for refresh: {e}");
            return;
        }
    };

    emit_folder_started(app, account_id, &folder.id);
    let db = state.sync_db.lock().await;
    let result = qsl_sync::sync_folder(
        &*db,
        backend.as_ref(),
        Some(blobs),
        folder,
        Some(SYNC_FETCH_LIMIT),
    )
    .await;
    drop(db);

    emit_folder_outcome(app, account_id, &folder.id, &result, /* live = */ true).await;
}

/// Re-sync every folder of one account in response to a debounced
/// `AccountChanged` event (JMAP path). Walks `sync_account` and
/// emits one `SyncEvent::FolderSynced` per outcome — same shape the
/// IMAP per-folder path produces, so the UI doesn't have to care
/// which adapter pushed.
pub(crate) async fn sync_one_account(app: &AppHandle, blobs: &BlobStore, account_id: &AccountId) {
    let state: tauri::State<'_, AppState> = app.state();
    let backend = match backend_factory::get_or_open(&state, account_id).await {
        Ok(b) => b,
        Err(e) => {
            warn!(account = %account_id.0, "open backend for account refresh: {e}");
            return;
        }
    };

    // Iterate folders ourselves and emit `sync_event` after each one
    // commits, instead of going through `qsl_sync::sync_account` which
    // returns the entire outcome vec at once. The batchy form left the
    // UI staring at a partial sidebar for the whole sync window
    // (~30-60s on a fresh Gmail add) — the per-folder events that bump
    // `sync_tick` for the sidebar refetch all fired in a single burst
    // at the end, and a mid-sync UI reload would only see whatever had
    // been committed so far. Per-folder emit gives the sidebar a
    // refresh trigger as each new folder lands.
    //
    // Releasing the sync_db lock between folders also lets the IPC
    // connection (`state.db`) read the freshly-committed state without
    // waiting for the entire bootstrap to finish.
    let folders = match backend.list_folders().await {
        Ok(f) => f,
        Err(e) => {
            warn!(account = %account_id.0, "live list_folders: {e}");
            return;
        }
    };
    for folder in folders {
        emit_folder_started(app, account_id, &folder.id);
        let result = {
            let db = state.sync_db.lock().await;
            qsl_sync::sync_folder(
                &*db,
                backend.as_ref(),
                Some(blobs),
                &folder,
                Some(SYNC_FETCH_LIMIT),
            )
            .await
        };
        if let Err(e) = &result {
            warn!(folder = %folder.id.0, "live sync_folder: {e}");
        }
        emit_folder_outcome(app, account_id, &folder.id, &result, /* live = */ true).await;
    }
}

/// True if the folder is the account's canonical Inbox. Used by the
/// notification path to suppress duplicates on Gmail (every message
/// lands in both INBOX and All Mail) and to keep Sent / Drafts / etc.
/// from popping desktop notifications. Falls back to `false` on
/// lookup error so we err on the side of "no notification" rather
/// than spamming the user.
async fn folder_is_inbox(app: &AppHandle, folder_id: &FolderId) -> bool {
    let state: tauri::State<'_, AppState> = app.state();
    let db = state.sync_db.lock().await;
    match qsl_storage::repos::folders::find(&*db, folder_id).await {
        Ok(Some(f)) => matches!(f.role, Some(FolderRole::Inbox)),
        Ok(None) => false,
        Err(e) => {
            warn!(
                folder = %folder_id.0,
                "folder_is_inbox lookup failed: {e}"
            );
            false
        }
    }
}

/// Emit a `SyncEvent` for one folder's outcome, looking up the
/// post-sync `unread_count` and (if `live`) firing a desktop
/// notification when new messages arrived. Both bootstrap and
/// reactive paths funnel through here so the IPC shape stays
/// uniform.
/// Emit `SyncEvent::FolderStarted` so the UI's status bar can flip
/// to "Syncing X…" before the (potentially multi-second) `sync_folder`
/// call returns. Caller invokes this *just before* awaiting the sync
/// — see comments in `bootstrap_account` / `sync_one_folder` /
/// `sync_one_account`. Best-effort, ignores emit errors.
fn emit_folder_started(app: &AppHandle, account: &AccountId, folder: &FolderId) {
    let event = SyncEvent::FolderStarted {
        account: account.clone(),
        folder: folder.clone(),
    };
    if let Err(e) = app.emit(SYNC_EVENT, &event) {
        warn!("emit sync_event(FolderStarted): {e}");
    }
}

async fn emit_folder_outcome(
    app: &AppHandle,
    account: &AccountId,
    folder: &FolderId,
    result: &Result<qsl_sync::SyncReport, qsl_sync::SyncError>,
    live: bool,
) {
    let event = match result {
        Ok(report) => {
            // Skip the unread COUNT on no-op syncs. The query scans
            // every row in the folder (json_extract over flags_json
            // can't use an index) — ~1.4s on a 30k-row Gmail folder
            // — and most IDLE polls add zero rows / zero flag changes
            // so the count is guaranteed unchanged. Reuse the value
            // we cached the last time something *did* change. First
            // sync per folder still pays the cost (cache miss).
            let nothing_changed = report.added == 0
                && report.updated == 0
                && report.flag_updates == 0
                && report.removed == 0;
            let unread = {
                let state: tauri::State<'_, AppState> = app.state();
                if nothing_changed {
                    if let Some(v) = state.unread_cache.lock().await.get(folder).copied() {
                        v
                    } else {
                        let db = state.sync_db.lock().await;
                        let v = qsl_storage::repos::messages::count_unread_by_folder(&*db, folder)
                            .await
                            .unwrap_or(0);
                        drop(db);
                        state.unread_cache.lock().await.insert(folder.clone(), v);
                        v
                    }
                } else {
                    let db = state.sync_db.lock().await;
                    let v = qsl_storage::repos::messages::count_unread_by_folder(&*db, folder)
                        .await
                        .unwrap_or(0);
                    drop(db);
                    state.unread_cache.lock().await.insert(folder.clone(), v);
                    v
                }
            };
            SyncEvent::FolderSynced {
                account: account.clone(),
                folder: folder.clone(),
                added: report.added as u32,
                updated: report.updated as u32,
                flag_updates: report.flag_updates as u32,
                removed: report.removed as u32,
                unread_count: unread,
                live,
            }
        }
        Err(e) => SyncEvent::FolderError {
            account: account.clone(),
            folder: folder.clone(),
            error: format!("{e}"),
        },
    };

    // Emit the sync event BEFORE the (potentially slow) notification
    // preview path. The UI's status bar transitions out of
    // "Initializing…" on the first FolderSynced event; blocking the
    // emit on the preview-lookup path leaves the user staring at the
    // initial-state spinner for the full duration of `list_by_folder`
    // — and on `[Gmail]/All Mail` post-Turso-0.5.3 that's >1s
    // (telemetry 2026-05-07).
    if let Err(e) = app.emit(SYNC_EVENT, &event) {
        warn!("emit sync_event: {e}");
    }

    // Notification preview after emit. Same-folder gate as before
    // (Inbox-role only; Gmail's All Mail / Important / Spam don't
    // pop a banner). Notifications are best-effort and fire-and-
    // forget; the preview lookup still runs to populate the
    // `"{from} — {subject}"` body when there's a single new message.
    if let SyncEvent::FolderSynced {
        added,
        live: live_event,
        ..
    } = &event
    {
        if *live_event
            && *added > 0
            && folder_is_inbox(app, folder).await
            && notifications_enabled(app, account).await
        {
            let preview = if *added == 1 {
                let state: tauri::State<'_, AppState> = app.state();
                let db = state.sync_db.lock().await;
                match qsl_storage::repos::messages::list_by_folder(&*db, folder, 1, 0).await {
                    Ok(mut v) => v.pop(),
                    Err(e) => {
                        warn!(
                            account = %account.0,
                            folder = %folder.0,
                            "preview lookup failed: {e}; firing notification without sender/subject"
                        );
                        None
                    }
                }
            } else {
                None
            };
            fire_new_mail_notification(app, account, folder, *added as usize, preview.as_ref());
        }
    }
}

/// Honour both notification switches the UI exposes: the global
/// `notifications.master` app setting (Settings → Notifications) and
/// the per-account `notify_enabled` flag (Settings → Accounts).
/// Neither was consulted before, so muting an account or the master
/// toggle still popped banners carrying sender + subject. Missing
/// setting / unknown account default to "enabled" so a transient DB
/// hiccup never silently kills notifications.
async fn notifications_enabled(app: &AppHandle, account: &AccountId) -> bool {
    const KEY_NOTIFY_MASTER: &str = "notifications.master";
    let state: tauri::State<'_, AppState> = app.state();
    let db = state.sync_db.lock().await;
    let master_on = match repos::app_settings::get(&*db, KEY_NOTIFY_MASTER).await {
        Ok(Some(v)) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "off"
        ),
        Ok(None) => true,
        Err(e) => {
            debug!("notifications: master setting lookup failed: {e}");
            true
        }
    };
    if !master_on {
        return false;
    }
    match repos::accounts::find(&*db, account).await {
        Ok(Some(acct)) => acct.notify_enabled,
        Ok(None) => true,
        Err(e) => {
            debug!(account = %account.0, "notifications: account lookup failed: {e}");
            true
        }
    }
}

/// Fire an OS-native "new mail" notification via
/// `tauri-plugin-notification`. Best-effort: failures are logged
/// and the engine moves on (a missing notification surface — Linux
/// without a notification daemon, Windows action center disabled —
/// shouldn't stall sync).
///
/// Single-message bursts (`count == 1` and `preview.is_some()`) get
/// a per-message body — `"Alice Cohen — Project status"` — so the
/// notification is actionable at a glance. Multi-message bursts
/// fall back to a count-only body because picking one message to
/// preview would misrepresent the rest.
///
/// Action buttons (Mark read / Archive on Linux per the v0.1 plan)
/// are deferred: `tauri-plugin-notification` 2.3.3 only exposes
/// `action_type_id` on mobile, and adding `notify-rust` for the
/// Linux desktop path requires its own callback-dispatch wiring
/// that's larger than this PR's scope.
fn fire_new_mail_notification(
    app: &AppHandle,
    account: &AccountId,
    folder: &FolderId,
    count: usize,
    preview: Option<&qsl_core::MessageHeaders>,
) {
    use tauri_plugin_notification::NotificationExt;

    let (title, body) = match (count, preview) {
        (1, Some(headers)) => {
            let from = headers
                .from
                .first()
                .map(|a| {
                    a.display_name
                        .clone()
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| a.address.clone())
                })
                .unwrap_or_else(|| "Unknown sender".to_string());
            let subject = if headers.subject.is_empty() {
                "(no subject)".to_string()
            } else {
                headers.subject.clone()
            };
            (format!("New from {from}"), format!("{from} — {subject}"))
        }
        (1, None) => (
            "New message".to_string(),
            format!("{} · {}", account.0, folder.0),
        ),
        (n, _) => (
            format!("{n} new messages"),
            format!("{} · {}", account.0, folder.0),
        ),
    };

    info!(
        account = %account.0,
        folder = %folder.0,
        count = count,
        title = %title,
        "notification: firing new-mail notification"
    );
    if let Err(e) = app
        .notification()
        .builder()
        .title(&title)
        .body(&body)
        .show()
    {
        debug!(
            account = %account.0,
            folder = %folder.0,
            "notification failed: {e}"
        );
    }
}

/// Run one outbox-drain pass. Drains up to 32 entries per call;
/// any DLQ transitions get echoed to the UI as `SyncEvent::FolderError`
/// so the user sees a "failed to sync" banner.
async fn drain_outbox_once(app: &AppHandle) -> Result<(), qsl_core::StorageError> {
    let state: tauri::State<'_, AppState> = app.state();
    let resolver = AppHandleResolver { app: app.clone() };
    let db = state.sync_db.lock().await;
    let outcomes = qsl_sync::outbox_drain::drain(&*db, &resolver, 32).await?;
    drop(db);

    for outcome in outcomes {
        match outcome {
            qsl_sync::outbox_drain::DrainOutcome::Sent { id, op_kind } => {
                tracing::info!(id, op_kind, "outbox: sent");
            }
            qsl_sync::outbox_drain::DrainOutcome::Retrying {
                id,
                op_kind,
                attempts_after,
                error,
            } => {
                tracing::warn!(
                    id,
                    op_kind,
                    attempts_after,
                    error,
                    "outbox: scheduled retry"
                );
            }
            qsl_sync::outbox_drain::DrainOutcome::DeadLettered { id, op_kind, error } => {
                warn!(id, op_kind, error, "outbox: dead-lettered");
                // Surface as a synthetic FolderError so the UI's
                // existing sync_event listener picks it up. We
                // don't have a folder context here — use a sentinel
                // so the UI banner can still render with the
                // operator-visible error.
                let event = qsl_ipc::SyncEvent::FolderError {
                    account: qsl_core::AccountId(String::new()),
                    folder: qsl_core::FolderId(format!("outbox:{op_kind}")),
                    error: format!("queued mutation failed: {error}"),
                };
                if let Err(e) = app.emit(SYNC_EVENT, &event) {
                    warn!("emit sync_event for DLQ: {e}");
                }
            }
        }
    }
    Ok(())
}

/// `BackendResolver` impl that walks back through the `AppHandle`
/// to reach the cached backend factory. Lets the outbox drain stay
/// in `qsl-sync` (which is backend-agnostic) without that
/// crate having to depend on `qsl-imap-client` /
/// `qsl-jmap-client`.
struct AppHandleResolver {
    app: AppHandle,
}

#[async_trait::async_trait]
impl qsl_sync::outbox_drain::BackendResolver for AppHandleResolver {
    async fn open(
        &self,
        account: &AccountId,
    ) -> Result<std::sync::Arc<dyn qsl_core::MailBackend>, qsl_core::MailError> {
        let state: tauri::State<'_, AppState> = self.app.state();
        backend_factory::get_or_open(&state, account).await
    }
}

#[cfg(test)]
mod tests {
    use super::{prioritize_imap_folders, MAX_IMAP_WATCHERS_PER_ACCOUNT};
    use qsl_core::{AccountId, Folder, FolderId, FolderRole};

    fn folder(path: &str, role: Option<FolderRole>) -> Folder {
        Folder {
            id: FolderId(path.to_string()),
            account_id: AccountId("acct".to_string()),
            name: path.to_string(),
            path: path.to_string(),
            role,
            unread_count: 0,
            total_count: 0,
            parent: None,
        }
    }

    #[test]
    fn small_account_keeps_everything_active() {
        let folders = vec![
            folder("INBOX", Some(FolderRole::Inbox)),
            folder("Sent", Some(FolderRole::Sent)),
            folder("user/projects", None),
        ];
        let (active, polled) = prioritize_imap_folders(folders);
        assert_eq!(active.len(), 3);
        assert!(polled.is_empty());
    }

    #[test]
    fn cap_at_max_and_keep_well_known_roles() {
        let mut folders: Vec<Folder> = (0..30)
            .map(|i| folder(&format!("user/{i:02}"), None))
            .collect();
        folders.push(folder("INBOX", Some(FolderRole::Inbox)));
        folders.push(folder("[Gmail]/All Mail", Some(FolderRole::All)));
        folders.push(folder("[Gmail]/Sent Mail", Some(FolderRole::Sent)));
        folders.push(folder("Drafts", Some(FolderRole::Drafts)));

        let (active, polled) = prioritize_imap_folders(folders);

        assert_eq!(active.len(), MAX_IMAP_WATCHERS_PER_ACCOUNT);
        assert_eq!(polled.len(), 30 + 4 - MAX_IMAP_WATCHERS_PER_ACCOUNT);

        // Inbox / All / Sent / Drafts must always make the cut.
        let active_paths: Vec<_> = active.iter().map(|f| f.path.as_str()).collect();
        assert!(active_paths.contains(&"INBOX"));
        assert!(active_paths.contains(&"[Gmail]/All Mail"));
        assert!(active_paths.contains(&"[Gmail]/Sent Mail"));
        assert!(active_paths.contains(&"Drafts"));
    }

    #[test]
    fn untagged_split_is_alphabetical_and_stable() {
        let folders: Vec<Folder> = ["delta", "alpha", "charlie", "bravo"]
            .iter()
            .map(|p| folder(p, None))
            .collect();
        let (active, _) = prioritize_imap_folders(folders);
        let paths: Vec<_> = active.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["alpha", "bravo", "charlie", "delta"]);
    }
}
