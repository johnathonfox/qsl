// SPDX-License-Identifier: Apache-2.0

//! Shared runtime state for the Tauri shell.
//!
//! `AppState` owns the long-lived handles every command needs: the
//! Turso-backed [`qsl_storage::TursoConn`] for persistence and a
//! per-account cache of live [`MailBackend`] implementations. The
//! reader pane is a sandboxed `<iframe srcdoc>` inside the host
//! webview, so there's no out-of-process renderer state to track.
//!
//! The backend cache is lazily populated — a `MailBackend` is built and
//! logged in the first time a command actually reaches out to the
//! provider, not at boot. This keeps window-open fast even with many
//! accounts configured.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;
use std::time::Instant;

use qsl_core::{AccountId, FolderId, MailBackend};
use qsl_ipc::{MessageId, RenderedMessage};
use qsl_storage::TursoConn;
use tokio::sync::{Mutex, Notify, OnceCell};

/// One entry of [`AppState::backends`].
///
/// Stores the live backend handle alongside the `Instant` it was
/// built. `backend_factory::get_or_open` checks the age and rebuilds
/// when it's older than `MAX_BACKEND_AGE` so the next IMAP / JMAP
/// command runs against a fresh OAuth access token.
pub struct CachedBackend {
    pub backend: Arc<dyn MailBackend>,
    pub built_at: Instant,
}

/// Slot in the per-account backend cache.
///
/// Wrapping `CachedBackend` in `Arc<OnceCell<...>>` single-flights
/// the build: if N concurrent commands hit a cold cache, only the
/// first runs `refresh_access_token` + `connect`, and the rest wait
/// on the same `OnceCell::get_or_try_init` future. Without this
/// they'd all refresh the OAuth token in parallel, which works (the
/// refresh tokens are reusable) but burns extra network round-trips
/// and risks tripping provider rate limits on big bursts.
pub type BackendSlot = Arc<OnceCell<CachedBackend>>;

/// Long-lived state attached to the Tauri app via `manage`.
///
/// Commands reach it through `tauri::State<AppState>`.
pub struct AppState {
    /// Writable handle to the on-disk Turso database, used by the
    /// IPC command path (every `commands/*.rs` handler). All
    /// foreground repository calls go through this.
    pub db: Arc<Mutex<TursoConn>>,

    /// Second connection to the same database file, dedicated to
    /// the sync engine's background work (initial CONNECT/LIST
    /// bootstrap, IMAP IDLE / JMAP push refreshes,
    /// `messages_refresh_folder`). Without this split, the sync
    /// engine's writes would block IPC reads on the single
    /// `Arc<Mutex<TursoConn>>` lock — concretely, `messages_get`
    /// would stall behind a long sync transaction and the reader
    /// pane would freeze on "Loading…" until sync finished.
    /// Multi-connection concurrency requires WAL mode, which
    /// `TursoConn::open` enables.
    pub sync_db: Arc<Mutex<TursoConn>>,

    /// Per-account backend cache. Populated lazily on first use,
    /// aged out by `backend_factory::get_or_open` when the cached
    /// entry is older than the OAuth access-token TTL window, and
    /// evicted when an account is removed or a foreground command
    /// catches `MailError::Auth`. The `OnceCell` slot single-flights
    /// the per-account build so concurrent cache misses don't all
    /// refresh tokens in parallel.
    pub backends: Mutex<HashMap<AccountId, BackendSlot>>,

    /// Root of the on-disk data directory (blobs, logs, future
    /// attachment spill). Resolved once at startup via `directories`
    /// and kept here so commands don't recompute it.
    #[allow(dead_code)] // consumed by later commands in week 5 part 2
    pub data_dir: PathBuf,

    /// Single-entry cache of the most recently rendered message —
    /// the `RenderedMessage` produced by the last `messages_get` call.
    /// `messages_open_in_window` (popup-reader path) consults this
    /// before re-issuing `messages_get`: when the user double-clicks
    /// a row that's currently selected in the main reader pane, the
    /// body has just been fetched, sanitized, and decoded, so paying
    /// the lazy-fetch + sanitize cost a second time wastes ~50–500 ms.
    /// We cache only the last one because the typical "select then
    /// pop out" pattern hits exactly that — a multi-entry LRU would
    /// pay more in eviction bookkeeping than the second-most-recent
    /// hit rate is worth.
    ///
    /// Cache validity: the cached `RenderedMessage` may carry stale
    /// flags if the user mutates them between the fetch and the
    /// pop-out, but the popup body-render only consumes
    /// `sanitized_html` / `body_text` (immutable after first parse)
    /// so flag drift is not a correctness issue here. UI surfaces
    /// that need fresh flags re-call `messages_get` regardless.
    pub last_rendered: Mutex<Option<(MessageId, RenderedMessage)>>,

    /// Per-(account, folder) cancellation flags for in-flight
    /// history-sync ("Pull full mail history") jobs. The Tauri
    /// command flips the `AtomicBool` to true; the
    /// `qsl_sync::history::pull_history` driver checks it between
    /// chunks and bails cleanly. Cleared by the driver on terminal
    /// transitions so a future re-start gets a fresh token.
    pub history_cancellers: Mutex<HashMap<(AccountId, FolderId), Arc<AtomicBool>>>,

    /// Per-account serialization for history-sync pulls. Each
    /// account has ONE cached IMAP session (single
    /// `MailBackend::pull_history_chunk` in flight at a time on the
    /// connection); two parallel pulls on the same account would
    /// fight for it and split each pull's chunks across long gaps.
    /// The driver task acquires this mutex before its loop and
    /// holds it for the full pull, so a second pull on the same
    /// account queues until the first finishes (or is canceled).
    /// Different accounts are unaffected — they have separate
    /// sessions and progress in parallel.
    pub history_account_locks: Mutex<HashMap<AccountId, Arc<Mutex<()>>>>,

    /// Refcount of in-flight bulk history pulls across all accounts.
    /// Bumped on entry to `pull_history` and decremented on exit
    /// (success, cancel, or error) via the `PullGuard` RAII type
    /// in `commands/history_sync.rs`. While > 0 the
    /// `messages_fts_idx` is dropped (rebuilt by `pull_history` on
    /// the way out), so any `fts_match()` query against `messages`
    /// either errors or full-scans. `messages_search` checks this
    /// and returns an empty page with `indexing_in_progress=true`
    /// instead of trying to query the missing index, so the UI can
    /// render a "search paused" banner instead of hanging on a
    /// doomed query.
    pub pull_in_progress: Arc<AtomicU32>,

    /// Per-folder cache of the most recent `count_unread_by_folder`
    /// result. Populated by `sync_engine::emit_folder_outcome` whenever
    /// a sync cycle reports a real change (added / updated /
    /// flag_updates / removed > 0); reused (without re-querying) on
    /// no-op cycles. The unread COUNT scans every row in the folder
    /// because of the `json_extract(flags_json, '$.seen')` predicate
    /// — on a 30k-row Gmail mailbox that's ~1.4s per call. Re-running
    /// it on every IDLE poll of every folder, even when nothing
    /// actually changed, was pegging a CPU and producing thousands of
    /// `slow_query` warnings per hour. The cache turns the no-op case
    /// into a `HashMap::get`.
    pub unread_cache: Arc<Mutex<HashMap<FolderId, u32>>>,

    /// Folders covered by a live IMAP IDLE watcher or a JMAP push
    /// connection. Populated by `sync_engine::run` after watchers are
    /// spawned. `messages_refresh_folder` consults this set on every
    /// folder click and skips the on-click sync when the folder is
    /// already being pushed in real time — clicking would otherwise
    /// fire an extra SELECT + UID SEARCH + reconcile pass that can
    /// stall the IPC thread on the slow `messages` SELECT for
    /// 1-2 seconds, with no observable freshness gain because the
    /// watcher will deliver the same updates on its own.
    pub watched_folders: Arc<Mutex<HashSet<FolderId>>>,

    /// Fired by the `ui_ready` IPC command once the Dioxus app has
    /// mounted in the webview. The sync engine awaits this (with a
    /// short safety timeout) before its bootstrap pass so the
    /// initial paint isn't competing with IMAP CONNECT + LIST +
    /// SELECT churn for tokio worker threads. `Notify` buffers a
    /// single permit, so the call ordering between the UI signal
    /// and the engine's wait is irrelevant.
    pub ui_ready: Arc<Notify>,

    /// Captured at the very top of `main()` and read once on the
    /// first `ui_ready` IPC so we can log a single "first-paint"
    /// number (process start → wasm-mounted). `OnceCell` ensures the
    /// log fires exactly once even if `ui_ready` is called from
    /// multiple windows during a session.
    pub boot_at: Instant,
    pub first_paint_logged: Arc<std::sync::atomic::AtomicBool>,

    /// Pinged by `accounts_add_oauth` / `accounts_remove` after the
    /// account table changes. The sync engine waits on this (with a
    /// timeout) whenever it has nothing to watch, and its reactive
    /// loop restarts discovery on it, so an account added at runtime
    /// — or on a fresh install — gets live watchers without an app
    /// restart.
    pub accounts_changed: Arc<Notify>,

    /// Filesystem paths the user has chosen through the native file
    /// picker (`compose_pick_attachments`) this session. `drafts_save`
    /// only accepts attachment paths from this set (or ones already
    /// persisted on the same draft row), so a compromised webview
    /// can't name `~/.ssh/id_rsa` as an attachment and have the host
    /// read and upload it.
    pub picked_attachment_paths: Mutex<HashSet<PathBuf>>,
}

impl AppState {
    /// Build an `AppState` given an already-opened database and the
    /// resolved data directory.
    pub fn new(db: TursoConn, sync_db: TursoConn, data_dir: PathBuf, boot_at: Instant) -> Self {
        Self {
            db: Arc::new(Mutex::new(db)),
            sync_db: Arc::new(Mutex::new(sync_db)),
            backends: Mutex::new(HashMap::new()),
            data_dir,
            history_cancellers: Mutex::new(HashMap::new()),
            history_account_locks: Mutex::new(HashMap::new()),
            pull_in_progress: Arc::new(AtomicU32::new(0)),
            unread_cache: Arc::new(Mutex::new(HashMap::new())),
            watched_folders: Arc::new(Mutex::new(HashSet::new())),
            last_rendered: Mutex::new(None),
            ui_ready: Arc::new(Notify::new()),
            boot_at,
            first_paint_logged: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            accounts_changed: Arc::new(Notify::new()),
            picked_attachment_paths: Mutex::new(HashSet::new()),
        }
    }
}
