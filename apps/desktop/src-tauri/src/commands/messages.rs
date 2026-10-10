// SPDX-License-Identifier: Apache-2.0

//! `messages_*` Tauri commands.
//!
//! Implements the read-path surface of `COMMANDS.md §Messages`:
//! `messages_list`, `messages_list_unified`, `messages_search`,
//! `messages_get`, plus the write-path / mutation commands
//! (`messages_mark_read`, `messages_flag`, `messages_move`,
//! `messages_archive`, `messages_delete`, `messages_send`) and the
//! `messages_open_attachment` extractor that pulls attachment bytes
//! out of cached message blobs and hands them to the OS default
//! application via the user's Downloads directory.

use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine as _;
use qsl_core::{EmailAddress, FolderRole, MessageFlags, MessageHeaders};
use qsl_ipc::{DraftId, FolderId, IpcResult, MessageId, MessagePage, RenderedMessage, SortOrder};
use qsl_mime::{
    compose::build_rfc5322, extract_attachment_bytes, parse_rfc822, sanitize_email_html,
    sanitize_email_html_trusted, MessageIdentity,
};
use qsl_storage::{
    repos::accounts as accounts_repo, repos::app_settings as app_settings_repo,
    repos::drafts as drafts_repo, repos::folders as folders_repo, repos::messages as messages_repo,
    repos::outbox as outbox_repo, repos::remote_content_opt_ins, repos::threads as threads_repo,
    BlobStore,
};
use serde::Deserialize;
use tauri::State;

use crate::backend_factory;
use crate::state::AppState;

/// Phase 0 Week 5 caps a single page to 500 headers. Sync engine paging
/// (Phase 1) negotiates higher bounds directly with the backend.
const MAX_PAGE_LIMIT: u32 = 500;

/// Look up `threads.message_count` for every distinct thread id
/// referenced by a page of headers. Returns the wire-form
/// `HashMap<String, u32>` that ships in `MessagePage::thread_counts`
/// — empty if no message in the page has a `thread_id`. Keyed by
/// `ThreadId.0` so JSON serialization is a flat string-to-int
/// object instead of nested.
async fn thread_counts_for_page(
    db: &dyn qsl_storage::DbConn,
    messages: &[qsl_core::MessageHeaders],
) -> IpcResult<std::collections::HashMap<String, u32>> {
    let mut seen: std::collections::HashSet<&qsl_core::ThreadId> = std::collections::HashSet::new();
    let mut ids: Vec<qsl_core::ThreadId> = Vec::new();
    for m in messages {
        if let Some(tid) = &m.thread_id {
            if seen.insert(tid) {
                ids.push(tid.clone());
            }
        }
    }
    let counts = threads_repo::counts_by_ids(db, &ids).await?;
    Ok(counts.into_iter().map(|(k, v)| (k.0, v)).collect())
}

/// `app_settings_v1` key for the global "always load remote images"
/// toggle. Mirrored from `apps/desktop/ui/src/settings.rs::KEY_REMOTE_IMAGES`
/// — keep both in sync. Stored as plain text "true"/"false".
const KEY_REMOTE_IMAGES_ALWAYS: &str = "privacy.remote_images_always";

#[derive(Debug, Deserialize)]
pub struct MessagesListInput {
    pub folder: FolderId,
    pub limit: u32,
    pub offset: u32,
    #[serde(default)]
    pub sort: SortOrder,
}

/// `messages_list` — return one page of a folder's message list.
///
/// Reads from the local cache; sorting beyond `DateDesc` is a Phase 1
/// concern, so for now non-`DateDesc` sorts fall back to `DateDesc` and
/// emit a `tracing` warning. The UI should still feel responsive: the
/// Phase 0 proof-of-life inbox is sorted newest-first anyway.
#[tauri::command]
pub async fn messages_list(
    state: State<'_, AppState>,
    input: MessagesListInput,
) -> IpcResult<MessagePage> {
    let MessagesListInput {
        folder,
        limit,
        offset,
        sort,
    } = input;

    let limit = limit.min(MAX_PAGE_LIMIT);
    if sort != SortOrder::DateDesc {
        tracing::warn!(
            requested = ?sort,
            "messages_list: Phase 0 Week 5 only implements date_desc — falling back"
        );
    }

    let db = state.db.lock().await;
    let messages = messages_repo::list_by_folder(&*db, &folder, limit, offset).await?;
    let total_count = messages_repo::count_by_folder(&*db, &folder).await?;
    let unread_count = messages_repo::count_unread_by_folder(&*db, &folder).await?;
    let thread_counts = thread_counts_for_page(&*db, &messages).await?;

    tracing::debug!(
        folder = %folder.0,
        page = messages.len(),
        total = total_count,
        unread = unread_count,
        "messages_list"
    );

    Ok(MessagePage {
        messages,
        total_count,
        unread_count,
        thread_counts,
        indexing_in_progress: false,
    })
}

#[derive(Debug, Deserialize)]
pub struct MessagesListUnifiedInput {
    pub limit: u32,
    pub offset: u32,
    #[serde(default)]
    pub sort: SortOrder,
}

/// `messages_list_unified` — one page of the unified inbox: every
/// account's INBOX-role folder merged and sorted by date desc.
///
/// Resolves the set of INBOX folders by `folders::list_by_role` so
/// we don't depend on a hardcoded folder-name convention; works
/// for both IMAP (`\Inbox` SPECIAL-USE) and JMAP (`Mailbox.role =
/// inbox`) accounts because both adapters normalize to
/// `FolderRole::Inbox` at sync time.
#[tauri::command]
pub async fn messages_list_unified(
    state: State<'_, AppState>,
    input: MessagesListUnifiedInput,
) -> IpcResult<MessagePage> {
    let MessagesListUnifiedInput {
        limit,
        offset,
        sort,
    } = input;
    let limit = limit.min(MAX_PAGE_LIMIT);
    if sort != SortOrder::DateDesc {
        tracing::warn!(
            requested = ?sort,
            "messages_list_unified: Phase 1 Week 12 only implements date_desc — falling back"
        );
    }

    let db = state.db.lock().await;
    let inboxes = folders_repo::list_by_role(&*db, FolderRole::Inbox).await?;
    let folder_ids: Vec<FolderId> = inboxes.iter().map(|f| f.id.clone()).collect();
    let messages = messages_repo::list_by_folders(&*db, &folder_ids, limit, offset).await?;
    let total_count = messages_repo::count_by_folders(&*db, &folder_ids).await?;
    let unread_count = messages_repo::count_unread_by_folders(&*db, &folder_ids).await?;
    let thread_counts = thread_counts_for_page(&*db, &messages).await?;
    drop(db);

    tracing::debug!(
        inbox_folders = inboxes.len(),
        page = messages.len(),
        total = total_count,
        unread = unread_count,
        "messages_list_unified"
    );

    Ok(MessagePage {
        messages,
        total_count,
        unread_count,
        thread_counts,
        indexing_in_progress: false,
    })
}

#[derive(Debug, Deserialize)]
pub struct MessagesSearchInput {
    /// Raw user query — Gmail-style operator syntax. Parsed by
    /// `qsl_search::parse`. Empty / whitespace returns no rows.
    pub query: String,
    pub limit: u32,
    pub offset: u32,
}

/// `messages_search` — run a Gmail-style operator query across the
/// whole local cache and return matching message headers.
///
/// Pipeline: parse the user string with `qsl_search::parse`,
/// dispatch to `repos::search::search_with_query` to get
/// `Vec<MessageId>` ordered by relevance, then hydrate each id back
/// to a full `MessageHeaders`. Hydration runs serially to keep the
/// db lock contention bounded; for the 50-row default page that's
/// well under a frame.
///
/// Returns `MessagePage` so the UI can reuse the same list-rendering
/// path as folder browsing. `unread_count` counts only the rows on
/// this page — totals across the whole result set aren't tracked
/// (the FTS index doesn't expose `count(*)` cheaply, and the page
/// answer is what the user can see).
#[tauri::command]
pub async fn messages_search(
    state: State<'_, AppState>,
    input: MessagesSearchInput,
) -> IpcResult<MessagePage> {
    let MessagesSearchInput {
        query,
        limit,
        offset,
    } = input;
    let limit = limit.min(MAX_PAGE_LIMIT);

    // While a bulk history pull is running, the FTS index is dropped
    // (rebuilt at the end of the pull). Don't run `fts_match()`
    // against the missing index — it'll either error or full-scan.
    // Instead, return an empty page tagged with `indexing_in_progress`
    // so the UI renders a "search paused while syncing" banner
    // instead of hanging on a doomed query and freezing the UI thread.
    if state
        .pull_in_progress
        .load(std::sync::atomic::Ordering::Relaxed)
        > 0
    {
        return Ok(MessagePage {
            messages: Vec::new(),
            total_count: 0,
            unread_count: 0,
            thread_counts: std::collections::HashMap::new(),
            indexing_in_progress: true,
        });
    }

    let parsed = qsl_search::parse(&query);
    if parsed.is_empty() {
        return Ok(MessagePage {
            messages: Vec::new(),
            total_count: 0,
            unread_count: 0,
            thread_counts: std::collections::HashMap::new(),
            indexing_in_progress: false,
        });
    }

    let db = state.db.lock().await;
    let ids = qsl_telemetry::time_op!(
        target: "qsl::slow::db",
        limit_ms: qsl_telemetry::slow::limits::DB_QUERY_MS,
        op: "search_with_query",
        fields: { limit = limit, offset = offset },
        qsl_storage::repos::search::search_with_query(&*db, &parsed, limit, offset)
    )?;

    let mut messages = Vec::with_capacity(ids.len());
    for id in &ids {
        match messages_repo::get(&*db, id).await {
            Ok(h) => messages.push(h),
            Err(e) => {
                tracing::warn!(id = %id.0, "messages_search: hydrate failed: {e}");
            }
        }
    }
    drop(db);

    let unread_count: u32 = messages
        .iter()
        .filter(|m| !m.flags.seen)
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    let total_count: u32 = messages.len().try_into().unwrap_or(u32::MAX);
    let thread_counts = {
        let db = state.db.lock().await;
        thread_counts_for_page(&*db, &messages).await?
    };

    tracing::debug!(
        query = %query,
        page = messages.len(),
        "messages_search"
    );

    Ok(MessagePage {
        messages,
        total_count,
        unread_count,
        thread_counts,
        indexing_in_progress: false,
    })
}

#[derive(Debug, Deserialize)]
pub struct MessagesGetInput {
    pub id: MessageId,
    /// One-shot override that forces the trusted sanitizer for this
    /// render. Used by the reader-pane "Load images" button so the
    /// user can let remote content through for a single message
    /// without persistently trusting the sender. Defaults to `false`.
    #[serde(default)]
    pub force_trusted: bool,
}

/// `messages_get` — hydrate a single message for the reader pane.
///
/// - Always returns headers from the local Turso cache.
/// - When the body blob is on disk (`body_path` non-null), parses it
///   and returns `body_text` / `sanitized_html` / `attachments`.
/// - When the body blob is missing — header-only row from a
///   pre-Week-9 sync, or one whose body fetch failed during the
///   sync cycle's body-fetch pass — falls back to a live
///   `fetch_raw_message` against the cached `MailBackend`,
///   persists the bytes to the blob store, and continues with the
///   parse path. A failed lazy fetch logs a warning and returns
///   headers-only rather than surfacing the error to the UI.
/// - `sender_is_trusted` is true when the message's first `From`
///   address is recorded in `remote_content_opt_ins` for this
///   account. Trusted senders skip the remote-content URL filter
///   inside `sanitize_email_html_trusted` so their image pixels,
///   stylesheets, and fonts render. `remote_content_blocked` is
///   the inverse — true when the sanitizer was the blocking
///   variant. The UI uses both to decide whether to show a "load
///   remote content" banner.
#[tauri::command]
pub async fn messages_get(
    state: State<'_, AppState>,
    input: MessagesGetInput,
) -> IpcResult<RenderedMessage> {
    tracing::debug!(id = %input.id.0, "messages_get");
    let rendered = render_message(&state, &input.id, input.force_trusted).await?;
    // Backlog #11 — populate the single-entry cache so a subsequent
    // `messages_open_in_window` for the same id can skip the re-fetch
    // + re-sanitize. The cache is invalidated implicitly: the next
    // `messages_get` for a different id (or the same id with a
    // different `force_trusted`) overwrites the slot. Only the
    // foreground `messages_get` writes the cache — `messages_thread`
    // explicitly skips it because the popup reader hands back a
    // single id, not a thread.
    *state.last_rendered.lock().await = Some((input.id.clone(), rendered.clone()));
    Ok(rendered)
}

#[derive(Debug, Deserialize)]
pub struct MessagesThreadInput {
    /// Any message in the thread — usually the one the user has
    /// selected in the message list. The command resolves the row's
    /// `thread_id`, then renders every message attached to that
    /// thread in date-ascending order. Singleton threads (or
    /// messages with `thread_id = NULL`) round-trip a one-element
    /// vec so the caller doesn't need a fallback path.
    pub id: MessageId,
    /// Same `force_trusted` semantics as `messages_get` — applied to
    /// every message in the thread. The reader's "Load images"
    /// banner is whole-thread because remote-image trust is per
    /// sender, not per individual message, and the user typically
    /// flips it once for the whole conversation.
    #[serde(default)]
    pub force_trusted: bool,
}

/// `messages_thread` — render every message in the same thread as
/// `input.id`. Drives the desktop UI's stacked thread reader: the
/// caller selects one message, the renderer paints all of them as a
/// vertical stack with prior messages collapsed.
///
/// Lock discipline: takes the DB mutex twice — once for the input
/// row's headers (to resolve the thread id), then once again per
/// rendered message via [`render_message`]. We don't hold a single
/// lock across the loop because [`lazy_fetch_body`] inside
/// `render_message` can block on the network for tens of seconds and
/// we don't want that blocking IPC for unrelated reads.
#[tauri::command]
pub async fn messages_thread(
    state: State<'_, AppState>,
    input: MessagesThreadInput,
) -> IpcResult<Vec<RenderedMessage>> {
    tracing::debug!(id = %input.id.0, "messages_thread");
    let db = state.db.lock().await;
    let headers = messages_repo::get(&*db, &input.id).await?;
    let thread_id = headers.thread_id.clone();
    let ids: Vec<MessageId> = match thread_id {
        Some(ref tid) => messages_repo::list_by_thread(&*db, tid)
            .await?
            .into_iter()
            .map(|h| h.id)
            .collect(),
        None => vec![input.id.clone()],
    };
    drop(db);

    let mut out = Vec::with_capacity(ids.len());
    for id in &ids {
        out.push(render_message(&state, id, input.force_trusted).await?);
    }
    Ok(out)
}

/// Shared rendering pipeline for `messages_get` and `messages_thread`.
/// Pulls the row's headers + body bytes (cached or lazy-fetched),
/// applies trust resolution against the user's three opt-in surfaces,
/// and runs the sanitizer. Does NOT touch `state.last_rendered` —
/// that cache is only meaningful for the singleton-render path the
/// popup reader uses, and we don't want a thread render to clobber
/// the user's most-recently-viewed message id with the chronologically
/// last one.
async fn render_message(
    state: &AppState,
    id: &MessageId,
    force_trusted: bool,
) -> IpcResult<RenderedMessage> {
    let db = state.db.lock().await;
    let headers = messages_repo::get(&*db, id).await?;
    let body_path = messages_repo::body_path(&*db, id).await?;
    // Trust resolution stacks three sources, in priority order:
    //
    // 1. `force_trusted` — per-render override used by the reader's
    //    "Load images" banner button. One render, no storage.
    // 2. Global `privacy.remote_images_always` setting — when on,
    //    every message renders as if the sender is trusted. Stored
    //    as "true"/"false" plain text in `app_settings_v1`.
    // 3. Per-sender opt-in (`remote_content_opt_ins`) — set by the
    //    "Always load from this sender" banner button.
    //
    // Any one of these flips the renderer to the trusted path.
    let global_remote_images_on = matches!(
        app_settings_repo::get(&*db, KEY_REMOTE_IMAGES_ALWAYS).await?,
        Some(ref v) if v == "true"
    );
    let sender_is_trusted = if force_trusted || global_remote_images_on {
        true
    } else {
        match headers.from.first() {
            Some(addr) if !addr.address.is_empty() => {
                remote_content_opt_ins::is_trusted(&*db, &headers.account_id, &addr.address).await?
            }
            _ => false,
        }
    };
    tracing::debug!(
        id = %id.0,
        sender_is_trusted,
        "render_message sanitize path"
    );
    drop(db);

    let blobs = BlobStore::new(state.data_dir.join("blobs"));
    let bytes = if body_path.is_some() {
        load_cached_body(&blobs, &headers).await
    } else {
        lazy_fetch_body(state, &blobs, &headers).await
    };

    let (body_text, sanitized_html, attachments) = match bytes {
        Some(bytes) => parse_and_sanitize(&bytes, &headers, sender_is_trusted),
        None => (None, None, Vec::new()),
    };

    Ok(RenderedMessage {
        headers,
        sanitized_html,
        body_text,
        attachments,
        sender_is_trusted,
        remote_content_blocked: !sender_is_trusted,
    })
}

#[derive(Debug, Deserialize)]
pub struct MessagesTrustSenderInput {
    pub account_id: qsl_core::AccountId,
    pub email_address: String,
}

/// Persist a per-sender remote-content opt-in. Subsequent
/// `messages_get` calls for any message whose `From` is `email_address`
/// on `account_id` will run the trusted sanitizer (images,
/// stylesheets, fonts not stripped). Existing rows are upserted.
///
/// Backs the reader-pane "Always load from this sender" banner button.
#[tauri::command]
pub async fn messages_trust_sender(
    state: State<'_, AppState>,
    input: MessagesTrustSenderInput,
) -> IpcResult<()> {
    let MessagesTrustSenderInput {
        account_id,
        email_address,
    } = input;
    let db = state.db.lock().await;
    remote_content_opt_ins::add(&*db, &account_id, &email_address).await?;
    drop(db);
    tracing::info!(account = %account_id.0, %email_address, "messages_trust_sender: added opt-in");
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct MessagesOpenAttachmentInput {
    pub message_id: MessageId,
    /// `AttachmentRef` from `messages_get`'s `RenderedMessage.attachments`.
    /// Currently encoded as `"part/{i}"`; this command parses the suffix
    /// and looks up the part by index.
    pub attachment_id: qsl_core::AttachmentRef,
}

/// `messages_open_attachment` — extract one attachment's bytes, write
/// them to the user's Downloads folder under the suggested filename
/// (suffixed `(1)`, `(2)`, … on collision), and open the resulting
/// file with the system default application.
///
/// Reuses the same `load_cached_body` + `lazy_fetch_body` path as
/// [`messages_get`] so we never re-fetch when the body blob is
/// already on disk. The MIME walk is delegated to
/// `qsl_mime::extract_attachment_bytes`, which uses the same part-index
/// numbering [`parse_rfc822`] burns into each `AttachmentRef`.
///
/// On any failure (no body bytes, malformed MIME, index out of range,
/// I/O error, missing Downloads dir) returns an `IpcError` with a
/// short message — the UI surfaces that as a toast.
#[tauri::command]
pub async fn messages_open_attachment(
    state: State<'_, AppState>,
    input: MessagesOpenAttachmentInput,
) -> IpcResult<String> {
    use qsl_ipc::{IpcError, IpcErrorKind};

    let MessagesOpenAttachmentInput {
        message_id,
        attachment_id,
    } = input;
    tracing::debug!(id = %message_id.0, attachment = %attachment_id.0, "messages_open_attachment");

    // Resolve the part index baked into the attachment id by
    // `qsl_mime::body_from`. The format is `"part/{i}"`; anything
    // else is an unsupported (or stale) shape.
    let part_index: usize = attachment_id
        .0
        .strip_prefix("part/")
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or_else(|| {
            IpcError::new(
                IpcErrorKind::Internal,
                format!(
                    "messages_open_attachment: unrecognized attachment id `{}`",
                    attachment_id.0
                ),
            )
        })?;

    // Pull headers + cached body path. Same shape as `messages_get`.
    let db = state.db.lock().await;
    let headers = messages_repo::get(&*db, &message_id).await?;
    let body_path = messages_repo::body_path(&*db, &message_id).await?;
    drop(db);

    let blobs = BlobStore::new(state.data_dir.join("blobs"));
    let bytes = if body_path.is_some() {
        load_cached_body(&blobs, &headers).await
    } else {
        lazy_fetch_body(&state, &blobs, &headers).await
    };
    let bytes = bytes.ok_or_else(|| {
        IpcError::new(
            IpcErrorKind::NotFound,
            format!(
                "messages_open_attachment: could not load body for {}",
                message_id.0
            ),
        )
    })?;

    let (filename, payload) = extract_attachment_bytes(&bytes, part_index).ok_or_else(|| {
        IpcError::new(
            IpcErrorKind::NotFound,
            format!("messages_open_attachment: no binary part at index {part_index}"),
        )
    })?;

    // Resolve Downloads dir. UserDirs::download_dir() returns Some on
    // platforms that publish `XDG_DOWNLOAD_DIR` / Known Folder /
    // similar; fall back to data_dir for headless setups so the
    // command still produces *something* useful.
    let download_dir = directories::UserDirs::new()
        .and_then(|d| d.download_dir().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| state.data_dir.join("downloads"));
    if let Err(e) = std::fs::create_dir_all(&download_dir) {
        return Err(IpcError::new(
            IpcErrorKind::Storage,
            format!(
                "messages_open_attachment: create {}: {e}",
                download_dir.display()
            ),
        ));
    }

    let safe_name = sanitize_attachment_filename(&filename);
    let target_path = unique_path(&download_dir, &safe_name);
    let bytes_written = payload.len();
    if let Err(e) = std::fs::write(&target_path, payload) {
        return Err(IpcError::new(
            IpcErrorKind::Storage,
            format!(
                "messages_open_attachment: write {}: {e}",
                target_path.display()
            ),
        ));
    }
    mark_downloaded_from_internet(&target_path);

    let target_str = target_path.to_string_lossy().into_owned();
    // Never hand sender-controlled executables, scripts, or
    // browser-rendered documents straight to a launcher: `.exe`,
    // `.lnk`, `.hta`, `.desktop` would run; `.html`/`.svg` would
    // render with scripts at a `file://` origin outside the reader
    // sandbox. Save them and tell the user where they are instead.
    if is_unsafe_to_launch(&safe_name) {
        tracing::info!(
            path = %target_str,
            size = bytes_written,
            "attachment saved but not opened (launch-unsafe type)"
        );
        return Ok(format!(
            "{target_str} (saved; not opened automatically because this file type can run code)"
        ));
    }
    if let Err(e) = webbrowser::open(&target_str) {
        // The file is written even if open failed — caller can still
        // navigate to Downloads manually. Log and surface a soft
        // error so the UI shows "saved but couldn't open".
        tracing::warn!(path = %target_str, "open attachment via webbrowser::open failed: {e}");
        return Err(IpcError::new(
            IpcErrorKind::Internal,
            format!("saved to {target_str} but failed to open: {e}"),
        ));
    }

    tracing::info!(path = %target_str, size = bytes_written, "attachment opened");
    Ok(target_str)
}

/// Strip path separators and other shell-hostile characters so a
/// suggested filename from a remote sender can't escape the Downloads
/// directory or get interpreted by the shell. Replaces `/` `\` `:`,
/// the rest of the Windows-reserved set (`< > " | ? *`), control
/// characters, and Unicode bidi-override / isolate controls (the
/// `invoice\u{202E}fdp.exe` → "invoiceexe.pdf" spoof) with `_`.
/// Windows reserved device names (`CON`, `NUL`, `COM1`, …) get a
/// prefix so the OS doesn't treat them as devices. Empty result falls
/// back to `attachment.bin`.
fn sanitize_attachment_filename(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            let bidi = matches!(
                c,
                '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            );
            if matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
                || c.is_control()
                || bidi
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    out = out
        .trim_matches(|c: char| c == '.' || c.is_whitespace())
        .to_string();
    if out.is_empty() {
        return "attachment.bin".to_string();
    }
    let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        out.insert(0, '_');
    }
    out
}

/// File types we refuse to auto-launch after saving: anything the OS
/// or a browser would *execute* rather than display. Extension match
/// is case-insensitive on the final extension only, which also
/// catches `report.pdf.exe`. Documents (`.pdf`, `.docx`, images, …)
/// are not listed and open as before.
fn is_unsafe_to_launch(filename: &str) -> bool {
    const UNSAFE: &[&str] = &[
        // Windows executables / scripts / shortcuts.
        "exe",
        "com",
        "bat",
        "cmd",
        "scr",
        "pif",
        "msi",
        "msp",
        "mst",
        "cpl",
        "dll",
        "sys",
        "drv",
        "ocx",
        "lnk",
        "url",
        "inf",
        "reg",
        "hta",
        "vbs",
        "vbe",
        "js",
        "jse",
        "ws",
        "wsf",
        "wsh",
        "wsc",
        "sct",
        "ps1",
        "psm1",
        "psd1",
        "ps1xml",
        "psc1",
        "msh",
        "msh1",
        "msh2",
        "mshxml",
        "jar",
        "application",
        "gadget",
        "appx",
        "msix",
        "appinstaller",
        "diagcab",
        "settingcontent-ms",
        "chm",
        "iso",
        "img",
        "vhd",
        "vhdx",
        // Unix / macOS launchables.
        "sh",
        "bash",
        "zsh",
        "csh",
        "ksh",
        "fish",
        "run",
        "bin",
        "desktop",
        "app",
        "action",
        "command",
        "workflow",
        "terminal",
        "pkg",
        "dmg",
        "deb",
        "rpm",
        "appimage",
        "pl",
        "py",
        "pyc",
        "pyw",
        "rb",
        "php",
        "cgi",
        "elf",
        "so",
        "dylib",
        // Browser-rendered with script at a file:// origin.
        "html",
        "htm",
        "xhtml",
        "xht",
        "shtml",
        "svg",
        "svgz",
        "xml",
        "xsl",
        "xslt",
        "mht",
        "mhtml",
        "swf",
    ];
    filename
        .rsplit_once('.')
        .map(|(_, ext)| ext.trim())
        .is_some_and(|ext| UNSAFE.iter().any(|u| u.eq_ignore_ascii_case(ext)))
}

/// Windows: write the `Zone.Identifier` alternate data stream so the
/// file carries the Mark-of-the-Web (ZoneId 3 = Internet). Explorer,
/// SmartScreen, and Office protected view key off it; without it a
/// saved attachment looks like a locally-authored file. Best-effort,
/// no-op elsewhere.
fn mark_downloaded_from_internet(path: &std::path::Path) {
    #[cfg(windows)]
    {
        let ads = format!("{}:Zone.Identifier", path.display());
        if let Err(e) = std::fs::write(&ads, "[ZoneTransfer]\r\nZoneId=3\r\n") {
            tracing::debug!(path = %path.display(), "Zone.Identifier write failed: {e}");
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
}

/// Find a non-existing path inside `dir` for `filename`. If the file
/// exists, append ` (1)`, ` (2)`, … before the extension. Caps at 999
/// before falling back to the bare name (callers will then overwrite).
fn unique_path(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match filename.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (filename.to_string(), String::new()),
    };
    for n in 1..1000 {
        let p = dir.join(format!("{stem} ({n}){ext}"));
        if !p.exists() {
            return p;
        }
    }
    dir.join(filename)
}

/// Read a previously-fetched body blob from disk. A stale
/// `body_path` with no file on disk is a cache bug, not a
/// user-visible error: log and return `None`.
async fn load_cached_body(blobs: &BlobStore, headers: &MessageHeaders) -> Option<Vec<u8>> {
    match blobs
        .get(&headers.account_id, &headers.folder_id, &headers.id)
        .await
    {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::warn!(id = %headers.id.0, "messages_get: body blob missing: {e}");
            None
        }
    }
}

/// Fetch the body live from the backend, persist to the blob store,
/// and update `body_path`. Any failure (no backend, network, parse,
/// storage write) logs a warning and returns `None` — the reader
/// pane still renders headers + plaintext-fallback.
async fn lazy_fetch_body(
    state: &AppState,
    blobs: &BlobStore,
    headers: &MessageHeaders,
) -> Option<Vec<u8>> {
    // Wrap the fetch in `with_auth_retry` so a `MailError::Auth`
    // mid-call (token revoked, server clock skew, anything that's not
    // caught by the 30-min proactive eviction) gets one transparent
    // retry against a freshly-rebuilt backend. `fetch_raw_message` is
    // an idempotent read so re-running it is safe.
    let id = headers.id.clone();
    let raw = match backend_factory::with_auth_retry(state, &headers.account_id, |backend| {
        let id = id.clone();
        async move { backend.fetch_raw_message(&id).await }
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(id = %headers.id.0, "messages_get: lazy fetch failed: {e}");
            return None;
        }
    };

    let path = match blobs
        .put(&headers.account_id, &headers.folder_id, &headers.id, &raw)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(id = %headers.id.0, "messages_get: blob store write failed: {e}");
            // Bytes in hand are still useful even if persistence
            // failed — return them anyway so the user sees their
            // message.
            return Some(raw);
        }
    };

    let db = state.db.lock().await;
    if let Err(e) =
        messages_repo::set_body_path(&*db, &headers.id, Some(&path.to_string_lossy())).await
    {
        tracing::warn!(id = %headers.id.0, "messages_get: set_body_path failed: {e}");
    }

    Some(raw)
}

/// Run the parse + ammonia pass over a body blob and split the
/// returned `MessageBody` into the three fields the IPC contract
/// expects.
fn parse_and_sanitize(
    bytes: &[u8],
    headers: &MessageHeaders,
    sender_is_trusted: bool,
) -> (Option<String>, Option<String>, Vec<qsl_core::Attachment>) {
    let parsed = parse_rfc822(
        bytes,
        MessageIdentity {
            id: &headers.id,
            account_id: &headers.account_id,
            folder_id: &headers.folder_id,
            thread_id: headers.thread_id.as_ref(),
            size: headers.size,
            flags: &headers.flags,
            labels: &headers.labels,
        },
    );
    match parsed {
        Some(body) => {
            // The trusted-sender variant skips only the
            // remote-content URL filter — script/iframe/event-
            // handler/etc. stripping is unconditional regardless of
            // trust.
            let sanitize = if sender_is_trusted {
                sanitize_email_html_trusted
            } else {
                sanitize_email_html
            };
            let sanitized = body.body_html.as_deref().map(sanitize);
            (body.body_text, sanitized, body.attachments)
        }
        None => (None, None, Vec::new()),
    }
}

#[derive(Debug, Deserialize)]
pub struct MessagesMarkReadInput {
    pub ids: Vec<MessageId>,
    /// `true` marks read (sets `\Seen`); `false` marks unread.
    pub seen: bool,
}

/// `messages_mark_read` — flip the seen flag locally and queue an
/// outbox entry for the server.
///
/// Optimistic shape per `PHASE_1.md` Week 14: apply the local
/// update first, enqueue the outbox row second, return. The
/// background drain worker dispatches the row to
/// `MailBackend::update_flags` and on success deletes the row.
/// On failure it backs off; after `MAX_ATTEMPTS` the row enters
/// the dead-letter state and the UI surfaces a "failed to sync"
/// banner.
///
/// Per-account grouping: the outbox is keyed on `account_id`, so
/// mixed-account batches enqueue one row per account. The
/// `payload_json` shape is documented next to
/// `qsl_sync::outbox_drain::FlagsPayload`.
#[tauri::command]
pub async fn messages_mark_read(
    state: State<'_, AppState>,
    input: MessagesMarkReadInput,
) -> IpcResult<()> {
    let MessagesMarkReadInput { ids, seen } = input;
    tracing::debug!(count = ids.len(), seen, "ipc: messages_mark_read");
    if ids.is_empty() {
        return Ok(());
    }

    let db = state.db.lock().await;

    // Optimistic local update: read each row, flip the bit, write.
    // We don't pre-batch by account here because flag updates touch
    // a single row each — pulling the existing record gives us the
    // other flags so a future polish-pass `update_flags` against
    // multiple bits works cleanly.
    let mut by_account: std::collections::HashMap<qsl_core::AccountId, Vec<MessageId>> =
        std::collections::HashMap::new();
    for id in &ids {
        let mut headers = match messages_repo::get(&*db, id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(id = %id.0, "messages_mark_read: skipping unknown id: {e}");
                continue;
            }
        };
        if headers.flags.seen == seen {
            continue;
        }
        headers.flags.seen = seen;
        if let Err(e) = messages_repo::update_flags(&*db, id, &headers.flags).await {
            tracing::warn!(id = %id.0, "messages_mark_read: local update failed: {e}");
            continue;
        }
        by_account
            .entry(headers.account_id)
            .or_default()
            .push(id.clone());
    }

    // Queue one outbox row per account. Payload is JSON of the
    // Vec<MessageId> + the desired flag delta — drain dispatches.
    for (account, ids) in by_account {
        let add = MessageFlags {
            seen,
            ..Default::default()
        };
        let remove = MessageFlags {
            seen: !seen,
            ..Default::default()
        };
        let payload = serde_json::json!({
            "ids": ids,
            "add": add,
            "remove": remove,
        });
        outbox_repo::enqueue(&*db, &account, "update_flags", &payload.to_string()).await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct MessagesFlagInput {
    pub ids: Vec<MessageId>,
    /// `true` sets `\Flagged` (the user's "starred" / "important"
    /// indicator); `false` clears it.
    pub flagged: bool,
}

/// `messages_flag` — flip the flagged ("starred") bit. Mirrors
/// [`messages_mark_read`]: optimistic local update + outbox row,
/// returns immediately.
#[tauri::command]
pub async fn messages_flag(state: State<'_, AppState>, input: MessagesFlagInput) -> IpcResult<()> {
    let MessagesFlagInput { ids, flagged } = input;
    tracing::debug!(count = ids.len(), flagged, "ipc: messages_flag");
    if ids.is_empty() {
        return Ok(());
    }

    let db = state.db.lock().await;
    let mut by_account: std::collections::HashMap<qsl_core::AccountId, Vec<MessageId>> =
        std::collections::HashMap::new();
    for id in &ids {
        let mut headers = match messages_repo::get(&*db, id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(id = %id.0, "messages_flag: skipping unknown id: {e}");
                continue;
            }
        };
        if headers.flags.flagged == flagged {
            continue;
        }
        headers.flags.flagged = flagged;
        if let Err(e) = messages_repo::update_flags(&*db, id, &headers.flags).await {
            tracing::warn!(id = %id.0, "messages_flag: local update failed: {e}");
            continue;
        }
        by_account
            .entry(headers.account_id)
            .or_default()
            .push(id.clone());
    }

    for (account, ids) in by_account {
        let add = MessageFlags {
            flagged,
            ..Default::default()
        };
        let remove = MessageFlags {
            flagged: !flagged,
            ..Default::default()
        };
        let payload = serde_json::json!({
            "ids": ids,
            "add": add,
            "remove": remove,
        });
        outbox_repo::enqueue(&*db, &account, "update_flags", &payload.to_string()).await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct MessagesMoveInput {
    pub ids: Vec<MessageId>,
    pub target: FolderId,
}

/// `messages_move` — relocate messages into `target`. Local
/// optimistic update flips `messages.folder_id`; the outbox row
/// drives the server-side move (IMAP MOVE / Email/set mailboxIds)
/// once the drain wakes up.
#[tauri::command]
pub async fn messages_move(state: State<'_, AppState>, input: MessagesMoveInput) -> IpcResult<()> {
    let MessagesMoveInput { ids, target } = input;
    tracing::debug!(count = ids.len(), target = %target.0, "ipc: messages_move");
    if ids.is_empty() {
        return Ok(());
    }

    let db = state.db.lock().await;
    let mut by_account: std::collections::HashMap<qsl_core::AccountId, Vec<MessageId>> =
        std::collections::HashMap::new();
    for id in &ids {
        let headers = match messages_repo::get(&*db, id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(id = %id.0, "messages_move: skipping unknown id: {e}");
                continue;
            }
        };
        if headers.folder_id == target {
            continue;
        }
        if let Err(e) = messages_repo::set_folder(&*db, id, &target).await {
            tracing::warn!(id = %id.0, "messages_move: local update failed: {e}");
            continue;
        }
        by_account
            .entry(headers.account_id)
            .or_default()
            .push(id.clone());
    }

    for (account, ids) in by_account {
        let payload = serde_json::json!({
            "ids": ids,
            "target": target,
        });
        outbox_repo::enqueue(&*db, &account, "move_messages", &payload.to_string()).await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct MessagesArchiveInput {
    pub ids: Vec<MessageId>,
}

/// `messages_archive` — archive messages by moving them to the
/// account's archive target. Resolution per account: prefer a folder
/// with `FolderRole::Archive` (Fastmail-style), then fall back to
/// `FolderRole::All` (Gmail's `[Gmail]/All Mail` — moving INBOX → All
/// Mail removes the INBOX label, which is exactly Gmail's archive
/// semantic).
///
/// Local update flips `messages.folder_id`; the existing
/// `OP_MOVE` outbox op carries the move to the wire. We do not
/// introduce a separate "archive" op — the move-to-correct-target
/// abstraction handles both Gmail and Fastmail correctly through the
/// backend's `move_messages` (UID MOVE on IMAP, `Email/set
/// mailboxIds` on JMAP).
#[tauri::command]
pub async fn messages_archive(
    state: State<'_, AppState>,
    input: MessagesArchiveInput,
) -> IpcResult<()> {
    let MessagesArchiveInput { ids } = input;
    tracing::debug!(count = ids.len(), "ipc: messages_archive");
    if ids.is_empty() {
        return Ok(());
    }

    let db = state.db.lock().await;
    // Group ids by account so we resolve the archive target once per
    // account, not per message.
    let mut by_account: std::collections::HashMap<qsl_core::AccountId, Vec<MessageId>> =
        std::collections::HashMap::new();
    for id in &ids {
        let headers = match messages_repo::get(&*db, id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(id = %id.0, "messages_archive: skipping unknown id: {e}");
                continue;
            }
        };
        by_account
            .entry(headers.account_id)
            .or_default()
            .push(id.clone());
    }

    for (account, account_ids) in by_account {
        let folders = folders_repo::list_by_account(&*db, &account).await?;
        let target = resolve_archive_target(&folders).ok_or_else(|| {
            qsl_ipc::IpcError::new(
                qsl_ipc::IpcErrorKind::NotFound,
                format!(
                    "messages_archive: no archive target for account {} (need Archive- or All-role folder)",
                    account.0
                ),
            )
        })?;

        let mut moved = Vec::with_capacity(account_ids.len());
        for id in account_ids {
            // Skip messages already in the archive target.
            let headers = match messages_repo::get(&*db, &id).await {
                Ok(h) => h,
                Err(_) => continue,
            };
            if headers.folder_id == target {
                continue;
            }
            if let Err(e) = messages_repo::set_folder(&*db, &id, &target).await {
                tracing::warn!(id = %id.0, "messages_archive: local update failed: {e}");
                continue;
            }
            moved.push(id);
        }

        if moved.is_empty() {
            continue;
        }

        let payload = serde_json::json!({
            "ids": moved,
            "target": target,
        });
        outbox_repo::enqueue(&*db, &account, "move_messages", &payload.to_string()).await?;
    }
    Ok(())
}

/// Pick the best archive target for an account given its folder list.
/// Prefers a folder with `FolderRole::Archive`; falls back to
/// `FolderRole::All`. Returns `None` if neither is present, in which
/// case the caller should surface an error rather than guess.
fn resolve_archive_target(folders: &[qsl_core::Folder]) -> Option<FolderId> {
    folders
        .iter()
        .find(|f| matches!(f.role, Some(FolderRole::Archive)))
        .or_else(|| {
            folders
                .iter()
                .find(|f| matches!(f.role, Some(FolderRole::All)))
        })
        .map(|f| f.id.clone())
}

#[derive(Debug, Deserialize)]
pub struct MessagesDeleteInput {
    pub ids: Vec<MessageId>,
}

/// `messages_delete` — remove messages locally and queue the
/// server-side delete (IMAP `+FLAGS (\Deleted) + UID EXPUNGE` /
/// JMAP `Email/destroy`). Note: Gmail interprets `\Deleted +
/// EXPUNGE` as "move to Trash" while Fastmail's `Email/destroy`
/// is permanent. The trait surface is the same; the visible
/// difference shows up in whether the message is recoverable.
#[tauri::command]
pub async fn messages_delete(
    state: State<'_, AppState>,
    input: MessagesDeleteInput,
) -> IpcResult<()> {
    let MessagesDeleteInput { ids } = input;
    tracing::debug!(count = ids.len(), "ipc: messages_delete");
    if ids.is_empty() {
        return Ok(());
    }

    let db = state.db.lock().await;
    let blobs = BlobStore::new(state.data_dir.join("blobs"));
    let mut by_account: std::collections::HashMap<qsl_core::AccountId, Vec<MessageId>> =
        std::collections::HashMap::new();
    for id in &ids {
        let headers = match messages_repo::get(&*db, id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(id = %id.0, "messages_delete: skipping unknown id: {e}");
                continue;
            }
        };
        if let Err(e) = messages_repo::delete(&*db, id).await {
            tracing::warn!(id = %id.0, "messages_delete: local delete failed: {e}");
            continue;
        }
        // The body blob is not reachable through the row once it's
        // gone; drop it now so deleted mail doesn't linger on disk.
        if let Err(e) = blobs
            .delete(&headers.account_id, &headers.folder_id, id)
            .await
        {
            tracing::debug!(id = %id.0, "messages_delete: blob cleanup failed: {e}");
        }
        by_account
            .entry(headers.account_id)
            .or_default()
            .push(id.clone());
    }

    for (account, ids) in by_account {
        let payload = serde_json::json!({ "ids": ids });
        outbox_repo::enqueue(&*db, &account, "delete_messages", &payload.to_string()).await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct MessagesSendInput {
    pub draft_id: DraftId,
}

/// `messages_send` — convert a saved draft into an outbox row and
/// drop it on the wire.
///
/// Reads the draft from storage, looks up the account's email
/// address for the From envelope, builds the RFC 5322 byte stream
/// via `qsl_mime::compose::build_rfc5322`, base64-encodes the
/// bytes into the outbox payload (so the JSON row stays a single
/// SQLite text column), and enqueues an `OP_SUBMIT_MESSAGE` row.
/// The drain worker picks it up and routes through the account's
/// `MailBackend::submit_message`.
///
/// The draft row is deleted on enqueue. Once the bytes are in the
/// outbox the draft is no longer the source of truth — the queue
/// row is. If submission DLQs, the user sees a "failed to send"
/// banner; the bytes are recoverable from the outbox row's
/// payload.
#[tauri::command]
pub async fn messages_send(state: State<'_, AppState>, input: MessagesSendInput) -> IpcResult<()> {
    let MessagesSendInput { draft_id } = input;
    tracing::debug!(draft_id = %draft_id.0, "ipc: messages_send");

    let db = state.db.lock().await;
    let draft = drafts_repo::get(&*db, &draft_id).await?;
    let account = accounts_repo::get(&*db, &draft.account_id).await?;

    let from = EmailAddress {
        address: account.email_address.clone(),
        display_name: Some(account.display_name.clone()),
    };

    let built = build_rfc5322(&draft, &from).map_err(|e| {
        qsl_ipc::IpcError::new(
            qsl_ipc::IpcErrorKind::Internal,
            format!("messages_send: build RFC 5322: {e}"),
        )
    })?;

    let payload = serde_json::json!({
        "message_id": built.message_id,
        "raw_b64": base64_engine.encode(&built.bytes),
    });

    outbox_repo::enqueue(
        &*db,
        &draft.account_id,
        qsl_sync::outbox_drain::OP_SUBMIT_MESSAGE,
        &payload.to_string(),
    )
    .await?;
    drafts_repo::delete(&*db, &draft_id).await?;

    // Contacts collection: every recipient address the user just
    // sent to seeds the autocomplete dropdown (PR-C2). We touch the
    // contact rows here, before dropping the db guard, so a single
    // send is atomic against an interleaved query_prefix call. As
    // with the inbound side, upsert failures are warn-logged and
    // don't block the send — the message is already in the outbox
    // and will go out regardless of whether contacts were updated.
    let now = chrono::Utc::now().timestamp();
    for addr in draft
        .to
        .iter()
        .chain(draft.cc.iter())
        .chain(draft.bcc.iter())
    {
        if let Err(e) = qsl_storage::repos::contacts::upsert_seen(
            &*db,
            &addr.address,
            addr.display_name.as_deref(),
            qsl_storage::repos::contacts::Source::Outbound,
            now,
        )
        .await
        {
            tracing::warn!(
                draft = %draft_id.0,
                address = %addr.address,
                "messages_send: contact upsert failed: {e}"
            );
        }
    }

    drop(db);

    tracing::info!(
        draft = %draft_id.0,
        account = %draft.account_id.0,
        message_id = %built.message_id,
        "messages_send: enqueued submit_message"
    );

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct MessagesLoadOlderInput {
    pub folder: FolderId,
    pub limit: u32,
}

/// `messages_load_older` — pager backfill for the message-list pane.
///
/// Asks the account's [`MailBackend`] for headers strictly older than
/// the lowest currently-synced message in `folder`, persists the
/// returned rows (running the standard threading pass on each insert),
/// and returns the count added.
///
/// IMAP backends compute the anchor from the lowest local UID and
/// run a UID FETCH inverted-range request; JMAP and other backends
/// without an override get the trait's default empty implementation
/// for now (Phase 2 follow-up wires up `Email/query` paging).
///
/// Returns `0` when the historical tail is exhausted, when the
/// folder is empty (so the bootstrap sync is the right tool, not
/// the pager), or when the backend can't paginate older.
#[tauri::command]
pub async fn messages_load_older(
    state: State<'_, AppState>,
    input: MessagesLoadOlderInput,
) -> IpcResult<u32> {
    let MessagesLoadOlderInput { folder, limit } = input;
    let limit = limit.clamp(1, MAX_PAGE_LIMIT);

    // Resolve the account id from the folder row so we can open the
    // right backend. `list_by_folder` with a generous cap pulls every
    // header so we can derive the IMAP UID floor below.
    let (account_id, anchor) = {
        let db = state.db.lock().await;
        let folder_row = folders_repo::get(&*db, &folder).await?;
        let local = messages_repo::list_by_folder(&*db, &folder, MAX_PAGE_LIMIT, 0).await?;
        let anchor = lowest_imap_uid(&local);
        (folder_row.account_id, anchor)
    };

    let Some(anchor) = anchor else {
        tracing::debug!(folder = %folder.0, "messages_load_older: empty folder, nothing to page");
        return Ok(0);
    };

    let backend = backend_factory::get_or_open(&state, &account_id).await?;

    let older = backend.fetch_older_headers(&folder, anchor, limit).await?;

    if older.is_empty() {
        tracing::debug!(
            folder = %folder.0,
            anchor,
            "messages_load_older: backend returned no older messages"
        );
        return Ok(0);
    }

    let mut added = 0u32;
    let db = state.db.lock().await;
    for h in &older {
        match messages_repo::find(&*db, &h.id).await? {
            Some(_) => {
                // Already in DB — skip insert; the bootstrap or live
                // sync got there first. Don't count toward `added`.
                continue;
            }
            None => {
                messages_repo::insert(&*db, h, None).await?;
                if let Err(e) = qsl_sync::threading::attach_to_thread(&*db, h).await {
                    tracing::warn!(message = %h.id.0, "thread assembly failed: {e}");
                }
                added += 1;
            }
        }
    }
    drop(db);

    tracing::info!(
        folder = %folder.0,
        anchor,
        returned = older.len(),
        inserted = added,
        "messages_load_older"
    );
    Ok(added)
}

/// Walk a slice of locally-cached headers, decode each id with the
/// IMAP `MessageRef` codec, and return the smallest UID. JMAP-shaped
/// ids fail the decode and are silently skipped — for those backends
/// the pager isn't usable until `Email/query` paging lands.
///
/// Returns `None` when the slice is empty or no id parses as IMAP.
fn lowest_imap_uid(messages: &[MessageHeaders]) -> Option<u64> {
    messages
        .iter()
        .filter_map(|m| qsl_imap_client::MessageRef::decode(&m.id).ok())
        .map(|r| u64::from(r.uid))
        .min()
}

#[derive(Debug, Deserialize)]
pub struct MessagesRefreshFolderInput {
    pub folder: FolderId,
}

/// `messages_refresh_folder` — kick a one-shot sync of one folder.
///
/// Triggered by the UI when the user opens a folder. The reactive
/// `sync_engine` already pushes new mail via IMAP IDLE for the top 10
/// IMAP folders per account (and a 2-min poll for the rest), and JMAP
/// push covers every folder on a JMAP account in real time. For those
/// folders this command is a no-op — re-running SELECT + UID SEARCH
/// + reconcile on every click added 1-2 s of UI-thread blocking with
/// no freshness gain (the watcher delivers the same updates).
///
/// For folders that aren't watched (the IMAP poll-only tail), the
/// sync work is spawned onto a background task and the IPC returns
/// immediately so the UI thread is never blocked. `sync_one_folder`
/// emits its own `sync_event` when it lands; the UI's reactive
/// resources refetch when the event arrives.
#[tauri::command]
pub async fn messages_refresh_folder(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    input: MessagesRefreshFolderInput,
) -> IpcResult<()> {
    let folder_id = input.folder;
    if state.watched_folders.lock().await.contains(&folder_id) {
        tracing::debug!(
            folder = %folder_id.0,
            "messages_refresh_folder: skipped (folder is push-watched)"
        );
        return Ok(());
    }
    let folder = {
        let db = state.db.lock().await;
        folders_repo::get(&*db, &folder_id).await?
    };
    let blobs = BlobStore::new(state.data_dir.join("blobs"));
    let account_id = folder.account_id.clone();
    let app_for_task = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::sync_engine::sync_one_folder(&app_for_task, &blobs, &account_id, &folder).await;
    });
    tracing::info!(folder = %folder_id.0, "messages_refresh_folder: scheduled");
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct MessagesOpenInWindowInput {
    pub id: MessageId,
}

/// `messages_open_in_window` — pop a new Tauri window that mounts the
/// reader-only Dioxus route for the supplied message id.
///
/// The popup's window label is `reader-<sanitized_id>`; the message
/// id is injected into the popup's JS context as
/// `window.__QSL_READER_ID__` via `initialization_script`. The
/// Dioxus root component reads that global at boot and mounts the
/// `ReaderOnlyApp` instead of the three-pane shell.
///
/// We pre-fetch the rendered message and inline its JSON as
/// `window.__QSL_READER_PRELOAD__` so the popup's reader-only
/// component can mount instantly without a follow-up `messages_get`
/// round-trip.
///
/// Calling this for an already-open popup focuses the existing
/// window instead of spawning a duplicate.
#[tauri::command]
pub async fn messages_open_in_window<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    input: MessagesOpenInWindowInput,
) -> IpcResult<()> {
    use tauri::Manager;

    let t_start = std::time::Instant::now();

    // Tauri labels accept only `[a-zA-Z0-9_-]` per the docs. IMAP ids
    // contain `|` and `:`; map any other char to `_` for the label.
    let safe_id: String = input
        .id
        .0
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let label = format!("reader-{safe_id}");

    if let Some(existing) = app.get_webview_window(&label) {
        if let Err(e) = existing.set_focus() {
            tracing::warn!(window = %label, error = %e, "messages_open_in_window: set_focus failed");
        }
        return Ok(());
    }

    // Pre-fetch the message before opening the popup so the Dioxus
    // bundle inside the popup can mount with the body already in
    // hand. Without this, the popup boots, runs `use_resource` to
    // call `messages_get`, waits for the round-trip, and only then
    // composes HTML — adding ~hundreds of ms of perceived latency
    // on top of the wasm boot. We embed the JSON serialization of
    // `RenderedMessage` as `window.__QSL_READER_PRELOAD__` and the
    // popup's reader-only app uses it directly. A fetch failure is
    // logged but doesn't abort the open: the popup falls back to
    // calling `messages_get` itself when `__QSL_READER_PRELOAD__`
    // is `null`.
    let state_for_render: tauri::State<AppState> = app.state();
    let t_preload_start = std::time::Instant::now();
    // Backlog #11 — peek the single-entry render cache. If the user
    // double-clicks a message that's currently selected in the main
    // pane, `messages_get` already populated this slot; reusing the
    // hit skips the body lazy-fetch (~50 ms warm cache, ~500 ms cold)
    // plus the ammonia sanitize pass.
    let cached_rendered: Option<RenderedMessage> = {
        let guard = state_for_render.last_rendered.lock().await;
        guard
            .as_ref()
            .filter(|(id, _)| id == &input.id)
            .map(|(_, r)| r.clone())
    };
    let rendered_opt: Option<RenderedMessage> = if let Some(r) = cached_rendered {
        tracing::info!(
            id = %input.id.0,
            "messages_open_in_window: served preload from last_rendered cache"
        );
        Some(r)
    } else {
        match messages_get(
            state,
            MessagesGetInput {
                id: input.id.clone(),
                force_trusted: false,
            },
        )
        .await
        {
            Ok(rendered) => Some(rendered),
            Err(e) => {
                tracing::warn!(error = %e, "messages_open_in_window: preload fetch failed");
                None
            }
        }
    };
    let preload_json: String = rendered_opt
        .as_ref()
        .map(|r| {
            serde_json::to_string(r).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "messages_open_in_window: serialize preload failed");
                "null".to_string()
            })
        })
        .unwrap_or_else(|| "null".to_string());
    tracing::info!(
        ms = t_preload_start.elapsed().as_millis() as u64,
        bytes = preload_json.len(),
        "messages_open_in_window: preload fetched"
    );

    // initialization_script runs once in the new webview before the
    // wasm bundle boots. Setting `__QSL_READER_ID__` and
    // `__QSL_READER_PRELOAD__` here lets the Dioxus root component
    // branch on the id and skip a follow-up IPC round-trip when the
    // preload is present.
    let init_script = format!(
        "window.__QSL_READER_ID__ = {};\nwindow.__QSL_READER_PRELOAD__ = {};",
        serde_json::to_string(&input.id.0).expect("serializing message id"),
        preload_json,
    );

    let title = format!("QSL — {}", input.id.0);
    let t_window_start = std::time::Instant::now();
    let _window =
        tauri::WebviewWindowBuilder::new(&app, &label, tauri::WebviewUrl::App("index.html".into()))
            .title(title)
            .inner_size(720.0, 800.0)
            .initialization_script(&init_script)
            // Child windows need an explicit opt-in or right-click →
            // Inspect / Ctrl+Shift+I are silently disabled. Debug
            // builds only — release builds ship without the inspector.
            .devtools(cfg!(debug_assertions))
            .build()
            .map_err(|e| {
                qsl_ipc::IpcError::new(
                    qsl_ipc::IpcErrorKind::Internal,
                    format!("create reader window: {e}"),
                )
            })?;
    tracing::info!(
        ms = t_window_start.elapsed().as_millis() as u64,
        "messages_open_in_window: WebviewWindow built"
    );

    tracing::info!(
        window = %label,
        id = %input.id.0,
        total_ms = t_start.elapsed().as_millis() as u64,
        "messages_open_in_window"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsl_core::{AccountId, Folder};

    fn folder(id: &str, role: Option<FolderRole>) -> Folder {
        Folder {
            id: FolderId(id.into()),
            account_id: AccountId("acct".into()),
            name: id.rsplit('/').next().unwrap_or(id).into(),
            path: id.into(),
            role,
            unread_count: 0,
            total_count: 0,
            parent: None,
        }
    }

    #[test]
    fn attachment_filename_sanitizer_neutralizes_spoofing_and_reserved_names() {
        // Bidi override that renders `invoice\u{202E}fdp.exe` as
        // "invoiceexe.pdf" in a UI.
        assert_eq!(
            sanitize_attachment_filename("invoice\u{202E}fdp.exe"),
            "invoice_fdp.exe"
        );
        assert_eq!(
            sanitize_attachment_filename("../../etc/passwd"),
            "_.._etc_passwd"
        );
        assert_eq!(
            sanitize_attachment_filename("a<b>c|d?e*f\"g.txt"),
            "a_b_c_d_e_f_g.txt"
        );
        assert_eq!(sanitize_attachment_filename("CON"), "_CON");
        assert_eq!(sanitize_attachment_filename("com1.txt"), "_com1.txt");
        assert_eq!(sanitize_attachment_filename("..."), "attachment.bin");
        assert_eq!(sanitize_attachment_filename("report.pdf"), "report.pdf");
    }

    #[test]
    fn launch_unsafe_types_are_recognized() {
        for f in [
            "invoice.pdf.exe",
            "setup.MSI",
            "run.sh",
            "link.lnk",
            "page.html",
            "image.svg",
            "script.ps1",
            "app.desktop",
        ] {
            assert!(is_unsafe_to_launch(f), "{f} should not auto-launch");
        }
        for f in [
            "report.pdf",
            "photo.JPG",
            "sheet.xlsx",
            "notes.txt",
            "archive.zip",
            "noext",
        ] {
            assert!(!is_unsafe_to_launch(f), "{f} should open normally");
        }
    }

    #[test]
    fn resolve_archive_target_prefers_archive_role() {
        let folders = vec![
            folder("INBOX", Some(FolderRole::Inbox)),
            folder("Archive", Some(FolderRole::Archive)),
            folder("[Gmail]/All Mail", Some(FolderRole::All)),
        ];
        assert_eq!(
            resolve_archive_target(&folders),
            Some(FolderId("Archive".into())),
        );
    }

    #[test]
    fn resolve_archive_target_falls_back_to_all() {
        let folders = vec![
            folder("INBOX", Some(FolderRole::Inbox)),
            folder("[Gmail]/All Mail", Some(FolderRole::All)),
            folder("[Gmail]/Sent Mail", Some(FolderRole::Sent)),
        ];
        assert_eq!(
            resolve_archive_target(&folders),
            Some(FolderId("[Gmail]/All Mail".into())),
        );
    }

    #[test]
    fn resolve_archive_target_returns_none_without_archive_or_all() {
        let folders = vec![
            folder("INBOX", Some(FolderRole::Inbox)),
            folder("Trash", Some(FolderRole::Trash)),
        ];
        assert_eq!(resolve_archive_target(&folders), None);
    }

    #[test]
    fn sanitize_attachment_filename_strips_path_separators() {
        // Path traversal hardening: `/` → `_`, leading dots trimmed.
        // `../../etc/passwd` becomes `.._.._etc_passwd` after `/` →
        // `_`, then leading dot/whitespace trim drops the leading
        // double-dot for `_.._etc_passwd`.
        assert_eq!(
            sanitize_attachment_filename("../../etc/passwd"),
            "_.._etc_passwd"
        );
    }

    #[test]
    fn sanitize_attachment_filename_strips_backslash_and_colon() {
        assert_eq!(
            sanitize_attachment_filename(r"C:\Windows\evil.exe"),
            "C__Windows_evil.exe"
        );
    }

    #[test]
    fn sanitize_attachment_filename_strips_control_chars() {
        assert_eq!(sanitize_attachment_filename("foo\nbar\tbaz"), "foo_bar_baz");
    }

    #[test]
    fn sanitize_attachment_filename_falls_back_when_empty() {
        assert_eq!(sanitize_attachment_filename(""), "attachment.bin");
        assert_eq!(sanitize_attachment_filename("   .  "), "attachment.bin");
    }

    #[test]
    fn unique_path_returns_input_when_absent() {
        let dir = std::env::temp_dir().join(format!("qsl-uniq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = unique_path(&dir, "fresh.bin");
        assert_eq!(p, dir.join("fresh.bin"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unique_path_appends_counter_on_collision() {
        let dir = std::env::temp_dir().join(format!("qsl-uniq-coll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("doc.pdf"), b"x").unwrap();
        let p = unique_path(&dir, "doc.pdf");
        assert_eq!(p, dir.join("doc (1).pdf"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unique_path_handles_no_extension() {
        let dir = std::env::temp_dir().join(format!("qsl-uniq-noext-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("README"), b"x").unwrap();
        let p = unique_path(&dir, "README");
        assert_eq!(p, dir.join("README (1)"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
