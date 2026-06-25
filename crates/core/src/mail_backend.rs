// SPDX-License-Identifier: Apache-2.0

//! The `MailBackend` trait — the one seam the rest of the workspace sees
//! for any mail protocol adapter.
//!
//! Every read, write, and live-sync operation goes through this trait. The
//! IMAP and JMAP adapters each implement it; everything else depends on the
//! trait, not on either adapter.
//!
//! Trait shape is per `TRAITS.md`. Phase 0 Week 4 lands the read path
//! (`list_folders`, `list_messages`, `fetch_message`); the write-side
//! methods (`update_flags`, `move_messages`, `delete_messages`,
//! `save_draft`, `submit_message`) are part of the trait surface now but
//! their concrete implementations return `MailError::Other("not yet
//! implemented")` until Week 2 of Phase 1 lands the write path.

use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_core::stream::{BoxStream, Stream};

use crate::error::MailError;
use crate::ids::{AttachmentRef, FolderId, MessageId};
use crate::message::{MessageBody, MessageFlags, MessageHeaders};
use crate::sync_state::SyncState;
use crate::Folder;

/// The result of a `list_messages` call.
#[derive(Debug, Clone)]
pub struct MessageList {
    /// Full headers for messages newly appended in the folder since
    /// the last cursor (UID > cached UIDNEXT on IMAP, JMAP equivalent).
    pub messages: Vec<MessageHeaders>,
    /// Flag-only updates for already-known messages whose flags have
    /// changed since the last cursor. On IMAP this is populated by the
    /// CONDSTORE `UID FETCH ... (UID FLAGS) (CHANGEDSINCE <modseq>)`
    /// pass — it lets the sync engine apply incremental flag changes
    /// via `messages::update_flags` without a full header re-fetch.
    /// Empty on full fetches and on backends that don't surface
    /// per-message modseq deltas yet (JMAP currently).
    pub flag_updates: Vec<(MessageId, MessageFlags)>,
    /// The new sync cursor to persist. Hand it back on the next call.
    pub new_state: SyncState,
    /// IDs of messages the server says have disappeared since `since`.
    /// Empty when `since` was `None` (full fetch).
    pub removed: Vec<MessageId>,
}

/// One chunk of a `pull_history_chunk` response.
#[derive(Debug, Clone)]
pub struct HistoryChunk {
    /// Headers in this chunk, in no particular order.
    pub headers: Vec<MessageHeaders>,
    /// Anchor for the next chunk. Caller passes this back as the
    /// `before_anchor` argument on the next call. `0` (or any value
    /// `<= 1`) signals tail-exhausted; the driver loop exits.
    pub next_anchor: u64,
}

/// Real-time change notifications from a backend's live-sync stream.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BackendEvent {
    MessageAdded {
        folder: FolderId,
        id: MessageId,
    },
    MessageChanged {
        folder: FolderId,
        id: MessageId,
    },
    MessageRemoved {
        folder: FolderId,
        id: MessageId,
    },
    FolderChanged {
        folder: FolderId,
    },
    /// Account-wide change pushed by a backend that doesn't surface
    /// per-folder deltas (JMAP's EventSource is the textbook case —
    /// it tells you "Email has new state" without naming a mailbox).
    /// The sync engine reacts by running `sync_account` once per
    /// debounce window for the affected account.
    AccountChanged,
    ConnectionLost,
    ConnectionRestored,
}

/// The one protocol-agnostic mail abstraction.
///
/// Implementations live in `qsl-imap-client` and
/// `qsl-jmap-client`. The sync engine (`qsl-sync`) and the CLI
/// (`mailcli`) depend only on this trait.
#[async_trait]
pub trait MailBackend: Send + Sync {
    // ---------- Discovery ----------

    /// Return all folders / mailboxes for this account.
    async fn list_folders(&self) -> Result<Vec<Folder>, MailError>;

    // ---------- Read ----------

    /// Fetch message headers for a folder. When `since` is `Some`, return
    /// only the delta against that cursor plus the list of removed ids.
    /// When `since` is `None`, return every message the adapter can
    /// reasonably surface (bounded by `limit` if set).
    async fn list_messages(
        &self,
        folder: &FolderId,
        since: Option<&SyncState>,
        limit: Option<u32>,
    ) -> Result<MessageList, MailError>;

    /// Fetch a batch of headers strictly **older** than the
    /// caller's anchor cursor. Used by the desktop's "Load older
    /// messages" pager to walk back through the historical tail
    /// past the bounded initial-sync window.
    ///
    /// `before_anchor` is an opaque, backend-specific cursor:
    /// - IMAP: lowest UID currently synced for the folder. The
    ///   adapter does `UID FETCH <before-limit>:<before-1>` to get
    ///   the next slice.
    /// - JMAP: lowest `receivedAt` epoch-second of any synced
    ///   message; adapter passes through to `Email/query`'s
    ///   `before` filter.
    ///
    /// Returns up to `limit` headers. An empty `Ok(Vec::new())`
    /// means the historical tail is exhausted (or the backend
    /// can't paginate older). Default impl returns empty so any
    /// backend that doesn't override stays compilable.
    async fn fetch_older_headers(
        &self,
        _folder: &FolderId,
        _before_anchor: u64,
        _limit: u32,
    ) -> Result<Vec<MessageHeaders>, MailError> {
        Ok(Vec::new())
    }

    /// Pull one chunk of older history, returning the headers plus
    /// the anchor the caller should use on the next chunk. Powers
    /// the "Pull full mail history" backfill in `qsl_sync::history`.
    ///
    /// `before_anchor` is the lowest UID/key the caller currently
    /// has; the chunk should contain entries strictly older than
    /// that. `limit` caps the response size so the caller can throttle.
    ///
    /// Returns a [`HistoryChunk`] whose `next_anchor` is `<= 1` once
    /// the historical tail is exhausted. Setting `next_anchor = 0`
    /// signals "no more history available from this backend" and the
    /// driver loop will exit.
    ///
    /// Default impl reports tail-exhausted immediately so backends
    /// that haven't wired up history paging stay compilable; backends
    /// that paginate (IMAP today, JMAP `Email/query` later) override.
    async fn pull_history_chunk(
        &self,
        _folder: &FolderId,
        _before_anchor: u64,
        _limit: u32,
    ) -> Result<HistoryChunk, MailError> {
        Ok(HistoryChunk {
            headers: Vec::new(),
            next_anchor: 0,
        })
    }

    /// Enumerate every message id the server currently has in
    /// `folder`. Used by `qsl-sync` to reconcile server-side
    /// deletions: after the normal `list_messages` pass, the engine
    /// diffs this set against the local cache and removes anything
    /// the server no longer carries.
    ///
    /// Independent of the CONDSTORE/QRESYNC paths because Gmail
    /// doesn't advertise QRESYNC (so VANISHED responses aren't
    /// available there) and JMAP has no equivalent push-on-delete
    /// signal — a periodic enumeration is the only universally
    /// reliable route.
    ///
    /// Default impl returns an empty vec so backends that haven't
    /// wired this up yet stay compilable; the sync engine treats
    /// "empty live set + non-empty local set" as a backend-incapable
    /// signal and skips the prune step.
    async fn list_known_ids(&self, _folder: &FolderId) -> Result<Vec<MessageId>, MailError> {
        Ok(Vec::new())
    }

    /// Fetch the full body of a single message.
    async fn fetch_message(&self, id: &MessageId) -> Result<MessageBody, MailError>;

    /// Fetch the **raw** RFC 822 bytes for a single message.
    ///
    /// `qsl-sync`'s body-fetching pass calls this and writes the
    /// returned bytes straight to the `BlobStore`; `messages_get`
    /// re-parses the bytes off disk via `qsl_mime::parse_rfc822`.
    /// Returning `Vec<u8>` rather than `MessageBody` avoids a parse +
    /// re-serialize roundtrip and keeps `BlobStore` the single source
    /// of truth for the bytes that get rendered.
    ///
    /// Default implementation errors out — backends that haven't
    /// wired up byte-level access yet still satisfy the trait, and
    /// the sync engine logs + skips messages whose backend can't
    /// supply raw bytes.
    async fn fetch_raw_message(&self, _id: &MessageId) -> Result<Vec<u8>, MailError> {
        Err(MailError::Other(
            "fetch_raw_message is not implemented for this backend".into(),
        ))
    }

    /// Fetch the bytes of a single attachment.
    async fn fetch_attachment(
        &self,
        message: &MessageId,
        attachment: &AttachmentRef,
    ) -> Result<Vec<u8>, MailError>;

    // ---------- Write (Phase 1) ----------

    async fn update_flags(
        &self,
        messages: &[MessageId],
        add: MessageFlags,
        remove: MessageFlags,
    ) -> Result<(), MailError>;

    async fn move_messages(
        &self,
        messages: &[MessageId],
        target: &FolderId,
    ) -> Result<(), MailError>;

    async fn delete_messages(&self, messages: &[MessageId]) -> Result<(), MailError>;

    // ---------- Compose / Send (Phase 2) ----------

    /// Append a draft to the account's Drafts mailbox. When `replace`
    /// is `Some`, the backend MUST delete (IMAP `\Deleted` + EXPUNGE)
    /// or destroy (JMAP `Email/set { destroy }`) the prior server-side
    /// copy *after* the new one lands. Post-write order matters: a
    /// transient failure between APPEND and DELETE leaves the user
    /// with a duplicate, never zero copies.
    ///
    /// Returns the canonical id of the newly-saved server-side draft.
    /// `qsl-sync`'s outbox drain stores it via
    /// `qsl_storage::repos::drafts::set_server_id` and feeds it back
    /// as `replace` on the next save so the server's Drafts mailbox
    /// converges to one row per local draft instead of accumulating
    /// every intermediate version.
    async fn save_draft(
        &self,
        raw_rfc822: &[u8],
        replace: Option<&MessageId>,
    ) -> Result<MessageId, MailError>;

    async fn submit_message(&self, raw_rfc822: &[u8]) -> Result<Option<MessageId>, MailError>;

    // ---------- Live sync (Phase 1) ----------

    /// Refresh the in-memory folder state cursor (uidnext, highestmodseq)
    /// without fetching any messages. Called by `qsl-sync` after a
    /// reconciliation pass that pruned local messages, so the persisted
    /// sync cursor reflects any server-state changes that happened between
    /// the `list_messages` SELECT and the `list_known_ids` round-trip.
    ///
    /// Default implementation is a no-op. Backends whose cursor can become
    /// stale during a sync cycle (IMAP, which does a separate SELECT inside
    /// `list_known_ids`) should override with a lightweight SELECT-only
    /// round-trip and encode the result into the returned string.
    async fn refresh_folder_state(&self, _folder: &FolderId) -> Result<Option<String>, MailError> {
        Ok(None)
    }

    /// Subscribe to real-time changes. Stream yields until the handle is
    /// dropped. Default implementation returns an empty stream — adapters
    /// override when they support a push mechanism (IDLE for IMAP,
    /// EventSource for JMAP).
    fn watch(&self) -> BoxStream<'static, BackendEvent> {
        Box::pin(EmptyStream)
    }
}

/// Trivial empty stream — kept local to this module so `qsl-core`
/// doesn't pull in `futures-util` just for one utility constructor.
struct EmptyStream;

impl Stream for EmptyStream {
    type Item = BackendEvent;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}
