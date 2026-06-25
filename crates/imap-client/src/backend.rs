// SPDX-License-Identifier: Apache-2.0

//! [`ImapBackend`] — the concrete [`MailBackend`] implementation.
//!
//! The session is held behind a tokio `Mutex` because IMAP is a
//! stateful, serialized protocol: there's exactly one in-flight command
//! at a time per connection. Every [`MailBackend`] method locks the
//! mutex, runs its command sequence, unlocks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_imap::types::Fetch;
use async_imap::{Client, Session};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, MutexGuard};
use tokio_rustls::client::TlsStream;
use tracing::{debug, info, warn};

/// Connection-freshness window. If no command has run on the cached
/// session for this long, the next acquire issues a `NOOP` first to
/// confirm the socket is still alive. On NOOP failure the backend
/// transparently reconnects in place via `dial_session` using the
/// stored credentials.
///
/// 5 minutes is well under typical NAT idle-eviction (15-30 min on
/// most home routers) and well over the cost of a NOOP round-trip
/// (~50 ms) so the heartbeat doesn't add visible latency to active
/// use. After laptop sleep / Wi-Fi flap / VPN reconnect, the next
/// command pays one NOOP probe and either continues on the same
/// socket or reconnects without surfacing a mid-session error.
const STALE_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Default IMAPS port, captured on the backend so the self-heal
/// reconnect can reach the same endpoint without rethreading it
/// through every call site.
const IMAPS_PORT: u16 = 993;

use qsl_core::{
    AccountId, AttachmentRef, BackendKind, EmailAddress, Folder, FolderId, FolderRole, MailBackend,
    MailError, MessageBody, MessageFlags, MessageHeaders, MessageId, MessageList, SyncState,
    ThreadId,
};

use crate::auth::XOAuth2;
use crate::capabilities::require as require_caps;
use crate::sync_state::{BackendState, MessageRef};

/// TLS-wrapped TCP stream that backs every IMAP session this crate
/// produces. Exposed so sibling modules (notably `idle`) can take a
/// `Session<StreamT>` directly without constructing an `ImapBackend`.
pub type StreamT = TlsStream<TcpStream>;

/// Production-grade IMAP backend: TLS, XOAUTH2, CONDSTORE + QRESYNC +
/// IDLE required at connect.
pub struct ImapBackend {
    session: Mutex<Session<StreamT>>,
    /// Last successful command boundary. Read by `lock_session_alive`
    /// to decide whether to issue a `NOOP` heartbeat before handing
    /// the session out, written after every successful acquire.
    /// Separate mutex from `session` so the activity update is brief
    /// and doesn't extend the session-lock window — both locks are
    /// taken in the same order (`session` first) at every call site,
    /// so there's no deadlock risk.
    last_activity: Mutex<Instant>,
    account: AccountId,
    host: Arc<str>,
    /// True when the server advertised `X-GM-EXT-1`, Gmail's extension
    /// family. Toggles the FETCH query on `list_messages` to include
    /// `X-GM-LABELS` so per-message Gmail labels round-trip into
    /// `MessageHeaders.labels`.
    gmail_ext: bool,
    /// True when the server supports `$Forwarded` keywords. Determined
    /// during `dial_session` based on Gmail extension or KEYWORD
    /// capability. When false, `render_imap_flags` skips the flag.
    supports_forwarded: bool,
    /// Account email — needed at SMTP submission time for the SASL
    /// `authentication-identity` and the envelope `MAIL FROM:`.
    /// Stored on the backend so the [`MailBackend::submit_message`]
    /// impl can reach it without a fresh round-trip through the
    /// account repo.
    email: Arc<str>,
    /// OAuth2 access token captured at connect time. SMTP uses the
    /// same XOAUTH2 stack as IMAP, so the same token works for the
    /// submission burst as long as it hasn't expired in the interim.
    /// If lettre returns an auth error, the outbox drain will retry
    /// against a freshly-built backend whose token has just been
    /// refreshed. Also reused by `lock_session_alive` when it
    /// needs to reconnect a NOOP-failed socket — if the token is
    /// stale at that point, the reconnect's XOAUTH2 returns
    /// `MailError::Auth` which the caller's `with_auth_retry`
    /// wrapper handles by evicting the cached backend.
    access_token: Arc<str>,
}

impl ImapBackend {
    /// Wrap an already-authenticated [`Session`]. Used by tests that
    /// supply a pre-scripted stream; the production `connect_tls`
    /// constructor is the normal entry point.
    ///
    /// `email` and `access_token` are the SASL identity + bearer used
    /// at the IMAP login that produced this session — passed through
    /// so the SMTP submission path can reuse them. Tests that don't
    /// exercise submission can pass empty strings.
    pub(crate) fn from_session(
        session: Session<StreamT>,
        account: AccountId,
        host: impl Into<Arc<str>>,
        gmail_ext: bool,
        supports_forwarded: bool,
        email: impl Into<Arc<str>>,
        access_token: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            session: Mutex::new(session),
            last_activity: Mutex::new(Instant::now()),
            account,
            host: host.into(),
            gmail_ext,
            supports_forwarded,
            email: email.into(),
            access_token: access_token.into(),
        }
    }

    /// Acquire the session, running a `NOOP` heartbeat first if the
    /// last successful command was more than [`STALE_THRESHOLD`] ago.
    /// If NOOP fails, transparently reconnects in place via
    /// `dial_session` using the stored credentials. Updates
    /// `last_activity` and returns the locked guard.
    ///
    /// All MailBackend method bodies acquire the session through
    /// this helper so the heartbeat is uniform — a single
    /// `self.session.lock().await` somewhere would skip the probe
    /// and resurrect the post-sleep wedge.
    async fn lock_session_alive(&self) -> Result<MutexGuard<'_, Session<StreamT>>, MailError> {
        let stale = {
            let activity = self.last_activity.lock().await;
            activity.elapsed() >= STALE_THRESHOLD
        };
        let mut guard = self.session.lock().await;
        if stale {
            match guard.noop().await {
                Ok(()) => {
                    debug!(host = %self.host, "NOOP heartbeat ok");
                }
                Err(e) => {
                    info!(host = %self.host, "NOOP heartbeat failed ({e}); reconnecting in place");
                    let DialedSession {
                        session: fresh,
                        gmail_ext: _,
                        supports_forwarded: _,
                    } = dial_session(&self.host, IMAPS_PORT, &self.email, &self.access_token)
                        .await?;
                    *guard = fresh;
                    *self.last_activity.lock().await = Instant::now();
                }
            }
        }
        Ok(guard)
    }

    /// Shared FETCH path for `fetch_older_headers` and
    /// `pull_history_chunk`. Same UID-range query, same response
    /// translation; the only knob is `with_thread_headers`.
    ///
    /// `with_thread_headers = true` keeps `BODY.PEEK[HEADER]` in the
    /// FETCH so `In-Reply-To` and `References` round-trip — needed by
    /// any caller that will run threading on the result. The "load
    /// older" pager wants this. `with_thread_headers = false` drops
    /// it: the server stops streaming the raw header block (~1-4 KB
    /// per message on Gmail), which is the dominant wire cost on a
    /// 500-message chunk against a deep folder. The history-pull
    /// driver passes `false` because `qsl-sync::history` deliberately
    /// skips per-message threading (`history.rs::persist_chunk` doc).
    /// Threading rebuilds out-of-band when the user hits a chunk
    /// during normal browsing.
    async fn fetch_uid_range_headers(
        &self,
        folder: &FolderId,
        before_anchor: u64,
        limit: u32,
        with_thread_headers: bool,
    ) -> Result<Vec<MessageHeaders>, MailError> {
        if before_anchor <= 1 || limit == 0 {
            return Ok(Vec::new());
        }
        let before = u32::try_from(before_anchor).map_err(|_| {
            MailError::Protocol(format!(
                "before_anchor {before_anchor} exceeds IMAP UID range"
            ))
        })?;

        let mut session = self.lock_session_alive().await?;

        let mbox = session
            .select(&folder.0)
            .await
            .map_err(|e| MailError::Protocol(format!("SELECT {}: {e}", folder.0)))?;
        let uidvalidity = mbox
            .uid_validity
            .ok_or_else(|| MailError::Protocol("SELECT missing UIDVALIDITY".into()))?;

        let high = before.saturating_sub(1);
        let low = before.saturating_sub(limit).max(1);
        // IMAP UID FETCH accepts inverted ranges; the server returns
        // whatever exists in the range (deleted UIDs are absent from
        // the response).
        let uid_set = format!("{low}:{high}");
        let query = match (with_thread_headers, self.gmail_ext) {
            (true, true) => {
                "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODY.PEEK[HEADER] X-GM-LABELS)"
            }
            (true, false) => "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODY.PEEK[HEADER])",
            (false, true) => "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE X-GM-LABELS)",
            (false, false) => "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE)",
        };
        let fetch_start = std::time::Instant::now();
        let mut fetches = session
            .uid_fetch(&uid_set, query)
            .await
            .map_err(|e| MailError::Protocol(format!("UID FETCH {uid_set} {query}: {e}")))?;

        let mut messages = Vec::new();
        while let Some(item) = fetches.next().await {
            let fetch = item.map_err(|e| MailError::Protocol(format!("FETCH entry: {e}")))?;
            match fetch_to_headers(&fetch, folder, uidvalidity, &self.account) {
                Ok(Some(h)) => messages.push(h),
                Ok(None) => {
                    debug!(message = ?fetch.message, "older FETCH missing UID — skipping");
                }
                Err(e) => {
                    warn!(error = %e, message = ?fetch.message, "older FETCH translate failed");
                }
            }
        }
        let elapsed_ms = fetch_start.elapsed().as_millis() as u64;
        if elapsed_ms >= qsl_telemetry::slow::limits::IMAP_CMD_MS {
            warn!(
                target: "qsl::slow::imap",
                op = "uid_fetch_headers",
                folder = %folder.0,
                range = %uid_set,
                count = messages.len(),
                with_thread_headers,
                elapsed_ms,
                limit_ms = qsl_telemetry::slow::limits::IMAP_CMD_MS,
                "slow UID FETCH headers"
            );
        } else {
            debug!(
                folder = %folder.0,
                range = %uid_set,
                count = messages.len(),
                with_thread_headers,
                elapsed_ms,
                "IMAP fetch_uid_range_headers"
            );
        }
        *self.last_activity.lock().await = Instant::now();
        Ok(messages)
    }

    /// Connect to `host:port` over TLS, authenticate via SASL XOAUTH2
    /// with the supplied `access_token`, verify required capabilities,
    /// and return a ready-to-use backend.
    pub async fn connect_tls(
        host: &str,
        port: u16,
        email: &str,
        access_token: &str,
        account: AccountId,
    ) -> Result<Self, MailError> {
        let DialedSession {
            session,
            gmail_ext,
            supports_forwarded,
        } = qsl_telemetry::time_op!(
            target: "qsl::slow::imap",
            limit_ms: qsl_telemetry::slow::limits::OAUTH_TOKEN_MS,
            op: "connect_tls",
            fields: { host = %host, port = port, email = %email },
            dial_session(host, port, email, access_token)
        )?;
        info!(
            host,
            email, gmail_ext, supports_forwarded, "IMAP connected and authenticated"
        );
        Ok(Self::from_session(
            session,
            account,
            host,
            gmail_ext,
            supports_forwarded,
            email,
            access_token,
        ))
    }

    /// The host this backend connected to — exposed for logs/diagnostics.
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Result of [`dial_session`] — the authenticated session plus the
/// capability flags the caller may want to vary behavior on. The
/// IDLE watcher discards the flags; `ImapBackend::connect_tls`
/// stashes `gmail_ext` so `list_messages` can request `X-GM-LABELS`.
pub struct DialedSession {
    pub session: Session<StreamT>,
    pub gmail_ext: bool,
    /// True when the server supports `$Forwarded` (RFC 5788 KEYWORD or
    /// Gmail extension). When false, `render_imap_flags` skips the
    /// flag to avoid a STORE failure on servers that reject unknown
    /// keywords.
    pub supports_forwarded: bool,
}

/// Open a fresh TLS+IMAP session against `host:port`, run XOAUTH2,
/// verify required capabilities, and return the bare
/// `async_imap::Session`. Both [`ImapBackend::connect_tls`] and the
/// [`crate::idle`] watcher call through this; exposing it keeps the
/// auth + CAPABILITY logic in one place rather than duplicating it
/// for the IDLE side connection.
pub async fn dial_session(
    host: &str,
    port: u16,
    email: &str,
    access_token: &str,
) -> Result<DialedSession, MailError> {
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| MailError::Network(format!("tcp connect {host}:{port}: {e}")))?;
    let tls = tls_connect(host, tcp).await?;

    let mut client = Client::new(tls);
    // Read the server greeting. async-imap requires this before any
    // commands run — without it the first command returns UNTAGGED.
    let _greeting = client
        .read_response()
        .await
        .map_err(|e| MailError::Protocol(format!("greeting: {e}")))?;

    let authenticator = XOAuth2::new(email, access_token);
    let mut session = client
        .authenticate("XOAUTH2", &authenticator)
        .await
        .map_err(|(e, _client)| MailError::Auth(format!("XOAUTH2: {e}")))?;

    // Force a CAPABILITY roundtrip; some servers only advertise the
    // post-auth set after login, not in the greeting.
    let caps = session
        .capabilities()
        .await
        .map_err(|e| MailError::Protocol(format!("CAPABILITY: {e}")))?;
    // `async_imap::types::Capability` is an enum (`Imap4rev1`,
    // `Auth(String)`, `Atom(String)`). Debug-formatting it yields
    // strings like `Atom("IDLE")` that never matched the uppercase
    // atom names the capabilities check expects, so pattern-match
    // explicitly here.
    let cap_strings: Vec<String> = caps
        .iter()
        .map(|c| match c {
            async_imap::types::Capability::Imap4rev1 => "IMAP4REV1".to_string(),
            async_imap::types::Capability::Auth(s) => format!("AUTH={s}"),
            async_imap::types::Capability::Atom(s) => s.clone(),
        })
        .collect();
    tracing::debug!(capabilities = ?cap_strings, "IMAP server capabilities");
    if let Err(e) = require_caps(&cap_strings) {
        tracing::warn!(
            advertised = ?cap_strings,
            "IMAP capability check failed: {e}"
        );
        return Err(e);
    }

    let gmail_ext = cap_strings
        .iter()
        .any(|c| c.eq_ignore_ascii_case("X-GM-EXT-1"));
    let supports_forwarded = gmail_ext
        || cap_strings
            .iter()
            .any(|c| c.eq_ignore_ascii_case("KEYWORD"));

    Ok(DialedSession {
        session,
        gmail_ext,
        supports_forwarded,
    })
}

async fn tls_connect(host: &str, tcp: TcpStream) -> Result<StreamT, MailError> {
    use tokio_rustls::rustls::{pki_types::ServerName, ClientConfig, RootCertStore};

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| MailError::Network(format!("invalid SNI hostname {host}: {e}")))?;

    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| MailError::Network(format!("TLS handshake with {host}: {e}")))
}

// ---------- MailBackend impl ----------

const NOT_YET: &str = "IMAP adapter read-path arrives in Phase 0 Week 4 part 2a (this PR); \
    concrete command machinery for list_folders / list_messages / fetch_message is the \
    next commit in this branch";

#[async_trait]
impl MailBackend for ImapBackend {
    async fn list_folders(&self) -> Result<Vec<Folder>, MailError> {
        let mut session = self.lock_session_alive().await?;
        let mut stream = session
            .list(None, Some("*"))
            .await
            .map_err(|e| MailError::Protocol(format!("LIST: {e}")))?;

        let mut folders = Vec::new();
        let mut skipped_noselect = 0usize;
        while let Some(item) = stream.next().await {
            let name = item.map_err(|e| MailError::Protocol(format!("LIST entry: {e}")))?;
            // RFC 3501 §7.2.2: a `\Noselect` mailbox can't be opened
            // — it's a hierarchy node only (Gmail's bare `[Gmail]` is
            // the textbook case). Including it would make `sync_account`
            // fail SELECT on every cycle.
            if name
                .attributes()
                .iter()
                .any(|a| matches!(a, async_imap::types::NameAttribute::NoSelect))
            {
                skipped_noselect += 1;
                continue;
            }
            folders.push(name_to_folder(&name, &self.account));
        }
        drop(stream);

        // Populate unread and total counts via STATUS. A per-folder
        // round-trip is acceptable — most accounts have <20 folders.
        for folder in &mut folders {
            match session.status(&folder.path, "(MESSAGES UNSEEN)").await {
                Ok(mbox) => {
                    folder.total_count = mbox.exists;
                    if let Some(unseen) = mbox.unseen {
                        folder.unread_count = unseen;
                    }
                }
                Err(e) => {
                    warn!(
                        folder = %folder.path,
                        "STATUS failed (counts will be stale): {e}"
                    );
                }
            }
        }

        debug!(
            count = folders.len(),
            skipped_noselect, "IMAP LIST returned folders"
        );
        *self.last_activity.lock().await = Instant::now();
        Ok(folders)
    }

    async fn refresh_folder_state(&self, folder: &FolderId) -> Result<Option<String>, MailError> {
        let mut session = self.lock_session_alive().await?;
        let mbox = session
            .select(&folder.0)
            .await
            .map_err(|e| MailError::Protocol(format!("SELECT {}: {e}", folder.0)))?;
        let uidvalidity = mbox
            .uid_validity
            .ok_or_else(|| MailError::Protocol("SELECT missing UIDVALIDITY".into()))?;
        let highestmodseq = mbox.highest_modseq.unwrap_or(0);
        let uidnext = mbox.uid_next.unwrap_or(1);
        *self.last_activity.lock().await = Instant::now();
        Ok(Some(
            BackendState {
                uidvalidity,
                highestmodseq,
                uidnext,
            }
            .encode(),
        ))
    }

    async fn list_messages(
        &self,
        folder: &FolderId,
        since: Option<&SyncState>,
        limit: Option<u32>,
    ) -> Result<MessageList, MailError> {
        let mut session = self.lock_session_alive().await?;

        let mbox = session
            .select(&folder.0)
            .await
            .map_err(|e| MailError::Protocol(format!("SELECT {}: {e}", folder.0)))?;
        let uidvalidity = mbox
            .uid_validity
            .ok_or_else(|| MailError::Protocol("SELECT missing UIDVALIDITY".into()))?;
        let uidnext = mbox.uid_next.unwrap_or(1);
        // CONDSTORE (RFC 7162) servers return HIGHESTMODSEQ in the
        // SELECT response code. Connection setup already required
        // CONDSTORE in `connect_tls`, so this should always be `Some`
        // against Gmail; default to 0 defensively so a server that
        // omits it just falls back to no-flag-delta mode.
        let highest_modseq = mbox.highest_modseq.unwrap_or(0);

        // Build the new backend state from what SELECT told us. Any
        // call to list_messages ends with this persisted regardless of
        // how the fetch side goes.
        let new_state = BackendState {
            uidvalidity,
            highestmodseq: highest_modseq,
            uidnext,
        };

        // Decide the UID set to FETCH. If `since` is present *and*
        // UIDVALIDITY matches, we only need messages the server added
        // after the previous uidnext. Otherwise we do a bounded initial
        // sync.
        let uid_set = match since {
            Some(state) => {
                let cached = BackendState::from_sync(state)?;
                if cached.uidvalidity != uidvalidity {
                    warn!(
                        cached = cached.uidvalidity,
                        observed = uidvalidity,
                        "UIDVALIDITY changed; caller must refetch from scratch"
                    );
                    return Err(MailError::UidValidityChanged {
                        folder: folder.0.clone(),
                        cached: cached.uidvalidity,
                        observed: uidvalidity,
                    });
                }
                // New messages have UID >= cached.uidnext.
                format!("{}:*", cached.uidnext)
            }
            None => match limit {
                // A bare `1:*` would pull the whole folder. For initial
                // sync we lean on the limit if the caller supplied one.
                Some(n) if n > 0 => {
                    // Fetch the `n` highest UIDs — the most recent messages
                    // are usually what the UI wants first.
                    let lo = uidnext.saturating_sub(n);
                    format!("{}:*", lo.max(1))
                }
                _ => "1:*".to_string(),
            },
        };

        // Append `X-GM-LABELS` against Gmail (X-GM-EXT-1 advertised
        // at connect time). Sending it to a server that doesn't
        // support the extension would BAD the whole FETCH; the flag
        // is set in `dial_session` so we know it's safe here.
        //
        // `BODY.PEEK[HEADER]` pulls the full RFC 5322 header block so
        // `fetch_to_headers` can parse `References` (which IMAP's
        // structured ENVELOPE doesn't surface — it carries
        // `In-Reply-To` only). The bytes are typically <4 KB per
        // message, well under the cost of a second fetch round-trip.
        // `.PEEK[…]` form means the FETCH does NOT mark the message
        // `\Seen` — important so sync doesn't flip read state by
        // looking.
        let query = if self.gmail_ext {
            "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODY.PEEK[HEADER] X-GM-LABELS)"
        } else {
            "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODY.PEEK[HEADER])"
        };
        let mut fetches = session
            .uid_fetch(&uid_set, query)
            .await
            .map_err(|e| MailError::Protocol(format!("UID FETCH {uid_set} {query}: {e}")))?;

        let mut messages = Vec::new();
        while let Some(item) = fetches.next().await {
            let fetch = item.map_err(|e| MailError::Protocol(format!("FETCH entry: {e}")))?;
            match fetch_to_headers(&fetch, folder, uidvalidity, &self.account) {
                Ok(Some(h)) => messages.push(h),
                Ok(None) => {
                    debug!(message = ?fetch.message, "FETCH response missing UID — skipping");
                }
                Err(e) => {
                    warn!(error = %e, message = ?fetch.message, "failed to translate FETCH");
                }
            }
        }
        drop(fetches);

        // CONDSTORE flag-delta pass — only when we have a usable
        // prior modseq AND there's at least one already-known UID
        // (uidnext > 1). Server returns the flag state for every
        // message whose modseq has advanced past `cached.highestmodseq`,
        // including ones the previous loop already returned because
        // their modseq advanced when they were appended; that's fine
        // — applying an update after an insert is a no-op since the
        // values match.
        let flag_updates = match since {
            Some(state) => {
                let cached = BackendState::from_sync(state)?;
                if cached.highestmodseq > 0 && uidnext > 1 {
                    let upper = uidnext.saturating_sub(1);
                    fetch_flag_changes(
                        &mut session,
                        folder,
                        uidvalidity,
                        upper,
                        cached.highestmodseq,
                    )
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "CHANGEDSINCE flag-delta pass failed; skipping");
                        Vec::new()
                    })
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        };

        debug!(
            folder = %folder.0,
            count = messages.len(),
            flag_updates = flag_updates.len(),
            "IMAP list_messages"
        );

        *self.last_activity.lock().await = Instant::now();
        Ok(MessageList {
            messages,
            flag_updates,
            new_state: SyncState {
                folder_id: folder.clone(),
                backend_state: new_state.encode(),
            },
            // Server-side deletion detection runs out-of-band via
            // `MailBackend::list_known_ids` — `qsl-sync` calls it on
            // every cycle and diffs against the local cache. This is
            // backend-agnostic and works on Gmail (which doesn't
            // advertise QRESYNC) without a VANISHED parser. `removed`
            // stays empty here because nothing in this fetch path can
            // observe deletions.
            removed: Vec::new(),
        })
    }

    /// Pager: fetch headers for UIDs strictly below `before_anchor`,
    /// up to `limit` messages. Used by the desktop's "Load older"
    /// button to backfill messages past the bounded initial sync
    /// window.
    ///
    /// `before_anchor` is the lowest UID the caller currently has
    /// for this folder (cast through `u64` for trait neutrality;
    /// IMAP UIDs always fit in `u32`). When `before_anchor <= 1`
    /// the historical tail is already exhausted so we short-circuit
    /// without dialing the server.
    async fn fetch_older_headers(
        &self,
        folder: &FolderId,
        before_anchor: u64,
        limit: u32,
    ) -> Result<Vec<MessageHeaders>, MailError> {
        // "Load older" feeds straight into the visible message list,
        // which threads on `In-Reply-To` / `References`. Keep
        // BODY.PEEK[HEADER] in the query so threading attachment can
        // run inline. The history-pull path (`pull_history_chunk`)
        // takes the lighter route — see `fetch_uid_range_headers`.
        self.fetch_uid_range_headers(folder, before_anchor, limit, true)
            .await
    }

    async fn pull_history_chunk(
        &self,
        folder: &FolderId,
        before_anchor: u64,
        limit: u32,
    ) -> Result<qsl_core::HistoryChunk, MailError> {
        if before_anchor <= 1 || limit == 0 {
            return Ok(qsl_core::HistoryChunk {
                headers: Vec::new(),
                next_anchor: 0,
            });
        }
        // History-pull drops `BODY.PEEK[HEADER]` from the FETCH —
        // see `fetch_uid_range_headers`. Big wire-cost saving on
        // Gmail (each header block is ~1-4 KB and X-GM-LABELS
        // already covers what we surface). The history persist path
        // (`qsl-sync::history::persist_chunk`) skips threading
        // anyway, so In-Reply-To / References would have been
        // dropped on the floor.
        let headers = self
            .fetch_uid_range_headers(folder, before_anchor, limit, false)
            .await?;

        // Advance the anchor. Two cases:
        //
        // 1. Non-empty chunk: use the lowest UID it returned. That's
        //    the next call's `before` boundary, exclusive.
        //
        // 2. Empty chunk: we just walked through `limit` UIDs that
        //    are all EXPUNGEd (Gmail's INBOX is dense with these on
        //    accounts that archive aggressively — every message
        //    moved to All Mail leaves a hole). Naively moving the
        //    anchor down by `limit` makes the driver burn dozens of
        //    no-op chunks walking through dead space at ~200ms
        //    each. Do a single `UID SEARCH UID 1:<before-1>` to
        //    find the largest existing UID below the anchor and
        //    jump straight there. One round-trip beats 50.
        let next_anchor = if !headers.is_empty() {
            headers
                .iter()
                .filter_map(|h| MessageRef::decode(&h.id).ok())
                .map(|r| u64::from(r.uid))
                .min()
                .unwrap_or(0)
        } else {
            self.next_existing_uid_below(folder, before_anchor)
                .await
                .unwrap_or_else(|e| {
                    // Fall back to the conservative walk on search
                    // failure — slower, but correct.
                    warn!(
                        folder = %folder.0,
                        before = before_anchor,
                        "UID SEARCH skip-gap failed: {e}; falling back to slow walk"
                    );
                    let before = u32::try_from(before_anchor).unwrap_or(u32::MAX);
                    u64::from(before.saturating_sub(limit).max(1))
                })
        };
        Ok(qsl_core::HistoryChunk {
            headers,
            next_anchor,
        })
    }

    async fn list_known_ids(&self, folder: &FolderId) -> Result<Vec<MessageId>, MailError> {
        let mut session = self.lock_session_alive().await?;

        let mbox = session
            .select(&folder.0)
            .await
            .map_err(|e| MailError::Protocol(format!("SELECT {}: {e}", folder.0)))?;
        let uidvalidity = mbox
            .uid_validity
            .ok_or_else(|| MailError::Protocol("SELECT missing UIDVALIDITY".into()))?;

        // `UID SEARCH ALL` returns every UID currently in the folder.
        // Cheap relative to a full FETCH: a folder with 50K messages
        // is ~250 KB on the wire (UID-list responses are uncompressed
        // ASCII integers). We don't paginate; the reconciliation pass
        // is happy to walk one set at a time.
        let uids = session
            .uid_search("ALL")
            .await
            .map_err(|e| MailError::Protocol(format!("UID SEARCH ALL {}: {e}", folder.0)))?;

        debug!(
            folder = %folder.0,
            count = uids.len(),
            "IMAP list_known_ids"
        );
        *self.last_activity.lock().await = Instant::now();
        let result: Vec<MessageId> = uids
            .into_iter()
            .map(|uid| {
                MessageRef {
                    uidvalidity,
                    uid,
                    folder: folder.0.clone(),
                }
                .encode()
            })
            .collect();
        Ok(result)
    }

    async fn fetch_raw_message(&self, id: &MessageId) -> Result<Vec<u8>, MailError> {
        let r = MessageRef::decode(id)?;
        let mut session = self.lock_session_alive().await?;

        let mbox = session
            .select(&r.folder)
            .await
            .map_err(|e| MailError::Protocol(format!("SELECT {}: {e}", r.folder)))?;
        let current_uv = mbox
            .uid_validity
            .ok_or_else(|| MailError::Protocol("SELECT missing UIDVALIDITY".into()))?;
        if current_uv != r.uidvalidity {
            return Err(MailError::UidValidityChanged {
                folder: r.folder.clone(),
                cached: r.uidvalidity,
                observed: current_uv,
            });
        }

        let query = "(UID RFC822)";
        let mut fetches = session
            .uid_fetch(&r.uid.to_string(), query)
            .await
            .map_err(|e| MailError::Protocol(format!("UID FETCH {} {query}: {e}", r.uid)))?;

        let fetch = fetches
            .next()
            .await
            .ok_or(MailError::NotFound(format!(
                "message UID {} in {}",
                r.uid, r.folder
            )))?
            .map_err(|e| MailError::Protocol(format!("FETCH entry: {e}")))?;
        drop(fetches);

        *self.last_activity.lock().await = Instant::now();
        let raw = fetch
            .body()
            .ok_or_else(|| MailError::Protocol("FETCH returned no RFC822 body".into()))?
            .to_vec();
        Ok(raw)
    }

    async fn fetch_message(&self, id: &MessageId) -> Result<MessageBody, MailError> {
        // Implemented in terms of `fetch_raw_message` so the byte-level
        // path stays the single source of truth. Flags + labels aren't
        // populated here — callers that need them read from the
        // `messages` table, which the sync engine keeps current.
        let r = MessageRef::decode(id)?;
        let raw = self.fetch_raw_message(id).await?;
        let folder_id = FolderId(r.folder.clone());
        let flags = MessageFlags::default();
        let identity = qsl_mime::MessageIdentity {
            id,
            account_id: &self.account,
            folder_id: &folder_id,
            thread_id: None,
            size: raw.len() as u32,
            flags: &flags,
            labels: &[],
        };
        qsl_mime::parse_rfc822(&raw, identity)
            .ok_or_else(|| MailError::Parse(format!("mail-parser could not parse UID {}", r.uid)))
    }

    async fn fetch_attachment(
        &self,
        message: &MessageId,
        attachment: &AttachmentRef,
    ) -> Result<Vec<u8>, MailError> {
        let _ = (message, attachment);
        Err(MailError::Other(NOT_YET.into()))
    }

    async fn update_flags(
        &self,
        messages: &[MessageId],
        add: MessageFlags,
        remove: MessageFlags,
    ) -> Result<(), MailError> {
        if messages.is_empty() {
            return Ok(());
        }
        // Group ids by folder so each `STORE` runs against the right
        // mailbox. The MessageId encoding is `imap|<uv>|<uid>|<folder>`
        // so the folder is recoverable per id without consulting
        // storage.
        let mut by_folder: std::collections::HashMap<(String, u32), Vec<u32>> =
            std::collections::HashMap::new();
        for id in messages {
            let r = MessageRef::decode(id)?;
            by_folder
                .entry((r.folder, r.uidvalidity))
                .or_default()
                .push(r.uid);
        }

        let add_flags = render_imap_flags(&add, self.supports_forwarded);
        let rem_flags = render_imap_flags(&remove, self.supports_forwarded);
        if add_flags.is_empty() && rem_flags.is_empty() {
            return Ok(());
        }

        let mut session = self.lock_session_alive().await?;
        for ((folder, uidvalidity), uids) in by_folder {
            let mbox = session
                .select(&folder)
                .await
                .map_err(|e| MailError::Protocol(format!("SELECT {folder}: {e}")))?;
            let current_uv = mbox.uid_validity.ok_or_else(|| {
                MailError::Protocol(format!("SELECT {folder}: missing UIDVALIDITY"))
            })?;
            if current_uv != uidvalidity {
                return Err(MailError::UidValidityChanged {
                    folder: folder.clone(),
                    cached: uidvalidity,
                    observed: current_uv,
                });
            }
            // Chunk the UID set so a bulk action on thousands of
            // messages doesn't blow IMAP server command-line limits
            // (audit P1 #1). Each chunk emits its own STORE call.
            for uid_set in uid_chunks(&uids) {
                if !add_flags.is_empty() {
                    let q = format!("+FLAGS ({add_flags})");
                    let mut stream = session
                        .uid_store(&uid_set, &q)
                        .await
                        .map_err(|e| MailError::Protocol(format!("STORE {q}: {e}")))?;
                    while let Some(r) = stream.next().await {
                        r.map_err(|e| MailError::Protocol(format!("STORE response: {e}")))?;
                    }
                    drop(stream);
                }
                if !rem_flags.is_empty() {
                    let q = format!("-FLAGS ({rem_flags})");
                    let mut stream = session
                        .uid_store(&uid_set, &q)
                        .await
                        .map_err(|e| MailError::Protocol(format!("STORE {q}: {e}")))?;
                    while let Some(r) = stream.next().await {
                        r.map_err(|e| MailError::Protocol(format!("STORE response: {e}")))?;
                    }
                    drop(stream);
                }
            }
        }
        *self.last_activity.lock().await = Instant::now();
        Ok(())
    }

    async fn move_messages(
        &self,
        messages: &[MessageId],
        target: &FolderId,
    ) -> Result<(), MailError> {
        if messages.is_empty() {
            return Ok(());
        }
        // Group by source (folder, uidvalidity); each batch runs one
        // SELECT + one UID MOVE. Per RFC 6851 the server atomically
        // copies + expunges in one round-trip; async-imap exposes it
        // as `uid_mv`. Servers that don't advertise MOVE fall back
        // to `uid_copy` + `STORE +FLAGS (\Deleted)` + `UID EXPUNGE`,
        // which we implement explicitly because async-imap doesn't
        // do the fallback for us.
        let mut by_folder: std::collections::HashMap<(String, u32), Vec<u32>> =
            std::collections::HashMap::new();
        for id in messages {
            let r = MessageRef::decode(id)?;
            by_folder
                .entry((r.folder, r.uidvalidity))
                .or_default()
                .push(r.uid);
        }

        let mut session = self.lock_session_alive().await?;
        for ((folder, uidvalidity), uids) in by_folder {
            let mbox = session
                .select(&folder)
                .await
                .map_err(|e| MailError::Protocol(format!("SELECT {folder}: {e}")))?;
            let current_uv = mbox.uid_validity.ok_or_else(|| {
                MailError::Protocol(format!("SELECT {folder}: missing UIDVALIDITY"))
            })?;
            if current_uv != uidvalidity {
                return Err(MailError::UidValidityChanged {
                    folder: folder.clone(),
                    cached: uidvalidity,
                    observed: current_uv,
                });
            }
            // Chunk the UID set so a bulk move on thousands of
            // messages doesn't blow IMAP server command-line limits
            // (audit P1 #1). Each chunk runs its own MOVE (with
            // COPY+STORE+EXPUNGE fallback if MOVE isn't supported).
            for uid_set in uid_chunks(&uids) {
                // Try MOVE first. Errors that look like "BAD command"
                // fall back to COPY+STORE+EXPUNGE; everything else
                // propagates.
                match session.uid_mv(&uid_set, &target.0).await {
                    Ok(()) => continue,
                    Err(e) => {
                        let msg = e.to_string();
                        if !msg.contains("BAD") && !msg.to_ascii_lowercase().contains("not enabled")
                        {
                            return Err(MailError::Protocol(format!(
                                "UID MOVE {uid_set} {}: {e}",
                                target.0
                            )));
                        }
                        debug!(error = %msg, "UID MOVE not supported; falling back to COPY+STORE+EXPUNGE");
                    }
                }
                session.uid_copy(&uid_set, &target.0).await.map_err(|e| {
                    MailError::Protocol(format!("UID COPY {uid_set} {}: {e}", target.0))
                })?;
                let mut store_stream = session
                    .uid_store(&uid_set, "+FLAGS (\\Deleted)")
                    .await
                    .map_err(|e| MailError::Protocol(format!("STORE \\Deleted {uid_set}: {e}")))?;
                while let Some(r) = store_stream.next().await {
                    r.map_err(|e| MailError::Protocol(format!("STORE response: {e}")))?;
                }
                drop(store_stream);
                // UID EXPUNGE (RFC 4315) targets just the UIDs we just
                // marked. Plain `EXPUNGE` would also pick up any other
                // already-`\Deleted` messages in the folder, which is
                // unsafe in a shared-mailbox scenario.
                let expunge_stream = session
                    .uid_expunge(&uid_set)
                    .await
                    .map_err(|e| MailError::Protocol(format!("UID EXPUNGE {uid_set}: {e}")))?;
                // The stream returned by uid_expunge is `!Unpin`, so
                // pin it on the heap before driving with `.next()`.
                let mut expunge_stream = Box::pin(expunge_stream);
                while let Some(r) = expunge_stream.next().await {
                    r.map_err(|e| MailError::Protocol(format!("UID EXPUNGE response: {e}")))?;
                }
                drop(expunge_stream);
            }
        }
        *self.last_activity.lock().await = Instant::now();
        Ok(())
    }

    async fn delete_messages(&self, messages: &[MessageId]) -> Result<(), MailError> {
        if messages.is_empty() {
            return Ok(());
        }
        // RFC-style "delete" flips `\Deleted` then expunges. Some
        // servers (Gmail) treat \Deleted as "move to Trash"; that's
        // the user-visible expectation here too, so we don't try to
        // emulate a hard purge.
        let mut by_folder: std::collections::HashMap<(String, u32), Vec<u32>> =
            std::collections::HashMap::new();
        for id in messages {
            let r = MessageRef::decode(id)?;
            by_folder
                .entry((r.folder, r.uidvalidity))
                .or_default()
                .push(r.uid);
        }

        let mut session = self.lock_session_alive().await?;
        for ((folder, uidvalidity), uids) in by_folder {
            let mbox = session
                .select(&folder)
                .await
                .map_err(|e| MailError::Protocol(format!("SELECT {folder}: {e}")))?;
            let current_uv = mbox.uid_validity.ok_or_else(|| {
                MailError::Protocol(format!("SELECT {folder}: missing UIDVALIDITY"))
            })?;
            if current_uv != uidvalidity {
                return Err(MailError::UidValidityChanged {
                    folder: folder.clone(),
                    cached: uidvalidity,
                    observed: current_uv,
                });
            }
            // Chunk the UID set so a bulk delete on thousands of
            // messages doesn't blow IMAP server command-line limits
            // (audit P1 #1). Each chunk runs its own STORE+EXPUNGE.
            for uid_set in uid_chunks(&uids) {
                let mut store_stream = session
                    .uid_store(&uid_set, "+FLAGS (\\Deleted)")
                    .await
                    .map_err(|e| MailError::Protocol(format!("STORE \\Deleted {uid_set}: {e}")))?;
                while let Some(r) = store_stream.next().await {
                    r.map_err(|e| MailError::Protocol(format!("STORE response: {e}")))?;
                }
                drop(store_stream);
                let expunge_stream = session
                    .uid_expunge(&uid_set)
                    .await
                    .map_err(|e| MailError::Protocol(format!("UID EXPUNGE {uid_set}: {e}")))?;
                // The stream returned by uid_expunge is `!Unpin`, so
                // pin it on the heap before driving with `.next()`.
                let mut expunge_stream = Box::pin(expunge_stream);
                while let Some(r) = expunge_stream.next().await {
                    r.map_err(|e| MailError::Protocol(format!("UID EXPUNGE response: {e}")))?;
                }
                drop(expunge_stream);
            }
        }
        *self.last_activity.lock().await = Instant::now();
        Ok(())
    }

    async fn save_draft(
        &self,
        raw_rfc822: &[u8],
        replace: Option<&MessageId>,
    ) -> Result<MessageId, MailError> {
        // Find the Drafts mailbox by role. We can't hardcode the path
        // because Gmail uses `[Gmail]/Drafts` while a generic IMAP
        // server might just use `Drafts` or a localized name; the
        // role classifier in `name_to_folder` already normalises this
        // for the Gmail bracket-prefix and the standard SPECIAL-USE
        // attributes.
        let folders = self.list_folders().await?;
        let drafts = folders
            .into_iter()
            .find(|f| f.role == Some(FolderRole::Drafts))
            .ok_or_else(|| MailError::NotFound("IMAP save_draft: no Drafts mailbox".into()))?;

        // Pull the Message-ID *before* APPEND. We use it after to
        // resolve the new copy's UID via `UID SEARCH HEADER Message-ID`
        // since async-imap's high-level `append` doesn't surface
        // APPENDUID. Failing to find a Message-ID is fatal because
        // without it we have no way to locate the just-written copy
        // and would have to return a stale or synthetic id — that
        // breaks the dedup contract on the next save.
        let message_id = qsl_mime::extract_message_id(raw_rfc822).ok_or_else(|| {
            MailError::Parse(
                "IMAP save_draft: outgoing bytes had no Message-ID header — refusing to APPEND \
                 since the new UID can't be resolved without one"
                    .into(),
            )
        })?;

        let mut session = self.lock_session_alive().await?;
        // `\Seen` keeps the draft from showing up as unread (the user
        // wrote it; nothing to "read" later); `\Draft` is the IMAP
        // standard marker so the server's web UI groups the message
        // alongside its native drafts. Most servers (Gmail included)
        // already imply `\Draft` for everything in the Drafts
        // mailbox; sending it explicitly is harmless and survives a
        // future move-out-of-Drafts.
        session
            .append(&drafts.id.0, Some("(\\Seen \\Draft)"), None, raw_rfc822)
            .await
            .map_err(|e| MailError::Protocol(format!("APPEND {}: {e}", drafts.id.0)))?;
        debug!(folder = %drafts.id.0, "IMAP save_draft APPEND ok");

        // Resolve the canonical id we just wrote. SELECT is required
        // before UID SEARCH; we then look up by the Message-ID header
        // we extracted before the APPEND. UIDVALIDITY comes back from
        // SELECT and pairs with the UID to form the
        // `imap|<uv>|<uid>|<folder>` MessageId.
        let mbox = session
            .select(&drafts.id.0)
            .await
            .map_err(|e| MailError::Protocol(format!("SELECT {}: {e}", drafts.id.0)))?;
        let uidvalidity = mbox
            .uid_validity
            .ok_or_else(|| MailError::Protocol("SELECT missing UIDVALIDITY".into()))?;
        // `UID SEARCH HEADER` quotes the value as an IMAP astring.
        // The Message-ID we extracted is bracket-wrapped (`<id>`); IMAP
        // SEARCH HEADER expects the *substring* it's matching against,
        // and brackets work fine because the server compares the
        // entire header value (or substring of it, server-discretion)
        // against what we send.
        let query = format!("HEADER Message-ID {}", quote_imap_astring(&message_id));
        let uids = session
            .uid_search(&query)
            .await
            .map_err(|e| MailError::Protocol(format!("UID SEARCH {query}: {e}")))?;
        let uid = uids.into_iter().max().ok_or_else(|| {
            MailError::Protocol(format!(
                "IMAP save_draft: APPEND ok but UID SEARCH for {message_id} returned no rows"
            ))
        })?;
        let new_id = MessageRef {
            uidvalidity,
            uid,
            folder: drafts.id.0.clone(),
        }
        .encode();

        // Best-effort destroy of the prior copy. We APPEND first so a
        // transient failure here leaves the user with a duplicate,
        // never zero copies; the next save_draft cycle will retry the
        // delete via the freshly-stored server_id. Mismatched
        // UIDVALIDITY (rare; Drafts-folder rebuilds) means the prior
        // UID is no longer valid — log and skip rather than fail.
        if let Some(prior) = replace {
            if let Err(e) =
                destroy_prior_draft(&mut session, &drafts.id.0, uidvalidity, prior).await
            {
                warn!("IMAP save_draft: destroy of prior copy failed (will retry next cycle): {e}");
            }
        }

        *self.last_activity.lock().await = Instant::now();
        Ok(new_id)
    }

    async fn submit_message(&self, raw_rfc822: &[u8]) -> Result<Option<MessageId>, MailError> {
        let route = SmtpRoute::for_imap_host(&self.host).ok_or_else(|| {
            MailError::Other(format!(
                "no SMTP route hardcoded for IMAP host {}",
                self.host
            ))
        })?;

        let (from, recipients) = qsl_mime::extract_envelope(raw_rfc822);
        let from = from.ok_or_else(|| {
            MailError::Parse("submit_message: outgoing bytes had no From header".into())
        })?;
        if recipients.is_empty() {
            return Err(MailError::Other(
                "submit_message: no recipients (To/Cc/Bcc all empty)".into(),
            ));
        }
        let recipient_addrs: Vec<String> = recipients.into_iter().map(|a| a.address).collect();

        qsl_smtp_client::submit(qsl_smtp_client::Submission {
            host: route.host,
            port: route.port,
            tls: route.tls,
            username: &self.email,
            oauth_token: &self.access_token,
            from: &from.address,
            to: &recipient_addrs,
            raw_bytes: raw_rfc822,
        })
        .await
        .map_err(map_smtp_error)?;

        if let Err(e) = self.append_to_sent(raw_rfc822, route.sent_mailbox).await {
            // Submission succeeded; the APPEND is a best-effort
            // mirror so the user sees their message in Sent before
            // the next sync round-trips it. Logging-without-failing
            // matches the IMAP submission norm — Gmail also
            // auto-files outgoing mail in [Gmail]/Sent Mail when
            // submitted on the same authenticated identity.
            warn!(
                "submit_message: SMTP submission succeeded but APPEND to {} failed: {e}",
                route.sent_mailbox
            );
        }
        *self.last_activity.lock().await = Instant::now();
        Ok(None)
    }
}

/// SMTP routing for one IMAP host. Hardcoded per-provider until we
/// grow a real autoconfig story (Outlook, Yahoo, custom domains).
struct SmtpRoute {
    host: &'static str,
    port: u16,
    tls: qsl_smtp_client::TlsMode,
    /// IMAP mailbox name to APPEND a copy into post-submission. Gmail
    /// auto-files into `[Gmail]/Sent Mail` on its own when the SASL
    /// identity matches, so APPEND is a fast-path to surface the
    /// message before the next sync — the exact mailbox name is
    /// provider-specific.
    sent_mailbox: &'static str,
}

impl SmtpRoute {
    fn for_imap_host(imap_host: &str) -> Option<Self> {
        match imap_host {
            "imap.gmail.com" => Some(Self {
                host: qsl_smtp_client::gmail::HOST,
                port: qsl_smtp_client::gmail::PORT_STARTTLS,
                tls: qsl_smtp_client::gmail::TLS,
                sent_mailbox: "[Gmail]/Sent Mail",
            }),
            _ => None,
        }
    }
}

fn map_smtp_error(e: qsl_smtp_client::SmtpError) -> MailError {
    use qsl_smtp_client::SmtpError;
    match e {
        SmtpError::InvalidInput(m) => MailError::Other(format!("smtp invalid input: {m}")),
        SmtpError::Transport(m) => MailError::Network(m),
        SmtpError::Auth(m) => MailError::Auth(m),
        SmtpError::Rejected(m) => MailError::Other(format!("smtp rejected: {m}")),
    }
}

impl ImapBackend {
    async fn append_to_sent(&self, raw_rfc822: &[u8], mailbox: &str) -> Result<(), MailError> {
        let mut session = self.lock_session_alive().await?;
        session
            .append(mailbox, Some("(\\Seen)"), None, raw_rfc822)
            .await
            .map_err(|e| MailError::Protocol(format!("APPEND {mailbox}: {e}")))?;
        Ok(())
    }

    /// Find the largest existing UID strictly below `before` in
    /// `folder`. Used by [`pull_history_chunk`] to skip over runs
    /// of EXPUNGEd UIDs (Gmail INBOX after heavy archiving) in a
    /// single round-trip. Returns the next anchor for the pager:
    /// `max_uid + 1` so the next chunk's range still includes the
    /// found UID, or `0` when no messages exist below `before`
    /// (signals tail-exhausted to the driver loop).
    async fn next_existing_uid_below(
        &self,
        folder: &FolderId,
        before: u64,
    ) -> Result<u64, MailError> {
        let upper = u32::try_from(before.saturating_sub(1))
            .map_err(|_| MailError::Protocol(format!("anchor {before} exceeds IMAP UID range")))?;
        if upper == 0 {
            return Ok(0);
        }
        let mut session = self.lock_session_alive().await?;
        session
            .select(&folder.0)
            .await
            .map_err(|e| MailError::Protocol(format!("SELECT {}: {e}", folder.0)))?;
        let uids = session
            .uid_search(format!("UID 1:{upper}"))
            .await
            .map_err(|e| MailError::Protocol(format!("UID SEARCH UID 1:{upper}: {e}")))?;
        *self.last_activity.lock().await = Instant::now();
        let anchor = uids
            .into_iter()
            .max()
            .map(|u| u64::from(u) + 1)
            .unwrap_or(0);
        Ok(anchor)
    }
}

// ---------- helpers ----------

/// Quote a string for IMAP's `astring` syntax (RFC 3501 §4.3).
/// Wraps in double quotes and backslash-escapes any embedded `"` or
/// `\`. Used for `UID SEARCH HEADER Message-ID <quoted>` so a
/// `Message-ID` containing whitespace, brackets, or other characters
/// the IMAP parser would reject as a bare atom round-trips correctly.
fn quote_imap_astring(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Mark a prior draft `\Deleted` and `UID EXPUNGE` it. Caller has
/// already SELECTed `drafts_folder` and confirmed it matches the
/// folder portion of `prior`. Mismatched UIDVALIDITY is fatal because
/// the UID we'd issue STORE for would silently target an unrelated
/// message — better to surface the mismatch and skip than corrupt the
/// folder. UIDPLUS' `UID EXPUNGE` (RFC 4315) scopes the expunge to
/// just the supplied UIDs, so we don't accidentally sweep up other
/// already-`\Deleted` rows another client left behind.
async fn destroy_prior_draft(
    session: &mut Session<StreamT>,
    drafts_folder: &str,
    current_uidvalidity: u32,
    prior: &MessageId,
) -> Result<(), MailError> {
    let prior_ref = MessageRef::decode(prior)?;
    if prior_ref.folder != drafts_folder {
        return Err(MailError::Other(format!(
            "prior draft folder {} != current drafts folder {drafts_folder}; skipping",
            prior_ref.folder
        )));
    }
    if prior_ref.uidvalidity != current_uidvalidity {
        return Err(MailError::Other(format!(
            "prior UIDVALIDITY {} != current {current_uidvalidity}; the prior UID is no longer \
             valid",
            prior_ref.uidvalidity
        )));
    }

    let uid_set = prior_ref.uid.to_string();
    let store_stream = session
        .uid_store(&uid_set, "+FLAGS (\\Deleted)")
        .await
        .map_err(|e| MailError::Protocol(format!("UID STORE \\Deleted {uid_set}: {e}")))?;
    let mut store_stream = Box::pin(store_stream);
    while let Some(r) = store_stream.next().await {
        r.map_err(|e| MailError::Protocol(format!("UID STORE response: {e}")))?;
    }
    drop(store_stream);

    let expunge_stream = session
        .uid_expunge(&uid_set)
        .await
        .map_err(|e| MailError::Protocol(format!("UID EXPUNGE {uid_set}: {e}")))?;
    let mut expunge_stream = Box::pin(expunge_stream);
    while let Some(r) = expunge_stream.next().await {
        r.map_err(|e| MailError::Protocol(format!("UID EXPUNGE response: {e}")))?;
    }
    drop(expunge_stream);

    debug!(
        uid = prior_ref.uid,
        folder = drafts_folder,
        "destroyed prior draft"
    );
    Ok(())
}

fn name_to_folder(name: &async_imap::types::Name, account: &AccountId) -> Folder {
    // IMAP's LIST response hands us a hierarchical path delimited by
    // some character (usually '/' or '.'). We store the full path as-is
    // and derive the leaf as the display name.
    let path = name.name().to_string();
    let delimiter = name.delimiter().unwrap_or("/");
    let display = path
        .rsplit_once(delimiter)
        .map(|(_, leaf)| leaf.to_string())
        .unwrap_or_else(|| path.clone());
    let role = role_from_attributes(
        &name
            .attributes()
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<_>>(),
    )
    .or_else(|| role_from_canonical_name(&path));

    Folder {
        id: FolderId(path.clone()),
        account_id: account.clone(),
        name: display,
        path,
        role,
        unread_count: 0,
        total_count: 0,
        parent: None,
    }
}

/// Map RFC 3501's reserved "INBOX" mailbox name to
/// [`FolderRole::Inbox`] when the server didn't include `\Inbox`
/// SPECIAL-USE. Gmail in particular omits the attribute because
/// INBOX is implicit per spec; without this fallback the watcher
/// pool prioritizer doesn't recognize INBOX as a high-priority
/// folder.
fn role_from_canonical_name(path: &str) -> Option<FolderRole> {
    if path.eq_ignore_ascii_case("INBOX") {
        Some(FolderRole::Inbox)
    } else {
        None
    }
}

fn role_from_attributes(attributes: &[String]) -> Option<FolderRole> {
    // IMAP SPECIAL-USE (RFC 6154) attributes are prefixed with `\`. The
    // Debug formatting of async-imap's `NameAttribute::Custom` yields
    // something like `Custom("\\Inbox")`, so we look for the
    // well-known names anywhere in the formatted string.
    let joined = attributes.join(" ").to_ascii_lowercase();
    if joined.contains("inbox") {
        Some(FolderRole::Inbox)
    } else if joined.contains("sent") {
        Some(FolderRole::Sent)
    } else if joined.contains("drafts") {
        Some(FolderRole::Drafts)
    } else if joined.contains("trash") {
        Some(FolderRole::Trash)
    } else if joined.contains("junk") || joined.contains("spam") {
        Some(FolderRole::Spam)
    } else if joined.contains("archive") {
        Some(FolderRole::Archive)
    } else if joined.contains("important") {
        Some(FolderRole::Important)
    } else if joined.contains("all") {
        Some(FolderRole::All)
    } else if joined.contains("flagged") {
        Some(FolderRole::Flagged)
    } else {
        None
    }
}

// Kept around because callers will eventually need it when the fetch
// path lands in the next increment on this branch.
#[allow(dead_code)]
fn ensure_uidvalidity_matches(
    cached: &BackendState,
    observed_uidvalidity: u32,
) -> Result<(), MailError> {
    if cached.uidvalidity != observed_uidvalidity {
        warn!(
            cached = cached.uidvalidity,
            observed = observed_uidvalidity,
            "UIDVALIDITY changed — cached state is stale"
        );
        return Err(MailError::Protocol(
            "UIDVALIDITY changed; refetch the folder from scratch".into(),
        ));
    }
    Ok(())
}

fn fetch_to_headers(
    fetch: &Fetch,
    folder: &FolderId,
    uidvalidity: u32,
    account: &AccountId,
) -> Result<Option<MessageHeaders>, MailError> {
    let Some(uid) = fetch.uid else {
        return Ok(None);
    };
    let envelope = fetch.envelope();
    let flags = extract_flags(fetch);
    let size = fetch.size.unwrap_or(0);
    let rfc822_message_id = envelope
        .and_then(|e| e.message_id.as_deref())
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(|s| s.to_string());
    let subject = envelope
        .and_then(|e| e.subject.as_deref())
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(qsl_mime::decode_header_value)
        .unwrap_or_default();
    let from = addr_vec(envelope.and_then(|e| e.from.as_ref()));
    let reply_to = addr_vec(envelope.and_then(|e| e.reply_to.as_ref()));
    let to = addr_vec(envelope.and_then(|e| e.to.as_ref()));
    let cc = addr_vec(envelope.and_then(|e| e.cc.as_ref()));
    let bcc = addr_vec(envelope.and_then(|e| e.bcc.as_ref()));

    // Prefer INTERNALDATE (always present on servers). Fall back to the
    // envelope date if the server skips it for some reason.
    let date = fetch
        .internal_date()
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| {
            envelope
                .and_then(|e| e.date.as_deref())
                .and_then(|b| std::str::from_utf8(b).ok())
                .and_then(parse_rfc2822_to_utc)
        })
        .unwrap_or_else(Utc::now);

    let r = MessageRef {
        uidvalidity,
        uid,
        folder: folder.0.clone(),
    };

    // X-GM-LABELS, when present, contains every Gmail label the
    // message carries — including system labels (`\Inbox`, `\Sent`,
    // `\Important`) the user can't see in the web UI. Strip the
    // backslash-prefixed system ones so what lands in
    // `MessageHeaders.labels` is just the user-visible label set,
    // matching what JMAP returns from `Mailbox/get`.
    let labels = fetch
        .gmail_labels()
        .map(|labels| {
            labels
                .iter()
                .map(|l| l.to_string())
                .filter(|l| !l.starts_with('\\'))
                .collect()
        })
        .unwrap_or_default();

    // Threading needs `In-Reply-To` and `References`. ENVELOPE only
    // surfaces `In-Reply-To`; we additionally requested
    // `BODY.PEEK[HEADER]` and parse the raw header block here. The
    // bytes may not be present on a malformed FETCH response —
    // treat both fields as empty in that case (the threading
    // pipeline falls back to subject normalization).
    let (in_reply_to, references) = fetch
        .header()
        .map(qsl_mime::extract_thread_headers)
        .unwrap_or_default();

    Ok(Some(MessageHeaders {
        id: r.encode(),
        account_id: account.clone(),
        folder_id: folder.clone(),
        thread_id: None::<ThreadId>,
        rfc822_message_id,
        subject,
        from,
        reply_to,
        to,
        cc,
        bcc,
        date,
        flags,
        labels,
        snippet: String::new(),
        size,
        has_attachments: false,
        in_reply_to,
        references,
    }))
}

fn addr_vec(addrs: Option<&Vec<imap_proto::Address<'_>>>) -> Vec<EmailAddress> {
    let Some(list) = addrs else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|a| {
            let mailbox = a
                .mailbox
                .as_deref()
                .and_then(|b| std::str::from_utf8(b).ok())?;
            let host = a
                .host
                .as_deref()
                .and_then(|b| std::str::from_utf8(b).ok())?;
            let name = a
                .name
                .as_deref()
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(qsl_mime::decode_header_value);
            Some(EmailAddress {
                address: format!("{mailbox}@{host}"),
                display_name: name,
            })
        })
        .collect()
}

/// Render a `MessageFlags` set as a space-separated IMAP flag list
/// suitable for `+FLAGS (...)` / `-FLAGS (...)`. Skips `forwarded`
/// when not set; emits `$Forwarded` (the de-facto Gmail/Apple
/// convention) when set and `supports_forwarded` is true, since IMAP
/// has no standard `\Forwarded`. Returns an empty string when no
/// flags are set so the caller can skip the STORE round-trip entirely.
fn render_imap_flags(flags: &MessageFlags, supports_forwarded: bool) -> String {
    let mut parts = Vec::with_capacity(5);
    if flags.seen {
        parts.push("\\Seen");
    }
    if flags.flagged {
        parts.push("\\Flagged");
    }
    if flags.answered {
        parts.push("\\Answered");
    }
    if flags.draft {
        parts.push("\\Draft");
    }
    if flags.forwarded && supports_forwarded {
        parts.push("$Forwarded");
    }
    parts.join(" ")
}

fn extract_flags(fetch: &Fetch) -> MessageFlags {
    use async_imap::types::Flag;
    let mut flags = MessageFlags::default();
    for f in fetch.flags() {
        match f {
            Flag::Seen => flags.seen = true,
            Flag::Flagged => flags.flagged = true,
            Flag::Answered => flags.answered = true,
            Flag::Draft => flags.draft = true,
            Flag::Custom(s) if s.eq_ignore_ascii_case("$forwarded") => flags.forwarded = true,
            _ => {}
        }
    }
    flags
}

/// CONDSTORE flag-delta pass. Issues
/// `UID FETCH 1:<upper> (UID FLAGS) (CHANGEDSINCE <modseq>)` and
/// returns one `(MessageId, MessageFlags)` tuple per message whose
/// flags moved since `modseq`. Errors propagate up — the caller
/// (`list_messages`) downgrades any failure to "no flag delta this
/// cycle" rather than failing the whole sync.
async fn fetch_flag_changes(
    session: &mut Session<StreamT>,
    folder: &FolderId,
    uidvalidity: u32,
    upper: u32,
    modseq: u64,
) -> Result<Vec<(MessageId, MessageFlags)>, MailError> {
    let uid_set = format!("1:{upper}");
    let query = format!("(UID FLAGS) (CHANGEDSINCE {modseq})");
    let mut fetches = session
        .uid_fetch(&uid_set, &query)
        .await
        .map_err(|e| MailError::Protocol(format!("UID FETCH {uid_set} {query}: {e}")))?;

    let mut updates = Vec::new();
    while let Some(item) = fetches.next().await {
        let fetch = item.map_err(|e| MailError::Protocol(format!("FETCH entry: {e}")))?;
        let Some(uid) = fetch.uid else {
            debug!(message = ?fetch.message, "CHANGEDSINCE FETCH missing UID — skipping");
            continue;
        };
        let id = MessageRef {
            uidvalidity,
            uid,
            folder: folder.0.clone(),
        }
        .encode();
        updates.push((id, extract_flags(&fetch)));
    }
    Ok(updates)
}

fn parse_rfc2822_to_utc(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

// ---------- BackendKind helper ----------

/// True if the given account kind is backed by this adapter.
pub fn handles(kind: &BackendKind) -> bool {
    matches!(kind, BackendKind::ImapSmtp)
}

// ---------- UID chunking ----------

/// Maximum number of UIDs in a single `UID STORE` / `UID MOVE` /
/// `UID EXPUNGE` command. RFC 3501 doesn't fix a command length but
/// most production IMAP servers cap at ~8 KB; staying at 1000 UIDs
/// keeps each command's bytes well below that even with 7-digit UIDs
/// (~8 KB worst case for the UID set alone). Combined with
/// [`UID_BATCH_BYTES_LIMIT`] this protects bulk operations on
/// thousands of messages from running into server-side rejection.
const UID_BATCH_LIMIT: usize = 1000;

/// Maximum bytes (digits + commas) in one comma-joined UID set.
/// Tighter than the typical 8 KB server limit so the surrounding
/// `UID STORE <set> +FLAGS (\\Seen)` envelope has room without ever
/// approaching overflow.
const UID_BATCH_BYTES_LIMIT: usize = 4096;

/// Split `uids` into IMAP-friendly comma-joined batches.
///
/// Each emitted string is at most [`UID_BATCH_LIMIT`] UIDs and
/// [`UID_BATCH_BYTES_LIMIT`] bytes. Order within each batch matches
/// the input slice; UIDs are not deduplicated. Empty input yields
/// an empty Vec.
///
/// Background: the audit found `UID STORE` / `UID MOVE` building one
/// massive set via `.join(",")` regardless of `messages.len()`. Bulk
/// actions on thousands of rows could overflow server command-line
/// limits. Chunking yields one command per ~1000 UIDs; partial
/// failures surface visibly per chunk rather than as a silent
/// dropped sync.
fn uid_chunks(uids: &[u32]) -> Vec<String> {
    let mut out = Vec::new();
    if uids.is_empty() {
        return out;
    }
    let mut current = String::new();
    let mut count = 0usize;
    for &u in uids {
        let s = u.to_string();
        // Bytes this UID would add (comma + digits, or just digits
        // when the chunk is empty).
        let needed = if current.is_empty() {
            s.len()
        } else {
            1 + s.len()
        };
        let count_full = count >= UID_BATCH_LIMIT;
        let bytes_full = !current.is_empty() && current.len() + needed > UID_BATCH_BYTES_LIMIT;
        if count_full || bytes_full {
            out.push(std::mem::take(&mut current));
            count = 0;
        }
        if !current.is_empty() {
            current.push(',');
        }
        current.push_str(&s);
        count += 1;
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_from_attributes_recognizes_special_use() {
        assert_eq!(
            role_from_attributes(&["\\Inbox".into()]),
            Some(FolderRole::Inbox)
        );
        assert_eq!(
            role_from_attributes(&["Custom(\"\\\\Sent\")".into()]),
            Some(FolderRole::Sent)
        );
        assert_eq!(
            role_from_attributes(&["\\Drafts".into(), "\\HasNoChildren".into()]),
            Some(FolderRole::Drafts)
        );
        assert_eq!(role_from_attributes(&["\\HasChildren".into()]), None);
    }

    #[test]
    fn ensure_uidvalidity_flags_change() {
        let cached = BackendState {
            uidvalidity: 10,
            highestmodseq: 1,
            uidnext: 1,
        };
        assert!(ensure_uidvalidity_matches(&cached, 10).is_ok());
        let err = ensure_uidvalidity_matches(&cached, 11).unwrap_err();
        assert!(err.to_string().contains("UIDVALIDITY changed"));
    }

    #[test]
    fn handles_imapsmtp_only() {
        assert!(handles(&BackendKind::ImapSmtp));
        assert!(!handles(&BackendKind::Jmap));
    }

    #[test]
    fn uid_chunks_empty_input_yields_no_batches() {
        assert!(uid_chunks(&[]).is_empty());
    }

    #[test]
    fn uid_chunks_small_input_collapses_to_one_batch() {
        let batches = uid_chunks(&[1, 2, 3, 4, 5]);
        assert_eq!(batches, vec!["1,2,3,4,5".to_string()]);
    }

    #[test]
    fn uid_chunks_caps_at_count_limit() {
        // 1500 UIDs → two batches: 1000 + 500.
        let uids: Vec<u32> = (1..=1500).collect();
        let batches = uid_chunks(&uids);
        assert_eq!(
            batches.len(),
            2,
            "expected 2 batches, got {}",
            batches.len()
        );
        let first_count = batches[0].split(',').count();
        let second_count = batches[1].split(',').count();
        assert_eq!(first_count, UID_BATCH_LIMIT);
        assert_eq!(second_count, 1500 - UID_BATCH_LIMIT);
    }

    #[test]
    fn uid_chunks_caps_at_byte_limit() {
        // Use UIDs that are 7 digits each so we hit the 4096-byte cap
        // before the 1000-count cap. 4096 / 8 ≈ 512 per batch, so
        // 1000 UIDs straddles two batches by bytes alone.
        let uids: Vec<u32> = (1_000_000..1_001_000).collect();
        let batches = uid_chunks(&uids);
        assert!(
            batches.len() >= 2,
            "expected ≥2 batches by byte cap, got {}",
            batches.len()
        );
        for b in &batches {
            assert!(
                b.len() <= UID_BATCH_BYTES_LIMIT,
                "batch overshot byte cap: {} bytes",
                b.len()
            );
        }
    }

    #[test]
    fn uid_chunks_preserves_order_across_batches() {
        let uids: Vec<u32> = (1..=2500).collect();
        let batches = uid_chunks(&uids);
        let mut rebuilt: Vec<u32> = Vec::new();
        for b in batches {
            for tok in b.split(',') {
                rebuilt.push(tok.parse().expect("digits"));
            }
        }
        assert_eq!(rebuilt, uids, "uid_chunks reordered the input");
    }
}
