// SPDX-License-Identifier: Apache-2.0

//! QSL JMAP adapter — [`MailBackend`] implementation over
//! `jmap-client` v0.4.
//!
//! The backend is constructed with a session URL and a bearer access
//! token minted by `qsl-auth`:
//!
//! 1. `jmap_client::client::Client::new().credentials(Credentials::bearer(token)).connect(session_url)`.
//! 2. `mailbox_get(None, None)` for discovery → `Vec<Folder>`.
//! 3. `list_messages` / `fetch_message` use `Email/query`, `Email/get`,
//!    and `Email/changes` for delta sync. The server's state token
//!    round-trips through `SyncState.backend_state`.
//!
//! Phase 0 Week 4 ships the **read path**. Write methods return
//! `MailError::Other("not yet implemented")` until Phase 1 Week 2, and
//! `watch()` stays at the trait default empty stream until Phase 1 Week
//! 1 when EventSource lands.

pub mod push;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use jmap_client::client::Client;
use jmap_client::core::set::SetObject;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use qsl_core::{
    AccountId, Attachment, AttachmentRef, BackendKind, EmailAddress, Folder, FolderId, FolderRole,
    MailBackend, MailError, MessageBody, MessageFlags, MessageHeaders, MessageId, MessageList,
    SyncState, ThreadId,
};

pub use push::watch_account;

/// JMAP-backed [`MailBackend`].
pub struct JmapBackend {
    client: Mutex<Client>,
    account_id: AccountId,
    session_url: String,
    /// Identity used for `EmailSubmission/set` (`From` header validation).
    /// Resolved once at connect-time by matching the supplied account email
    /// against `Identity/get`.
    identity_id: Arc<str>,
}

impl JmapBackend {
    /// Connect to a JMAP session URL with the supplied bearer access
    /// token. The session URL typically lives at
    /// `https://<host>/.well-known/jmap` or a provider-specific path.
    ///
    /// `email` is the account's primary address — used at connect-time to
    /// pick the matching submission identity from `Identity/get` so
    /// `submit_message` knows which `From` to send under.
    pub async fn connect(
        session_url: &str,
        access_token: &str,
        account_id: AccountId,
        email: &str,
    ) -> Result<Self, MailError> {
        let client = dial_client(session_url, access_token).await?;
        let identity_id = resolve_identity_id(&client, email).await?;
        info!(session_url, %email, %identity_id, "JMAP connected");
        Ok(Self {
            client: Mutex::new(client),
            account_id,
            session_url: session_url.to_string(),
            identity_id: Arc::from(identity_id),
        })
    }

    /// Session URL this backend connected to — exposed for logs and
    /// diagnostics.
    pub fn session_url(&self) -> &str {
        &self.session_url
    }
}

/// Fetch the full identity list and pick the one whose `email` matches the
/// account's primary address. Falls back to the first identity (with a
/// `warn`) if no match — matches Fastmail's typical "single primary
/// identity" shape but logs the surprise so multi-identity setups don't
/// silently send under the wrong From.
async fn resolve_identity_id(client: &Client, email: &str) -> Result<String, MailError> {
    let mut request = client.build();
    request.get_identity();
    let mut response = request.send_get_identity().await.map_err(map_jmap_error)?;
    let identities = response.take_list();
    if identities.is_empty() {
        return Err(MailError::Auth(
            "JMAP Identity/get returned no identities".into(),
        ));
    }
    if let Some(matched) = identities.iter().find(|i| i.email() == Some(email)) {
        return matched
            .id()
            .map(str::to_string)
            .ok_or_else(|| MailError::Protocol("Identity/get matched entry has no id".into()));
    }
    let first = &identities[0];
    let fallback = first
        .id()
        .map(str::to_string)
        .ok_or_else(|| MailError::Protocol("Identity/get fallback entry has no id".into()))?;
    let fallback_email = first.email().unwrap_or("(none)");
    warn!(
        wanted = email,
        got = fallback_email,
        "JMAP Identity/get: no exact email match, falling back to first identity"
    );
    Ok(fallback)
}

/// Open a fresh JMAP `Client` against `session_url` with a bearer
/// access token. Both [`JmapBackend::connect`] and the
/// [`crate::push::watch_account`] watcher call through this so the
/// connect logic — bearer credentials, session resolution — lives
/// in one place. Mirrors `qsl_imap_client::dial_session`.
pub async fn dial_client(session_url: &str, access_token: &str) -> Result<Client, MailError> {
    // jmap-client 0.4 appends `/.well-known/jmap` to whatever it is
    // given, so it must receive the bare origin — passing the full
    // well-known URL produced `…/.well-known/jmap/.well-known/jmap`,
    // which Fastmail 302s to a marketing page. Accept either shape
    // from callers and normalise here.
    let origin = session_origin(session_url);
    // Fastmail answers `/.well-known/jmap` with a 302 to
    // `/jmap/session`. jmap-client refuses every redirect unless the
    // target host is in its trusted list, and the trusted list is
    // also what keeps the bearer token from being replayed to a
    // third-party host — so trust exactly the host we dialled.
    let trusted_host = host_of(&origin)
        .ok_or_else(|| MailError::Other(format!("JMAP session URL has no host: {session_url}")))?;
    qsl_telemetry::time_op!(
        target: "qsl::slow::jmap",
        limit_ms: qsl_telemetry::slow::limits::HTTP_JMAP_MS,
        op: "jmap_session_connect",
        fields: { session_url = %origin },
        Client::new()
            .credentials(jmap_client::client::Credentials::bearer(access_token))
            .follow_redirects([trusted_host])
            // jmap-client's default is a 10 s whole-request timeout,
            // which a multi-MB `Email/import` upload (draft with
            // attachments) cannot meet on an ordinary uplink.
            .timeout(std::time::Duration::from_secs(120))
            .connect(&origin)
    )
    .map_err(|e| MailError::Network(format!("JMAP connect {origin}: {e}")))
}

/// Reduce a configured session URL to the origin jmap-client wants:
/// strip a trailing `/.well-known/jmap` (with or without trailing
/// slash) and any trailing `/`.
fn session_origin(session_url: &str) -> String {
    let trimmed = session_url.trim_end_matches('/');
    trimmed
        .strip_suffix("/.well-known/jmap")
        .unwrap_or(trimmed)
        .trim_end_matches('/')
        .to_string()
}

/// Host component of an `https://host[:port][/…]` origin, without
/// userinfo or port. `None` when there is no scheme separator or the
/// host is empty.
fn host_of(origin: &str) -> Option<String> {
    let rest = origin.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = host_port.split(':').next()?;
    (!host.is_empty()).then(|| host.to_string())
}

// ---------- MailBackend impl ----------

const NOT_YET: &str =
    "JMAP adapter read-path arrives in Phase 0 Week 4 (Mailbox/get landed here); \
    Email/query + Email/get + Email/changes wiring is staged for Phase 1 Week 1";

#[async_trait]
impl MailBackend for JmapBackend {
    async fn list_folders(&self) -> Result<Vec<Folder>, MailError> {
        use jmap_client::core::query::Comparator;
        use jmap_client::mailbox::query::Filter as MailboxFilter;

        let client = self.client.lock().await;

        // JMAP's `mailbox_get(id, …)` takes a single id; for "all
        // mailboxes" we first Mailbox/query to get the id set, then
        // Mailbox/get each. One extra roundtrip — acceptable at the
        // mailbox count we expect (<100).
        let ids = client
            .mailbox_query(
                None::<jmap_client::core::query::Filter<MailboxFilter>>,
                None::<Vec<Comparator<jmap_client::mailbox::query::Comparator>>>,
            )
            .await
            .map_err(|e| MailError::Protocol(format!("Mailbox/query: {e}")))?
            .take_ids();

        let mut folders = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(mb) = client
                .mailbox_get(&id, None::<Vec<jmap_client::mailbox::Property>>)
                .await
                .map_err(|e| MailError::Protocol(format!("Mailbox/get {id}: {e}")))?
            {
                folders.push(mailbox_to_folder(mb, &self.account_id));
            }
        }
        drop(client);

        debug!(count = folders.len(), "JMAP Mailbox/get returned folders");
        Ok(folders)
    }

    async fn list_messages(
        &self,
        folder: &FolderId,
        since: Option<&SyncState>,
        limit: Option<u32>,
    ) -> Result<MessageList, MailError> {
        use jmap_client::core::query::Comparator;
        use jmap_client::email::{self, query::Filter};

        let client = self.client.lock().await;

        // Discovery: what are the ids in this mailbox that changed
        // since our last sync? JMAP's Email/changes is the right answer
        // when `since` is present — it also tells us what was destroyed.
        // For the initial sync (no `since`) we fall back to Email/query
        // scoped to `inMailbox = <folder>`.
        let (ids_to_fetch, removed, new_state_token) = if let Some(state) = since {
            let changes = client
                .email_changes(state.backend_state.as_str(), None)
                .await
                .map_err(|e| MailError::Protocol(format!("Email/changes: {e}")))?;
            let created: Vec<String> = changes.created().iter().map(|s| s.to_string()).collect();
            let updated: Vec<String> = changes.updated().iter().map(|s| s.to_string()).collect();
            let destroyed: Vec<MessageId> = changes
                .destroyed()
                .iter()
                .map(|s| MessageId(s.to_string()))
                .collect();
            let mut all = created;
            all.extend(updated);
            let new_state = changes.new_state().to_string();
            (all, destroyed, new_state)
        } else {
            let filter = Filter::in_mailbox(folder.backend_key(&self.account_id).to_string());
            let query = client
                .email_query(
                    Some(filter),
                    None::<Vec<Comparator<email::query::Comparator>>>,
                )
                .await
                .map_err(|e| MailError::Protocol(format!("Email/query: {e}")))?;
            let all_ids: Vec<String> = query.ids().iter().map(|s| s.to_string()).collect();
            let ids = match limit {
                Some(n) if (n as usize) < all_ids.len() => all_ids
                    .into_iter()
                    .rev()
                    .take(n as usize)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect(),
                _ => all_ids,
            };
            // Email/query doesn't return a state-like cursor on its
            // own; the state we persist is Email/changes-ready —
            // clients must do one follow-up `email_changes` on next
            // sync. We seed with the query's `query_state` if present,
            // otherwise an empty string (which JMAP treats as "any
            // prior state").
            let new_state = query.query_state().to_string();
            (ids, Vec::new(), new_state)
        };

        let mut messages = Vec::with_capacity(ids_to_fetch.len());
        for id in &ids_to_fetch {
            let email = client
                .email_get(id.as_str(), None::<Vec<jmap_client::email::Property>>)
                .await
                .map_err(|e| MailError::Protocol(format!("Email/get {id}: {e}")))?;
            if let Some(email) = email {
                messages.push(email_to_headers(&email, folder, &self.account_id));
            }
        }
        drop(client);

        debug!(
            folder = %folder.0,
            fetched = messages.len(),
            destroyed = removed.len(),
            "JMAP list_messages"
        );

        Ok(MessageList {
            messages,
            // JMAP `Email/changes` returns ID-level created/updated/
            // destroyed sets but no per-message flag delta in the
            // shape `flag_updates` expects. Surfacing JMAP keyword
            // changes here lands alongside the `Email/changes` →
            // `Email/get` follow-up fetch in the JMAP polish pass.
            flag_updates: Vec::new(),
            new_state: SyncState {
                folder_id: folder.clone(),
                backend_state: new_state_token,
            },
            removed,
        })
    }

    async fn list_known_ids(&self, folder: &FolderId) -> Result<Vec<MessageId>, MailError> {
        use jmap_client::core::query::Comparator;
        use jmap_client::email::{self, query::Filter};

        let client = self.client.lock().await;
        let query = client
            .email_query(
                Some(Filter::in_mailbox(
                    folder.backend_key(&self.account_id).to_string(),
                )),
                None::<Vec<Comparator<email::query::Comparator>>>,
            )
            .await
            .map_err(|e| MailError::Protocol(format!("Email/query {}: {e}", folder.0)))?;
        let ids: Vec<MessageId> = query
            .ids()
            .iter()
            .map(|s| MessageId(s.to_string()))
            .collect();
        drop(client);
        debug!(
            folder = %folder.0,
            count = ids.len(),
            "JMAP list_known_ids"
        );
        Ok(ids)
    }

    async fn fetch_message(&self, id: &MessageId) -> Result<MessageBody, MailError> {
        let client = self.client.lock().await;
        let email = client
            .email_get(&id.0, None::<Vec<jmap_client::email::Property>>)
            .await
            .map_err(|e| MailError::Protocol(format!("Email/get {}: {e}", id.0)))?
            .ok_or_else(|| MailError::NotFound(format!("JMAP email id {}", id.0)))?;
        drop(client);

        // Folder assignment: JMAP emails belong to one-or-more mailboxes
        // via `mailboxIds`. For our MessageBody we pick the first
        // (there's no guaranteed canonical one in JMAP). Callers that
        // care about the "which folder" story can look at mailbox_ids
        // directly once we surface it.
        let folder_id = FolderId::scoped(
            &self.account_id,
            email.mailbox_ids().first().map(|s| &**s).unwrap_or(""),
        );

        let headers = email_to_headers(&email, &folder_id, &self.account_id);

        // Body content: JMAP returns textBody/htmlBody as references
        // into `bodyValues`. For Phase 0 read path, `preview()` + what
        // text_body/html_body point at is enough to surface plaintext.
        // Full bodyValues wiring lands in the Phase 1 polish pass.
        let body_text = email.preview().map(str::to_string);

        Ok(MessageBody {
            headers,
            body_html: None,
            body_text,
            attachments: Vec::<Attachment>::new(),
            in_reply_to: email
                .in_reply_to()
                .and_then(|list| list.first())
                .map(|s| format!("<{s}>")),
            references: email
                .references()
                .map(|list| list.iter().map(|s| format!("<{s}>")).collect())
                .unwrap_or_default(),
        })
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
        let client = self.client.lock().await;
        // JMAP doesn't have a `STORE +FLAGS` batch primitive — each
        // (id, keyword, set) tuple goes through `email_set_keyword`.
        // For the typical mark-read flow that's `messages.len()`
        // round-trips with one keyword each; batched mutations land
        // in the polish pass when we move to building a single
        // `Email/set` request manually.
        for id in messages {
            for (kw, set) in flag_diff(&add, true)
                .iter()
                .chain(flag_diff(&remove, false).iter())
            {
                client
                    .email_set_keyword(&id.0, kw, *set)
                    .await
                    .map_err(|e| {
                        MailError::Protocol(format!("Email/set keyword {kw} on {}: {e}", id.0))
                    })?;
            }
        }
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
        let client = self.client.lock().await;
        // JMAP's move semantics live inside Email/set: replacing
        // `mailboxIds` with `[target]` removes the message from
        // every other mailbox in one round-trip. That's the spec's
        // "move" — preserving secondary labels would be a
        // copy-shaped operation users don't expect from "move to
        // folder."
        for id in messages {
            client
                .email_set_mailboxes(&id.0, [target.backend_key(&self.account_id)])
                .await
                .map_err(|e| MailError::Protocol(format!("Email/set mailboxIds {}: {e}", id.0)))?;
        }
        Ok(())
    }

    async fn delete_messages(&self, messages: &[MessageId]) -> Result<(), MailError> {
        if messages.is_empty() {
            return Ok(());
        }
        let client = self.client.lock().await;
        for id in messages {
            client
                .email_destroy(&id.0)
                .await
                .map_err(|e| MailError::Protocol(format!("Email/set destroy {}: {e}", id.0)))?;
        }
        Ok(())
    }

    async fn save_draft(
        &self,
        raw_rfc822: &[u8],
        replace: Option<&MessageId>,
    ) -> Result<MessageId, MailError> {
        // Locate the Drafts mailbox via role (same look-up the
        // submit_message path does); JMAP wants the actual mailbox
        // id rather than a name.
        let folders = self.list_folders().await?;
        let drafts_id = folders
            .into_iter()
            .find_map(|f| (f.role == Some(FolderRole::Drafts)).then_some(f.id))
            .ok_or_else(|| MailError::NotFound("JMAP save_draft: no Drafts mailbox".into()))?;

        let client = self.client.lock().await;
        // `email_import` targets the session's primary mail account
        // (`primaryAccounts[urn:ietf:params:jmap:mail]`). QSL's own
        // `AccountId` (`fastmail:<email>`) is a local storage key and
        // means nothing to the server — passing it as the JMAP
        // accountId made every import fail with `accountNotFound`.
        let email = client
            .email_import(
                raw_rfc822.to_vec(),
                [drafts_id.backend_key(&self.account_id)],
                Some(["$draft"]),
                None,
            )
            .await
            .map_err(map_jmap_error)?;
        let id = email
            .id()
            .ok_or_else(|| MailError::Protocol("Email/import returned no id".into()))?
            .to_string();
        debug!(email_id = %id, drafts = %drafts_id.0, "JMAP save_draft import ok");

        // Best-effort destroy of the prior copy via Email/set { destroy }.
        // Same APPEND-then-destroy ordering as the IMAP path: a
        // failure here leaves the user with a duplicate, never zero
        // copies, and the next save_draft cycle retries with the
        // freshly-stored server_id.
        if let Some(prior) = replace {
            let mut request = client.build();
            // Default account id (the primary mail account) — same
            // reasoning as the import above.
            let set_email = request.set_email();
            set_email.destroy([prior.0.as_str()]);
            match request.send_set_email().await {
                Ok(_) => {
                    debug!(prior = %prior.0, "JMAP save_draft: prior copy destroyed");
                }
                Err(e) => {
                    warn!(
                        prior = %prior.0,
                        "JMAP save_draft: destroy failed (will retry next cycle): {e}"
                    );
                }
            }
        }
        drop(client);
        Ok(MessageId(id))
    }

    async fn submit_message(&self, raw_rfc822: &[u8]) -> Result<Option<MessageId>, MailError> {
        // Pre-flight envelope check (matches the IMAP path's check at
        // `qsl_imap_client::backend::ImapBackend::submit_message`).
        let (from, recipients) = qsl_mime::extract_envelope(raw_rfc822);
        if from.is_none() {
            return Err(MailError::Parse(
                "submit_message: outgoing bytes had no From header".into(),
            ));
        }
        if recipients.is_empty() {
            return Err(MailError::Other(
                "submit_message: no recipients (To/Cc/Bcc all empty)".into(),
            ));
        }

        // Look up Drafts + Sent mailbox ids per-send. JMAP requires the
        // email to live in Drafts with `$draft` before submission;
        // `onSuccessUpdateEmail` then atomically moves it to Sent.
        let folders = self.list_folders().await?;
        let (drafts_id, sent_id) = find_drafts_and_sent(&folders)?;

        let client = self.client.lock().await;
        let drafts_mailbox = drafts_id.backend_key(&self.account_id);
        let sent_mailbox = sent_id.backend_key(&self.account_id);

        // Step 1: upload + Email/import in one helper. The blob lives
        // in the JMAP file store; the Email object references it.
        // Targets the session's primary mail account (see
        // `save_draft` for why QSL's local AccountId must not be
        // used here).
        let email = client
            .email_import(
                raw_rfc822.to_vec(),
                [drafts_mailbox],
                Some(["$draft"]),
                None,
            )
            .await
            .map_err(map_jmap_error)?;
        let email_id = email
            .id()
            .ok_or_else(|| MailError::Protocol("Email/import returned no id".into()))?
            .to_string();

        // Step 2: EmailSubmission/set with onSuccessUpdateEmail. Build
        // the request manually — the high-level `email_submission_create`
        // helper doesn't expose `onSuccessUpdateEmail`, which is the
        // mechanism Fastmail uses to atomically move the email out of
        // Drafts and into Sent on submission success.
        let mut request = client.build();
        let set_req = request.set_email_submission();
        let create_id = set_req
            .create()
            .email_id(&email_id)
            .identity_id(self.identity_id.as_ref())
            .create_id()
            .ok_or_else(|| {
                MailError::Protocol("EmailSubmission/set: builder did not yield create_id".into())
            })?;
        set_req
            .arguments()
            .on_success_update_email(&create_id)
            .keyword("$draft", false)
            .mailbox_id(drafts_mailbox, false)
            .mailbox_id(sent_mailbox, true);
        request
            .send_set_email_submission()
            .await
            .map_err(map_jmap_error)?;

        debug!(%email_id, drafts = %drafts_id.0, sent = %sent_id.0, "JMAP submit_message ok");

        // Canonical `MessageId` arrives via the existing JMAP EventSource
        // push pipeline (Phase 1 Week 11) — no synthetic local id here.
        Ok(None)
    }
}

// ---------- helpers ----------

fn mailbox_to_folder(mb: jmap_client::mailbox::Mailbox, account: &AccountId) -> Folder {
    let id = mb.id().map(str::to_string).unwrap_or_default();
    let name = mb.name().map(str::to_string).unwrap_or_default();
    let role = jmap_role_to_folder_role(&mb.role());
    let parent = mb.parent_id().map(|p| FolderId::scoped(account, p));
    // `total_emails()` / `unread_emails()` already default to 0 on
    // missing fields; they return `usize`.
    let unread = mb.unread_emails() as u32;
    let total = mb.total_emails() as u32;

    Folder {
        // Account-scoped: JMAP mailbox ids are only unique within an
        // account, and `folders.id` is a global key locally.
        id: FolderId::scoped(account, &id),
        account_id: account.clone(),
        name: name.clone(),
        // JMAP mailboxes are flat at the wire level; parent info is a
        // reference. For display, we leave `path` == `name` — the UI can
        // reconstruct a tree from `parent` if it wants hierarchy.
        path: name,
        role,
        unread_count: unread,
        total_count: total,
        parent,
    }
}

fn email_to_headers(
    email: &jmap_client::email::Email,
    folder: &FolderId,
    account: &AccountId,
) -> MessageHeaders {
    let id = MessageId(email.id().unwrap_or_default().to_string());
    let subject = email.subject().unwrap_or_default().to_string();
    let rfc822_message_id = email
        .message_id()
        .and_then(|list| list.first())
        .map(|s| format!("<{s}>"));
    let date = email
        .received_at()
        .or_else(|| email.sent_at())
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
        .unwrap_or_else(Utc::now);

    let flags = keywords_to_flags(&email.keywords());
    let snippet = email.preview().unwrap_or_default().to_string();
    let size = u32::try_from(email.size()).unwrap_or(u32::MAX);

    let in_reply_to = email
        .in_reply_to()
        .and_then(|list| list.first())
        .map(|s| format!("<{s}>"));
    let references: Vec<String> = email
        .references()
        .map(|list| list.iter().map(|s| format!("<{s}>")).collect())
        .unwrap_or_default();

    MessageHeaders {
        id,
        account_id: account.clone(),
        folder_id: folder.clone(),
        thread_id: None::<ThreadId>,
        rfc822_message_id,
        subject,
        from: translate_addrs(email.from()),
        reply_to: translate_addrs(email.reply_to()),
        to: translate_addrs(email.to()),
        cc: translate_addrs(email.cc()),
        bcc: translate_addrs(email.bcc()),
        date,
        flags,
        // JMAP mailboxes serve as both folders and labels; a message in
        // multiple mailboxes shows up in each. For QSL, the
        // secondary mailboxes become labels.
        labels: email.mailbox_ids().iter().map(|s| s.to_string()).collect(),
        snippet,
        size,
        has_attachments: email.has_attachment(),
        in_reply_to,
        references,
    }
}

fn translate_addrs(addrs: Option<&[jmap_client::email::EmailAddress]>) -> Vec<EmailAddress> {
    let Some(list) = addrs else {
        return Vec::new();
    };
    list.iter()
        .map(|a| EmailAddress {
            address: a.email().to_string(),
            display_name: a.name().map(str::to_string),
        })
        .collect()
}

/// Translate a `MessageFlags` set into a list of `(keyword, set)`
/// tuples for `Email/set`. `set_to` is the second tuple element —
/// `true` for the "add" path, `false` for the "remove" path.
/// Skips any flag that's `false` so we don't issue no-op patches.
fn flag_diff(flags: &MessageFlags, set_to: bool) -> Vec<(String, bool)> {
    let mut out = Vec::with_capacity(5);
    if flags.seen {
        out.push(("$seen".to_string(), set_to));
    }
    if flags.flagged {
        out.push(("$flagged".to_string(), set_to));
    }
    if flags.answered {
        out.push(("$answered".to_string(), set_to));
    }
    if flags.draft {
        out.push(("$draft".to_string(), set_to));
    }
    if flags.forwarded {
        out.push(("$forwarded".to_string(), set_to));
    }
    out
}

fn keywords_to_flags(keywords: &[&str]) -> MessageFlags {
    let mut flags = MessageFlags::default();
    for k in keywords {
        match k.to_ascii_lowercase().as_str() {
            "$seen" => flags.seen = true,
            "$flagged" => flags.flagged = true,
            "$answered" => flags.answered = true,
            "$draft" => flags.draft = true,
            "$forwarded" => flags.forwarded = true,
            _ => {}
        }
    }
    flags
}

/// Translate JMAP's built-in mailbox roles (RFC 8621 §2) into QSL's
/// `FolderRole`. `All` and `Flagged` don't exist as standard JMAP roles
/// — Gmail's "All Mail" and "Starred" are IMAP-specific concepts that
/// show up in JMAP as custom labels, which we surface as the None
/// default here and leave for client-side classification.
fn jmap_role_to_folder_role(role: &jmap_client::mailbox::Role) -> Option<FolderRole> {
    use jmap_client::mailbox::Role as R;
    match role {
        R::Inbox => Some(FolderRole::Inbox),
        R::Sent => Some(FolderRole::Sent),
        R::Drafts => Some(FolderRole::Drafts),
        R::Trash => Some(FolderRole::Trash),
        R::Junk => Some(FolderRole::Spam),
        R::Archive => Some(FolderRole::Archive),
        R::Important => Some(FolderRole::Important),
        R::Other(_) | R::None => None,
    }
}

/// Pull the Drafts and Sent mailbox ids out of a folder list. JMAP send
/// requires both: the email is created in Drafts with `$draft`, then
/// `onSuccessUpdateEmail` flips it into Sent on submission success. The
/// look-up runs per-send (one extra JMAP round-trip via `list_folders`)
/// rather than caching, since Fastmail mailboxes can be added/removed
/// out-of-band and we want to use the live ids.
fn find_drafts_and_sent(folders: &[Folder]) -> Result<(FolderId, FolderId), MailError> {
    let mut drafts: Option<FolderId> = None;
    let mut sent: Option<FolderId> = None;
    for f in folders {
        match f.role {
            Some(FolderRole::Drafts) => drafts = Some(f.id.clone()),
            Some(FolderRole::Sent) => sent = Some(f.id.clone()),
            _ => {}
        }
    }
    let drafts =
        drafts.ok_or_else(|| MailError::NotFound("JMAP submit: no Drafts mailbox".into()))?;
    let sent = sent.ok_or_else(|| MailError::NotFound("JMAP submit: no Sent mailbox".into()))?;
    Ok((drafts, sent))
}

/// Translate `jmap_client::Error` into our coarse `MailError` categories.
/// The outbox drain at `qsl_sync::outbox_drain::drain_one` doesn't switch
/// on the variant for retry-vs-DLQ decisions (it just retries up to
/// `MAX_ATTEMPTS`), so this mapping is for diagnostics. Source variants:
/// `~/.cargo/registry/src/index.crates.io-…/jmap-client-0.4.1/src/lib.rs:422`.
fn map_jmap_error(e: jmap_client::Error) -> MailError {
    use jmap_client::Error::*;
    match e {
        Transport(re) => MailError::Network(re.to_string()),
        Parse(je) => MailError::Protocol(format!("JMAP response parse: {je}")),
        Internal(s) => MailError::Other(format!("JMAP internal: {s}")),
        Problem(pd) => match pd.status {
            Some(401) | Some(403) => MailError::Auth(format!("JMAP problem: {pd}")),
            _ => MailError::ServerRejected(format!("JMAP problem: {pd}")),
        },
        Server(s) => {
            let lower = s.to_ascii_lowercase();
            if lower.contains("401") || lower.contains("403") || lower.contains("unauthorized") {
                MailError::Auth(s)
            } else {
                MailError::ServerRejected(s)
            }
        }
        Method(m) => MailError::ServerRejected(format!("JMAP method error: {m}")),
        Set(se) => MailError::ServerRejected(format!("JMAP set error: {se}")),
    }
}

/// True if the given account kind is backed by this adapter.
pub fn handles(kind: &BackendKind) -> bool {
    matches!(kind, BackendKind::Jmap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmap_client::mailbox::Role as R;

    #[test]
    fn role_translation_covers_known_jmap_roles() {
        assert_eq!(jmap_role_to_folder_role(&R::Inbox), Some(FolderRole::Inbox));
        assert_eq!(jmap_role_to_folder_role(&R::Sent), Some(FolderRole::Sent));
        assert_eq!(
            jmap_role_to_folder_role(&R::Drafts),
            Some(FolderRole::Drafts)
        );
        assert_eq!(jmap_role_to_folder_role(&R::Trash), Some(FolderRole::Trash));
        // Fastmail / JMAP uses "Junk"; QSL normalizes to Spam.
        assert_eq!(jmap_role_to_folder_role(&R::Junk), Some(FolderRole::Spam));
        assert_eq!(
            jmap_role_to_folder_role(&R::Archive),
            Some(FolderRole::Archive)
        );
        assert_eq!(jmap_role_to_folder_role(&R::None), None);
        assert_eq!(jmap_role_to_folder_role(&R::Other("X".into())), None);
    }

    #[test]
    fn handles_jmap_only() {
        assert!(handles(&BackendKind::Jmap));
        assert!(!handles(&BackendKind::ImapSmtp));
    }

    fn folder(id: &str, role: Option<FolderRole>) -> Folder {
        Folder {
            id: FolderId(id.into()),
            account_id: AccountId("acc-1".into()),
            name: id.into(),
            path: id.into(),
            role,
            unread_count: 0,
            total_count: 0,
            parent: None,
        }
    }

    #[test]
    fn find_drafts_and_sent_picks_role_matched_folders() {
        let folders = vec![
            folder("inbox-1", Some(FolderRole::Inbox)),
            folder("drafts-1", Some(FolderRole::Drafts)),
            folder("sent-1", Some(FolderRole::Sent)),
            folder("custom-1", None),
        ];
        let (drafts, sent) = find_drafts_and_sent(&folders).expect("both roles present");
        assert_eq!(drafts.0, "drafts-1");
        assert_eq!(sent.0, "sent-1");
    }

    #[test]
    fn find_drafts_and_sent_errors_when_drafts_missing() {
        let folders = vec![folder("sent-1", Some(FolderRole::Sent))];
        let err = find_drafts_and_sent(&folders).unwrap_err();
        assert!(
            matches!(err, MailError::NotFound(ref s) if s.contains("Drafts")),
            "expected NotFound containing Drafts, got: {err:?}"
        );
    }

    #[test]
    fn find_drafts_and_sent_errors_when_sent_missing() {
        let folders = vec![folder("drafts-1", Some(FolderRole::Drafts))];
        let err = find_drafts_and_sent(&folders).unwrap_err();
        assert!(
            matches!(err, MailError::NotFound(ref s) if s.contains("Sent")),
            "expected NotFound containing Sent, got: {err:?}"
        );
    }

    #[test]
    fn map_jmap_error_parse_is_protocol() {
        let serde_err: serde_json::Error = serde_json::from_str::<u8>("not-json").unwrap_err();
        let mapped = map_jmap_error(jmap_client::Error::Parse(serde_err));
        assert!(matches!(mapped, MailError::Protocol(_)), "{mapped:?}");
    }

    #[test]
    fn map_jmap_error_server_string_with_401_is_auth() {
        let mapped = map_jmap_error(jmap_client::Error::Server("HTTP 401 Unauthorized".into()));
        assert!(matches!(mapped, MailError::Auth(_)), "{mapped:?}");
    }

    #[test]
    fn map_jmap_error_server_string_without_401_is_rejected() {
        let mapped = map_jmap_error(jmap_client::Error::Server("quota exceeded".into()));
        assert!(matches!(mapped, MailError::ServerRejected(_)), "{mapped:?}");
    }

    #[test]
    fn map_jmap_error_internal_is_other() {
        let mapped = map_jmap_error(jmap_client::Error::Internal("oops".into()));
        assert!(matches!(mapped, MailError::Other(_)), "{mapped:?}");
    }
}
