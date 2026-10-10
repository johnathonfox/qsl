// SPDX-License-Identifier: Apache-2.0

//! `accounts_*` Tauri commands.
//!
//! See `COMMANDS.md §Accounts` for the catalogue. `accounts_list` is
//! the read path the sidebar consumes; the per-row mutators
//! (`accounts_set_display_name`, `accounts_set_signature`,
//! `accounts_set_notify_enabled`, `accounts_remove`) back the
//! Settings → Accounts tab. `accounts_add_oauth` is still stubbed
//! pending the first-run OAuth flow (PR-O1).

use std::sync::atomic::Ordering;

use chrono::Utc;
use qsl_auth::{revoke_refresh_token, run_loopback_flow, AuthError, ProviderKind, TokenVault};
use qsl_core::{AccountId, BackendKind};
use qsl_ipc::{Account, IpcResult};
use qsl_storage::repos::accounts as accounts_repo;
use qsl_storage::BlobStore;
use serde::Deserialize;
use tauri::{Emitter, State};

use crate::state::AppState;
use crate::sync_engine;

/// Tauri event fired whenever the set of configured accounts changes
/// (add succeeds, remove). Carries no payload — listeners just refetch
/// `accounts_list`. Used by the main window's sidebar + topbar and
/// the Settings → Accounts panel so the UI doesn't lag behind a
/// mutation done from another window. Defined here rather than in
/// `qsl-ipc` because it's a UI-side coordination signal, not part of
/// the public IPC surface other crates depend on.
pub const ACCOUNTS_EVENT: &str = "accounts_changed";

/// `accounts_list` — return every configured account, ordered by
/// `created_at`. Called by the sidebar on window open and by the
/// Settings → Accounts tab.
#[tauri::command]
pub async fn accounts_list(state: State<'_, AppState>) -> IpcResult<Vec<Account>> {
    let db = state.db.lock().await;
    let accounts = accounts_repo::list(&*db).await?;
    tracing::debug!(count = accounts.len(), "accounts_list");
    Ok(accounts)
}

#[derive(Debug, Deserialize)]
pub struct AccountsSetDisplayNameInput {
    pub id: AccountId,
    pub display_name: String,
}

/// `accounts_set_display_name` — rename an account. The display name
/// is the user-facing label in the sidebar; renaming is rename-safe
/// (id stays put, no folder churn).
#[tauri::command]
pub async fn accounts_set_display_name(
    state: State<'_, AppState>,
    input: AccountsSetDisplayNameInput,
) -> IpcResult<()> {
    let db = state.db.lock().await;
    accounts_repo::set_display_name(&*db, &input.id, &input.display_name).await?;
    tracing::info!(account = %input.id.0, "accounts_set_display_name");
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct AccountsSetSignatureInput {
    pub id: AccountId,
    /// `None` / empty string clears the signature.
    pub signature: Option<String>,
}

/// `accounts_set_signature` — patch the per-account signature
/// appended to outbound mail. The compose pane reads this on draft
/// open; existing drafts are not retroactively rewritten.
#[tauri::command]
pub async fn accounts_set_signature(
    state: State<'_, AppState>,
    input: AccountsSetSignatureInput,
) -> IpcResult<()> {
    let db = state.db.lock().await;
    accounts_repo::set_signature(&*db, &input.id, input.signature.as_deref()).await?;
    tracing::info!(account = %input.id.0, "accounts_set_signature");
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct AccountsSetNotifyEnabledInput {
    pub id: AccountId,
    pub enabled: bool,
}

/// `accounts_set_notify_enabled` — toggle whether new-mail
/// notifications fire for this account. Sync continues either way;
/// only the desktop notification bridge consults the flag.
#[tauri::command]
pub async fn accounts_set_notify_enabled(
    state: State<'_, AppState>,
    input: AccountsSetNotifyEnabledInput,
) -> IpcResult<()> {
    let db = state.db.lock().await;
    accounts_repo::set_notify_enabled(&*db, &input.id, input.enabled).await?;
    tracing::info!(account = %input.id.0, enabled = input.enabled, "accounts_set_notify_enabled");
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct AccountsAddOauthInput {
    /// Provider slug as known to `qsl_auth::lookup` — e.g. `"gmail"`,
    /// `"fastmail"`. The Dioxus side picks from `qsl_auth::provider::builtin`.
    pub provider: String,
    /// Email address the user typed. Becomes the persisted account's
    /// `email_address` and is sent as `login_hint` to the provider so
    /// the OAuth picker lands on the right mailbox.
    pub email: String,
}

/// `accounts_add_oauth` — drive the OAuth2 + PKCE loopback flow for
/// `provider`, persist the resulting account row + refresh token,
/// and kick off a one-shot bootstrap sync so the sidebar populates
/// with folders + recent mail.
///
/// The command blocks for the full flow duration (default cap 5
/// minutes — `qsl_auth::flow::DEFAULT_FLOW_TIMEOUT`) because that's
/// how long we're willing to wait for the user to approve in the
/// browser. The Dioxus side renders a "Waiting for browser approval…"
/// state for the duration; on resolution it closes the oauth-add
/// window and the main window's sidebar refetches via the existing
/// `sync_event` listener.
///
/// Re-add semantics: if the email already has an account row,
/// `update` overwrites it (and the new refresh token replaces the
/// old keychain entry). Same shape as `mailcli auth add`.
#[tauri::command]
pub async fn accounts_add_oauth(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    input: AccountsAddOauthInput,
) -> IpcResult<Account> {
    let AccountsAddOauthInput { provider, email } = input;
    let provider_obj = qsl_auth::lookup(&provider).ok_or_else(|| {
        qsl_ipc::IpcError::new(
            qsl_ipc::IpcErrorKind::NotFound,
            format!("unknown provider: {provider}"),
        )
    })?;
    // Validate before the browser round-trip: the id becomes the
    // keychain entry, the blob directory, and the folder-id prefix.
    let account_id = AccountId::for_provider(&provider, &email).map_err(|reason| {
        qsl_ipc::IpcError::new(
            qsl_ipc::IpcErrorKind::Internal,
            format!("invalid account: {reason}"),
        )
    })?;
    let email = email.trim().to_string();

    tracing::info!(provider = %provider, %email, "accounts_add_oauth: starting OAuth + PKCE flow");
    let outcome = run_loopback_flow(provider_obj, Some(&email))
        .await
        .map_err(map_auth_error)?;

    let refresh = outcome.tokens.refresh.ok_or_else(|| {
        qsl_ipc::IpcError::new(
            qsl_ipc::IpcErrorKind::Internal,
            "provider returned no refresh_token (user must include offline_access scope)"
                .to_string(),
        )
    })?;

    let kind = match provider_obj.profile().kind {
        ProviderKind::ImapSmtp => BackendKind::ImapSmtp,
        ProviderKind::Jmap => BackendKind::Jmap,
        _ => {
            return Err(qsl_ipc::IpcError::new(
                qsl_ipc::IpcErrorKind::Internal,
                format!("provider {provider} uses an unsupported backend kind"),
            ));
        }
    };

    let account = Account {
        id: account_id.clone(),
        kind: kind.clone(),
        display_name: email.clone(),
        email_address: email.clone(),
        created_at: Utc::now(),
        signature: None,
        notify_enabled: true,
    };

    {
        let db = state.db.lock().await;
        match accounts_repo::find(&*db, &account.id).await? {
            Some(_) => {
                tracing::info!(account = %account.id.0, "accounts_add_oauth: re-add — updating");
                accounts_repo::update(&*db, &account).await?;
            }
            None => {
                accounts_repo::insert(&*db, &account).await?;
            }
        }
    }

    tracing::info!(account = %account_id.0, "accounts_add_oauth: persisting refresh token to OS keychain");
    let vault = TokenVault::new();
    vault.put(&account_id, &refresh).await.map_err(|e| {
        qsl_ipc::IpcError::new(
            qsl_ipc::IpcErrorKind::Internal,
            format!("persist refresh token: {e}"),
        )
    })?;
    tracing::info!(account = %account_id.0, "accounts_add_oauth: keychain entry written");

    // Kick a bootstrap sync. `sync_one_account` walks list_folders →
    // sync_folder per folder and emits a `sync_event` for each, which
    // the UI's existing listener consumes to bump `sync_tick` and
    // refetch the sidebar's account list. Failure is non-fatal: the
    // account row is already persisted, the user can hit refresh.
    //
    // Also re-emits `accounts_changed` once the spawned sync returns
    // so the UI gets one final "everything is ready" refetch trigger.
    // Without this, the rapid burst of per-folder `sync_event`s gets
    // coalesced by Dioxus into a single refetch that occasionally
    // lands while the last sync_folder is still committing — symptom
    // is "only some of my folders showed up after add until I
    // reloaded." The `accounts_changed` arrives strictly AFTER the
    // full sync_account commit, breaking the race.
    tracing::info!(account = %account_id.0, "accounts_add_oauth: kicking off bootstrap sync (background)");
    let blobs = BlobStore::new(state.data_dir.join("blobs"));
    let app_for_sync = app.clone();
    let account_id_for_sync = account_id.clone();
    tauri::async_runtime::spawn(async move {
        sync_engine::sync_one_account(&app_for_sync, &blobs, &account_id_for_sync).await;
        tracing::info!(account = %account_id_for_sync.0, "accounts_add_oauth: bootstrap sync finished");
        if let Err(e) = app_for_sync.emit(ACCOUNTS_EVENT, ()) {
            tracing::warn!(
                account = %account_id_for_sync.0,
                "post-bootstrap re-emit accounts_changed failed: {e}"
            );
        }
    });

    if let Err(e) = app.emit(ACCOUNTS_EVENT, ()) {
        tracing::warn!("accounts_add_oauth: emit accounts_changed failed: {e}");
    }
    // Wake the sync engine so the new account gets IDLE / push
    // watchers now rather than after the next app restart.
    state.accounts_changed.notify_one();

    tracing::info!(
        account = %account.id.0,
        scopes = outcome.granted_scopes.len(),
        "accounts_add_oauth: complete"
    );
    Ok(account)
}

fn map_auth_error(e: AuthError) -> qsl_ipc::IpcError {
    use qsl_ipc::IpcErrorKind;
    let kind = match &e {
        AuthError::Browser(_) => IpcErrorKind::Internal,
        AuthError::AuthResponse(_) => IpcErrorKind::Permission,
        AuthError::TokenExchange(_) => IpcErrorKind::Permission,
        _ => IpcErrorKind::Internal,
    };
    qsl_ipc::IpcError::new(kind, format!("OAuth flow: {e}"))
}

#[derive(Debug, Deserialize)]
pub struct AccountsRemoveInput {
    pub id: AccountId,
}

/// `accounts_remove` — delete an account row.
///
/// Order matters here. Six classes of state hang off an account:
///
///   1. **In-flight history-sync drivers.** Their cancel flags live in
///      `state.history_cancellers`; the driver task notices the flip
///      between chunks and bails. We trip every flag for this
///      account *before* touching the database so that any chunk in
///      flight when the FK CASCADE drops the messages doesn't waste
///      an extra round-trip.
///   2. **Per-(account, folder) and per-account in-memory maps.**
///      `history_cancellers` and `history_account_locks` are keyed by
///      `AccountId`; we drain them so a re-add of the same email
///      doesn't inherit a stale token.
///   3. **Cached `MailBackend` handle.** Cleared so a re-add doesn't
///      hit the stale handle still pointing at the removed account's
///      access token.
///   4. **Refresh token in the OS keychain + at the OAuth provider.**
///      We POST to the provider's RFC 7009 revocation endpoint
///      best-effort (5-second timeout, never blocking — see
///      `qsl_auth::revoke_refresh_token`) so a previously-exfiltrated
///      token becomes useless server-side, then delete the libsecret
///      entry under `com.qsl.app/<provider>:<email>`. Without this
///      step the keychain entry orphaned across removes, leaving
///      stale credentials around forever.
///   5. **On-disk message bodies under
///      `<data_dir>/blobs/<account_id>/`**. The DB CASCADE drops the
///      `messages` rows but can't reach the filesystem. Without this
///      step, the body files linger as orphans until `mailcli reset`.
///   6. **Global autocomplete `contacts_v1`** if this is the last
///      account. The table doesn't carry an `account_id` column —
///      contacts dedup by email globally — so per-account cleanup
///      isn't possible without a schema change. When zero accounts
///      remain post-delete we truncate the table so the user's
///      correspondent list doesn't outlive every account they had
///      configured.
///
/// Then the database row goes. With `PRAGMA foreign_keys=ON` (set in
/// `TursoConn::open`) the schema's `ON DELETE CASCADE` clauses fire,
/// dropping every folder / thread / message / attachment / outbox /
/// contact / draft / remote_content_opt_in / history_sync_state row
/// belonging to this account. Before the pragma flip those clauses
/// were dead code; migration 0011 cleans up any pre-existing orphans
/// from that era so a re-add doesn't collide on UNIQUE indexes
/// (`folders_account_path`, `contacts_account_address`).
///
/// Fires `ACCOUNTS_EVENT` so the main window's sidebar + topbar
/// refetch immediately rather than waiting for the user to manually
/// refresh.
#[tauri::command]
pub async fn accounts_remove(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    input: AccountsRemoveInput,
) -> IpcResult<()> {
    tracing::debug!(id = %input.id.0, "ipc: accounts_remove");
    // Refuse ids that don't name an existing account *before* any
    // side effect. An empty id used to sail through: the row delete
    // was a no-op, but `BlobStore::delete_account("")` resolved to
    // the blob root and `remove_dir_all`'d every account's cached
    // bodies.
    if input.id.0.trim().is_empty() {
        return Err(qsl_ipc::IpcError::new(
            qsl_ipc::IpcErrorKind::NotFound,
            "accounts_remove: empty account id".to_string(),
        ));
    }
    {
        let db = state.db.lock().await;
        accounts_repo::get(&*db, &input.id).await?;
    }
    {
        let mut cancellers = state.history_cancellers.lock().await;
        let to_drop: Vec<_> = cancellers
            .keys()
            .filter(|(account, _)| account == &input.id)
            .cloned()
            .collect();
        for key in &to_drop {
            if let Some(flag) = cancellers.get(key) {
                flag.store(true, Ordering::SeqCst);
            }
        }
        for key in &to_drop {
            cancellers.remove(key);
        }
        if !to_drop.is_empty() {
            tracing::info!(
                account = %input.id.0,
                cancelled = to_drop.len(),
                "accounts_remove: signalled history-sync drivers to bail"
            );
        }
    }
    state.history_account_locks.lock().await.remove(&input.id);
    state.backends.lock().await.remove(&input.id);

    revoke_and_delete_keychain(&input.id).await;

    let db = state.db.lock().await;
    accounts_repo::delete(&*db, &input.id).await?;
    let remaining = accounts_repo::list(&*db).await?.len();
    if remaining == 0 {
        if let Err(e) = qsl_storage::repos::contacts::clear_all(&*db).await {
            tracing::warn!("accounts_remove: contacts_v1 truncate failed (continuing): {e}");
        }
    }
    drop(db);

    let blobs = BlobStore::new(state.data_dir.join("blobs"));
    if let Err(e) = blobs.delete_account(&input.id).await {
        tracing::warn!(
            account = %input.id.0,
            "accounts_remove: blob dir cleanup failed (continuing): {e}"
        );
    }

    if let Err(e) = app.emit(ACCOUNTS_EVENT, ()) {
        tracing::warn!("accounts_remove: emit accounts_changed failed: {e}");
    }
    state.accounts_changed.notify_one();
    tracing::info!(
        account = %input.id.0,
        last_account = remaining == 0,
        "accounts_remove"
    );
    Ok(())
}

/// Best-effort token revocation + keychain cleanup for `accounts_remove`.
/// Failures are logged and swallowed — local cleanup must succeed even
/// if the user is offline or the provider is 5xxing.
///
/// AccountId shape is `<provider_slug>:<email>` (set at add time in
/// `accounts_add_oauth`); we split on the first colon to recover the
/// slug.
async fn revoke_and_delete_keychain(account: &AccountId) {
    let vault = TokenVault::new();

    // Provider lookup is best-effort. An unrecognized slug (e.g. an
    // account row that predates a provider rename) means we skip the
    // network revoke but still try the keychain delete below.
    let provider_slug = account.0.split_once(':').map(|(p, _)| p);
    let provider = provider_slug.and_then(qsl_auth::lookup);

    if let Some(provider) = provider {
        match vault.get(account).await {
            Ok(refresh) => {
                if let Err(e) = revoke_refresh_token(provider, &refresh).await {
                    // Non-fatal: token will become unusable as soon as the
                    // keychain entry is gone (no way to ask for a new
                    // access token), and the refresh token's natural
                    // expiry will eventually clean up server-side.
                    tracing::warn!(
                        account = %account.0,
                        "accounts_remove: provider revoke failed (continuing): {e}"
                    );
                }
            }
            Err(AuthError::Keyring(_)) => {
                tracing::debug!(
                    account = %account.0,
                    "accounts_remove: no keychain entry to revoke"
                );
            }
            Err(e) => {
                tracing::warn!(
                    account = %account.0,
                    "accounts_remove: keychain read failed (skipping revoke): {e}"
                );
            }
        }
    } else {
        tracing::debug!(
            account = %account.0,
            "accounts_remove: unknown provider slug; skipping server-side revoke"
        );
    }

    if let Err(e) = vault.delete(account).await {
        tracing::warn!(
            account = %account.0,
            "accounts_remove: keychain delete failed: {e}"
        );
    }
}
