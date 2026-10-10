// SPDX-License-Identifier: Apache-2.0

//! `settings_*` and `app_settings_*` Tauri commands.
//!
//! Two pieces:
//!
//!   - `settings_open` pops a dedicated Settings window mounting
//!     the Dioxus `SettingsApp` route. Mirrors the popup-reader
//!     pattern: build a `WebviewWindowBuilder` with `__QSL_VIEW__ =
//!     'settings'` injected via `initialization_script`, the Dioxus
//!     root branches on that and mounts a different component tree.
//!     A repeat call focuses the existing window.
//!
//!   - `app_settings_get` / `app_settings_set` are thin wrappers
//!     around the `app_settings_v1` k/v table (Appearance / Privacy
//!     tab state — theme, density, "always load remote images"
//!     master toggle).

use qsl_ipc::IpcResult;
use qsl_storage::repos::app_settings as app_settings_repo;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};

use crate::state::AppState;

/// Tauri event name emitted whenever `app_settings_set` writes a
/// value. Payload is `AppSettingsChangedPayload`. The main-window UI
/// subscribes so theme / density / privacy radio flips in the
/// Settings window apply live without a restart.
pub const APP_SETTINGS_CHANGED: &str = "app_settings_changed";

#[derive(Debug, Clone, Serialize)]
pub struct AppSettingsChangedPayload {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct AppSettingsGetInput {
    pub key: String,
}

/// `app_settings_get` — read a global setting key. Returns `None`
/// (serialized as `null`) when the key has never been written; the
/// UI is responsible for defaulting.
#[tauri::command]
pub async fn app_settings_get(
    state: State<'_, AppState>,
    input: AppSettingsGetInput,
) -> IpcResult<Option<String>> {
    let db = state.db.lock().await;
    let value = app_settings_repo::get(&*db, &input.key).await?;
    Ok(value)
}

#[derive(Debug, Deserialize)]
pub struct AppSettingsSetInput {
    pub key: String,
    pub value: String,
}

/// `app_settings_set` — upsert a global setting key, then broadcast
/// the change to every Tauri window so live consumers (theme + density
/// on the main pane, etc.) can re-read without polling.
#[tauri::command]
pub async fn app_settings_set<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    input: AppSettingsSetInput,
) -> IpcResult<()> {
    {
        let db = state.db.lock().await;
        app_settings_repo::set(&*db, &input.key, &input.value).await?;
    }
    tracing::info!(
        key = %input.key,
        value = %input.value,
        "app_settings_set"
    );
    let payload = AppSettingsChangedPayload {
        key: input.key,
        value: input.value,
    };
    if let Err(e) = app.emit(APP_SETTINGS_CHANGED, payload) {
        // Emit failure shouldn't block the write — we already
        // persisted; the next consumer will read on next mount.
        tracing::warn!(error = %e, "app_settings_set: emit failed");
    }
    Ok(())
}

/// `settings_open` — show the Settings window. Idempotent: if the
/// window already exists this just brings it to the front.
///
/// The window mounts a fresh `index.html` with
/// `window.__QSL_VIEW__ = 'settings'` set before wasm boots; the
/// Dioxus root branches on that and mounts `SettingsApp` instead of
/// the three-pane shell.
#[tauri::command]
pub async fn settings_open<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> IpcResult<()> {
    open_view_window(&app, "settings", "QSL — Settings", 720.0, 560.0)
}

/// `oauth_add_open` — show the first-run / add-account window. Same
/// pattern as `settings_open`: a labelled secondary window with
/// `__QSL_VIEW__ = 'oauth-add'` injected so the Dioxus root mounts
/// the `OAuthAddApp` route. The window itself just renders the
/// provider picker; the actual flow runs inside the
/// `accounts_add_oauth` command.
#[tauri::command]
pub async fn oauth_add_open<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> IpcResult<()> {
    open_view_window(&app, "oauth-add", "QSL — Add account", 520.0, 460.0)
}

/// `oauth_add_close` — close the add-account window from its own
/// wasm side after success / cancel.
///
/// Why a host-side command instead of JS `window.close()`: on
/// webkit2gtk, calling `window.close()` from inside a Tauri-owned
/// webview window often unloads the page (clearing the Dioxus root)
/// without actually closing the GTK window. The user sees a blank
/// shell with the title bar still up. Going through Tauri's
/// `WebviewWindow::close` does the right thing on every platform.
/// `core:window:allow-close` in `capabilities/default.json` already
/// covers the equivalent JS path; this command makes the Rust side
/// the single source of truth.
///
/// Also re-emits `accounts_changed` as a defensive second emit. The
/// authoritative emit happens inside `accounts_add_oauth` right after
/// the row + token are persisted, but the main window has been seen
/// to miss it on a fresh-launch path (sidebar stuck on the empty
/// state until the user manually reloaded). Re-emitting here, after
/// the OAuth-add window has finished its work and the host is back
/// in a quiet state, gives the main window a second chance — at
/// worst the event arrives twice and the sidebar refetches twice,
/// which is cheap. Cancel paths also hit this emit; there's no
/// account row change in that case but a redundant refetch is
/// harmless.
#[tauri::command]
pub async fn oauth_add_close<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> IpcResult<()> {
    use tauri::Manager;
    if let Some(window) = app.get_webview_window("oauth-add") {
        if let Err(e) = window.close() {
            tracing::warn!(error = %e, "oauth_add_close: WebviewWindow::close failed");
        }
    }
    if let Err(e) = app.emit(crate::commands::accounts::ACCOUNTS_EVENT, ()) {
        tracing::warn!("oauth_add_close: re-emit accounts_changed failed: {e}");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct OauthProviderInfo {
    pub slug: String,
    pub name: String,
}

/// `oauth_providers_list` — return the built-in OAuth providers in
/// the order the picker should display them. Sourced from
/// `qsl_auth::provider::builtin` so the host stays the source of
/// truth; the UI has no compile-time knowledge of which providers
/// exist.
#[tauri::command]
pub async fn oauth_providers_list() -> IpcResult<Vec<OauthProviderInfo>> {
    let providers = qsl_auth::provider::builtin()
        .iter()
        .map(|p| OauthProviderInfo {
            slug: p.profile().slug.to_string(),
            name: p.profile().name.to_string(),
        })
        .collect();
    Ok(providers)
}

fn open_view_window<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    label: &str,
    title: &str,
    width: f64,
    height: f64,
) -> IpcResult<()> {
    use tauri::Manager;

    if let Some(existing) = app.get_webview_window(label) {
        if let Err(e) = existing.set_focus() {
            tracing::warn!(window = %label, error = %e, "open_view_window: set_focus failed");
        }
        return Ok(());
    }

    let init_script = format!(
        "window.__QSL_VIEW__ = {};",
        serde_json::Value::String(label.to_string())
    );
    let _window =
        tauri::WebviewWindowBuilder::new(app, label, tauri::WebviewUrl::App("index.html".into()))
            .title(title)
            .inner_size(width, height)
            .initialization_script(&init_script)
            .devtools(cfg!(debug_assertions))
            .build()
            .map_err(|e| {
                qsl_ipc::IpcError::new(
                    qsl_ipc::IpcErrorKind::Internal,
                    format!("create {label} window: {e}"),
                )
            })?;

    tracing::info!(window = %label, "open_view_window: built");
    Ok(())
}
