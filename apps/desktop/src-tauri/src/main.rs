// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! QSL desktop shell entry point.
//!
//! Boots Tauri 2, opens the Turso-backed DB, installs [`AppState`] on the
//! Tauri manager, and registers every `qsl-*` command. The Dioxus
//! UI rides in Tauri's webview and calls these commands over the
//! standard `invoke` bridge.
//!
//! # Runtime shape
//!
//! - Tauri owns the event loop and the tokio runtime (via its built-in
//!   `tauri::async_runtime`).
//! - On `setup`, we resolve the OS data directory with `directories`,
//!   open the database, run pending migrations, and hand the handle to
//!   [`AppState`]. The reader pane lives inside the host webview as a
//!   sandboxed `<iframe srcdoc>`, so there's no auxiliary renderer
//!   process to attach. (See `docs/servo-tombstone.md` for the
//!   previous Servo-backed reader implementation.)

mod backend_factory;
mod commands;
mod imap_idle;
mod jmap_push;
mod mailto;
mod reconnect;
mod state;
mod sync_engine;
mod tray;

use std::path::PathBuf;
use std::time::Instant;

use directories::ProjectDirs;
use qsl_storage::{run_migrations, TursoConn};
use tauri::Manager;

use crate::state::AppState;

fn main() {
    let boot_at = Instant::now();
    // Linux webview workaround. webkit2gtk's DMA-BUF renderer asks
    // libgbm for framebuffers; on hybrid AMD/NVIDIA boxes (or any rig
    // where libgbm lands on the NVIDIA proprietary stack) the GBM
    // allocator returns `Invalid argument` because the proprietary
    // driver doesn't expose the format modifiers webkit wants, and the
    // webview paints nothing — the chrome shows but the body is blank.
    // Rolling webkit back to its SHM rendering path bypasses GBM
    // entirely and makes the webview render normally. The path is a
    // shade slower than DMA-BUF on hardware where DMA-BUF actually
    // works, but the performance hit is negligible for an email client.
    //
    // Gated on `is_none()` so a user export still wins, and confined
    // to Linux because macOS / Windows webviews don't go through this
    // path at all.
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            // SAFETY: called pre-main, before any other thread can
            // observe or mutate the process environment.
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
            }
        }
    }

    // Telemetry: route Tauri / plugin logs through `tracing`. Matches
    // the mailcli pattern so operators can use the same `RUST_LOG`
    // filters. `init` returns an error if it has already been called in
    // this process (e.g. a hot-reloaded test harness); we log and
    // continue rather than panic.
    if let Err(e) = qsl_telemetry::init(None) {
        eprintln!("qsl-telemetry: {e}");
    }

    // Install a rustls `CryptoProvider` before any TLS traffic starts.
    // tokio-rustls / hyper-rustls / lettre all reach rustls indirectly;
    // installing `ring` once at startup avoids the auto-pick panic
    // when more than one provider feature is enabled in the dep graph.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        // An earlier call already installed a provider. That's fine;
        // we don't want to panic on hot-reload or double-init.
        tracing::debug!("rustls CryptoProvider was already installed; continuing");
    }

    tauri::Builder::default()
        // Single-instance plugin must be the first plugin registered:
        // it acquires the OS-level lock during plugin init, so a second
        // launch returns from `Builder::run` immediately (passing argv
        // to the running instance) without spinning up the rest of the
        // pipeline. The closure runs *inside the original process*
        // when a second launch attempts to start; we focus the main
        // window so the user sees their existing instance instead of
        // a silent no-op.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            // `LaunchAgent` is the only macOS option the plugin
            // currently exposes; Linux + Windows use their own paths
            // (XDG autostart entry / registry Run key) regardless of
            // this argument. `None` for the args slot — we don't want
            // QSL to launch with extra flags.
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(
            tauri_plugin_window_state::Builder::default()
                // Only persist window state for the long-lived chrome
                // windows. Reader popups have unique labels per
                // message id (`reader-<account>-<uid>-<folder>`), so
                // saving them would accumulate one entry per message
                // ever opened in the state file.
                .with_filter(|label| matches!(label, "main" | "settings"))
                // Skip position. Wayland compositors (KWin, mutter,
                // sway) don't expose absolute window coordinates to
                // applications, so the plugin always sees x=0, y=0;
                // restoring those bogus coords races with the
                // compositor's own placement and produces a window
                // that opens off-screen / on the wrong monitor / at a
                // surprising spot. Size + maximized + fullscreen are
                // honored across compositors and are the bits users
                // actually expect to persist.
                .with_state_flags(
                    tauri_plugin_window_state::StateFlags::SIZE
                        | tauri_plugin_window_state::StateFlags::MAXIMIZED
                        | tauri_plugin_window_state::StateFlags::FULLSCREEN,
                )
                .build(),
        )
        .setup(move |app| {
            // Resolve data dir + open DB on the Tauri async runtime so
            // we don't block the UI thread. `block_on` here is fine: we
            // only do it once at startup, before any window is shown.
            // Tauri's setup hook returns `Box<dyn Error>` (not Send+Sync),
            // while `bootstrap_state` produces the Send+Sync variant so
            // it stays usable in other async contexts — unsize the error
            // explicitly to bridge the two.
            let state = tauri::async_runtime::block_on(bootstrap_state(boot_at))
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;
            app.manage(state);

            // Phase 1 Week 10: kick off a background sync of every
            // configured account so the UI sees fresh mail without the
            // user having to run `mailcli sync` first. Live IDLE
            // watchers are layered on in PR 7b — the engine module
            // already exposes the right seam for them.
            sync_engine::spawn(app.handle().clone());

            // System tray icon. Failure to install isn't fatal — on
            // window managers without StatusNotifierItem support the
            // tray just won't appear, and the main window remains the
            // primary entry point.
            if let Err(e) = tray::install(app.handle()) {
                tracing::warn!("tray install failed: {e}");
            }

            // Wire deep-link handler. The `on_open_url` callback fires
            // whenever the OS hands us a `mailto:` URL — both for
            // already-running instances (single-instance plugin
            // forwards the argv) and for the launching instance via
            // `get_current()`. Cold-start URLs (the OS starts QSL via
            // a mailto link before any window opens) are surfaced
            // through the same callback once the listener is wired,
            // so this single hook covers every path.
            mailto::install(app.handle());

            // Enable the WebKit spell-checker on Linux. The
            // `spellcheck="true"` attribute we set on compose
            // <input>/<textarea> nodes is a per-field opt-in, but
            // webkit2gtk's engine itself is gated by a separate
            // `WebContext` flag that defaults off — so without this
            // call no underlines appear regardless of the attribute.
            // macOS / Windows webviews enable spell-check when the
            // attribute is present, so they don't need this.
            #[cfg(target_os = "linux")]
            if let Some(window) = app.get_webview_window("main") {
                if let Err(e) = window.with_webview(|webview| {
                    use webkit2gtk::{WebContextExt, WebViewExt};
                    let inner = webview.inner();
                    if let Some(ctx) = inner.context() {
                        ctx.set_spell_checking_enabled(true);
                        // Empty languages list ⇒ webkit2gtk picks the
                        // user's locale via $LANG / $LC_MESSAGES,
                        // falling back to the first available
                        // dictionary. Avoids hard-coding "en_US" for
                        // non-English users.
                        ctx.set_spell_checking_languages(&[]);
                    }
                }) {
                    tracing::warn!("spell-check enable failed: {e}");
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::ui_ready,
            commands::ui_log,
            commands::accounts::accounts_list,
            commands::folders::folders_list,
            commands::messages::messages_list,
            commands::messages::messages_list_unified,
            commands::messages::messages_search,
            commands::messages::messages_mark_read,
            commands::messages::messages_flag,
            commands::messages::messages_move,
            commands::messages::messages_archive,
            commands::messages::messages_delete,
            commands::messages::messages_get,
            commands::messages::messages_thread,
            commands::messages::messages_trust_sender,
            commands::messages::messages_load_older,
            commands::messages::messages_refresh_folder,
            commands::messages::messages_send,
            commands::messages::messages_open_in_window,
            commands::messages::messages_open_attachment,
            commands::drafts::drafts_save,
            commands::drafts::drafts_load,
            commands::drafts::drafts_list,
            commands::drafts::drafts_delete,
            commands::reader::open_external_url,
            commands::contacts::contacts_query,
            commands::accounts::accounts_set_display_name,
            commands::accounts::accounts_set_signature,
            commands::accounts::accounts_set_notify_enabled,
            commands::accounts::accounts_remove,
            commands::accounts::accounts_add_oauth,
            commands::settings::settings_open,
            commands::settings::oauth_add_open,
            commands::settings::oauth_add_close,
            commands::settings::oauth_providers_list,
            commands::settings::app_settings_get,
            commands::settings::app_settings_set,
            commands::compose::compose_pick_attachments,
            commands::history_sync::history_sync_start,
            commands::history_sync::history_sync_cancel,
            commands::history_sync::history_sync_list,
            mailto::default_email_client_is,
            mailto::default_email_client_set,
            mailto::default_email_client_unset,
        ])
        .run(tauri::generate_context!())
        .expect("error while running QSL");
}

/// Resolve the OS data directory, open the Turso database, run pending
/// migrations, and build the shared [`AppState`].
///
/// Kept as a free function so the bootstrap logic is testable and so
/// `setup` stays a one-liner.
async fn bootstrap_state(
    boot_at: Instant,
) -> Result<AppState, Box<dyn std::error::Error + Send + Sync>> {
    let data_dir = resolve_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    tracing::info!(data_dir = %data_dir.display(), "qsl desktop: data dir ready");

    let db_path = data_dir.join("qsl.db");
    tracing::info!(db = %db_path.display(), "qsl desktop: opening IPC database");
    let db = TursoConn::open(&db_path).await?;

    // Run migrations on the IPC connection only — they're idempotent
    // at the SQLite layer regardless, but doing it once before the
    // sync connection opens means schema is in place by the time the
    // sync engine touches the file.
    tracing::info!("qsl desktop: running migrations");
    run_migrations(&db).await?;
    // Repair a full-text index lost to a crash mid history-pull.
    // Best-effort: search degrades, the app must still start.
    if let Err(e) = qsl_storage::ensure_fts_index(&db).await {
        tracing::warn!("qsl desktop: FTS index repair failed (search may be unavailable): {e}");
    }

    // Second connection to the same file for the sync engine. WAL
    // mode is enabled by `TursoConn::open`, so reads on `db` won't
    // block while `sync_db` is mid-transaction. See `AppState::sync_db`
    // for the full rationale.
    tracing::info!("qsl desktop: opening sync database");
    let sync_db = TursoConn::open(&db_path).await?;

    tracing::info!(
        data_dir = %data_dir.display(),
        db = %db_path.display(),
        "qsl desktop ready"
    );

    Ok(AppState::new(db, sync_db, data_dir, boot_at))
}

/// Mirror of mailcli's data-dir resolution so both binaries read and
/// write the same Turso file by default.
fn resolve_data_dir() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let dirs =
        ProjectDirs::from("app", "qsl", "qsl").ok_or("could not resolve OS data directory")?;
    Ok(dirs.data_dir().to_path_buf())
}
