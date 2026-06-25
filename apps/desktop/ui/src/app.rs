// SPDX-License-Identifier: Apache-2.0

//! Root Dioxus component for the QSL UI (wasm32-only).
//!
//! Phase 0 Week 5 renders a three-pane layout:
//!
//!   ┌──────────┬─────────────┬────────────────────┐
//!   │ Sidebar  │ Message     │ Reader pane        │
//!   │ accounts │ list for    │ headers + text/    │
//!   │ + folders│ selected    │ plain body         │
//!   │          │ folder      │                    │
//!   └──────────┴─────────────┴────────────────────┘
//!
//! All three panes are driven by global signals (selected account,
//! selected folder, selected message). Data comes from Tauri commands
//! over the `window.__TAURI_INTERNALS__.invoke` bridge; HTML
//! rendering via Servo arrives in Week 6.

use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use qsl_ipc::{
    Account, AccountId, Attachment, Contact, Draft, DraftAttachment, DraftBodyKind, DraftId,
    EmailAddress, Folder, FolderId, MessageHeaders, MessageId, MessagePage, RenderedMessage,
    SortOrder, SyncEvent,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Stylesheet bundled into the wasm output. The `asset!` macro
/// hashes the file at compile time, copies it into the dx output
/// directory, and gives us back a stable URL — the older
/// `Dioxus.toml [web.resource] style = [...]` entry injects the
/// `<link>` tag but doesn't actually copy the file in dx 0.7, so
/// without `asset!` the stylesheet 404s and the UI renders
/// unstyled. Linked in `App()` via `document::Stylesheet`.
pub(crate) const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

// ---------- Tauri bridge ----------

// `window.__TAURI_INTERNALS__.invoke` is the stable IPC hook Tauri 2
// exposes on every window without configuration. The `window.__TAURI__`
// convenience namespace is only bound when `app.withGlobalTauri: true`
// is set in `tauri.conf.json`, which we don't enable — so reach for the
// internal hook directly. This is exactly what `@tauri-apps/api`'s
// `invoke()` wraps under the hood.
//
// `tauriListen` mirrors `@tauri-apps/api/event#listen`: registers the
// Rust callback via `transformCallback` (which assigns it a numeric id
// the Rust side can later use to unlisten) and tells the event plugin
// to start delivering. We use the same `kind: 'Any'` target the JS API
// defaults to so events emitted from any window reach this listener.
#[wasm_bindgen(inline_js = r#"
    export async function coreInvoke(cmd, args) {
        return await window.__TAURI_INTERNALS__.invoke(cmd, args);
    }
    export async function tauriListen(event, handler) {
        // Tauri's event hub delivers `{ event, id, payload }` to the
        // wrapped callback. Strip the wrapper before calling into
        // wasm so the Rust side gets just the typed payload — every
        // current consumer wants the payload, not the metadata.
        const wrapped = function(raw) {
            try { handler(raw && raw.payload); }
            catch (e) { console.warn('event handler:', e); }
        };
        const cbId = window.__TAURI_INTERNALS__.transformCallback(wrapped);
        return await window.__TAURI_INTERNALS__.invoke('plugin:event|listen', {
            event,
            target: { kind: 'Any' },
            handler: cbId,
        });
    }

    // Returns the popup-window message id, or null when this isn't
    // a popup. The Tauri `messages_open_in_window` command sets
    // `window.__QSL_READER_ID__` via initialization_script before
    // the wasm bundle boots — the Dioxus root reads it and mounts
    // the reader-only component instead of the three-pane shell.
    export function readerWindowMessageId() {
        return window.__QSL_READER_ID__ || null;
    }

    // Returns the JSON-serialized RenderedMessage the Tauri command
    // pre-fetched for this popup, or null when the preload isn't
    // available (older host, fetch failed, etc.). Stringifying on
    // the JS side means the wasm code can deserialize through the
    // same serde path it uses for IPC results.
    export function readerWindowPreload() {
        return window.__QSL_READER_PRELOAD__
            ? JSON.stringify(window.__QSL_READER_PRELOAD__)
            : null;
    }

    // Set the `data-theme` attribute on `<html>` so the CSS rules in
    // `tailwind.css` (the `:root[data-theme="light"]` block + the
    // `prefers-color-scheme` block for `data-theme="system"`) flip
    // tokens. Pass one of "system", "dark", "light"; anything else
    // is treated as "system" so a corrupt setting doesn't lock the
    // user out of the theme they expect.
    export function setRootTheme(theme) {
        const root = document.documentElement;
        if (!root) return;
        const t = (theme === "dark" || theme === "light") ? theme : "system";
        root.setAttribute("data-theme", t);
    }

    // Set the `data-density` attribute on `<html>` so the
    // `:root[data-density="..."]` blocks in tailwind.css apply.
    // "compact" tightens row tokens; "large" relaxes them and bumps
    // type sizes; anything else falls back to the unset default
    // ("comfortable") so a corrupt setting doesn't lock the user
    // into one extreme.
    export function setRootDensity(density) {
        const root = document.documentElement;
        if (!root) return;
        const d = (density === "compact" || density === "large")
            ? density
            : "comfortable";
        root.setAttribute("data-density", d);
    }

    // Returns the secondary-window route this Dioxus instance should
    // mount: `'settings'`, `'oauth-add'`, etc. `null` for the main
    // three-pane window (the global isn't set there). Set by the
    // host's `initialization_script` before wasm boots so the root
    // component can branch synchronously without a flash.
    export function readerWindowView() {
        return window.__QSL_VIEW__ || null;
    }

    // Install the parent-side listener for link-click postMessages
    // sent by the sandboxed reader iframe (see
    // `qsl_core::compose_reader_html`'s click forwarder). The
    // sandboxed iframe can't navigate top-level and can't share
    // an origin with the host, so it postMessages every clicked
    // anchor up here; we filter on `data.type === 'qsl-link-click'`
    // and forward the URL to Tauri's `open_external_url` command,
    // which validates the scheme and shells out to `webbrowser::
    // open`. Idempotent — repeat installs replace the previous
    // listener.
    export function installReaderLinkListener() {
        if (window.__qslLinkListener) {
            window.removeEventListener('message', window.__qslLinkListener);
        }
        const listener = function(e) {
            // Defence-in-depth: the sandboxed reader iframe is the only
            // sender we accept here, and `sandbox="allow-scripts"`
            // (without `allow-same-origin`) gives it the opaque "null"
            // origin. Anything else posting to this window — a future
            // child iframe with same-origin, a window.open()'d helper,
            // a browser extension — should not be able to drive
            // `open_external_url`. The structural sandbox already
            // blocks that, but this guard makes the contract explicit
            // and survives a future change to the iframe shape.
            if (e.origin !== 'null') return;
            const data = e && e.data;
            if (!data || typeof data !== 'object' || data.type !== 'qsl-link-click') return;
            const url = data.url;
            if (typeof url !== 'string' || url.length === 0) return;
            window.__TAURI_INTERNALS__
                .invoke('open_external_url', { input: { url: url } })
                .catch(function(err) { console.warn('open_external_url:', err); });
        };
        window.addEventListener('message', listener);
        window.__qslLinkListener = listener;
    }
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = coreInvoke)]
    async fn core_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_name = tauriListen)]
    pub(crate) async fn tauri_listen(
        event: &str,
        handler: &js_sys::Function,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_name = setRootTheme)]
    pub(crate) fn set_root_theme(theme: &str);

    #[wasm_bindgen(js_name = setRootDensity)]
    pub(crate) fn set_root_density(density: &str);

    /// Returns the message id this popup window is for, set by the
    /// Tauri `WebviewWindowBuilder::initialization_script` in
    /// `messages_open_in_window`. `JsValue::null` when the global
    /// isn't set, i.e. this is the main three-pane window.
    #[wasm_bindgen(js_name = readerWindowMessageId)]
    pub(crate) fn reader_window_message_id() -> JsValue;

    /// Returns the JSON-stringified `RenderedMessage` the Tauri host
    /// pre-fetched into `window.__QSL_READER_PRELOAD__`, or
    /// `JsValue::null` when no preload is available. The reader-only
    /// component uses this to render the popup body without a
    /// follow-up `messages_get` IPC round-trip.
    #[wasm_bindgen(js_name = readerWindowPreload)]
    pub(crate) fn reader_window_preload() -> JsValue;

    /// Returns the value of `window.__QSL_VIEW__` (`"settings"`,
    /// `"oauth-add"`, etc.), set by `WebviewWindowBuilder::
    /// initialization_script` in the corresponding open-window
    /// command. `JsValue::null` for the main three-pane window.
    #[wasm_bindgen(js_name = readerWindowView)]
    pub(crate) fn reader_window_view() -> JsValue;

    /// Install the `message`-event listener that forwards link-click
    /// postMessages from the sandboxed reader iframe to Tauri's
    /// `open_external_url` command. Called once at app boot.
    #[wasm_bindgen(js_name = installReaderLinkListener)]
    pub(crate) fn install_reader_link_listener();
}

/// Thin wrapper around the Tauri `invoke` bridge. Serializes `args` to
/// JSON, forwards to JS, and deserializes the return value into `T`.
///
/// The return path round-trips through `JSON.stringify` +
/// `serde_json::from_str` instead of `serde_wasm_bindgen::from_value`.
/// `serde-wasm-bindgen` 0.6 silently dropped `Option<FolderRole>` to
/// `None` for several externally-tagged unit-variant tag values that the
/// Rust side ships as plain JSON strings, so the sidebar saw INBOX +
/// All Mail and lost the rest of the [Gmail]/* mailboxes. Tauri 2's
/// command results are JSON-encoded over the wire anyway, so the
/// round-trip is just re-stringifying the value the JS bridge already
/// `JSON.parse`d — no information loss, and `serde_json` handles
/// externally-tagged enums correctly.
pub(crate) async fn invoke<T>(cmd: &str, args: impl Serialize) -> Result<T, String>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let js_args = serde_wasm_bindgen::to_value(&args).map_err(|e| e.to_string())?;
    let js_ret = core_invoke(cmd, js_args)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let json = js_sys::JSON::stringify(&js_ret)
        .map_err(|e| format!("invoke {cmd}: JSON.stringify: {e:?}"))?
        .as_string()
        .ok_or_else(|| format!("invoke {cmd}: JSON.stringify returned non-string"))?;
    serde_json::from_str(&json).map_err(|e| format!("invoke {cmd}: {e}"))
}

// ---------- Selection state ----------

/// Global selection state shared across all three panes.
///
/// `unified` toggles between the per-folder view and the unified
/// inbox (every account's INBOX-role folder merged). When set, the
/// message-list pane invokes `messages_list_unified` and ignores
/// `account` / `folder`. Selecting a regular folder clears it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Selection {
    pub account: Option<AccountId>,
    pub folder: Option<FolderId>,
    pub message: Option<MessageId>,
    pub unified: bool,
}

/// Compose-pane open state. `None` means the message-list pane is
/// shown in the middle; `Some` means the compose form is shown
/// instead, optionally rehydrated from a persisted draft id.
#[derive(Debug, Clone, PartialEq)]
pub struct ComposeState {
    /// Default account to compose from. Pre-filled from the current
    /// selection if one is highlighted, otherwise the first
    /// available account.
    pub default_account: Option<AccountId>,
    /// Draft to rehydrate. `None` opens a fresh compose; `Some`
    /// pulls fields via `drafts_load` on mount.
    pub draft_id: Option<DraftId>,
    /// Optional one-shot prefill (used by `mailto:` deep links). When
    /// `draft_id` is `None` and `prefill` is `Some`, the compose
    /// pane seeds its fields from this struct on first mount and
    /// then forgets it — subsequent edits + autosaves treat the
    /// pane as a fresh draft.
    pub prefill: Option<ComposePrefill>,
}

/// One-shot prefill values for a fresh compose. Mirrors the subset of
/// RFC 6068 mailto fields the desktop's deep-link handler parses;
/// adding more fields here is a backward-compatible expansion.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ComposePrefill {
    pub to: Option<String>,
    pub cc: Option<String>,
    pub bcc: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
}

/// Global revision counter, bumped on every `sync_event`. Drives
/// resources whose work is structurally cross-folder — folder lists in
/// the sidebar (unread counts can change in any folder) and the
/// unified inbox.
pub type SyncTick = Signal<u64>;

/// Per-folder revision counter. The sync listener bumps the entry for
/// the folder named in `SyncEvent::FolderSynced` / `FolderError`, so a
/// per-folder `MessageListV2` only refetches when *its* folder
/// actually synced. Without this, a 10-folder bootstrap pass would
/// trigger 10 refetches of the visible folder; with it, only the
/// matching event triggers work.
pub type FolderTokens = Signal<HashMap<FolderId, u64>>;

/// Open context-menu state. `Some` while the right-click popover is
/// shown. The pixel coords are viewport-relative; the popover renders
/// itself with `position: fixed` at those coordinates. `is_unread`
/// drives the Mark read / Mark unread label without re-fetching the
/// flag.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageContextMenu {
    pub x: f64,
    pub y: f64,
    pub message_id: MessageId,
    pub is_unread: bool,
}

/// Newtype around the unread-subset signal so it can ride the
/// type-keyed `use_context` system without colliding with the
/// `Signal<Vec<MessageId>>` already used for `visible_messages`.
/// Read with `use_context::<UnreadVisible>().0.read()`.
#[derive(Clone, Copy)]
pub struct UnreadVisible(pub Signal<Vec<MessageId>>);

/// `thread_id.0 → message-count` for the threads referenced by the
/// currently-rendered message list. Populated by whichever list
/// pane is active (folder / unified / search) from
/// `MessagePage::thread_counts`. The list rows look up their own
/// thread id and render a count badge when the value > 1, so the
/// user can see "this conversation has N replies" without opening
/// it.
#[derive(Clone, Copy)]
pub struct ThreadCounts(pub Signal<std::collections::HashMap<String, u32>>);

/// Conversation-threading toggle (`reading.threading`). When `true`
/// (default): the message list rolls adjacent same-thread rows into
/// a `ThreadRow` with a count badge, the reader pane fetches the
/// whole thread via `messages_thread`, and `MessageRowV2` shows
/// "(N)" badges. When `false`: every message is its own row + the
/// reader shows only the selected message. Newtype so the bool
/// signal doesn't collide with other `Signal<bool>` contexts.
#[derive(Clone, Copy)]
pub struct ThreadingEnabled(pub Signal<bool>);

/// Client-side optimistic "this message is now read" set. Populated
/// the moment the user clicks a row (synchronously, before the
/// `messages_mark_read` IPC fires) so `MessageRowV2` can flip its
/// bold→normal styling immediately without the message-list having
/// to refetch. Without this, every click was bumping `sync_tick`
/// just to repaint one row's visual state, forcing a full
/// `messages_list` IPC (slim id query + hydration) — a 1.5+ s freeze
/// per click on a 30k-row Gmail mailbox under Turso 0.5.3's
/// SORTER-on-ORDER-BY behaviour.
///
/// The set persists for the life of the shell. Once the next
/// legitimate sync_event refetch lands, the row's `flags.seen` is
/// `true` in the fetched data and the override becomes a no-op (the
/// `&&` short-circuits) — so growth is bounded by messages clicked
/// per session, which never matters in practice.
#[derive(Clone, Copy)]
pub struct ClientReadIds(pub Signal<std::collections::HashSet<MessageId>>);

// ---------- Root ----------

/// Apply the persisted `appearance.theme` + `appearance.density`
/// settings to `<html>` at boot and re-apply on every
/// `app_settings_changed` event. Every Dioxus root (the main shell,
/// the Settings window, the popup reader, the OAuth-add window)
/// must call this so its `<html data-theme=…>` matches what the
/// user picked — otherwise the window paints with the dark default
/// regardless of the stored preference and clicking a Theme radio
/// in Settings only updates whichever windows had subscribed.
///
/// Defaults: `system` (follows `prefers-color-scheme`) for theme,
/// `comfortable` for density. Bad / missing values fall back to
/// these so a corrupt setting can't trap the user.
pub fn use_appearance_hooks() {
    use_hook(|| {
        wasm_bindgen_futures::spawn_local(async {
            let theme = invoke::<Option<String>>(
                "app_settings_get",
                serde_json::json!({ "input": { "key": "appearance.theme" } }),
            )
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "system".to_string());
            set_root_theme(&theme);

            let density = invoke::<Option<String>>(
                "app_settings_get",
                serde_json::json!({ "input": { "key": "appearance.density" } }),
            )
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "comfortable".to_string());
            set_root_density(&density);
        });
    });
    use_hook(|| {
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |payload: JsValue| {
            #[derive(serde::Deserialize)]
            struct Changed {
                key: String,
                value: String,
            }
            let Ok(evt) = serde_wasm_bindgen::from_value::<Changed>(payload) else {
                return;
            };
            match evt.key.as_str() {
                "appearance.theme" => set_root_theme(&evt.value),
                "appearance.density" => set_root_density(&evt.value),
                _ => {}
            }
        });
        wasm_bindgen_futures::spawn_local(async move {
            let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
            if let Err(e) = tauri_listen("app_settings_changed", func).await {
                web_sys_log(&format!("app_settings_changed listen failed: {e:?}"));
            }
            Box::leak(Box::new(cb));
        });
    });
}

pub fn App() -> Element {
    // Secondary-window detection: the Tauri popup `initialization_script`
    // injects either `window.__QSL_READER_ID__` (popup reader) or
    // `window.__QSL_VIEW__` ('settings', 'oauth-add', …) before the
    // wasm bundle boots. Branch synchronously so the wrong shell
    // never paints.
    let popup_id_js: JsValue = reader_window_message_id();
    if !popup_id_js.is_null() && !popup_id_js.is_undefined() {
        if let Some(id_str) = popup_id_js.as_string() {
            return rsx! {
                crate::reader_only::ReaderOnlyApp {
                    message_id: MessageId(id_str)
                }
            };
        }
    }
    let view_js: JsValue = reader_window_view();
    if let Some(view) = view_js.as_string() {
        match view.as_str() {
            "settings" => return rsx! { crate::settings::SettingsApp {} },
            "oauth-add" => return rsx! { crate::oauth_add::OAuthAddApp {} },
            other => {
                web_sys_log(&format!(
                    "App: unknown __QSL_VIEW__ = {other}; falling through"
                ));
            }
        }
    }
    full_app_shell()
}

fn full_app_shell() -> Element {
    use_hook(|| {
        tracing::info!("ui: main shell mounting");
    });
    let selection = use_signal(Selection::default);
    let mut sync_tick: SyncTick = use_signal(|| 0u64);
    let mut folder_tokens: FolderTokens = use_signal(HashMap::new);
    let compose: Signal<Option<ComposeState>> = use_signal(|| None);
    let help_visible: Signal<bool> = use_signal(|| false);
    // Multi-select state. `bulk_selected` carries the currently-checked
    // message ids; the bulk-action bar reveals when it's non-empty and
    // the per-row checkboxes paint a filled state when their id is in
    // the set. Lives at App root so it survives folder switches and
    // can be read from any pane that wants to act on the selection.
    let bulk_selected: Signal<HashSet<MessageId>> = use_signal(HashSet::new);
    // Active search query — empty string means "no search active, show
    // the regular folder / unified inbox view". Sits at the App root
    // so it survives sidebar navigation; clearing it (via Esc on the
    // input or the bar's clear button) returns to the previous view
    // without touching `selection`.
    let search_query: Signal<String> = use_signal(String::new);

    // Account filter for the unified-inbox / folder views. `None`
    // shows every account; `Some(id)` scopes the message list to a
    // single account. Per post-phase-2.md assumption A1 the chip is
    // a filter, not an active-account swap — the sidebar still shows
    // every account's mailboxes side by side.
    let account_filter: Signal<Option<AccountId>> = use_signal(|| None);

    // Currently-visible message ids in display order. Each list
    // component (folder view, unified view, search results, threads)
    // publishes its rendered set so `j` / `k` can step through them
    // without re-fetching. Sorted by date-desc to match the rendering.
    let visible_messages: Signal<Vec<MessageId>> = use_signal(Vec::new);
    // Subset of `visible_messages` that's still unread, in the same
    // display order. Drives the `n` "next unread" shortcut so the
    // dispatcher doesn't have to query flags per keypress. Each list
    // component that publishes `visible_messages` also publishes the
    // unread subset from the same data — see the use_effect blocks
    // in `MessageListPaneV2`, the unified inbox, and the search
    // results pane.
    let unread_visible: Signal<Vec<MessageId>> = use_signal(Vec::new);
    // `thread_id.0 -> message-count` for the threads referenced by
    // the active list pane. Each pane writes its `MessagePage::
    // thread_counts` here; rows read it to decide whether to show a
    // "(N)" badge alongside the subject. Wrapped with a newtype for
    // the same reason as `UnreadVisible`.
    let thread_counts: Signal<std::collections::HashMap<String, u32>> =
        use_signal(std::collections::HashMap::new);
    // Optimistic "this id was clicked + marked-read this session" set.
    // Provided as a context so `MessageRowV2` can flip its
    // bold→normal styling synchronously when the reader-pane
    // mark-read effect adds an id, without forcing the
    // `messages_list` use_resource to refetch (which on a 30k-row
    // Gmail mailbox is a 1.5+ s slim id query under Turso 0.5.3).
    let client_read_ids: Signal<HashSet<MessageId>> = use_signal(HashSet::new);
    // Conversation-threading toggle. Loaded once at boot and live-
    // updated via `app_settings_changed`. Default-on so existing
    // users see no change unless they opt out.
    let mut threading_enabled: Signal<bool> = use_signal(|| true);
    use_hook(move || {
        wasm_bindgen_futures::spawn_local(async move {
            let v = invoke::<Option<String>>(
                "app_settings_get",
                serde_json::json!({ "input": { "key": crate::settings::KEY_THREADING } }),
            )
            .await
            .ok()
            .flatten();
            // Stored "true"/"false"; absent → default on.
            threading_enabled.set(!matches!(v.as_deref(), Some("false")));
        });
    });
    use_hook(move || {
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |payload: JsValue| {
            #[derive(serde::Deserialize)]
            struct Changed {
                key: String,
                value: String,
            }
            let Ok(evt) = serde_wasm_bindgen::from_value::<Changed>(payload) else {
                return;
            };
            if evt.key == crate::settings::KEY_THREADING {
                threading_enabled.set(evt.value != "false");
            }
        });
        wasm_bindgen_futures::spawn_local(async move {
            let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
            if let Err(e) = tauri_listen("app_settings_changed", func).await {
                web_sys_log(&format!("threading toggle listen failed: {e:?}"));
            }
            Box::leak(Box::new(cb));
        });
    });

    // Command palette visibility (⌘K) and recent-search ring buffer for
    // the palette's "Recent" section. Both live at App root so the
    // palette can pull across pane boundaries on open.
    let palette_visible: Signal<bool> = use_signal(|| false);
    let mut recent_searches: Signal<Vec<String>> = use_signal(Vec::new);

    // Undo-send deadline (epoch ms). `Some(t)` means a Send click is
    // armed but holding for the configured undo window; `None` means
    // no pending send. Lives at App root so the global Esc handler
    // (which doesn't see ComposePane's locals) can clear it on Cancel
    // — unwinding pending sends takes priority over closing compose.
    let undo_send_pending: Signal<Option<f64>> = use_signal(|| None);

    // Right-click context menu state. `Some` while the popover is
    // visible. Lives at App root so a single popover element renders
    // over the whole shell and dismiss-on-outside-click stays simple
    // (no per-row click-outside listeners). Both `MessageRowV2` and
    // `ThreadRow` write to it on right-click.
    let context_menu: Signal<Option<MessageContextMenu>> = use_signal(|| None);
    // Expose the context-menu signal to nested rows without threading
    // it through every intermediate list component (SearchList,
    // UnifiedInbox, MessageListV2, ThreadRow). The rows reach for it
    // via `use_context::<Signal<Option<MessageContextMenu>>>()`.
    use_context_provider(|| context_menu);

    // Drag-and-drop state. `Some(ids)` while a message-row drag is in
    // flight; `None` otherwise. Sidebar rows read this to decide
    // whether to highlight as a drop target (or paint a no-drop cursor
    // for blocked roles), and `ondrop` reads the ids out for
    // `messages_move`. Using a signal here instead of round-tripping
    // through `dataTransfer` avoids JSON ser/de on every drag and keeps
    // the drop guard a simple `is_some()` check in `ondragover`.
    let drag_state: Signal<Option<Vec<MessageId>>> = use_signal(|| None);
    use_context_provider(|| drag_state);
    // Expose `bulk_selected` to the sidebar drop handlers so a drop
    // can clear the multi-select set after a successful move (matches
    // bulk-action-bar behaviour). Existing prop-threaded callers stay
    // untouched.
    use_context_provider(|| bulk_selected);
    // Same pattern for `visible_messages` + `selection`: action
    // handlers across the shell (sidebar drops, bulk-action-bar,
    // context-menu) read these to compute the "next message after
    // move" landing point so the reader pane doesn't get stranded
    // showing a ghost copy of a message that's no longer in view.
    use_context_provider(|| visible_messages);
    // Wrap the unread-subset signal in a newtype so it doesn't
    // collide with `Signal<Vec<MessageId>>` (which is already
    // claimed by `visible_messages`); Dioxus's `use_context` is
    // type-keyed, so two registrations of the same concrete type
    // would shadow each other.
    use_context_provider(|| UnreadVisible(unread_visible));
    use_context_provider(|| ThreadCounts(thread_counts));
    use_context_provider(|| ThreadingEnabled(threading_enabled));
    use_context_provider(|| ClientReadIds(client_read_ids));
    use_context_provider(|| selection);

    // Capture cleared search queries into the recent ring buffer.
    // Watching the transition non-empty → empty avoids polluting the
    // ring with every keystroke while still recording every query the
    // user actually saw results for. Bounded to 8 entries; dedup keeps
    // a re-typed query from filling the buffer.
    {
        let mut last_query: Signal<String> = use_signal(String::new);
        let q_now = search_query.read().clone();
        use_effect(use_reactive!(|q_now| {
            // `peek()` reads without subscribing — `use_effect` re-runs
            // on any signal it has *read* (subscribed to), so doing
            // `last_query.read()` here while also `last_query.set(...)`
            // below creates a self-trigger loop that crashes the wasm
            // bundle (white screen on boot). The reactive trigger we
            // *do* want is `q_now` from the surrounding `use_reactive!`.
            let prev = last_query.peek().clone();
            if !prev.is_empty() && q_now.is_empty() {
                let trimmed = prev.trim().to_string();
                if !trimmed.is_empty() {
                    recent_searches.with_mut(|v| {
                        v.retain(|s| s != &trimmed);
                        v.insert(0, trimmed);
                        v.truncate(8);
                    });
                }
            }
            last_query.set(q_now);
        }));
    }

    // The reader iframe is part of the Dioxus DOM tree — z-index
    // handles overlap natively, so opening Compose / palette doesn't
    // need to nudge the renderer.
    let _ = palette_visible;
    // Most recent sync_event payload, rendered in the bottom status
    // bar. `None` means we haven't seen any events yet — the bar
    // shows "Initializing…" / "Syncing…" until the first event lands.
    let mut sync_status: Signal<SyncStatus> = use_signal(|| SyncStatus::Initializing);

    // In-flight history-sync, kept separate from `sync_status` so a
    // FolderSynced cycle arriving mid-pull doesn't blow away the
    // progress line. Cleared when the pull terminates (completed /
    // canceled / error) — see `HistoryActivity::from_event`.
    let mut history_activity: Signal<Option<HistoryActivity>> = use_signal(|| None);

    // Pane widths in CSS pixels. Defaults match the original
    // 200/280/rest layout. Drag handlers below mutate these.
    let mut sidebar_w = use_signal(|| 240u32);
    let mut list_w = use_signal(|| 320u32);
    // `Some((target, start_x_in_client_pixels, start_width))` while
    // a splitter is being dragged; `None` otherwise. The overlay div
    // renders only when this is `Some`, keeping the iframe from
    // capturing pointer events mid-drag.
    let mut drag = use_signal(|| Option::<(SplitTarget, f64, u32)>::None);

    // Listen for sync engine events: bump sync_tick so cross-folder
    // resources (sidebar, unified inbox) refetch, bump the per-folder
    // token so the message list for that specific folder refetches,
    // and update the status bar signal with the parsed payload. The
    // JS-side `tauriListen` wrapper passes us just `event.payload`,
    // which deserializes straight into a `SyncEvent` enum.
    use_hook(move || {
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |payload: JsValue| {
            let parsed = serde_wasm_bindgen::from_value::<SyncEvent>(payload);
            // No-change `FolderSynced` cycles (idle IMAP polls of
            // folders that didn't change) should not bump `sync_tick`
            // or `folder_tokens` — that would trigger the sidebar
            // `folders_list` refetch and the per-folder
            // `messages_list` refetch, both of which fan out into
            // expensive `count_unread_by_folder` queries. The status
            // bar and history-activity pane still need to react to
            // the event, so those updates run unconditionally below.
            let triggers_refetch = match &parsed {
                Ok(SyncEvent::FolderSynced {
                    added,
                    updated,
                    flag_updates,
                    removed,
                    ..
                }) => *added + *updated + *flag_updates + *removed > 0,
                Ok(SyncEvent::FolderError { .. }) => true,
                // FolderStarted fires *before* sync_folder runs —
                // nothing has been written yet, so don't refetch.
                // The status bar still updates via the unconditional
                // SyncStatus path below.
                Ok(SyncEvent::FolderStarted { .. }) => false,
                Ok(SyncEvent::HistorySyncProgress { .. }) => false,
                // Unparseable payload: preserve previous defensive
                // behaviour and trigger a refetch — better to repaint
                // a few times than to drop a real change on the floor.
                Err(_) => true,
            };
            if triggers_refetch {
                sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            }
            if let Ok(evt) = parsed {
                match &evt {
                    SyncEvent::FolderStarted { .. } => {}
                    SyncEvent::FolderSynced { folder, .. } => {
                        tracing::info!(folder = %folder.0, "ui: sync_event FolderSynced");
                    }
                    SyncEvent::FolderError { folder, .. } => {
                        tracing::warn!(folder = %folder.0, "ui: sync_event FolderError");
                    }
                    SyncEvent::HistorySyncProgress { .. } => {}
                }
                let folder = if triggers_refetch {
                    match &evt {
                        SyncEvent::FolderSynced { folder, .. }
                        | SyncEvent::FolderError { folder, .. } => Some(folder.clone()),
                        // FolderStarted has triggers_refetch=false so
                        // it never reaches this branch; explicit arm
                        // keeps the match exhaustive.
                        SyncEvent::FolderStarted { .. } => None,
                        // History-sync progress doesn't invalidate any
                        // folder's message list (the rows show up via
                        // the normal sync path); the Settings panel
                        // listens for these directly.
                        SyncEvent::HistorySyncProgress { .. } => None,
                    }
                } else {
                    None
                };
                if let Some(folder) = folder {
                    folder_tokens.with_mut(|m| {
                        let entry = m.entry(folder).or_insert(0);
                        *entry = entry.wrapping_add(1);
                    });
                }
                if let Some(s) = SyncStatus::from_event(&evt) {
                    sync_status.set(s);
                }
                if let Some(update) = HistoryActivity::from_event(&evt) {
                    match update {
                        Some(activity) => history_activity.set(Some(activity)),
                        None => {
                            // Terminal status: only clear the bar
                            // when this event matches the activity
                            // currently displayed. A different folder
                            // finishing while INBOX is still pulling
                            // would otherwise wipe the running line.
                            if let SyncEvent::HistorySyncProgress {
                                account, folder, ..
                            } = &evt
                            {
                                let cur_matches = history_activity
                                    .peek()
                                    .as_ref()
                                    .map(|a| a.account == *account && a.folder_id == *folder)
                                    .unwrap_or(false);
                                if cur_matches {
                                    history_activity.set(None);
                                }
                            }
                        }
                    }
                }
            }
        });
        wasm_bindgen_futures::spawn_local(async move {
            let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
            if let Err(e) = tauri_listen("sync_event", func).await {
                web_sys_log(&format!("sync_event listen failed: {e:?}"));
            }
            Box::leak(Box::new(cb));
        });
    });

    // `accounts_changed` is fired by the host after an OAuth add
    // succeeds and after `accounts_remove`. Bumping `sync_tick`
    // refetches every reactive `accounts_list` consumer (sidebar,
    // command palette folders) without waiting for the bootstrap
    // sync's first FolderSynced event to arrive — that latency was
    // the gap users were noticing as "I removed the account but
    // it's still in the sidebar."
    //
    // After the bump, we also validate global selection state against
    // the fresh accounts list and clear anything that referenced the
    // removed account. Without this step, removing the currently-
    // selected account leaves the message list and reader pane
    // painting rows from the deleted account until the user
    // navigates elsewhere or reloads — the storage-side CASCADE
    // wiped the rows, but the UI's cached `Selection` still pointed
    // at a now-empty folder. Validates instead of clearing
    // unconditionally so adding a new account doesn't disrupt the
    // user's current view of an existing one.
    let mut selection_for_listener = selection;
    let mut bulk_for_listener = bulk_selected;
    let mut visible_for_listener = visible_messages;
    let mut compose_for_listener = compose;
    let mut folder_tokens_for_listener = folder_tokens;
    use_hook(move || {
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |_payload: JsValue| {
            tracing::info!("ui: accounts_changed event received — refetching account list");
            sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            wasm_bindgen_futures::spawn_local(async move {
                let Ok(accounts) = invoke::<Vec<Account>>("accounts_list", ()).await else {
                    return;
                };
                tracing::info!(count = accounts.len(), "ui: account list refreshed");
                let alive: HashSet<AccountId> = accounts.iter().map(|a| a.id.clone()).collect();
                let selection_stale = selection_for_listener
                    .peek()
                    .account
                    .as_ref()
                    .map(|a| !alive.contains(a))
                    .unwrap_or(false);
                if selection_stale {
                    selection_for_listener.set(Selection::default());
                    visible_for_listener.set(Vec::new());
                    bulk_for_listener.set(HashSet::new());
                    folder_tokens_for_listener.set(HashMap::new());
                }
                let compose_stale = compose_for_listener
                    .peek()
                    .as_ref()
                    .and_then(|c| c.default_account.as_ref())
                    .map(|a| !alive.contains(a))
                    .unwrap_or(false);
                if compose_stale {
                    compose_for_listener.set(None);
                }
            });
        });
        wasm_bindgen_futures::spawn_local(async move {
            let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
            if let Err(e) = tauri_listen("accounts_changed", func).await {
                web_sys_log(&format!("accounts_changed listen failed: {e:?}"));
            }
            Box::leak(Box::new(cb));
        });
    });

    // (Removed on the webkit-iframe branch: the rect tracker existed
    // to position the GTK Servo overlay surface; with the iframe
    // rendering email bodies in-DOM there's nothing to track.)

    // Install the reader-iframe link forwarder. The sandboxed iframe
    // postMessages every clicked anchor URL up to this window; the
    // listener invokes `open_external_url`, which shells out to the
    // OS default browser. Once per app session — the JS side is
    // idempotent.
    use_hook(|| {
        install_reader_link_listener();
    });

    use_appearance_hooks();

    // Listen for the global "always load remote images" setting
    // changing in the Settings window. Bump `sync_tick` so the
    // currently-open reader pane refetches via `messages_get` and
    // applies the new policy without the user having to reselect
    // the message. Only fires on the privacy key — theme/density
    // changes are already handled inside `use_appearance_hooks`.
    use_hook(move || {
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |payload: JsValue| {
            #[derive(serde::Deserialize)]
            struct Changed {
                key: String,
            }
            let Ok(evt) = serde_wasm_bindgen::from_value::<Changed>(payload) else {
                return;
            };
            if evt.key == "privacy.remote_images_always" {
                sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            }
        });
        wasm_bindgen_futures::spawn_local(async move {
            let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
            if let Err(e) = tauri_listen("app_settings_changed", func).await {
                web_sys_log(&format!("app_settings_changed for reader listen: {e:?}"));
            }
            Box::leak(Box::new(cb));
        });
    });

    // Listen for the system-tray "Compose" menu emitting `tray_compose`.
    // Dioxus owns compose state via the `compose` signal; on the event
    // we just open a fresh draft pane. Empty payload — the tray menu
    // doesn't preselect an account, same as the sidebar Compose button.
    use_hook(move || {
        let mut compose_for_tray = compose;
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |_: JsValue| {
            compose_for_tray.set(Some(ComposeState {
                default_account: None,
                draft_id: None,
                prefill: None,
            }));
        });
        wasm_bindgen_futures::spawn_local(async move {
            let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
            if let Err(e) = tauri_listen("tray_compose", func).await {
                web_sys_log(&format!("tray_compose listen failed: {e:?}"));
            }
            Box::leak(Box::new(cb));
        });
    });

    // Listen for `mailto:` deep-link events emitted by the desktop
    // shell. The Rust side parses the URL into a structured payload;
    // we open a fresh compose pane with the parsed fields applied as
    // a one-shot prefill. The compose pane treats these as fresh
    // user input — autosave will persist them as a normal draft on
    // first edit.
    use_hook(move || {
        let mut compose_for_mailto = compose;
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |payload: JsValue| {
            #[derive(serde::Deserialize)]
            struct Payload {
                to: Option<String>,
                cc: Option<String>,
                bcc: Option<String>,
                subject: Option<String>,
                body: Option<String>,
            }
            let Ok(p) = serde_wasm_bindgen::from_value::<Payload>(payload) else {
                web_sys_log("mailto_open: failed to deserialize payload");
                return;
            };
            compose_for_mailto.set(Some(ComposeState {
                default_account: None,
                draft_id: None,
                prefill: Some(ComposePrefill {
                    to: p.to,
                    cc: p.cc,
                    bcc: p.bcc,
                    subject: p.subject,
                    body: p.body,
                }),
            }));
        });
        wasm_bindgen_futures::spawn_local(async move {
            let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
            if let Err(e) = tauri_listen("mailto_open", func).await {
                web_sys_log(&format!("mailto_open listen failed: {e:?}"));
            }
            Box::leak(Box::new(cb));
        });
    });

    // Tell the Rust side the UI is mounted so the sync engine can
    // start its bootstrap pass. Without this signal the engine waits
    // up to 10s before kicking off, but firing it explicitly keeps
    // the gate tight on a healthy launch. Fires once per app session.
    use_hook(|| {
        wasm_bindgen_futures::spawn_local(async {
            tracing::info!("ui: signalling ui_ready to host");
            if let Err(e) = invoke::<()>("ui_ready", serde_json::json!({})).await {
                tracing::warn!("ui_ready invoke failed: {e}");
                web_sys_log(&format!("ui_ready: {e}"));
            } else {
                tracing::info!("ui: ui_ready handshake complete");
            }
        });
    });

    // Install the document-level keydown listener once per session.
    // Dioxus's element-level `onkeydown` only fires when that element
    // (or a child) has focus, which doesn't cover the "no input
    // focused, just press `c`" case the Gmail-style scheme assumes.
    // A document listener catches the keystroke regardless of focus
    // and `is_typing()` swallows it again for `<input>` / `<textarea>`
    // / `[contenteditable]`. The closure leaks via `Box::leak` because
    // the listener lives for the app's lifetime.
    use_hook(move || {
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |event_js: JsValue| {
            let Ok(event) = event_js.dyn_into::<web_sys::KeyboardEvent>() else {
                return;
            };
            let key = event.key();
            let ctrl_or_meta = event.ctrl_key() || event.meta_key();
            // Apply the typing-guard ONLY to unmodified keystrokes —
            // a bare `j` / `k` / `r` while focused in an input is the
            // user typing those letters, not a command. Modifier-
            // prefixed shortcuts like Ctrl+K are intentional commands
            // in every context (the keystroke produces no text input)
            // and must work even when focus is in the search bar or
            // compose body. Without this exemption Ctrl+K silently
            // dropped on every focused input.
            //
            // Escape during a pending undo-send is also exempted: it's
            // a modal-cancel keystroke, never typed text, and the user
            // expects "Esc cancels" to work even with focus in the
            // body textarea where they clicked Send from.
            let allow_through =
                ctrl_or_meta || (key == "Escape" && undo_send_pending.read().is_some());
            if !allow_through && is_typing_in_field() {
                return;
            }
            let Some(cmd) = crate::keyboard::parse(&key, ctrl_or_meta) else {
                return;
            };
            event.prevent_default();
            dispatch_keyboard_command(
                cmd,
                selection,
                compose,
                sync_tick,
                help_visible,
                search_query,
                visible_messages,
                unread_visible,
                palette_visible,
                undo_send_pending,
                context_menu,
            );
        });
        if let Some(window) = web_sys::window() {
            if let Some(document) = window.document() {
                let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
                if let Err(e) = document.add_event_listener_with_callback("keydown", func) {
                    web_sys_log(&format!("keydown listener install failed: {e:?}"));
                }
            }
        }
        Box::leak(Box::new(cb));
    });

    let onmousemove_shell = move |e: Event<MouseData>| {
        let Some((target, start_x, start_w)) = *drag.read() else {
            return;
        };
        let dx = e.client_coordinates().x - start_x;
        let new_w = (start_w as f64 + dx).round();
        let clamped = match target {
            SplitTarget::Sidebar => new_w.clamp(160.0, 480.0) as u32,
            SplitTarget::List => new_w.clamp(220.0, 720.0) as u32,
        };
        match target {
            SplitTarget::Sidebar => sidebar_w.set(clamped),
            SplitTarget::List => list_w.set(clamped),
        }
    };
    let onmouseup_shell = move |_| drag.set(None);

    let onmousedown_sidebar = move |e: Event<MouseData>| {
        e.prevent_default();
        drag.set(Some((
            SplitTarget::Sidebar,
            e.client_coordinates().x,
            sidebar_w(),
        )));
    };
    let onmousedown_list = move |e: Event<MouseData>| {
        e.prevent_default();
        drag.set(Some((
            SplitTarget::List,
            e.client_coordinates().x,
            list_w(),
        )));
    };

    let grid_style = format!(
        "grid-template-columns: {}px 5px {}px 5px 1fr;",
        sidebar_w(),
        list_w()
    );
    let dragging = drag.read().is_some();

    rsx! {
        document::Stylesheet { href: TAILWIND_CSS }
        div {
            class: "app-shell",
            style: "{grid_style}",
            onmousemove: onmousemove_shell,
            onmouseup: onmouseup_shell,
            onmouseleave: onmouseup_shell,
            TopBar { account_filter, palette_visible, sync_tick }
            div {
                class: "shell-pane shell-pane-sidebar",
                SidebarV2 { selection, sync_tick, compose }
            }
            div {
                class: "shell-splitter",
                onmousedown: onmousedown_sidebar,
            }
            div {
                class: "shell-pane shell-pane-list",
                MessageListPaneV2 { selection, sync_tick, folder_tokens, bulk_selected, search_query, account_filter, visible_messages }
            }
            div {
                class: "shell-splitter",
                onmousedown: onmousedown_list,
            }
            div {
                class: "shell-pane shell-pane-reader",
                if compose.read().is_some() {
                    ComposePane { compose, sync_tick, undo_send_pending }
                } else {
                    ReaderPaneV2 { selection, sync_tick, compose }
                }
            }
            // Full-window overlay during drag so the reader's iframe
            // (and any other webview child) can't capture pointer
            // events. Pointer events still bubble to `.app-shell`,
            // which is where the move/up handlers live.
            if dragging {
                div { class: "shell-drag-overlay" }
            }
            StatusBar { status: sync_status, history: history_activity }
            if help_visible() {
                ShortcutsOverlay { visible: help_visible }
            }
            if palette_visible() {
                CommandPalette {
                    visible: palette_visible,
                    selection,
                    compose,
                    sync_tick,
                    search_query,
                    recent_searches,
                    help_visible,
                }
            }
            if context_menu.read().is_some() {
                MessageContextPopover { context_menu, compose, sync_tick, selection }
            }
        }
    }
}

/// Returns `true` when the document's currently-focused element is one
/// the user is typing into — `<input>`, `<textarea>`, `<select>`, or a
/// `[contenteditable]` element. Single-letter keyboard shortcuts must
/// not fire in those cases (otherwise `c` while editing the To: field
/// would open a new compose). Best-effort: when we can't reach the
/// document or the active element, default to `false` so the
/// shortcuts work — never `true` (the safe-against-misfire bias is
/// to *fire* the shortcut, since the user's intent is "act on this
/// app," and the shortcut is a no-op when no message is selected).
/// Best-effort detection of "this is a Mac" so the topbar pill and any
/// other shortcut hint can render `⌘K` on macOS and `Ctrl K` on
/// Linux / Windows. The shortcut binding is the same conceptually
/// (`event.metaKey || event.ctrlKey` is what `parse()` checks) but
/// users see different keycap glyphs on different keyboards.
///
/// Reads `navigator.platform` — deprecated by the spec but still
/// populated by every shipping browser engine, including Servo's
/// embedded webview. Falls back to `userAgent` substring sniff if
/// `platform` is absent. Falls back to "Ctrl K" if neither is
/// available — better to show the binding that actually works on the
/// platform we're most likely running on (Linux desktop) than to
/// confidently lie with `⌘K`.
fn palette_shortcut_label() -> &'static str {
    let Some(window) = web_sys::window() else {
        return "Ctrl K";
    };
    let nav = window.navigator();
    let platform = nav.platform().unwrap_or_default().to_ascii_lowercase();
    let ua = nav.user_agent().unwrap_or_default().to_ascii_lowercase();
    if platform.contains("mac") || ua.contains("mac os x") {
        "⌘K"
    } else {
        "Ctrl K"
    }
}

fn is_typing_in_field() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    let Some(document) = window.document() else {
        return false;
    };
    let Some(active) = document.active_element() else {
        return false;
    };
    let tag = active.tag_name();
    if tag.eq_ignore_ascii_case("INPUT")
        || tag.eq_ignore_ascii_case("TEXTAREA")
        || tag.eq_ignore_ascii_case("SELECT")
    {
        return true;
    }
    matches!(
        active.get_attribute("contenteditable").as_deref(),
        Some("true") | Some("")
    )
}

/// Turn a [`crate::keyboard::KeyboardCommand`] into actual side effects
/// against the App-root signals. Pulled out of the listener closure
/// for readability — the closure can stay tightly scoped to "parse +
/// guard," and this function owns the per-command dispatch.
#[allow(clippy::too_many_arguments)]
fn dispatch_keyboard_command(
    cmd: crate::keyboard::KeyboardCommand,
    mut selection: Signal<Selection>,
    mut compose: Signal<Option<ComposeState>>,
    mut sync_tick: SyncTick,
    mut help_visible: Signal<bool>,
    mut search_query: Signal<String>,
    visible_messages: Signal<Vec<MessageId>>,
    unread_visible: Signal<Vec<MessageId>>,
    mut palette_visible: Signal<bool>,
    mut undo_send_pending: Signal<Option<f64>>,
    mut context_menu: Signal<Option<MessageContextMenu>>,
) {
    use crate::keyboard::KeyboardCommand;

    match cmd {
        KeyboardCommand::Compose => {
            // Empty compose. Default-account resolution happens inside
            // the compose pane when it can't read `selection.account`,
            // so we don't need to fetch the account list here.
            let default_account = selection.read().account.clone();
            compose.set(Some(ComposeState {
                default_account,
                draft_id: None,
                prefill: None,
            }));
        }
        KeyboardCommand::Cancel => {
            // Priority: pending undo-send → context menu → palette →
            // help → compose → search → selection. One press unwinds
            // one layer — matches Gmail / native dialog behaviour.
            // Pending undo-send sits above compose so Esc cancels the
            // in-flight send before it closes the pane (closing alone
            // wouldn't cancel — the pending future is decoupled).
            if undo_send_pending.read().is_some() {
                undo_send_pending.set(None);
            } else if context_menu.read().is_some() {
                context_menu.set(None);
            } else if *palette_visible.read() {
                palette_visible.set(false);
            } else if *help_visible.read() {
                help_visible.set(false);
            } else if compose.read().is_some() {
                compose.set(None);
            } else if !search_query.read().is_empty() {
                search_query.set(String::new());
            } else if selection.read().message.is_some() {
                selection.with_mut(|s| s.message = None);
            }
        }
        KeyboardCommand::TogglePalette => {
            let cur = *palette_visible.read();
            palette_visible.set(!cur);
        }
        KeyboardCommand::FocusSearch => {
            // Focus the search input by id — the bar lives at the
            // top of the message-list pane and renders unconditionally,
            // so the element is always in the DOM. `getElementById`
            // returns null only mid-mount; in that case `/` is a no-op.
            if let Some(window) = web_sys::window() {
                if let Some(document) = window.document() {
                    if let Some(el) = document.get_element_by_id("qsl-search-input") {
                        if let Ok(input) = el.dyn_into::<web_sys::HtmlInputElement>() {
                            let _ = input.focus();
                            input.select();
                        }
                    }
                }
            }
        }
        KeyboardCommand::ToggleHelp => {
            let cur = *help_visible.read();
            help_visible.set(!cur);
        }
        KeyboardCommand::Archive => {
            let Some(id) = selection.read().message.clone() else {
                return;
            };
            // Pre-compute next-selection target from the visible list
            // *before* the IPC fires; otherwise the post-move refetch
            // would race the read-back. Same pattern as the drag-drop
            // handlers — see `format::next_selection_after_move`.
            let next_sel = crate::format::next_selection_after_move(
                &visible_messages.read(),
                Some(&id),
                std::slice::from_ref(&id),
            );
            spawn(async move {
                let payload = serde_json::json!({
                    "input": { "ids": [id.clone()] }
                });
                if let Err(e) = invoke::<()>("messages_archive", payload).await {
                    web_sys_log(&format!("messages_archive: {e}"));
                    return;
                }
                selection.with_mut(|s| s.message = next_sel);
                sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            });
        }
        KeyboardCommand::Delete => {
            let Some(id) = selection.read().message.clone() else {
                return;
            };
            let next_sel = crate::format::next_selection_after_move(
                &visible_messages.read(),
                Some(&id),
                std::slice::from_ref(&id),
            );
            spawn(async move {
                let payload = serde_json::json!({
                    "input": { "ids": [id.clone()] }
                });
                if let Err(e) = invoke::<()>("messages_delete", payload).await {
                    web_sys_log(&format!("messages_delete: {e}"));
                    return;
                }
                selection.with_mut(|s| s.message = next_sel);
                sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            });
        }
        KeyboardCommand::NextUnread => {
            // Walk the unread subset in display order. Pick the
            // first unread strictly after the current selection, or
            // wrap to the first unread overall if there's nothing
            // later. No-op when there's nothing unread; the user
            // just won't notice the keystroke.
            let unread = unread_visible.read().clone();
            if unread.is_empty() {
                return;
            }
            let visible = visible_messages.read().clone();
            let cur = selection.read().message.clone();
            let cur_pos = cur
                .as_ref()
                .and_then(|c| visible.iter().position(|m| m.0 == c.0));
            let next = match cur_pos {
                Some(idx) => unread
                    .iter()
                    .find(|u| {
                        visible
                            .iter()
                            .position(|m| m.0 == u.0)
                            .is_some_and(|p| p > idx)
                    })
                    .cloned()
                    .unwrap_or_else(|| unread[0].clone()),
                None => unread[0].clone(),
            };
            selection.with_mut(|s| s.message = Some(next));
        }
        KeyboardCommand::NextMessage | KeyboardCommand::PrevMessage => {
            // Walk the published `visible_messages` list relative to the
            // current selection. Wraps at both ends so the user can hold
            // `j` to cycle the inbox without hitting an invisible stop.
            // No-op when the list is empty (compose pane open, search
            // returned nothing, etc.).
            let ids = visible_messages.read().clone();
            if ids.is_empty() {
                return;
            }
            let cur = selection.read().message.clone();
            let cur_idx = cur
                .as_ref()
                .and_then(|c| ids.iter().position(|m| m.0 == c.0));
            let next_idx = match (cmd, cur_idx) {
                (KeyboardCommand::NextMessage, None) => 0,
                (KeyboardCommand::PrevMessage, None) => ids.len() - 1,
                (KeyboardCommand::NextMessage, Some(i)) => (i + 1) % ids.len(),
                (KeyboardCommand::PrevMessage, Some(i)) => {
                    if i == 0 {
                        ids.len() - 1
                    } else {
                        i - 1
                    }
                }
                _ => unreachable!(),
            };
            selection.with_mut(|s| s.message = Some(ids[next_idx].clone()));
        }
        KeyboardCommand::Reply | KeyboardCommand::ReplyAll | KeyboardCommand::Forward => {
            let Some(id) = selection.read().message.clone() else {
                return;
            };
            let kind = match cmd {
                KeyboardCommand::Reply => ReplyKind::Reply,
                KeyboardCommand::ReplyAll => ReplyKind::ReplyAll,
                _ => ReplyKind::Forward,
            };
            // Reply / forward need the full RenderedMessage (subject
            // re-write, quoted body, etc.). Fetch it on demand — adds
            // ~one IPC round-trip but avoids lifting the reader's
            // already-rendered message out to a global signal.
            spawn(async move {
                let payload = serde_json::json!({
                    "input": { "id": id.clone(), "force_trusted": false }
                });
                match invoke::<RenderedMessage>("messages_get", payload).await {
                    Ok(rendered) => open_reply(rendered, compose, kind),
                    Err(e) => web_sys_log(&format!("messages_get for shortcut: {e}")),
                }
            });
        }
    }
}

/// Modal cheatsheet shown over the app shell when `?` is pressed.
/// Closing is via either pressing `?` or `Esc` (both routed through
/// the keyboard dispatcher) or clicking the backdrop.
/// Right-click popover anchored at the cursor coordinates carried by
/// `context_menu`. Operates on the single `message_id` that opened it
/// (NOT on the bulk selection — right-click is single-target by
/// convention; bulk lives in the `bulk-action-bar`). Dismisses on:
///   - any item click (after the action fires),
///   - clicking the transparent backdrop,
///   - Esc (handled by `dispatch_keyboard_command`'s Cancel arm; this
///     popover takes priority over palette / compose / search).
///
/// Reply / Reply-all / Forward fetch the `RenderedMessage` on demand
/// (one IPC round-trip) and call `open_reply` — the same path the
/// keyboard `r` / `a` / `f` shortcuts use, so the resulting compose
/// pane has identical headers + quoted-body.
#[component]
fn MessageContextPopover(
    mut context_menu: Signal<Option<MessageContextMenu>>,
    compose: Signal<Option<ComposeState>>,
    sync_tick: SyncTick,
    selection: Signal<Selection>,
) -> Element {
    let Some(state) = context_menu.read().clone() else {
        return rsx! {};
    };
    let MessageContextMenu {
        x,
        y,
        message_id,
        is_unread,
    } = state;
    // Pin to the viewport. The backdrop catches outside-clicks; the
    // popover stops propagation so clicking inside doesn't dismiss.
    let style = format!("position: fixed; left: {x}px; top: {y}px;");

    let mut dismiss = move || context_menu.set(None);

    let on_reply = {
        let id = message_id.clone();
        let compose_signal = compose;
        let mut menu = context_menu;
        move |_| {
            menu.set(None);
            let id = id.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let payload = serde_json::json!({
                    "input": { "id": id.clone(), "force_trusted": false }
                });
                match invoke::<RenderedMessage>("messages_get", payload).await {
                    Ok(rendered) => open_reply(rendered, compose_signal, ReplyKind::Reply),
                    Err(e) => web_sys_log(&format!("messages_get for context reply: {e}")),
                }
            });
        }
    };

    let on_reply_all = {
        let id = message_id.clone();
        let compose_signal = compose;
        let mut menu = context_menu;
        move |_| {
            menu.set(None);
            let id = id.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let payload = serde_json::json!({
                    "input": { "id": id.clone(), "force_trusted": false }
                });
                match invoke::<RenderedMessage>("messages_get", payload).await {
                    Ok(rendered) => open_reply(rendered, compose_signal, ReplyKind::ReplyAll),
                    Err(e) => web_sys_log(&format!("messages_get for context reply-all: {e}")),
                }
            });
        }
    };

    let on_forward = {
        let id = message_id.clone();
        let compose_signal = compose;
        let mut menu = context_menu;
        move |_| {
            menu.set(None);
            let id = id.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let payload = serde_json::json!({
                    "input": { "id": id.clone(), "force_trusted": false }
                });
                match invoke::<RenderedMessage>("messages_get", payload).await {
                    Ok(rendered) => open_reply(rendered, compose_signal, ReplyKind::Forward),
                    Err(e) => web_sys_log(&format!("messages_get for context forward: {e}")),
                }
            });
        }
    };

    let visible_messages = use_context::<Signal<Vec<MessageId>>>();
    let on_archive = {
        let id = message_id.clone();
        let mut sync_tick = sync_tick;
        let mut selection = selection;
        let mut menu = context_menu;
        move |_| {
            menu.set(None);
            let id = id.clone();
            // Compute the next-selection target only when the
            // right-clicked row IS the currently-open one — otherwise
            // we'd hijack the reader's focus on a context action that
            // had nothing to do with the open message.
            let target_open = selection
                .read()
                .message
                .as_ref()
                .is_some_and(|m| m.0 == id.0);
            let next_sel = if target_open {
                crate::format::next_selection_after_move(
                    &visible_messages.read(),
                    Some(&id),
                    std::slice::from_ref(&id),
                )
            } else {
                None
            };
            wasm_bindgen_futures::spawn_local(async move {
                let payload = serde_json::json!({ "input": { "ids": [id.clone()] } });
                if let Err(e) = invoke::<()>("messages_archive", payload).await {
                    web_sys_log(&format!("context archive: {e}"));
                    return;
                }
                if target_open {
                    selection.with_mut(|s| s.message = next_sel);
                }
                sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            });
        }
    };

    let on_delete = {
        let id = message_id.clone();
        let mut sync_tick = sync_tick;
        let mut selection = selection;
        let mut menu = context_menu;
        move |_| {
            menu.set(None);
            let id = id.clone();
            let target_open = selection
                .read()
                .message
                .as_ref()
                .is_some_and(|m| m.0 == id.0);
            let next_sel = if target_open {
                crate::format::next_selection_after_move(
                    &visible_messages.read(),
                    Some(&id),
                    std::slice::from_ref(&id),
                )
            } else {
                None
            };
            wasm_bindgen_futures::spawn_local(async move {
                let payload = serde_json::json!({ "input": { "ids": [id.clone()] } });
                if let Err(e) = invoke::<()>("messages_delete", payload).await {
                    web_sys_log(&format!("context delete: {e}"));
                    return;
                }
                if target_open {
                    selection.with_mut(|s| s.message = next_sel);
                }
                sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            });
        }
    };

    // The toggle: if currently unread, mark read; if currently read,
    // mark unread. `is_unread` is captured at right-click time so the
    // label matches what the user saw on the row.
    let toggle_label = if is_unread {
        "Mark as read"
    } else {
        "Mark as unread"
    };
    let on_toggle_read = {
        let id = message_id.clone();
        let mut sync_tick = sync_tick;
        let mut menu = context_menu;
        let target_seen = is_unread; // unread → set seen=true
        move |_| {
            menu.set(None);
            let id = id.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let payload = serde_json::json!({
                    "input": { "ids": [id.clone()], "seen": target_seen }
                });
                if let Err(e) = invoke::<()>("messages_mark_read", payload).await {
                    web_sys_log(&format!("context mark_read: {e}"));
                    return;
                }
                sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            });
        }
    };

    let on_open_window = {
        let id = message_id.clone();
        let mut menu = context_menu;
        move |_| {
            menu.set(None);
            let id = id.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = invoke::<()>(
                    "messages_open_in_window",
                    serde_json::json!({ "input": { "id": id } }),
                )
                .await
                {
                    web_sys_log(&format!("context open_in_window: {e}"));
                }
            });
        }
    };

    rsx! {
        div {
            class: "ctx-menu-backdrop",
            onclick: move |_| dismiss(),
            oncontextmenu: move |evt: Event<MouseData>| {
                // Right-click on the backdrop also dismisses, and we
                // suppress the browser's native menu so it doesn't
                // pile up on top of ours.
                evt.prevent_default();
                dismiss();
            },
            div {
                class: "ctx-menu",
                style: "{style}",
                onclick: |evt: Event<MouseData>| evt.stop_propagation(),
                oncontextmenu: |evt: Event<MouseData>| evt.prevent_default(),
                button { class: "ctx-menu-item", r#type: "button", onclick: on_reply, "Reply" }
                button { class: "ctx-menu-item", r#type: "button", onclick: on_reply_all, "Reply all" }
                button { class: "ctx-menu-item", r#type: "button", onclick: on_forward, "Forward" }
                div { class: "ctx-menu-sep" }
                button { class: "ctx-menu-item", r#type: "button", onclick: on_toggle_read, "{toggle_label}" }
                button { class: "ctx-menu-item", r#type: "button", onclick: on_archive, "Archive" }
                button { class: "ctx-menu-item ctx-menu-item-danger", r#type: "button", onclick: on_delete, "Delete" }
                div { class: "ctx-menu-sep" }
                button { class: "ctx-menu-item", r#type: "button", onclick: on_open_window, "Open in new window" }
            }
        }
    }
}

#[component]
fn ShortcutsOverlay(mut visible: Signal<bool>) -> Element {
    rsx! {
        div {
            class: "shortcuts-overlay-backdrop",
            onclick: move |_| visible.set(false),
            div {
                class: "shortcuts-overlay",
                onclick: |evt: Event<MouseData>| evt.stop_propagation(),
                h2 { class: "shortcuts-title", "Keyboard Shortcuts" }
                table {
                    class: "shortcuts-table",
                    tbody {
                        for (key, label) in [
                            ("⌘K", "Command palette"),
                            ("j", "Next message"),
                            ("k", "Previous message"),
                            ("n", "Next unread"),
                            ("c", "Compose"),
                            ("e", "Archive selected message"),
                            ("#", "Delete selected message"),
                            ("r", "Reply"),
                            ("a", "Reply all"),
                            ("f", "Forward"),
                            ("/", "Search mail"),
                            ("Esc", "Close palette / compose / search / selection"),
                            ("?", "Toggle this help"),
                        ] {
                            tr {
                                td {
                                    class: "shortcut-key",
                                    kbd { "{key}" }
                                }
                                td { class: "shortcut-label", "{label}" }
                            }
                        }
                    }
                }
                p {
                    class: "shortcuts-footnote",
                    "Shortcuts are ignored while typing in a field."
                }
            }
        }
    }
}

/// Command palette (⌘K). Centered overlay that fuzzy-matches the
/// query against three sources: every account's folders ("jump to"),
/// a static command list (compose / settings / add account / help),
/// and recent search queries. ESC / Cmd+K closes; arrow keys
/// navigate; Enter dispatches.
#[component]
fn CommandPalette(
    mut visible: Signal<bool>,
    mut selection: Signal<Selection>,
    mut compose: Signal<Option<ComposeState>>,
    sync_tick: SyncTick,
    mut search_query: Signal<String>,
    recent_searches: Signal<Vec<String>>,
    mut help_visible: Signal<bool>,
) -> Element {
    let mut query = use_signal(String::new);
    let mut active_idx = use_signal(|| 0usize);

    // Live full-text-search hits for the current query. Re-fires on
    // every keystroke; the SQL FTS path is fast enough that we don't
    // bother debouncing. Skipped for queries < 2 chars to avoid the
    // unhelpful "match every message starting with t" results that a
    // single character produces.
    let q_for_search = query.read().clone();
    let search_hits = use_resource(use_reactive!(|q_for_search| async move {
        if q_for_search.trim().len() < 2 {
            return Ok::<MessagePage, String>(MessagePage {
                messages: Vec::new(),
                total_count: 0,
                unread_count: 0,
                thread_counts: std::collections::HashMap::new(),
                indexing_in_progress: false,
            });
        }
        invoke::<MessagePage>(
            "messages_search",
            serde_json::json!({
                "input": { "query": q_for_search, "limit": 6, "offset": 0 },
            }),
        )
        .await
    }));

    // Pull every account + its folders. Refetched on each open since
    // the palette only mounts when `visible` is true; closed-then-
    // reopened picks up brand-new accounts/folders without staleness.
    let folders = use_resource(|| async move {
        let accounts = invoke::<Vec<Account>>("accounts_list", ()).await?;
        let mut out: Vec<(Account, Vec<Folder>)> = Vec::with_capacity(accounts.len());
        for a in accounts {
            let folders_for_account = invoke::<Vec<Folder>>(
                "folders_list",
                serde_json::json!({ "input": { "account": a.id } }),
            )
            .await
            .unwrap_or_default();
            out.push((a, folders_for_account));
        }
        Ok::<_, String>(out)
    });

    // Build the entry list. Filter happens against the lowercase
    // search-text of each entry; substring is good enough for v0.1.
    let raw_query = query.read().clone();
    let q = raw_query.to_lowercase();
    // Static commands always appear so users can discover them.
    let mut entries: Vec<PaletteEntry> = vec![
        PaletteEntry::Command(PaletteCommand::Compose),
        PaletteEntry::Command(PaletteCommand::OpenSettings),
        PaletteEntry::Command(PaletteCommand::AddAccount),
        PaletteEntry::Command(PaletteCommand::ToggleHelp),
        PaletteEntry::Command(PaletteCommand::ClearReader),
    ];

    if let Some(Ok(account_groups)) = folders.read_unchecked().as_ref() {
        for (account, folder_list) in account_groups {
            for f in folder_list {
                entries.push(PaletteEntry::Folder {
                    account_id: account.id.clone(),
                    folder_id: f.id.clone(),
                    folder_label: crate::format::display_name_for_folder(&f.name).to_string(),
                    account_label: account.email_address.clone(),
                });
            }
        }
    }

    for s in recent_searches.read().iter() {
        entries.push(PaletteEntry::RecentSearch(s.clone()));
    }

    // Substring-filter the standard entries against the typed query.
    // Search-typed entries (RunSearch / SearchHit) are added below
    // and bypass this filter — they're computed from the query.
    let mut filtered: Vec<PaletteEntry> = if q.is_empty() {
        entries
    } else {
        entries
            .into_iter()
            .filter(|e| e.search_text().to_lowercase().contains(&q))
            .collect()
    };

    // Prepend search entries when the user has typed at least two
    // chars: the explicit "Search mail for: q" entry first (so Enter
    // on a fresh query opens the search results pane), then live
    // hits. The hits are limited to 6 to keep the palette terse.
    let trimmed_query = raw_query.trim();
    if trimmed_query.len() >= 2 {
        let mut search_entries: Vec<PaletteEntry> =
            vec![PaletteEntry::RunSearch(trimmed_query.to_string())];
        if let Some(Ok(MessagePage { messages, .. })) = search_hits.read_unchecked().as_ref() {
            for m in messages.iter() {
                let sender = m
                    .from
                    .first()
                    .map(|a| {
                        a.display_name
                            .clone()
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| a.address.clone())
                    })
                    .unwrap_or_default();
                search_entries.push(PaletteEntry::SearchHit {
                    message_id: m.id.clone(),
                    subject: m.subject.clone(),
                    sender,
                    query: trimmed_query.to_string(),
                });
            }
        }
        search_entries.extend(filtered.into_iter());
        filtered = search_entries;
    }

    // Clamp the active index inside the filtered range. Re-evaluating
    // on each render means a query that filters the list shorter
    // doesn't leave the highlight pointing past the end.
    let max_idx = filtered.len().saturating_sub(1);
    let cur_idx = (*active_idx.read()).min(max_idx);

    let mut dispatch_entry = move |entry: PaletteEntry, mut visible: Signal<bool>| {
        match entry {
            PaletteEntry::Folder {
                account_id,
                folder_id,
                ..
            } => {
                selection.with_mut(|s| {
                    s.account = Some(account_id);
                    s.folder = Some(folder_id);
                    s.message = None;
                    s.unified = false;
                });
            }
            PaletteEntry::Command(PaletteCommand::Compose) => {
                let default_account = selection.read().account.clone();
                compose.set(Some(ComposeState {
                    default_account,
                    draft_id: None,
                    prefill: None,
                }));
            }
            PaletteEntry::Command(PaletteCommand::OpenSettings) => {
                spawn(async move {
                    if let Err(e) = invoke::<()>("settings_open", serde_json::json!({})).await {
                        web_sys_log(&format!("settings_open: {e}"));
                    }
                });
            }
            PaletteEntry::Command(PaletteCommand::AddAccount) => {
                spawn(async move {
                    if let Err(e) = invoke::<()>("oauth_add_open", serde_json::json!({})).await {
                        web_sys_log(&format!("oauth_add_open: {e}"));
                    }
                });
            }
            PaletteEntry::Command(PaletteCommand::ToggleHelp) => {
                let cur = *help_visible.read();
                help_visible.set(!cur);
            }
            PaletteEntry::Command(PaletteCommand::ClearReader) => {
                selection.with_mut(|s| s.message = None);
            }
            PaletteEntry::RecentSearch(s) => {
                search_query.set(s);
            }
            PaletteEntry::RunSearch(s) => {
                search_query.set(s);
            }
            PaletteEntry::SearchHit {
                message_id, query, ..
            } => {
                // Pin the search-results pane to the originating
                // query so the message lands inside its own context
                // (with surrounding hits visible to scroll through).
                // Setting the message id alone wouldn't be enough
                // when the user is currently looking at a folder
                // that doesn't contain the picked message.
                search_query.set(query);
                selection.with_mut(|s| s.message = Some(message_id));
            }
        }
        let _ = sync_tick;
        visible.set(false);
    };

    rsx! {
        div {
            class: "palette-backdrop",
            onclick: move |_| visible.set(false),
            div {
                class: "palette-shell",
                onclick: |evt: Event<MouseData>| evt.stop_propagation(),
                input {
                    id: "qsl-palette-input",
                    class: "palette-input",
                    r#type: "text",
                    autocomplete: "off",
                    spellcheck: "false",
                    placeholder: "Search mail · jump to mailbox · run command",
                    value: "{query}",
                    oninput: move |evt: Event<FormData>| {
                        query.set(evt.value());
                        active_idx.set(0);
                    },
                    onkeydown: {
                        let entries_for_key = filtered.clone();
                        move |evt: Event<KeyboardData>| {
                            match evt.key() {
                                Key::Escape => {
                                    evt.prevent_default();
                                    visible.set(false);
                                }
                                Key::ArrowDown => {
                                    evt.prevent_default();
                                    if !entries_for_key.is_empty() {
                                        let next = (cur_idx + 1) % entries_for_key.len();
                                        active_idx.set(next);
                                    }
                                }
                                Key::ArrowUp => {
                                    evt.prevent_default();
                                    if !entries_for_key.is_empty() {
                                        let prev = if cur_idx == 0 {
                                            entries_for_key.len() - 1
                                        } else {
                                            cur_idx - 1
                                        };
                                        active_idx.set(prev);
                                    }
                                }
                                Key::Enter => {
                                    evt.prevent_default();
                                    if let Some(entry) = entries_for_key.get(cur_idx).cloned() {
                                        dispatch_entry(entry, visible);
                                    }
                                }
                                _ => {}
                            }
                        }
                    },
                    autofocus: true,
                }
                if filtered.is_empty() {
                    div { class: "palette-empty", "No matches." }
                } else {
                    div {
                        class: "palette-list",
                        for (i, entry) in filtered.iter().enumerate() {
                            {
                                let entry_for_click = entry.clone();
                                let row_class = if i == cur_idx {
                                    "palette-row palette-row-active"
                                } else {
                                    "palette-row"
                                };
                                rsx! {
                                    button {
                                        key: "{i}",
                                        class: row_class,
                                        r#type: "button",
                                        onmouseenter: move |_| active_idx.set(i),
                                        onclick: move |_| dispatch_entry(entry_for_click.clone(), visible),
                                        span { class: "palette-row-kind", "{entry.kind_label()}" }
                                        span { class: "palette-row-label", "{entry.primary_label()}" }
                                        if let Some(meta) = entry.secondary_label() {
                                            span { class: "palette-row-meta", "{meta}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div {
                    class: "palette-footnote",
                    "↑↓ navigate · ↵ select · Esc close"
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PaletteEntry {
    Folder {
        account_id: AccountId,
        folder_id: FolderId,
        folder_label: String,
        account_label: String,
    },
    Command(PaletteCommand),
    RecentSearch(String),
    /// "Search mail for: <query>" — opens the SearchResults pane with
    /// the query, same as typing into the `/` bar.
    RunSearch(String),
    /// A live full-text-search match, surfaced inline in the palette.
    /// Picking it opens the message in the reader and pins the
    /// SearchResults pane to the originating query so the surrounding
    /// hits are still visible.
    SearchHit {
        message_id: MessageId,
        subject: String,
        sender: String,
        query: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaletteCommand {
    Compose,
    OpenSettings,
    AddAccount,
    ToggleHelp,
    ClearReader,
}

impl PaletteEntry {
    fn kind_label(&self) -> &'static str {
        match self {
            PaletteEntry::Folder { .. } => "jump",
            PaletteEntry::Command(_) => "cmd",
            PaletteEntry::RecentSearch(_) => "recent",
            PaletteEntry::RunSearch(_) => "search",
            PaletteEntry::SearchHit { .. } => "hit",
        }
    }

    fn primary_label(&self) -> String {
        match self {
            PaletteEntry::Folder { folder_label, .. } => folder_label.clone(),
            PaletteEntry::Command(cmd) => cmd.label().to_string(),
            PaletteEntry::RecentSearch(q) => q.clone(),
            PaletteEntry::RunSearch(q) => format!("Search mail for: {q}"),
            PaletteEntry::SearchHit { subject, .. } => {
                if subject.is_empty() {
                    "(no subject)".to_string()
                } else {
                    subject.clone()
                }
            }
        }
    }

    fn secondary_label(&self) -> Option<String> {
        match self {
            PaletteEntry::Folder { account_label, .. } => Some(account_label.clone()),
            PaletteEntry::Command(_) => None,
            PaletteEntry::RecentSearch(_) => None,
            PaletteEntry::RunSearch(_) => None,
            PaletteEntry::SearchHit { sender, .. } => Some(sender.clone()),
        }
    }

    /// Text the filter substring-matches against. Includes both the
    /// primary label and the secondary so typing the account name
    /// surfaces every folder under it. RunSearch / SearchHit bypass
    /// the substring gate (they're computed from the query) and
    /// return the empty string to opt out of post-filtering.
    fn search_text(&self) -> String {
        match self {
            PaletteEntry::Folder {
                folder_label,
                account_label,
                ..
            } => format!("{folder_label} {account_label}"),
            PaletteEntry::Command(cmd) => cmd.label().to_string(),
            PaletteEntry::RecentSearch(q) => q.clone(),
            PaletteEntry::RunSearch(_) | PaletteEntry::SearchHit { .. } => String::new(),
        }
    }
}

impl PaletteCommand {
    fn label(&self) -> &'static str {
        match self {
            PaletteCommand::Compose => "Compose new message",
            PaletteCommand::OpenSettings => "Open settings",
            PaletteCommand::AddAccount => "Add account",
            PaletteCommand::ToggleHelp => "Toggle keyboard shortcuts",
            PaletteCommand::ClearReader => "Close reader",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SplitTarget {
    Sidebar,
    List,
}

// ---------- Status bar ----------

/// Sync activity surfaced in the bottom status bar.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncStatus {
    /// No sync_event has landed yet — engine is still in its
    /// pre-bootstrap wait or just kicking off.
    Initializing,
    /// Sync engine has begun a folder cycle but `FolderSynced` hasn't
    /// landed yet. Lets the status bar render "Syncing INBOX…" while
    /// the per-folder sync_folder runs (multi-second on large
    /// folders).
    Syncing { folder: String },
    /// Most recent successful folder cycle. `live=false` rows
    /// (bootstrap pass) get a slightly different label.
    Synced {
        folder: String,
        added: u32,
        updated: u32,
        live: bool,
    },
    /// Most recent failure, kept around until the next successful
    /// cycle replaces it.
    Failed { folder: String, error: String },
}

impl SyncStatus {
    fn from_event(evt: &SyncEvent) -> Option<Self> {
        match evt {
            SyncEvent::FolderStarted { folder, .. } => Some(SyncStatus::Syncing {
                folder: short_folder_label(&folder.0),
            }),
            SyncEvent::FolderSynced {
                folder,
                added,
                updated,
                live,
                ..
            } => Some(SyncStatus::Synced {
                folder: short_folder_label(&folder.0),
                added: *added,
                updated: *updated,
                live: *live,
            }),
            SyncEvent::FolderError { folder, error, .. } => Some(SyncStatus::Failed {
                folder: short_folder_label(&folder.0),
                error: error.clone(),
            }),
            // History-sync progress is surfaced through the dedicated
            // `history_activity` signal so it can preempt the regular
            // folder-sync line in the status bar without losing it.
            SyncEvent::HistorySyncProgress { .. } => None,
        }
    }
}

/// In-flight history-sync surfaced in the bottom status bar. Lives in
/// its own signal (not folded into [`SyncStatus`]) so a folder-sync
/// cycle landing while a history pull is running doesn't overwrite
/// the progress line — the bar overlays history on top while the pull
/// is active and falls back to the regular sync status when it ends.
///
/// Multi-folder edge case: only the most recently touched (account,
/// folder) is tracked. The driver runs at most one active pull per
/// account (per `history_account_locks`), so for the dominant
/// single-account user this is exactly one row at a time. Multi-account
/// last-write-wins is acceptable for an indicator — the Settings panel
/// is the source of truth for full per-row state.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryActivity {
    pub account: AccountId,
    pub folder_id: FolderId,
    /// Already short-labeled for display (e.g. `INBOX`).
    pub folder_label: String,
    pub fetched: u32,
    pub total_estimate: Option<u32>,
}

impl HistoryActivity {
    /// Translate a `HistorySyncProgress` into a status-bar update.
    /// `Some(Some(_))` = show this activity, `Some(None)` = clear if
    /// the currently-shown activity matches this (account, folder),
    /// `None` = ignore (status doesn't affect the bar — e.g. pending
    /// rows are queued and don't represent active work).
    fn from_event(evt: &SyncEvent) -> Option<Option<Self>> {
        let SyncEvent::HistorySyncProgress {
            account,
            folder,
            status,
            fetched,
            total_estimate,
            ..
        } = evt
        else {
            return None;
        };
        match status.as_str() {
            "running" | "in-flight" => Some(Some(HistoryActivity {
                account: account.clone(),
                folder_id: folder.clone(),
                folder_label: short_folder_label(&folder.0),
                fetched: *fetched,
                total_estimate: *total_estimate,
            })),
            "completed" | "canceled" | "error" => Some(None),
            // `pending` rows are queued behind the active pull. Don't
            // surface them in the status bar — it would race with the
            // running row's progress line on multi-folder kicks.
            _ => None,
        }
    }
}

/// Render a folder id like "imap:user@host:INBOX" → "INBOX". Falls
/// back to the raw id when it doesn't carry a colon-separated tail.
fn short_folder_label(folder_id: &str) -> String {
    folder_id
        .rsplit_once(':')
        .map(|(_, tail)| tail.to_string())
        .unwrap_or_else(|| folder_id.to_string())
}

/// Top bar above the three-pane shell. Renders the `qsl` wordmark,
/// version, a `⌘K` command-palette pill (no-op until the palette
/// lands), and an account-filter chip on the right. Mono + dense
/// per `docs/ui-direction.md` § Top bar.
///
/// `account_filter` is the App-root signal that scopes the message
/// list to a single account. `None` = show every account; clicking
/// the chip opens a dropdown with the configured accounts plus an
/// "all accounts" reset.
///
/// `sync_tick` drives the chip's account-list refetch on
/// `accounts_changed` (host-emitted after add / remove) so the
/// chip's options don't lag a deletion done in Settings.
#[component]
fn TopBar(
    account_filter: Signal<Option<AccountId>>,
    mut palette_visible: Signal<bool>,
    sync_tick: SyncTick,
) -> Element {
    let tick_value = sync_tick();
    let accounts = use_resource(use_reactive!(|tick_value| async move {
        let _ = tick_value;
        invoke::<Vec<Account>>("accounts_list", ()).await
    }));
    let mut chip_open: Signal<bool> = use_signal(|| false);

    let chip_label: String = match (
        account_filter.read().clone(),
        accounts.read_unchecked().as_ref(),
    ) {
        (None, Some(Ok(list))) if list.is_empty() => "no accounts".to_string(),
        (None, _) => "all accounts".to_string(),
        (Some(id), Some(Ok(list))) => list
            .iter()
            .find(|a| a.id == id)
            .map(|a| a.email_address.clone())
            .unwrap_or_else(|| id.0.clone()),
        (Some(id), _) => id.0.clone(),
    };

    rsx! {
        header {
            class: "topbar",
            div {
                class: "topbar-left",
                span { class: "topbar-wordmark", "qsl" }
                span {
                    class: "topbar-version",
                    {env!("CARGO_PKG_VERSION")}
                }
            }
            button {
                class: "topbar-cmd-pill",
                r#type: "button",
                title: "Command palette ({palette_shortcut_label()})",
                onclick: move |_| {
                    let cur = *palette_visible.read();
                    palette_visible.set(!cur);
                },
                span { class: "topbar-cmd-key", "{palette_shortcut_label()}" }
                span { "search · jump · command" }
            }
            div {
                class: "topbar-right",
                div {
                    class: "topbar-chip-wrap",
                    button {
                        class: if chip_open() { "topbar-chip topbar-chip-open" } else { "topbar-chip" },
                        r#type: "button",
                        title: "Filter messages by account",
                        onclick: move |_| {
                            let cur = chip_open();
                            chip_open.set(!cur);
                        },
                        span { class: "topbar-chip-label", "{chip_label}" }
                        span { class: "topbar-chip-arrow", if chip_open() { "▴" } else { "▾" } }
                    }
                    if chip_open() {
                        div {
                            class: "topbar-chip-menu",
                            button {
                                class: if account_filter.read().is_none() {
                                    "topbar-chip-item topbar-chip-item-active"
                                } else {
                                    "topbar-chip-item"
                                },
                                r#type: "button",
                                onclick: move |_| {
                                    account_filter.set(None);
                                    chip_open.set(false);
                                },
                                "all accounts"
                            }
                            match &*accounts.read_unchecked() {
                                Some(Ok(list)) => rsx! {
                                    for a in list.iter().cloned() {
                                        {
                                            let id_for_select = a.id.clone();
                                            let id_for_match = a.id.clone();
                                            let active = account_filter.read().as_ref() == Some(&id_for_match);
                                            rsx! {
                                                button {
                                                    key: "{a.id.0}",
                                                    class: if active {
                                                        "topbar-chip-item topbar-chip-item-active"
                                                    } else {
                                                        "topbar-chip-item"
                                                    },
                                                    r#type: "button",
                                                    onclick: move |_| {
                                                        account_filter.set(Some(id_for_select.clone()));
                                                        chip_open.set(false);
                                                    },
                                                    "{a.email_address}"
                                                }
                                            }
                                        }
                                    }
                                },
                                Some(Err(e)) => rsx! {
                                    span { class: "topbar-chip-item topbar-chip-error", "Error: {e}" }
                                },
                                None => rsx! {},
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn StatusBar(status: Signal<SyncStatus>, history: Signal<Option<HistoryActivity>>) -> Element {
    let history_snapshot = history.read().clone();
    let snapshot = status.read().clone();
    // History-sync preempts the regular folder-sync line while a pull
    // is active — it's the long-running, user-initiated operation the
    // status bar should foreground. The folder line resumes when the
    // pull terminates.
    let (dot_class, label) = if let Some(activity) = &history_snapshot {
        let detail = match (activity.fetched, activity.total_estimate) {
            (fetched, Some(total)) if total > 0 => {
                let pct = (fetched as f64 / total as f64 * 100.0).clamp(0.0, 100.0);
                format!("{fetched} / ~{total} ({pct:.0}%)")
            }
            (fetched, _) => format!("{fetched} fetched"),
        };
        (
            "status-dot working",
            format!("Pulling history · {} · {detail}", activity.folder_label),
        )
    } else {
        match &snapshot {
            SyncStatus::Initializing => ("status-dot working", "Initializing…".to_string()),
            SyncStatus::Syncing { folder } => ("status-dot working", format!("Syncing {folder}…")),
            SyncStatus::Synced {
                folder,
                added,
                updated,
                live,
            } => {
                let prefix = if *live { "Synced" } else { "Loaded" };
                let counts = if *added == 0 && *updated == 0 {
                    String::new()
                } else if *updated == 0 {
                    format!(" · {added} new")
                } else if *added == 0 {
                    format!(" · {updated} updated")
                } else {
                    format!(" · {added} new · {updated} updated")
                };
                ("status-dot ok", format!("{prefix} {folder}{counts}"))
            }
            SyncStatus::Failed { folder, error } => (
                "status-dot error",
                format!("Sync failed: {folder} — {error}"),
            ),
        }
    };

    rsx! {
        footer {
            class: "status-bar",
            div {
                class: "status-left",
                span { class: "{dot_class}" }
                span { class: "status-label", "{label}" }
            }
            div {
                class: "status-center",
                // Capability flags (CONDSTORE / QRESYNC / IDLE) land here
                // once the connection-level negotiation surfaces in the
                // sync events. Phase 2 placeholder: blank center column
                // keeps the 3-column grid stable.
            }
            div {
                class: "status-right",
                span { "? help" }
            }
        }
    }
}

/// Tiny `console.log` shim — saves pulling `web-sys` for one call.
pub(crate) fn web_sys_log(msg: &str) {
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console)]
        fn log(s: &str);
    }
    log(msg);
}

// ---------- Reader-pane HTML composer ----------

/// Build the HTML document the Servo reader pane renders when a
/// message is selected. Thin wrapper around
/// [`qsl_mime::compose_reader_html`] that translates from the IPC
/// `RenderedMessage` shape — both this UI path and the desktop popup
/// install path go through the same shared composer so the markup is
/// byte-identical and the placeholder / theming rules live in one
/// place.
pub(crate) fn compose_reader_html(rendered: &RenderedMessage) -> String {
    let origin = web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_else(|| "*".to_string());
    qsl_core::compose_reader_html(
        rendered.sanitized_html.as_deref(),
        rendered.body_text.as_deref(),
        &origin,
    )
}

/// Compact byte-size formatter for attachment chips. Uses
/// IEC-style binary units (KiB/MiB) with one decimal of precision
/// for the `<10 MiB` range and integer truncation past that. Free
/// function so the [`AttachmentChips`] component stays focused.
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else if bytes < GIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    }
}

// ---------- Middle pane: compose ----------

#[component]
fn ComposePane(
    compose: Signal<Option<ComposeState>>,
    sync_tick: SyncTick,
    undo_send_pending: Signal<Option<f64>>,
) -> Element {
    let initial = compose.read().clone();
    let Some(initial) = initial else {
        return rsx! { p { class: "hint", "No compose state — this shouldn't render." } };
    };

    let accounts = use_resource(|| async { invoke::<Vec<Account>>("accounts_list", ()).await });

    // Pre-load draft if we were opened with one. `loaded` flips
    // true after the load completes (or immediately for fresh
    // composes) so the form fields don't render before they're
    // populated.
    let draft_id = use_signal(|| initial.draft_id.clone());
    let mut account_id = use_signal(|| initial.default_account.clone());
    let mut to_str = use_signal(String::new);
    let mut cc_str = use_signal(String::new);
    let mut bcc_str = use_signal(String::new);
    let mut subject = use_signal(String::new);
    let mut body = use_signal(String::new);
    let mut loaded = use_signal(|| initial.draft_id.is_none());
    // Bcc starts hidden: most outgoing mail doesn't use it, so the
    // dense compose chrome shouldn't reserve a row by default. The
    // user reveals it via the `+bcc` link in the Cc row, OR a draft
    // hydration that finds non-empty bcc content auto-reveals it
    // (carrying over from a saved draft or a future reply-with-bcc
    // flow). Once shown in this compose session, stays shown.
    let mut bcc_revealed = use_signal(|| false);

    // Once-per-mount guard for "did we already append the signature?"
    // Without it the signature effect would re-run on every account
    // switch and stack copies into the body, or worse, append over a
    // user's edits. We append on first observation of a non-empty
    // account_id when the body is empty, then never again.
    let mut signature_applied = use_signal(|| false);
    let mut last_change = use_signal(|| 0u64);
    let mut save_status: Signal<SaveStatus> = use_signal(|| SaveStatus::Idle);
    let send_in_flight: Signal<bool> = use_signal(|| false);
    // Drives the countdown banner re-render. Updated by the timer in
    // `send_now` while `undo_send_pending` is `Some`. Local because
    // the App-level Cancel handler doesn't need to read it — only
    // `undo_send_pending` (the deadline) is the cross-component
    // contract; this is just for display.
    let undo_send_now_ms = use_signal(|| 0.0_f64);
    // Attachments. Populated either by the file picker (`+ Attach`
    // button) or rehydrated from the loaded draft. Round-trips through
    // every `drafts_save` call so the persisted draft row matches the
    // editor state.
    let mut attachments: Signal<Vec<DraftAttachment>> = use_signal(Vec::new);
    // Reply context from the original draft (when opened via Reply /
    // Reply-All / Forward). Not edited by the user but must survive
    // every save round-trip so the eventual `messages_send` call
    // sees the correct `In-Reply-To` / `References` in storage.
    let mut in_reply_to = use_signal(|| None::<String>);
    let mut references = use_signal(Vec::<String>::new);

    // Inline spell-check toggle (`compose.spellcheck`). Read once at
    // mount, default-on if unset, then live-updated via the same
    // `app_settings_changed` event the appearance hooks use — so
    // toggling the Settings checkbox flips underline rendering on
    // the open compose pane without re-mounting it.
    let mut spellcheck_on = use_signal(|| true);
    use_hook(move || {
        wasm_bindgen_futures::spawn_local(async move {
            let v = invoke::<Option<String>>(
                "app_settings_get",
                serde_json::json!({ "input": { "key": crate::settings::KEY_SPELLCHECK } }),
            )
            .await
            .ok()
            .flatten();
            // Stored as "true"/"false" strings; absent → default on.
            let on = !matches!(v.as_deref(), Some("false"));
            spellcheck_on.set(on);
        });
    });
    use_hook(move || {
        let cb = Closure::<dyn FnMut(JsValue)>::new(move |payload: JsValue| {
            #[derive(serde::Deserialize)]
            struct Changed {
                key: String,
                value: String,
            }
            let Ok(evt) = serde_wasm_bindgen::from_value::<Changed>(payload) else {
                return;
            };
            if evt.key == crate::settings::KEY_SPELLCHECK {
                spellcheck_on.set(evt.value != "false");
            }
        });
        wasm_bindgen_futures::spawn_local(async move {
            let func = cb.as_ref().unchecked_ref::<js_sys::Function>();
            if let Err(e) = tauri_listen("app_settings_changed", func).await {
                web_sys_log(&format!("compose spellcheck listen failed: {e:?}"));
            }
            Box::leak(Box::new(cb));
        });
    });

    // One-shot prefill from a `mailto:` deep-link (or any other
    // ComposeState carrying `prefill`). Only applies when no
    // draft_id was supplied — drafts override prefills, since the
    // saved draft is by definition the authoritative copy.
    use_hook({
        let prefill = initial.prefill.clone();
        let has_draft = initial.draft_id.is_some();
        move || {
            if has_draft {
                return;
            }
            let Some(p) = prefill else {
                return;
            };
            if let Some(v) = p.to {
                to_str.set(v);
            }
            if let Some(v) = p.cc {
                cc_str.set(v);
            }
            if let Some(v) = p.bcc {
                if !v.trim().is_empty() {
                    bcc_revealed.set(true);
                    bcc_str.set(v);
                }
            }
            if let Some(v) = p.subject {
                subject.set(v);
            }
            if let Some(v) = p.body {
                body.set(v);
            }
        }
    });

    // One-shot draft hydration. `use_hook` runs at mount; the
    // dependency-free `use_future` would refire on every render.
    use_hook({
        let initial_id = initial.draft_id.clone();
        move || {
            if let Some(id) = initial_id {
                wasm_bindgen_futures::spawn_local(async move {
                    let result = invoke::<Draft>(
                        "drafts_load",
                        serde_json::json!({ "input": { "id": id } }),
                    )
                    .await;
                    match result {
                        Ok(d) => {
                            account_id.set(Some(d.account_id));
                            to_str.set(format_addrs(&d.to));
                            cc_str.set(format_addrs(&d.cc));
                            let bcc_loaded = format_addrs(&d.bcc);
                            if !bcc_loaded.trim().is_empty() {
                                bcc_revealed.set(true);
                            }
                            bcc_str.set(bcc_loaded);
                            subject.set(d.subject);
                            body.set(d.body);
                            in_reply_to.set(d.in_reply_to);
                            references.set(d.references);
                            attachments.set(d.attachments);
                            loaded.set(true);
                        }
                        Err(e) => {
                            web_sys_log(&format!("drafts_load: {e}"));
                            loaded.set(true);
                        }
                    }
                });
            }
        }
    });

    // Append the per-account signature on the first compose mount
    // for a fresh draft. Reads `compose.signature.<account_id>` from
    // app_settings; if non-empty, appends `\n\n-- \n<sig>` to the
    // body. RFC 3676 §4.3 sig delimiter (`-- ` with trailing space
    // and a literal newline) is what every modern client expects.
    // Skipped when:
    //   - draft was hydrated from disk (existing draft already has
    //     the user's prior body, including any earlier signature),
    //   - body already has content (user pasted before the
    //     signature lookup landed), or
    //   - this compose session has already applied a signature.
    {
        let initial_had_draft = initial.draft_id.is_some();
        let acc = account_id.read().clone();
        use_effect(use_reactive!(|acc| {
            if initial_had_draft {
                return;
            }
            if *signature_applied.read() {
                return;
            }
            let Some(account) = acc.as_ref() else {
                return;
            };
            if !body.read().is_empty() {
                return;
            }
            let key = crate::settings::compose_signature_key(account);
            wasm_bindgen_futures::spawn_local(async move {
                let payload = serde_json::json!({ "input": { "key": key } });
                match invoke::<Option<String>>("app_settings_get", payload).await {
                    Ok(Some(sig)) if !sig.trim().is_empty() => {
                        let mut current = body.read().clone();
                        if current.is_empty() && !*signature_applied.read() {
                            current.push_str("\n\n-- \n");
                            current.push_str(&sig);
                            body.set(current);
                            signature_applied.set(true);
                        }
                    }
                    _ => {}
                }
            });
        }));
    }

    // Auto-save: every change bumps `last_change`. A spawned future
    // sleeps 5s, then checks whether `last_change` advanced; if not,
    // it persists. Multiple concurrent futures are fine — only the
    // one whose snapshot still matches will actually save.
    use_effect({
        let acc_signal = account_id;
        let to_signal = to_str;
        let cc_signal = cc_str;
        let bcc_signal = bcc_str;
        let subject_signal = subject;
        let body_signal = body;
        let in_reply_to_signal = in_reply_to;
        let references_signal = references;
        let attachments_signal = attachments;
        let mut draft_signal = draft_id;
        let last_change_signal = last_change;
        let mut status_signal = save_status;
        let mut sync_tick = sync_tick;
        move || {
            let current = last_change_signal();
            if current == 0 {
                return;
            }
            let acc = acc_signal.read().clone();
            let Some(acc) = acc else { return };
            let to = parse_addrs(&to_signal.read());
            let cc = parse_addrs(&cc_signal.read());
            let bcc = parse_addrs(&bcc_signal.read());
            let subject_text = subject_signal.read().clone();
            let body_text = body_signal.read().clone();
            let id = draft_signal.read().clone();
            let in_reply_to_val = in_reply_to_signal.read().clone();
            let references_val = references_signal.read().clone();
            let attachments_val = attachments_signal.read().clone();

            wasm_bindgen_futures::spawn_local(async move {
                gloo_timers::future::sleep(std::time::Duration::from_secs(5)).await;
                if last_change_signal() != current {
                    return; // a more recent edit will handle the save
                }
                let payload = serde_json::json!({
                    "input": {
                        "draft": {
                            "id": id,
                            "account_id": acc,
                            "to": to,
                            "cc": cc,
                            "bcc": bcc,
                            "subject": subject_text,
                            "body": body_text,
                            "body_kind": DraftBodyKind::Plain,
                            "attachments": attachments_val,
                            "in_reply_to": in_reply_to_val,
                            "references": references_val,
                        }
                    }
                });
                match invoke::<DraftId>("drafts_save", payload).await {
                    Ok(new_id) => {
                        draft_signal.set(Some(new_id));
                        status_signal.set(SaveStatus::Saved);
                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                    }
                    Err(e) => {
                        web_sys_log(&format!("drafts_save (auto): {e}"));
                        status_signal.set(SaveStatus::Error(e));
                    }
                }
            });
        }
    });

    // Manual save. Mirrors the auto-save closure but skips the 5s
    // wait. Used for the toolbar Save button + onkeydown Ctrl-S.
    let mut manual_save = {
        let acc_signal = account_id;
        let to_signal = to_str;
        let cc_signal = cc_str;
        let bcc_signal = bcc_str;
        let subject_signal = subject;
        let body_signal = body;
        let in_reply_to_signal = in_reply_to;
        let references_signal = references;
        let attachments_signal = attachments;
        let mut draft_signal = draft_id;
        let mut status_signal = save_status;
        let mut sync_tick = sync_tick;
        move || {
            let acc = acc_signal.read().clone();
            let Some(acc) = acc else { return };
            let to = parse_addrs(&to_signal.read());
            let cc = parse_addrs(&cc_signal.read());
            let bcc = parse_addrs(&bcc_signal.read());
            let subject_text = subject_signal.read().clone();
            let body_text = body_signal.read().clone();
            let id = draft_signal.read().clone();
            let in_reply_to_val = in_reply_to_signal.read().clone();
            let references_val = references_signal.read().clone();
            let attachments_val = attachments_signal.read().clone();
            status_signal.set(SaveStatus::Saving);
            wasm_bindgen_futures::spawn_local(async move {
                let payload = serde_json::json!({
                    "input": {
                        "draft": {
                            "id": id,
                            "account_id": acc,
                            "to": to,
                            "cc": cc,
                            "bcc": bcc,
                            "subject": subject_text,
                            "body": body_text,
                            "body_kind": DraftBodyKind::Plain,
                            "attachments": attachments_val,
                            "in_reply_to": in_reply_to_val,
                            "references": references_val,
                        }
                    }
                });
                match invoke::<DraftId>("drafts_save", payload).await {
                    Ok(new_id) => {
                        draft_signal.set(Some(new_id));
                        status_signal.set(SaveStatus::Saved);
                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                    }
                    Err(e) => {
                        web_sys_log(&format!("drafts_save (manual): {e}"));
                        status_signal.set(SaveStatus::Error(e));
                    }
                }
            });
        }
    };

    // Send: save the draft (so the server-side row reflects current
    // editor state), then enqueue an `OP_SUBMIT_MESSAGE` outbox row
    // via `messages_send`. On success, close the compose pane —
    // the drain worker takes over from there.
    //
    // Undo-send: when `compose.undo_send` is `5` / `10` / `30` (sec),
    // the click instead arms a banner with a deadline. The body of
    // this closure spawns a 250 ms tick loop that watches for the
    // user (or the Esc handler in `dispatch_keyboard_command`) clearing
    // `undo_send_pending`. If the deadline arrives with the same
    // pending value, we proceed to save + submit; if it changed, we
    // bail. Equality on the deadline (as opposed to a separate
    // generation counter) is what makes external cancellation work
    // without extra plumbing — the App-level Cancel handler just sets
    // the signal to `None` and our loop notices.
    let mut send_now = {
        let acc_signal = account_id;
        let to_signal = to_str;
        let cc_signal = cc_str;
        let bcc_signal = bcc_str;
        let subject_signal = subject;
        let body_signal = body;
        let in_reply_to_signal = in_reply_to;
        let references_signal = references;
        let attachments_signal = attachments;
        let mut draft_signal = draft_id;
        let mut status_signal = save_status;
        let mut sync_tick = sync_tick;
        let mut compose_signal = compose;
        let mut sending = send_in_flight;
        let mut undo_pending = undo_send_pending;
        let mut undo_now_ms = undo_send_now_ms;
        move || {
            if *sending.read() {
                return;
            }
            if undo_pending.read().is_some() {
                return;
            }
            let acc = acc_signal.read().clone();
            let Some(_) = acc else { return };
            let to = parse_addrs(&to_signal.read());
            let cc = parse_addrs(&cc_signal.read());
            let bcc = parse_addrs(&bcc_signal.read());
            if to.is_empty() && cc.is_empty() && bcc.is_empty() {
                status_signal.set(SaveStatus::Error("Add at least one recipient".into()));
                return;
            }
            wasm_bindgen_futures::spawn_local(async move {
                // Read the undo-send setting once per click. `off`
                // (or unset) means "send immediately"; otherwise we
                // hold the click for the configured number of seconds.
                let setting = invoke::<Option<String>>(
                    "app_settings_get",
                    serde_json::json!({ "input": { "key": "compose.undo_send" } }),
                )
                .await
                .ok()
                .flatten();
                let hold_secs: u64 = match setting.as_deref() {
                    Some("5") => 5,
                    Some("10") => 10,
                    Some("30") => 30,
                    _ => 0,
                };

                if hold_secs > 0 {
                    let now_ms = js_sys::Date::now();
                    let deadline_ms = now_ms + (hold_secs as f64) * 1000.0;
                    undo_pending.set(Some(deadline_ms));
                    undo_now_ms.set(now_ms);
                    loop {
                        gloo_timers::future::sleep(std::time::Duration::from_millis(250)).await;
                        let cur = *undo_pending.read();
                        if cur != Some(deadline_ms) {
                            // Cancelled (set to None) or replaced
                            // (deadline rearmed by another click).
                            return;
                        }
                        let now = js_sys::Date::now();
                        undo_now_ms.set(now);
                        if now >= deadline_ms {
                            break;
                        }
                    }
                    let cur = *undo_pending.read();
                    if cur != Some(deadline_ms) {
                        return;
                    }
                    undo_pending.set(None);
                }

                // Re-snapshot the form. Edits during the hold window
                // are intentionally honored — "send in 30s, fix typos
                // in the meantime" is part of the value of undo-send.
                let acc = match acc_signal.read().clone() {
                    Some(a) => a,
                    None => return,
                };
                let to = parse_addrs(&to_signal.read());
                let cc = parse_addrs(&cc_signal.read());
                let bcc = parse_addrs(&bcc_signal.read());
                let subject_text = subject_signal.read().clone();
                let body_text = body_signal.read().clone();
                let id = draft_signal.read().clone();
                let in_reply_to_val = in_reply_to_signal.read().clone();
                let references_val = references_signal.read().clone();
                let attachments_val = attachments_signal.read().clone();

                sending.set(true);
                status_signal.set(SaveStatus::Saving);

                let save_payload = serde_json::json!({
                    "input": {
                        "draft": {
                            "id": id,
                            "account_id": acc,
                            "to": to,
                            "cc": cc,
                            "bcc": bcc,
                            "subject": subject_text,
                            "body": body_text,
                            "body_kind": DraftBodyKind::Plain,
                            "attachments": attachments_val,
                            "in_reply_to": in_reply_to_val,
                            "references": references_val,
                        }
                    }
                });
                let saved_id = match invoke::<DraftId>("drafts_save", save_payload).await {
                    Ok(id) => id,
                    Err(e) => {
                        web_sys_log(&format!("messages_send: pre-save: {e}"));
                        status_signal.set(SaveStatus::Error(e));
                        sending.set(false);
                        return;
                    }
                };
                draft_signal.set(Some(saved_id.clone()));
                let send_payload = serde_json::json!({
                    "input": { "draft_id": saved_id }
                });
                match invoke::<()>("messages_send", send_payload).await {
                    Ok(()) => {
                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                        compose_signal.set(None);
                    }
                    Err(e) => {
                        web_sys_log(&format!("messages_send: {e}"));
                        status_signal.set(SaveStatus::Error(format!("Send failed: {e}")));
                        sending.set(false);
                    }
                }
            });
        }
    };

    // Cancel a pending undo-send. Idempotent — clicking when nothing
    // is pending is a no-op. Used by the on-screen Undo button; the
    // global Esc handler in `dispatch_keyboard_command` clears the
    // signal directly.
    let mut cancel_undo_send = {
        let mut undo_pending = undo_send_pending;
        let mut status = save_status;
        move || {
            if undo_pending.read().is_some() {
                undo_pending.set(None);
                status.set(SaveStatus::Idle);
            }
        }
    };

    let mut discard = {
        let mut compose_signal = compose;
        let mut sync_tick = sync_tick;
        move || {
            if let Some(id) = draft_id.read().clone() {
                wasm_bindgen_futures::spawn_local(async move {
                    let _ = invoke::<()>(
                        "drafts_delete",
                        serde_json::json!({ "input": { "id": id } }),
                    )
                    .await;
                });
            }
            sync_tick.with_mut(|t| *t = t.wrapping_add(1));
            compose_signal.set(None);
        }
    };

    let mut close_compose = {
        let mut compose_signal = compose;
        move || compose_signal.set(None)
    };

    let bump = move || {
        last_change.with_mut(|n| *n = n.wrapping_add(1));
        save_status.set(SaveStatus::Dirty);
    };

    let subject_label = {
        let s = subject.read().clone();
        if s.is_empty() {
            "(no subject)".to_string()
        } else {
            s
        }
    };
    let body_chars = body.read().chars().count();
    let body_words = body.read().split_whitespace().count();

    rsx! {
        section {
            class: "compose-pane",
            header {
                class: "compose-head",
                strong { "qsl" }
                span { class: "compose-statusline-key", "//" }
                span { "compose · {subject_label}" }
                span { class: "compose-spacer" }
                ComposeStatusLabel { status: save_status }
                button {
                    class: "compose-action danger",
                    r#type: "button",
                    onclick: move |_| discard(),
                    "discard"
                }
                button {
                    class: "compose-action secondary",
                    r#type: "button",
                    onclick: move |_| manual_save(),
                    "save"
                }
                button {
                    class: "compose-action secondary",
                    r#type: "button",
                    onclick: move |_| close_compose(),
                    span { class: "compose-statusline-key", "⌘W" }
                    " close"
                }
            }
            if !*loaded.read() {
                p { class: "hint", "Loading draft…" }
            } else {
                div {
                    class: "compose-form",
                    div {
                        class: "field-row",
                        label { class: "label", r#for: "compose-from", "From" }
                        select {
                            id: "compose-from",
                            value: account_id.read().as_ref().map(|a| a.0.clone()).unwrap_or_default(),
                            oninput: {
                                let mut bump = bump;
                                move |evt: Event<FormData>| {
                                    let raw = evt.value();
                                    if raw.is_empty() {
                                        account_id.set(None);
                                    } else {
                                        account_id.set(Some(AccountId(raw)));
                                    }
                                    bump();
                                }
                            },
                            match &*accounts.read_unchecked() {
                                None => rsx! { option { value: "", "Loading…" } },
                                Some(Err(_)) => rsx! { option { value: "", "(error loading accounts)" } },
                                Some(Ok(list)) => rsx! {
                                    if list.is_empty() {
                                        option { value: "", "No accounts" }
                                    }
                                    for a in list.iter() {
                                        {
                                            let label = format!(
                                                "{} — {}",
                                                a.display_name, a.email_address
                                            );
                                            rsx! {
                                                option {
                                                    value: "{a.id.0}",
                                                    "{label}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    AddressField {
                        label: "To",
                        value: to_str,
                        on_change: bump,
                    }
                    // Cc row: full AddressField, plus a `+bcc` reveal
                    // link inline when Bcc is still hidden. Once Bcc is
                    // showing, the link is gone — there's no need to
                    // re-hide it for the duration of this compose
                    // session.
                    div {
                        class: "compose-cc-row",
                        AddressField {
                            label: "Cc",
                            value: cc_str,
                            on_change: bump,
                        }
                        if !*bcc_revealed.read() {
                            button {
                                r#type: "button",
                                class: "compose-bcc-reveal",
                                title: "Show the Bcc field",
                                onclick: move |_| bcc_revealed.set(true),
                                "+bcc"
                            }
                        }
                    }
                    if *bcc_revealed.read() {
                        AddressField {
                            label: "Bcc",
                            value: bcc_str,
                            on_change: bump,
                        }
                    }
                    div {
                        class: "field-row",
                        label { class: "label", r#for: "compose-subject", "Subject" }
                        input {
                            id: "compose-subject",
                            class: "compose-input",
                            r#type: "text",
                            spellcheck: if *spellcheck_on.read() { "true" } else { "false" },
                            value: "{subject}",
                            oninput: {
                                let mut bump = bump;
                                move |evt: Event<FormData>| {
                                    subject.set(evt.value());
                                    bump();
                                }
                            }
                        }
                    }
                    // Attachments row. The chip list mirrors the
                    // `attachments` signal — picking files via the
                    // button appends; clicking × removes. Empty list
                    // collapses to just the button.
                    AttachmentsRow {
                        attachments,
                        on_change: bump,
                    }
                    textarea {
                        class: "compose-body",
                        rows: "20",
                        placeholder: "Write your message…",
                        spellcheck: if *spellcheck_on.read() { "true" } else { "false" },
                        value: "{body}",
                        oninput: {
                            let mut bump = bump;
                            move |evt: Event<FormData>| {
                                body.set(evt.value());
                                bump();
                            }
                        },
                        // Ctrl/Cmd+Enter sends. The document-level
                        // keyboard parser is bypassed inside textareas
                        // (see `is_typing_in_field`), so this handler
                        // owns the send shortcut for the compose pane.
                        onkeydown: {
                            let mut send_now_kbd = send_now;
                            move |evt: Event<KeyboardData>| {
                                if (evt.modifiers().contains(Modifiers::CONTROL)
                                    || evt.modifiers().contains(Modifiers::META))
                                    && evt.key() == Key::Enter
                                {
                                    evt.prevent_default();
                                    send_now_kbd();
                                }
                            }
                        }
                    }
                }
            }
            // Status line — the ⌘↵ send affordance is the only send
            // surface in the new design (ui-direction.md § Compose).
            // Click triggers send_now; ⌘↵ on the textarea above does
            // the same. No button-shaped Send element appears anywhere.
            footer {
                class: "compose-statusline",
                div {
                    class: "compose-statusline-left",
                    span { "plain" }
                    span { class: "status-sep", "·" }
                    span { "{body_words}w / {body_chars}c" }
                }
                div {
                    class: "compose-statusline-center",
                    ComposeStatusLabel { status: save_status }
                }
                div {
                    class: "compose-statusline-right",
                    if let Some(deadline) = *undo_send_pending.read() {
                        // Pending undo-send. Replace the Send button
                        // with Undo + countdown. The button gets
                        // `autofocus` so Esc on it (without leaving
                        // the pane) cancels — the document-level
                        // Cancel handler also clears the signal, so
                        // any-focus Esc still works.
                        {
                            let now = *undo_send_now_ms.read();
                            let remaining_ms = (deadline - now).max(0.0);
                            let secs = (remaining_ms / 1000.0).ceil() as i64;
                            rsx! {
                                span { class: "compose-undo-countdown", "Sending in {secs}s" }
                                button {
                                    class: "compose-statusline-send danger",
                                    r#type: "button",
                                    title: "Cancel send (Esc)",
                                    autofocus: true,
                                    onclick: move |_| cancel_undo_send(),
                                    span { class: "compose-statusline-key", "Esc" }
                                    " undo"
                                }
                            }
                        }
                    } else {
                        button {
                            class: "compose-statusline-send",
                            r#type: "button",
                            title: "Send (⌘↵)",
                            disabled: *send_in_flight.read(),
                            onclick: move |_| send_now(),
                            span { class: "compose-statusline-key", "⌘↵" }
                            " "
                            if *send_in_flight.read() { "sending…" } else { "send" }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SaveStatus {
    Idle,
    Dirty,
    Saving,
    Saved,
    Error(String),
}

/// Compose-pane attachments row: a list of attachment chips plus an
/// "Attach" button that opens the OS file picker via
/// `compose_pick_attachments`. The picker returns one
/// [`DraftAttachment`] per chosen file; the list is appended (existing
/// attachments are preserved) and `on_change` fires so the auto-save
/// effect bumps `last_change` for the next save round-trip.
///
/// File size is rendered as a humanized string (KB/MB) so the user
/// sees that "they're about to send a 14 MB attachment" before
/// hitting Send.
#[component]
fn AttachmentsRow(
    mut attachments: Signal<Vec<DraftAttachment>>,
    on_change: EventHandler<()>,
) -> Element {
    let pick = move |_| {
        let mut atts = attachments;
        let on_change = on_change;
        wasm_bindgen_futures::spawn_local(async move {
            let payload = serde_json::json!({ "input": { "title": "Attach files" } });
            match invoke::<Vec<DraftAttachment>>("compose_pick_attachments", payload).await {
                Ok(picked) if picked.is_empty() => {
                    // User cancelled the dialog. No-op.
                }
                Ok(picked) => {
                    atts.with_mut(|v| v.extend(picked));
                    on_change.call(());
                }
                Err(e) => {
                    web_sys_log(&format!("compose_pick_attachments: {e}"));
                }
            }
        });
    };

    let items = attachments.read().clone();

    rsx! {
        div {
            class: "compose-attachments-row",
            label { class: "label", "Files" }
            div {
                class: "compose-attachments-list",
                for (idx, att) in items.iter().enumerate().map(|(i, a)| (i, a.clone())) {
                    {
                        let on_change_remove = on_change;
                        let label = format!(
                            "{} ({})",
                            att.filename,
                            humanize_bytes(att.size_bytes)
                        );
                        rsx! {
                            span {
                                key: "{idx}-{att.path}",
                                class: "compose-attachment-chip",
                                title: "{att.path}",
                                "{label}"
                                button {
                                    class: "compose-attachment-remove",
                                    r#type: "button",
                                    title: "Remove this attachment",
                                    onclick: move |_| {
                                        attachments.with_mut(|v| {
                                            if idx < v.len() {
                                                v.remove(idx);
                                            }
                                        });
                                        on_change_remove.call(());
                                    },
                                    "×"
                                }
                            }
                        }
                    }
                }
                button {
                    class: "compose-attachment-add",
                    r#type: "button",
                    title: "Attach files (opens file picker)",
                    onclick: pick,
                    "+ Attach"
                }
            }
        }
    }
}

/// Render a byte count as a short, humanized string. Approximate — the
/// goal is "user sees that this is small/big" not exact accounting.
fn humanize_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if n >= GB {
        format!("{:.1} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.0} KB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

#[component]
fn ComposeStatusLabel(status: Signal<SaveStatus>) -> Element {
    rsx! {
        match &*status.read() {
            SaveStatus::Idle => rsx! { span { class: "compose-status muted", "" } },
            SaveStatus::Dirty => rsx! { span { class: "compose-status dirty", "Unsaved changes" } },
            SaveStatus::Saving => rsx! { span { class: "compose-status muted", "Saving…" } },
            SaveStatus::Saved => rsx! { span { class: "compose-status muted", "Saved" } },
            SaveStatus::Error(e) => rsx! { span { class: "compose-status error", "Save failed: {e}" } },
        }
    }
}

#[component]
fn AddressField(label: String, value: Signal<String>, on_change: EventHandler<()>) -> Element {
    let id = format!("compose-{}", label.to_ascii_lowercase());

    // Autocomplete dropdown state. Each `AddressField` instance has
    // its own — multiple fields don't share a dropdown so opening
    // To: doesn't squash a Cc: dropdown that's already open.
    let suggestions: Signal<Vec<Contact>> = use_signal(Vec::new);
    let highlighted: Signal<usize> = use_signal(|| 0usize);
    let dropdown_open: Signal<bool> = use_signal(|| false);

    // Re-fetch suggestions whenever the *active segment* (the chunk
    // after the last comma/semicolon) changes and is at least 2
    // characters. Below the 2-char threshold the dropdown closes —
    // surfacing the whole table on a single character is noisy and
    // the IPC round-trip is wasted.
    let value_str = value.read().clone();
    let active = active_segment(&value_str).to_string();
    use_effect(use_reactive!(|active| {
        let mut suggestions = suggestions;
        let mut dropdown_open = dropdown_open;
        let mut highlighted = highlighted;
        if active.trim().len() < 2 {
            suggestions.set(Vec::new());
            dropdown_open.set(false);
            highlighted.set(0);
            return;
        }
        wasm_bindgen_futures::spawn_local(async move {
            let payload = serde_json::json!({ "input": { "prefix": active.trim(), "limit": 8 } });
            match invoke::<Vec<Contact>>("contacts_query", payload).await {
                Ok(rows) => {
                    let any = !rows.is_empty();
                    suggestions.set(rows);
                    dropdown_open.set(any);
                    highlighted.set(0);
                }
                Err(e) => {
                    web_sys_log(&format!("contacts_query: {e}"));
                    suggestions.set(Vec::new());
                    dropdown_open.set(false);
                }
            }
        });
    }));

    let snapshot = suggestions.read().clone();
    let snapshot_for_keys = snapshot.clone();
    let is_open = dropdown_open();
    let active_idx = highlighted();

    rsx! {
        div {
            class: "field-row field-row-autocomplete",
            label { class: "label", r#for: "{id}", "{label}" }
            div {
                class: "compose-input-wrap",
                input {
                    id: "{id}",
                    class: "compose-input",
                    r#type: "text",
                    placeholder: "name@example.com, another@example.com",
                    value: "{value.read()}",
                    autocomplete: "off",
                    oninput: {
                        let mut value = value;
                        move |evt: Event<FormData>| {
                            value.set(evt.value());
                            on_change.call(());
                        }
                    },
                    onkeydown: {
                        let mut value = value;
                        let on_change_for_keys = on_change;
                        let suggestions_for_keys = suggestions;
                        let mut highlighted = highlighted;
                        let mut dropdown_open = dropdown_open;
                        move |evt: Event<KeyboardData>| {
                            if !is_open {
                                return;
                            }
                            let key = evt.key().to_string();
                            let len = suggestions_for_keys.read().len();
                            if len == 0 {
                                return;
                            }
                            match key.as_str() {
                                "ArrowDown" => {
                                    evt.prevent_default();
                                    highlighted.set((active_idx + 1) % len);
                                }
                                "ArrowUp" => {
                                    evt.prevent_default();
                                    highlighted.set(if active_idx == 0 {
                                        len - 1
                                    } else {
                                        active_idx - 1
                                    });
                                }
                                "Enter" | "Tab" => {
                                    let pick = suggestions_for_keys
                                        .read()
                                        .get(active_idx)
                                        .cloned();
                                    if let Some(pick) = pick {
                                        evt.prevent_default();
                                        let next = replace_active_segment(
                                            &value.read(),
                                            &format_contact(&pick),
                                        );
                                        value.set(next);
                                        dropdown_open.set(false);
                                        on_change_for_keys.call(());
                                    }
                                }
                                "Escape" => {
                                    evt.prevent_default();
                                    dropdown_open.set(false);
                                }
                                _ => {}
                            }
                        }
                    },
                    // Closing on blur uses a small delay (gloo
                    // sleep-then-set) so a click on a dropdown row
                    // gets a chance to fire its onmousedown before
                    // the dropdown unmounts. Without the delay the
                    // input loses focus, the dropdown closes, and
                    // the click never lands.
                    onblur: {
                        let mut dropdown_open = dropdown_open;
                        move |_| {
                            wasm_bindgen_futures::spawn_local(async move {
                                gloo_timers::future::sleep(
                                    std::time::Duration::from_millis(150),
                                )
                                .await;
                                dropdown_open.set(false);
                            });
                        }
                    },
                }
                if is_open && !snapshot.is_empty() {
                    div {
                        class: "compose-autocomplete",
                        for (i, contact) in snapshot.iter().enumerate().collect::<Vec<_>>() {
                            div {
                                key: "{contact.address}",
                                class: if i == active_idx {
                                    "compose-autocomplete-row active"
                                } else {
                                    "compose-autocomplete-row"
                                },
                                // `onmousedown` (not `onclick`) so we
                                // beat the input's onblur — clicking
                                // a row should pick it, not just
                                // close the dropdown.
                                onmousedown: {
                                    let mut value = value;
                                    let mut dropdown_open = dropdown_open;
                                    let on_change = on_change;
                                    let pick = contact.clone();
                                    move |evt: Event<MouseData>| {
                                        evt.prevent_default();
                                        let next = replace_active_segment(
                                            &value.read(),
                                            &format_contact(&pick),
                                        );
                                        value.set(next);
                                        dropdown_open.set(false);
                                        on_change.call(());
                                    }
                                },
                                if let Some(name) = contact.display_name.as_deref() {
                                    if !name.is_empty() {
                                        span {
                                            class: "compose-autocomplete-name",
                                            "{name}"
                                        }
                                    }
                                }
                                span {
                                    class: "compose-autocomplete-address",
                                    "{contact.address}"
                                }
                            }
                        }
                        // Suppress an unused-var warning for the moved snapshot.
                        // (No-op block: the iterator above borrowed it once.)
                        {
                            let _ = &snapshot_for_keys;
                            rsx! {}
                        }
                    }
                }
            }
        }
    }
}

/// Slice of `line` that's currently being typed — everything after
/// the last `,` or `;`. Used to scope autocomplete to the active
/// address rather than the whole field. Trims leading whitespace
/// so `"alice@…, bo"` returns `"bo"`, not `" bo"`.
fn active_segment(line: &str) -> &str {
    let split_at = line.rfind([',', ';']).map(|i| i + 1).unwrap_or(0);
    line[split_at..].trim_start()
}

/// Replace the active segment of `line` with `replacement`, keeping
/// the leading addresses and the comma. Used when the user picks
/// a dropdown row.
fn replace_active_segment(line: &str, replacement: &str) -> String {
    let split_at = line.rfind([',', ';']).map(|i| i + 1).unwrap_or(0);
    let prefix = &line[..split_at];
    // Reattach with a single space after the separator so subsequent
    // typing produces `addr1, addr2` not `addr1,addr2`.
    let glue = if prefix.is_empty() { "" } else { " " };
    format!("{prefix}{glue}{replacement}, ")
}

/// Format a Contact as the user-facing one-line address form. Uses
/// `Name <addr>` when a display name is present, just `addr`
/// otherwise — matches what `format_addrs` produces for hand-typed
/// entries.
fn format_contact(c: &Contact) -> String {
    match c.display_name.as_deref() {
        Some(name) if !name.is_empty() => format!("{name} <{}>", c.address),
        _ => c.address.clone(),
    }
}

/// Parse a comma- or semicolon-separated address line into typed
/// [`EmailAddress`] entries. Strips whitespace, drops empty
/// segments. The Phase 2 v1 path doesn't try to extract display
/// names — `Name <addr@host>` segments collapse to `addr@host`. A
/// proper RFC 5322 address parser arrives with the SMTP /
/// JMAP submission week (18 / 19).
fn parse_addrs(line: &str) -> Vec<EmailAddress> {
    line.split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|raw| {
            let address = if let (Some(open), Some(close)) = (raw.find('<'), raw.rfind('>')) {
                raw[open + 1..close].trim().to_string()
            } else {
                raw.to_string()
            };
            EmailAddress {
                address,
                display_name: None,
            }
        })
        .collect()
}

/// Render a Vec of typed addresses back into a comma-separated input
/// line for re-editing.
fn format_addrs(addrs: &[EmailAddress]) -> String {
    addrs
        .iter()
        .map(|a| match &a.display_name {
            Some(name) if !name.is_empty() => format!("{name} <{}>", a.address),
            _ => a.address.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------- Sidebar ----------

/// Flat list of every account's
/// well-known mailboxes followed by a Labels group of user-defined
/// folders. Click handlers update `selection` directly; the message
/// list and reader panes follow once their lift-ins land.
#[component]
fn SidebarV2(
    selection: Signal<Selection>,
    sync_tick: SyncTick,
    compose: Signal<Option<ComposeState>>,
) -> Element {
    // Refetch on every sync_event / accounts_changed tick so a
    // brand-new account from `accounts_add_oauth` appears in the
    // sidebar without requiring the user to restart. Two trigger
    // paths feed `sync_tick`: `accounts_changed` (host emits once
    // immediately, plus a defensive second emit from
    // `oauth_add_close`) and per-folder `sync_event` once bootstrap
    // sync gets going.
    //
    // Reading the signal *inside* the closure passed to
    // `use_resource` is the canonical Dioxus 0.7 way to register a
    // dependency — `use_reactive!` was doing this in spirit but had
    // a known wrinkle where the dep wasn't always picked up on the
    // first signal change after mount. Using the inline read keeps
    // the reactivity wiring as obvious as possible.
    let mut sync_tick_for_refetch = sync_tick;
    let accounts = use_resource(move || {
        let _ = sync_tick_for_refetch();
        async move { invoke::<Vec<Account>>("accounts_list", ()).await }
    });

    // First-launch auto-open: if the very first accounts_list result is
    // empty, jump straight to the add-account window instead of leaving
    // the user staring at the empty-state blurb. Gated on a one-shot
    // flag so a mid-session "remove the last account" doesn't re-pop
    // the window — the empty-state's "Add an account" button covers
    // that path. The flag is signal-local to this SidebarV2 mount,
    // which matches the process lifetime, so a fresh app launch
    // re-enables the auto-open.
    let mut oauth_auto_opened: Signal<bool> = use_signal(|| false);
    use_effect(move || {
        if *oauth_auto_opened.read() {
            return;
        }
        let read = accounts.read_unchecked();
        let Some(Ok(list)) = read.as_ref() else {
            return;
        };
        if !list.is_empty() {
            return;
        }
        oauth_auto_opened.set(true);
        spawn(async {
            if let Err(e) = invoke::<()>("oauth_add_open", serde_json::json!({})).await {
                web_sys_log(&format!("oauth_add_open (auto): {e}"));
            }
        });
    });

    rsx! {
        aside {
            class: "sidebar",
            button {
                class: "sidebar-compose-btn",
                r#type: "button",
                title: "Compose (c)",
                onclick: move |_| {
                    compose.set(Some(ComposeState {
                        default_account: None,
                        draft_id: None,
                prefill: None,
            }));
                },
                span { class: "sidebar-compose-plus", "+" }
                "Compose"
            }
            div {
                class: "sidebar-scroll",
                match &*accounts.read_unchecked() {
                    None => rsx! {},
                    Some(Err(e)) => rsx! { p { class: "sidebar-account-email", "Error: {e}" } },
                    Some(Ok(list)) if list.is_empty() => rsx! {
                        div {
                            class: "sidebar-empty-state",
                            p {
                                class: "sidebar-empty-blurb",
                                "No accounts configured yet."
                            }
                            button {
                                class: "sidebar-empty-add",
                                r#type: "button",
                                onclick: |_| {
                                    spawn(async {
                                        if let Err(e) = invoke::<()>("oauth_add_open", serde_json::json!({})).await {
                                            web_sys_log(&format!("oauth_add_open: {e}"));
                                        }
                                    });
                                },
                                "Add an account"
                            }
                        }
                    },
                    Some(Ok(list)) => rsx! {
                        for a in list.iter().cloned() {
                            SidebarAccountBlock { account: a, selection, sync_tick }
                        }
                    },
                }
            }
            div {
                class: "sidebar-footer",
                button {
                    class: "sidebar-settings-btn",
                    r#type: "button",
                    title: "Open settings",
                    onclick: |_| {
                        spawn(async {
                            if let Err(e) = invoke::<()>("settings_open", serde_json::json!({})).await {
                                web_sys_log(&format!("settings_open: {e}"));
                            }
                        });
                    },
                    span { class: "sidebar-settings-icon", "⚙" }
                    span { "Settings" }
                }
            }
        }
    }
}

#[component]
fn SidebarAccountBlock(
    account: Account,
    selection: Signal<Selection>,
    sync_tick: SyncTick,
) -> Element {
    // Inline-read on `sync_tick` inside the closure (same canonical
    // Dioxus 0.7 pattern as SidebarV2's accounts fetch). Was on the
    // `use_reactive!` macro form, which has a documented wrinkle of
    // missing the first signal change after mount on at least one
    // component — observed as "added a fresh Gmail account, the
    // sidebar shows the account header but never populates folders
    // until I reload the UI." First sync_event from the bootstrap
    // bumps sync_tick, the inline read picks it up, this resource
    // refetches and the sidebar fills in.
    let id_for_fetch = account.id.clone();
    let mut tick_for_refetch = sync_tick;
    let folders = use_resource(move || {
        let id = id_for_fetch.clone();
        let _ = tick_for_refetch();
        async move {
            invoke::<Vec<Folder>>(
                "folders_list",
                serde_json::json!({ "input": { "account": id } }),
            )
            .await
        }
    });

    // Auto-select INBOX on first folder-list load, but only if the
    // user hasn't already picked something. Runs once per account
    // block, fires whenever the resource transitions to Ready and
    // the selection is still empty.
    {
        let mut selection = selection;
        let account_id = account.id.clone();
        use_effect(move || {
            if selection.read().folder.is_some() || selection.read().unified {
                return;
            }
            let read = folders.read_unchecked();
            let Some(Ok(list)) = read.as_ref() else {
                return;
            };
            let inbox = list
                .iter()
                .find(|f| matches!(f.role, Some(qsl_ipc::FolderRole::Inbox)));
            if let Some(inbox) = inbox {
                let mut sel = selection.write();
                sel.account = Some(account_id.clone());
                sel.folder = Some(inbox.id.clone());
                sel.message = None;
                sel.unified = false;
            }
        });
    }

    // Hide the email line when the display name is just the same email
    // (the default for a fresh OAuth add) or empty — otherwise the
    // header paints the address twice. A user-customised display name
    // ("Work", "Personal", ...) keeps both lines so the email stays
    // visible somewhere in the sidebar.
    let show_email_line = !account.display_name.is_empty()
        && account.display_name.trim() != account.email_address.trim();

    rsx! {
        div {
            class: "sidebar-account-header",
            span { class: "sidebar-account-label", "{account.display_name}" }
            if show_email_line {
                span { class: "sidebar-account-email", "{account.email_address}" }
            }
        }
        match &*folders.read_unchecked() {
            None => rsx! {},
            Some(Err(e)) => rsx! { p { class: "sidebar-account-email", "{e}" } },
            Some(Ok(list)) => {
                let (mailboxes, labels) = split_mailboxes_labels(list.clone());
                rsx! {
                    p { class: "sidebar-group-label", "Mailboxes" }
                    for f in mailboxes.into_iter() {
                        SidebarMailboxRow {
                            folder: f,
                            account_id: account.id.clone(),
                            selection,
                            sync_tick,
                        }
                    }
                    if !labels.is_empty() {
                        p { class: "sidebar-group-label", "Labels" }
                        for f in labels.into_iter() {
                            SidebarLabelRow {
                                folder: f,
                                account_id: account.id.clone(),
                                selection,
                                sync_tick,
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn SidebarMailboxRow(
    folder: Folder,
    account_id: AccountId,
    selection: Signal<Selection>,
    sync_tick: SyncTick,
) -> Element {
    let is_selected = selection
        .read()
        .folder
        .as_ref()
        .is_some_and(|f| f.0 == folder.id.0);
    let unread = folder.unread_count;
    let role = folder.role.clone();
    let drop_blocked = crate::format::is_drop_blocked(role.as_ref());
    let drag_state = use_context::<Signal<Option<Vec<MessageId>>>>();
    let mut drop_hover = use_signal(|| false);

    // Class composition mirrors the existing `selected` rule, plus
    // drag-time decorations: `drop-target` highlights the row currently
    // hovered by a valid drag, `drop-blocked` paints a no-drop cursor
    // on Important / Flagged / All while *any* drag is in flight (so
    // the user sees they can't aim there before they release).
    let drag_in_flight = drag_state.read().is_some();
    let row_class = match (
        is_selected,
        drag_in_flight,
        drop_blocked,
        *drop_hover.read(),
    ) {
        (true, _, _, _) => "sidebar-row selected".to_string(),
        (false, true, true, _) => "sidebar-row sidebar-row-drop-blocked".to_string(),
        (false, true, false, true) => "sidebar-row sidebar-row-drop-target".to_string(),
        _ => "sidebar-row".to_string(),
    };

    let folder_id_for_drop = folder.id.clone();
    rsx! {
        div {
            class: "{row_class}",
            ondragover: move |evt: Event<DragData>| {
                if drag_in_flight && !drop_blocked {
                    // `prevent_default` is the HTML5 contract that
                    // turns `dragover` into a legal drop target. Set
                    // the hover flag *here* (continuously, while
                    // the cursor is over the row) rather than only
                    // on `dragenter`, because HTML5 fires spurious
                    // `dragleave` events whenever the cursor crosses
                    // a child element's boundary — leaving the
                    // highlight to flicker. `peek` first so we don't
                    // re-render every dragover tick.
                    evt.prevent_default();
                    if !*drop_hover.peek() {
                        web_sys_log("dnd ondragover: hover=true");
                        drop_hover.set(true);
                    }
                }
            },
            ondragleave: move |_: Event<DragData>| {
                drop_hover.set(false);
            },
            ondrop: {
                let target = folder_id_for_drop.clone();
                let mut drag_state_w = drag_state;
                let mut bulk_selected = use_context::<Signal<HashSet<MessageId>>>();
                let visible_messages = use_context::<Signal<Vec<MessageId>>>();
                let mut sync_tick = sync_tick;
                let mut selection_w = selection;
                move |evt: Event<DragData>| {
                    web_sys_log("dnd ondrop: fired");
                    drop_hover.set(false);
                    if drop_blocked {
                        web_sys_log("dnd ondrop: blocked role, abort");
                        return;
                    }
                    let Some(ids) = drag_state_w.write().take() else {
                        web_sys_log("dnd ondrop: drag_state empty");
                        return;
                    };
                    if ids.is_empty() {
                        return;
                    }
                    evt.prevent_default();
                    let target = target.clone();
                    // Snapshot the next-selection target *now*, before
                    // the IPC removes the dragged ids from the local
                    // view. Computed against the visible list as the
                    // user sees it; the post-move refetch will update
                    // it and our chosen id will still be in there.
                    let next_sel = crate::format::next_selection_after_move(
                        &visible_messages.read(),
                        selection_w.read().message.as_ref(),
                        &ids,
                    );
                    spawn(async move {
                        let payload = serde_json::json!({
                            "input": { "ids": ids, "target": target },
                        });
                        if let Err(e) = invoke::<()>("messages_move", payload).await {
                            web_sys_log(&format!("dnd messages_move: {e}"));
                            return;
                        }
                        bulk_selected.with_mut(|s| s.clear());
                        selection_w.with_mut(|s| s.message = next_sel);
                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                    });
                }
            },
            onclick: {
                let folder_id = folder.id.clone();
                let account_id = account_id.clone();
                move |_| {
                    let mut sel = selection.write();
                    sel.account = Some(account_id.clone());
                    sel.folder = Some(folder_id.clone());
                    sel.message = None;
                    sel.unified = false;
                }
            },
            div {
                class: "sidebar-row-left",
                MailboxRoleIcon { role: role.clone() }
                span {
                    class: "sidebar-row-name",
                    "{crate::format::display_name_for_folder_with_role(&folder.name, folder.role.as_ref())}"
                }
            }
            if unread > 0 {
                span {
                    class: if is_selected { "sidebar-unread-active" } else { "sidebar-unread-inactive" },
                    "{unread}"
                }
            }
        }
    }
}

#[component]
fn SidebarLabelRow(
    folder: Folder,
    account_id: AccountId,
    selection: Signal<Selection>,
    sync_tick: SyncTick,
) -> Element {
    let is_selected = selection
        .read()
        .folder
        .as_ref()
        .is_some_and(|f| f.0 == folder.id.0);
    let unread = folder.unread_count;
    let color = label_color(&folder.name);
    let drop_blocked = crate::format::is_drop_blocked(folder.role.as_ref());
    let drag_state = use_context::<Signal<Option<Vec<MessageId>>>>();
    let mut drop_hover = use_signal(|| false);
    let drag_in_flight = drag_state.read().is_some();
    let row_class = match (
        is_selected,
        drag_in_flight,
        drop_blocked,
        *drop_hover.read(),
    ) {
        (true, _, _, _) => "sidebar-row selected".to_string(),
        (false, true, true, _) => "sidebar-row sidebar-row-drop-blocked".to_string(),
        (false, true, false, true) => "sidebar-row sidebar-row-drop-target".to_string(),
        _ => "sidebar-row".to_string(),
    };
    let folder_id_for_drop = folder.id.clone();
    rsx! {
        div {
            class: "{row_class}",
            ondragover: move |evt: Event<DragData>| {
                if drag_in_flight && !drop_blocked {
                    evt.prevent_default();
                    if !*drop_hover.peek() {
                        drop_hover.set(true);
                    }
                }
            },
            ondragleave: move |_: Event<DragData>| {
                drop_hover.set(false);
            },
            ondrop: {
                let target = folder_id_for_drop.clone();
                let mut drag_state_w = drag_state;
                let mut bulk_selected = use_context::<Signal<HashSet<MessageId>>>();
                let visible_messages = use_context::<Signal<Vec<MessageId>>>();
                let mut sync_tick = sync_tick;
                let mut selection_w = selection;
                move |evt: Event<DragData>| {
                    drop_hover.set(false);
                    if drop_blocked {
                        return;
                    }
                    let Some(ids) = drag_state_w.write().take() else {
                        return;
                    };
                    if ids.is_empty() {
                        return;
                    }
                    evt.prevent_default();
                    let target = target.clone();
                    let next_sel = crate::format::next_selection_after_move(
                        &visible_messages.read(),
                        selection_w.read().message.as_ref(),
                        &ids,
                    );
                    spawn(async move {
                        let payload = serde_json::json!({
                            "input": { "ids": ids, "target": target },
                        });
                        if let Err(e) = invoke::<()>("messages_move", payload).await {
                            web_sys_log(&format!("dnd messages_move (label): {e}"));
                            return;
                        }
                        bulk_selected.with_mut(|s| s.clear());
                        selection_w.with_mut(|s| s.message = next_sel);
                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                    });
                }
            },
            onclick: {
                let folder_id = folder.id.clone();
                let account_id = account_id.clone();
                move |_| {
                    let mut sel = selection.write();
                    sel.account = Some(account_id.clone());
                    sel.folder = Some(folder_id.clone());
                    sel.message = None;
                    sel.unified = false;
                }
            },
            div {
                class: "sidebar-row-left",
                span {
                    class: "sidebar-label-dot",
                    style: "background: {color};",
                }
                span {
                    class: "sidebar-row-name",
                    "{crate::format::display_name_for_folder_with_role(&folder.name, folder.role.as_ref())}"
                }
            }
            if unread > 0 {
                span {
                    class: if is_selected { "sidebar-unread-active" } else { "sidebar-unread-inactive" },
                    "{unread}"
                }
            }
        }
    }
}

/// Inline SVG icon for a mailbox row. Drawn rather than imported so
/// the sidebar has zero asset dependencies and the strokes can match
/// the surrounding text color via `currentColor`.
#[component]
fn MailboxRoleIcon(role: Option<qsl_ipc::FolderRole>) -> Element {
    use qsl_ipc::FolderRole;
    // 16px box, 1.5 stroke, lucide-style geometry.
    match role {
        Some(FolderRole::Inbox) => rsx! {
            svg {
                width: "16", height: "16", view_box: "0 0 24 24",
                fill: "none", stroke: "currentColor", stroke_width: "1.75",
                stroke_linecap: "round", stroke_linejoin: "round",
                polyline { points: "22 12 16 12 14 15 10 15 8 12 2 12" }
                path { d: "M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" }
            }
        },
        Some(FolderRole::Flagged) => rsx! {
            svg {
                width: "16", height: "16", view_box: "0 0 24 24",
                fill: "none", stroke: "currentColor", stroke_width: "1.75",
                stroke_linecap: "round", stroke_linejoin: "round",
                polygon { points: "12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" }
            }
        },
        Some(FolderRole::Sent) => rsx! {
            svg {
                width: "16", height: "16", view_box: "0 0 24 24",
                fill: "none", stroke: "currentColor", stroke_width: "1.75",
                stroke_linecap: "round", stroke_linejoin: "round",
                line { x1: "22", y1: "2", x2: "11", y2: "13" }
                polygon { points: "22 2 15 22 11 13 2 9 22 2" }
            }
        },
        Some(FolderRole::Drafts) => rsx! {
            svg {
                width: "16", height: "16", view_box: "0 0 24 24",
                fill: "none", stroke: "currentColor", stroke_width: "1.75",
                stroke_linecap: "round", stroke_linejoin: "round",
                path { d: "M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" }
                path { d: "M18.5 2.5a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4 9.5-9.5z" }
            }
        },
        Some(FolderRole::Spam) => rsx! {
            svg {
                width: "16", height: "16", view_box: "0 0 24 24",
                fill: "none", stroke: "currentColor", stroke_width: "1.75",
                stroke_linecap: "round", stroke_linejoin: "round",
                path { d: "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" }
                line { x1: "12", y1: "9", x2: "12", y2: "13" }
                line { x1: "12", y1: "17", x2: "12.01", y2: "17" }
            }
        },
        Some(FolderRole::Trash) => rsx! {
            svg {
                width: "16", height: "16", view_box: "0 0 24 24",
                fill: "none", stroke: "currentColor", stroke_width: "1.75",
                stroke_linecap: "round", stroke_linejoin: "round",
                polyline { points: "3 6 5 6 21 6" }
                path { d: "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" }
            }
        },
        // Archive, All, Important all collapse to the box/archive
        // glyph since they're conceptually "everything else"
        // mailboxes.
        _ => rsx! {
            svg {
                width: "16", height: "16", view_box: "0 0 24 24",
                fill: "none", stroke: "currentColor", stroke_width: "1.75",
                stroke_linecap: "round", stroke_linejoin: "round",
                polyline { points: "21 8 21 21 3 21 3 8" }
                rect { x: "1", y: "3", width: "22", height: "5" }
                line { x1: "10", y1: "12", x2: "14", y2: "12" }
            }
        },
    }
}

/// Split the backend's folder list into `(mailboxes, labels)`.
/// Mailboxes are well-known roles in priority order; labels are
/// everything else, alphabetized. `Important` falls into Labels per
/// the reference design — Gmail's per-label affordance reads more
/// like a tag than a destination folder.
fn split_mailboxes_labels(folders: Vec<Folder>) -> (Vec<Folder>, Vec<Folder>) {
    use qsl_ipc::FolderRole;
    fn band(role: &Option<FolderRole>) -> Option<u8> {
        match role {
            Some(FolderRole::Inbox) => Some(0),
            Some(FolderRole::Flagged) => Some(1),
            Some(FolderRole::Sent) => Some(2),
            Some(FolderRole::Drafts) => Some(3),
            Some(FolderRole::All) => Some(4),
            Some(FolderRole::Spam) => Some(5),
            Some(FolderRole::Trash) => Some(6),
            Some(FolderRole::Archive) => Some(7),
            _ => None,
        }
    }
    let mut mailboxes: Vec<Folder> = folders
        .iter()
        .filter(|f| band(&f.role).is_some())
        .cloned()
        .collect();
    mailboxes.sort_by_key(|f| band(&f.role).unwrap_or(u8::MAX));
    let mut labels: Vec<Folder> = folders
        .into_iter()
        .filter(|f| band(&f.role).is_none())
        .collect();
    labels.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    (mailboxes, labels)
}

// ---------- Message list ----------

#[component]
fn MessageListPaneV2(
    selection: Signal<Selection>,
    sync_tick: SyncTick,
    folder_tokens: FolderTokens,
    bulk_selected: Signal<HashSet<MessageId>>,
    search_query: Signal<String>,
    account_filter: Signal<Option<AccountId>>,
    visible_messages: Signal<Vec<MessageId>>,
) -> Element {
    let unified = selection.read().unified;
    let folder_id = selection.read().folder.clone();
    let any_checked = !bulk_selected.read().is_empty();
    let active_query = search_query.read().clone();
    let searching = !active_query.is_empty();
    rsx! {
        section {
            class: "msglist",
            SearchBar { search_query }
            if any_checked {
                BulkActionBar { bulk_selected, sync_tick }
            }
            if searching {
                SearchResults { query: active_query, selection, bulk_selected, account_filter, visible_messages }
            } else if unified {
                UnifiedMessageListV2 { selection, sync_tick, bulk_selected, account_filter, visible_messages }
            } else {
                match folder_id {
                    None => rsx! {
                        p {
                            class: "msglist-empty",
                            "Select a mailbox to view messages."
                        }
                    },
                    Some(fid) => rsx! {
                        MessageListV2 { folder: fid, selection, sync_tick, folder_tokens, bulk_selected, visible_messages }
                    },
                }
            }
        }
    }
}

/// Persistent search input above the message list. Uncontrolled-ish
/// pattern: the input value is bound to `search_query` via `oninput`,
/// and the parent re-renders the results list when the signal flips
/// from empty → non-empty (or back).
///
/// Esc on the input clears the query and blurs (returning the user
/// to the regular list). The keyboard cheatsheet's `/` shortcut
/// focuses this element by id.
#[component]
fn SearchBar(mut search_query: Signal<String>) -> Element {
    let value = search_query.read().clone();
    let has_value = !value.is_empty();
    rsx! {
        div {
            class: "msglist-search",
            input {
                id: "qsl-search-input",
                class: "msglist-search-input",
                r#type: "search",
                placeholder: "Search mail (try is:unread, from:alice, before:2026-01-01)",
                value: "{value}",
                autocomplete: "off",
                spellcheck: "false",
                oninput: move |e| search_query.set(e.value()),
                onkeydown: move |e: Event<KeyboardData>| {
                    if e.key().to_string() == "Escape" {
                        e.prevent_default();
                        search_query.set(String::new());
                        if let Some(window) = web_sys::window() {
                            if let Some(document) = window.document() {
                                if let Some(active) = document.active_element() {
                                    if let Ok(input) = active.dyn_into::<web_sys::HtmlInputElement>() {
                                        let _ = input.blur();
                                    }
                                }
                            }
                        }
                    }
                },
            }
            if has_value {
                button {
                    class: "msglist-search-clear",
                    r#type: "button",
                    title: "Clear search (Esc)",
                    onclick: move |_| search_query.set(String::new()),
                    "×"
                }
            }
        }
    }
}

/// Search results pane. Calls `messages_search` for the current
/// `query` (parsed Gmail-style on the backend) and renders the
/// matching headers as `MessageRowV2`s — same row component the
/// folder / unified inbox lists use, so selection / multi-select /
/// styling all behave identically.
#[component]
fn SearchResults(
    query: String,
    selection: Signal<Selection>,
    bulk_selected: Signal<HashSet<MessageId>>,
    account_filter: Signal<Option<AccountId>>,
    visible_messages: Signal<Vec<MessageId>>,
) -> Element {
    let q_for_fetch = query.clone();
    let page = use_resource(use_reactive!(|q_for_fetch| async move {
        invoke::<MessagePage>(
            "messages_search",
            serde_json::json!({
                "input": { "query": q_for_fetch, "limit": 100, "offset": 0 },
            }),
        )
        .await
    }));

    // Publish the rendered ids for `j` / `k` navigation. Has to live
    // in a `use_effect` — writing to a signal during render panics
    // in Dioxus 0.7. Re-runs on `page` or `account_filter` changes.
    {
        let mut visible_messages = visible_messages;
        let UnreadVisible(mut unread_visible) = use_context::<UnreadVisible>();
        let ThreadCounts(mut thread_counts) = use_context::<ThreadCounts>();
        use_effect(move || {
            let read = page.read_unchecked();
            let Some(Ok(MessagePage {
                messages,
                thread_counts: tc,
                ..
            })) = read.as_ref()
            else {
                visible_messages.set(Vec::new());
                unread_visible.set(Vec::new());
                thread_counts.set(std::collections::HashMap::new());
                return;
            };
            let filter = account_filter.read().clone();
            let filtered: Vec<&MessageHeaders> = match filter {
                Some(ref id) => messages.iter().filter(|m| m.account_id == *id).collect(),
                None => messages.iter().collect(),
            };
            let ids: Vec<MessageId> = filtered.iter().map(|m| m.id.clone()).collect();
            let unread: Vec<MessageId> = filtered
                .iter()
                .filter(|m| !m.flags.seen)
                .map(|m| m.id.clone())
                .collect();
            visible_messages.set(ids);
            unread_visible.set(unread);
            thread_counts.set(tc.clone());
        });
    }

    rsx! {
        match &*page.read_unchecked() {
            None => rsx! { p { class: "msglist-empty", "Searching…" } },
            Some(Err(e)) => rsx! { p { class: "msglist-empty", "{e}" } },
            Some(Ok(MessagePage { messages, total_count, unread_count, .. })) => {
                // Account filter is applied client-side — `messages_search`
                // is account-agnostic so we can scope without a re-query.
                let filter = account_filter.read().clone();
                let filtered: Vec<_> = match filter {
                    Some(ref id) => messages.iter().filter(|m| m.account_id == *id).cloned().collect(),
                    None => messages.clone(),
                };
                let shown = filtered.len() as u32;
                rsx! {
                    MessageListHeader {
                        title: format!("Search: {query}"),
                        shown,
                        total: *total_count,
                        unread: *unread_count,
                    }
                    div {
                        class: "msglist-scroll",
                        if filtered.is_empty() {
                            p { class: "msglist-empty", "No matches." }
                        } else {
                            for m in filtered.into_iter() {
                                MessageRowV2 { msg: m, selection, bulk_selected }
                            }
                        }
                    }
                }
            },
        }
    }
}

/// Floating action bar that overlays the top of the message list when
/// at least one row is checked. The selection lives at the App root,
/// so checkboxes and the bar both follow folder switches; clearing
/// happens explicitly via the "Clear" button or after a successful
/// bulk action. All four IPC commands already accept arrays of ids,
/// so each handler is a one-shot invoke + sync_tick bump.
#[component]
fn BulkActionBar(bulk_selected: Signal<HashSet<MessageId>>, sync_tick: SyncTick) -> Element {
    let count = bulk_selected.read().len();
    let label = if count == 1 {
        "1 selected".to_string()
    } else {
        format!("{count} selected")
    };

    // Snapshot the ids on click — `bulk_selected` is a signal, so
    // reading it inside the spawned future would force the closure to
    // capture a Signal (fine, but unnecessary) and risk reading after
    // a concurrent toggle. Snapshotting keeps the bulk action atomic
    // against the in-flight selection state at click time.
    let snapshot_ids = move |bulk_selected: Signal<HashSet<MessageId>>| -> Vec<MessageId> {
        bulk_selected.read().iter().cloned().collect()
    };

    // Reader-pane auto-advance after a bulk archive / delete: same
    // helper as the keyboard / context-menu / drag-drop paths, just
    // with a multi-id moved cohort.
    let visible_messages = use_context::<Signal<Vec<MessageId>>>();
    let selection_ctx = use_context::<Signal<Selection>>();

    rsx! {
        div {
            class: "bulk-action-bar",
            span { class: "bulk-action-count", "{label}" }
            button {
                class: "bulk-action",
                r#type: "button",
                title: "Archive selected (move to All Mail / Archive)",
                onclick: {
                    let mut bulk_selected = bulk_selected;
                    let mut sync_tick = sync_tick;
                    let mut selection_w = selection_ctx;
                    move |_| {
                        let ids = snapshot_ids(bulk_selected);
                        if ids.is_empty() {
                            return;
                        }
                        let next_sel = crate::format::next_selection_after_move(
                            &visible_messages.read(),
                            selection_w.read().message.as_ref(),
                            &ids,
                        );
                        let selection_changes = selection_w
                            .read()
                            .message
                            .as_ref()
                            .is_some_and(|m| ids.iter().any(|i| i.0 == m.0));
                        spawn(async move {
                            let payload = serde_json::json!({ "input": { "ids": ids } });
                            if let Err(e) = invoke::<()>("messages_archive", payload).await {
                                web_sys_log(&format!("bulk messages_archive: {e}"));
                                return;
                            }
                            bulk_selected.with_mut(|s| s.clear());
                            if selection_changes {
                                selection_w.with_mut(|s| s.message = next_sel);
                            }
                            sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                        });
                    }
                },
                "Archive"
            }
            button {
                class: "bulk-action",
                r#type: "button",
                title: "Mark selected as read",
                onclick: {
                    let mut bulk_selected = bulk_selected;
                    let mut sync_tick = sync_tick;
                    move |_| {
                        let ids = snapshot_ids(bulk_selected);
                        if ids.is_empty() {
                            return;
                        }
                        spawn(async move {
                            let payload = serde_json::json!({
                                "input": { "ids": ids, "seen": true },
                            });
                            if let Err(e) = invoke::<()>("messages_mark_read", payload).await {
                                web_sys_log(&format!("bulk messages_mark_read: {e}"));
                                return;
                            }
                            bulk_selected.with_mut(|s| s.clear());
                            sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                        });
                    }
                },
                "Mark read"
            }
            button {
                class: "bulk-action",
                r#type: "button",
                title: "Mark selected as unread",
                onclick: {
                    let mut bulk_selected = bulk_selected;
                    let mut sync_tick = sync_tick;
                    move |_| {
                        let ids = snapshot_ids(bulk_selected);
                        if ids.is_empty() {
                            return;
                        }
                        spawn(async move {
                            let payload = serde_json::json!({
                                "input": { "ids": ids, "seen": false },
                            });
                            if let Err(e) = invoke::<()>("messages_mark_read", payload).await {
                                web_sys_log(&format!("bulk messages_mark_read: {e}"));
                                return;
                            }
                            bulk_selected.with_mut(|s| s.clear());
                            sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                        });
                    }
                },
                "Mark unread"
            }
            button {
                class: "bulk-action bulk-action-delete",
                r#type: "button",
                title: "Delete selected (move to Trash on Gmail; permanent on JMAP)",
                onclick: {
                    let mut bulk_selected = bulk_selected;
                    let mut sync_tick = sync_tick;
                    let mut selection_w = selection_ctx;
                    move |_| {
                        let ids = snapshot_ids(bulk_selected);
                        if ids.is_empty() {
                            return;
                        }
                        let next_sel = crate::format::next_selection_after_move(
                            &visible_messages.read(),
                            selection_w.read().message.as_ref(),
                            &ids,
                        );
                        let selection_changes = selection_w
                            .read()
                            .message
                            .as_ref()
                            .is_some_and(|m| ids.iter().any(|i| i.0 == m.0));
                        spawn(async move {
                            let payload = serde_json::json!({ "input": { "ids": ids } });
                            if let Err(e) = invoke::<()>("messages_delete", payload).await {
                                web_sys_log(&format!("bulk messages_delete: {e}"));
                                return;
                            }
                            bulk_selected.with_mut(|s| s.clear());
                            if selection_changes {
                                selection_w.with_mut(|s| s.message = next_sel);
                            }
                            sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                        });
                    }
                },
                "Delete"
            }
            button {
                class: "bulk-action bulk-action-clear",
                r#type: "button",
                title: "Clear selection",
                onclick: {
                    let mut bulk_selected = bulk_selected;
                    move |_| bulk_selected.with_mut(|s| s.clear())
                },
                "Clear"
            }
        }
    }
}

#[component]
fn UnifiedMessageListV2(
    selection: Signal<Selection>,
    sync_tick: SyncTick,
    bulk_selected: Signal<HashSet<MessageId>>,
    account_filter: Signal<Option<AccountId>>,
    visible_messages: Signal<Vec<MessageId>>,
) -> Element {
    let tick_value = sync_tick();
    let page = use_resource(use_reactive!(|tick_value| async move {
        let _ = tick_value;
        invoke::<MessagePage>(
            "messages_list_unified",
            serde_json::json!({
                "input": { "limit": 100, "offset": 0, "sort": SortOrder::DateDesc },
            }),
        )
        .await
    }));

    // Publish the rendered ids for `j` / `k` navigation. Has to live
    // in a `use_effect` — writing to a signal during render panics
    // in Dioxus 0.7. Re-runs on `page` or `account_filter` changes.
    {
        let mut visible_messages = visible_messages;
        let UnreadVisible(mut unread_visible) = use_context::<UnreadVisible>();
        let ThreadCounts(mut thread_counts) = use_context::<ThreadCounts>();
        use_effect(move || {
            let read = page.read_unchecked();
            let Some(Ok(MessagePage {
                messages,
                thread_counts: tc,
                ..
            })) = read.as_ref()
            else {
                visible_messages.set(Vec::new());
                unread_visible.set(Vec::new());
                thread_counts.set(std::collections::HashMap::new());
                return;
            };
            let filter = account_filter.read().clone();
            let filtered: Vec<&MessageHeaders> = match filter {
                Some(ref id) => messages.iter().filter(|m| m.account_id == *id).collect(),
                None => messages.iter().collect(),
            };
            let ids: Vec<MessageId> = filtered.iter().map(|m| m.id.clone()).collect();
            let unread: Vec<MessageId> = filtered
                .iter()
                .filter(|m| !m.flags.seen)
                .map(|m| m.id.clone())
                .collect();
            visible_messages.set(ids);
            unread_visible.set(unread);
            thread_counts.set(tc.clone());
        });
    }

    rsx! {
        match &*page.read_unchecked() {
            None => rsx! { p { class: "msglist-empty", "Loading…" } },
            Some(Err(e)) => rsx! { p { class: "msglist-empty", "{e}" } },
            Some(Ok(MessagePage { messages, total_count, unread_count, .. })) => {
                // Account filter applies post-fetch — `messages_list_unified`
                // returns every account so a single chip flip doesn't pay
                // a re-query cost.
                let filter = account_filter.read().clone();
                let filtered: Vec<_> = match filter {
                    Some(ref id) => messages.iter().filter(|m| m.account_id == *id).cloned().collect(),
                    None => messages.clone(),
                };
                let shown = filtered.len() as u32;
                rsx! {
                    MessageListHeader {
                        title: "Unified Inbox".to_string(),
                        shown,
                        total: *total_count,
                        unread: *unread_count,
                    }
                    div {
                        class: "msglist-scroll",
                        if filtered.is_empty() {
                            p { class: "msglist-empty", "No messages." }
                        } else {
                            for m in filtered.into_iter() {
                                MessageRowV2 { msg: m, selection, bulk_selected }
                            }
                        }
                    }
                }
            },
        }
    }
}

#[component]
fn MessageListV2(
    folder: FolderId,
    selection: Signal<Selection>,
    sync_tick: SyncTick,
    folder_tokens: FolderTokens,
    bulk_selected: Signal<HashSet<MessageId>>,
    visible_messages: Signal<Vec<MessageId>>,
) -> Element {
    // Initial page size kept small so the first `messages_list` IPC call
    // on a folder switch returns quickly even on cold-cache reads of
    // large folders. The 20-column wide SELECT is N×heap-fetch; at 200
    // rows on `[Gmail]/All Mail` it has been observed to land 3+ seconds
    // (2026-05-06 telemetry) and hold `state.db.lock()` long enough to
    // wedge unrelated UI commands behind it. The `onscroll_msglist`
    // handler below grows the page by 50 each time the user nears the
    // bottom — so a window-tall list still fills before the scroll
    // reaches the missing rows.
    let mut visible_limit = use_signal(|| 50u32);
    // Inline-read pattern (per feedback_dioxus_use_resource_reactive.md):
    // `use_reactive!` has been observed to miss the first signal change
    // on at least one component, so read the signals inside the closure
    // and let Dioxus's hook runtime track the deps directly.
    //
    // Three deps:
    // - `folder_tokens[folder]` — bumped by backend `sync_event` for this
    //   specific folder; per-folder so an unrelated folder syncing
    //   doesn't fan out a refetch here.
    // - `sync_tick` — bumped by client-initiated actions (context menu
    //   Archive/Delete/Mark-read, bulk bar, keyboard shortcuts). Those
    //   write straight to the local DB and never round-trip through the
    //   sync engine, so `folder_tokens` is never bumped for them.
    // - `visible_limit` — paginated load-older.
    let folder_for_fetch = folder.clone();
    let folder_for_token_read = folder.clone();
    let folder_tokens_for_fetch = folder_tokens;
    let mut sync_tick_for_fetch = sync_tick;
    let page = use_resource(move || {
        let folder = folder_for_fetch.clone();
        let folder_for_token = folder_for_token_read.clone();
        let _ = folder_tokens_for_fetch
            .read()
            .get(&folder_for_token)
            .copied()
            .unwrap_or(0u64);
        let _ = sync_tick_for_fetch();
        let limit_value = visible_limit();
        async move {
            invoke::<MessagePage>(
                "messages_list",
                serde_json::json!({
                    "input": {
                        "folder": folder,
                        "limit": limit_value,
                        "offset": 0,
                        "sort": SortOrder::DateDesc,
                    },
                }),
            )
            .await
        }
    });

    // Lazy-fetch new IMAP messages whenever this folder is opened.
    // Fires once per `folder` value change. The Tauri command emits
    // `sync_event` when it finishes, which bumps this folder's entry
    // in `folder_tokens` and refetches the list above — so any newly-
    // arrived headers slide into the visible page automatically.
    {
        let folder_for_refresh = folder.clone();
        use_effect(use_reactive!(|folder_for_refresh| {
            let folder = folder_for_refresh.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = invoke::<()>(
                    "messages_refresh_folder",
                    serde_json::json!({ "input": { "folder": folder } }),
                )
                .await
                {
                    web_sys_log(&format!("messages_refresh_folder: {e}"));
                }
            });
        }));
    }

    // Auto-select the newest message on folder change (or initial
    // load) when nothing is selected yet. The first item is always
    // newest because the list is fetched with `SortOrder::DateDesc`.
    {
        let mut selection = selection;
        use_effect(move || {
            if selection.read().message.is_some() {
                return;
            }
            let read = page.read_unchecked();
            let Some(Ok(MessagePage { messages, .. })) = read.as_ref() else {
                return;
            };
            if let Some(first) = messages.first() {
                selection.write().message = Some(first.id.clone());
            }
        });
    }

    let mut loading_older = use_signal(|| false);
    let mut tail_exhausted = use_signal(|| false);

    // Pixel distance from the bottom that triggers the next batch.
    // 200px ≈ 3 message rows on the default theme — enough lead time
    // for the IPC + Tauri round-trip to complete before the user
    // hits true bottom on a fast scroll.
    const LOAD_THRESHOLD_PX: f64 = 200.0;

    // Infinite scroll. Each scroll event near the bottom of the
    // list dispatches one `messages_load_older` of 50, gated by
    // `loading_older` so a fast scroll doesn't queue several. After
    // a load lands, `visible_limit` grows and the new rows extend
    // the scrollable area downward — the user has to keep scrolling
    // for the next batch, which is the natural debounce.
    let onscroll_msglist = {
        let folder = folder.clone();
        let mut folder_tokens = folder_tokens;
        move |e: Event<ScrollData>| {
            if *loading_older.read() || *tail_exhausted.read() {
                return;
            }
            let scroll_top = e.data().scroll_top();
            let client_h = f64::from(e.data().client_height());
            let scroll_h = f64::from(e.data().scroll_height());
            if scroll_h - scroll_top - client_h >= LOAD_THRESHOLD_PX {
                return;
            }
            let folder = folder.clone();
            let folder_for_bump = folder.clone();
            loading_older.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                let result = invoke::<u32>(
                    "messages_load_older",
                    serde_json::json!({
                        "input": { "folder": folder, "limit": 50 },
                    }),
                )
                .await;
                match result {
                    Ok(0) => {
                        tail_exhausted.set(true);
                        visible_limit.with_mut(|n| *n = n.saturating_add(50));
                    }
                    Ok(n) => {
                        visible_limit.with_mut(|m| *m = m.saturating_add(n.max(50)));
                        folder_tokens.with_mut(|m| {
                            let entry = m.entry(folder_for_bump).or_insert(0);
                            *entry = entry.wrapping_add(1);
                        });
                    }
                    Err(e) => {
                        web_sys_log(&format!("messages_load_older: {e}"));
                    }
                }
                loading_older.set(false);
            });
        }
    };

    // Publish the rendered ids for `j` / `k` navigation. Lives in a
    // `use_effect` — writing to a signal during render panics in
    // Dioxus 0.7. Threads expose their head only; entering one
    // requires an explicit click.
    {
        let mut visible_messages = visible_messages;
        let UnreadVisible(mut unread_visible) = use_context::<UnreadVisible>();
        let ThreadCounts(mut thread_counts) = use_context::<ThreadCounts>();
        use_effect(move || {
            let read = page.read_unchecked();
            let Some(Ok(MessagePage {
                messages,
                thread_counts: tc,
                ..
            })) = read.as_ref()
            else {
                visible_messages.set(Vec::new());
                unread_visible.set(Vec::new());
                thread_counts.set(std::collections::HashMap::new());
                return;
            };
            let ids: Vec<MessageId> = messages.iter().map(|m| m.id.clone()).collect();
            let unread: Vec<MessageId> = messages
                .iter()
                .filter(|m| !m.flags.seen)
                .map(|m| m.id.clone())
                .collect();
            visible_messages.set(ids);
            unread_visible.set(unread);
            thread_counts.set(tc.clone());
        });
    }

    rsx! {
        match &*page.read_unchecked() {
            None => rsx! { p { class: "msglist-empty", "Loading…" } },
            Some(Err(e)) => rsx! { p { class: "msglist-empty", "{e}" } },
            Some(Ok(MessagePage { messages, total_count, unread_count, .. })) => {
                rsx! {
                    MessageListHeader {
                        title: folder_title_from_selection(&folder, &selection),
                        shown: messages.len() as u32,
                        total: *total_count,
                        unread: *unread_count,
                    }
                    div {
                        class: "msglist-scroll",
                        onscroll: onscroll_msglist,
                        if messages.is_empty() {
                            p { class: "msglist-empty", "No messages in this mailbox." }
                        } else {
                            // When the user has turned off conversation
                            // threading, render every message as a
                            // standalone row — same data shape, just
                            // skip the `group_by_thread` rollup so
                            // adjacent same-thread messages stay
                            // separate.
                            {
                                let ThreadingEnabled(threading_on) =
                                    use_context::<ThreadingEnabled>();
                                let items: Vec<crate::threading::MessageListItem> =
                                    if *threading_on.read() {
                                        crate::threading::group_by_thread(messages.clone())
                                    } else {
                                        messages
                                            .iter()
                                            .cloned()
                                            .map(crate::threading::MessageListItem::Single)
                                            .collect()
                                    };
                                rsx! {
                                    for item in items {
                                        match item {
                                            crate::threading::MessageListItem::Single(m) => rsx! {
                                                MessageRowV2 { msg: m, selection, bulk_selected }
                                            },
                                            crate::threading::MessageListItem::Thread { head, members } => rsx! {
                                                ThreadRow { head, members, selection, bulk_selected }
                                            },
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div {
                        class: "msglist-footer",
                        if *tail_exhausted.read() {
                            span { class: "msglist-tail-hint", "All older messages loaded." }
                        } else if *loading_older.read() {
                            span { class: "msglist-tail-hint", "Loading more…" }
                        }
                    }
                }
            },
        }
    }
}

#[component]
fn MessageListHeader(title: String, shown: u32, total: u32, unread: u32) -> Element {
    rsx! {
        div {
            class: "msglist-header",
            span { class: "msglist-header-title", "{title}" }
            span {
                class: "msglist-header-count",
                "{shown} of {total} · {unread} unread"
            }
        }
    }
}

#[component]
fn MessageRowV2(
    msg: MessageHeaders,
    selection: Signal<Selection>,
    bulk_selected: Signal<HashSet<MessageId>>,
) -> Element {
    let is_selected = selection
        .read()
        .message
        .as_ref()
        .is_some_and(|m| m.0 == msg.id.0);
    let is_checked = bulk_selected.read().contains(&msg.id);
    // Override `flags.seen` with the optimistic client-side set so
    // the row repaints bold→normal the instant the reader-pane
    // mark-read effect runs (synchronous, no IPC round-trip). The
    // persistent DB state catches up via the next legitimate refetch
    // — `flags.seen == true` carries the same signal once it lands.
    let ClientReadIds(client_read_ids) = use_context::<ClientReadIds>();
    let unread = !msg.flags.seen && !client_read_ids.read().contains(&msg.id);
    let from_addr = msg.from.first();
    let from_name = from_addr
        .map(|a| {
            a.display_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| a.address.clone())
        })
        .unwrap_or_default();
    let date = crate::format::format_relative_date(msg.date, chrono::Utc::now());
    let subject = if msg.subject.is_empty() {
        "(no subject)".to_string()
    } else {
        msg.subject.clone()
    };
    let snippet = msg.snippet.clone();
    let (flag_glyph, flag_class) = crate::format::flag_glyph(&msg.flags);
    let flag_div_class = format!("msg-row-flag {flag_class}");
    // Subject + preview render on a single line per ui-direction.md.
    let subject_line = if snippet.is_empty() {
        subject.clone()
    } else {
        format!("{subject} · {snippet}")
    };
    // Thread-count badge: when the message belongs to a thread with
    // more than one entry, show "(N)" before the subject so the user
    // knows clicking will open a stacked thread of N messages.
    // Looked up via the shared `ThreadCounts` context so we don't
    // need a per-row prop. Suppressed entirely when the user has
    // turned off conversation threading.
    let ThreadCounts(thread_counts_signal) = use_context::<ThreadCounts>();
    let ThreadingEnabled(threading_enabled) = use_context::<ThreadingEnabled>();
    let thread_count: Option<u32> = if *threading_enabled.read() {
        msg.thread_id
            .as_ref()
            .and_then(|t| thread_counts_signal.read().get(&t.0).copied())
            .filter(|n| *n > 1)
    } else {
        None
    };
    // `checked` is its own row state — the row stays a `selected` row
    // only when *opened* in the reader; bulk-checking just adds a
    // visual marker without taking over reader focus.
    let row_class = match (is_selected, is_checked, unread) {
        (true, _, true) => "msg-row selected unread",
        (true, _, false) => "msg-row selected",
        (false, true, true) => "msg-row checked unread",
        (false, true, false) => "msg-row checked",
        (false, false, true) => "msg-row unread",
        (false, false, false) => "msg-row",
    };

    let id_for_popup = msg.id.clone();
    let ondoubleclick = move |evt: Event<MouseData>| {
        evt.stop_propagation();
        let id = id_for_popup.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = invoke::<()>(
                "messages_open_in_window",
                serde_json::json!({ "input": { "id": id } }),
            )
            .await
            {
                web_sys_log(&format!("messages_open_in_window: {e}"));
            }
        });
    };

    let mut context_menu = use_context::<Signal<Option<MessageContextMenu>>>();
    let id_for_ctx = msg.id.clone();
    let oncontextmenu = move |evt: Event<MouseData>| {
        evt.prevent_default();
        evt.stop_propagation();
        let coords = evt.client_coordinates();
        context_menu.set(Some(MessageContextMenu {
            x: coords.x,
            y: coords.y,
            message_id: id_for_ctx.clone(),
            is_unread: unread,
        }));
    };

    // Drag source: dragging a row publishes the drag set into the
    // shared `drag_state` signal so sidebar rows can detect it. If the
    // dragged row is bulk-checked, drag every checked id (Gmail / Apple
    // Mail behaviour). Otherwise drag just this one id.
    let mut drag_state = use_context::<Signal<Option<Vec<MessageId>>>>();
    let id_for_drag = msg.id.clone();
    let ondragstart = move |evt: Event<DragData>| {
        let id = id_for_drag.clone();
        let ids = {
            let set = bulk_selected.read();
            if set.contains(&id) {
                set.iter().cloned().collect::<Vec<_>>()
            } else {
                vec![id]
            }
        };
        // webkit2gtk requires `dataTransfer.setData()` during
        // dragstart or it cancels the drag silently. The payload
        // itself is unused — we read ids back from `drag_state`.
        let _ = evt
            .data_transfer()
            .set_data("application/x-qsl-message-ids", &ids.len().to_string());
        web_sys_log(&format!("dnd ondragstart: {} ids", ids.len()));
        drag_state.set(Some(ids));
    };
    let ondragend = move |_: Event<DragData>| {
        web_sys_log("dnd ondragend");
        drag_state.set(None);
    };

    rsx! {
        div {
            class: row_class,
            draggable: "true",
            ondragstart: ondragstart,
            ondragend: ondragend,
            onclick: {
                let mid = msg.id.clone();
                move |_| selection.write().message = Some(mid.clone())
            },
            ondoubleclick: ondoubleclick,
            oncontextmenu: oncontextmenu,
            // Checkbox sits where the avatar normally lives. Click is
            // stop-propagation'd so checking a row doesn't also open
            // the reader (and vice-versa: clicking elsewhere on the
            // row never toggles the box).
            div {
                class: "msg-row-check",
                onclick: {
                    let mid = msg.id.clone();
                    let mut bulk_selected = bulk_selected;
                    move |evt: Event<MouseData>| {
                        evt.stop_propagation();
                        let id = mid.clone();
                        bulk_selected.with_mut(|set| {
                            if !set.remove(&id) {
                                set.insert(id);
                            }
                        });
                    }
                },
                input {
                    r#type: "checkbox",
                    checked: is_checked,
                    // The wrapping div handles the click; the input
                    // itself is non-interactive so the row keeps a
                    // single source of truth for toggle behaviour.
                    onclick: move |evt: Event<MouseData>| evt.stop_propagation(),
                    readonly: true,
                }
            }
            div { class: "{flag_div_class}", "{flag_glyph}" }
            div { class: "msg-row-from", "{from_name}" }
            div {
                class: "msg-row-subject",
                if let Some(n) = thread_count {
                    span { class: "msg-row-thread-count", title: "{n} messages in this thread", "{n}" }
                }
                "{subject_line}"
            }
            div { class: "msg-row-time", "{date}" }
        }
    }
}

/// Wrapper row rendered when [`crate::threading::group_by_thread`]
/// rolled two-or-more consecutive same-thread messages into one. The
/// row itself is a `MessageRowV2`-shaped header for the newest member
/// (`head`), augmented with a count badge and a chevron toggle.
/// Clicking the body selects the head; clicking the chevron expands
/// inline with the older members rendered indented below.
#[component]
fn ThreadRow(
    head: MessageHeaders,
    members: Vec<MessageHeaders>,
    selection: Signal<Selection>,
    bulk_selected: Signal<HashSet<MessageId>>,
) -> Element {
    let mut expanded = use_signal(|| false);
    let count = members.len();
    // "Unread" promotes to the parent row whenever any member is
    // unseen — matches Gmail and avoids surprising the user when the
    // collapsed row hides an unread reply.
    let any_unread = members.iter().any(|m| !m.flags.seen);

    let is_head_selected = selection
        .read()
        .message
        .as_ref()
        .is_some_and(|m| m.0 == head.id.0);
    // Thread "checked" means every member is in the bulk set. Toggling
    // the head's checkbox flips that all-or-nothing — bulk archive of
    // a thread therefore archives the whole conversation, not just
    // the head. Dragging individual members out of the set requires
    // expanding the thread.
    let all_checked =
        !members.is_empty() && members.iter().all(|m| bulk_selected.read().contains(&m.id));

    let from_addr = head.from.first();
    let from_name = from_addr
        .map(|a| {
            a.display_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| a.address.clone())
        })
        .unwrap_or_default();
    let date = crate::format::format_relative_date(head.date, chrono::Utc::now());
    let subject = if head.subject.is_empty() {
        "(no subject)".to_string()
    } else {
        head.subject.clone()
    };
    let snippet = head.snippet.clone();
    let (head_glyph, head_flag_class) = crate::format::flag_glyph(&head.flags);
    let head_flag_div_class = format!("msg-row-flag {head_flag_class}");
    let head_subject_line = if snippet.is_empty() {
        subject.clone()
    } else {
        format!("{subject} · {snippet}")
    };
    let is_expanded = expanded();
    let row_class = match (is_head_selected, all_checked, any_unread) {
        (true, _, true) => "msg-row thread-row selected unread",
        (true, _, false) => "msg-row thread-row selected",
        (false, true, true) => "msg-row thread-row checked unread",
        (false, true, false) => "msg-row thread-row checked",
        (false, false, true) => "msg-row thread-row unread",
        (false, false, false) => "msg-row thread-row",
    };
    let group_class = if is_expanded {
        "thread-group expanded"
    } else {
        "thread-group"
    };

    let id_for_popup = head.id.clone();
    let ondoubleclick = move |evt: Event<MouseData>| {
        evt.stop_propagation();
        let id = id_for_popup.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = invoke::<()>(
                "messages_open_in_window",
                serde_json::json!({ "input": { "id": id } }),
            )
            .await
            {
                web_sys_log(&format!("messages_open_in_window: {e}"));
            }
        });
    };

    let mut context_menu = use_context::<Signal<Option<MessageContextMenu>>>();
    let id_for_ctx = head.id.clone();
    let head_unread = !head.flags.seen;
    let oncontextmenu = move |evt: Event<MouseData>| {
        evt.prevent_default();
        evt.stop_propagation();
        let coords = evt.client_coordinates();
        context_menu.set(Some(MessageContextMenu {
            x: coords.x,
            y: coords.y,
            message_id: id_for_ctx.clone(),
            is_unread: head_unread,
        }));
    };

    // Drag source: dragging the thread row drags every member id
    // (matches the all-or-nothing checkbox semantic above). If any
    // member is in `bulk_selected`, drag the whole bulk set instead so
    // a multi-row drag scoops the thread along with its neighbours.
    let mut drag_state = use_context::<Signal<Option<Vec<MessageId>>>>();
    let member_ids_for_drag: Vec<MessageId> = members.iter().map(|m| m.id.clone()).collect();
    let ondragstart = move |evt: Event<DragData>| {
        let any_in_bulk = {
            let set = bulk_selected.read();
            member_ids_for_drag.iter().any(|id| set.contains(id))
        };
        let ids = if any_in_bulk {
            bulk_selected.read().iter().cloned().collect::<Vec<_>>()
        } else {
            member_ids_for_drag.clone()
        };
        // webkit2gtk-required setData (see MessageRowV2::ondragstart).
        let _ = evt
            .data_transfer()
            .set_data("application/x-qsl-message-ids", &ids.len().to_string());
        web_sys_log(&format!("dnd ondragstart (thread): {} ids", ids.len()));
        drag_state.set(Some(ids));
    };
    let ondragend = move |_: Event<DragData>| {
        web_sys_log("dnd ondragend (thread)");
        drag_state.set(None);
    };

    rsx! {
        div {
            class: group_class,
            div {
                class: row_class,
                draggable: "true",
                ondragstart: ondragstart,
                ondragend: ondragend,
                onclick: {
                    let mid = head.id.clone();
                    let mut selection = selection;
                    move |_| selection.write().message = Some(mid.clone())
                },
                ondoubleclick: ondoubleclick,
                oncontextmenu: oncontextmenu,
                div {
                    class: "msg-row-check",
                    onclick: {
                        let member_ids: Vec<MessageId> =
                            members.iter().map(|m| m.id.clone()).collect();
                        let mut bulk_selected = bulk_selected;
                        move |evt: Event<MouseData>| {
                            evt.stop_propagation();
                            bulk_selected.with_mut(|set| {
                                if all_checked {
                                    for id in &member_ids {
                                        set.remove(id);
                                    }
                                } else {
                                    for id in &member_ids {
                                        set.insert(id.clone());
                                    }
                                }
                            });
                        }
                    },
                    input {
                        r#type: "checkbox",
                        checked: all_checked,
                        onclick: move |evt: Event<MouseData>| evt.stop_propagation(),
                        readonly: true,
                    }
                }
                div { class: "{head_flag_div_class}", "{head_glyph}" }
                div {
                    class: "msg-row-from",
                    "{from_name}"
                    span {
                        class: "thread-count",
                        title: "{count} messages in thread",
                        "{count}"
                    }
                }
                div { class: "msg-row-subject", "{head_subject_line}" }
                div {
                    class: "msg-row-time",
                    "{date}"
                    button {
                        class: "thread-toggle",
                        r#type: "button",
                        title: if is_expanded { "Collapse thread" } else { "Expand thread" },
                        onclick: move |evt: Event<MouseData>| {
                            evt.stop_propagation();
                            let v = expanded();
                            expanded.set(!v);
                        },
                        if is_expanded { "▾" } else { "▸" }
                    }
                }
            }
            if is_expanded {
                div {
                    class: "thread-members",
                    // Skip the head — already rendered above. Members
                    // are in DateDesc order (newest first); rendering
                    // them as-is makes "click to select" feel like
                    // walking the conversation backwards in time.
                    for m in members.iter().skip(1).cloned() {
                        MessageRowV2 { msg: m, selection, bulk_selected }
                    }
                }
            }
        }
    }
}

/// Best-effort title for the message-list header. The selection only
/// holds the folder id; the sidebar already has the name in scope but
/// we'd need to either lift it up or refetch. For now, render the
/// last segment of the folder id (which is the canonical name on
/// IMAP) and run it through the shared display-name mapper so
/// "INBOX" shows as "Inbox" — matching the sidebar.
fn folder_title_from_selection(folder: &FolderId, _selection: &Signal<Selection>) -> String {
    let raw = &folder.0;
    let leaf = raw.rsplit_once(':').map(|(_, name)| name).unwrap_or(raw);
    crate::format::display_name_for_folder(leaf).to_string()
}

// ---------- Reader pane ----------

/// What variant of compose to open when a reader-action button is
/// clicked. Drives the pre-fill logic in [`open_reply`].
#[derive(Copy, Clone)]
enum ReplyKind {
    Reply,
    ReplyAll,
    Forward,
}

/// Build a `DraftInput` from the opened message + reply variant,
/// persist it via `drafts_save`, then point the compose pane at it.
/// Runs entirely off-main as a spawned future so the click handler
/// returns immediately. Errors are logged to the console; we don't
/// surface a UI banner since the only failure mode is a broken IPC
/// channel (which is recoverable on its own).
fn open_reply(
    rendered: RenderedMessage,
    mut compose: Signal<Option<ComposeState>>,
    kind: ReplyKind,
) {
    wasm_bindgen_futures::spawn_local(async move {
        let account_id = rendered.headers.account_id.clone();

        // Fetch accounts so reply-all can drop the user's own
        // address from the cc list. A miss (account vanished, list
        // failed) just leaves the user in the cc — they can edit.
        let self_email = if matches!(kind, ReplyKind::ReplyAll) {
            invoke::<Vec<Account>>("accounts_list", ())
                .await
                .ok()
                .and_then(|accts| {
                    accts
                        .into_iter()
                        .find(|a| a.id == account_id)
                        .map(|a| a.email_address)
                })
                .unwrap_or_default()
        } else {
            String::new()
        };

        let (to, cc, subject, in_reply_to, references, body) = match kind {
            ReplyKind::Reply => {
                let to = crate::reply::reply_to_recipients(&rendered.headers);
                let subject = crate::reply::reply_subject(&rendered.headers.subject);
                let body = crate::reply::quote_body_for_reply(&rendered, None);
                (
                    to,
                    Vec::<EmailAddress>::new(),
                    subject,
                    rendered.headers.rfc822_message_id.clone(),
                    crate::reply::reply_references(&rendered.headers),
                    body,
                )
            }
            ReplyKind::ReplyAll => {
                let to = crate::reply::reply_to_recipients(&rendered.headers);
                let cc = crate::reply::reply_all_cc(&rendered.headers, &to, &self_email);
                let subject = crate::reply::reply_subject(&rendered.headers.subject);
                let body = crate::reply::quote_body_for_reply(&rendered, None);
                (
                    to,
                    cc,
                    subject,
                    rendered.headers.rfc822_message_id.clone(),
                    crate::reply::reply_references(&rendered.headers),
                    body,
                )
            }
            ReplyKind::Forward => {
                let subject = crate::reply::forward_subject(&rendered.headers.subject);
                let body = crate::reply::forward_body(&rendered);
                (
                    Vec::<EmailAddress>::new(),
                    Vec::<EmailAddress>::new(),
                    subject,
                    None,
                    Vec::<String>::new(),
                    body,
                )
            }
        };

        let payload = serde_json::json!({
            "input": {
                "draft": {
                    "id": Option::<DraftId>::None,
                    "account_id": account_id,
                    "to": to,
                    "cc": cc,
                    "bcc": Vec::<EmailAddress>::new(),
                    "subject": subject,
                    "body": body,
                    "body_kind": DraftBodyKind::Plain,
                    "attachments": Vec::<()>::new(),
                    "in_reply_to": in_reply_to,
                    "references": references,
                }
            }
        });
        match invoke::<DraftId>("drafts_save", payload).await {
            Ok(draft_id) => {
                compose.set(Some(ComposeState {
                    default_account: Some(account_id),
                    draft_id: Some(draft_id),
                    prefill: None,
                }));
            }
            Err(e) => {
                web_sys_log(&format!("open_reply: drafts_save: {e}"));
            }
        }
    });
}

#[component]
fn ReaderPaneV2(
    selection: Signal<Selection>,
    sync_tick: SyncTick,
    compose: Signal<Option<ComposeState>>,
) -> Element {
    let message_id = selection.read().message.clone();

    rsx! {
        section {
            class: "reader-pane",
            match message_id {
                None => rsx! { div { class: "reader-empty", "Select a message to read." } },
                Some(id) => rsx! { ReaderV2 { id, selection, sync_tick, compose } },
            }
        }
    }
}

#[component]
fn ReaderV2(
    id: MessageId,
    selection: Signal<Selection>,
    sync_tick: SyncTick,
    compose: Signal<Option<ComposeState>>,
) -> Element {
    // `force_trusted` is the one-shot "Load images" override.
    // Thread-wide because remote-image trust is per-sender (and a
    // single thread is usually one sender), so flipping it for the
    // active card flips it for every card — matching what users do
    // when they click "Load images" on a multi-message conversation.
    // Resets when the user navigates to a different thread.
    let mut force_trusted: Signal<bool> = use_signal(|| false);
    {
        let id_for_reset = id.clone();
        use_effect(use_reactive!(|id_for_reset| {
            let _ = id_for_reset;
            force_trusted.set(false);
        }));
    }

    // Inline-read pattern (per feedback_dioxus_use_resource_reactive.md).
    // Three deps: the message id (anchor for the thread query), the
    // per-render force_trusted override, and sync_tick — the latter
    // so a settings flip ("always load remote images" toggle) and
    // any sync event re-renders the thread. `messages_thread`
    // returns every message attached to the same `thread_id` as the
    // anchor, in date-ascending order; singleton threads come back
    // as a one-element vec so the rendering path stays uniform.
    let id_for_fetch = id.clone();
    let mut force_trusted_for_fetch = force_trusted;
    let mut sync_tick_for_fetch = sync_tick;
    let ThreadingEnabled(threading_enabled) = use_context::<ThreadingEnabled>();
    let mut threading_for_fetch = threading_enabled;
    let thread = use_resource(move || {
        let id = id_for_fetch.clone();
        let force_trusted_val = *force_trusted_for_fetch.read();
        let _ = sync_tick_for_fetch();
        let threading_on = *threading_for_fetch.read();
        async move {
            // When threading is off, fetch only the single selected
            // message and wrap it in a one-element vec so the
            // stacked-card rendering path stays uniform. The reader
            // still shows one card; the user gets the same actions
            // and chrome, just no thread navigation.
            if !threading_on {
                let single = invoke::<RenderedMessage>(
                    "messages_get",
                    serde_json::json!({
                        "input": {
                            "id": id,
                            "force_trusted": force_trusted_val,
                        }
                    }),
                )
                .await?;
                return Ok::<_, String>(vec![single]);
            }
            let messages = invoke::<Vec<RenderedMessage>>(
                "messages_thread",
                serde_json::json!({
                    "input": {
                        "id": id,
                        "force_trusted": force_trusted_val,
                    }
                }),
            )
            .await?;
            Ok::<_, String>(messages)
        }
    });

    // Mark-as-read on selection. Fires once per anchor `id` change —
    // we mark only the originally-selected message, not the whole
    // thread, so unread sibling messages remain visually unread (and
    // therefore default-expanded) until the user clicks them. The
    // command queues an outbox entry for the server flag write, so
    // the `\Seen` flag eventually propagates over IMAP.
    //
    // Visual state is updated optimistically through the
    // `ClientReadIds` context set, NOT by bumping `sync_tick` to
    // force a `messages_list` refetch. The refetch was costing 1.5+ s
    // per click on a 30k-row Gmail mailbox under Turso 0.5.3
    // (telemetry 2026-05-08); the optimistic set lets the row repaint
    // bold→normal synchronously.
    {
        let id_for_mark = id.clone();
        let ClientReadIds(mut client_read_ids) = use_context::<ClientReadIds>();
        use_effect(use_reactive!(|id_for_mark| {
            let id = id_for_mark.clone();
            client_read_ids.write().insert(id.clone());
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = invoke::<()>(
                    "messages_mark_read",
                    serde_json::json!({ "input": { "ids": [id], "seen": true } }),
                )
                .await
                {
                    web_sys_log(&format!("messages_mark_read: {e}"));
                }
            });
        }));
    }

    rsx! {
        match &*thread.read_unchecked() {
            None => rsx! { div { class: "reader-scroll", p { class: "reader-body-loading", "Loading…" } } },
            Some(Err(e)) => rsx! { div { class: "reader-scroll", p { class: "reader-body-loading", "{e}" } } },
            Some(Ok(messages)) if messages.is_empty() => rsx! {
                div { class: "reader-empty", "Message not found." }
            },
            Some(Ok(messages)) => {
                // Toolbar target: the latest message in the thread.
                // Reply/ReplyAll/Forward all want the most recent
                // entry (Gmail-style "reply to the conversation").
                // Archive/Delete/Mark-read operate on every message
                // in the thread — closing a thread tab in the
                // message list should close the whole conversation.
                let target = messages.last().expect("non-empty");
                let subject = if target.headers.subject.is_empty() {
                    "(no subject)".to_string()
                } else {
                    target.headers.subject.clone()
                };
                // All ids in date-asc order; reused by the
                // thread-level archive / delete / mark-as-read
                // toolbar buttons.
                let thread_ids: Vec<MessageId> =
                    messages.iter().map(|m| m.headers.id.clone()).collect();
                let thread_count = messages.len();
                let primary_id = id.clone();
                rsx! {
                    // Toolbar above the header — keyboard hints
                    // replace the old pill action buttons. Reply
                    // family + Flag operate on the *latest* message
                    // (the one a user thinks of as "the
                    // conversation"). Archive / Delete /
                    // Mark-read-or-unread operate on the *whole
                    // thread* — closing a thread tab in the message
                    // list should close the whole conversation, not
                    // leave older messages hanging in the inbox.
                    div {
                        class: "reader-toolbar",
                        button {
                            class: "reader-hint",
                            r#type: "button",
                            title: "Reply (r)",
                            onclick: {
                                let r = target.clone();
                                move |_| open_reply(r.clone(), compose, ReplyKind::Reply)
                            },
                            span { class: "reader-hint-key", "[r]" }
                            " reply"
                        }
                        button {
                            class: "reader-hint",
                            r#type: "button",
                            title: "Reply to all (a)",
                            onclick: {
                                let r = target.clone();
                                move |_| open_reply(r.clone(), compose, ReplyKind::ReplyAll)
                            },
                            span { class: "reader-hint-key", "[a]" }
                            " reply-all"
                        }
                        button {
                            class: "reader-hint",
                            r#type: "button",
                            title: "Forward (f)",
                            onclick: {
                                let r = target.clone();
                                move |_| open_reply(r.clone(), compose, ReplyKind::Forward)
                            },
                            span { class: "reader-hint-key", "[f]" }
                            " forward"
                        }
                        button {
                            class: "reader-hint",
                            r#type: "button",
                            title: "Archive thread (e)",
                            onclick: {
                                let ids = thread_ids.clone();
                                let primary_id = primary_id.clone();
                                let mut selection = selection;
                                let mut sync_tick = sync_tick;
                                let visible_messages = use_context::<Signal<Vec<MessageId>>>();
                                move |_| {
                                    let ids = ids.clone();
                                    let next_sel = crate::format::next_selection_after_move(
                                        &visible_messages.read(),
                                        Some(&primary_id),
                                        std::slice::from_ref(&primary_id),
                                    );
                                    spawn(async move {
                                        let payload = serde_json::json!({
                                            "input": { "ids": ids }
                                        });
                                        if let Err(e) =
                                            invoke::<()>("messages_archive", payload).await
                                        {
                                            web_sys_log(&format!("messages_archive: {e}"));
                                            return;
                                        }
                                        selection.with_mut(|sel| sel.message = next_sel);
                                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                                    });
                                }
                            },
                            span { class: "reader-hint-key", "[e]" }
                            " archive"
                        }
                        button {
                            class: "reader-hint",
                            r#type: "button",
                            title: if target.headers.flags.flagged { "Unflag (s)" } else { "Flag (s)" },
                            onclick: {
                                let id = target.headers.id.clone();
                                let next_flagged = !target.headers.flags.flagged;
                                let mut sync_tick = sync_tick;
                                move |_| {
                                    let id = id.clone();
                                    spawn(async move {
                                        let payload = serde_json::json!({
                                            "input": {
                                                "ids": [id.clone()],
                                                "flagged": next_flagged,
                                            }
                                        });
                                        if let Err(e) =
                                            invoke::<()>("messages_flag", payload).await
                                        {
                                            web_sys_log(&format!("messages_flag: {e}"));
                                            return;
                                        }
                                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                                    });
                                }
                            },
                            span { class: "reader-hint-key", "[s]" }
                            if target.headers.flags.flagged { " unflag" } else { " flag" }
                        }
                        span { class: "reader-hint-spacer" }
                        button {
                            class: "reader-hint",
                            r#type: "button",
                            title: if target.headers.flags.seen { "Mark thread unread (u)" } else { "Mark thread read (u)" },
                            onclick: {
                                let ids = thread_ids.clone();
                                let next_seen = !target.headers.flags.seen;
                                let mut sync_tick = sync_tick;
                                move |_| {
                                    let ids = ids.clone();
                                    spawn(async move {
                                        let payload = serde_json::json!({
                                            "input": {
                                                "ids": ids,
                                                "seen": next_seen,
                                            }
                                        });
                                        if let Err(e) =
                                            invoke::<()>("messages_mark_read", payload).await
                                        {
                                            web_sys_log(&format!("messages_mark_read: {e}"));
                                            return;
                                        }
                                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                                    });
                                }
                            },
                            span { class: "reader-hint-key", "[u]" }
                            if target.headers.flags.seen { " unread" } else { " read" }
                        }
                        button {
                            class: "reader-hint",
                            r#type: "button",
                            title: "Delete thread (#)",
                            onclick: {
                                let ids = thread_ids.clone();
                                let primary_id = primary_id.clone();
                                let mut selection = selection;
                                let mut sync_tick = sync_tick;
                                let visible_messages = use_context::<Signal<Vec<MessageId>>>();
                                move |_| {
                                    let ids = ids.clone();
                                    let next_sel = crate::format::next_selection_after_move(
                                        &visible_messages.read(),
                                        Some(&primary_id),
                                        std::slice::from_ref(&primary_id),
                                    );
                                    spawn(async move {
                                        let payload = serde_json::json!({
                                            "input": { "ids": ids }
                                        });
                                        if let Err(e) =
                                            invoke::<()>("messages_delete", payload).await
                                        {
                                            web_sys_log(&format!("messages_delete: {e}"));
                                            return;
                                        }
                                        selection.with_mut(|sel| sel.message = next_sel);
                                        sync_tick.with_mut(|t| *t = t.wrapping_add(1));
                                    });
                                }
                            },
                            span { class: "reader-hint-key", "[#]" }
                            " delete"
                        }
                    }
                    // Thread chrome — one subject + a count badge for
                    // multi-message threads. The card stack below
                    // owns per-message headers (from / to / cc /
                    // date) so we don't duplicate them up here.
                    div {
                        class: "thread-chrome",
                        h1 { class: "reader-subject", "{subject}" }
                        if thread_count > 1 {
                            span { class: "thread-count", "{thread_count} messages" }
                        }
                    }
                    // Stacked card list. Each card is its own
                    // component with its own expansion signal so
                    // toggling one doesn't re-render every other.
                    // Default expansion (first paint only): unread
                    // messages, the user's anchor selection, and the
                    // last message are open; the rest start
                    // collapsed.
                    div {
                        class: "thread-stack",
                        for (idx, m) in messages.iter().cloned().enumerate() {
                            MessageCard {
                                key: "{m.headers.id.0}",
                                rendered: m,
                                primary_id: primary_id.clone(),
                                is_last: idx == thread_count - 1,
                                force_trusted,
                                compose,
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One card in the stacked thread reader. The card always renders
/// its header strip (from / date / snippet) so the user can see the
/// shape of the conversation at a glance; the body iframe + recipient
/// rows + attachments only mount when the card is expanded. We
/// deliberately don't render every iframe up-front — a 30-message
/// newsletter thread would otherwise mount 30 webkit iframes the
/// moment the thread opens, which is both slow and a real memory hit
/// on hybrid GPU boxes (see `feedback_nvidia_wayland`).
///
/// Default expansion (first paint only): every unread message, the
/// message the user clicked from the list (`primary_id`), and the
/// last message in the thread. Read messages collapse — they're
/// usually quotes you don't need to re-scan.
#[component]
fn MessageCard(
    rendered: RenderedMessage,
    primary_id: MessageId,
    is_last: bool,
    force_trusted: Signal<bool>,
    compose: Signal<Option<ComposeState>>,
) -> Element {
    let initially_expanded =
        !rendered.headers.flags.seen || rendered.headers.id == primary_id || is_last;
    let mut expanded = use_signal(|| initially_expanded);

    let primary = rendered.headers.from.first();
    let from_name = primary
        .map(|a| {
            a.display_name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| a.address.clone())
        })
        .unwrap_or_default();
    let from_addr = primary.map(|a| a.address.clone()).unwrap_or_default();
    let date = crate::format::format_relative_date(rendered.headers.date, chrono::Utc::now());
    let date_full = rendered.headers.date.to_rfc2822();
    // Single-line snippet for the collapsed-row preview. Real
    // sanitized HTML still goes through the iframe when expanded;
    // this is just a typeahead so the user knows what's behind
    // the click without unfolding it.
    let snippet = rendered.headers.snippet.clone();

    let card_class = if *expanded.read() {
        "thread-card thread-card-expanded"
    } else {
        "thread-card thread-card-collapsed"
    };

    rsx! {
        article {
            class: "{card_class}",
            // The header acts as a click-to-toggle target. We
            // intentionally use a real <button> so keyboard focus
            // works without extra ARIA juggling.
            button {
                r#type: "button",
                class: "thread-card-header",
                onclick: move |_| {
                    let cur = *expanded.read();
                    expanded.set(!cur);
                },
                title: if *expanded.read() { "Collapse this message" } else { "Expand this message" },
                span { class: "thread-card-from", "{from_name}" }
                if !from_addr.is_empty() && from_addr != from_name {
                    span { class: "thread-card-addr", "{from_addr}" }
                }
                if !*expanded.read() {
                    span { class: "thread-card-snippet", "{snippet}" }
                }
                span {
                    class: "thread-card-date",
                    title: "{date_full}",
                    "{date}"
                }
                if !rendered.headers.flags.seen {
                    span { class: "thread-card-unread-dot", title: "Unread", "" }
                }
            }
            if *expanded.read() {
                div {
                    class: "thread-card-body",
                    if !rendered.headers.to.is_empty() {
                        ReaderRecipientRow {
                            label: "To".to_string(),
                            addrs: rendered.headers.to.clone(),
                        }
                    }
                    if !rendered.headers.cc.is_empty() {
                        ReaderRecipientRow {
                            label: "Cc".to_string(),
                            addrs: rendered.headers.cc.clone(),
                        }
                    }
                    if !rendered.attachments.is_empty() {
                        ReaderAttachments {
                            attachments: rendered.attachments.clone(),
                            message_id: rendered.headers.id.clone(),
                        }
                    }
                    if rendered.remote_content_blocked {
                        RemoteContentBanner {
                            account_id: rendered.headers.account_id.clone(),
                            sender_addr: rendered
                                .headers
                                .from
                                .first()
                                .map(|a| a.address.clone())
                                .unwrap_or_default(),
                            force_trusted,
                        }
                    }
                    {
                        // Body slot — sandboxed iframe per card. See
                        // `ReaderV2`'s body-render comments for the
                        // sandbox / CSP rationale.
                        let body_html = compose_reader_html(&rendered);
                        let _ = compose;
                        rsx! {
                            iframe {
                                class: "reader-body-iframe",
                                "sandbox": "allow-scripts",
                                srcdoc: "{body_html}",
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ReaderRecipientRow(label: String, addrs: Vec<EmailAddress>) -> Element {
    rsx! {
        div {
            class: "reader-recipients",
            span { class: "reader-recipients-label", "{label}:" }
            for a in addrs.iter().cloned() {
                {
                    let name = a.display_name.clone().unwrap_or_default();
                    let addr = a.address.clone();
                    let title = if name.is_empty() {
                        addr.clone()
                    } else {
                        format!("{name} <{addr}>")
                    };
                    let display = if name.is_empty() { addr } else { name };
                    rsx! {
                        span { class: "reader-chip", title: "{title}", "{display}" }
                    }
                }
            }
        }
    }
}

/// Banner that appears above the reader body when the sanitizer
/// blocked remote content for this message. "Load images" flips
/// `force_trusted` for the current render only; "Always load from
/// this sender" persists an `remote_content_opt_ins` row via
/// `messages_trust_sender`, then re-fetches so subsequent loads
/// pick up the trust state.
#[component]
fn RemoteContentBanner(
    account_id: AccountId,
    sender_addr: String,
    force_trusted: Signal<bool>,
) -> Element {
    let mut trusting: Signal<bool> = use_signal(|| false);
    let sender_label = if sender_addr.is_empty() {
        "this sender".to_string()
    } else {
        sender_addr.clone()
    };

    let load_once = {
        let mut force_trusted = force_trusted;
        move |_| force_trusted.set(true)
    };

    let trust_sender = {
        let account_id = account_id.clone();
        let sender_addr = sender_addr.clone();
        let mut force_trusted = force_trusted;
        move |_| {
            if sender_addr.is_empty() || *trusting.read() {
                return;
            }
            trusting.set(true);
            let account_id = account_id.clone();
            let sender_addr = sender_addr.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match invoke::<()>(
                    "messages_trust_sender",
                    serde_json::json!({
                        "input": {
                            "account_id": account_id,
                            "email_address": sender_addr,
                        }
                    }),
                )
                .await
                {
                    Ok(()) => {
                        // Trigger a re-render through the same signal
                        // the per-render override uses; the resource
                        // closure re-fires and the next `messages_get`
                        // sees the new opt-in row.
                        force_trusted.set(true);
                    }
                    Err(e) => {
                        web_sys_log(&format!("messages_trust_sender: {e}"));
                    }
                }
                trusting.set(false);
            });
        }
    };

    rsx! {
        div {
            class: "reader-remote-banner",
            span {
                class: "reader-remote-banner-text",
                "Images blocked for privacy."
            }
            div {
                class: "reader-remote-banner-actions",
                button {
                    class: "reader-remote-banner-button",
                    r#type: "button",
                    onclick: load_once,
                    "Load images"
                }
                button {
                    class: "reader-remote-banner-button",
                    r#type: "button",
                    disabled: sender_addr.is_empty() || *trusting.read(),
                    onclick: trust_sender,
                    title: "{sender_label}",
                    if *trusting.read() {
                        "Saving…"
                    } else {
                        "Always load from this sender"
                    }
                }
            }
        }
    }
}

#[component]
fn ReaderAttachments(attachments: Vec<Attachment>, message_id: MessageId) -> Element {
    rsx! {
        div {
            class: "reader-attachments",
            for a in attachments.iter() {
                {
                    let name = if a.filename.is_empty() {
                        "(untitled)".to_string()
                    } else {
                        a.filename.clone()
                    };
                    let size = format_bytes(a.size);
                    let attachment_id = a.id.clone();
                    let message_id = message_id.clone();
                    let title = format!("{name} · {size} — click to open");
                    rsx! {
                        button {
                            class: "reader-attachment",
                            r#type: "button",
                            title: "{title}",
                            onclick: move |_| {
                                let attachment_id = attachment_id.clone();
                                let message_id = message_id.clone();
                                wasm_bindgen_futures::spawn_local(async move {
                                    match invoke::<String>(
                                        "messages_open_attachment",
                                        serde_json::json!({
                                            "input": {
                                                "message_id": message_id,
                                                "attachment_id": attachment_id,
                                            }
                                        }),
                                    ).await {
                                        Ok(path) => {
                                            web_sys_log(&format!("messages_open_attachment: {path}"));
                                        }
                                        Err(e) => {
                                            web_sys_log(&format!("messages_open_attachment: {e}"));
                                        }
                                    }
                                });
                            },
                            "📎 {name} · {size}"
                        }
                    }
                }
            }
        }
    }
}

/// Deterministic palette pick for a label dot. Hash the folder name
/// down to one of six accent colors so the same label keeps the same
/// dot across renders without persisting a color choice anywhere.
fn label_color(name: &str) -> &'static str {
    const PALETTE: &[&str] = &[
        "#D85A30", "#378ADD", "#1D9E75", "#A858C8", "#D8A030", "#30A0C8",
    ];
    let mut hash: u32 = 5381;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    PALETTE[(hash as usize) % PALETTE.len()]
}
