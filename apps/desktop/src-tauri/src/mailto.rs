// SPDX-License-Identifier: Apache-2.0

//! `mailto:` deep-link handling.
//!
//! When the user (or another app) clicks a `mailto:foo@bar.com?...`
//! link and QSL is registered as the system handler, the OS hands the
//! URL to us via `tauri-plugin-deep-link`. The plugin surfaces both
//! cold-start (QSL launched *because* of the mailto click) and
//! runtime (QSL was already open) deliveries through the same
//! `on_open_url` callback.
//!
//! `install` parses every URL into a [`MailtoPayload`], emits it as
//! the `mailto_open` event, and lets the Dioxus side open the compose
//! pane with the parsed fields applied. Parsing follows RFC 6068:
//! the path component is the primary `to:` list, query parameters
//! `cc`, `bcc`, `subject`, `body`, `in-reply-to` are honored.
//!
//! IPC commands `default_email_client_is` / `default_email_client_set`
//! / `default_email_client_unset` wrap the plugin's
//! `is_registered` / `register` / `unregister` so the Settings window
//! can show "QSL is the default" and offer a one-click toggle.

use qsl_ipc::{IpcError, IpcErrorKind, IpcResult};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_deep_link::DeepLinkExt;
use tracing::{debug, info, warn};

/// Tauri event name carrying a parsed mailto payload to the UI.
pub const MAILTO_EVENT: &str = "mailto_open";

/// Schemes we register and react to. Single-element today; the array
/// shape leaves room for `mailto:` aliases (e.g. `mailto-secure:`)
/// without rewriting the plugin wiring.
const SCHEMES: &[&str] = &["mailto"];

/// Subset of an RFC 6068 mailto URL we care about. The compose pane
/// uses these as prefill values when present.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MailtoPayload {
    pub to: Option<String>,
    pub cc: Option<String>,
    pub bcc: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub in_reply_to: Option<String>,
}

/// Wire the plugin's `on_open_url` callback so every incoming
/// `mailto:` URL is parsed and forwarded to the UI as a `mailto_open`
/// event. Idempotent — calling twice is harmless.
pub fn install(app: &AppHandle) {
    let app_handle = app.clone();
    app.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            if url.scheme().eq_ignore_ascii_case("mailto") {
                handle_mailto(&app_handle, url.as_str());
            } else {
                debug!(scheme = %url.scheme(), "deep_link: ignoring non-mailto URL");
            }
        }
    });
}

fn handle_mailto(app: &AppHandle, url: &str) {
    let payload = match parse_mailto(url) {
        Ok(p) => p,
        Err(e) => {
            warn!(url, "mailto: parse failed: {e}");
            return;
        }
    };
    info!(to = ?payload.to, subject = ?payload.subject, "mailto: open");
    // Bring the main window to the front so the compose pane is
    // visible — most callers (browser link click) leave QSL minimized
    // / hidden in the tray.
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    if let Err(e) = app.emit_to("main", MAILTO_EVENT, &payload) {
        warn!("mailto: emit failed: {e}");
    }
}

/// Parse a `mailto:` URL per the subset of RFC 6068 we care about.
/// The path component is the primary recipients list; `cc`, `bcc`,
/// `subject`, `body`, `in-reply-to` query parameters supply the rest.
/// Multiple values in `to`/`cc`/`bcc` are preserved as a comma-joined
/// string — the compose pane parses them with the same address-list
/// helper it uses for typed input.
pub fn parse_mailto(input: &str) -> Result<MailtoPayload, String> {
    let url = url::Url::parse(input).map_err(|e| format!("not a URL: {e}"))?;
    if !url.scheme().eq_ignore_ascii_case("mailto") {
        return Err(format!("expected mailto: scheme, got {}", url.scheme()));
    }

    let mut payload = MailtoPayload::default();
    // The "path" of a mailto URL is the comma-separated to-list. The
    // `url` crate returns it still percent-encoded (`a%2Bb%40x.com`),
    // so decode here; query values below come pre-decoded from
    // `query_pairs()`.
    let path = percent_encoding::percent_decode_str(url.path()).decode_utf8_lossy();
    if !path.is_empty() {
        payload.to = Some(path.into_owned());
    }

    for (key, value) in url.query_pairs() {
        let value = value.into_owned();
        match key.as_ref().to_ascii_lowercase().as_str() {
            "to" => append_addr(&mut payload.to, &value),
            "cc" => append_addr(&mut payload.cc, &value),
            "bcc" => append_addr(&mut payload.bcc, &value),
            "subject" => payload.subject = Some(value),
            "body" => payload.body = Some(value),
            "in-reply-to" => payload.in_reply_to = Some(value),
            _ => {} // ignore unknown query keys per RFC 6068 §6
        }
    }

    if payload.to.is_none()
        && payload.cc.is_none()
        && payload.bcc.is_none()
        && payload.subject.is_none()
        && payload.body.is_none()
    {
        return Err("mailto URL had no recognized fields".into());
    }
    Ok(payload)
}

fn append_addr(target: &mut Option<String>, value: &str) {
    match target {
        Some(existing) => {
            existing.push_str(", ");
            existing.push_str(value);
        }
        None => *target = Some(value.to_string()),
    }
}

// ---------- IPC: default-client status / toggle ----------

/// `default_email_client_is` — does the OS currently consider QSL the
/// default `mailto:` handler?
#[tauri::command]
pub async fn default_email_client_is(app: AppHandle) -> IpcResult<bool> {
    Ok(SCHEMES
        .iter()
        .all(|s| matches!(app.deep_link().is_registered(s), Ok(true))))
}

/// `default_email_client_set` — register QSL as the default handler
/// for every scheme in [`SCHEMES`]. Wraps the plugin's `register`,
/// which writes the platform-specific entry (Linux: updates
/// `~/.config/mimeapps.list` + the bundled `.desktop` file; macOS:
/// `LSSetDefaultHandlerForURLScheme`; Windows: `HKCU\Software\Classes`).
#[tauri::command]
pub async fn default_email_client_set(app: AppHandle) -> IpcResult<()> {
    for scheme in SCHEMES {
        app.deep_link().register(*scheme).map_err(|e| {
            IpcError::new(IpcErrorKind::Internal, format!("register {scheme}: {e}"))
        })?;
    }
    Ok(())
}

/// `default_email_client_unset` — give the scheme back to whatever the
/// OS picks next. Useful for sanity-checking the toggle and for users
/// who want to revert without uninstalling QSL.
#[tauri::command]
pub async fn default_email_client_unset(app: AppHandle) -> IpcResult<()> {
    for scheme in SCHEMES {
        app.deep_link().unregister(*scheme).map_err(|e| {
            IpcError::new(IpcErrorKind::Internal, format!("unregister {scheme}: {e}"))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_to_address() {
        let p = parse_mailto("mailto:alice@example.com").unwrap();
        assert_eq!(p.to.as_deref(), Some("alice@example.com"));
        assert_eq!(p.subject, None);
    }

    #[test]
    fn parses_subject_and_body() {
        let p = parse_mailto("mailto:bob@example.com?subject=Hi&body=Hello%20there").unwrap();
        assert_eq!(p.to.as_deref(), Some("bob@example.com"));
        assert_eq!(p.subject.as_deref(), Some("Hi"));
        assert_eq!(p.body.as_deref(), Some("Hello there"));
    }

    #[test]
    fn cc_and_bcc_query_params() {
        let p = parse_mailto("mailto:a@x?cc=b@y&bcc=c@z&subject=test").unwrap();
        assert_eq!(p.to.as_deref(), Some("a@x"));
        assert_eq!(p.cc.as_deref(), Some("b@y"));
        assert_eq!(p.bcc.as_deref(), Some("c@z"));
    }

    #[test]
    fn comma_separated_to_list() {
        let p = parse_mailto("mailto:a@x,b@x").unwrap();
        // url crate passes the path through; consumers re-parse the
        // address list with their existing helper.
        assert_eq!(p.to.as_deref(), Some("a@x,b@x"));
    }

    #[test]
    fn percent_encoded_path_is_decoded() {
        let p = parse_mailto("mailto:J%C3%BCrgen%2Btag%40example.com").unwrap();
        assert_eq!(p.to.as_deref(), Some("Jürgen+tag@example.com"));
    }

    #[test]
    fn rejects_non_mailto_scheme() {
        assert!(parse_mailto("https://example.com").is_err());
    }

    #[test]
    fn rejects_empty_url() {
        assert!(parse_mailto("mailto:").is_err());
    }

    #[test]
    fn merges_path_to_with_query_to() {
        let p = parse_mailto("mailto:primary@x?to=secondary@x").unwrap();
        assert_eq!(p.to.as_deref(), Some("primary@x, secondary@x"));
    }
}
