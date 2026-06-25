// SPDX-License-Identifier: Apache-2.0

//! Build the full HTML document the reader pane renders.
//!
//! The Dioxus UI hands this document to a sandboxed
//! `<iframe srcdoc>` inside the host webview. Both the inline
//! reader and the popup-window reader use this composer so the
//! placeholder, theming, and link-forwarder rules live in one
//! place.
//!
//! Inputs are primitive borrowed slices rather than the
//! `RenderedMessage` struct so this crate doesn't have to depend on
//! `qsl-ipc` (which is a heavier sibling crate that itself pulls in
//! Tauri-side serialization helpers).

/// Compose the wrapper HTML document for the reader pane. `body_html`
/// wins if non-empty; `body_text` is the plaintext fallback wrapped in
/// `<pre>`; if both are empty/whitespace-only the document falls back
/// to a "no body" hint.
///
/// `parent_origin` is the origin of the parent window (the webview
/// that hosts the sandboxed iframe). It is used as the `targetOrigin`
/// in `postMessage` calls from within the iframe, avoiding the
/// insecure wildcard `'*'`. Pass `"*"` only in test contexts where
/// no real parent window exists.
///
/// The caller must have already passed any HTML body through
/// [`crate::sanitize_email_html`] — this function does **not**
/// sanitize, it just frames the body in the wrapper chrome.
pub fn compose_reader_html(
    body_html: Option<&str>,
    body_text: Option<&str>,
    parent_origin: &str,
) -> String {
    let body_section = render_body_section(body_html, body_text);

    // Headers (subject / from / date / recipients) are rendered by
    // the Dioxus side as a styled card; the iframe contains body
    // markup only so the user sees each piece of info exactly once.
    // CSP applied inside the iframe srcdoc as a defence-in-depth layer
    // behind the ammonia allowlist + adblock filter. `default-src 'none'`
    // blocks every fetch except what we explicitly permit:
    //   - `img-src data: https: http:` covers per-sender / global
    //     opt-in remote images plus inline data URIs. `http:` is in
    //     the list because plenty of legitimate marketing email
    //     (Apple Store survey, older Mailchimp templates) ship
    //     image URLs over plain HTTP. Once the sanitizer has let a
    //     URL through (the user opted in per-sender or globally),
    //     blocking it again at the CSP layer is just user-hostile.
    //     The sanitizer is the privacy gate; the CSP shuts off
    //     non-image / non-data egress (script-src, connect-src,
    //     frame-src, etc.).
    //   - `style-src 'unsafe-inline'` because the wrapper's <style>
    //     block is inline and email content keeps its `style="..."`
    //     attributes.
    //   - `script-src 'unsafe-inline'` for the click forwarder below;
    //     the iframe sandbox is `allow-scripts` already, so this only
    //     scopes which scripts can run, not whether scripts run at all.
    //   - `base-uri 'none'` and `form-action 'none'` shut off two
    //     classic exfil channels (rewriting the document base, posting
    //     a smuggled form to an attacker URL).
    // If the sanitizer ever lets a tag through that fetches against
    // `connect-src`, `frame-src`, `font-src`, etc., the CSP shuts it
    // off rather than relying solely on ammonia's allowlist.
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: https: http:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <style>
    body {{
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: #e6e8eb;
      background: #0f1115;
      margin: 0;
      padding: 1.25rem;
    }}
    @media (prefers-color-scheme: light) {{
      body {{ color: #14161a; background: #ffffff; }}
    }}
    .qsl-body {{ color: inherit; }}
    .qsl-body pre {{ white-space: pre-wrap; word-wrap: break-word; margin: 0; font: inherit; }}
    .qsl-body a {{ color: #74b4ff; }}
    @media (prefers-color-scheme: light) {{
      .qsl-body a {{ color: #2563eb; }}
    }}
    /* Dimension-preserving placeholder for `<img>` tags whose src was
     * blocked by the remote-content filter. The sanitizer marks each
     * blocked img with `data-qsl-blocked`; ammonia's default allowlist
     * preserves any `width` / `height` HTML attribute so the box keeps
     * its original layout footprint. The min-width/min-height fallback
     * covers tags that had no dimensions at all. The dashed border is
     * deliberately subtle — visible enough to communicate "blocked"
     * without dominating the rendered email. */
    .qsl-body img[data-qsl-blocked] {{
      box-sizing: border-box;
      min-width: 24px;
      min-height: 24px;
      border: 1px dashed rgba(180, 180, 200, 0.30);
      background: rgba(255, 255, 255, 0.025);
    }}
    @media (prefers-color-scheme: light) {{
      .qsl-body img[data-qsl-blocked] {{
        border-color: rgba(20, 22, 26, 0.20);
        background: rgba(20, 22, 26, 0.025);
      }}
    }}
  </style>
</head>
<body>
  <div class="qsl-body">{body_section}</div>
  <script>
    // Click forwarder. The wrapper loads into a sandboxed
    // `<iframe>` inside the host webkit2gtk webview. Top-level
    // navigation is blocked by the sandbox (no `allow-top-navigation`),
    // so we postMessage the URL up to the parent frame; the Dioxus
    // shell forwards it to the host's `open_external_url` Tauri
    // command which validates the scheme and shells out to the OS
    // default browser.
    document.addEventListener('click', function(e) {{
      var node = e.target;
      while (node && node.nodeName !== 'A') node = node.parentNode;
      if (!node || !node.href) return;
      e.preventDefault();
      try {{
        window.parent.postMessage({{ type: 'qsl-link-click', url: node.href }}, '{parent_origin}');
      }} catch (err) {{}}
    }}, true);
  </script>
</body>
</html>"#,
        parent_origin = parent_origin,
    )
}

/// Pick the right body rendering for the reader pane. Separated from
/// `compose_reader_html` so the preference order (sanitized HTML →
/// escaped plaintext → "no body" hint) is easy to read and test.
fn render_body_section(body_html: Option<&str>, body_text: Option<&str>) -> String {
    if let Some(html) = body_html {
        if !html.trim().is_empty() {
            return html.to_string();
        }
    }
    if let Some(text) = body_text {
        if !text.trim().is_empty() {
            return format!("<pre>{}</pre>", minimal_escape(text));
        }
    }
    // `messages_get` already lazy-fetches the body if it's missing
    // locally, so reaching this branch means the message genuinely
    // has no body content (headers-only, or a fetch error already
    // surfaced).
    "<em>No body content available for this message.</em>".to_string()
}

/// Minimal HTML escaping for plaintext content. Not a full sanitizer
/// — only used on fields we know are plain text (subject, plaintext
/// body). HTML bodies go through [`crate::sanitize_email_html`]
/// before reaching this module.
fn minimal_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_wins_when_present() {
        let out = compose_reader_html(Some("<p>hello</p>"), Some("plain"), "*");
        assert!(out.contains("<p>hello</p>"));
        // Plaintext fallback should NOT have been emitted.
        assert!(!out.contains("<pre>plain</pre>"));
    }

    #[test]
    fn plaintext_used_when_html_empty() {
        let out = compose_reader_html(Some("   "), Some("hi & bye"), "*");
        assert!(
            out.contains("<pre>hi &amp; bye</pre>"),
            "plaintext branch did not render: {out}"
        );
    }

    #[test]
    fn plaintext_used_when_html_none() {
        let out = compose_reader_html(None, Some("only text"), "*");
        assert!(out.contains("<pre>only text</pre>"));
    }

    #[test]
    fn falls_back_to_hint_when_both_empty() {
        let out = compose_reader_html(None, None, "*");
        assert!(out.contains("No body content available"));
    }

    #[test]
    fn html_carries_blocked_img_marker_through() {
        // Sanitizer marks blocked imgs with data-qsl-blocked; the
        // wrapper must preserve that attribute byte-for-byte so the
        // CSS selector matches.
        let body = r#"<img data-qsl-blocked alt="hero">"#;
        let out = compose_reader_html(Some(body), None, "*");
        assert!(out.contains("data-qsl-blocked"));
        // CSS rule is also present so the placeholder is actually styled.
        assert!(out.contains("img[data-qsl-blocked]"));
    }

    /// Regression guard: the reader's defence-in-depth CSP must always
    /// be present and must keep `default-src 'none'`, `base-uri 'none'`,
    /// `form-action 'none'`. If a future change relaxes any of these,
    /// the iframe gains an exfil channel that ammonia + adblock alone
    /// can't close. Locks the directive set against accidental drift.
    #[test]
    fn reader_doc_carries_strict_csp_meta() {
        let out = compose_reader_html(Some("<p>x</p>"), None, "*");
        assert!(
            out.contains(r#"<meta http-equiv="Content-Security-Policy""#),
            "CSP meta tag missing"
        );
        for directive in [
            "default-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ] {
            assert!(
                out.contains(directive),
                "CSP missing required directive `{directive}` — every release must keep it"
            );
        }
    }

    /// `img-src` must include `data:`, `https:`, AND `http:` so
    /// real-world email (lots of marketing / transactional senders
    /// still ship image URLs over plain HTTP) can render once the
    /// sanitizer has let the URL through. The sanitizer is the
    /// remote-content opt-in gate; the CSP's job is to shut off
    /// non-image egress (script-src, connect-src, etc.), not to
    /// second-guess image scheme decisions.
    ///
    /// Conversely, `default-src 'none'` must remain so the absence
    /// of any other `*-src` directive blocks every other request
    /// type — that's what enforces "no script egress, no font egress,
    /// no fetch, no frame loads, no top-level navigation."
    #[test]
    fn reader_doc_csp_img_src_covers_http_https_data() {
        let out = compose_reader_html(Some("<p>x</p>"), None, "*");
        let csp_start = out
            .find("Content-Security-Policy")
            .expect("CSP meta missing");
        let csp_chunk = &out[csp_start..csp_start + 600];
        let img_src_start = csp_chunk.find("img-src ").expect("img-src missing");
        let img_src_segment = &csp_chunk[img_src_start..];
        let img_src_end = img_src_segment.find(';').unwrap_or(img_src_segment.len());
        let img_src = &img_src_segment[..img_src_end];
        for needed in ["data:", "https:", "http:"] {
            assert!(
                img_src.contains(needed),
                "img-src missing `{needed}`: {img_src}"
            );
        }
        assert!(out.contains("default-src 'none'"));
    }

    #[test]
    fn minimal_escape_handles_each_unsafe_char() {
        assert_eq!(minimal_escape("&"), "&amp;");
        assert_eq!(minimal_escape("<"), "&lt;");
        assert_eq!(minimal_escape(">"), "&gt;");
        assert_eq!(minimal_escape("\""), "&quot;");
        assert_eq!(minimal_escape("'"), "&#39;");
        assert_eq!(minimal_escape("plain"), "plain");
    }
}
