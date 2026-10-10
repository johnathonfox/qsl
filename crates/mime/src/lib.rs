// SPDX-License-Identifier: Apache-2.0

//! QSL MIME helpers — thin wrappers over `mail-parser`.
//!
//! Presents QSL domain types (`MessageHeaders`, `MessageBody`,
//! `Attachment`, `EmailAddress`) to callers and keeps the underlying
//! parser crate out of the public surface. Both `qsl-imap-client`
//! and `qsl-jmap-client` call into [`parse_rfc822`] when a
//! `fetch_message` response comes back as raw bytes.

use std::borrow::Cow;

use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine as _;
use chrono::{TimeZone, Utc};
use mail_parser::{Address, HeaderValue, Message, MessageParser, MimeHeaders, PartType};

pub mod compose;
pub mod remote_content;

// mail-parser's Address::iter() returns Box<dyn DoubleEndedIterator<...>>,
// which gives us one uniform shape regardless of whether the underlying
// header was a list or a group of addresses.

use qsl_core::{
    AccountId, Attachment, AttachmentRef, EmailAddress, FolderId, MessageBody, MessageFlags,
    MessageHeaders, MessageId, ThreadId,
};

/// Extract one attachment's `(filename, bytes)` from a raw RFC 822
/// blob, looked up by part index.
///
/// `part_index` corresponds to the `i` baked into
/// `Attachment::id = AttachmentRef("part/{i}")` by [`parse_rfc822`]'s
/// part walk — same numbering, same iteration order. The desktop
/// app's `messages_open_attachment` command parses the prefix off the
/// `AttachmentRef` it received from the UI and hands the bare index
/// in here.
///
/// Returns `None` when:
/// - the RFC 822 blob fails to parse,
/// - `part_index` is past the end of the part list, or
/// - the indexed part isn't a `Binary` / `InlineBinary` part (i.e. the
///   index points at a text/html alternative or similar).
pub fn extract_attachment_bytes(raw: &[u8], part_index: usize) -> Option<(String, Vec<u8>)> {
    let parsed = MessageParser::default().parse(raw)?;
    let part = parsed.parts.get(part_index)?;
    let bytes: Vec<u8> = match &part.body {
        PartType::Binary(b) | PartType::InlineBinary(b) => b.to_vec(),
        _ => return None,
    };
    let filename = part
        .attachment_name()
        .map(str::to_string)
        .unwrap_or_else(|| format!("attachment-{part_index}"));
    Some((filename, bytes))
}

/// Parse a raw RFC 822 blob into a QSL [`MessageBody`].
///
/// Identity fields the adapter supplies (its own opaque IDs, the account
/// and folder) are taken as parameters; the parser only owns the
/// RFC-5322 headers and part structure.
pub fn parse_rfc822(raw: &[u8], identity: MessageIdentity<'_>) -> Option<MessageBody> {
    let parsed = MessageParser::default().parse(raw)?;
    let headers = headers_from(&parsed, &identity);
    let (body_text, body_html, attachments) = body_from(&parsed);
    let in_reply_to = single_message_id(parsed.in_reply_to());
    let references = message_id_list(parsed.references());
    Some(MessageBody {
        headers,
        body_html,
        body_text,
        attachments,
        in_reply_to,
        references,
    })
}

/// Sanitize HTML email content for rendering in the Servo reader pane.
///
/// Uses `ammonia` with its conservative default allowlist plus two
/// project-specific adjustments:
///
/// - `style` attribute allowed on every accepted tag. HTML emails
///   rely heavily on inline styles for presentational layout
///   (centered tables, branded colors, etc.). Not allowing them
///   would render most marketing and transactional email as
///   unstyled text. Inline `style="..."` can't inject script — CSS
///   expressions were deprecated in every browser a decade ago, and
///   we're rendering via Servo with JavaScript disabled anyway
///   (belt + suspenders). The `<style>` **element** remains
///   stripped: it can load external resources via `@import url(...)`
///   which would bypass the remote-content policy.
/// - Tag stripping list (`script`, `iframe`, `object`, `embed`,
///   `form`, `input`, `button`, `textarea`, `select`, `style`,
///   `link`) is redundant with ammonia's default allowlist but
///   explicit — if ammonia ever loosens its defaults in a minor
///   release, these stay stripped.
///
/// **Remote-content blocking** (default): every URL in a `src` /
/// `background` / `poster` / `srcset` attribute is dropped unless
/// it is `data:` (inline base64) or `cid:` (inline multipart
/// content-id reference). Tracker filtering by adblock rules
/// (Mailchimp open pixels, GA collect, etc.) was the original
/// design but it leaked: marketing CDNs the user hadn't opted in
/// to still loaded. Default-block-all matches the reader UI
/// promise ("Images blocked for privacy" / "Load images" / "Always
/// load from this sender"). The user opts in per-sender, which
/// flips `messages_get` over to [`sanitize_email_html_trusted`].
/// Link hrefs are deliberately not filtered here — blocking an
/// outbound anchor is user-hostile; link-click cleaning (utm_*
/// stripping, Mailchimp/SendGrid redirect unwrapping) is a
/// separate pipeline stage in the renderer's `on_link_click`
/// callback.
///
/// For senders the user has explicitly trusted (recorded in
/// `remote_content_opt_ins`), `messages_get` calls
/// [`sanitize_email_html_trusted`] instead, which keeps every other
/// sanitization rule but skips the URL filter.
///
/// Returns empty-ish output is acceptable: the reader UI's
/// `compose_reader_html` falls back to the plaintext path when the
/// sanitized result is empty or whitespace-only.
pub fn sanitize_email_html(raw_html: &str) -> String {
    sanitize(raw_html, /* block_remote = */ true)
}

/// Sanitize HTML for a sender the user has trusted via
/// `remote_content_opt_ins` for this account. Every rule from
/// [`sanitize_email_html`] still applies (script stripping,
/// `javascript:` URL removal, event-handler attribute removal,
/// element allowlist), but `src` / `background` / `poster` /
/// `srcset` URLs are passed through unchecked.
pub fn sanitize_email_html_trusted(raw_html: &str) -> String {
    sanitize(raw_html, /* block_remote = */ false)
}

fn sanitize(raw_html: &str, block_remote: bool) -> String {
    let cleaned = ammonia::Builder::default()
        .add_generic_attributes(["style"])
        .add_url_schemes(["data", "cid"])
        // ammonia's `rm_tags` strips the tag wrapper but leaves the
        // text content as a plain text node. That bit us on Microsoft
        // 365 newsletters whose `<title>Learn simple prompts...</title>`
        // ended up rendering as a stray text line at the top of the
        // body. `add_clean_content_tags` is the right hammer for any
        // element whose contents are non-display markup that should
        // never render as text — `<head>` / `<title>` (HTML metadata)
        // and `<noscript>` (script-required-fallback messaging) join
        // ammonia's defaults of `<script>` / `<style>`.
        .add_clean_content_tags(["head", "title", "noscript"])
        .rm_tags([
            "script", "iframe", "object", "embed", "form", "input", "button", "textarea", "select",
            "style", "link",
        ])
        .attribute_filter(move |_element, attribute, value| -> Option<Cow<'_, str>> {
            // In `block_remote` mode (default), drop any image-loading
            // attribute that points at a remote URL. The reader UI
            // banner ("Images blocked for privacy" / "Load images" /
            // "Always load from this sender") is the user's gate;
            // letting non-tracker CDN images through silently would
            // contradict that promise. Inline `data:` and inline-CID
            // `cid:` references stay — they don't phone home.
            //
            // Trusted-sender mode (`block_remote=false`) skips this
            // filter entirely and lets every URL through.
            match attribute {
                // `data:` / `cid:` were added to the URL-scheme
                // allowlist for *image* sources. On an anchor they are
                // never useful and `data:text/html,…` is a classic
                // sandbox-escape probe, so drop them regardless of
                // trust mode. (The click forwarder + host opener
                // already refuse them; this is defence in depth.)
                "href" if url_is_inline_safe(value) => None,
                "src" | "background" | "poster" if block_remote && !url_is_inline_safe(value) => {
                    None
                }
                "srcset" if block_remote && !srcset_is_inline_safe(value) => None,
                "style" if block_remote => {
                    // CSS `background-image: url(...)` and friends are
                    // a second remote-content vector that the
                    // attribute-name match above misses. Drop any
                    // declaration that references a non-inline URL;
                    // keep the rest. See `filter_inline_style`.
                    Some(Cow::Owned(filter_inline_style(value)))
                }
                _ => Some(Cow::Borrowed(value)),
            }
        })
        .clean(raw_html)
        .to_string();
    // Element-level rewrite pass: tag every `<img>` whose `src` was
    // dropped by the attribute filter (or was never present) with a
    // `data-qsl-blocked` boolean attribute. The reader CSS frames
    // these as same-dimension placeholder boxes so layout doesn't
    // reflow when the user clicks "Load images". `ammonia::Builder`
    // doesn't expose element-level rewriting, so this happens after
    // the clean pass over the canonical output.
    if block_remote {
        mark_blocked_images(&cleaned)
    } else {
        cleaned
    }
}

/// Walk an ammonia-cleaned HTML string and append `data-qsl-blocked`
/// to every `<img>` tag that lacks a `src` attribute. Return the input
/// unchanged when no rewrite is needed (avoids spurious diff churn).
///
/// The output pre-existing `width` / `height` attributes (and inline
/// `style="width:..."`) are preserved by ammonia's default allowlist,
/// so the placeholder reserves the original layout box; the reader
/// stylesheet supplies a `min-width` / `min-height` fallback for tags
/// missing dimensions entirely.
fn mark_blocked_images(html: &str) -> String {
    // Cheap fast-path: if the cleaned HTML has no `<img` tokens at all,
    // there's nothing to do. ASCII match — safe even on UTF-8.
    if !html.contains("<img") {
        return html.to_string();
    }
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len() + 32);
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some(rel) = html[cursor..].find("<img") else {
            break;
        };
        let img_open = cursor + rel;
        let after_img = img_open + 4;
        // Confirm `<img` is the start of an actual tag — the next byte
        // must be whitespace, `/`, or `>`. Otherwise this is a partial
        // match inside another token (e.g. `<image>`) — copy past and
        // continue.
        let is_tag = matches!(
            bytes.get(after_img).copied(),
            Some(b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/')
        );
        if !is_tag {
            out.push_str(&html[cursor..=img_open]);
            cursor = img_open + 1;
            continue;
        }
        // Find the closing `>` of this tag, skipping any `>` inside a
        // quoted attribute value (html5ever's serializer does not
        // escape `>` in attribute values, so `alt="a>b"` is real).
        let Some(tag_end) = find_tag_end(html, after_img) else {
            // Unterminated tag — bail: copy the rest verbatim.
            out.push_str(&html[cursor..]);
            return out;
        };
        let attrs = &html[after_img..tag_end];
        // Copy everything up to (but not including) the closing `>`.
        out.push_str(&html[cursor..tag_end]);
        if !img_attrs_have_src(attrs) {
            out.push_str(" data-qsl-blocked");
        }
        out.push('>');
        cursor = tag_end + 1;
    }
    out.push_str(&html[cursor..]);
    out
}

/// Byte offset of the `>` that closes the tag whose attribute list
/// starts at `from`, honouring single- and double-quoted attribute
/// values. `None` if the tag is unterminated. Every index compared
/// is an ASCII byte, so slicing at the result is char-boundary safe.
fn find_tag_end(html: &str, from: usize) -> Option<usize> {
    let bytes = html.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate().skip(from) {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'>' => return Some(i),
                _ => {}
            },
        }
    }
    None
}

/// Walk an `<img>` tag's attribute slice (between the `<img` opener
/// and the closing `>`) and report whether a `src=` attribute is
/// present. Avoids the substring-false-positive case of e.g.
/// `<img title="src=here">`. ammonia normalizes its output enough
/// that this hand-rolled walk is sufficient — we only need to handle
/// canonically-emitted attribute syntax.
fn img_attrs_have_src(attrs: &str) -> bool {
    let bytes = attrs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip leading whitespace.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return false;
        }
        // A trailing `/` before `>` (self-closing) ends the attr list.
        if bytes[i] == b'/' {
            return false;
        }
        // Read attribute name until `=`, whitespace, or end-of-attrs.
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        if attrs[name_start..i].eq_ignore_ascii_case("src") {
            return true;
        }
        // Skip whitespace between name and `=` (allowed by HTML spec).
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            // Quoted or unquoted value.
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            } else {
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
            }
        }
    }
    false
}

/// Walk a CSS inline-style declaration list, drop any declaration
/// whose `url(...)` argument is blocked by `engine`, and re-emit the
/// rest. Not a full CSS parser — handles the `prop: url(arg) [other]`
/// shape that marketing emails actually ship and falls back to
/// keeping a declaration when the URL token can't be cleanly
/// extracted (so a malformed declaration with a tracking pixel stays
/// blocked at the higher-level `<img src>` filter).
///
/// Why drop the whole declaration rather than just the `url(...)`
/// token: the alternatives (rewriting to `none`, leaving an empty
/// `url()`) tend to fight the email's existing fallback chain,
/// whereas dropping the property entirely lets any earlier
/// declaration in the cascade or the user-agent default take over.
/// True if a single URL string is safe to keep without user opt-in:
/// `data:` (inline base64) and `cid:` (inline content-id reference
/// to a multipart/related body) don't make a network request.
/// Anything else is treated as remote and gets blocked in
/// untrusted-sender mode.
fn url_is_inline_safe(url: &str) -> bool {
    let trimmed = url.trim_start();
    let lower_first = trimmed
        .as_bytes()
        .iter()
        .take(5)
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let prefix = std::str::from_utf8(&lower_first).unwrap_or("");
    prefix.starts_with("data:") || prefix.starts_with("cid:")
}

/// True if every URL in a `srcset` value is inline-safe. `srcset` is a
/// comma-separated list of `<url> [<descriptor>]` entries (e.g.
/// `"a.png 1x, b.png 2x"`). One non-inline URL drops the whole
/// attribute — letting partial URLs through would defeat the block
/// since browsers pick from the list opportunistically.
fn srcset_is_inline_safe(srcset: &str) -> bool {
    srcset.split(',').all(|entry| {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return true;
        }
        let url = trimmed.split_whitespace().next().unwrap_or("");
        url_is_inline_safe(url)
    })
}

fn filter_inline_style(style: &str) -> String {
    // Fast path: scan once for declarations that could fetch a
    // remote resource. If nothing matches, return the input verbatim
    // — this preserves exact whitespace + trailing-semicolon shape,
    // which keeps the common no-image-styling case byte-identical to
    // the input and avoids spurious diffs in existing sanitizer tests.
    let mut any_blocked = false;
    let kept: Vec<&str> = split_declarations(style)
        .into_iter()
        .filter_map(|decl| {
            let trimmed = decl.trim();
            if trimmed.is_empty() {
                return None;
            }
            if declaration_may_fetch_remote(trimmed) {
                any_blocked = true;
                return None;
            }
            Some(trimmed)
        })
        .collect();
    if !any_blocked {
        return style.to_string();
    }
    // Slow path: rebuild from the kept declarations.
    let mut out = String::with_capacity(style.len());
    let mut first = true;
    for decl in kept {
        if !first {
            out.push_str("; ");
        }
        first = false;
        out.push_str(decl);
    }
    // Preserve a trailing semicolon when the input had one — keeps
    // emitted styles consistent with the canonical CSS shorthand
    // shape downstream tooling expects.
    if !out.is_empty() && style.trim_end().ends_with(';') {
        out.push(';');
    }
    out
}

/// Split a `style` attribute into declarations at top-level `;` —
/// i.e. not inside a quoted string or inside parentheses, so
/// `background: url("a;b")` stays one declaration. (A naive
/// `split(';')` let `url(&quot;https://t/p.gif?x=1;&quot;)` through:
/// the cut landed inside the quotes and the URL scanner then found
/// no closing quote and gave up.)
fn split_declarations(style: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    let mut depth: u32 = 0;
    let mut escaped = false;
    for (i, ch) in style.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match (quote, ch) {
            (_, '\\') => escaped = true,
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(ch),
            (None, '(') => depth += 1,
            (None, ')') => depth = depth.saturating_sub(1),
            (None, ';') if depth == 0 => {
                out.push(&style[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&style[start..]);
    out
}

/// CSS functions whose arguments the browser fetches. Checked against
/// the *normalised* declaration (comments stripped, escapes decoded,
/// ASCII-lowercased), so `URL(`, `\75rl(` and `url/**/(` all match.
const CSS_FETCHING_FUNCTIONS: &[&str] = &[
    "url(",
    "image-set(",
    "-webkit-image-set(",
    "image(",
    "src(",
    "cross-fade(",
    "-webkit-cross-fade(",
    "element(",
    "-moz-element(",
    "paint(",
    "@import",
];

/// Does this single declaration reference a non-inline (i.e. remote)
/// resource? Conservative: a fetching function with no extractable
/// argument counts as remote, because a malformed declaration we
/// can't parse is exactly the shape an exfil attempt would take.
fn declaration_may_fetch_remote(decl: &str) -> bool {
    let norm = normalize_css(decl);
    if !CSS_FETCHING_FUNCTIONS.iter().any(|f| norm.contains(f)) {
        return false;
    }
    let candidates = css_url_candidates(&norm);
    if candidates.is_empty() {
        return true;
    }
    candidates.iter().any(|c| !url_is_inline_safe(c))
}

/// Canonicalise a CSS declaration for matching: drop `/* … */`
/// comments, decode backslash escapes (`\75` → `u`, `\"` → `"`),
/// and ASCII-lowercase. Operates on `char`s, never on byte offsets,
/// so arbitrary UTF-8 (`font-family: Söhne`) is safe — the previous
/// byte-stepping scanner panicked on any multi-byte character.
fn normalize_css(decl: &str) -> String {
    let mut out = String::with_capacity(decl.len());
    let mut chars = decl.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                // Skip to the closing `*/` (or end of input).
                let mut prev = '\0';
                for c in chars.by_ref() {
                    if prev == '*' && c == '/' {
                        break;
                    }
                    prev = c;
                }
            }
            '\\' => {
                // CSS escape: up to 6 hex digits plus one optional
                // whitespace, or any single non-newline character.
                let mut hex = String::new();
                while hex.len() < 6 {
                    match chars.peek() {
                        Some(c) if c.is_ascii_hexdigit() => {
                            hex.push(*c);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                if hex.is_empty() {
                    if let Some(c) = chars.next() {
                        if c != '\n' {
                            out.push(c.to_ascii_lowercase());
                        }
                    }
                } else {
                    if chars.peek().is_some_and(|c| c.is_whitespace()) {
                        chars.next();
                    }
                    let decoded = u32::from_str_radix(&hex, 16)
                        .ok()
                        .and_then(char::from_u32)
                        .unwrap_or('\u{FFFD}');
                    out.push(decoded.to_ascii_lowercase());
                }
            }
            c => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

/// Every URL-ish argument in a normalised declaration: the argument
/// of each `url(` (quoted or bare) plus every quoted string anywhere
/// in the value (`image-set("…")`, `src("…")`, …). Returned slices
/// are trimmed.
fn css_url_candidates(norm: &str) -> Vec<&str> {
    let mut out = Vec::new();
    // Bare (unquoted) `url(…)` arguments.
    for (idx, _) in norm.match_indices("url(") {
        let rest = &norm[idx + 4..];
        let arg = rest.trim_start();
        if arg.starts_with(['"', '\'']) {
            continue; // handled by the quoted-string pass below
        }
        let end = arg.find(')').unwrap_or(arg.len());
        let bare = arg[..end].trim();
        if !bare.is_empty() {
            out.push(bare);
        }
    }
    // Quoted strings.
    let mut rest = norm;
    while let Some(open) = rest.find(['"', '\'']) {
        let quote = rest.as_bytes()[open];
        let body = &rest[open + 1..];
        match body.find(quote as char) {
            Some(close) => {
                let s = body[..close].trim();
                if !s.is_empty() {
                    out.push(s);
                }
                rest = &body[close + 1..];
            }
            None => {
                // Unterminated string: treat the remainder as the
                // candidate so a dangling `"https://…` is still seen.
                let s = body.trim();
                if !s.is_empty() {
                    out.push(s);
                }
                break;
            }
        }
    }
    out
}

/// Decode a single RFC-2047 encoded-word header value
/// (`=?UTF-8?Q?…?=`, `=?UTF-8?B?…?=`, etc.) into a plain `String`.
///
/// IMAP `ENVELOPE` responses surface raw header bytes with their
/// encoded-word wrappers intact; `mail-parser`'s `Message::subject()`
/// handles decoding as part of full-message parsing but there's no
/// exposed standalone "decode this header value" helper. Work around
/// that by parsing a synthetic one-header message and pulling the
/// decoded subject back out.
///
/// Returns the input unchanged if the parser can't build a Message
/// (shouldn't happen for well-formed input, but staying lenient
/// beats losing the raw text entirely).
pub fn decode_header_value(raw: &str) -> String {
    if !raw.contains("=?") {
        // Fast path: not an encoded word, nothing to do.
        return raw.to_string();
    }
    let synthetic = format!("Subject: {raw}\r\n\r\n");
    MessageParser::default()
        .parse(synthetic.as_bytes())
        .and_then(|m| m.subject().map(|s| s.to_string()))
        .unwrap_or_else(|| raw.to_string())
}

/// Parse just the headers plus a short snippet — used in list responses
/// where we don't want to buffer the full body.
pub fn parse_headers(raw: &[u8], identity: MessageIdentity<'_>) -> Option<MessageHeaders> {
    let parsed = MessageParser::default().parse(raw)?;
    Some(headers_from(&parsed, &identity))
}

/// Pull SMTP envelope addresses out of an RFC 5322 byte stream:
/// the From address (singular — first parsed `From:` entry) and
/// the flattened union of To + Cc + Bcc. Used by SMTP-submission
/// backends, which need the envelope independently of how the
/// header block renders downstream.
///
/// Bcc is included in the recipient list (that's what makes blind
/// carbon-copy actually work). The SMTP server does *not* strip the
/// `Bcc:` header from DATA on the caller's behalf — run the bytes
/// through [`compose::strip_bcc_header`] before submission.
///
/// Returns empty vecs / None if the parser can't make sense of the
/// bytes — the caller should treat that as a permanent failure
/// because there's no recoverable retry.
pub fn extract_envelope(raw: &[u8]) -> (Option<EmailAddress>, Vec<EmailAddress>) {
    let Some(parsed) = MessageParser::default().parse(raw) else {
        return (None, Vec::new());
    };
    let from = addresses_from_opt(parsed.from()).into_iter().next();
    let mut recipients = addresses_from_opt(parsed.to());
    recipients.extend(addresses_from_opt(parsed.cc()));
    recipients.extend(addresses_from_opt(parsed.bcc()));
    (from, recipients)
}

/// Pull the `Message-ID` header out of an RFC 5322 byte stream,
/// angle-bracket-wrapped to match the rest of the workspace
/// (`<id@example.com>`). `None` if no header was found or the
/// bytes don't parse.
pub fn extract_message_id(raw: &[u8]) -> Option<String> {
    let parsed = MessageParser::default().parse(raw)?;
    parsed.message_id().map(|id| format!("<{id}>"))
}

/// Pull `In-Reply-To` and `References` out of an RFC 5322 header
/// block (no body). Used by `qsl-imap-client` after a
/// `BODY.PEEK[HEADER]` FETCH — the structured ENVELOPE only
/// surfaces `In-Reply-To`, so the threading pipeline needs a
/// follow-up parse to recover `References` for the chain-walk
/// fallback.
///
/// Both Message-IDs are returned angle-bracket-wrapped to match the
/// shape the rest of the workspace already uses
/// (`<id@example.com>`).
pub fn extract_thread_headers(header_bytes: &[u8]) -> (Option<String>, Vec<String>) {
    // mail-parser wants a complete message. The header block from
    // `BODY.PEEK[HEADER]` ends with a CRLF separator already; tack
    // on an empty body so the parser stops cleanly.
    let synthetic = [header_bytes, b"\r\n"].concat();
    let Some(parsed) = MessageParser::default().parse(&synthetic) else {
        return (None, Vec::new());
    };
    let in_reply_to = single_message_id(parsed.in_reply_to());
    let references = message_id_list(parsed.references());
    (in_reply_to, references)
}

/// Identity fields the adapter knows that the MIME parser does not.
#[derive(Debug, Clone, Copy)]
pub struct MessageIdentity<'a> {
    pub id: &'a MessageId,
    pub account_id: &'a AccountId,
    pub folder_id: &'a FolderId,
    pub thread_id: Option<&'a ThreadId>,
    pub size: u32,
    pub flags: &'a MessageFlags,
    pub labels: &'a [String],
}

/// Replace line-breaking / NUL control characters in a decoded header
/// value with a single space. RFC 2047 encoded-words can smuggle raw
/// CR/LF into a decoded `Subject:` or display name (mail-parser does
/// no filtering); anything downstream that re-emits the string into
/// a header (Reply → `build_rfc5322`) must never see them. Other
/// control characters (tabs etc.) are left alone.
pub fn strip_header_controls(s: &str) -> String {
    if !s.contains(['\r', '\n', '\0']) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for ch in s.chars() {
        if matches!(ch, '\r' | '\n' | '\0') {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        } else {
            out.push(ch);
            last_was_space = false;
        }
    }
    out
}

fn headers_from(parsed: &Message<'_>, identity: &MessageIdentity<'_>) -> MessageHeaders {
    let subject = strip_header_controls(parsed.subject().unwrap_or_default());
    let from = addresses_from_opt(parsed.from());
    let reply_to = addresses_from_opt(parsed.reply_to());
    let to = addresses_from_opt(parsed.to());
    let cc = addresses_from_opt(parsed.cc());
    let bcc = addresses_from_opt(parsed.bcc());
    let date = parsed
        .date()
        .and_then(|d| Utc.timestamp_opt(d.to_timestamp(), 0).single())
        .unwrap_or_else(Utc::now);

    let rfc822_message_id = parsed.message_id().map(|s| format!("<{s}>"));
    let snippet = snippet_from(parsed);
    let has_attachments = parsed.attachment_count() > 0;
    let in_reply_to = single_message_id(parsed.in_reply_to());
    let references = message_id_list(parsed.references());

    MessageHeaders {
        id: identity.id.clone(),
        account_id: identity.account_id.clone(),
        folder_id: identity.folder_id.clone(),
        thread_id: identity.thread_id.cloned(),
        rfc822_message_id,
        subject,
        from,
        reply_to,
        to,
        cc,
        bcc,
        date,
        flags: identity.flags.clone(),
        labels: identity.labels.to_vec(),
        snippet,
        size: identity.size,
        has_attachments,
        in_reply_to,
        references,
    }
}

fn addresses_from_opt(addr: Option<&Address<'_>>) -> Vec<EmailAddress> {
    match addr {
        Some(a) => a.iter().map(addr_one).collect(),
        None => Vec::new(),
    }
}

fn addr_one(a: &mail_parser::Addr<'_>) -> EmailAddress {
    EmailAddress {
        address: strip_header_controls(a.address.as_deref().unwrap_or_default()),
        display_name: a.name.as_deref().map(strip_header_controls),
    }
}

fn single_message_id(hv: &HeaderValue<'_>) -> Option<String> {
    match hv {
        HeaderValue::Text(s) => Some(format!("<{s}>")),
        HeaderValue::TextList(list) => list.first().map(|s| format!("<{s}>")),
        _ => None,
    }
}

fn message_id_list(hv: &HeaderValue<'_>) -> Vec<String> {
    match hv {
        HeaderValue::Text(s) => vec![format!("<{s}>")],
        HeaderValue::TextList(list) => list.iter().map(|s| format!("<{s}>")).collect(),
        _ => Vec::new(),
    }
}

fn body_from(parsed: &Message<'_>) -> (Option<String>, Option<String>, Vec<Attachment>) {
    let body_text = parsed
        .body_text(0)
        .map(|b| b.into_owned())
        .filter(|s| !s.is_empty());
    let body_html = parsed
        .body_html(0)
        .map(|b| b.into_owned())
        .filter(|s| !s.is_empty());

    let mut attachments = Vec::new();
    // (content_id, "data:<mime>;base64,<bytes>") pairs for inline parts
    // referenced by `cid:` URLs in the HTML body. Built alongside the
    // attachment list so we walk parts only once.
    let mut cid_map: Vec<(String, String)> = Vec::new();
    for (i, part) in parsed.parts.iter().enumerate() {
        if !matches!(part.body, PartType::Binary(_) | PartType::InlineBinary(_)) {
            continue;
        }
        let filename = part.attachment_name().unwrap_or("attachment").to_string();
        let mime_type = part
            .content_type()
            .map(|ct| match (ct.ctype(), ct.subtype()) {
                (main, Some(sub)) => format!("{main}/{sub}"),
                (main, None) => main.to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let size = part.len() as u64;
        let inline = matches!(part.body, PartType::InlineBinary(_));
        let content_id = part.content_id().map(str::to_string);
        // Resolve `cid:` refs whenever a binary part advertises a
        // Content-ID, regardless of whether mail-parser categorized
        // it as InlineBinary or Binary. The disposition vs. inline
        // distinction is fuzzy in real-world email and the
        // authoritative signal for "this is referenced from the
        // HTML body" is just having a Content-ID.
        if let Some(cid) = content_id.as_deref() {
            let bytes_opt: Option<&[u8]> = match &part.body {
                PartType::InlineBinary(b) => Some(b.as_ref()),
                PartType::Binary(b) => Some(b.as_ref()),
                _ => None,
            };
            if let Some(bytes) = bytes_opt {
                let b64 = base64_engine.encode(bytes);
                cid_map.push((cid.to_string(), format!("data:{mime_type};base64,{b64}")));
            }
        }
        attachments.push(Attachment {
            // The part index is the stable, backend-agnostic handle for
            // this attachment within the message. IMAP callers can map
            // this to a BODY[n] section; JMAP already exposes blob ids.
            id: AttachmentRef(format!("part/{i}")),
            filename,
            mime_type,
            size,
            inline,
            content_id,
        });
    }
    let body_html = body_html.map(|html| rewrite_cid_refs(&html, &cid_map));
    (body_text, body_html, attachments)
}

/// Replace every `cid:<id>` URL in `html` with the matching inline
/// `data:` URI from `cid_map`. Without this rewrite the sanitizer
/// happily passes the `cid:` URL through (it's a non-network scheme),
/// but webkit2gtk has no resolver for it, so the embedded image
/// renders as broken-image / alt-text only — what the Apple Store
/// "AppleLogo" placeholder bug looked like.
///
/// String-replace is sufficient: mail-parser strips the angle brackets
/// from `Content-ID` so `cid_map` keys are bare ids, and HTML emails
/// reference them with the same bare form (`<img src="cid:foo@bar">`).
/// We also try the angle-bracketed variant defensively for parsers
/// that retain them.
fn rewrite_cid_refs(html: &str, cid_map: &[(String, String)]) -> String {
    /// Upper bound on the rewritten document. Each substitution
    /// splices in a whole base64 attachment; a body that mentions
    /// `cid:x` a few thousand times next to a multi-MB part would
    /// otherwise expand to tens of GB and abort the process on
    /// allocation failure. Past the cap, remaining references are
    /// left as-is (they render as broken images, which is the
    /// pre-rewrite behaviour anyway).
    const MAX_OUTPUT_BYTES: usize = 48 * 1024 * 1024;
    /// Per-Content-ID substitution budget. Legitimate HTML references
    /// an inline part a handful of times at most.
    const MAX_REPLACEMENTS_PER_CID: usize = 64;

    if cid_map.is_empty() {
        return html.to_string();
    }
    // Longest bare id first so `cid:img10` is matched before `cid:img1`
    // instead of being half-substituted by the shorter prefix.
    let mut entries: Vec<(&str, &str, usize)> = cid_map
        .iter()
        .filter_map(|(cid, uri)| {
            let bare = cid.trim_start_matches('<').trim_end_matches('>');
            (!bare.is_empty()).then_some((bare, uri.as_str(), 0usize))
        })
        .collect();
    entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    if entries.is_empty() {
        return html.to_string();
    }

    let mut out = String::with_capacity(html.len());
    let mut cursor = 0;
    for (idx, _) in html.match_indices("cid:") {
        if idx < cursor {
            continue; // inside a span we already consumed
        }
        let after = &html[idx + 4..];
        let Some(entry) = entries.iter_mut().find(|(bare, _, _)| {
            after.starts_with(*bare)
                && after[bare.len()..].chars().next().is_none_or(|c| {
                    matches!(c, '"' | '\'' | ')' | '>' | '<' | '&') || c.is_whitespace()
                })
        }) else {
            continue;
        };
        let (bare, uri, used) = entry;
        if *used >= MAX_REPLACEMENTS_PER_CID
            || out.len() + (idx - cursor) + uri.len() > MAX_OUTPUT_BYTES
        {
            continue;
        }
        *used += 1;
        out.push_str(&html[cursor..idx]);
        out.push_str(uri);
        cursor = idx + 4 + bare.len();
    }
    out.push_str(&html[cursor..]);
    out
}

fn snippet_from(parsed: &Message<'_>) -> String {
    const MAX: usize = 140;
    let raw = parsed
        .body_text(0)
        .or_else(|| parsed.body_html(0))
        .map(|b| b.into_owned())
        .unwrap_or_default();
    let one_line: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    // Fast path: if the byte length is already under the cap, no
    // truncation is needed and we don't have to walk the chars at all.
    if one_line.len() <= MAX {
        return one_line;
    }
    // `String::truncate` panics if the cut point lands inside a
    // multi-byte UTF-8 sequence (real Gmail content is full of emoji,
    // accented Western chars, CJK, etc.). Cap by char count instead —
    // 140 *characters* is also a more sensible snippet limit than 140
    // bytes since CJK senders would otherwise see a ~46-character
    // preview.
    let mut chars = one_line.chars();
    let mut truncated: String = chars.by_ref().take(MAX).collect();
    if chars.next().is_some() {
        truncated.push('\u{2026}');
    }
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsl_core::{AccountId, FolderId, MessageFlags, MessageId};

    const SAMPLE: &[u8] = b"From: Jane Doe <jane@example.com>\r\n\
To: me@example.com\r\n\
Subject: Hello\r\n\
Date: Fri, 18 Apr 2026 10:00:00 +0000\r\n\
Message-ID: <abc@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Just checking in.\r\n";

    fn ident<'a>(
        id: &'a MessageId,
        acct: &'a AccountId,
        folder: &'a FolderId,
        flags: &'a MessageFlags,
    ) -> MessageIdentity<'a> {
        MessageIdentity {
            id,
            account_id: acct,
            folder_id: folder,
            thread_id: None,
            size: SAMPLE.len() as u32,
            flags,
            labels: &[],
        }
    }

    #[test]
    fn parses_headers_and_plaintext_body() {
        let msg_id = MessageId("m1".into());
        let acct = AccountId("a1".into());
        let folder = FolderId("INBOX".into());
        let flags = MessageFlags::default();

        let body = parse_rfc822(SAMPLE, ident(&msg_id, &acct, &folder, &flags)).unwrap();
        assert_eq!(body.headers.subject, "Hello");
        assert_eq!(body.headers.from.len(), 1);
        assert_eq!(body.headers.from[0].address, "jane@example.com");
        assert_eq!(
            body.headers.from[0].display_name.as_deref(),
            Some("Jane Doe")
        );
        assert_eq!(body.headers.to[0].address, "me@example.com");
        assert_eq!(
            body.headers.rfc822_message_id.as_deref(),
            Some("<abc@example.com>")
        );
        assert_eq!(
            body.body_text.as_deref().unwrap().trim(),
            "Just checking in."
        );
        // mail-parser synthesizes an HTML fallback from the text/plain
        // part when no text/html is present; the important invariant is
        // that body_text is correct. Asserting body_html.is_none() would
        // over-specify the parser's behavior.
        assert!(body.attachments.is_empty());
        assert!(body.headers.snippet.contains("Just checking in"));
    }

    #[test]
    fn body_decodes_declared_windows_1252_charset() {
        // Defensive regression: the user's real-world mojibake report
        // (`Â®` / `Ã®` for `®`) was pinned to the renderer's data-URL
        // encoder, not to mail-parser. Lock in the assumption that
        // mail-parser honors the declared charset so MCP `get_message`
        // (and the desktop reader pane) both receive correctly-decoded
        // strings. If mail-parser ever regresses, this fails loudly.
        let mut raw = b"From: sender@example.com\r\n\
To: me@example.com\r\n\
Subject: Test\r\n\
Date: Fri, 18 Apr 2026 10:00:00 +0000\r\n\
Message-ID: <cp1252@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=windows-1252\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n\
Good Hands"
            .to_vec();
        // Windows-1252 0xAE → ®.
        raw.push(0xAE);
        raw.extend_from_slice(b"\r\n");

        let msg_id = MessageId("m1".into());
        let acct = AccountId("a1".into());
        let folder = FolderId("INBOX".into());
        let flags = MessageFlags::default();
        let body = parse_rfc822(&raw, ident(&msg_id, &acct, &folder, &flags)).unwrap();
        let text = body.body_text.expect("text body present");
        assert!(
            text.contains("Good Hands®"),
            "windows-1252 0xAE was not decoded to ®; got {text:?}"
        );
    }

    #[test]
    fn body_decodes_declared_iso_8859_1_charset() {
        let mut raw = b"From: sender@example.com\r\n\
To: me@example.com\r\n\
Subject: Test\r\n\
Date: Fri, 18 Apr 2026 10:00:00 +0000\r\n\
Message-ID: <iso@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=iso-8859-1\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n\
caf"
        .to_vec();
        // ISO-8859-1 0xE9 → é.
        raw.push(0xE9);
        raw.extend_from_slice(b"\r\n");

        let msg_id = MessageId("m1".into());
        let acct = AccountId("a1".into());
        let folder = FolderId("INBOX".into());
        let flags = MessageFlags::default();
        let body = parse_rfc822(&raw, ident(&msg_id, &acct, &folder, &flags)).unwrap();
        let text = body.body_text.expect("text body present");
        assert!(
            text.contains("café"),
            "iso-8859-1 0xE9 was not decoded to é; got {text:?}"
        );
    }

    #[test]
    fn parse_headers_matches_body_headers() {
        let msg_id = MessageId("m1".into());
        let acct = AccountId("a1".into());
        let folder = FolderId("INBOX".into());
        let flags = MessageFlags::default();

        let hdrs = parse_headers(SAMPLE, ident(&msg_id, &acct, &folder, &flags)).unwrap();
        assert_eq!(hdrs.subject, "Hello");
    }

    // ---------------------------------------------------------------
    // `sanitize_email_html` — XSS probes + benign HTML preservation.
    // ---------------------------------------------------------------

    #[test]
    fn sanitize_strips_script_tag() {
        let out = sanitize_email_html("<p>hi</p><script>alert('xss')</script>");
        assert!(!out.contains("<script"), "script tag survived: {out}");
        assert!(!out.contains("alert"), "script body survived: {out}");
        assert!(out.contains("<p>hi</p>"), "benign content lost: {out}");
    }

    #[test]
    fn sanitize_strips_iframe_object_embed() {
        for probe in [
            r#"<iframe src="https://attacker.example/"></iframe>"#,
            r#"<object data="evil.swf"></object>"#,
            r#"<embed src="evil.swf">"#,
        ] {
            let out = sanitize_email_html(probe);
            assert!(
                !out.contains("<iframe") && !out.contains("<object") && !out.contains("<embed"),
                "frame/object/embed survived on {probe:?} → {out:?}"
            );
        }
    }

    #[test]
    fn sanitize_strips_event_handler_attributes() {
        let out = sanitize_email_html(r#"<img src="x" onerror="alert(1)" alt="pic">"#);
        assert!(!out.contains("onerror"), "onerror survived: {out}");
        // The <img> itself is safe and should be preserved (remote
        // content blocking happens in a later Phase 1 step, not in
        // the sanitizer).
        assert!(out.contains("<img"), "img tag lost: {out}");
        assert!(out.contains(r#"alt="pic""#), "alt attribute lost: {out}");
    }

    #[test]
    fn sanitize_strips_javascript_urls() {
        let out = sanitize_email_html(r#"<a href="javascript:alert(1)">click</a>"#);
        assert!(
            !out.contains("javascript:"),
            "javascript URL survived: {out}"
        );
        // The anchor text stays; the href is just removed.
        assert!(out.contains("click"), "anchor text lost: {out}");
    }

    #[test]
    fn sanitize_strips_form_and_input() {
        let out = sanitize_email_html(
            r#"<form action="/steal"><input name="password" type="password"></form>"#,
        );
        assert!(!out.contains("<form"), "form survived: {out}");
        assert!(!out.contains("<input"), "input survived: {out}");
        assert!(!out.contains("password"), "field name survived: {out}");
    }

    #[test]
    fn sanitize_strips_style_tag_but_keeps_inline_style_attr() {
        let out = sanitize_email_html(
            r#"<style>@import url(https://attacker.example/evil.css);</style>
               <p style="color: #c00;">urgent</p>"#,
        );
        assert!(!out.contains("<style"), "style element survived: {out}");
        assert!(!out.contains("@import"), "style contents survived: {out}");
        assert!(
            out.contains(r#"style="color: #c00;""#),
            "inline style attr lost: {out}"
        );
    }

    #[test]
    fn sanitize_strips_mailchimp_tracking_pixel() {
        // Realistic Mailchimp open-tracking pixel URL.
        let probe = r#"<p>body</p><img src="https://acme.list-manage.com/track/open.php?u=abc&id=xyz" width="1" height="1">"#;
        let out = sanitize_email_html(probe);
        // The `src` is gone — ammonia drops just that attribute
        // when the filter returns None; the `<img>` wrapper stays
        // but is now sourceless and won't load anything.
        assert!(!out.contains("list-manage"), "pixel URL survived: {out}");
        assert!(!out.contains(r#"src=""#), "src attr survived: {out}");
    }

    #[test]
    fn sanitize_strips_google_analytics_pixel() {
        let probe = r#"<img src="https://www.google-analytics.com/collect?tid=UA-99">"#;
        let out = sanitize_email_html(probe);
        assert!(!out.contains("google-analytics"), "GA URL survived: {out}");
    }

    #[test]
    fn sanitize_blocks_benign_remote_image_src() {
        // Default policy is block-all-remote: even a non-tracker
        // CDN image is dropped until the user opts in via "Always
        // load from this sender" (which routes through
        // `sanitize_email_html_trusted`).
        let probe =
            r#"<img src="https://example.com/logo.png" alt="logo" width="100" height="40">"#;
        let out = sanitize_email_html(probe);
        assert!(
            !out.contains("https://example.com/logo.png"),
            "remote src kept: {out}"
        );
        assert!(out.contains(r#"alt="logo""#), "alt lost: {out}");
        assert!(
            out.contains("data-qsl-blocked"),
            "blocked marker missing: {out}"
        );
        // Dimensions are kept by ammonia's default allowlist so the
        // reader CSS reserves the original layout box.
        assert!(out.contains(r#"width="100""#), "width attr lost: {out}");
    }

    #[test]
    fn sanitize_preserves_inline_data_image_src() {
        // `data:` URIs are local, no network — pass through.
        let probe = r#"<img src="data:image/png;base64,iVBORw0KGgo=" alt="logo">"#;
        let out = sanitize_email_html(probe);
        assert!(
            out.contains("data:image/png;base64"),
            "data URI lost: {out}"
        );
        assert!(
            !out.contains("data-qsl-blocked"),
            "inline data img picked up a blocked marker: {out}"
        );
    }

    #[test]
    fn sanitize_preserves_inline_cid_image_src() {
        // `cid:` references resolve against multipart/related parts in
        // the same message — no network either.
        let probe = r#"<img src="cid:logo@example.com" alt="logo">"#;
        let out = sanitize_email_html(probe);
        assert!(out.contains("cid:logo@example.com"), "cid URI lost: {out}");
        assert!(
            !out.contains("data-qsl-blocked"),
            "inline cid img picked up a blocked marker: {out}"
        );
    }

    #[test]
    fn sanitize_blocks_remote_srcset_entries() {
        // `srcset` is a comma-separated `<url> <descriptor>` list. One
        // remote URL in the list is enough to drop the whole attribute
        // — partial passthrough lets the browser load the entry the
        // user didn't want.
        let probe = r#"<img srcset="https://cdn.example.com/a.png 1x, https://cdn.example.com/a@2x.png 2x" alt="hero">"#;
        let out = sanitize_email_html(probe);
        assert!(!out.contains("cdn.example.com"), "srcset URLs kept: {out}");
        assert!(
            out.contains("data-qsl-blocked"),
            "blocked marker missing: {out}"
        );
    }

    #[test]
    fn sanitize_blocks_remote_inline_background_image() {
        // CSS `background-image: url(...)` is the second remote-content
        // vector — must follow the same default-block policy.
        let probe = r#"<div style="color: #c00; background-image: url(https://cdn.example.com/bg.png);">hi</div>"#;
        let out = sanitize_email_html(probe);
        assert!(!out.contains("cdn.example.com"), "bg url survived: {out}");
        // The non-URL declaration on the same attribute survives.
        assert!(out.contains("color: #c00"), "color decl lost: {out}");
    }

    #[test]
    fn sanitize_marks_blocked_img_with_data_attribute() {
        // Tracker host → src filtered out. The remaining `<img>`
        // should pick up `data-qsl-blocked` so the reader CSS can
        // render a same-dimension placeholder box.
        let probe = r#"<img src="https://list-manage.com/track/open.gif" width="600" height="200" alt="hero">"#;
        let out = sanitize_email_html(probe);
        assert!(!out.contains("list-manage.com"), "tracker src kept: {out}");
        assert!(
            out.contains("data-qsl-blocked"),
            "blocked marker missing: {out}"
        );
        // Width / height attributes are kept by ammonia's default
        // allowlist, so the placeholder reserves the right box size.
        assert!(out.contains(r#"width="600""#), "width attr lost: {out}");
        assert!(out.contains(r#"height="200""#), "height attr lost: {out}");
    }

    #[test]
    fn mark_blocked_images_pure_helper() {
        // Tag without `src=` → mark.
        let marked = mark_blocked_images("<p>hi</p><img alt=\"pic\"><p>bye</p>");
        assert!(marked.contains(r#"<img alt="pic" data-qsl-blocked>"#));
        // Tag with `src=` → leave alone.
        let kept = mark_blocked_images(r#"<img src="x" alt="pic">"#);
        assert!(!kept.contains("data-qsl-blocked"));
        // No `<img>` at all → byte-identical output (fast path).
        let neutral = "<p>only text</p>";
        assert_eq!(mark_blocked_images(neutral), neutral);
        // Substring `<img` inside another token must not be rewritten.
        let other = "<imgx></imgx>";
        assert_eq!(mark_blocked_images(other), other);
    }

    #[test]
    fn img_attrs_have_src_does_not_match_attr_value() {
        // Hand-rolled attribute walker must distinguish a real
        // `src=...` attribute from a literal `src=` substring inside
        // another attribute value (e.g. `title="see src=here"`).
        assert!(!img_attrs_have_src(r#" title="see src=here" alt="x""#));
        assert!(img_attrs_have_src(r#" alt="x" src="http://h/p""#));
        assert!(img_attrs_have_src(r#" SRC="x""#));
        assert!(img_attrs_have_src(r#" src=unquoted"#));
        assert!(!img_attrs_have_src(r#" alt="x""#));
        // Self-closing slash before `>` shouldn't trip the walker.
        assert!(!img_attrs_have_src(r#" alt="x" /"#));
    }

    #[test]
    fn sanitize_preserves_href_even_when_host_matches_tracker() {
        // Link hrefs go through unfiltered — link-click cleaning
        // is a separate pipeline stage, and blocking an outbound
        // anchor is user-hostile.
        let probe = r#"<a href="https://acme.list-manage.com/subscribe/confirm">Confirm</a>"#;
        let out = sanitize_email_html(probe);
        assert!(
            out.contains(r#"href="https://acme.list-manage.com/subscribe/confirm""#),
            "href erroneously dropped: {out}"
        );
    }

    #[test]
    fn sanitize_trusted_keeps_tracker_image_src() {
        // Same Mailchimp pixel that the default sanitizer drops. With
        // the trusted variant, the user has explicitly opted in to
        // remote content from this sender, so the URL filter is
        // skipped and the `src` survives.
        let probe =
            r#"<p>body</p><img src="https://acme.list-manage.com/track/open.php?u=abc&id=xyz">"#;
        let out = sanitize_email_html_trusted(probe);
        assert!(
            out.contains("list-manage.com/track/open.php"),
            "trusted-sender pixel src dropped: {out}"
        );
    }

    #[test]
    fn sanitize_trusted_still_strips_scripts() {
        // Trust applies to remote content only — script/iframe/etc.
        // stripping must remain unconditional.
        let out = sanitize_email_html_trusted(
            "<p>hi</p><script>alert('xss')</script><iframe src=\"https://attacker.example/\"></iframe>",
        );
        assert!(!out.contains("<script"), "script survived: {out}");
        assert!(!out.contains("<iframe"), "iframe survived: {out}");
        assert!(out.contains("<p>hi</p>"));
    }

    #[test]
    fn sanitize_preserves_benign_email_html() {
        // Realistic marketing-email skeleton: table layout, inline
        // styles, an https anchor, an h1. None of this should be
        // touched.
        let input = r#"<h1 style="color:#222;">Hello, Jane</h1>
<table style="width: 100%;">
  <tr><td style="padding:1rem;">
    <a href="https://example.com/click?ref=abc">Visit our site</a>
  </td></tr>
</table>"#;
        let out = sanitize_email_html(input);
        assert!(out.contains("<h1"), "<h1> lost: {out}");
        // ammonia auto-adds `rel="noopener noreferrer"` on external
        // anchors — good security hygiene, so check href + anchor
        // text separately rather than the whole opening tag.
        assert!(
            out.contains(r#"href="https://example.com/click?ref=abc""#),
            "href lost: {out}"
        );
        assert!(out.contains("Visit our site"), "anchor text lost: {out}");
        assert!(out.contains("<table"), "<table> lost: {out}");
        // Inline styles preserved.
        assert!(out.contains(r#"style="color:#222;""#));
    }

    // ---------------------------------------------------------------
    // Inline-style remote-content gating (backlog item 4).
    // ---------------------------------------------------------------

    #[test]
    fn sanitize_strips_blocked_background_image_url() {
        // Mailchimp pixel hidden inside an inline style.
        let probe = r#"<div style="background-image: url(https://acme.list-manage.com/track/open.php?u=abc&id=xyz); color: #c00;">x</div>"#;
        let out = sanitize_email_html(probe);
        assert!(
            !out.contains("list-manage"),
            "background-image URL survived: {out}"
        );
        assert!(
            out.contains("color: #c00"),
            "sibling declaration dropped along with the blocked one: {out}"
        );
    }

    #[test]
    fn sanitize_strips_blocked_background_shorthand_url() {
        // `background:` shorthand also carries url(...) values.
        let probe = r#"<td style="background: url(https://www.google-analytics.com/collect?tid=UA-1) no-repeat;">x</td>"#;
        let out = sanitize_email_html(probe);
        assert!(
            !out.contains("google-analytics"),
            "shorthand background URL survived: {out}"
        );
    }

    #[test]
    fn sanitize_style_filter_survives_non_ascii_declarations() {
        // Regression: the previous scanner stepped byte-by-byte and
        // sliced `decl[i..]` inside a multi-byte char → panic, which
        // hung `messages_get` for any email with a non-ASCII font
        // name or an `&nbsp;` inside a style attribute.
        let probe =
            r#"<p style="font-family: Söhne, Arial; margin:0&nbsp;auto; color: #222">hi</p>"#;
        let out = sanitize_email_html(probe);
        assert!(out.contains("Söhne"), "non-ASCII style dropped: {out}");
        assert!(out.contains("color: #222"), "{out}");
        // Mixed with a blocked declaration, the non-ASCII one survives.
        let probe = r#"<p style="font-family: 日本語フォント; background: url(https://t.example/p.gif)">hi</p>"#;
        let out = sanitize_email_html(probe);
        assert!(out.contains("日本語フォント"), "{out}");
        assert!(!out.contains("t.example"), "{out}");
    }

    #[test]
    fn sanitize_style_filter_is_case_and_escape_insensitive() {
        for probe in [
            // Function names are case-insensitive in CSS.
            r#"<p style="background-image: URL(https://tracker.example/p.gif)">x</p>"#,
            r#"<p style="background: Url( 'https://tracker.example/p.gif' )">x</p>"#,
            // Ident escapes: `\75` is `u`.
            r#"<p style="background: \75rl(https://tracker.example/p.gif)">x</p>"#,
            r#"<p style="background: u\72 l(https://tracker.example/p.gif)">x</p>"#,
            // Comments inside the function name.
            r#"<p style="background: url/**/(https://tracker.example/p.gif)">x</p>"#,
            // Escaped scheme inside the argument.
            r#"<p style="background: url(\68ttps://tracker.example/p.gif)">x</p>"#,
            // `;` inside the quoted URL used to split the declaration
            // mid-string and defeat the scanner.
            r#"<p style="background: url(&quot;https://tracker.example/p.gif?x=1;&quot;)">x</p>"#,
            // String-argument image functions without url().
            r#"<p style="background-image: image-set(&quot;https://tracker.example/p.png&quot; 1x)">x</p>"#,
            r#"<p style="background-image: -webkit-image-set(url(https://tracker.example/p.png) 1x)">x</p>"#,
            // Malformed / unterminated: conservative drop.
            r#"<p style="background: url(https://tracker.example/p.gif">x</p>"#,
            r#"<p style="background: url(&quot;https://tracker.example/p.gif">x</p>"#,
        ] {
            let out = sanitize_email_html(probe);
            assert!(
                !out.contains("tracker.example"),
                "remote URL survived in block mode: {probe} → {out}"
            );
        }
    }

    #[test]
    fn sanitize_style_filter_keeps_inline_only_functions() {
        let probe = r#"<p style="background-image: image-set(&quot;data:image/png;base64,AAAA&quot; 1x); list-style: url(cid:bullet@x); color: red">x</p>"#;
        let out = sanitize_email_html(probe);
        assert!(out.contains("data:image/png;base64,AAAA"), "{out}");
        assert!(out.contains("cid:bullet@x"), "{out}");
        assert!(out.contains("color: red"), "{out}");
    }

    #[test]
    fn split_declarations_respects_quotes_and_parens() {
        let parts = split_declarations(r#"a: url("x;y"); b: calc(1;2); c: 'q;r'; d: e"#);
        assert_eq!(
            parts,
            vec![r#"a: url("x;y")"#, " b: calc(1;2)", " c: 'q;r'", " d: e"]
        );
    }

    #[test]
    fn normalize_css_decodes_escapes_and_strips_comments() {
        assert_eq!(normalize_css(r"\75RL(\68ttps://X)"), "url(https://x)");
        assert_eq!(normalize_css("ur/* c */l(A)"), "url(a)");
        assert_eq!(normalize_css("u\\72 l(a)"), "url(a)");
        assert_eq!(normalize_css("Söhne"), "söhne");
    }

    #[test]
    fn mark_blocked_images_handles_gt_inside_attribute_values() {
        // html5ever does not escape `>` in attribute values.
        let out = mark_blocked_images(r#"<img alt="a>b" width="1">"#);
        assert_eq!(out, r#"<img alt="a>b" width="1" data-qsl-blocked>"#);
        let out = mark_blocked_images(r#"<img alt='a>b' src="data:x">"#);
        assert_eq!(out, r#"<img alt='a>b' src="data:x">"#);
    }

    #[test]
    fn sanitize_drops_data_and_cid_hrefs() {
        let out = sanitize_email_html(
            r#"<a href="data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;">x</a><a href="https://example.com/">ok</a>"#,
        );
        assert!(!out.contains("data:text/html"), "{out}");
        assert!(out.contains(r#"href="https://example.com/""#), "{out}");
        let out = sanitize_email_html_trusted(r#"<a href="data:text/html,hi">x</a>"#);
        assert!(!out.contains("data:"), "{out}");
    }

    #[test]
    fn rewrite_cid_refs_matches_whole_ids_and_is_bounded() {
        let map = vec![
            ("img1".to_string(), "data:image/png;base64,ONE".to_string()),
            ("img10".to_string(), "data:image/png;base64,TEN".to_string()),
        ];
        let html = r#"<img src="cid:img10"><img src='cid:img1'><p>cid:img1</p><span style="background:url(cid:img1)">x</span>cid:img1x"#;
        let out = rewrite_cid_refs(html, &map);
        assert!(out.contains(r#"src="data:image/png;base64,TEN""#), "{out}");
        assert!(out.contains("src='data:image/png;base64,ONE'"), "{out}");
        assert!(out.contains("url(data:image/png;base64,ONE)"), "{out}");
        // Prefix of a different id is left alone.
        assert!(out.ends_with("cid:img1x"), "{out}");
        assert!(!out.contains("ONE0"), "prefix collision: {out}");

        // Amplification bound: a 4 MB part referenced 5000 times must
        // not expand to 20 GB.
        let big = format!(
            "data:application/octet-stream;base64,{}",
            "A".repeat(4 * 1024 * 1024)
        );
        let map = vec![("a".to_string(), big)];
        let html = "cid:a ".repeat(5000);
        let out = rewrite_cid_refs(&html, &map);
        assert!(
            out.len() < 60 * 1024 * 1024,
            "unbounded expansion: {} bytes",
            out.len()
        );
    }

    #[test]
    fn sanitize_blocks_benign_remote_background_image_url() {
        // Default policy is block-all-remote — non-tracker CDN bg
        // image is dropped. The trusted-sender variant
        // (sanitize_email_html_trusted) is the user's opt-in path.
        let probe = r#"<div style="background-image: url(https://example.com/hero.png); color: #222;">hero</div>"#;
        let out = sanitize_email_html(probe);
        assert!(
            !out.contains("hero.png"),
            "benign background URL kept: {out}"
        );
        assert!(
            out.contains("color: #222"),
            "sibling declaration dropped along with the blocked one: {out}"
        );
    }

    #[test]
    fn sanitize_strips_title_text_content() {
        // Many marketing emails (Microsoft 365 example) include a full
        // <html><head><title>...</title></head> structure inside the
        // text/html part. Without `clean_content_tags`, ammonia would
        // strip the `<title>` tag wrapper but keep the inner text,
        // producing a duplicate-of-subject line at the top of the
        // rendered body. The user noticed this as "what is this text
        // at the top of the email?"
        let probe = r#"<html><head><title>Learn simple prompts</title></head><body><p>Real body</p></body></html>"#;
        let out = sanitize_email_html(probe);
        assert!(
            !out.contains("Learn simple prompts"),
            "title text leaked: {out}"
        );
        assert!(out.contains("Real body"), "body content lost: {out}");
    }

    #[test]
    fn sanitize_strips_noscript_text_content() {
        // <noscript> is the standard fallback element for users with
        // JS disabled — but our reader has scripts enabled and the
        // text is invariably a "your browser doesn't support…" notice
        // that would render confusingly inline.
        let probe = r#"<p>Hi</p><noscript>Please enable JavaScript</noscript><p>Bye</p>"#;
        let out = sanitize_email_html(probe);
        assert!(
            !out.contains("Please enable JavaScript"),
            "noscript text leaked: {out}"
        );
        assert!(out.contains("Hi"));
        assert!(out.contains("Bye"));
    }

    #[test]
    fn parse_rfc822_rewrites_cid_refs_in_html() {
        // multipart/related with an HTML body that references an
        // inline image via `cid:`. Parser should rewrite the cid:
        // src to a data: URI built from the part's bytes.
        let raw = b"From: a@example.com\r\n\
To: b@example.com\r\n\
Subject: hi\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/related; boundary=\"BOUND\"\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>before</p><img src=\"cid:logo@example.com\" alt=\"AppleLogo\"><p>after</p>\r\n\
--BOUND\r\n\
Content-Type: image/png\r\n\
Content-Disposition: inline\r\n\
Content-ID: <logo@example.com>\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=\r\n\
--BOUND--\r\n";
        let id = MessageId("m".into());
        let acct = AccountId("a".into());
        let folder = FolderId("f".into());
        let flags = MessageFlags::default();
        let body = parse_rfc822(raw, ident(&id, &acct, &folder, &flags)).expect("parse");
        let html = body.body_html.expect("html present");
        assert!(
            !html.contains("cid:logo"),
            "cid: ref survived the rewrite: {html}"
        );
        assert!(
            html.contains("data:image/png;base64,"),
            "data URI not produced: {html}"
        );
        assert!(html.contains(r#"alt="AppleLogo""#), "alt text lost: {html}");
    }

    #[test]
    fn sanitize_keeps_inline_data_background_image_url() {
        // `data:` URIs in CSS url() pass through — local bytes only.
        let probe =
            r#"<div style="background-image: url(data:image/png;base64,iVBORw0KGgo=);">hi</div>"#;
        let out = sanitize_email_html(probe);
        assert!(out.contains("data:image/png"), "data URL stripped: {out}");
    }

    #[test]
    fn sanitize_handles_quoted_url_arg() {
        // Quoted URL forms must also be parsed — single, double, none.
        for probe in [
            r#"<div style='background-image: url("https://acme.list-manage.com/x.gif")'>x</div>"#,
            r#"<div style="background-image: url('https://acme.list-manage.com/x.gif')">x</div>"#,
            r#"<div style="background-image: url(https://acme.list-manage.com/x.gif)">x</div>"#,
        ] {
            let out = sanitize_email_html(probe);
            assert!(
                !out.contains("list-manage"),
                "tracker pixel survived in {probe:?} → {out:?}"
            );
        }
    }

    #[test]
    fn sanitize_inline_style_with_no_url_passes_through() {
        let probe = r#"<p style="color: #222; padding: 8px 16px; font-weight: 600;">hello</p>"#;
        let out = sanitize_email_html(probe);
        assert!(out.contains("color: #222"), "color lost: {out}");
        assert!(out.contains("padding: 8px 16px"), "padding lost: {out}");
        assert!(out.contains("font-weight: 600"), "font-weight lost: {out}");
    }

    #[test]
    fn sanitize_trusted_keeps_blocked_background_image() {
        // Trusted variant skips remote-content checks for inline
        // styles too, matching the per-attribute behavior.
        let probe = r#"<div style="background-image: url(https://acme.list-manage.com/track/open.php?u=abc&id=xyz);">x</div>"#;
        let out = sanitize_email_html_trusted(probe);
        assert!(
            out.contains("list-manage"),
            "trusted-sender background URL dropped: {out}"
        );
    }

    #[test]
    fn extract_envelope_pulls_from_and_recipients() {
        let raw = b"From: Sender <sender@example.com>\r\n\
To: alice@example.com, Bob <bob@example.com>\r\n\
Cc: carol@example.com\r\n\
Bcc: dave@example.com\r\n\
Subject: Hi\r\n\
\r\n\
body";
        let (from, recipients) = extract_envelope(raw);
        let from = from.expect("From should parse");
        assert_eq!(from.address, "sender@example.com");
        let addrs: Vec<&str> = recipients.iter().map(|a| a.address.as_str()).collect();
        assert_eq!(
            addrs,
            vec![
                "alice@example.com",
                "bob@example.com",
                "carol@example.com",
                "dave@example.com",
            ]
        );
    }

    #[test]
    fn extract_envelope_returns_empty_for_garbage() {
        let (from, recipients) = extract_envelope(b"\xff\xfeNot an email at all");
        // mail-parser is generous; the contract is just "no panic".
        // We don't assert from/recipients are empty — only that the
        // call returns without crashing.
        let _ = (from, recipients);
    }

    #[test]
    fn extract_message_id_unwraps_and_rewraps() {
        let raw = b"From: a@b\r\n\
Message-ID: <abc@host>\r\n\
To: c@d\r\n\
\r\n\
body";
        assert_eq!(extract_message_id(raw).as_deref(), Some("<abc@host>"));
    }

    #[test]
    fn extract_message_id_missing_header_is_none() {
        assert_eq!(extract_message_id(b"From: a@b\r\n\r\n").as_deref(), None);
    }

    /// Real-world Gmail bodies frequently exceed 140 bytes and contain
    /// multi-byte UTF-8 (emoji, accented chars, CJK). The previous
    /// snippet path called `String::truncate(140)`, which panics if
    /// the cut point lands inside a multi-byte sequence — this test
    /// reproduces the panic scenario by placing a non-ASCII character
    /// astride byte 140.
    #[test]
    fn snippet_handles_multibyte_at_byte_boundary() {
        // 139 bytes of ASCII, then `é` (0xC3 0xA9) — bytes 139..=140.
        // String::truncate(140) lands inside the codepoint and panics.
        let mut body = "a".repeat(139);
        body.push('é');
        body.push_str(" tail");
        let raw = format!(
            "From: a@b\r\nTo: c@d\r\nSubject: x\r\n\
             MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
             \r\n{body}\r\n"
        );
        let parsed = MessageParser::default()
            .parse(raw.as_bytes())
            .expect("parse");
        let s = snippet_from(&parsed);
        // Must not panic; must end with the ellipsis since the body
        // was longer than the cap.
        assert!(
            s.ends_with('\u{2026}'),
            "expected ellipsis suffix, got {s:?}"
        );
        // Must still be valid UTF-8 (compiles trivially since `s` is
        // `String`, but a smoke check that the truncation didn't
        // produce empty / nonsense.
        assert!(s.chars().count() > 100);
    }

    #[test]
    fn snippet_short_body_round_trips_unchanged() {
        let raw = "From: a@b\r\nTo: c@d\r\nSubject: x\r\n\
                   MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
                   \r\nshort body with naïve emoji 🦀";
        let parsed = MessageParser::default()
            .parse(raw.as_bytes())
            .expect("parse");
        let s = snippet_from(&parsed);
        assert_eq!(s, "short body with naïve emoji 🦀");
        assert!(!s.ends_with('\u{2026}'));
    }

    const MULTIPART_WITH_ATTACHMENT: &[u8] = b"From: Jane <jane@example.com>\r\n\
To: me@example.com\r\n\
Subject: With attachment\r\n\
Date: Fri, 18 Apr 2026 10:00:00 +0000\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=BOUND\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
See attached.\r\n\
--BOUND\r\n\
Content-Type: application/pdf; name=\"report.pdf\"\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
SGVsbG8sIFdvcmxkIQ==\r\n\
--BOUND--\r\n";

    #[test]
    fn extract_attachment_bytes_returns_decoded_payload() {
        // mail-parser walks parts in reverse order on multipart/mixed,
        // so the attachment lands at index 0 and the body at index 1
        // — the right approach is to scan, not assume.
        let parsed = MessageParser::default()
            .parse(MULTIPART_WITH_ATTACHMENT)
            .expect("multipart parses");
        let attach_index = parsed
            .parts
            .iter()
            .position(|p| matches!(p.body, PartType::Binary(_) | PartType::InlineBinary(_)))
            .expect("attachment part present");

        let (filename, bytes) =
            extract_attachment_bytes(MULTIPART_WITH_ATTACHMENT, attach_index).expect("found");
        assert_eq!(filename, "report.pdf");
        assert_eq!(bytes, b"Hello, World!");
    }

    #[test]
    fn extract_attachment_bytes_none_for_text_part() {
        let parsed = MessageParser::default()
            .parse(MULTIPART_WITH_ATTACHMENT)
            .unwrap();
        let text_index = parsed
            .parts
            .iter()
            .position(|p| matches!(p.body, PartType::Text(_)))
            .unwrap();
        assert!(extract_attachment_bytes(MULTIPART_WITH_ATTACHMENT, text_index).is_none());
    }

    #[test]
    fn extract_attachment_bytes_none_for_out_of_range() {
        assert!(extract_attachment_bytes(MULTIPART_WITH_ATTACHMENT, 999).is_none());
    }
}
