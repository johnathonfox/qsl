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
    // Build the ammonia builder on each call. Builder construction is
    // very cheap (empty HashSets + a few method calls); the real cost
    // is `.clean()`. Avoided OnceLock because ammonia::Builder doesn't
    // implement Clone, making a single cached instance for both the
    // trusted and blocking branches awkward to share.
    let mut builder = ammonia::Builder::default();
    builder.add_generic_attributes(["style"]);
    builder.add_url_schemes(["data", "cid"]);
    builder.add_clean_content_tags(["head", "title", "noscript"]);
    builder.rm_tags([
        "script", "iframe", "object", "embed", "form", "input", "button", "textarea", "select",
        "style", "link",
    ]);
    if block_remote {
        builder.attribute_filter(move |_element, attribute, value| -> Option<Cow<'_, str>> {
            match attribute {
                "src" | "background" | "poster" if !url_is_inline_safe(value) => None,
                "srcset" if !srcset_is_inline_safe(value) => None,
                "style" => Some(Cow::Owned(filter_inline_style(value))),
                _ => Some(Cow::Borrowed(value)),
            }
        });
    } else {
        builder.attribute_filter(|_element, _attribute, value| Some(Cow::Borrowed(value)));
    }
    let cleaned = builder.clean(raw_html).to_string();
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
        // Find the closing `>` of this tag.
        let Some(end_rel) = html[after_img..].find('>') else {
            // Unterminated tag — bail: copy the rest verbatim.
            out.push_str(&html[cursor..]);
            return out;
        };
        let tag_end = after_img + end_rel;
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
    if prefix.starts_with("data:") {
        return true;
    }
    // `cid:` is allowed when it references a bare content-id
    // (no network-path prefix like `//` which would make it a
    // protocol-relative URL). Content-ids naturally include `@`
    // and `/` as part of their value (RFC 5322 msg-id syntax).
    prefix.starts_with("cid:") && !trimmed[4..].starts_with("//")
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
    // Fast path: scan once for declarations carrying remote `url(...)`
    // tokens. If nothing matches, return the input verbatim — this
    // preserves exact whitespace + trailing-semicolon shape, which
    // keeps the common no-image-styling case byte-identical to the
    // input and avoids spurious diffs in existing sanitizer tests.
    let mut any_blocked = false;
    let kept: Vec<&str> = style
        .split(';')
        .filter_map(|decl| {
            let trimmed = decl.trim();
            if trimmed.is_empty() {
                return None;
            }
            for url in css_url_tokens(trimmed) {
                if !url_is_inline_safe(url) {
                    any_blocked = true;
                    return None;
                }
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

/// Yield each `url(...)` argument inside a CSS declaration. Strips
/// surrounding whitespace and matched single / double quotes.
/// Returns an empty iterator when no `url(` token is present.
fn css_url_tokens(decl: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = decl.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if !decl[i..].starts_with("url(") {
            i += 1;
            continue;
        }
        i += 4;
        // Skip leading whitespace inside the parens.
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        // Optional surrounding quote.
        let quote = match bytes.get(i) {
            Some(&b'"') => {
                i += 1;
                Some(b'"')
            }
            Some(&b'\'') => {
                i += 1;
                Some(b'\'')
            }
            _ => None,
        };
        let start = i;
        let end = match quote {
            Some(q) => bytes[i..].iter().position(|&b| b == q).map(|off| i + off),
            None => bytes[i..]
                .iter()
                .position(|&b| b == b')')
                .map(|off| i + off),
        };
        let Some(end) = end else { return out };
        let slice = decl[start..end].trim_end();
        if !slice.is_empty() {
            out.push(slice);
        }
        // Advance past the closing quote (if any) and the closing `)`.
        i = end + 1;
        if quote.is_some() {
            // Skip whitespace and the closing ')'.
            while i < bytes.len() && bytes[i] != b')' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
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
/// carbon-copy actually work); the SMTP server doesn't surface Bcc
/// to other recipients.
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

fn headers_from(parsed: &Message<'_>, identity: &MessageIdentity<'_>) -> MessageHeaders {
    let subject = parsed.subject().unwrap_or_default().to_string();
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
        address: a.address.as_deref().unwrap_or_default().to_string(),
        display_name: a.name.as_deref().map(str::to_string),
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
    if cid_map.is_empty() {
        return html.to_string();
    }
    let mut out = html.to_string();
    for (cid, data_uri) in cid_map {
        let bare = cid.trim_start_matches('<').trim_end_matches('>');
        if bare.is_empty() {
            continue;
        }
        // Most-specific replacement: the cid as-it-appears in HTML.
        // Quoted (`src="cid:foo"`), unquoted, and CSS `url(cid:foo)`
        // forms all share this `cid:<id>` substring, so one
        // replacement covers all three.
        out = out.replace(&format!("cid:{bare}"), data_uri);
    }
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
