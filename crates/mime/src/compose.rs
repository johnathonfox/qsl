// SPDX-License-Identifier: Apache-2.0

//! RFC 5322 message assembly for outgoing mail.
//!
//! Phase 2 Week 18 turns a [`Draft`] (the local compose-pane shape) plus
//! the user's `From` identity into a sendable byte stream. SMTP submission
//! (Week 18) and JMAP `EmailSubmission/set` (Week 19) both consume the
//! same RFC 5322 representation produced here.
//!
//! The Message-ID is **minted at build time** and returned alongside the
//! bytes so the desktop side can persist it on the outbox row. After
//! submission, the IDLE / EventSource push surfaces a server-side Sent
//! copy; matching by `Message-ID` is the reconciliation key called out
//! in `PHASE_2.md`'s open-questions section.
//!
//! Phase 2 Week 17's compose UX only writes `text/plain` bodies, so this
//! module ships a single-part `text/plain; charset=utf-8` builder and
//! defers the `multipart/alternative` (markdown → HTML) work to Week 20
//! where it lives next to the renderer's HTML sanitizer.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use mail_builder::{
    headers::{address::Address, message_id::MessageId, text::Text},
    MessageBuilder,
};
use rand::RngCore;
use thiserror::Error;

use qsl_core::{Draft, DraftAttachment, EmailAddress};

/// Successful build output. The Message-ID is angle-bracket-wrapped to
/// match the rest of the workspace's convention (`qsl-mime` parses
/// inbound headers with the brackets included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltMessage {
    /// RFC 5322-formatted message bytes, ready for SMTP `DATA` or JMAP
    /// `EmailSubmission/set`.
    pub bytes: Vec<u8>,
    /// `Message-ID` of the message we just built, in `<id@host>` form.
    /// Persist on the outbox row so the post-send Sent-folder copy can
    /// be reconciled by id.
    pub message_id: String,
}

/// Errors produced by [`build_rfc5322`].
#[derive(Debug, Error)]
pub enum ComposeError {
    /// All of `to`, `cc`, and `bcc` are empty — nothing to send to.
    /// SMTP servers reject `RCPT TO:<>` so we catch this at the
    /// builder boundary rather than letting the submission fail.
    #[error("draft has no recipients (To/Cc/Bcc all empty)")]
    NoRecipients,

    /// Couldn't extract a domain from the `From` address. Means the
    /// caller passed something that doesn't look like an email.
    #[error("from address has no domain: {0:?}")]
    InvalidFromAddress(String),

    /// A header-bound field (subject, address, display name,
    /// attachment filename, …) contained bytes that would let it
    /// escape its header line — CR, LF, NUL — or an address that
    /// isn't a plausible `local@domain` token. Refusing here closes
    /// the SMTP/MIME header-injection hole: a crafted inbound
    /// `Subject:` that decodes to `Hi\r\nBcc: evil@x` would otherwise
    /// ride a Reply straight into the outgoing header block and add
    /// the attacker as an envelope recipient.
    #[error("invalid {field} header value: {reason}")]
    InvalidHeader { field: String, reason: String },

    /// Attachment file couldn't be read at submission time. Path
    /// surfaced so the caller can DLQ the outbox row with a useful
    /// error rather than retrying forever against a missing file.
    #[error("attachment {filename} unreadable at {path}: {error}")]
    AttachmentRead {
        path: String,
        filename: String,
        error: String,
    },

    /// `mail-builder` write failure. Should be effectively unreachable
    /// since we write to `Vec<u8>`, but the API returns `io::Result`.
    #[error("mail-builder io: {0}")]
    Io(#[from] std::io::Error),
}

/// Assemble a sendable RFC 5322 message from the user's draft and their
/// `From` identity. Mints a `Message-ID` deterministically from the
/// `From` domain + a 64-bit random + nanosecond timestamp.
///
/// Headers set, in order:
///
/// 1. `Date` — auto-filled by mail-builder if not provided. We let it
///    use the system clock at build time.
/// 2. `Message-ID` — minted here as `<{rand_hex}.{nanos}.qsl@{host}>`.
///    `host` comes from the `From` domain so receivers can still
///    DKIM/SPF align even if the SMTP submission rewrites the envelope.
/// 3. `From`, `To`, `Cc`, `Bcc`, `Subject` — verbatim from the draft;
///    mail-builder handles RFC 2047 encoded-word for non-ASCII names
///    and subject lines.
/// 4. `In-Reply-To` and `References` — for replies. Mail-builder strips
///    the surrounding angle-brackets we store and re-wraps on output.
/// 5. `MIME-Version: 1.0` and a single `text/plain; charset=utf-8` body.
pub fn build_rfc5322(draft: &Draft, from: &EmailAddress) -> Result<BuiltMessage, ComposeError> {
    if draft.to.is_empty() && draft.cc.is_empty() && draft.bcc.is_empty() {
        return Err(ComposeError::NoRecipients);
    }

    // Header-injection guard. Every value that lands in the header
    // block is checked for line-breaking bytes *before* mail-builder
    // sees it; mail-builder's `Text` encoder passes a short ASCII
    // subject through verbatim (CR/LF included) and writes address
    // specs raw inside `<…>`, so it offers no protection on its own.
    validate_address("From", from)?;
    for a in &draft.to {
        validate_address("To", a)?;
    }
    for a in &draft.cc {
        validate_address("Cc", a)?;
    }
    for a in &draft.bcc {
        validate_address("Bcc", a)?;
    }
    validate_header_text("Subject", &draft.subject)?;
    if let Some(parent) = &draft.in_reply_to {
        validate_header_text("In-Reply-To", parent)?;
    }
    for r in &draft.references {
        validate_header_text("References", r)?;
    }
    for att in &draft.attachments {
        validate_header_text("Content-Disposition filename", &att.filename)?;
        validate_header_text("Content-Type", &att.mime_type)?;
    }

    let host = from
        .address
        .rsplit_once('@')
        .map(|(_, h)| h.to_string())
        .ok_or_else(|| ComposeError::InvalidFromAddress(from.address.clone()))?;

    // mail-builder expects the message-id without angle brackets; we
    // wrap on output (its `Header for MessageId` impl writes `<id>`).
    // Persist with brackets to match `MessageHeaders.rfc822_message_id`.
    let mid_inner = mint_message_id_inner(&host);
    let mid_wrapped = format!("<{mid_inner}>");

    let mut builder = MessageBuilder::new()
        .from(build_addr(from))
        .subject(Text::from(draft.subject.clone()))
        .message_id(MessageId::new(mid_inner))
        .text_body(draft.body.clone());

    if !draft.to.is_empty() {
        builder = builder.to(addrs_to_address(&draft.to));
    }
    if !draft.cc.is_empty() {
        builder = builder.cc(addrs_to_address(&draft.cc));
    }
    if !draft.bcc.is_empty() {
        builder = builder.bcc(addrs_to_address(&draft.bcc));
    }
    if let Some(parent) = &draft.in_reply_to {
        builder = builder.in_reply_to(MessageId::new(strip_brackets(parent).to_string()));
    }
    if !draft.references.is_empty() {
        let refs: Vec<String> = draft
            .references
            .iter()
            .map(|r| strip_brackets(r).to_string())
            .collect();
        builder = builder.references(MessageId::from(refs));
    }

    // Attachments. Each entry's bytes are read synchronously here —
    // this is called from a tokio worker (outbox drain or messages_send
    // command), so the blocking IO is fine on a worker thread. Inline
    // attachments use Content-Disposition: inline + a generated `cid`,
    // matching the existing `DraftAttachment.inline` convention.
    for att in &draft.attachments {
        let bytes = read_attachment_bytes(att)?;
        let filename = att.filename.clone();
        let mime = att.mime_type.clone();
        if att.inline {
            // CID is path-derived — stable across re-saves of the same
            // draft so a referenced `<img src="cid:...">` keeps working.
            let cid = inline_cid(&att.path);
            builder = builder.inline(mime, cid, bytes);
        } else {
            builder = builder.attachment(mime, filename, bytes);
        }
    }

    let bytes = builder.write_to_vec()?;
    Ok(BuiltMessage {
        bytes,
        message_id: mid_wrapped,
    })
}

fn read_attachment_bytes(att: &DraftAttachment) -> Result<Vec<u8>, ComposeError> {
    std::fs::read(Path::new(&att.path)).map_err(|e| ComposeError::AttachmentRead {
        path: att.path.clone(),
        filename: att.filename.clone(),
        error: e.to_string(),
    })
}

/// Stable CID derived from the attachment's filesystem path. Hashing
/// the path keeps it short and avoids whitespace / non-token characters
/// that confuse some MIME parsers, while still being deterministic so
/// the same draft re-builds with the same CID across saves.
fn inline_cid(path: &str) -> String {
    let mut buf = [0u8; 8];
    let mut h = 0u64;
    for (i, b) in path.bytes().enumerate() {
        h = h.wrapping_add((b as u64).wrapping_mul((i as u64).wrapping_add(31)));
    }
    buf.copy_from_slice(&h.to_be_bytes());
    format!("att-{:016x}@qsl.local", u64::from_be_bytes(buf))
}

/// Reject header text that could terminate its header line. CR, LF
/// and NUL are never legitimate inside a single header value we
/// author; everything else (including non-ASCII) is left for
/// mail-builder's RFC 2047 encoder.
fn validate_header_text(field: &str, value: &str) -> Result<(), ComposeError> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(ComposeError::InvalidHeader {
            field: field.to_string(),
            reason: "contains CR, LF, or NUL".to_string(),
        });
    }
    Ok(())
}

/// Validate one recipient / sender. The display name only has to be
/// line-safe (mail-builder quotes and RFC 2047-encodes it). The
/// addr-spec is written raw between angle brackets, so it must be a
/// single token: no whitespace, no control characters, no `<>`, no
/// list separators, and exactly one `@` with non-empty sides.
fn validate_address(field: &str, a: &EmailAddress) -> Result<(), ComposeError> {
    if let Some(name) = &a.display_name {
        validate_header_text(field, name)?;
    }
    let addr = a.address.as_str();
    let bad = |reason: &str| ComposeError::InvalidHeader {
        field: field.to_string(),
        reason: format!("address {addr:?} {reason}"),
    };
    if addr.is_empty() {
        return Err(bad("is empty"));
    }
    if addr
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';' | '"'))
    {
        return Err(bad("contains whitespace, control, or delimiter characters"));
    }
    match addr.split_once('@') {
        Some((local, domain))
            if !local.is_empty() && !domain.is_empty() && !domain.contains('@') =>
        {
            Ok(())
        }
        _ => Err(bad("is not of the form local@domain")),
    }
}

/// Remove the `Bcc:` header (including any folded continuation
/// lines) from an RFC 5322 byte stream, leaving everything else —
/// header order, line endings, body — byte-identical.
///
/// [`build_rfc5322`] keeps `Bcc:` in the bytes it returns so the copy
/// APPENDed to the user's Sent folder records who was blind-copied.
/// The SMTP `DATA` payload must *not* carry it (RFC 5322 §3.6.3): the
/// envelope `RCPT TO` list is what actually delivers to Bcc
/// recipients, and leaving the header in would disclose every Bcc
/// address to every To/Cc recipient. Callers submitting over SMTP
/// run the bytes through this first. JMAP servers strip Bcc at
/// `EmailSubmission` time themselves (RFC 8621 §7), so the JMAP path
/// submits the full bytes.
///
/// Only the header block (everything before the first blank line) is
/// inspected; the body is never touched. Input without a blank-line
/// separator is treated as all-header.
pub fn strip_bcc_header(raw: &[u8]) -> Vec<u8> {
    // Locate the header/body boundary. mail-builder always emits
    // CRLF; tolerate bare LF for bytes that came from elsewhere.
    let header_end = find_header_end(raw).unwrap_or(raw.len());
    let (headers, body) = raw.split_at(header_end);

    let mut out = Vec::with_capacity(raw.len());
    let mut skipping = false;
    let mut start = 0;
    while start < headers.len() {
        // One physical line, including its terminator.
        let end = headers[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| start + p + 1)
            .unwrap_or(headers.len());
        let line = &headers[start..end];
        let is_continuation = matches!(line.first(), Some(b' ' | b'\t'));
        if is_continuation {
            if !skipping {
                out.extend_from_slice(line);
            }
        } else {
            skipping = line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"bcc:");
            if !skipping {
                out.extend_from_slice(line);
            }
        }
        start = end;
    }
    out.extend_from_slice(body);
    out
}

/// Byte offset of the first empty line terminator that separates the
/// header block from the body — i.e. the index right after the
/// header block's final line terminator, so the returned split keeps
/// the blank line with the body.
fn find_header_end(raw: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < raw.len() {
        let line_end = raw[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| i + p + 1)?;
        let line = &raw[i..line_end];
        if line == b"\r\n" || line == b"\n" {
            return Some(i);
        }
        i = line_end;
    }
    None
}

fn build_addr(a: &EmailAddress) -> Address<'static> {
    Address::new_address(
        a.display_name.as_ref().filter(|s| !s.is_empty()).cloned(),
        a.address.clone(),
    )
}

fn addrs_to_address(addrs: &[EmailAddress]) -> Address<'static> {
    if addrs.len() == 1 {
        build_addr(&addrs[0])
    } else {
        Address::new_list(addrs.iter().map(build_addr).collect())
    }
}

fn strip_brackets(s: &str) -> &str {
    s.strip_prefix('<')
        .unwrap_or(s)
        .strip_suffix('>')
        .unwrap_or(s)
}

/// Mint the inner part of a Message-ID: 16 hex chars of randomness
/// plus a nanosecond timestamp, joined by `.qsl@<host>`. Random side
/// keeps the value globally unique even on a fast local clock; the
/// timestamp side keeps it monotonic per-process for ordering in
/// debug logs.
fn mint_message_id_inner(host: &str) -> String {
    let mut buf = [0u8; 8];
    rand::rng().fill_bytes(&mut buf);
    let entropy = u64::from_be_bytes(buf);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{entropy:016x}.{nanos}.qsl@{host}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use qsl_core::{AccountId, DraftBodyKind, DraftId};

    fn email(name: Option<&str>, addr: &str) -> EmailAddress {
        EmailAddress {
            display_name: name.map(str::to_string),
            address: addr.to_string(),
        }
    }

    fn draft(subject: &str, body: &str, to: Vec<EmailAddress>) -> Draft {
        let now = Utc::now();
        Draft {
            id: DraftId("d1".into()),
            account_id: AccountId("a1".into()),
            in_reply_to: None,
            references: vec![],
            to,
            cc: vec![],
            bcc: vec![],
            subject: subject.to_string(),
            body: body.to_string(),
            body_kind: DraftBodyKind::Plain,
            attachments: vec![],
            created_at: now,
            updated_at: now,
        }
    }

    fn body_str(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    #[test]
    fn no_recipients_is_an_error() {
        let d = draft("Hi", "body", vec![]);
        let from = email(Some("Me"), "me@example.com");
        let err = build_rfc5322(&d, &from).unwrap_err();
        assert!(matches!(err, ComposeError::NoRecipients));
    }

    #[test]
    fn invalid_from_is_an_error() {
        let d = draft("Hi", "body", vec![email(None, "to@example.com")]);
        let from = email(None, "no-at-sign");
        let err = build_rfc5322(&d, &from).unwrap_err();
        // The address validator runs first and rejects the shape;
        // either error is acceptable as long as the build refuses.
        assert!(matches!(
            err,
            ComposeError::InvalidFromAddress(_) | ComposeError::InvalidHeader { .. }
        ));
    }

    #[test]
    fn ascii_message_round_trip_has_required_headers() {
        let d = draft(
            "Hello",
            "Body line 1\nLine 2",
            vec![email(None, "to@example.com")],
        );
        let from = email(Some("Me"), "me@example.com");
        let built = build_rfc5322(&d, &from).unwrap();
        let s = body_str(&built.bytes);
        assert!(s.contains("From: \"Me\" <me@example.com>"), "got: {s}");
        assert!(s.contains("To: <to@example.com>") || s.contains("To: to@example.com"));
        assert!(s.contains("Subject: Hello"));
        assert!(s.contains("MIME-Version: 1.0"));
        assert!(s.contains("Date: "));
        assert!(s.contains("Message-ID: <"));
        assert!(s.contains("Body line 1"));
        // Body separator (header / body boundary) is CRLF CRLF.
        assert!(s.contains("\r\n\r\n"));
    }

    #[test]
    fn message_id_is_returned_with_brackets_and_uses_from_domain() {
        let d = draft("Hi", "body", vec![email(None, "to@example.com")]);
        let from = email(None, "user@qsl.test");
        let built = build_rfc5322(&d, &from).unwrap();
        assert!(built.message_id.starts_with('<'));
        assert!(built.message_id.ends_with('>'));
        assert!(
            built.message_id.contains("@qsl.test>"),
            "host should match from-domain: {}",
            built.message_id
        );
        // The wire format also includes the Message-ID, with brackets.
        let s = body_str(&built.bytes);
        assert!(s.contains(&format!("Message-ID: {}", built.message_id)));
    }

    #[test]
    fn message_ids_are_unique_across_calls() {
        let d = draft("Hi", "body", vec![email(None, "to@example.com")]);
        let from = email(None, "me@example.com");
        let a = build_rfc5322(&d, &from).unwrap().message_id;
        let b = build_rfc5322(&d, &from).unwrap().message_id;
        assert_ne!(a, b, "two builds produced the same Message-ID");
    }

    #[test]
    fn non_ascii_subject_is_rfc2047_encoded() {
        // Smart quotes + em dash + a non-Latin name. mail-builder
        // wraps in `=?utf-8?Q?...?=` or `=?utf-8?B?...?=` as
        // appropriate.
        let d = draft(
            "Quarterly review — Q1 2026 \u{201c}strategy\u{201d}",
            "body",
            vec![email(None, "to@example.com")],
        );
        let from = email(Some("Renée"), "me@example.com");
        let built = build_rfc5322(&d, &from).unwrap();
        let s = body_str(&built.bytes);
        // Subject line must be encoded — raw UTF-8 bytes shouldn't
        // appear in the wire form.
        let subject_line = s.lines().find(|l| l.starts_with("Subject:")).unwrap();
        assert!(
            subject_line.contains("=?utf-8?") || subject_line.contains("=?UTF-8?"),
            "subject not RFC 2047 encoded: {subject_line}"
        );
        assert!(
            !subject_line.contains("\u{2014}"),
            "raw em dash leaked into subject line: {subject_line}"
        );
        // Same for the From display name.
        let from_line = s.lines().find(|l| l.starts_with("From:")).unwrap();
        assert!(
            from_line.contains("=?utf-8?") || from_line.contains("=?UTF-8?"),
            "from name not RFC 2047 encoded: {from_line}"
        );
    }

    #[test]
    fn multiple_to_cc_bcc_are_emitted() {
        let mut d = draft(
            "Hi",
            "body",
            vec![
                email(Some("Alice"), "alice@example.com"),
                email(None, "bob@example.com"),
            ],
        );
        d.cc = vec![email(None, "carol@example.com")];
        d.bcc = vec![email(None, "dave@example.com")];
        let from = email(None, "me@example.com");
        let s = body_str(&build_rfc5322(&d, &from).unwrap().bytes);

        assert!(s.contains("alice@example.com"));
        assert!(s.contains("bob@example.com"));
        assert!(s
            .lines()
            .any(|l| l.starts_with("Cc:") && l.contains("carol@example.com")));
        assert!(s
            .lines()
            .any(|l| l.starts_with("Bcc:") && l.contains("dave@example.com")));

        // The SMTP wire form must drop Bcc while keeping every other
        // header and the body byte-for-byte.
        let built = build_rfc5322(&d, &from).unwrap();
        let wire = body_str(&strip_bcc_header(&built.bytes));
        assert!(!wire.contains("dave@example.com"), "Bcc leaked: {wire}");
        assert!(
            !wire.to_ascii_lowercase().contains("\nbcc:"),
            "Bcc header survived: {wire}"
        );
        assert!(wire.contains("carol@example.com"));
        assert!(wire.contains("Subject: Hi"));
        assert!(wire.contains("\r\n\r\nbody"), "body not preserved: {wire}");
        let original_lines = body_str(&built.bytes).lines().count();
        assert_eq!(wire.lines().count(), original_lines - 1);
    }

    #[test]
    fn strip_bcc_removes_folded_continuation_lines_only() {
        let raw = b"From: <a@x>\r\nBcc: <b@x>,\r\n <c@x>\r\nTo: <d@x>\r\n\r\nbcc: not a header\r\n";
        let out = strip_bcc_header(raw);
        assert_eq!(
            out,
            b"From: <a@x>\r\nTo: <d@x>\r\n\r\nbcc: not a header\r\n".to_vec()
        );
        // No Bcc at all: byte-identical.
        let plain = b"From: <a@x>\r\n\r\nhi\r\n";
        assert_eq!(strip_bcc_header(plain), plain.to_vec());
    }

    #[test]
    fn crlf_in_subject_is_rejected() {
        // The remote-triggerable shape: an inbound RFC 2047 subject
        // decoding to a CRLF that a Reply then carries forward.
        let d = draft(
            "Hi\r\nBcc: evil@attacker.test",
            "body",
            vec![email(None, "to@example.com")],
        );
        let from = email(None, "me@example.com");
        let err = build_rfc5322(&d, &from).unwrap_err();
        assert!(matches!(err, ComposeError::InvalidHeader { .. }), "{err:?}");
        let d = draft("Hi\nX: y", "body", vec![email(None, "to@example.com")]);
        assert!(build_rfc5322(&d, &from).is_err());
    }

    #[test]
    fn malformed_addresses_are_rejected() {
        let from = email(None, "me@example.com");
        for bad in [
            "a@b\r\nX: y",
            "a b@example.com",
            "<a@b>",
            "a@b,c@d",
            "no-at-sign",
            "@example.com",
            "user@",
            "",
        ] {
            let d = draft("Hi", "body", vec![email(None, bad)]);
            let err = build_rfc5322(&d, &from).unwrap_err();
            assert!(
                matches!(err, ComposeError::InvalidHeader { .. }),
                "{bad:?} accepted: {err:?}"
            );
        }
        // Display names are RFC 2047-encoded by mail-builder, so
        // anything line-safe is fine; CR/LF is not.
        let d = draft(
            "Hi",
            "body",
            vec![email(Some("Eve\r\nBcc: x@y"), "ok@example.com")],
        );
        assert!(build_rfc5322(&d, &from).is_err());
        let d = draft(
            "Hi",
            "body",
            vec![email(Some("Rénée \"R\" O'Neil"), "ok@example.com")],
        );
        assert!(build_rfc5322(&d, &from).is_ok());
    }

    #[test]
    fn reply_headers_strip_then_rewrap_brackets() {
        let mut d = draft("Re: Hi", "body", vec![email(None, "to@example.com")]);
        d.in_reply_to = Some("<parent@example.com>".to_string());
        d.references = vec!["<a@example.com>".into(), "<b@example.com>".into()];
        let from = email(None, "me@example.com");
        let s = body_str(&build_rfc5322(&d, &from).unwrap().bytes);

        let irt = s.lines().find(|l| l.starts_with("In-Reply-To:")).unwrap();
        assert!(irt.contains("<parent@example.com>"), "got: {irt}");
        // No double-wrapping (no `<<` anywhere in the line).
        assert!(!irt.contains("<<"), "double-wrapped: {irt}");

        let refs = s.lines().find(|l| l.starts_with("References:")).unwrap();
        assert!(
            refs.contains("<a@example.com>") && refs.contains("<b@example.com>"),
            "got: {refs}"
        );
        assert!(!refs.contains("<<"), "double-wrapped: {refs}");
    }

    #[test]
    fn attachments_appear_as_multipart_parts() {
        // Write a small file to a tempdir, reference it from the
        // draft, and check that build_rfc5322 emits a multipart message
        // whose bytes contain the attachment's filename + payload.
        let tmp = std::env::temp_dir().join("qsl-test-attachment.txt");
        std::fs::write(&tmp, b"hello attachment\n").unwrap();

        let mut d = draft("Hi", "body", vec![email(None, "to@example.com")]);
        d.attachments = vec![DraftAttachment {
            path: tmp.to_string_lossy().into_owned(),
            filename: "report.txt".to_string(),
            mime_type: "text/plain".to_string(),
            size_bytes: 17,
            inline: false,
        }];
        let from = email(None, "me@example.com");
        let s = body_str(&build_rfc5322(&d, &from).unwrap().bytes);

        // Multipart envelope shows up.
        assert!(
            s.lines()
                .any(|l| l.starts_with("Content-Type:") && l.contains("multipart/")),
            "missing multipart Content-Type in: {s}"
        );
        // Attachment part has a filename header.
        assert!(
            s.contains("filename=\"report.txt\"") || s.contains("filename=report.txt"),
            "missing attachment filename in: {s}"
        );
        // mail-builder picks the encoding (base64 for binary, qp for
        // ascii-ish text), so check for either form of the payload —
        // the literal bytes in qp/7bit, or the base64-encoded version
        // for binary mime types.
        let body_b64 = base64_encode(b"hello attachment\n");
        let qp = "hello attachment";
        assert!(
            s.contains(&body_b64) || s.contains(qp),
            "missing attachment payload (any encoding) in: {s}"
        );
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn missing_attachment_path_surfaces_attachment_read_error() {
        let mut d = draft("Hi", "body", vec![email(None, "to@example.com")]);
        d.attachments = vec![DraftAttachment {
            path: "/nonexistent/path/qsl-test-missing".into(),
            filename: "missing.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_bytes: 0,
            inline: false,
        }];
        let from = email(None, "me@example.com");
        let err = build_rfc5322(&d, &from).unwrap_err();
        assert!(
            matches!(err, ComposeError::AttachmentRead { ref filename, .. } if filename == "missing.bin"),
            "expected AttachmentRead error, got: {err:?}"
        );
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        STANDARD.encode(bytes)
    }

    #[test]
    fn body_uses_text_plain_utf8() {
        let d = draft("Hi", "Hello — world", vec![email(None, "to@example.com")]);
        let from = email(None, "me@example.com");
        let s = body_str(&build_rfc5322(&d, &from).unwrap().bytes);
        // Expect a Content-Type: text/plain; charset="utf-8" on the
        // body part (mail-builder may quote attribute values).
        assert!(
            s.lines().any(|l| l.starts_with("Content-Type:")
                && l.contains("text/plain")
                && l.to_lowercase().contains("utf-8")),
            "missing text/plain;charset=utf-8 header in: {s}"
        );
    }
}
