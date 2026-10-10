// SPDX-License-Identifier: Apache-2.0

//! Reply / Reply-All / Forward helpers.
//!
//! Pure functions that build the pre-fill payload for the compose
//! pane from an opened message. No Dioxus / wasm dependencies — this
//! module is exercised by `cargo test` on the host so the
//! address-list manipulation, subject prefix logic, and quoted-body
//! formatting are covered without firing up a webview.
//!
//! Callers in `app.rs` wrap these into a `drafts_save` IPC call,
//! then `compose.set(...)` the returned `DraftId` so the existing
//! `ComposePane` hydration path picks it up via `drafts_load`. No
//! new state shape, no new IPC commands.

use chrono::{DateTime, Utc};
use qsl_ipc::{EmailAddress, MessageHeaders, RenderedMessage};

/// Add a `Re: ` prefix to a subject unless one is already present.
/// Matches the conventional case-insensitive check that mail clients
/// have used since RFC 5322 — `RE:`, `re:`, `Re :`, etc. all count
/// as already-prefixed.
pub fn reply_subject(original: &str) -> String {
    let trimmed = original.trim_start();
    if has_prefix(trimmed, "re:") {
        original.to_string()
    } else {
        format!("Re: {}", trimmed)
    }
}

/// Add a `Fwd: ` prefix to a subject unless one is already present.
/// Treats `Fw:` as equivalent to `Fwd:` (Outlook ships `Fw:` by
/// default on the wire) so a reforward doesn't double-prefix.
pub fn forward_subject(original: &str) -> String {
    let trimmed = original.trim_start();
    if has_prefix(trimmed, "fwd:") || has_prefix(trimmed, "fw:") {
        original.to_string()
    } else {
        format!("Fwd: {}", trimmed)
    }
}

fn has_prefix(s: &str, needle_lower: &str) -> bool {
    // `get` (not slicing) so a multibyte character straddling the
    // prefix boundary — e.g. a CJK subject — can't panic the UI.
    s.get(..needle_lower.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(needle_lower))
}

/// Build the To list for a reply. Prefers `Reply-To` over `From`
/// when present (RFC 5322 §3.6.2), falling back to `From`.
pub fn reply_to_recipients(headers: &MessageHeaders) -> Vec<EmailAddress> {
    if !headers.reply_to.is_empty() {
        return headers.reply_to.clone();
    }
    headers.from.clone()
}

/// Build the Cc list for a reply-all. Combines the original
/// message's `To` and `Cc`, then drops any address that matches
/// `account_email` (case-insensitive) so the user doesn't reply to
/// themselves. Also drops anyone already in the reply's `To`
/// (which is `reply_to_recipients`'s output) so the reply doesn't
/// duplicate the primary recipient.
pub fn reply_all_cc(
    headers: &MessageHeaders,
    primary_to: &[EmailAddress],
    account_email: &str,
) -> Vec<EmailAddress> {
    let mut seen: Vec<String> = primary_to
        .iter()
        .map(|a| a.address.to_lowercase())
        .collect();
    seen.push(account_email.to_lowercase());
    let mut out = Vec::new();
    for addr in headers.to.iter().chain(headers.cc.iter()) {
        let lower = addr.address.to_lowercase();
        if seen.iter().any(|a| a == &lower) {
            continue;
        }
        seen.push(lower);
        out.push(addr.clone());
    }
    out
}

/// Build the References chain for a reply per RFC 5322 §3.6.4:
/// the new message's `References` is the original's `References`
/// (or `In-Reply-To` if `References` is empty) plus the original's
/// `Message-ID`.
///
/// All values are kept angle-bracket-wrapped to match what
/// `qsl-mime` produces.
pub fn reply_references(headers: &MessageHeaders) -> Vec<String> {
    let mut chain: Vec<String> = headers.references.clone();
    if chain.is_empty() {
        if let Some(in_reply_to) = &headers.in_reply_to {
            chain.push(in_reply_to.clone());
        }
    }
    if let Some(mid) = &headers.rfc822_message_id {
        if !chain.iter().any(|r| r == mid) {
            chain.push(mid.clone());
        }
    }
    chain
}

/// Format an attribution line and quoted body for a reply. Plain
/// text only — markdown / HTML compose is Phase 2 Week 20+.
///
/// Output shape:
///
/// ```text
/// <blank line for the user's cursor>
/// <blank>
/// On 2026-04-27 14:32, Jane Doe <jane@example.com> wrote:
/// > original line 1
/// > original line 2
/// >
/// > original line 4 (after a blank line)
/// ```
pub fn quote_body_for_reply(
    rendered: &RenderedMessage,
    now_local_offset_seconds: Option<i32>,
) -> String {
    let attribution = attribution_line(&rendered.headers, now_local_offset_seconds);
    let quoted = match rendered.body_text.as_deref() {
        Some(text) if !text.trim().is_empty() => quote_lines(text),
        _ => "(no plaintext body — see HTML body in the original.)".to_string(),
    };
    format!("\n\n{attribution}\n{quoted}\n")
}

/// Forwarded message block. Includes a small header preamble so
/// the recipient sees who originally sent the message.
pub fn forward_body(rendered: &RenderedMessage) -> String {
    let h = &rendered.headers;
    let from = format_addrs(&h.from);
    let to = format_addrs(&h.to);
    let cc = format_addrs(&h.cc);
    let subject = h.subject.as_str();
    let date = h.date.format("%Y-%m-%d %H:%M %Z");

    let mut block = String::with_capacity(256);
    block.push_str("\n\n---------- Forwarded message ----------\n");
    block.push_str(&format!("From: {from}\n"));
    block.push_str(&format!("Date: {date}\n"));
    block.push_str(&format!("Subject: {subject}\n"));
    block.push_str(&format!("To: {to}\n"));
    if !cc.is_empty() {
        block.push_str(&format!("Cc: {cc}\n"));
    }
    block.push('\n');
    if let Some(text) = rendered.body_text.as_deref() {
        block.push_str(text);
    } else {
        block.push_str("(no plaintext body — see HTML body in the original.)");
    }
    block
}

fn attribution_line(headers: &MessageHeaders, _now_local_offset_seconds: Option<i32>) -> String {
    // We don't know the user's locale or timezone in the WASM bundle
    // beyond what `chrono::Local` can derive. Use the message's
    // declared timestamp in UTC for portability — a standard
    // attribution form like Mutt's, where the date is unambiguous.
    let primary = headers.from.first();
    let label = match primary {
        Some(EmailAddress {
            display_name: Some(name),
            address,
        }) if !name.is_empty() => format!("{name} <{address}>"),
        Some(EmailAddress { address, .. }) => address.clone(),
        None => "(unknown sender)".to_string(),
    };
    let date: DateTime<Utc> = headers.date;
    format!("On {} UTC, {} wrote:", date.format("%Y-%m-%d %H:%M"), label)
}

fn quote_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.matches('\n').count() * 2);
    let mut first = true;
    for line in text.lines() {
        if !first {
            out.push('\n');
        }
        first = false;
        if line.is_empty() {
            out.push('>');
        } else {
            out.push_str("> ");
            out.push_str(line);
        }
    }
    out
}

fn format_addrs(addrs: &[EmailAddress]) -> String {
    addrs
        .iter()
        .map(|a| match &a.display_name {
            Some(name) if !name.is_empty() => format!("{} <{}>", name, a.address),
            _ => a.address.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use qsl_ipc::{
        AccountId, Attachment, FolderId, MessageFlags, MessageHeaders, MessageId, RenderedMessage,
    };

    fn addr(name: Option<&str>, email: &str) -> EmailAddress {
        EmailAddress {
            display_name: name.map(str::to_string),
            address: email.to_string(),
        }
    }

    fn fixture(subject: &str, from: Vec<EmailAddress>) -> MessageHeaders {
        MessageHeaders {
            id: MessageId("m1".into()),
            account_id: AccountId("a1".into()),
            folder_id: FolderId("INBOX".into()),
            thread_id: None,
            rfc822_message_id: Some("<orig@example.com>".to_string()),
            subject: subject.to_string(),
            from,
            reply_to: vec![],
            to: vec![],
            cc: vec![],
            bcc: vec![],
            date: Utc.with_ymd_and_hms(2026, 4, 27, 14, 32, 0).unwrap(),
            flags: MessageFlags::default(),
            labels: vec![],
            snippet: String::new(),
            size: 0,
            has_attachments: false,
            in_reply_to: None,
            references: vec![],
        }
    }

    fn rendered_with_body(headers: MessageHeaders, body: Option<&str>) -> RenderedMessage {
        RenderedMessage {
            headers,
            sanitized_html: None,
            body_text: body.map(str::to_string),
            attachments: Vec::<Attachment>::new(),
            sender_is_trusted: false,
            remote_content_blocked: false,
        }
    }

    #[test]
    fn reply_subject_adds_re_when_absent() {
        assert_eq!(reply_subject("Hello"), "Re: Hello");
        assert_eq!(reply_subject("  Hello"), "Re: Hello");
    }

    #[test]
    fn reply_subject_keeps_existing_re_prefix() {
        assert_eq!(reply_subject("Re: Hello"), "Re: Hello");
        assert_eq!(reply_subject("RE: Hello"), "RE: Hello");
        assert_eq!(reply_subject("re: Hello"), "re: Hello");
        // Spaces preserved exactly when prefix matches.
        assert_eq!(reply_subject("  Re: Hello"), "  Re: Hello");
    }

    #[test]
    fn forward_subject_adds_fwd_when_absent_and_not_fw() {
        assert_eq!(forward_subject("Hello"), "Fwd: Hello");
        assert_eq!(forward_subject("Re: Hello"), "Fwd: Re: Hello");
    }

    #[test]
    fn forward_subject_treats_outlook_fw_prefix_as_already_forwarded() {
        assert_eq!(forward_subject("Fw: Hello"), "Fw: Hello");
        assert_eq!(forward_subject("Fwd: Hello"), "Fwd: Hello");
    }

    #[test]
    fn reply_to_recipients_prefers_reply_to_over_from() {
        let mut h = fixture("Hi", vec![addr(Some("From"), "from@example.com")]);
        h.reply_to = vec![addr(Some("Reply"), "reply@example.com")];
        let recipients = reply_to_recipients(&h);
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].address, "reply@example.com");
    }

    #[test]
    fn reply_to_recipients_falls_back_to_from() {
        let h = fixture("Hi", vec![addr(Some("From"), "from@example.com")]);
        let recipients = reply_to_recipients(&h);
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].address, "from@example.com");
    }

    #[test]
    fn reply_all_cc_excludes_self_and_primary() {
        let mut h = fixture("Hi", vec![addr(Some("Sender"), "sender@example.com")]);
        h.to = vec![
            addr(None, "me@example.com"),
            addr(None, "alice@example.com"),
        ];
        h.cc = vec![
            addr(None, "BOB@example.com"),
            addr(None, "sender@example.com"), // already covered by reply To
        ];
        let primary_to = reply_to_recipients(&h);
        let cc = reply_all_cc(&h, &primary_to, "me@example.com");
        let emails: Vec<&str> = cc.iter().map(|a| a.address.as_str()).collect();
        assert_eq!(emails, vec!["alice@example.com", "BOB@example.com"]);
    }

    #[test]
    fn reply_references_chain_appends_message_id() {
        let mut h = fixture("Hi", vec![]);
        h.references = vec!["<a@x>".into(), "<b@x>".into()];
        h.rfc822_message_id = Some("<c@x>".to_string());
        assert_eq!(
            reply_references(&h),
            vec!["<a@x>".to_string(), "<b@x>".into(), "<c@x>".into()]
        );
    }

    #[test]
    fn reply_references_falls_back_to_in_reply_to_when_chain_empty() {
        let mut h = fixture("Hi", vec![]);
        h.references = vec![];
        h.in_reply_to = Some("<parent@x>".to_string());
        h.rfc822_message_id = Some("<c@x>".to_string());
        assert_eq!(
            reply_references(&h),
            vec!["<parent@x>".to_string(), "<c@x>".into()]
        );
    }

    #[test]
    fn reply_references_handles_no_message_id() {
        let mut h = fixture("Hi", vec![]);
        h.references = vec!["<a@x>".into()];
        h.rfc822_message_id = None;
        assert_eq!(reply_references(&h), vec!["<a@x>".to_string()]);
    }

    #[test]
    fn quote_body_includes_attribution_and_quoted_lines() {
        let h = fixture("Hi", vec![addr(Some("Jane Doe"), "jane@example.com")]);
        let r = rendered_with_body(h, Some("line 1\nline 2\n\nline 4"));
        let quoted = quote_body_for_reply(&r, None);
        assert!(quoted.contains("Jane Doe <jane@example.com> wrote:"));
        assert!(quoted.contains("> line 1"));
        assert!(quoted.contains("> line 2"));
        assert!(quoted.contains("\n>\n> line 4"));
    }

    #[test]
    fn quote_body_handles_missing_plaintext() {
        let h = fixture("Hi", vec![addr(None, "from@example.com")]);
        let r = rendered_with_body(h, None);
        let quoted = quote_body_for_reply(&r, None);
        assert!(quoted.contains("(no plaintext body"));
    }

    #[test]
    fn forward_body_includes_header_block_and_original_body() {
        let mut h = fixture("Subj", vec![addr(Some("Sender"), "sender@example.com")]);
        h.to = vec![addr(None, "me@example.com")];
        h.cc = vec![addr(None, "alice@example.com")];
        let r = rendered_with_body(h, Some("body content"));
        let fwd = forward_body(&r);
        assert!(fwd.contains("---------- Forwarded message ----------"));
        assert!(fwd.contains("From: Sender <sender@example.com>"));
        assert!(fwd.contains("To: me@example.com"));
        assert!(fwd.contains("Cc: alice@example.com"));
        assert!(fwd.contains("Subject: Subj"));
        assert!(fwd.contains("body content"));
    }
}
