// SPDX-License-Identifier: Apache-2.0

//! QSL SMTP submission adapter.
//!
//! Wraps `lettre` for submission on port 587 (STARTTLS) or 465 (implicit
//! TLS) with SASL XOAUTH2. STARTTLS downgrade is never permitted: when
//! [`TlsMode::Starttls`] is requested we use lettre's `starttls_relay`
//! constructor, which fails the handshake instead of falling back to
//! plaintext if the server doesn't advertise the STARTTLS extension.
//!
//! # Phase 2 Week 18 scope
//!
//! Gmail submission against `smtp.gmail.com`. The OAuth token comes
//! from the same `qsl-auth` token-vault path the IMAP backend uses;
//! the caller mints the token and hands it in. Token refresh on
//! expiry is the caller's responsibility — `submit` doesn't retry on
//! auth failure since that would mean making token-mint decisions
//! down here.
//!
//! Fastmail's JMAP `EmailSubmission/set` lives in `qsl-jmap-client`,
//! not here, so this crate is Gmail-only at present. The shape would
//! generalize to any XOAUTH2 SMTP host (e.g. Outlook 365) without
//! changes.
//!
//! # Why a thin wrapper rather than calling lettre directly
//!
//! - The desktop's outbox-drain operates on an opaque payload. Having
//!   one `submit(Submission<'_>) -> Result<(), SmtpError>` function
//!   keeps the drain dispatcher's match arm trivial.
//! - The error surface ([`SmtpError`]) collapses lettre's broad
//!   `Error` enum into the failure modes the outbox actually cares
//!   about: invalid input (don't retry), transport failure (retry),
//!   auth failure (retry only after token refresh), server rejection
//!   (DLQ).

use lettre::{
    address::Envelope,
    transport::smtp::{
        authentication::{Credentials, Mechanism},
        client::{Tls, TlsParameters},
        AsyncSmtpTransport,
    },
    Address, AsyncTransport, Tokio1Executor,
};
use thiserror::Error;

/// Encryption mode for the SMTP control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// Port 587 — start in plaintext, upgrade via STARTTLS. Downgrade
    /// is never permitted: if the server doesn't advertise STARTTLS,
    /// the handshake fails. This is the standard Gmail submission
    /// port.
    Starttls,
    /// Port 465 — implicit TLS from the first byte. Used by hosts
    /// that don't run STARTTLS or where STARTTLS is operationally
    /// disfavored.
    Implicit,
}

/// Inputs for one SMTP submission attempt.
#[derive(Debug, Clone)]
pub struct Submission<'a> {
    /// Hostname of the SMTP relay, e.g. `smtp.gmail.com`. Lettre's
    /// resolver / connection code picks an address — DNS failures
    /// surface through [`SmtpError::Transport`].
    pub host: &'a str,
    /// Port — typically 587 for STARTTLS or 465 for implicit TLS.
    pub port: u16,
    pub tls: TlsMode,
    /// SASL `authentication-identity` for XOAUTH2 — the user's email
    /// address, not the OAuth client id.
    pub username: &'a str,
    /// OAuth2 access token (raw, no `Bearer ` prefix). Lettre's
    /// XOAUTH2 mechanism formats it as
    /// `user={u}\x01auth=Bearer {t}\x01\x01`.
    pub oauth_token: &'a str,
    /// Envelope `MAIL FROM:<...>`. Usually the same as `username`,
    /// but we accept them separately so a user with multiple From
    /// aliases on one OAuth account can specify the alias here.
    pub from: &'a str,
    /// Envelope `RCPT TO:<...>` — the union of the message's To, Cc,
    /// and Bcc. Caller responsibility to flatten; the SMTP envelope
    /// doesn't distinguish, and including Bcc here is what makes
    /// blind-carbon-copy work without leaking addresses in the
    /// rendered headers.
    pub to: &'a [String],
    /// Pre-assembled RFC 5322 message bytes (CRLF-terminated lines).
    /// Produced by `qsl_mime::compose::build_rfc5322`.
    pub raw_bytes: &'a [u8],
}

/// Failure modes for [`submit`]. Mapped onto outbox drain semantics:
/// [`InvalidInput`] is don't-retry, [`Transport`] and [`Auth`] are
/// retry (the latter only after the caller's token refresh),
/// [`Rejected`] DLQs.
#[derive(Debug, Error)]
pub enum SmtpError {
    /// One of the addresses didn't parse, or the recipient list was
    /// empty. These are caller bugs — retrying won't help.
    #[error("invalid address: {0}")]
    InvalidInput(String),

    /// Failed to set up the SMTP transport (DNS, TCP, TLS handshake)
    /// or the SMTP greeting did not arrive. Recoverable next tick.
    #[error("smtp transport: {0}")]
    Transport(String),

    /// Server rejected authentication. Routed separately so the
    /// outbox drain can refresh the token before retrying.
    #[error("smtp authentication failed: {0}")]
    Auth(String),

    /// Server accepted envelope + auth but rejected the submission
    /// (5xx during DATA). The wrapped string is the server's
    /// response code + message.
    #[error("smtp rejected submission: {0}")]
    Rejected(String),
}

/// Submit one message via SMTP. Opens a fresh transport, sends, and
/// drops the connection.
///
/// Returns `Ok(())` only after the server has fully accepted the
/// `DATA` segment (250 response). Any earlier failure maps onto one
/// of the [`SmtpError`] variants per the documented retry semantics.
pub async fn submit(s: Submission<'_>) -> Result<(), SmtpError> {
    let from_addr: Address = s
        .from
        .parse()
        .map_err(|e| SmtpError::InvalidInput(format!("from address {:?}: {e}", s.from)))?;
    if s.to.is_empty() {
        return Err(SmtpError::InvalidInput(
            "recipient list is empty".to_string(),
        ));
    }
    let to_addrs: Vec<Address> =
        s.to.iter()
            .map(|raw| {
                raw.parse::<Address>()
                    .map_err(|e| SmtpError::InvalidInput(format!("to address {raw:?}: {e}")))
            })
            .collect::<Result<_, _>>()?;

    let envelope = Envelope::new(Some(from_addr), to_addrs)
        .map_err(|e| SmtpError::InvalidInput(format!("envelope: {e}")))?;

    let credentials = Credentials::new(s.username.to_string(), s.oauth_token.to_string());

    let transport = match s.tls {
        TlsMode::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(s.host)
            .map_err(|e| SmtpError::Transport(format!("build relay {}: {e}", s.host)))?
            .port(s.port)
            .credentials(credentials)
            .authentication(vec![Mechanism::Xoauth2])
            .build(),
        TlsMode::Implicit => {
            let tls_params = TlsParameters::new(s.host.to_string())
                .map_err(|e| SmtpError::Transport(format!("TLS params {}: {e}", s.host)))?;
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(s.host)
                .tls(Tls::Wrapper(tls_params))
                .port(s.port)
                .credentials(credentials)
                .authentication(vec![Mechanism::Xoauth2])
                .build()
        }
    };

    let to_count = s.to.len() as u64;
    let bytes = s.raw_bytes.len() as u64;
    qsl_telemetry::time_op!(
        target: "qsl::slow::smtp",
        limit_ms: qsl_telemetry::slow::limits::SMTP_SUBMIT_MS,
        op: "smtp_submit",
        fields: { host = %s.host, to_count = to_count, bytes = bytes },
        transport.send_raw(&envelope, s.raw_bytes)
    )
    .map_err(map_lettre_error)?;
    Ok(())
}

/// Translate lettre's broad `Error` into our outbox-aware enum.
/// Network / TLS / DNS failures are retryable; SMTP-level rejections
/// split between auth and content rejection; everything else falls
/// back to `Transport` so the outbox doesn't drop the message.
fn map_lettre_error(err: lettre::transport::smtp::Error) -> SmtpError {
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("authentication") || lower.contains("xoauth") {
        SmtpError::Auth(msg)
    } else if lower.contains("permanent") || lower.contains("rejected") {
        SmtpError::Rejected(msg)
    } else {
        SmtpError::Transport(msg)
    }
}

/// Default SMTP host + port for Gmail. Surfaced as a constant so the
/// IMAP backend's `submit_message` impl can reach for it without
/// duplicating the literal.
pub mod gmail {
    use super::TlsMode;
    pub const HOST: &str = "smtp.gmail.com";
    /// STARTTLS submission port (RFC 6409). Gmail also accepts 465
    /// (implicit TLS); we default to 587 because that's the
    /// historically standard submission port.
    pub const PORT_STARTTLS: u16 = 587;
    pub const PORT_IMPLICIT: u16 = 465;
    pub const TLS: TlsMode = TlsMode::Starttls;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn submit_rejects_empty_recipient_list() {
        let to: [String; 0] = [];
        let err = submit(Submission {
            host: "smtp.gmail.com",
            port: 587,
            tls: TlsMode::Starttls,
            username: "user@example.com",
            oauth_token: "ya29.faketoken",
            from: "user@example.com",
            to: &to,
            raw_bytes: b"From: user@example.com\r\nTo: x@example.com\r\nSubject: t\r\n\r\nbody\r\n",
        })
        .await
        .unwrap_err();
        assert!(
            matches!(err, SmtpError::InvalidInput(_)),
            "expected InvalidInput, got {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_rejects_malformed_from() {
        let to = ["someone@example.com".to_string()];
        let err = submit(Submission {
            host: "smtp.gmail.com",
            port: 587,
            tls: TlsMode::Starttls,
            username: "user@example.com",
            oauth_token: "ya29.faketoken",
            from: "not-an-address",
            to: &to,
            raw_bytes: b"...",
        })
        .await
        .unwrap_err();
        match err {
            SmtpError::InvalidInput(msg) => assert!(
                msg.contains("from address"),
                "expected from-address phrasing, got {msg}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submit_rejects_malformed_recipient() {
        let to = ["good@example.com".to_string(), "invalid".to_string()];
        let err = submit(Submission {
            host: "smtp.gmail.com",
            port: 587,
            tls: TlsMode::Starttls,
            username: "user@example.com",
            oauth_token: "ya29.faketoken",
            from: "user@example.com",
            to: &to,
            raw_bytes: b"...",
        })
        .await
        .unwrap_err();
        match err {
            SmtpError::InvalidInput(msg) => assert!(
                msg.contains("to address") && msg.contains("invalid"),
                "expected to-address phrasing, got {msg}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn gmail_constants_match_documented_values() {
        assert_eq!(gmail::HOST, "smtp.gmail.com");
        assert_eq!(gmail::PORT_STARTTLS, 587);
        assert_eq!(gmail::PORT_IMPLICIT, 465);
        assert_eq!(gmail::TLS, TlsMode::Starttls);
    }
}
