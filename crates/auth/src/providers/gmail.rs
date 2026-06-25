// SPDX-License-Identifier: Apache-2.0

//! Gmail / Google Workspace OAuth2 profile.
//!
//! Scopes: full read/write/send via `https://mail.google.com/`. That's
//! the umbrella Gmail scope for IMAP + SMTP with XOAUTH2 — narrower
//! `gmail.readonly` / `gmail.send` exist but don't cover our full range
//! of sync operations.
//!
//! Endpoints come from Google's OpenID Connect Discovery document
//! <https://accounts.google.com/.well-known/openid-configuration>; we
//! hardcode them rather than fetch at runtime because they've been stable
//! for years.

use std::sync::LazyLock;

use crate::provider::{OAuthProvider, ProviderKind, ProviderProfile};

macro_rules! env_or_die {
    ($name:literal) => {
        match option_env!($name) {
            Some(v) => v,
            None => panic!(
                "qsl-auth: {} not set at build time. \
                 Create a .env file or set the environment variable before building.",
                $name
            ),
        }
    };
}

pub static GMAIL: GmailProvider = GmailProvider;

pub struct GmailProvider;

impl OAuthProvider for GmailProvider {
    fn profile(&self) -> &'static ProviderProfile {
        &PROFILE
    }
}

static PROFILE: LazyLock<ProviderProfile> = LazyLock::new(|| ProviderProfile {
    name: "Gmail",
    slug: "gmail",
    client_id: env_or_die!("QSL_GMAIL_CLIENT_ID"),
    // Empty for Desktop-app-type Google OAuth 2.0 Client IDs (PKCE-
    // only flow). Populate via `QSL_GMAIL_CLIENT_SECRET` at
    // build time if the client is Web-application-type — those
    // demand the secret on the token exchange even with PKCE, and
    // Google will return `client_secret is missing` without it.
    client_secret: env_or_die!("QSL_GMAIL_CLIENT_SECRET"),
    authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    revocation_url: "https://oauth2.googleapis.com/revoke",
    scopes: &["https://mail.google.com/"],
    kind: ProviderKind::ImapSmtp,
});
