// SPDX-License-Identifier: Apache-2.0

//! Fastmail OAuth2 profile (JMAP backend).
//!
//! Fastmail's OAuth2 endpoints live under `api.fastmail.com/oauth`; the
//! JMAP session + core scopes cover read, write, and submission.
//! Reference: <https://www.fastmail.com/dev/oauth/>.

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

pub static FASTMAIL: FastmailProvider = FastmailProvider;

pub struct FastmailProvider;

impl OAuthProvider for FastmailProvider {
    fn profile(&self) -> &'static ProviderProfile {
        &PROFILE
    }
}

static PROFILE: LazyLock<ProviderProfile> = LazyLock::new(|| ProviderProfile {
    name: "Fastmail",
    slug: "fastmail",
    client_id: env_or_die!("QSL_FASTMAIL_CLIENT_ID"),
    // Fastmail's native-app OAuth is PKCE-only (no secret). Env-var
    // hook kept for future-proofing in case they add a confidential
    // mode.
    client_secret: env_or_die!("QSL_FASTMAIL_CLIENT_SECRET"),
    authorization_url: "https://api.fastmail.com/oauth/authorize",
    token_url: "https://api.fastmail.com/oauth/refresh",
    // Fastmail's revocation endpoint isn't published as a stable static
    // URL — RFC 7009 says clients should discover it via the OAuth
    // metadata document, which Fastmail surfaces through the JMAP
    // session response rather than a `.well-known` doc. Empty here
    // means `accounts_remove` falls back to local-only cleanup
    // (keychain delete + DB cascade) for Fastmail accounts. A
    // follow-up can wire JMAP-session-driven revocation.
    revocation_url: "",
    scopes: &[
        "https://www.fastmail.com/dev/protocol-imap",
        "https://www.fastmail.com/dev/protocol-smtp",
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:mail",
        "urn:ietf:params:jmap:submission",
    ],
    kind: ProviderKind::Jmap,
});
