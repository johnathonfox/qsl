// SPDX-License-Identifier: Apache-2.0

//! High-level OAuth2 Authorization Code + PKCE flow orchestrator.
//!
//! Handwritten on top of `reqwest` instead of the `oauth2` crate — this
//! is two short HTTP interactions (authorize, exchange) with no runtime
//! state to track beyond one request/response pair each. A framework
//! would obscure more than it'd save.

use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::{distr::Alphanumeric, Rng};
use serde::Deserialize;
use tracing::{debug, info, warn};
use url::Url;

use crate::error::AuthError;
use crate::loopback::LoopbackRedirect;
use crate::pkce;
use crate::provider::OAuthProvider;
use crate::tokens::{AccessToken, RefreshToken, TokenSet};

/// Default time the flow waits on the browser / user before giving up.
pub const DEFAULT_FLOW_TIMEOUT: Duration = Duration::from_secs(300);

/// What the flow returns on success. Caller is responsible for persisting
/// the refresh token via [`crate::TokenVault`] and the access token
/// in-memory.
#[derive(Debug)]
pub struct FlowOutcome {
    pub tokens: TokenSet,
    /// Scopes the token was actually granted. Providers may downscope
    /// what we requested (or upscope for legacy reasons).
    pub granted_scopes: Vec<String>,
}

/// Run the full authorization flow against a provider.
///
/// 1. Bind a loopback listener on 127.0.0.1:<ephemeral>.
/// 2. Generate PKCE verifier + S256 challenge and a random CSRF `state`.
/// 3. Construct the authorization URL and open it in the user's browser.
/// 4. Wait for the browser to redirect back to the loopback. Verify the
///    `state` matches what we sent.
/// 5. Exchange the code + verifier for tokens at the provider's token
///    endpoint via HTTPS POST.
///
/// `email_hint` is passed to Google as `login_hint=` so the account
/// picker lands on the right mailbox. Providers that don't recognize
/// the parameter ignore it.
///
/// Delegates to [`run_loopback_flow_with`] using `webbrowser::open` as
/// the navigation step. Tests bypass the real browser by calling
/// `run_loopback_flow_with` directly with a fake opener.
pub async fn run_loopback_flow(
    provider: &dyn OAuthProvider,
    email_hint: Option<&str>,
) -> Result<FlowOutcome, AuthError> {
    run_loopback_flow_with(provider, email_hint, |url| {
        webbrowser::open(url)
            .map(|_| ())
            .map_err(|e| AuthError::Browser(format!("webbrowser::open: {e}")))
    })
    .await
}

/// Same as [`run_loopback_flow`] but with the browser-open step
/// injectable. Production code uses [`run_loopback_flow`]; integration
/// tests pass a closure that simulates the user clicking through the
/// authorization page (typically by spawning a `reqwest::get` against
/// the auth URL — the mock OAuth server then 302s back to the loopback
/// redirect URI).
///
/// `open_browser` is called with the fully-built authorization URL.
/// It must trigger something that eventually GETs the loopback
/// redirect URI; the rest of the flow blocks on that.
pub async fn run_loopback_flow_with<F>(
    provider: &dyn OAuthProvider,
    email_hint: Option<&str>,
    open_browser: F,
) -> Result<FlowOutcome, AuthError>
where
    F: FnOnce(&str) -> Result<(), AuthError>,
{
    let profile = provider.profile();
    let client_id = profile.require_client_id()?;

    let loopback = LoopbackRedirect::bind().await?;
    let redirect_uri = loopback.redirect_uri();

    let verifier = pkce::random_verifier(64);
    let challenge = pkce::sha256_challenge(&verifier);
    let state = random_state();

    let auth_url = build_authorize_url(
        profile.authorization_url,
        client_id,
        &redirect_uri,
        profile.scopes,
        &state,
        &challenge,
        email_hint,
    )?;
    // The auth_url carries one-time CSRF state + PKCE challenge as
    // query params. PKCE means the URL alone is useless without our
    // private code_verifier (which never leaves this process), so
    // it isn't a credential leak per se — but it's still cryptographic
    // material and bad hygiene to splat into shared logs. Log the
    // structured shape instead so debugging stays useful.
    info!(
        provider = profile.slug,
        scopes = profile.scopes.len(),
        has_email_hint = email_hint.is_some(),
        "opening browser for authorization"
    );
    debug!(
        provider = profile.slug,
        host = auth_url.host_str().unwrap_or("?"),
        "auth URL prepared (state + PKCE challenge redacted)"
    );

    open_browser(auth_url.as_str())?;

    let response = loopback.await_redirect(DEFAULT_FLOW_TIMEOUT).await?;
    if response.state != state {
        warn!("state mismatch on loopback redirect (CSRF?)");
        return Err(AuthError::AuthResponse(
            "state mismatch (possible CSRF)".into(),
        ));
    }

    let tokens = exchange_code(
        profile.token_url,
        client_id,
        profile.client_secret,
        &redirect_uri,
        &response.code,
        &verifier,
    )
    .await?;

    Ok(tokens)
}

#[allow(clippy::too_many_arguments)]
fn build_authorize_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[&str],
    state: &str,
    challenge: &str,
    email_hint: Option<&str>,
) -> Result<Url, AuthError> {
    let mut url = Url::parse(endpoint)?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("scope", &scopes.join(" "));
        q.append_pair("state", state);
        q.append_pair("code_challenge", challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("access_type", "offline"); // Google: request refresh token
        q.append_pair("prompt", "consent"); // always prompt so we reliably get refresh_token
        if let Some(hint) = email_hint {
            q.append_pair("login_hint", hint);
        }
    }
    Ok(url)
}

fn random_state() -> String {
    // 32 chars of url-safe alphanumerics ≈ 190 bits of entropy — plenty
    // to make CSRF forgery impossible in practice.
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    // All fields default — the error path (HTTP 400 with
    // `{"error": "...", "error_description": "..."}`) has neither
    // `access_token` nor `token_type`, and previously failing to
    // deserialize because `access_token` was required hid real
    // error responses behind a generic "JSON parse" message. Check
    // `error` first in the consumer, then unwrap `access_token`.
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

async fn exchange_code(
    endpoint: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<FlowOutcome, AuthError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| AuthError::Other(format!("reqwest build: {e}")))?;

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    // Confidential clients (Web-application-type Google OAuth, Microsoft
    // 365 ADAL, etc.) demand the secret on the token exchange even with
    // PKCE. Native clients (Desktop app, Fastmail) leave this empty and
    // skip the field entirely.
    if !client_secret.is_empty() {
        form.push(("client_secret", client_secret));
    }

    let resp = client
        .post(endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| AuthError::TokenExchange(format!("HTTP error: {e}")))?;

    let status = resp.status();
    // Buffer as text first so a non-JSON body (HTML error page, empty
    // response, truncated proxy response) surfaces its actual bytes in
    // the error message instead of the generic serde "error decoding
    // response body" that reqwest produces.
    let raw = resp
        .text()
        .await
        .map_err(|e| AuthError::TokenExchange(format!("HTTP body read: {e}")))?;

    let body: TokenResponse = serde_json::from_str(&raw).map_err(|e| {
        // Truncate so we don't paste a full HTML page into the error.
        let snippet: String = raw.chars().take(200).collect();
        AuthError::TokenExchange(format!(
            "JSON parse: {e} — HTTP {status}, body starts: {snippet:?}"
        ))
    })?;

    if !status.is_success() || body.error.is_some() {
        let msg = body
            .error_description
            .or(body.error)
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(AuthError::TokenExchange(msg));
    }

    if let Some(tt) = body.token_type.as_deref() {
        if !tt.eq_ignore_ascii_case("bearer") {
            warn!(token_type = tt, "non-bearer token_type on exchange");
        }
    }

    let access_token = body.access_token.ok_or_else(|| {
        AuthError::TokenExchange(
            "success response missing `access_token` field — server violated RFC 6749 §5.1".into(),
        )
    })?;

    let expires_at = body.expires_in.map(expires_at_from_now);
    let granted_scopes = body
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    Ok(FlowOutcome {
        tokens: TokenSet {
            access: AccessToken(access_token),
            refresh: body.refresh_token.map(RefreshToken),
            expires_at,
        },
        granted_scopes,
    })
}

/// `expires_in` is an unchecked value from the token endpoint.
/// `chrono::Duration::seconds` panics past ~i64::MAX/1000 and the
/// addition panics on overflow, so clamp to a sane window (0 .. 1 year)
/// instead of letting a hostile or buggy response abort the process.
pub(crate) fn expires_at_from_now(expires_in: i64) -> DateTime<Utc> {
    const MAX_SECS: i64 = 365 * 24 * 60 * 60;
    let secs = expires_in.clamp(0, MAX_SECS);
    Utc::now() + ChronoDuration::seconds(secs)
}

// Unused-but-kept for potential future nonce experiments. Keeps the
// base64 import relevant to the binary instead of the test module alone.
#[allow(dead_code)]
fn base64_url_nopad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_has_all_required_params() {
        let url = build_authorize_url(
            "https://example.test/auth",
            "client-xyz",
            "http://127.0.0.1:12345/",
            &["scope-a", "scope-b"],
            "state-abc",
            "challenge-def",
            Some("foo@bar"),
        )
        .unwrap();

        let params: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        assert_eq!(params.get("response_type").unwrap(), "code");
        assert_eq!(params.get("client_id").unwrap(), "client-xyz");
        assert_eq!(
            params.get("redirect_uri").unwrap(),
            "http://127.0.0.1:12345/"
        );
        assert_eq!(params.get("scope").unwrap(), "scope-a scope-b");
        assert_eq!(params.get("state").unwrap(), "state-abc");
        assert_eq!(params.get("code_challenge").unwrap(), "challenge-def");
        assert_eq!(params.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(params.get("login_hint").unwrap(), "foo@bar");
    }

    #[test]
    fn random_state_has_expected_length() {
        for _ in 0..10 {
            assert_eq!(random_state().len(), 32);
        }
    }
}
