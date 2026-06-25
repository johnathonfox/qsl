// SPDX-License-Identifier: Apache-2.0

//! Minimal HTTP server that catches the OAuth2 loopback redirect.
//!
//! The flow binds this server on `127.0.0.1:0` (ephemeral port), hands
//! the resulting URL to the provider as the redirect URI, waits for
//! exactly one connection, parses the request line for `?code=` and
//! `?state=`, writes a tiny HTML response so the user sees a friendly
//! "You can close this tab" page, and shuts down.
//!
//! Intentionally hand-rolled — a full HTTP framework is overkill for one
//! `GET /?code=…&state=…` handler and just drags dependencies along.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tracing::{debug, warn};
use url::Url;

use crate::error::AuthError;

/// What the loopback handler returns to the caller.
#[derive(Debug)]
pub struct LoopbackResult {
    /// The OAuth2 authorization `code`.
    pub code: String,
    /// The `state` parameter as received. The flow compares it against
    /// the value it originally sent.
    pub state: String,
}

/// A bound loopback listener. Hold on to it between generating the
/// authorization URL (which needs [`redirect_uri`]) and awaiting the
/// redirect (which calls [`await_redirect`]).
pub struct LoopbackRedirect {
    listener: TcpListener,
    port: u16,
}

impl LoopbackRedirect {
    /// Bind a listener on `127.0.0.1:<ephemeral>` and return it. The
    /// chosen port is reported via [`redirect_uri`].
    pub async fn bind() -> Result<Self, AuthError> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let listener = TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();
        debug!(port, "loopback redirect server listening");
        Ok(Self { listener, port })
    }

    /// The URL we'll hand to the OAuth2 provider as the redirect target.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    /// Ephemeral port the listener ended up on. Exposed for tests.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Accept exactly one incoming request, parse out `?code` and
    /// `?state`, send the success page, close.
    ///
    /// Times out after `wait` — if the user never completes the browser
    /// flow we don't want a background thread sitting there forever.
    pub async fn await_redirect(self, wait: Duration) -> Result<LoopbackResult, AuthError> {
        let accept = self.listener.accept();
        let (socket, peer) = timeout(wait, accept)
            .await
            .map_err(|_| AuthError::Cancelled)??;
        debug!(%peer, "loopback redirect received");

        handle_connection(socket).await
    }
}

async fn handle_connection(mut socket: tokio::net::TcpStream) -> Result<LoopbackResult, AuthError> {
    // The browser sends `GET /?code=…&state=… HTTP/1.1\r\n...`. We read
    // only enough bytes to find the end of the request line — a couple
    // of KB is plenty. Anything bigger is suspect; we cap the read.
    const MAX: usize = 8192;
    let mut buf = vec![0u8; MAX];
    let mut read = 0;

    loop {
        if read >= MAX {
            return Err(AuthError::AuthResponse(
                "loopback request exceeded 8 KB before end of request line".into(),
            ));
        }
        let n = socket.read(&mut buf[read..]).await?;
        if n == 0 {
            return Err(AuthError::AuthResponse(
                "loopback peer closed before sending the redirect".into(),
            ));
        }
        read += n;
        // We only need the request line, which ends at the first `\r\n`.
        if buf[..read].windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }

    let request = String::from_utf8_lossy(&buf[..read]).into_owned();
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| AuthError::AuthResponse("empty request on loopback".into()))?;
    let parsed = parse_request_line(first_line)?;

    // Send a minimal success page before closing. The user closes the
    // browser tab; the app takes over.
    let _ = socket.write_all(SUCCESS_RESPONSE).await;
    let _ = socket.shutdown().await;

    Ok(parsed)
}

fn parse_request_line(line: &str) -> Result<LoopbackResult, AuthError> {
    // Shape: `GET /path?code=…&state=… HTTP/1.1`.
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" {
        return Err(AuthError::AuthResponse(format!(
            "unexpected method {method} on loopback"
        )));
    }
    // Parse against an arbitrary absolute base so `url` can pull query params.
    let url = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|e| AuthError::AuthResponse(format!("bad target {target:?}: {e}")))?;
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            "error_description" => error_description = Some(v.into_owned()),
            _ => {}
        }
    }
    if let Some(kind) = error {
        let desc = error_description.unwrap_or_default();
        warn!(%kind, %desc, "provider returned authorization error");
        return Err(AuthError::AuthResponse(format!("{kind}: {desc}")));
    }
    match (code, state) {
        (Some(code), Some(state)) => Ok(LoopbackResult { code, state }),
        (_, None) => Err(AuthError::AuthResponse(
            "redirect missing `state` parameter".into(),
        )),
        (None, _) => Err(AuthError::AuthResponse(
            "redirect missing `code` parameter".into(),
        )),
    }
}

const SUCCESS_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Connection: close\r\n\
\r\n\
<!doctype html><html><head><title>QSL</title><style>\
body{font-family:system-ui,sans-serif;margin:4em auto;max-width:32em;color:#333}\
</style></head><body><h1>Authentication complete</h1>\
<p>You can close this tab and return to QSL.</p></body></html>";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_code_and_state() {
        let line = "GET /?code=abc&state=xyz HTTP/1.1";
        let r = parse_request_line(line).unwrap();
        assert_eq!(r.code, "abc");
        assert_eq!(r.state, "xyz");
    }

    #[test]
    fn parse_percent_decodes_values() {
        let line = "GET /?code=a%2Fb&state=s HTTP/1.1";
        let r = parse_request_line(line).unwrap();
        assert_eq!(r.code, "a/b");
    }

    #[test]
    fn parse_surfaces_error_param() {
        let line = "GET /?error=access_denied&error_description=user%20said%20no HTTP/1.1";
        let err = parse_request_line(line).unwrap_err();
        assert!(err.to_string().contains("access_denied"));
    }

    #[test]
    fn parse_rejects_missing_params() {
        assert!(parse_request_line("GET /?code=abc HTTP/1.1").is_err());
        assert!(parse_request_line("GET /?state=xyz HTTP/1.1").is_err());
    }

    #[test]
    fn parse_rejects_non_get() {
        assert!(parse_request_line("POST /?code=a&state=b HTTP/1.1").is_err());
    }

    #[tokio::test]
    async fn bind_returns_ephemeral_port() {
        let r = LoopbackRedirect::bind().await.unwrap();
        assert!(r.port() > 0);
        let uri = r.redirect_uri();
        assert!(uri.starts_with("http://127.0.0.1:"));
        assert!(uri.ends_with('/'));
    }
}
