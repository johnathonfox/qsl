// SPDX-License-Identifier: Apache-2.0

//! IMAP IDLE watcher (RFC 2177).
//!
//! [`watch_folder`] runs an IDLE loop on a dedicated session and emits
//! a [`BackendEvent::FolderChanged`] every time the server pushes
//! untagged data for the SELECTed folder. The async-imap state
//! machine is roughly:
//!
//! ```text
//!   session.select(folder)
//!   loop {
//!       idle = session.idle()       // consumes session
//!       idle.init()                 // sends `IDLE`
//!       match idle.wait()? {
//!           NewData(resp) => emit FolderChanged
//!           Timeout      => 29-min refresh — re-IDLE
//!           ManualInterrupt => exit cleanly
//!       }
//!       session = idle.done()       // sends `DONE`, recovers session
//!   }
//! ```
//!
//! Reconnect on socket drop is **out of scope**: this function only
//! owns one session for one folder. Callers (the sync engine in
//! `qsl-sync`) detect the returned `Err` and build a fresh
//! session via [`crate::backend::dial_session`] before calling
//! `watch_folder` again.
//!
//! IDLE refresh follows RFC 2177's recommendation of "well below 30
//! minutes" — async-imap defaults to 29 minutes via
//! `Handle::wait()`. We let it use that default; the timeout fires
//! a `Timeout` response which we treat as "send DONE, send IDLE
//! again."

use async_imap::extensions::idle::IdleResponse;
use async_imap::Session;
use tokio::sync::mpsc;

use qsl_core::{AccountId, BackendEvent, FolderId, MailError};

use crate::backend::{StreamT, DIAL_STEP_TIMEOUT};

/// Run the IDLE loop on `session` against `folder` and forward each
/// activity notice to `tx` as [`BackendEvent::FolderChanged`].
///
/// Returns `Ok(())` when the receiver drops (caller is shutting down)
/// or async-imap signals `ManualInterrupt`. Returns `Err` on any
/// protocol or network failure — the caller is expected to recover
/// by dialing a fresh session and calling this again.
pub async fn watch_folder(
    mut session: Session<StreamT>,
    folder: FolderId,
    account: AccountId,
    tx: mpsc::Sender<BackendEvent>,
) -> Result<(), MailError> {
    // SELECT once. Re-SELECTing on every IDLE refresh would cost a
    // round-trip per cycle for no benefit; the server keeps the
    // mailbox selected across a DONE/IDLE pair.
    session
        .select(folder.backend_key(&account))
        .await
        .map_err(|e| MailError::Protocol(format!("SELECT {}: {e}", folder.0)))?;
    tracing::info!(
        account = %account.0,
        folder = %folder.0,
        "IMAP IDLE watcher started"
    );

    loop {
        let mut idle = session.idle();
        // `init` and `done` each await a tagged server response. On a
        // half-open socket they block until the OS gives up (possibly
        // never), so the watcher sits silent instead of reconnecting.
        // Bound them; `wait()` itself is already capped at 29 min.
        tokio::time::timeout(DIAL_STEP_TIMEOUT, idle.init())
            .await
            .map_err(|_| MailError::Network("IDLE init: timed out".into()))?
            .map_err(|e| MailError::Protocol(format!("IDLE init: {e}")))?;

        // The future returned by `wait()` borrows from `idle`, so it
        // has to be dropped before we can call `idle.done()`. Scope
        // the borrow tightly. Hold `_stop` for the future's lifetime
        // — dropping it triggers ManualInterrupt before the await
        // even gets a chance to read.
        let response = {
            let (wait_fut, _stop) = idle.wait();
            wait_fut.await
        }
        .map_err(|e| MailError::Protocol(format!("IDLE wait: {e}")))?;

        session = tokio::time::timeout(DIAL_STEP_TIMEOUT, idle.done())
            .await
            .map_err(|_| MailError::Network("IDLE done: timed out".into()))?
            .map_err(|e| MailError::Protocol(format!("IDLE done: {e}")))?;

        match response {
            IdleResponse::NewData(resp) => {
                tracing::debug!(
                    folder = %folder.0,
                    "IDLE got server data: {:?}",
                    resp.parsed()
                );
                if tx
                    .send(BackendEvent::FolderChanged {
                        folder: folder.clone(),
                    })
                    .await
                    .is_err()
                {
                    tracing::debug!(folder = %folder.0, "IDLE receiver dropped — exiting");
                    return Ok(());
                }
            }
            IdleResponse::Timeout => {
                // RFC 2177 refresh — just loop back to re-IDLE.
                tracing::debug!(folder = %folder.0, "IDLE 29-min refresh");
            }
            IdleResponse::ManualInterrupt => {
                tracing::debug!(folder = %folder.0, "IDLE manual interrupt — exiting");
                return Ok(());
            }
        }
    }
}
