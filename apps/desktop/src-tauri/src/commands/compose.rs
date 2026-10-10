// SPDX-License-Identifier: Apache-2.0

//! `compose_*` Tauri commands. Currently just `compose_pick_attachments`,
//! the OS-native file picker that backs the compose pane's "Attach"
//! button.
//!
//! The picker runs on a Tauri async-runtime task (rfd's `AsyncFileDialog`
//! is awaited there) so it doesn't block the UI tokio executor. Each
//! selected file is stat'd to fill in `size_bytes` and the MIME type is
//! guessed from extension via `mime_guess`. The path is stored as a
//! UTF-8 string; non-UTF-8 paths (rare on modern Linux/macOS, possible
//! on legacy Windows) are skipped with a warn-log rather than failing
//! the whole pick — the user just won't see them in the result list.

use std::path::PathBuf;

use qsl_core::DraftAttachment;
use qsl_ipc::{IpcError, IpcErrorKind, IpcResult};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct ComposePickAttachmentsInput {
    /// Optional title for the file dialog. UI passes "Attach files" but
    /// callers can override (e.g. a future "Attach signature image"
    /// flow). `None` falls back to the OS default.
    #[serde(default)]
    pub title: Option<String>,
}

/// `compose_pick_attachments` — open a multi-select native file picker
/// and return one [`DraftAttachment`] per chosen file. Cancelling the
/// dialog returns an empty `Vec` (NOT an error). Files whose path
/// can't be expressed as UTF-8 are dropped with a warn-log; everything
/// else round-trips through the picker → tokio metadata stat → UI
/// signal pipeline.
///
/// Inline flag is always `false` here — inline images come from a
/// separate "Insert image" affordance (not yet wired) so the picker
/// can stay single-purpose.
#[tauri::command]
pub async fn compose_pick_attachments(
    state: tauri::State<'_, crate::state::AppState>,
    input: ComposePickAttachmentsInput,
) -> IpcResult<Vec<DraftAttachment>> {
    tracing::debug!("ipc: compose_pick_attachments");
    let title = input.title.unwrap_or_else(|| "Attach files".to_string());

    let paths: Vec<PathBuf> = rfd::AsyncFileDialog::new()
        .set_title(&title)
        .pick_files()
        .await
        .map(|handles| {
            handles
                .into_iter()
                .map(|h| h.path().to_path_buf())
                .collect()
        })
        .unwrap_or_default();

    let mut attachments = Vec::with_capacity(paths.len());
    for path in paths {
        let Some(path_str) = path.to_str().map(str::to_string) else {
            tracing::warn!(path = ?path, "compose_pick_attachments: skipped non-UTF-8 path");
            continue;
        };
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| path_str.clone());
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) => {
                return Err(IpcError::new(
                    IpcErrorKind::Internal,
                    format!("compose_pick_attachments: stat {filename}: {e}"),
                ));
            }
        };
        let mime_type = mime_guess::from_path(&path)
            .first_or_octet_stream()
            .to_string();
        // Record the user's choice so `drafts_save` can tell a
        // picker-selected path from one invented by the webview.
        state
            .picked_attachment_paths
            .lock()
            .await
            .insert(PathBuf::from(&path_str));
        attachments.push(DraftAttachment {
            path: path_str,
            filename,
            mime_type,
            size_bytes: metadata.len(),
            inline: false,
        });
    }

    tracing::info!(count = attachments.len(), "compose_pick_attachments");
    Ok(attachments)
}
