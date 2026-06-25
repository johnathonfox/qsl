// SPDX-License-Identifier: Apache-2.0

//! On-disk blob store for raw `.eml` message bodies.
//!
//! Layout (per `DESIGN.md` §4.4):
//!
//! ```text
//! <root>/<account_id>/<folder_id>/<message_id>.eml.zst   # default, compressed
//! <root>/<account_id>/<folder_id>/<message_id>.eml       # if Compression::None
//! ```
//!
//! Compression defaults to zstd (level 3) so every write goes through it
//! unless the caller explicitly asks for `Compression::None`. The `.zst`
//! extension distinguishes compressed blobs on disk for manual inspection
//! with `zstdcat`.
//!
//! Path components are percent-encoded for characters that are reserved on
//! Windows (`<>:"/\|?*` plus control chars) so IMAP message IDs like
//! `1712345:42` don't trip `ERROR_INVALID_PARAMETER`. The encoding is
//! reversible, but callers should treat the on-disk filename as opaque —
//! use the returned [`PathBuf`] from [`BlobStore::put`] rather than
//! reconstructing one.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use qsl_core::{AccountId, FolderId, MessageId, StorageError};

/// The zstd compression level used by default.
///
/// Level 3 is zstd's default — good ratio and fast enough that it doesn't
/// dominate a message fetch.
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// How to lay bytes down on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compression {
    /// zstd compression at [`DEFAULT_COMPRESSION_LEVEL`]. Default for new
    /// blob stores.
    #[default]
    Zstd,
    /// No compression; raw RFC 822 bytes. Useful for tests and debug
    /// inspection.
    None,
}

/// On-disk blob store rooted at a user-supplied directory.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
    compression: Compression,
}

impl BlobStore {
    /// Construct a store rooted at `root` with the default compression
    /// (zstd). The root directory is created lazily on first write.
    pub fn new<P: Into<PathBuf>>(root: P) -> Self {
        Self {
            root: root.into(),
            compression: Compression::default(),
        }
    }

    /// Swap the compression mode. Intended for test fixtures and the
    /// eventual `Settings` toggle.
    pub fn with_compression(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }

    /// Root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Compression mode currently in effect.
    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Write a raw RFC 822 message body. Overwrites any existing blob for
    /// the same key.
    pub async fn put(
        &self,
        account: &AccountId,
        folder: &FolderId,
        message: &MessageId,
        rfc822: &[u8],
    ) -> Result<PathBuf, StorageError> {
        let path = self.path_for(account, folder, message);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(err_io)?;
        }

        let compression = self.compression;
        let rfc822 = rfc822.to_vec();
        let write_path = path.clone();
        tokio::task::spawn_blocking(move || write_blob(&write_path, &rfc822, compression))
            .await
            .map_err(err_join)??;

        Ok(path)
    }

    /// Read a blob back as raw RFC 822 bytes. Returns
    /// [`StorageError::NotFound`] if the blob is missing.
    pub async fn get(
        &self,
        account: &AccountId,
        folder: &FolderId,
        message: &MessageId,
    ) -> Result<Vec<u8>, StorageError> {
        let path = self.path_for(account, folder, message);
        let compression = self.compression;
        tokio::task::spawn_blocking(move || read_blob(&path, compression))
            .await
            .map_err(err_join)?
    }

    /// Remove a blob if present. Missing blobs are treated as success.
    pub async fn delete(
        &self,
        account: &AccountId,
        folder: &FolderId,
        message: &MessageId,
    ) -> Result<(), StorageError> {
        let path = self.path_for(account, folder, message);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(err_io(e)),
        }
    }

    /// Wipe every blob owned by `account`. Used by `accounts_remove`
    /// because the database CASCADE drops the `messages` rows but
    /// can't reach across the FFI boundary to clean the on-disk
    /// `<data_dir>/blobs/<account_id>/` tree — without this call
    /// the bodies linger as orphan files until `mailcli reset`.
    /// Missing directory is treated as success (a fresh account that
    /// never had any bodies persisted yet still goes through this
    /// path on remove).
    pub async fn delete_account(&self, account: &AccountId) -> Result<(), StorageError> {
        let path = self.root.join(sanitize_path_component(&account.0));
        match tokio::fs::remove_dir_all(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(err_io(e)),
        }
    }

    /// Absolute path a blob *would* live at, whether or not it exists.
    ///
    /// Each ID component is percent-encoded against the Windows filename
    /// reserved set so cross-platform storage works even when backends hand
    /// us IDs that contain `:` or `/`.
    pub fn path_for(&self, account: &AccountId, folder: &FolderId, message: &MessageId) -> PathBuf {
        let mut p = self.root.clone();
        p.push(sanitize_path_component(&account.0));
        p.push(sanitize_path_component(&folder.0));
        let ext = match self.compression {
            Compression::Zstd => "eml.zst",
            Compression::None => "eml",
        };
        p.push(format!("{}.{}", sanitize_path_component(&message.0), ext));
        p
    }
}

/// Percent-encode characters that aren't safe in a Windows filename
/// component. The Windows reserved set is `<>:"/\|?*` plus all control
/// characters (0x00-0x1F); we also encode `.` at the head and `%` itself
/// (so the encoding is reversible).
fn sanitize_path_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        let needs_encode = matches!(
            c,
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '%'
        ) || c.is_control()
            || (i == 0 && c == '.');
        if needs_encode {
            for b in c.to_string().bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn write_blob(path: &Path, bytes: &[u8], compression: Compression) -> Result<(), StorageError> {
    let tmp = path.with_extension("tmp");
    {
        let file = std::fs::File::create(&tmp).map_err(err_io)?;
        match compression {
            Compression::Zstd => {
                let mut encoder =
                    zstd::stream::Encoder::new(file, DEFAULT_COMPRESSION_LEVEL).map_err(err_io)?;
                encoder.write_all(bytes).map_err(err_io)?;
                encoder.finish().map_err(err_io)?;
            }
            Compression::None => {
                let mut file = file;
                file.write_all(bytes).map_err(err_io)?;
                file.sync_all().map_err(err_io)?;
            }
        }
    }
    std::fs::rename(&tmp, path).map_err(err_io)
}

fn read_blob(path: &Path, compression: Compression) -> Result<Vec<u8>, StorageError> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(StorageError::NotFound);
        }
        Err(e) => return Err(err_io(e)),
    };
    match compression {
        Compression::Zstd => {
            let mut decoder = zstd::stream::Decoder::new(file).map_err(err_io)?;
            let mut buf = Vec::new();
            decoder.read_to_end(&mut buf).map_err(err_io)?;
            Ok(buf)
        }
        Compression::None => {
            let mut file = file;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).map_err(err_io)?;
            Ok(buf)
        }
    }
}

fn err_io(e: std::io::Error) -> StorageError {
    StorageError::Db(format!("blob i/o: {e}"))
}

fn err_join(e: tokio::task::JoinError) -> StorageError {
    StorageError::Db(format!("blob task panicked: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (AccountId, FolderId, MessageId) {
        (
            AccountId("acct-1".into()),
            FolderId("INBOX".into()),
            MessageId("1712345:42".into()),
        )
    }

    #[tokio::test]
    async fn zstd_roundtrip() {
        let tmp = tempdir();
        let store = BlobStore::new(tmp.path());
        let (a, f, m) = ids();

        let payload = vec![b'x'; 100 * 1024];
        let path = store.put(&a, &f, &m, &payload).await.unwrap();
        assert!(path.to_string_lossy().ends_with(".eml.zst"));
        assert!(std::fs::metadata(&path).unwrap().len() < payload.len() as u64);

        let back = store.get(&a, &f, &m).await.unwrap();
        assert_eq!(back, payload);
    }

    #[tokio::test]
    async fn raw_roundtrip() {
        let tmp = tempdir();
        let store = BlobStore::new(tmp.path()).with_compression(Compression::None);
        let (a, f, m) = ids();

        let payload = b"From: me\r\nTo: you\r\nSubject: hi\r\n\r\nhello\r\n";
        let path = store.put(&a, &f, &m, payload).await.unwrap();
        assert!(path.to_string_lossy().ends_with(".eml"));
        assert!(!path.to_string_lossy().ends_with(".zst"));

        let back = store.get(&a, &f, &m).await.unwrap();
        assert_eq!(back, payload);
    }

    #[tokio::test]
    async fn missing_returns_not_found() {
        let tmp = tempdir();
        let store = BlobStore::new(tmp.path());
        let (a, f, m) = ids();
        let err = store.get(&a, &f, &m).await.unwrap_err();
        assert!(matches!(err, qsl_core::StorageError::NotFound));
    }

    #[test]
    fn sanitize_escapes_windows_reserved_characters() {
        // IMAP-style MessageIds embed `:`; backslashes and slashes can
        // appear in some backends' folder paths; `*?` show up in wildcard-y
        // labels. All of these must be encoded so NTFS doesn't reject the
        // filename with ERROR_INVALID_PARAMETER.
        let s = sanitize_path_component("1712345:42/x\\y*?\"<>|");
        assert!(!s.contains(':'), "colon not escaped: {s}");
        assert!(!s.contains('/'), "forward slash not escaped: {s}");
        assert!(!s.contains('\\'), "backslash not escaped: {s}");
        assert!(!s.contains('*'), "star not escaped: {s}");
        assert!(!s.contains('?'), "question not escaped: {s}");
        assert!(!s.contains('"'), "quote not escaped: {s}");
        assert!(!s.contains('<'), "less-than not escaped: {s}");
        assert!(!s.contains('>'), "greater-than not escaped: {s}");
        assert!(!s.contains('|'), "pipe not escaped: {s}");
        // Printable ASCII round-trip — `a-z`, `0-9`, etc. survive.
        assert_eq!(
            sanitize_path_component("plain-ascii.123"),
            "plain-ascii.123"
        );
    }

    #[tokio::test]
    async fn colon_bearing_message_id_roundtrips() {
        // Regression: IMAP mints IDs like `<folder_uid_validity>:<uid>`;
        // storing them unescaped broke the blob store on Windows with
        // ERROR_INVALID_PARAMETER.
        let tmp = tempdir();
        let store = BlobStore::new(tmp.path());
        let a = AccountId("acct-1".into());
        let f = FolderId("INBOX".into());
        let m = MessageId("1712345:42".into());
        let payload = b"body";
        let path = store.put(&a, &f, &m, payload).await.unwrap();
        assert!(
            !path.file_name().unwrap().to_string_lossy().contains(':'),
            "on-disk filename must not contain a raw colon: {path:?}"
        );
        let back = store.get(&a, &f, &m).await.unwrap();
        assert_eq!(back, payload);
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let tmp = tempdir();
        let store = BlobStore::new(tmp.path());
        let (a, f, m) = ids();
        // Missing → ok.
        store.delete(&a, &f, &m).await.unwrap();
        // Present → ok.
        store.put(&a, &f, &m, b"body").await.unwrap();
        store.delete(&a, &f, &m).await.unwrap();
        // Missing again → still ok.
        store.delete(&a, &f, &m).await.unwrap();
    }

    /// Minimal tempdir helper — std::env::temp_dir() + unique subdir.
    /// Avoids pulling in the `tempfile` crate just for tests.
    struct OwnedTempDir(PathBuf);

    impl OwnedTempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for OwnedTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> OwnedTempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("qsl-blobs-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        OwnedTempDir(dir)
    }
}
