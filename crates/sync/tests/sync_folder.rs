// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `qsl_sync::sync_folder`.
//!
//! Drives the function with a stub `MailBackend` against an in-memory
//! Turso database. The IMAP/JMAP adapters' own protocol behavior is
//! tested elsewhere; here we only care that `sync_folder` walks the
//! header upsert + cursor-persist loop correctly.

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use tokio::runtime::Runtime;

use qsl_core::{
    Account, AccountId, AttachmentRef, BackendKind, EmailAddress, Folder, FolderId, FolderRole,
    MailBackend, MailError, MessageBody, MessageFlags, MessageHeaders, MessageId, MessageList,
    SyncState,
};
use qsl_storage::{
    repos::{folders as folders_repo, messages as messages_repo, sync_states as sync_states_repo},
    run_migrations, BlobStore, TursoConn,
};

use qsl_sync::sync_folder;

// ---------- Stub backend ----------

/// Minimal `MailBackend` that returns a scripted sequence of
/// `MessageList` responses and a per-`MessageId` map of raw bytes.
/// Each call to `list_messages` consumes one response from the front
/// of the queue; `fetch_raw_message` reads from `raw_bodies`.
struct StubBackend {
    folders: Vec<Folder>,
    responses: Mutex<Vec<MessageList>>,
    raw_bodies: std::collections::HashMap<String, Vec<u8>>,
    /// IDs that should fail their body fetch — simulates a UIDVALIDITY
    /// race or a server hiccup mid-cycle.
    failing_ids: std::collections::HashSet<String>,
    /// Per-folder live id sets the reconciliation pass walks. `None`
    /// signals "don't override the trait default" which the engine
    /// then treats as backend-incapable and skips the prune.
    live_ids: Option<std::collections::HashMap<String, Vec<MessageId>>>,
}

#[async_trait]
impl MailBackend for StubBackend {
    async fn list_folders(&self) -> Result<Vec<Folder>, MailError> {
        Ok(self.folders.clone())
    }

    async fn list_messages(
        &self,
        _folder: &FolderId,
        _since: Option<&SyncState>,
        _limit: Option<u32>,
    ) -> Result<MessageList, MailError> {
        let mut q = self.responses.lock().unwrap();
        if q.is_empty() {
            Err(MailError::Other("stub: no scripted responses left".into()))
        } else {
            Ok(q.remove(0))
        }
    }

    async fn list_known_ids(&self, folder: &FolderId) -> Result<Vec<MessageId>, MailError> {
        match &self.live_ids {
            Some(map) => Ok(map.get(&folder.0).cloned().unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    async fn fetch_message(&self, _id: &MessageId) -> Result<MessageBody, MailError> {
        unimplemented!("sync_folder uses fetch_raw_message; fetch_message isn't exercised")
    }

    async fn fetch_raw_message(&self, id: &MessageId) -> Result<Vec<u8>, MailError> {
        if self.failing_ids.contains(&id.0) {
            return Err(MailError::Protocol(format!(
                "stub: scripted failure for {}",
                id.0
            )));
        }
        self.raw_bodies
            .get(&id.0)
            .cloned()
            .ok_or_else(|| MailError::NotFound(id.0.clone()))
    }

    async fn fetch_attachment(
        &self,
        _message: &MessageId,
        _attachment: &AttachmentRef,
    ) -> Result<Vec<u8>, MailError> {
        unimplemented!()
    }

    async fn update_flags(
        &self,
        _messages: &[MessageId],
        _add: MessageFlags,
        _remove: MessageFlags,
    ) -> Result<(), MailError> {
        unimplemented!()
    }

    async fn move_messages(
        &self,
        _messages: &[MessageId],
        _target: &FolderId,
    ) -> Result<(), MailError> {
        unimplemented!()
    }

    async fn delete_messages(&self, _messages: &[MessageId]) -> Result<(), MailError> {
        unimplemented!()
    }

    async fn save_draft(
        &self,
        _raw_rfc822: &[u8],
        _replace: Option<&MessageId>,
    ) -> Result<MessageId, MailError> {
        unimplemented!()
    }

    async fn submit_message(&self, _raw_rfc822: &[u8]) -> Result<Option<MessageId>, MailError> {
        unimplemented!()
    }
}

// ---------- Fixtures ----------

fn rt() -> Runtime {
    Runtime::new().unwrap()
}

fn header(id: &str, account: &AccountId, folder: &FolderId, subject: &str) -> MessageHeaders {
    MessageHeaders {
        id: MessageId(id.into()),
        account_id: account.clone(),
        folder_id: folder.clone(),
        thread_id: None,
        rfc822_message_id: None,
        subject: subject.into(),
        from: vec![EmailAddress {
            address: "sender@example.com".into(),
            display_name: None,
        }],
        reply_to: vec![],
        to: vec![],
        cc: vec![],
        bcc: vec![],
        date: Utc::now() - ChronoDuration::hours(1),
        flags: MessageFlags::default(),
        labels: vec![],
        snippet: String::new(),
        size: 1024,
        has_attachments: false,
        in_reply_to: None,
        references: vec![],
    }
}

async fn seed_account(conn: &TursoConn) -> (AccountId, Folder) {
    let acct = Account {
        id: AccountId("acct".into()),
        kind: BackendKind::ImapSmtp,
        display_name: "x".into(),
        email_address: "x@example.com".into(),
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        signature: None,
        notify_enabled: true,
    };
    qsl_storage::repos::accounts::insert(conn, &acct)
        .await
        .unwrap();
    let folder = Folder {
        id: FolderId("INBOX".into()),
        account_id: acct.id.clone(),
        name: "Inbox".into(),
        path: "INBOX".into(),
        role: Some(FolderRole::Inbox),
        unread_count: 0,
        total_count: 0,
        parent: None,
    };
    // Insert the folder up-front so tests that seed messages directly
    // (bypassing `sync_folder`'s own folder upsert) don't trip the
    // `messages.folder_id REFERENCES folders(id)` constraint now that
    // FK enforcement is on. `sync_folder` itself will upsert the same
    // row, which is a safe no-op.
    qsl_storage::repos::folders::insert(conn, &folder)
        .await
        .unwrap();
    (acct.id, folder)
}

// ---------- Tests ----------

#[test]
fn sync_folder_inserts_new_headers_and_persists_cursor() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        let h1 = header("m1", &acct_id, &folder.id, "first");
        let h2 = header("m2", &acct_id, &folder.id, "second");
        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![MessageList {
                messages: vec![h1.clone(), h2.clone()],
                flag_updates: vec![],
                new_state: SyncState {
                    folder_id: folder.id.clone(),
                    backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":3}".into(),
                },
                removed: vec![],
            }]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        let report = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(report.added, 2);
        assert_eq!(report.updated, 0);
        assert_eq!(report.removed, 0);

        // Headers landed in storage.
        let stored = messages_repo::get(&conn, &h1.id).await.unwrap();
        assert_eq!(stored.subject, "first");

        // Cursor persisted.
        let cursor = sync_states_repo::get(&conn, &folder.id)
            .await
            .unwrap()
            .expect("cursor");
        assert!(cursor.backend_state.contains("uidnext"));

        // Folder upserted.
        assert!(folders_repo::find(&conn, &folder.id)
            .await
            .unwrap()
            .is_some());
    });
}

#[test]
fn sync_folder_updates_existing_headers() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        let mut h1 = header("m1", &acct_id, &folder.id, "first");
        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![
                MessageList {
                    messages: vec![h1.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
                // Second cycle: same UID, flag flipped to seen.
                {
                    h1.flags.seen = true;
                    MessageList {
                        messages: vec![h1.clone()],
                        flag_updates: vec![],
                        new_state: SyncState {
                            folder_id: folder.id.clone(),
                            backend_state: "{\"uidvalidity\":1,\"highestmodseq\":1,\"uidnext\":2}"
                                .into(),
                        },
                        removed: vec![],
                    }
                },
            ]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        let r1 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r1.added, 1);
        assert_eq!(r1.updated, 0);

        let r2 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r2.added, 0);
        assert_eq!(r2.updated, 1);

        let stored = messages_repo::get(&conn, &h1.id).await.unwrap();
        assert!(stored.flags.seen);
    });
}

/// Re-syncing a chunk whose rows match what we already store should
/// produce zero `updated` writes — the apply_chunk plain-update
/// bucket gates on `(folder_id, flags_json, labels_json)` and skips
/// the row when all three match. Without this skip every IDLE poll
/// of every folder fired a per-row UPDATE that touched FTS + every
/// secondary index, the dominant `slow_tx_execute` source after
/// PR #144 silenced the count cascade.
#[test]
fn sync_folder_skips_update_when_resynced_row_unchanged() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        let h1 = header("m1", &acct_id, &folder.id, "subject");
        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![
                MessageList {
                    messages: vec![h1.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
                // Second cycle: server re-delivers the EXACT same
                // header (same flags, same labels, same folder).
                MessageList {
                    messages: vec![h1.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
            ]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        let r1 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r1.added, 1);
        assert_eq!(r1.updated, 0);

        let r2 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r2.added, 0);
        assert_eq!(
            r2.updated, 0,
            "re-syncing unchanged rows must NOT produce UPDATE writes — \
             that's the whole point of the skip-unchanged gate"
        );
    });
}

#[test]
fn sync_folder_fetches_bodies_for_new_messages() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        let h1 = header("m1", &acct_id, &folder.id, "first");
        let h2 = header("m2", &acct_id, &folder.id, "second");

        let mut bodies = std::collections::HashMap::new();
        bodies.insert(
            "m1".to_string(),
            b"From: a\r\nSubject: first\r\n\r\nbody-1\r\n".to_vec(),
        );
        bodies.insert(
            "m2".to_string(),
            b"From: b\r\nSubject: second\r\n\r\nbody-2\r\n".to_vec(),
        );

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![MessageList {
                messages: vec![h1.clone(), h2.clone()],
                flag_updates: vec![],
                new_state: SyncState {
                    folder_id: folder.id.clone(),
                    backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":3}".into(),
                },
                removed: vec![],
            }]),
            raw_bodies: bodies,
            failing_ids: Default::default(),
            live_ids: None,
        };

        let tmp = scratch_dir();
        let blobs = BlobStore::new(&tmp);

        let report = sync_folder(&conn, &backend, Some(&blobs), &folder, None)
            .await
            .unwrap();
        assert_eq!(report.added, 2);
        assert_eq!(report.bodies_fetched, 2);
        assert_eq!(report.bodies_failed, 0);

        // body_path now non-null for both messages.
        let p1 = messages_repo::body_path(&conn, &h1.id).await.unwrap();
        assert!(p1.is_some(), "body_path missing for m1");

        // BlobStore::get returns the same bytes we handed the stub.
        let back = blobs
            .get(&acct_id, &folder.id, &h1.id)
            .await
            .expect("blob present");
        assert_eq!(back, b"From: a\r\nSubject: first\r\n\r\nbody-1\r\n");
    });
}

#[test]
fn sync_folder_logs_and_skips_failed_body_fetches() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        let h_ok = header("ok", &acct_id, &folder.id, "fine");
        let h_bad = header("bad", &acct_id, &folder.id, "broken");

        let mut bodies = std::collections::HashMap::new();
        bodies.insert("ok".to_string(), b"raw ok\r\n".to_vec());
        // h_bad has no body in the map; even if it did, failing_ids
        // forces a Protocol error.
        let mut failing = std::collections::HashSet::new();
        failing.insert("bad".to_string());

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![MessageList {
                messages: vec![h_ok.clone(), h_bad.clone()],
                flag_updates: vec![],
                new_state: SyncState {
                    folder_id: folder.id.clone(),
                    backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":3}".into(),
                },
                removed: vec![],
            }]),
            raw_bodies: bodies,
            failing_ids: failing,
            live_ids: None,
        };

        let tmp = scratch_dir();
        let blobs = BlobStore::new(&tmp);

        let report = sync_folder(&conn, &backend, Some(&blobs), &folder, None)
            .await
            .unwrap();
        assert_eq!(report.added, 2);
        assert_eq!(report.bodies_fetched, 1);
        assert_eq!(report.bodies_failed, 1);

        // The good message has a body_path; the bad one does not.
        assert!(messages_repo::body_path(&conn, &h_ok.id)
            .await
            .unwrap()
            .is_some());
        assert!(messages_repo::body_path(&conn, &h_bad.id)
            .await
            .unwrap()
            .is_none());
    });
}

#[test]
fn sync_folder_applies_flag_updates_via_update_flags() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        // Cycle 1: insert m1 with default flags.
        let h1 = header("m1", &acct_id, &folder.id, "first");
        // Cycle 2: m1 disappears from `messages` (server says no new
        // appends), but its flags moved per CHANGEDSINCE — `flag_updates`
        // carries the delta.
        let new_flags = MessageFlags {
            seen: true,
            flagged: true,
            ..Default::default()
        };

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![
                MessageList {
                    messages: vec![h1.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":1,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
                MessageList {
                    messages: vec![],
                    flag_updates: vec![(h1.id.clone(), new_flags.clone())],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":2,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
            ]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        let r1 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r1.added, 1);
        assert_eq!(r1.flag_updates, 0);

        // Pre-cycle-2: stored row has default flags.
        let pre = messages_repo::get(&conn, &h1.id).await.unwrap();
        assert!(!pre.flags.seen);

        let r2 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r2.added, 0);
        assert_eq!(r2.updated, 0);
        assert_eq!(r2.flag_updates, 1);

        // Post-cycle-2: stored row picked up the flag delta.
        let post = messages_repo::get(&conn, &h1.id).await.unwrap();
        assert!(post.flags.seen);
        assert!(post.flags.flagged);
    });
}

#[test]
fn sync_folder_skips_flag_updates_for_unknown_messages() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (_acct_id, folder) = seed_account(&conn).await;

        // Cache has nothing in it. CHANGEDSINCE pass surfaces an
        // update for a UID we never inserted (earlier bounded sync
        // didn't pull this far back). `sync_folder` should log + skip,
        // not propagate StorageError::NotFound.
        let stranger_flags = MessageFlags {
            seen: true,
            ..Default::default()
        };
        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![MessageList {
                messages: vec![],
                flag_updates: vec![(MessageId("never-inserted".into()), stranger_flags)],
                new_state: SyncState {
                    folder_id: folder.id.clone(),
                    backend_state: "{\"uidvalidity\":1,\"highestmodseq\":2,\"uidnext\":1}".into(),
                },
                removed: vec![],
            }]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        let r = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r.added, 0);
        assert_eq!(r.flag_updates, 0); // skipped, not counted
    });
}

#[test]
fn sync_account_walks_every_folder_and_collects_outcomes() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, inbox) = seed_account(&conn).await;

        let sent = Folder {
            id: FolderId("Sent".into()),
            account_id: acct_id.clone(),
            name: "Sent".into(),
            path: "[Gmail]/Sent Mail".into(),
            role: Some(FolderRole::Sent),
            unread_count: 0,
            total_count: 0,
            parent: None,
        };

        let h_inbox = header("inbox-1", &acct_id, &inbox.id, "first");
        let h_sent = header("sent-1", &acct_id, &sent.id, "outgoing");

        let backend = StubBackend {
            folders: vec![inbox.clone(), sent.clone()],
            // One MessageList per folder, in the order list_folders
            // returned them.
            responses: Mutex::new(vec![
                MessageList {
                    messages: vec![h_inbox.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: inbox.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
                MessageList {
                    messages: vec![h_sent.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: sent.id.clone(),
                        backend_state: "{\"uidvalidity\":7,\"highestmodseq\":0,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
            ]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        let outcomes = qsl_sync::sync_account(&conn, &backend, None, None)
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 2);
        for o in &outcomes {
            let report = o.result.as_ref().expect("folder synced");
            assert_eq!(report.added, 1, "folder {}", o.folder_id.0);
        }

        // Both folder rows now exist.
        assert!(folders_repo::find(&conn, &inbox.id)
            .await
            .unwrap()
            .is_some());
        assert!(folders_repo::find(&conn, &sent.id).await.unwrap().is_some());
        // Both messages landed.
        assert_eq!(
            messages_repo::get(&conn, &h_inbox.id)
                .await
                .unwrap()
                .subject,
            "first"
        );
        assert_eq!(
            messages_repo::get(&conn, &h_sent.id).await.unwrap().subject,
            "outgoing"
        );
    });
}

#[test]
fn sync_account_continues_after_per_folder_failures() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, inbox) = seed_account(&conn).await;

        let broken = Folder {
            id: FolderId("Broken".into()),
            account_id: acct_id.clone(),
            name: "Broken".into(),
            path: "Broken".into(),
            role: None,
            unread_count: 0,
            total_count: 0,
            parent: None,
        };

        let h_inbox = header("inbox-1", &acct_id, &inbox.id, "first");

        // First call (inbox): succeeds. Second call (broken):
        // empty responses queue → stub returns MailError. The
        // failure should NOT abort the cycle.
        let backend = StubBackend {
            folders: vec![inbox.clone(), broken.clone()],
            responses: Mutex::new(vec![MessageList {
                messages: vec![h_inbox.clone()],
                flag_updates: vec![],
                new_state: SyncState {
                    folder_id: inbox.id.clone(),
                    backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":2}".into(),
                },
                removed: vec![],
            }]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        let outcomes = qsl_sync::sync_account(&conn, &backend, None, None)
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes[0].result.is_ok(), "inbox should have synced");
        assert!(
            outcomes[1].result.is_err(),
            "broken folder should report failure"
        );
        // Inbox state still landed despite the second folder failing.
        assert_eq!(
            messages_repo::get(&conn, &h_inbox.id)
                .await
                .unwrap()
                .subject,
            "first"
        );
    });
}

// ---------- Threading (Phase 1 Week 13) ----------

#[test]
fn threading_attaches_via_in_reply_to() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        // Cycle 1: insert the root message with an rfc822 message id.
        let mut root = header("root-1", &acct_id, &folder.id, "Quarterly review");
        root.rfc822_message_id = Some("<root-mid@example.com>".into());

        // Cycle 2: a reply that points at the root via In-Reply-To.
        let mut reply = header("reply-1", &acct_id, &folder.id, "Re: Quarterly review");
        reply.rfc822_message_id = Some("<reply-mid@example.com>".into());
        reply.in_reply_to = Some("<root-mid@example.com>".into());
        reply.references = vec!["<root-mid@example.com>".into()];

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![
                MessageList {
                    messages: vec![root.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":1,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
                MessageList {
                    messages: vec![reply.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":2,\"uidnext\":3}"
                            .into(),
                    },
                    removed: vec![],
                },
            ]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();

        let stored_root = messages_repo::get(&conn, &root.id).await.unwrap();
        let stored_reply = messages_repo::get(&conn, &reply.id).await.unwrap();
        assert!(stored_root.thread_id.is_some(), "root needs a thread");
        assert_eq!(
            stored_root.thread_id, stored_reply.thread_id,
            "reply must share the root's thread"
        );
    });
}

#[test]
fn threading_attaches_via_subject_when_references_chain_breaks() {
    rt().block_on(async {
        // Models the spec exit criterion: "Subject-renamed replies
        // in a conversation ('Re: → (no subject)') still attach via
        // References chain." Here we model the more permissive
        // subject fallback: a reply with the same normalized
        // subject but no In-Reply-To still threads.
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        let mut root = header("root-2", &acct_id, &folder.id, "Lunch tomorrow?");
        root.rfc822_message_id = Some("<root2-mid@example.com>".into());

        // Mailing-list digest pattern: subject preserved, but
        // In-Reply-To wasn't rewritten. Subject-recency match
        // should still attach.
        let reply = header("reply-2", &acct_id, &folder.id, "Re: Lunch tomorrow?");

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![
                MessageList {
                    messages: vec![root.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":1,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
                MessageList {
                    messages: vec![reply.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":2,\"uidnext\":3}"
                            .into(),
                    },
                    removed: vec![],
                },
            ]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();

        let stored_root = messages_repo::get(&conn, &root.id).await.unwrap();
        let stored_reply = messages_repo::get(&conn, &reply.id).await.unwrap();
        assert_eq!(
            stored_root.thread_id, stored_reply.thread_id,
            "subject-fallback should attach the reply to the root's thread"
        );
    });
}

#[test]
fn threading_creates_new_thread_when_no_match() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        let mut a = header("m-a", &acct_id, &folder.id, "Subject A");
        a.rfc822_message_id = Some("<a-mid@example.com>".into());
        let mut b = header("m-b", &acct_id, &folder.id, "Subject B");
        b.rfc822_message_id = Some("<b-mid@example.com>".into());

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![MessageList {
                messages: vec![a.clone(), b.clone()],
                flag_updates: vec![],
                new_state: SyncState {
                    folder_id: folder.id.clone(),
                    backend_state: "{\"uidvalidity\":1,\"highestmodseq\":1,\"uidnext\":3}".into(),
                },
                removed: vec![],
            }]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();

        let ta = messages_repo::get(&conn, &a.id).await.unwrap().thread_id;
        let tb = messages_repo::get(&conn, &b.id).await.unwrap().thread_id;
        assert!(ta.is_some() && tb.is_some());
        assert_ne!(ta, tb, "different subjects must mint different threads");
    });
}

/// Local tempdir helper — `qsl-storage` rolls its own to avoid a
/// `tempfile` dev-dep, so this crate does the same.
fn scratch_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("qsl-sync-test-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn sync_folder_deletes_backend_reported_removals() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        // Seed three rows that the backend will then say are gone.
        for id in ["m_gone_1", "m_gone_2", "m_gone_3"] {
            let h = header(id, &acct_id, &folder.id, "doomed");
            messages_repo::insert(&conn, &h, None).await.unwrap();
        }
        // One row that should survive (backend doesn't mention it).
        let keep = header("m_keep", &acct_id, &folder.id, "alive");
        messages_repo::insert(&conn, &keep, None).await.unwrap();

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![MessageList {
                messages: vec![],
                flag_updates: vec![],
                new_state: SyncState {
                    folder_id: folder.id.clone(),
                    backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":1}".into(),
                },
                removed: vec![
                    MessageId("m_gone_1".into()),
                    MessageId("m_gone_2".into()),
                    MessageId("m_gone_3".into()),
                ],
            }]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None,
        };

        let report = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(report.removed, 3);

        // Doomed rows are gone, the other survives.
        for id in ["m_gone_1", "m_gone_2", "m_gone_3"] {
            assert!(
                messages_repo::find(&conn, &MessageId(id.into()))
                    .await
                    .unwrap()
                    .is_none(),
                "{id} should have been deleted"
            );
        }
        assert!(messages_repo::find(&conn, &keep.id)
            .await
            .unwrap()
            .is_some());
    });
}

/// Reconciliation pass: when the backend reports a non-empty live id
/// set on a non-initial sync, anything in storage but not in that set
/// is pruned. Catches Gmail-style deletes (no QRESYNC, no VANISHED).
#[test]
fn sync_folder_prunes_stale_rows_via_reconciliation() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        // Cycle 1: seed the cache with three rows.
        let h1 = header("m1", &acct_id, &folder.id, "first");
        let h2 = header("m2", &acct_id, &folder.id, "second");
        let h3 = header("m3", &acct_id, &folder.id, "third");

        let mut live_for_cycle2 = std::collections::HashMap::new();
        live_for_cycle2.insert(folder.id.0.clone(), vec![h1.id.clone(), h3.id.clone()]);

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![
                // First cycle: server has all three, no `since` cursor.
                MessageList {
                    messages: vec![h1.clone(), h2.clone(), h3.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":4}"
                            .into(),
                    },
                    removed: vec![],
                },
                // Second cycle: server reports no deltas in messages
                // but `list_known_ids` will only return m1 + m3.
                MessageList {
                    messages: vec![],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":1,\"uidnext\":4}"
                            .into(),
                    },
                    removed: vec![],
                },
            ]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: Some(live_for_cycle2),
        };

        let r1 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r1.added, 3);
        // Reconcile pass is gated on `prior.is_some()` — first cycle
        // shouldn't prune anything even though `live_ids` is set.
        assert_eq!(r1.removed, 0);

        let r2 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r2.added, 0);
        // m2 was missing from `list_known_ids` → pruned.
        assert_eq!(r2.removed, 1);

        assert!(messages_repo::find(&conn, &h1.id).await.unwrap().is_some());
        assert!(messages_repo::find(&conn, &h2.id).await.unwrap().is_none());
        assert!(messages_repo::find(&conn, &h3.id).await.unwrap().is_some());
    });
}

/// `list_known_ids` returning empty is treated as "backend opted out"
/// and the reconcile pass leaves the cache alone — even on a cycle
/// where everything in storage is technically "missing from the live
/// set." Without this guard, the default trait impl (returns empty)
/// would wipe the entire folder on every JMAP sync.
#[test]
fn sync_folder_skips_reconcile_when_live_set_is_empty() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        let h1 = header("m1", &acct_id, &folder.id, "first");

        let backend = StubBackend {
            folders: vec![folder.clone()],
            responses: Mutex::new(vec![
                MessageList {
                    messages: vec![h1.clone()],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":0,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
                MessageList {
                    messages: vec![],
                    flag_updates: vec![],
                    new_state: SyncState {
                        folder_id: folder.id.clone(),
                        backend_state: "{\"uidvalidity\":1,\"highestmodseq\":1,\"uidnext\":2}"
                            .into(),
                    },
                    removed: vec![],
                },
            ]),
            raw_bodies: Default::default(),
            failing_ids: Default::default(),
            live_ids: None, // trait default → empty vec → skip prune
        };

        sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        let r2 = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .unwrap();
        assert_eq!(r2.removed, 0);
        // The cached row survives because the engine refused to
        // interpret an empty live set as "everything is gone."
        assert!(messages_repo::find(&conn, &h1.id).await.unwrap().is_some());
    });
}

// ---------- UIDVALIDITY recovery ----------

/// Specialised stub for the recovery test: scripted-error on the
/// first `list_messages` call, scripted-success on the second.
/// Captures each call's `since` arg so the test can assert the
/// recovery call was issued with `None` (the fresh-sync path).
struct RecoveringStub {
    folders: Vec<Folder>,
    calls: Mutex<u32>,
    /// Taken on the first `list_messages` call. `None` after the take
    /// so the second call falls through to `on_recovery`.
    recovery_error: Mutex<Option<MailError>>,
    on_recovery: Mutex<Option<MessageList>>,
    /// Returned by `list_known_ids` — the live UID set under the
    /// post-recovery uidvalidity. Anything in local storage with a
    /// different id should be pruned by reconciliation.
    live_ids: Vec<MessageId>,
    /// `Some(_)` for every call where `since` was `Some`; `None`
    /// otherwise. Asserted by the test to verify the cursor was
    /// cleared between calls.
    since_seen: Mutex<Vec<bool>>,
}

#[async_trait]
impl MailBackend for RecoveringStub {
    async fn list_folders(&self) -> Result<Vec<Folder>, MailError> {
        Ok(self.folders.clone())
    }

    async fn list_messages(
        &self,
        _folder: &FolderId,
        since: Option<&SyncState>,
        _limit: Option<u32>,
    ) -> Result<MessageList, MailError> {
        self.since_seen.lock().unwrap().push(since.is_some());
        *self.calls.lock().unwrap() += 1;
        if let Some(err) = self.recovery_error.lock().unwrap().take() {
            return Err(err);
        }
        self.on_recovery
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| MailError::Other("RecoveringStub: no recovery response left".into()))
    }

    async fn list_known_ids(&self, _folder: &FolderId) -> Result<Vec<MessageId>, MailError> {
        Ok(self.live_ids.clone())
    }

    async fn fetch_message(&self, _id: &MessageId) -> Result<MessageBody, MailError> {
        unimplemented!()
    }
    async fn fetch_raw_message(&self, _id: &MessageId) -> Result<Vec<u8>, MailError> {
        unimplemented!()
    }
    async fn fetch_attachment(
        &self,
        _message: &MessageId,
        _attachment: &AttachmentRef,
    ) -> Result<Vec<u8>, MailError> {
        unimplemented!()
    }
    async fn update_flags(
        &self,
        _messages: &[MessageId],
        _add: MessageFlags,
        _remove: MessageFlags,
    ) -> Result<(), MailError> {
        unimplemented!()
    }
    async fn move_messages(
        &self,
        _messages: &[MessageId],
        _target: &FolderId,
    ) -> Result<(), MailError> {
        unimplemented!()
    }
    async fn delete_messages(&self, _messages: &[MessageId]) -> Result<(), MailError> {
        unimplemented!()
    }
    async fn save_draft(
        &self,
        _raw_rfc822: &[u8],
        _replace: Option<&MessageId>,
    ) -> Result<MessageId, MailError> {
        unimplemented!()
    }
    async fn submit_message(&self, _raw_rfc822: &[u8]) -> Result<Option<MessageId>, MailError> {
        unimplemented!()
    }
}

/// When `list_messages` returns `MailError::UidValidityChanged`,
/// `sync_folder` must:
///   1. Clear the cached sync cursor.
///   2. Re-call `list_messages` with `since = None` (the fresh-sync
///      path).
///   3. Continue normally — the reconciliation pass under the post-
///      recovery state prunes the stale-uidvalidity rows that are
///      still in the local cache.
///
/// Without recovery, the cached cursor stays poisoned and every
/// subsequent sync cycle re-errors on the same mismatch.
#[test]
fn sync_folder_recovers_when_backend_reports_uidvalidity_change() {
    rt().block_on(async {
        let conn = TursoConn::in_memory().await.unwrap();
        run_migrations(&conn).await.unwrap();
        let (acct_id, folder) = seed_account(&conn).await;

        // Pre-seed a stale sync cursor: what the cache would hold
        // from the prior UIDVALIDITY's last successful sync.
        sync_states_repo::put(
            &conn,
            &SyncState {
                folder_id: folder.id.clone(),
                backend_state: "{\"uidvalidity\":1,\"highestmodseq\":99,\"uidnext\":42}".into(),
            },
        )
        .await
        .unwrap();

        // Pre-seed a message under the OLD uidvalidity so the
        // reconciliation pass has something to prune in the same
        // recovery cycle.
        let old_id = MessageId("imap|1|10|INBOX".into());
        let stale = header(&old_id.0, &acct_id, &folder.id, "stale");
        messages_repo::insert(&conn, &stale, None).await.unwrap();

        // Fresh response under the post-recovery uidvalidity.
        let new_id = MessageId("imap|2|1|INBOX".into());
        let fresh = header(&new_id.0, &acct_id, &folder.id, "fresh");
        let backend = RecoveringStub {
            folders: vec![folder.clone()],
            calls: Mutex::new(0),
            recovery_error: Mutex::new(Some(MailError::UidValidityChanged {
                folder: folder.id.0.clone(),
                cached: 1,
                observed: 2,
            })),
            on_recovery: Mutex::new(Some(MessageList {
                messages: vec![fresh.clone()],
                flag_updates: vec![],
                new_state: SyncState {
                    folder_id: folder.id.clone(),
                    backend_state: "{\"uidvalidity\":2,\"highestmodseq\":0,\"uidnext\":2}".into(),
                },
                removed: vec![],
            })),
            live_ids: vec![new_id.clone()],
            since_seen: Mutex::new(Vec::new()),
        };

        let report = sync_folder(&conn, &backend, None, &folder, None)
            .await
            .expect("recovery succeeds");

        // The recovery refetched as a fresh sync (one new insert).
        assert_eq!(report.added, 1, "expected exactly one new header inserted");
        // Reconciliation under the post-recovery state prunes the
        // stale-uidvalidity row.
        assert!(
            report.removed >= 1,
            "expected stale-uidvalidity row pruned; report = {report:?}"
        );

        let stale_row = messages_repo::find(&conn, &old_id).await.unwrap();
        assert!(
            stale_row.is_none(),
            "stale-UIDVALIDITY row should be pruned"
        );
        let fresh_row = messages_repo::find(&conn, &new_id).await.unwrap();
        assert!(
            fresh_row.is_some(),
            "fresh row under new UIDVALIDITY should be persisted"
        );

        // Verify the cursor was cleared between calls: first call
        // saw the stale cursor, second call saw `None`.
        let calls = *backend.calls.lock().unwrap();
        assert_eq!(calls, 2, "expected exactly 2 list_messages calls");
        let since_seen = backend.since_seen.lock().unwrap().clone();
        assert_eq!(
            since_seen,
            vec![true, false],
            "first call should pass the stale cursor; recovery call should pass None"
        );

        // The new state from the recovery call must have been
        // persisted; otherwise the next cycle would refire the
        // recovery path forever.
        let after = sync_states_repo::get(&conn, &folder.id).await.unwrap();
        let after_state = after.expect("post-recovery cursor must be set");
        assert!(
            after_state.backend_state.contains("\"uidvalidity\":2"),
            "post-recovery cursor should reflect the new uidvalidity, got {:?}",
            after_state.backend_state
        );
    });
}
