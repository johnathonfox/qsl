-- SPDX-License-Identifier: Apache-2.0

-- Account-scoped folder ids: invalidate the cached mail tree.
--
-- Until this schema version the IMAP backend minted `folders.id`
-- from the bare mailbox path (`INBOX`, `[Gmail]/All Mail`) and
-- message ids as `imap|<uidvalidity>|<uid>|<path>` — neither carried
-- the owning account, while `folders.id` and `messages.id` are
-- *global* primary keys. With two accounts configured, the second
-- account's `sync_folder` found the first account's `INBOX` row,
-- re-pointed its `account_id`, shared its sync cursor, and the
-- reconciliation pass then pruned the other account's messages as
-- "deleted on the server". Both accounts took turns wiping each
-- other every cycle.
--
-- Backends now mint `FolderId::scoped(account, key)` =
-- `<account_id>|<key>` and the message id's folder segment carries
-- the scoped id. Rows written under the old scheme can't be rewritten
-- in place: `folders.id` is referenced by `messages.folder_id` with
-- no `ON UPDATE CASCADE`, the message ids need a string rewrite
-- inside a `|`-delimited encoding, and the whole thing would have to
-- run with foreign keys deferred — more fragile than it is worth for
-- what is, by design, a cache of server state.
--
-- So this migration drops the cached tree and lets the next sync
-- pass rebuild it under the new ids:
--
--   * folders            → cascades to messages → attachments
--   * threads            → re-minted by the threading pass
--   * history_sync_state → re-created when the user pulls history
--   * outbox rows that reference old message/folder ids (flag, move,
--     delete, save_draft ops) are dropped — the ids inside them can
--     no longer be decoded. Pending `submit_message` rows carry the
--     full RFC 5322 bytes and are kept so a queued send still goes
--     out.
--   * drafts.server_id   → NULL; the next draft save re-uploads and
--     the stale server copy is left for the user to clean up.
--
-- Accounts, drafts, contacts, app settings, and remote-content
-- opt-ins are untouched. Body blobs under `<data_dir>/blobs/` are
-- orphaned by this (their path embeds the old folder id); they are
-- re-fetched on demand and `mailcli reset` reclaims the space.

DELETE FROM outbox WHERE op_kind <> 'submit_message';
UPDATE drafts SET server_id = NULL WHERE server_id IS NOT NULL;
DELETE FROM history_sync_state;
DELETE FROM messages;
DELETE FROM threads;
DELETE FROM folders;
