# Changelog

## Unreleased

### Security and correctness audit (2026-10-10)

Full report with severities and reproduction notes:
[`docs/security/audit-2026-10-10.md`](docs/security/audit-2026-10-10.md).

- **Multi-account data loss fixed.** Folder ids are now account-scoped
  (`<account_id>|<mailbox>`) and IMAP message ids carry the scoped
  folder, so two accounts with the same folder name no longer take
  over each other's folder row and prune each other's messages.
  **Migration 0019 drops the cached folder/message/thread tables and
  pending non-send outbox rows; the next sync rebuilds them.** Body
  blobs under `<data_dir>/blobs/` are orphaned and re-fetched on
  demand (`mailcli reset` reclaims the space).
- **Bcc no longer leaks.** The SMTP `DATA` payload has the `Bcc:`
  header stripped; the Sent-folder copy keeps it.
- **Header injection closed.** Outgoing subject, addresses, display
  names, attachment names and reply headers are rejected if they
  contain CR/LF/NUL; decoded inbound headers have those characters
  neutralised so a crafted subject can't ride a Reply into the wire.
- **Reader sanitizer:** the inline-style remote-content filter is
  case-, escape-, and comment-insensitive, handles `image-set()`,
  quoted `;`, and no longer panics on non-ASCII style values (which
  hung the reader on "Loading…"). `data:`/`cid:` are dropped from
  `href`. `cid:` rewriting matches whole ids and is size-bounded.
- **Storage:** a transaction dropped mid-flight is rolled back before
  the next statement, not just before the next `BEGIN` (a queued send
  could otherwise be resurrected and sent twice). Thread ids are 128
  bits. The FTS index is repaired at startup if a crash mid
  history-pull removed it. Deleted messages now delete their body
  blob.
- **Sync engine:** the outbox drain starts unconditionally at boot
  and the engine re-runs account discovery when accounts change or
  nothing was watchable, so a fresh install or an offline boot no
  longer leaves sends/flag changes queued until restart.
- **JMAP:** session URL handling fixed (`jmap-client` appends
  `/.well-known/jmap` itself and needs the redirect host trusted);
  write paths use the server's account id instead of QSL's local one.
  Both bugs made the Fastmail backend non-functional.
- **IMAP:** connect / TLS / auth / IDLE `DONE` steps are bounded by a
  30 s timeout; a failed CONDSTORE delta no longer advances the
  modseq cursor past unfetched flag changes.
- **Attachments:** executables, scripts, shortcuts and browser-rendered
  types (`.html`, `.svg`, …) are saved but not auto-launched; names
  have bidi-override characters and Windows reserved names
  neutralised; Windows files get the Mark-of-the-Web.
- **Drafts:** attachment paths must come from the native file picker
  (or already be on the draft row); the webview can't name arbitrary
  local files.
- **Auth:** a keychain write failure during refresh-token rotation no
  longer discards the only valid token; the OAuth loopback server
  ignores stray connections / favicon probes instead of failing the
  flow and answers provider denials with a page; hostile `expires_in`
  values are clamped instead of panicking; account emails are
  validated before an id is minted.
- **Misc:** `mailto:` links are delivered when QSL is already running
  (single-instance `deep-link` feature) and the path is
  percent-decoded; notification master/per-account toggles are
  honoured; `accounts_remove` with an empty id no longer wipes the
  blob store; release builds ship without devtools; search terms
  containing `:`/`(`/quotes are escaped instead of erroring; two UI
  panics (CJK subject prefix check, inverted `<…>` address range)
  fixed.

- Renamed the project from **Capytain** to **QSL**. Cargo packages
  (`capytain-*` → `qsl-*`), the Tauri app identifier
  (`app.capytain.desktop` → `app.qsl.desktop`), build-time env var
  prefix (`CAPYTAIN_*` → `QSL_*`, including the Gmail / Fastmail
  OAuth client-id slots and the `*_SKIP_UI_BUILD` /
  `*_CORPUS_REGEN` switches), workspace dep references, log
  prefixes, copyright notices, and all documentation have all been
  updated. **Action required for existing checkouts:**
  - Re-export `QSL_GMAIL_CLIENT_ID` / `QSL_GMAIL_CLIENT_SECRET` /
    `QSL_FASTMAIL_CLIENT_ID` / `QSL_FASTMAIL_CLIENT_SECRET` (any
    `.env` or shell config still using the `CAPYTAIN_*` names will
    fail to build the `qsl-auth` crate).
  - The Tauri identifier change means a fresh install on the same
    machine will look for its sqlite DB and keyring entries under
    `app.qsl.desktop` rather than `app.capytain.desktop`. Migrate
    existing data by moving `~/.local/share/app.capytain.desktop`
    → `~/.local/share/app.qsl.desktop` (or the equivalent on
    macOS / Windows) before first launch.
  - The git remote and the local working directory are not part of
    this commit — see the rebrand PR description for the
    `gh repo rename` and `mv` commands the maintainer runs by hand.
