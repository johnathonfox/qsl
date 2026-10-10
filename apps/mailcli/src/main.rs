// SPDX-License-Identifier: Apache-2.0

//! `mailcli` — QSL's headless protocol CLI.
//!
//! Phase 0 scope (all of Week 4 landed end-to-end here):
//!
//! - `auth add <provider> <email>` runs the OAuth2 + PKCE flow against
//!   the built-in provider profile, stores the refresh token in the
//!   keychain, and writes an account row to the local database.
//! - `auth list` prints accounts on disk with a keychain presence flag.
//! - `auth remove <email>` deletes both the DB row and the keychain
//!   entry.
//! - `list-folders <email>` connects via the appropriate adapter (IMAP
//!   for Gmail, JMAP for Fastmail) using an access token refreshed
//!   against the stored refresh token, and prints every folder the
//!   server advertises.
//! - `list-messages <email> <folder> [--limit N]` SELECT+FETCHes
//!   (IMAP) or Email/query+get-s (JMAP) the most recent N messages.
//! - `sync <email>` finds the INBOX, upserts its folder row, runs
//!   delta sync against any previously-persisted cursor, writes each
//!   message header via `qsl_storage::repos::messages`, and
//!   persists the new sync cursor. Prints
//!   `Synced N new messages, M removed, in T ms`.
//! - `show-message <id>` is a placeholder — IMAP ids encode the
//!   folder so it would be self-contained, but we want a consistent
//!   UX across both adapters; the full version lands with the Phase
//!   1 polish pass.

use std::path::PathBuf;

use chrono::Utc;
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use tracing::info;

use qsl_auth::{
    lookup as provider_lookup, refresh_access_token, run_loopback_flow, AuthError, TokenVault,
};
use qsl_core::{
    Account, AccountId, BackendKind, Draft, DraftBodyKind, DraftId, EmailAddress, FolderId,
    MailBackend, MailError,
};
use qsl_imap_client::ImapBackend;
use qsl_jmap_client::JmapBackend;
use qsl_storage::{repos, run_migrations, DbConn, Params, TursoConn, Value};

/// QSL headless protocol CLI.
#[derive(Debug, Parser)]
#[command(name = "mailcli", version, about, long_about = None)]
struct Cli {
    /// Tracing filter directive, e.g. `info`, `debug`, or
    /// `qsl_imap_client=trace,warn`. Takes precedence over
    /// `RUST_LOG`.
    #[arg(long, value_name = "FILTER", global = true)]
    log_level: Option<String>,

    /// Override the QSL data directory. Defaults to the
    /// OS-idiomatic location (XDG on Linux, Application Support on
    /// macOS, AppData on Windows).
    #[arg(long, value_name = "DIR", global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// OAuth2 account management.
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },

    /// List folders (mailboxes) on the server. Phase 0 stub.
    ListFolders {
        /// Email address of the previously-added account.
        email: String,
    },

    /// List messages in a folder. Phase 0 stub.
    ListMessages {
        email: String,
        folder: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },

    /// Show a single message by ID. Phase 0 stub.
    ShowMessage { id: String },

    /// Sync an account. Phase 0 stub.
    Sync { email: String },

    /// Pull historical mail (everything older than what live-sync has)
    /// for one folder or every folder on an account.
    ///
    /// Mirrors the desktop's per-folder history-sync surface but
    /// drives `qsl_sync::history::pull_history` directly with no UI
    /// in the loop — the goal is to test backfill perf (chunk size,
    /// batch_insert_skip_existing throughput) on real mailboxes
    /// without the Settings panel.
    ///
    /// Requires that `mailcli sync <email>` has run at least once so
    /// each folder has a local UID floor to anchor the backfill at.
    /// Runs folders sequentially so the per-account IMAP session
    /// isn't multiplexed (matches the desktop's per-account lock).
    HistorySync {
        /// Email of the previously-added account.
        email: String,

        /// Restrict to one folder (e.g. `INBOX`,
        /// `[Gmail]/All Mail`). Mutually exclusive with `--all`.
        #[arg(long, value_name = "NAME", conflicts_with = "all")]
        folder: Option<String>,

        /// Pull every folder on the account, sequentially. Skips
        /// folders with no local messages (no anchor available).
        #[arg(long)]
        all: bool,
    },

    /// Wipe local state. Removes the Turso database file
    /// (`qsl.db`, `-wal`, `-shm`), the cached message-body blob
    /// store, and every keychain refresh-token for accounts known
    /// to the database. Useful when a schema migration wedges, when
    /// a stale orphaned-row state needs clearing, or to hand off the
    /// box without leaking local mail.
    ///
    /// Requires `--yes` to proceed without an interactive prompt.
    Reset {
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },

    /// Inspect local-state integrity and (optionally) repair it.
    ///
    /// Audits the database for orphaned rows, stuck history-sync
    /// jobs, dead-lettered outbox entries, empty thread shells, and
    /// SQLite engine-level corruption. Read-only by default; pass
    /// `--fix` to apply the documented repair for each finding.
    ///
    /// Run with the desktop app closed — repairs that touch
    /// history-sync state assume no driver is currently holding the
    /// row.
    Doctor {
        /// Apply repairs (delete FK-orphan rows, reset stuck/errored
        /// history-sync rows to `pending`, drop empty thread shells,
        /// prune accounts whose keychain entry is gone). Without this
        /// flag the command is read-only.
        #[arg(long)]
        fix: bool,

        /// Wipe the entire history-sync state table — every "Pull
        /// full mail history" job, regardless of status, is dropped.
        /// Use after a Turso schema wedge or to start the
        /// per-folder backfill from scratch. Independent of `--fix`.
        /// Confirmation prompt unless `--yes`.
        #[arg(long)]
        reset_history_sync: bool,

        /// Drop and recreate the Tantivy-backed FTS index on
        /// `messages`. Fixes "wrong # of entries in index
        /// __turso_internal_fts_dir_messages_fts_idx_key" reports
        /// from the schema-integrity check, which slow per-message
        /// inserts to a crawl during history sync. The index is
        /// rebuilt from existing message rows in one bulk operation —
        /// no message data is touched. Independent of `--fix`.
        #[arg(long)]
        rebuild_fts: bool,

        /// `VACUUM` the database — rebuild the file to reclaim
        /// leaked / never-used pages reported by the schema-integrity
        /// check ("Page N: never used"). No data loss; just compacts
        /// the file. Slow on a populated DB. Run AFTER
        /// `--rebuild-fts` if both are needed: rebuilding the FTS
        /// index drops pages that VACUUM then reclaims. Independent
        /// of `--fix`.
        #[arg(long)]
        vacuum: bool,

        /// Skip interactive confirmation for destructive repair
        /// steps (account pruning, history-sync wipe, FTS rebuild,
        /// vacuum).
        #[arg(long)]
        yes: bool,
    },

    /// Build an RFC 5322 message and submit it via the account's send
    /// path (Gmail SMTP+XOAUTH2 for IMAP accounts, JMAP
    /// `EmailSubmission/set` for Fastmail accounts). Smoke-test path
    /// for the Phase 2 send pipeline — bypasses the desktop UI and
    /// the local outbox; calls `MailBackend::submit_message` directly.
    Send {
        /// Email address of the previously-added "From" account.
        from: String,

        /// Recipient. Repeat for multiple addresses.
        #[arg(long, value_name = "ADDR", required = true)]
        to: Vec<String>,

        /// Optional Cc. Repeat for multiple addresses.
        #[arg(long, value_name = "ADDR")]
        cc: Vec<String>,

        /// Optional Bcc. Repeat for multiple addresses.
        #[arg(long, value_name = "ADDR")]
        bcc: Vec<String>,

        /// Subject line.
        #[arg(long)]
        subject: String,

        /// Plain-text body (mutually exclusive with `--body-file`).
        #[arg(long, conflicts_with = "body_file")]
        body: Option<String>,

        /// Read the plain-text body from a file
        /// (mutually exclusive with `--body`).
        #[arg(long, value_name = "PATH", conflicts_with = "body")]
        body_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AuthAction {
    /// Run the OAuth2 + PKCE flow for a provider and store the refresh
    /// token in the OS keychain.
    Add {
        /// One of `gmail`, `fastmail`.
        provider: String,
        /// Email address the user is authenticating.
        email: String,
    },

    /// List locally-known accounts and whether the keychain has a
    /// refresh token for each.
    List,

    /// Remove an account locally: delete the row from storage and the
    /// refresh token from the keychain.
    Remove {
        /// Email address of the account to remove.
        email: String,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    if let Err(e) = qsl_telemetry::init(cli.log_level.as_deref()) {
        eprintln!("mailcli: failed to initialize tracing: {e}");
        return std::process::ExitCode::from(1);
    }

    // Install a rustls `CryptoProvider` before any TLS traffic starts.
    // Both `ring` and `aws-lc-rs` end up enabled transitively (reqwest
    // + async-imap + tokio-rustls + servo-side crypto in the larger
    // workspace), so rustls refuses to auto-pick and panics at the
    // first HTTPS resolution. Mirror `qsl-desktop/src/main.rs` —
    // prefer `ring` explicitly.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls CryptoProvider was already installed; continuing");
    }

    match run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mailcli: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<(), MailcliError> {
    let paths = DataPaths::resolve(cli.data_dir.as_deref())?;
    match cli.command {
        Command::Auth { action } => dispatch_auth(action, &paths).await,
        Command::ListFolders { email } => list_folders(&email, &paths).await,
        Command::ListMessages {
            email,
            folder,
            limit,
        } => list_messages(&email, &folder, limit, &paths).await,
        Command::ShowMessage { id } => show_message(&id, &paths).await,
        Command::Sync { email } => sync_account(&email, &paths).await,
        Command::HistorySync { email, folder, all } => {
            history_sync_account(&email, folder.as_deref(), all, &paths).await
        }
        Command::Reset { yes } => reset_local_state(yes, &paths).await,
        Command::Doctor {
            fix,
            reset_history_sync,
            rebuild_fts,
            vacuum,
            yes,
        } => doctor(fix, reset_history_sync, rebuild_fts, vacuum, yes, &paths).await,
        Command::Send {
            from,
            to,
            cc,
            bcc,
            subject,
            body,
            body_file,
        } => send_message(&from, &to, &cc, &bcc, &subject, body, body_file, &paths).await,
    }
}

async fn dispatch_auth(action: AuthAction, paths: &DataPaths) -> Result<(), MailcliError> {
    match action {
        AuthAction::Add { provider, email } => auth_add(&provider, &email, paths).await,
        AuthAction::List => auth_list(paths).await,
        AuthAction::Remove { email } => auth_remove(&email, paths).await,
    }
}

async fn auth_add(provider_slug: &str, email: &str, paths: &DataPaths) -> Result<(), MailcliError> {
    let provider = qsl_auth::lookup(provider_slug)
        .ok_or_else(|| MailcliError::Usage(format!("unknown provider: {provider_slug}")))?;

    info!(provider = provider_slug, %email, "starting OAuth2 + PKCE flow");
    let outcome = run_loopback_flow(provider, Some(email)).await?;

    let refresh = outcome.tokens.refresh.ok_or_else(|| {
        MailcliError::Auth(AuthError::TokenExchange(
            "provider did not return a refresh_token; \
             re-run with `prompt=consent` on the server side or add the `offline_access` scope"
                .into(),
        ))
    })?;

    let account_id = AccountId::for_provider(provider_slug, email).map_err(MailcliError::Usage)?;
    // `ProviderKind` is `#[non_exhaustive]`. The fallback keeps future
    // variants (e.g. EAS when/if it becomes relevant — unlikely per
    // DESIGN.md §2, but cheap insurance) from breaking this crate.
    let kind = match provider.profile().kind {
        qsl_auth::ProviderKind::ImapSmtp => BackendKind::ImapSmtp,
        qsl_auth::ProviderKind::Jmap => BackendKind::Jmap,
        _ => {
            return Err(MailcliError::Usage(format!(
                "provider {provider_slug} uses an unsupported backend kind"
            )))
        }
    };
    let account = Account {
        id: account_id.clone(),
        kind: kind.clone(),
        display_name: email.to_string(),
        email_address: email.to_string(),
        created_at: Utc::now(),
        signature: None,
        notify_enabled: true,
    };

    let conn = paths.open_db().await?;
    let vault = TokenVault::new();
    match repos::accounts::find(&conn, &account.id).await? {
        Some(_) => {
            info!("account already present; updating");
            repos::accounts::update(&conn, &account).await?;
        }
        None => {
            repos::accounts::insert(&conn, &account).await?;
        }
    }
    vault.put(&account_id, &refresh).await?;

    println!(
        "added {email} ({} provider, backend={kind:?}, {} scope(s))",
        provider.profile().name,
        outcome.granted_scopes.len(),
    );
    Ok(())
}

async fn auth_list(paths: &DataPaths) -> Result<(), MailcliError> {
    let conn = paths.open_db().await?;
    let vault = TokenVault::new();

    let accounts = repos::accounts::list(&conn).await?;
    if accounts.is_empty() {
        println!("no accounts configured. Use `mailcli auth add <provider> <email>`.");
        return Ok(());
    }
    println!(
        "{:<40}  {:<10}  {:<8}  email",
        "account_id", "backend", "keychain"
    );
    for a in accounts {
        let has_token = vault.contains(&a.id).await.unwrap_or(false);
        println!(
            "{:<40}  {:<10}  {:<8}  {}",
            a.id.0,
            format!("{:?}", a.kind),
            if has_token { "ok" } else { "MISSING" },
            a.email_address
        );
    }
    Ok(())
}

async fn auth_remove(email: &str, paths: &DataPaths) -> Result<(), MailcliError> {
    let conn = paths.open_db().await?;
    let vault = TokenVault::new();

    // Accounts are minted as `<provider>:<email>` but the user only
    // types the email — look up by email and remove every match.
    let accounts = repos::accounts::list(&conn).await?;
    let matches: Vec<_> = accounts
        .into_iter()
        .filter(|a| a.email_address == email)
        .collect();
    if matches.is_empty() {
        return Err(MailcliError::Usage(format!("no account found for {email}")));
    }
    for a in matches {
        vault.delete(&a.id).await?;
        repos::accounts::delete(&conn, &a.id).await?;
        println!("removed {}", a.id.0);
    }
    Ok(())
}

// ---------- reset ----------

/// Wipe local state. Best-effort: each step logs and continues if the
/// next is still possible, so a partial environment (no DB yet, no
/// keychain entries, missing blobs dir) doesn't error out the whole
/// command. Order matters — we list accounts and clear keychain
/// entries *before* deleting the database so we don't lose the
/// account-id list we need to drive `vault.delete`.
async fn reset_local_state(yes: bool, paths: &DataPaths) -> Result<(), MailcliError> {
    let db_path = paths.db_path();
    let blobs_path = paths.data_dir.join("blobs");

    // Enumerate keychain entries from the DB before we delete it. If
    // the DB doesn't exist or fails to open, just skip — the user is
    // wiping anyway.
    let account_ids: Vec<AccountId> = match TursoConn::open(&db_path).await {
        Ok(conn) => {
            // Migrations needed before the accounts table is queryable
            // on a fresh-but-half-baked file. Failure here is
            // non-fatal: we'll just skip keychain cleanup.
            if let Err(e) = run_migrations(&conn).await {
                eprintln!("mailcli reset: skipping keychain cleanup, migrations failed: {e}");
                Vec::new()
            } else {
                match repos::accounts::list(&conn).await {
                    Ok(accounts) => accounts.into_iter().map(|a| a.id).collect(),
                    Err(e) => {
                        eprintln!("mailcli reset: skipping keychain cleanup, list failed: {e}");
                        Vec::new()
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("mailcli reset: skipping keychain cleanup, db open failed: {e}");
            Vec::new()
        }
    };

    println!("Will delete:");
    println!("  database:      {}", db_path.display());
    println!("  blob store:    {}", blobs_path.display());
    if account_ids.is_empty() {
        println!("  keychain:      (no accounts found)");
    } else {
        println!(
            "  keychain:      {} refresh-token entr{}",
            account_ids.len(),
            if account_ids.len() == 1 { "y" } else { "ies" }
        );
    }
    println!();

    if !yes {
        eprint!("Continue? [y/N] ");
        use std::io::Write;
        std::io::stderr().flush().ok();
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| MailcliError::Usage(format!("read confirmation: {e}")))?;
        let trimmed = input.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("aborted.");
            return Ok(());
        }
    }

    let vault = TokenVault::new();
    let mut keychain_removed = 0usize;
    for id in &account_ids {
        match vault.delete(id).await {
            Ok(()) => keychain_removed += 1,
            Err(e) => eprintln!("  keychain delete {} failed (non-fatal): {e}", id.0),
        }
    }

    // Remove the SQLite triplet — `qsl.db` plus the WAL sidecars that
    // Turso may have created. Each is independently optional; missing
    // is fine.
    let mut files_removed = 0usize;
    for suffix in ["", "-wal", "-shm"] {
        let p = db_path.with_extension(format!("db{suffix}"));
        if p.exists() {
            match std::fs::remove_file(&p) {
                Ok(()) => files_removed += 1,
                Err(e) => eprintln!("  remove {} failed: {e}", p.display()),
            }
        }
    }

    let mut blobs_removed = false;
    if blobs_path.exists() {
        match std::fs::remove_dir_all(&blobs_path) {
            Ok(()) => blobs_removed = true,
            Err(e) => eprintln!("  remove {} failed: {e}", blobs_path.display()),
        }
    }

    println!(
        "reset complete: {keychain_removed} keychain entr{}, {files_removed} db file{}, blobs {}",
        if keychain_removed == 1 { "y" } else { "ies" },
        if files_removed == 1 { "" } else { "s" },
        if blobs_removed { "removed" } else { "absent" },
    );
    Ok(())
}

// ---------- doctor ----------

/// Section header in `doctor` output. Kept consistent so a future
/// `--json` flag can swap the formatter without rewriting each check.
/// Flushes stdout so the header lands before the (potentially slow)
/// query that follows — line buffering would otherwise hold the
/// header until the next `println!` and the user couldn't tell which
/// step the doctor is stuck on.
fn print_section(title: &str) {
    use std::io::Write;
    println!();
    println!("== {title} ==");
    let _ = std::io::stdout().flush();
}

/// Progress breadcrumb for individual queries inside a section.
/// Same flush rationale as `print_section` — the integrity check and
/// FK-orphan COUNTs can each take tens of seconds on a large DB and
/// without a flushed marker the run looks frozen.
fn step(msg: &str) {
    use std::io::Write;
    println!("  · {msg}");
    let _ = std::io::stdout().flush();
}

/// Interactive y/N prompt used by destructive doctor repairs.
/// Returns `Ok(true)` when the user confirms, `Ok(false)` otherwise.
/// `yes=true` short-circuits to `true` without reading stdin so
/// scripted invocations don't hang.
fn confirm(prompt: &str, yes: bool) -> Result<bool, MailcliError> {
    if yes {
        return Ok(true);
    }
    use std::io::Write;
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| MailcliError::Usage(format!("read confirmation: {e}")))?;
    let trimmed = input.trim().to_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

/// Audit + (optionally) repair the local DB. Designed for the
/// "everything got weird, what's actually wrong" use case after a
/// crash or upgrade — runs every cheap consistency check we know
/// about and either reports findings (`--fix=false`) or applies the
/// documented repair (`--fix=true`).
///
/// Each check is independent and best-effort: a failure in one
/// section logs and continues so the others still run. Exit code
/// stays 0 unless we hit an unrecoverable error opening the DB —
/// the output is the report, not the exit status.
async fn doctor(
    fix: bool,
    reset_history_sync: bool,
    rebuild_fts: bool,
    vacuum: bool,
    yes: bool,
    paths: &DataPaths,
) -> Result<(), MailcliError> {
    let conn = paths.open_db().await?;
    let any_repair = fix || reset_history_sync || rebuild_fts || vacuum;
    let mode = if any_repair { "REPAIR" } else { "READ-ONLY" };
    println!("qsl doctor — {mode}");
    println!("database: {}", paths.db_path().display());

    // 1. SQLite engine-level integrity. Detects torn pages, bad
    //    indexes, broken WAL frames. There is no automatic repair —
    //    if this fails, the user's recourse is `mailcli reset` and
    //    re-sync from the server.
    print_section("[1/7] schema integrity");
    step("running PRAGMA integrity_check (slow on large DBs — minutes is normal)");
    match conn.query("PRAGMA integrity_check", Params::empty()).await {
        Ok(rows) => {
            let mut all_ok = true;
            for row in &rows {
                let msg = row.get_str("integrity_check").unwrap_or("?");
                if msg == "ok" {
                    println!("  ok");
                } else {
                    all_ok = false;
                    println!("  ! {msg}");
                }
            }
            if !all_ok {
                println!("  (engine-level corruption — repair via `mailcli reset`)");
            }
        }
        Err(e) => println!("  ! integrity_check failed: {e}"),
    }

    // 2. Foreign-key violations. With `PRAGMA foreign_keys=ON` set
    //    on every connection (since `TursoConn::open`) plus migration
    //    0011's one-time orphan sweep, the schema's FK declarations
    //    enforce themselves at write time and there should be no
    //    surviving violations. We sample each account-scoped table
    //    explicitly because Turso 0.5.3 doesn't recognize
    //    `PRAGMA foreign_key_check` (returns "Not a valid pragma
    //    name") — re-implementing the check ourselves keeps the
    //    coverage and avoids depending on Turso shipping the pragma.
    print_section("[2/7] foreign-key violations");
    let fk_orphan_checks: &[(&str, &str)] = &[
        ("folders", "account_id"),
        ("threads", "account_id"),
        ("messages", "account_id"),
        ("outbox", "account_id"),
        ("contacts", "account_id"),
        ("remote_content_opt_ins", "account_id"),
        ("drafts", "account_id"),
        ("history_sync_state", "account_id"),
    ];
    let mut total_orphans = 0u64;
    for (table, col) in fk_orphan_checks {
        step(&format!("scanning {table}"));
        let sql = format!(
            "SELECT COUNT(*) AS n FROM {table} \
             WHERE {col} NOT IN (SELECT id FROM accounts)"
        );
        match conn.query_one(&sql, Params::empty()).await {
            Ok(row) => {
                let n = row.get_i64("n").unwrap_or(0).max(0) as u64;
                if n > 0 {
                    total_orphans += n;
                    println!("  ! {table}: {n} row(s) with no matching accounts.id");
                }
            }
            Err(e) => println!("  ! {table}: query failed: {e}"),
        }
    }
    if total_orphans == 0 {
        println!("  none");
    } else if fix {
        // FK enforcement should make new orphans impossible, but a DB
        // migrated up from the FK-OFF era may still carry rows from
        // accounts that were removed before migration 0011's sweep
        // ran. `--fix` deletes them — the same DELETE that 0011 used,
        // run again at the user's request.
        let mut total_repaired = 0u64;
        for (table, col) in fk_orphan_checks {
            let sql = format!(
                "DELETE FROM {table} \
                 WHERE {col} NOT IN (SELECT id FROM accounts)"
            );
            match conn.execute(&sql, Params::empty()).await {
                Ok(n) => {
                    if n > 0 {
                        total_repaired += n;
                        println!("  repaired: {table} — deleted {n} orphan row(s)");
                    }
                }
                Err(e) => println!("  ! delete on {table} failed: {e}"),
            }
        }
        println!("  (total deleted: {total_repaired})");
    } else {
        println!("  ({total_orphans} orphan(s) total; `--fix` deletes them)");
    }

    // 3. History-sync rows in `running` from a prior crash. By
    //    construction we are running offline, so any `running` row
    //    is stale. Repair: flip back to `pending` so the desktop
    //    app's resume path picks it up cleanly on next launch.
    print_section("[3/7] history-sync stuck `running` rows");
    step("querying history_sync_state");
    let stuck = conn
        .query(
            "SELECT account_id, folder_id FROM history_sync_state WHERE status = ?1",
            Params(vec![Value::Text("running")]),
        )
        .await
        .unwrap_or_default();
    if stuck.is_empty() {
        println!("  none");
    } else {
        for row in &stuck {
            let acct = row.get_str("account_id").unwrap_or("?");
            let folder = row.get_str("folder_id").unwrap_or("?");
            println!("  - {acct} / {folder}");
        }
        if fix {
            let now = Utc::now().timestamp();
            match conn
                .execute(
                    "UPDATE history_sync_state SET status = 'pending', updated_at = ?1 \
                     WHERE status = 'running'",
                    Params(vec![Value::Integer(now)]),
                )
                .await
            {
                Ok(n) => println!("  repaired: {n} row(s) flipped to `pending`"),
                Err(e) => println!("  ! repair failed: {e}"),
            }
        } else {
            println!("  ({} row(s); `--fix` flips to pending)", stuck.len());
        }
    }

    // 4. History-sync rows in `error`. The driver bumps to this
    //    state on a fatal pull failure and `last_error` carries the
    //    message. On `--fix` we flip them back to `pending` so the
    //    desktop's resume path retries on next launch — most errors
    //    are transient (network blip mid-pull, server-side
    //    rate-limit, expired token), and forcing the user to click
    //    "Restart" in Settings for each one isn't useful.
    print_section("[4/7] history-sync `error` rows");
    step("querying history_sync_state");
    let errs = conn
        .query(
            "SELECT account_id, folder_id, last_error \
             FROM history_sync_state WHERE status = ?1",
            Params(vec![Value::Text("error")]),
        )
        .await
        .unwrap_or_default();
    if errs.is_empty() {
        println!("  none");
    } else {
        for row in &errs {
            let acct = row.get_str("account_id").unwrap_or("?");
            let folder = row.get_str("folder_id").unwrap_or("?");
            let last = row
                .get_optional_str("last_error")
                .unwrap_or(None)
                .unwrap_or("(no message)");
            println!("  ! {acct} / {folder}: {last}");
        }
        if fix {
            let now = Utc::now().timestamp();
            match conn
                .execute(
                    "UPDATE history_sync_state \
                     SET status = 'pending', last_error = NULL, updated_at = ?1 \
                     WHERE status = 'error'",
                    Params(vec![Value::Integer(now)]),
                )
                .await
            {
                Ok(n) => println!("  repaired: {n} row(s) flipped to `pending` for retry"),
                Err(e) => println!("  ! repair failed: {e}"),
            }
        } else {
            println!(
                "  ({} row(s); `--fix` flips to pending so they retry)",
                errs.len()
            );
        }
    }

    // 5. Outbox dead-lettered rows (`next_attempt_at IS NULL`).
    //    Drain worker stops retrying past `MAX_ATTEMPTS = 5`. No
    //    auto-repair — the user may want to inspect `last_error`
    //    and decide whether to re-enqueue or drop.
    print_section("[5/7] outbox dead-letter");
    step("querying outbox");
    let dlq = conn
        .query(
            "SELECT id, account_id, op_kind, attempts, last_error \
             FROM outbox WHERE next_attempt_at IS NULL",
            Params::empty(),
        )
        .await
        .unwrap_or_default();
    if dlq.is_empty() {
        println!("  none");
    } else {
        for row in &dlq {
            let id = row.get_str("id").unwrap_or("?");
            let acct = row.get_str("account_id").unwrap_or("?");
            let kind = row.get_str("op_kind").unwrap_or("?");
            let attempts = row.get_i64("attempts").unwrap_or(0);
            let last = row
                .get_optional_str("last_error")
                .unwrap_or(None)
                .unwrap_or("");
            println!("  ! {id} ({acct} / {kind}, {attempts} attempts) {last}");
        }
        println!(
            "  ({} row(s); inspect manually with `sqlite3 {}`)",
            dlq.len(),
            paths.db_path().display()
        );
    }

    // 6. Empty thread shells. Threads with no surviving messages
    //    are leftovers from a delete that didn't (or couldn't, pre
    //    FK-ON) cascade. Safe to drop — no user data lives in the
    //    thread row itself.
    print_section("[6/7] empty thread shells");
    step("scanning threads ⨯ messages (slow on large mailboxes)");
    let empty_threads = conn
        .query(
            "SELECT t.id FROM threads t \
             LEFT JOIN messages m ON m.thread_id = t.id \
             WHERE m.id IS NULL",
            Params::empty(),
        )
        .await
        .unwrap_or_default();
    if empty_threads.is_empty() {
        println!("  none");
    } else {
        for row in empty_threads.iter().take(10) {
            println!("  - {}", row.get_str("id").unwrap_or("?"));
        }
        if empty_threads.len() > 10 {
            println!("  ... and {} more", empty_threads.len() - 10);
        }
        if fix {
            match conn
                .execute(
                    "DELETE FROM threads WHERE id NOT IN (SELECT DISTINCT thread_id FROM messages WHERE thread_id IS NOT NULL)",
                    Params::empty(),
                )
                .await
            {
                Ok(n) => println!("  repaired: {n} empty thread(s) deleted"),
                Err(e) => println!("  ! repair failed: {e}"),
            }
        } else {
            println!("  ({} row(s); `--fix` deletes them)", empty_threads.len());
        }
    }

    // 7. Orphaned accounts: rows in `accounts` whose refresh-token
    //    entry is gone from the OS keychain. The next refresh attempt
    //    would 401 forever — the account is effectively dead. On
    //    `--fix` we delete the row, which (with FK enforcement on)
    //    cascades to every folder / message / thread / outbox / etc.
    //    belonging to that account. Confirmation prompt before each
    //    deletion unless `--yes` is passed; the user might just want
    //    to re-run `mailcli auth add` instead.
    print_section("[7/7] orphaned accounts (no keychain entry)");
    step("listing accounts");
    match repos::accounts::list(&conn).await {
        Ok(accounts) if accounts.is_empty() => println!("  no accounts configured"),
        Ok(accounts) => {
            let vault = TokenVault::new();
            let mut orphans: Vec<AccountId> = Vec::new();
            for a in &accounts {
                step(&format!("checking keychain for {}", a.id.0));
                let present = vault.contains(&a.id).await.unwrap_or(false);
                if !present {
                    orphans.push(a.id.clone());
                    println!("  ! {} — missing keychain entry", a.id.0);
                }
            }
            if orphans.is_empty() {
                println!("  all {} account(s) have keychain entries", accounts.len());
            } else if fix {
                let mut pruned = 0usize;
                for id in &orphans {
                    let prompt = format!("  delete account {} and all its local data?", id.0);
                    match confirm(&prompt, yes) {
                        Ok(true) => match repos::accounts::delete(&conn, id).await {
                            Ok(()) => {
                                pruned += 1;
                                println!("    deleted {} (cascade dropped local data)", id.0);
                            }
                            Err(e) => println!("    ! delete {} failed: {e}", id.0),
                        },
                        Ok(false) => println!("    skipped {}", id.0),
                        Err(e) => {
                            println!("    ! prompt failed: {e}");
                            break;
                        }
                    }
                }
                println!("  ({pruned} account(s) pruned; rerun `mailcli auth add` to re-attach)");
            } else {
                println!(
                    "  ({} account(s); `--fix` prunes them — local data cascades. \
                     Or `mailcli auth add <provider> <email>` to re-attach.)",
                    orphans.len()
                );
            }
        }
        Err(e) => println!("  ! list accounts failed: {e}"),
    }

    // 8. Optional full wipe of history-sync state. Independent of
    //    `--fix` because the intent is different ("start over",
    //    not "repair errors"). Drops every row regardless of
    //    status — completed pulls included — so the user gets a
    //    fresh slate next time they kick off a "Pull full mail
    //    history" from Settings.
    if reset_history_sync {
        print_section("history-sync table — full reset");
        let count = match conn
            .query_one(
                "SELECT COUNT(*) AS n FROM history_sync_state",
                Params::empty(),
            )
            .await
        {
            Ok(row) => row.get_i64("n").unwrap_or(0).max(0) as u64,
            Err(_) => 0,
        };
        if count == 0 {
            println!("  history_sync_state already empty — nothing to do");
        } else {
            println!("  will drop {count} row(s) from history_sync_state");
            if confirm("  proceed?", yes)? {
                match conn
                    .execute("DELETE FROM history_sync_state", Params::empty())
                    .await
                {
                    Ok(n) => println!("  reset: {n} row(s) deleted"),
                    Err(e) => println!("  ! reset failed: {e}"),
                }
            } else {
                println!("  skipped.");
            }
        }
    }

    // 9. Optional FTS rebuild. Tantivy-backed FTS index drift
    //    surfaces in the schema-integrity check as "wrong # of
    //    entries in index __turso_internal_fts_dir_…". When that
    //    drift is present, every `messages::insert` pays a
    //    reconciliation tax — observed as ~1s/insert during a
    //    history-sync pull, vs. sub-millisecond on a healthy index.
    //    Drop + CREATE INDEX rebuilds from existing rows in one bulk
    //    pass; data in `messages` is untouched. Slow on a populated
    //    DB (Turso re-tokenizes every row) but a one-shot fix.
    if rebuild_fts {
        print_section("FTS index rebuild");
        let count = match conn
            .query_one("SELECT COUNT(*) AS n FROM messages", Params::empty())
            .await
        {
            Ok(row) => row.get_i64("n").unwrap_or(0).max(0) as u64,
            Err(_) => 0,
        };
        println!("  will reindex {count} message row(s)");
        if confirm("  proceed?", yes)? {
            // DROP first, then CREATE — `IF EXISTS` / `IF NOT EXISTS`
            // keep both halves idempotent so a partial run can be
            // re-attempted.
            match conn
                .execute("DROP INDEX IF EXISTS messages_fts_idx", Params::empty())
                .await
            {
                Ok(_) => println!("  dropped old index"),
                Err(e) => println!("  ! drop failed: {e}"),
            }
            match conn
                .execute(
                    "CREATE INDEX IF NOT EXISTS messages_fts_idx ON messages \
                     USING fts (subject, from_json, to_json, snippet)",
                    Params::empty(),
                )
                .await
            {
                Ok(_) => println!("  rebuilt index — re-run `mailcli doctor` to confirm clean"),
                Err(e) => println!("  ! rebuild failed: {e}"),
            }
        } else {
            println!("  skipped.");
        }
    }

    // 10. Optional VACUUM. Goal: reclaim pages flagged "Page N:
    //     never used" by the schema-integrity check (allocated but
    //     unreferenced — leaked space, not data corruption).
    //
    //     We can't actually do this on Turso 0.5.3:
    //       - Plain `VACUUM` returns "not supported yet, use VACUUM
    //         INTO 'filename' to create a compacted copy"
    //       - `VACUUM INTO 'path'` panics inside the engine
    //         (turso_core::vdbe::execute → "StepResult::IO returned
    //         but no completions available"), tearing down the whole
    //         process. We can't catch that from the conn.execute
    //         match arm — Rust panics in foreign code don't return
    //         as Err.
    //
    //     Until Turso ships a working VACUUM, the only way to
    //     reclaim leaked pages is `mailcli reset --yes` followed by a
    //     re-add (the messages get re-pulled from the server, the
    //     leaked pages are gone with the old file). The leaked pages
    //     themselves are cosmetic — they don't hurt query speed; the
    //     FTS index drift was the perf bottleneck and `--rebuild-fts`
    //     handles that one. Leaving the flag wired so the help text
    //     stays discoverable, but emitting a clear bail message
    //     rather than crashing.
    if vacuum {
        print_section("VACUUM");
        println!("  skipped — Turso 0.5.3 has no working VACUUM:");
        println!("    plain VACUUM is unimplemented");
        println!("    VACUUM INTO panics in turso_core::vdbe::execute");
        println!();
        println!("  the leaked-pages report from the schema-integrity");
        println!("  check is cosmetic — it doesn't slow queries. Run");
        println!("  `mailcli reset --yes` and re-add your account if you");
        println!("  want a physically-compact file. (Track upstream for");
        println!("  the fix — once Turso ships a working VACUUM, switch");
        println!("  this section to the working call.)");
    }

    println!();
    if any_repair {
        println!("doctor: repair pass complete.");
    } else {
        println!("doctor: read-only pass complete. Re-run with `--fix` to apply repairs.");
    }
    Ok(())
}

// ---------- read path commands ----------

async fn resolve_account(conn: &TursoConn, email: &str) -> Result<qsl_core::Account, MailcliError> {
    let accounts = repos::accounts::list(conn).await?;
    accounts
        .into_iter()
        .find(|a| a.email_address == email)
        .ok_or_else(|| {
            MailcliError::Usage(format!(
                "no account found for {email}; run `mailcli auth add`"
            ))
        })
}

fn provider_slug_from_id(id: &AccountId) -> Option<&str> {
    id.0.split_once(':').map(|(slug, _)| slug)
}

/// Build a live [`MailBackend`] for an account by refreshing its access
/// token and handing it to the right adapter.
async fn open_backend(account: &Account) -> Result<Box<dyn MailBackend>, MailcliError> {
    let slug = provider_slug_from_id(&account.id).ok_or_else(|| {
        MailcliError::Usage(format!(
            "account id {} does not follow `<provider>:<email>`",
            account.id.0
        ))
    })?;
    let provider = provider_lookup(slug)
        .ok_or_else(|| MailcliError::Usage(format!("unknown provider: {slug}")))?;
    let vault = TokenVault::new();
    let token_set = refresh_access_token(provider, &vault, &account.id).await?;

    match account.kind {
        BackendKind::ImapSmtp => {
            let host = match slug {
                "gmail" => "imap.gmail.com",
                other => {
                    return Err(MailcliError::Usage(format!(
                        "no hardcoded IMAP host for provider {other}; \
                         set one in qsl-imap-client before connecting"
                    )))
                }
            };
            let backend = ImapBackend::connect_tls(
                host,
                993,
                &account.email_address,
                token_set.access.expose(),
                account.id.clone(),
            )
            .await?;
            Ok(Box::new(backend))
        }
        BackendKind::Jmap => {
            let session_url = match slug {
                "fastmail" => "https://api.fastmail.com/.well-known/jmap",
                other => {
                    return Err(MailcliError::Usage(format!(
                        "no hardcoded JMAP session URL for provider {other}"
                    )))
                }
            };
            let backend = JmapBackend::connect(
                session_url,
                token_set.access.expose(),
                account.id.clone(),
                &account.email_address,
            )
            .await
            .map_err(MailcliError::Mail)?;
            Ok(Box::new(backend))
        }
        _ => Err(MailcliError::Usage(format!(
            "account {} uses an unsupported backend kind",
            account.id.0
        ))),
    }
}

async fn list_folders(email: &str, paths: &DataPaths) -> Result<(), MailcliError> {
    let conn = paths.open_db().await?;
    let account = resolve_account(&conn, email).await?;
    let backend = open_backend(&account).await?;
    let folders = backend.list_folders().await?;

    println!(
        "{:<24}  {:<12}  {:>7}  {:>7}  path",
        "id", "role", "unread", "total"
    );
    for f in folders {
        let role = f
            .role
            .as_ref()
            .map(|r| format!("{r:?}"))
            .unwrap_or_default();
        let truncated_id: String = f.id.0.chars().take(24).collect();
        println!(
            "{:<24}  {:<12}  {:>7}  {:>7}  {}",
            truncated_id, role, f.unread_count, f.total_count, f.path
        );
    }
    Ok(())
}

async fn list_messages(
    email: &str,
    folder: &str,
    limit: u32,
    paths: &DataPaths,
) -> Result<(), MailcliError> {
    let conn = paths.open_db().await?;
    let account = resolve_account(&conn, email).await?;
    let backend = open_backend(&account).await?;
    // CLI users type the wire mailbox name; the backend expects the
    // account-scoped storage id.
    let fid = FolderId::scoped(&account.id, folder);

    let out = backend.list_messages(&fid, None, Some(limit)).await?;
    println!("{:<12}  {:<20}  {:<32}  subject", "flags", "from", "date");
    for m in &out.messages {
        let flags = format!(
            "{}{}{}",
            if m.flags.seen { "R" } else { "U" },
            if m.flags.flagged { "*" } else { " " },
            if m.flags.answered { "↩" } else { " " },
        );
        let from = m
            .from
            .first()
            .map(|a| a.address.clone())
            .unwrap_or_default();
        let from: String = from.chars().take(20).collect();
        println!(
            "{:<12}  {:<20}  {:<32}  {}",
            flags,
            from,
            m.date.to_rfc3339(),
            m.subject
        );
    }
    println!(
        "({} messages; new sync cursor persisted on next `sync`)",
        out.messages.len()
    );
    Ok(())
}

async fn show_message(id: &str, _paths: &DataPaths) -> Result<(), MailcliError> {
    // Decoding the id tells us which account (by provider slug for
    // IMAP; opaque for JMAP). For Phase 0 we just say "look it up once
    // you know the account" — the user passes an account email
    // separately in future revisions. Today the command is a
    // placeholder to prove the CLI shape.
    Err(MailcliError::Usage(format!(
        "`show-message {id}` needs an --email selector; \
         today `list-messages` prints ids in a debuggable format and \
         `show-message` with an account hint lands in Phase 1 Week 1"
    )))
}

async fn sync_account(email: &str, paths: &DataPaths) -> Result<(), MailcliError> {
    use std::time::Instant;

    let conn = paths.open_db().await?;
    let account = resolve_account(&conn, email).await?;
    let backend = open_backend(&account).await?;
    let blobs = qsl_storage::BlobStore::new(paths.data_dir.join("blobs"));

    let start = Instant::now();
    let outcomes = qsl_sync::sync_account(&conn, backend.as_ref(), Some(&blobs), Some(200)).await?;
    let duration = start.elapsed();

    // Aggregate counts across every folder we visited; print one
    // line per folder for visibility on partial failures.
    let mut total = qsl_sync::SyncReport::default();
    for outcome in &outcomes {
        match &outcome.result {
            Ok(report) => {
                println!(
                    "  {}: {} new, {} updated, {} flag deltas, {} removed, {} bodies ({} failed)",
                    outcome.folder_id.0,
                    report.added,
                    report.updated,
                    report.flag_updates,
                    report.removed,
                    report.bodies_fetched,
                    report.bodies_failed,
                );
                total.added += report.added;
                total.updated += report.updated;
                total.flag_updates += report.flag_updates;
                total.removed += report.removed;
                total.bodies_fetched += report.bodies_fetched;
                total.bodies_failed += report.bodies_failed;
            }
            Err(e) => {
                println!("  {}: FAILED — {}", outcome.folder_id.0, e);
            }
        }
    }
    println!(
        "Total: {} new, {} updated, {} flag deltas, {} removed, {} bodies ({} failed) across {} folders in {} ms",
        total.added,
        total.updated,
        total.flag_updates,
        total.removed,
        total.bodies_fetched,
        total.bodies_failed,
        outcomes.len(),
        duration.as_millis()
    );
    Ok(())
}

/// Drive `qsl_sync::history::pull_history` from the CLI without the
/// desktop's UI in the loop. Used to test backfill perf (chunk size,
/// `batch_insert_skip_existing` throughput) on real Gmail/Fastmail
/// accounts.
///
/// Resolves the anchor from each folder's lowest local UID — same
/// rule the desktop's `compute_start_metrics` follows. Folders with
/// no local rows are skipped (run `mailcli sync <email>` first to
/// seed them). Folders run sequentially: history-sync uses the
/// per-account IMAP session and parallelizing them just thrashes.
async fn history_sync_account(
    email: &str,
    only_folder: Option<&str>,
    all: bool,
    paths: &DataPaths,
) -> Result<(), MailcliError> {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::Mutex;

    if only_folder.is_none() && !all {
        return Err(MailcliError::Usage(
            "history-sync: pass --folder <name> or --all".into(),
        ));
    }

    let conn = paths.open_db().await?;
    let account = resolve_account(&conn, email).await?;
    let backend = open_backend(&account).await?;

    // Snapshot the locally-known folder rows; pull_history needs a
    // local FolderId (the row already lives in the folders table from
    // the bootstrap sync). We don't open the IMAP session ourselves
    // for folder enumeration — the bootstrap should already have
    // populated them via `mailcli sync`.
    let folders = repos::folders::list_by_account(&conn, &account.id).await?;
    let targets: Vec<_> = if let Some(name) = only_folder {
        folders
            .into_iter()
            .filter(|f| f.name == name || f.id.0 == name || f.id.backend_key(&account.id) == name)
            .collect()
    } else {
        folders
    };

    if targets.is_empty() {
        return Err(MailcliError::Usage(format!(
            "history-sync: no matching folder rows. \
             Run `mailcli sync {email}` first so the folder list is populated."
        )));
    }

    // Wrap the conn for `pull_history` (it requires shared access
    // since the driver locks per-chunk).
    let conn = Arc::new(Mutex::new(conn));
    let cancel = Arc::new(AtomicBool::new(false));

    let total_start = Instant::now();
    let mut completed = 0u32;
    let mut skipped = 0u32;
    let mut errored = 0u32;

    for folder in targets {
        // Anchor = lowest local UID. Skip folders the bootstrap
        // hasn't touched yet — the desktop refuses these too.
        let anchor = {
            let db = conn.lock().await;
            let ids = repos::messages::list_ids_by_folder(&*db, &folder.id).await?;
            ids.iter()
                .filter_map(|m| qsl_imap_client::MessageRef::decode(m).ok())
                .map(|r| u64::from(r.uid))
                .min()
        };
        let Some(anchor) = anchor else {
            println!(
                "  {}: skipped (no local messages — run `sync` first)",
                folder.name
            );
            skipped += 1;
            continue;
        };
        if anchor <= 1 {
            println!("  {}: nothing to backfill (anchor at UID 1)", folder.name);
            completed += 1;
            continue;
        }
        let estimate = anchor.saturating_sub(1);

        println!(
            "  {}: starting (anchor uid={}, estimate ~{} messages)…",
            folder.name, anchor, estimate
        );
        let folder_start = Instant::now();
        let folder_label = folder.name.clone();
        let progress_cb = move |p: qsl_sync::history::HistoryProgress| {
            // Single-line progress with carriage-return so the
            // terminal updates in place. Emit on every chunk;
            // `pull_history` already coalesces to chunk granularity.
            let pct = match p.total_estimate {
                Some(total) if total > 0 => format!(
                    "{:.0}%",
                    (p.fetched_total as f64 / total as f64 * 100.0).clamp(0.0, 100.0)
                ),
                _ => "?".to_string(),
            };
            print!(
                "\r    {} fetched (anchor {}, {})         ",
                p.fetched_total, p.anchor_uid, pct
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();
        };

        match qsl_sync::history::pull_history(
            conn.clone(),
            backend.as_ref(),
            &account.id,
            &folder.id,
            anchor,
            Some(estimate),
            cancel.clone(),
            progress_cb,
        )
        .await
        {
            Ok(()) => {
                println!(
                    "\n  {}: complete in {} ms",
                    folder_label,
                    folder_start.elapsed().as_millis()
                );
                completed += 1;
            }
            Err(e) => {
                println!("\n  {}: FAILED — {}", folder_label, e);
                errored += 1;
            }
        }
    }

    println!(
        "Total: {} folder(s) complete, {} skipped (no anchor), {} errored — {} ms",
        completed,
        skipped,
        errored,
        total_start.elapsed().as_millis()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_message(
    from_email: &str,
    to: &[String],
    cc: &[String],
    bcc: &[String],
    subject: &str,
    body: Option<String>,
    body_file: Option<PathBuf>,
    paths: &DataPaths,
) -> Result<(), MailcliError> {
    let body = match (body, body_file) {
        (Some(b), None) => b,
        (None, Some(p)) => std::fs::read_to_string(&p)
            .map_err(|e| MailcliError::Usage(format!("read --body-file {}: {e}", p.display())))?,
        (None, None) => {
            return Err(MailcliError::Usage(
                "send: provide either --body or --body-file".into(),
            ))
        }
        (Some(_), Some(_)) => {
            return Err(MailcliError::Usage(
                "send: --body and --body-file are mutually exclusive".into(),
            ))
        }
    };

    let conn = paths.open_db().await?;
    let account = resolve_account(&conn, from_email).await?;

    let now = Utc::now();
    let draft = Draft {
        id: DraftId(format!("smoke-{}", now.timestamp_nanos_opt().unwrap_or(0))),
        account_id: account.id.clone(),
        in_reply_to: None,
        references: Vec::new(),
        to: to.iter().map(|s| parse_addr(s)).collect(),
        cc: cc.iter().map(|s| parse_addr(s)).collect(),
        bcc: bcc.iter().map(|s| parse_addr(s)).collect(),
        subject: subject.to_string(),
        body,
        body_kind: DraftBodyKind::Plain,
        attachments: Vec::new(),
        created_at: now,
        updated_at: now,
    };
    let from = EmailAddress {
        address: account.email_address.clone(),
        display_name: Some(account.display_name.clone()),
    };
    let built = qsl_mime::compose::build_rfc5322(&draft, &from)
        .map_err(|e| MailcliError::Usage(format!("build_rfc5322: {e}")))?;

    let backend = open_backend(&account).await?;
    backend
        .submit_message(&built.bytes)
        .await
        .map_err(MailcliError::Mail)?;

    println!(
        "Sent {} from {} to {} recipient(s)",
        built.message_id,
        account.email_address,
        to.len() + cc.len() + bcc.len()
    );
    Ok(())
}

/// Parse a CLI address argument into an `EmailAddress`. Accepts a bare
/// `addr@domain` — display-name parsing (`Name <addr@dom>`) is overkill
/// for the smoke-test surface and would fight clap's value parsing.
fn parse_addr(s: &str) -> EmailAddress {
    EmailAddress {
        address: s.trim().to_string(),
        display_name: None,
    }
}

// ---------- paths + DB ----------

struct DataPaths {
    data_dir: PathBuf,
}

impl DataPaths {
    fn resolve(override_dir: Option<&std::path::Path>) -> Result<Self, MailcliError> {
        let data_dir = match override_dir {
            Some(p) => p.to_path_buf(),
            None => ProjectDirs::from("app", "qsl", "qsl")
                .ok_or_else(|| {
                    MailcliError::Usage(
                        "could not resolve OS data directory; pass --data-dir".into(),
                    )
                })?
                .data_dir()
                .to_path_buf(),
        };
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| MailcliError::Usage(format!("create {data_dir:?}: {e}")))?;
        Ok(Self { data_dir })
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("qsl.db")
    }

    async fn open_db(&self) -> Result<TursoConn, MailcliError> {
        let path = self.db_path();
        let conn = TursoConn::open(&path).await?;
        run_migrations(&conn).await?;
        Ok(conn)
    }
}

// ---------- error type ----------

#[derive(Debug, thiserror::Error)]
enum MailcliError {
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Mail(#[from] MailError),
    #[error(transparent)]
    Storage(#[from] qsl_core::StorageError),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

impl From<qsl_sync::SyncError> for MailcliError {
    fn from(e: qsl_sync::SyncError) -> Self {
        match e {
            qsl_sync::SyncError::Mail(m) => MailcliError::Mail(m),
            qsl_sync::SyncError::Storage(s) => MailcliError::Storage(s),
        }
    }
}
