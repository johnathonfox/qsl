// SPDX-License-Identifier: Apache-2.0

//! Opaque identifier newtypes used throughout the core.
//!
//! Each type wraps a `String` chosen by the backend that minted it. The core
//! never parses or interprets the inner string — for IMAP, a [`MessageId`]
//! encodes `<folder_uid_validity>:<uid>`; for JMAP it's the opaque email id
//! issued by the server. Callers should treat these values as bytes-on-the-
//! wire and compare them only for equality.

use serde::{Deserialize, Serialize};

/// Identifies an `Account` inside QSL's local storage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountId(pub String);

impl AccountId {
    /// Mint the canonical `<provider>:<email>` id for a new account,
    /// validating the user-typed email first. The id doubles as the
    /// OS-keychain entry name, the blob-store directory name, and the
    /// prefix of every [`FolderId`] in the account, so it must be a
    /// single clean token: no whitespace or control characters, no
    /// [`FolderId::SCOPE_SEP`], and a plausible `local@domain` shape.
    pub fn for_provider(provider: &str, email: &str) -> Result<Self, String> {
        let email = email.trim();
        if email.is_empty() {
            return Err("email address is empty".into());
        }
        if email
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == FolderId::SCOPE_SEP)
        {
            return Err(format!(
                "email address {email:?} contains whitespace, control, or '{}' characters",
                FolderId::SCOPE_SEP
            ));
        }
        match email.split_once('@') {
            Some((local, domain))
                if !local.is_empty() && !domain.is_empty() && !domain.contains('@') => {}
            _ => {
                return Err(format!(
                    "email address {email:?} is not of the form local@domain"
                ))
            }
        }
        if provider.is_empty()
            || provider
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        {
            return Err(format!(
                "provider slug {provider:?} is not a plain identifier"
            ));
        }
        Ok(AccountId(format!("{provider}:{email}")))
    }
}

/// Identifies a folder or mailbox inside an account.
///
/// `folders.id` is a global primary key in local storage, but the
/// names backends hand us are only unique *within* an account —
/// every IMAP account has an `INBOX`, and JMAP mailbox ids are only
/// guaranteed unique per account. Two accounts syncing the same
/// bare name would take turns re-owning one row, sharing one sync
/// cursor, and pruning each other's messages. So every backend
/// mints folder ids through [`FolderId::scoped`], which prefixes the
/// owning account, and recovers the wire name through
/// [`FolderId::backend_key`].
///
/// Encoding: `<account_id>|<backend_key>`. `|` can't appear in an
/// account id (`<provider>:<email>` — see the validation in the
/// account-add path), so splitting on the *first* `|` is
/// unambiguous even when the backend key itself contains `|`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FolderId(pub String);

impl FolderId {
    /// Separator between the account prefix and the backend's own
    /// key. Rejected in account ids at creation time so it never
    /// appears in the prefix.
    pub const SCOPE_SEP: char = '|';

    /// Mint the storage id for `backend_key` (an IMAP mailbox path,
    /// a JMAP mailbox id) owned by `account`.
    pub fn scoped(account: &AccountId, backend_key: &str) -> Self {
        FolderId(format!("{}{}{}", account.0, Self::SCOPE_SEP, backend_key))
    }

    /// The backend's own name for this folder — what goes on the
    /// wire (`SELECT`, `inMailbox`, …). Strips the `account` prefix
    /// when present. A raw, unscoped id (legacy rows, test fixtures)
    /// is returned unchanged so callers degrade gracefully instead of
    /// addressing a mailbox that doesn't exist.
    pub fn backend_key<'a>(&'a self, account: &AccountId) -> &'a str {
        self.0
            .strip_prefix(account.0.as_str())
            .and_then(|rest| rest.strip_prefix(Self::SCOPE_SEP))
            .unwrap_or(&self.0)
    }

    /// Account-agnostic view of the backend key, for display code
    /// that has only the id in hand. Everything after the first
    /// [`Self::SCOPE_SEP`]; the whole string if there is none.
    pub fn display_key(&self) -> &str {
        self.0
            .split_once(Self::SCOPE_SEP)
            .map(|(_, key)| key)
            .unwrap_or(&self.0)
    }
}

/// Identifies a single message. Backend-specific encoding; see the module
/// docs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(pub String);

/// Identifies a thread (conversation). Either the backend's native thread id
/// (Gmail `X-GM-THRID`, JMAP thread id) or a synthetic id minted by
/// `crates/sync` when the backend doesn't expose one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThreadId(pub String);

/// Identifies a draft under construction. Distinct from [`MessageId`] because
/// drafts may not yet have been persisted server-side.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DraftId(pub String);

/// Identifies an attachment within its parent message. Not unique across
/// messages.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttachmentRef(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_serializes_transparently() {
        let id = AccountId("gmail:foo@example.com".into());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"gmail:foo@example.com\"");
        let round: AccountId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, round);
    }

    #[test]
    fn account_id_for_provider_validates_email_shape() {
        assert_eq!(
            AccountId::for_provider("gmail", " alice@example.com ").unwrap(),
            AccountId("gmail:alice@example.com".into())
        );
        for bad in [
            "",
            "alice",
            "@example.com",
            "alice@",
            "a@b@c",
            "alice @example.com",
            "alice@exa|mple.com",
            "alice@exam\nple.com",
        ] {
            assert!(
                AccountId::for_provider("gmail", bad).is_err(),
                "{bad:?} accepted"
            );
        }
        assert!(AccountId::for_provider("g mail", "alice@example.com").is_err());
        assert!(AccountId::for_provider("", "alice@example.com").is_err());
    }

    #[test]
    fn folder_ids_are_scoped_per_account_and_round_trip_the_backend_key() {
        let a = AccountId("gmail:alice@example.com".into());
        let b = AccountId("gmail:bob@example.com".into());
        let fa = FolderId::scoped(&a, "INBOX");
        let fb = FolderId::scoped(&b, "INBOX");
        assert_ne!(fa, fb, "two accounts' INBOX must not share a storage id");
        assert_eq!(fa.backend_key(&a), "INBOX");
        assert_eq!(fb.backend_key(&b), "INBOX");
        assert_eq!(fa.display_key(), "INBOX");

        // Backend keys may themselves contain the separator or the
        // account id; only the leading prefix is stripped.
        let weird = FolderId::scoped(&a, "odd|name|gmail:alice@example.com");
        assert_eq!(weird.backend_key(&a), "odd|name|gmail:alice@example.com");
        assert_eq!(weird.display_key(), "odd|name|gmail:alice@example.com");

        // Legacy / unscoped ids degrade to themselves rather than to
        // an empty or truncated mailbox name.
        let legacy = FolderId("[Gmail]/All Mail".into());
        assert_eq!(legacy.backend_key(&a), "[Gmail]/All Mail");
        assert_eq!(legacy.display_key(), "[Gmail]/All Mail");

        // Asking with the wrong account does not strip someone
        // else's prefix.
        assert_eq!(fa.backend_key(&b), fa.0);
    }

    #[test]
    fn distinct_types_with_identical_strings_are_not_interchangeable() {
        let m = MessageId("abc".into());
        let f = FolderId("abc".into());
        // This is a compile-time guarantee — the assertion is only here to
        // document intent.
        assert_eq!(m.0, f.0);
    }
}
