// SPDX-License-Identifier: Apache-2.0

//! Search query parser.
//!
//! Translates Gmail-style operator syntax (`from:alice subject:invoice
//! is:unread before:2026-01-01`) into two pieces the storage layer
//! consumes:
//!
//!   - A **Tantivy match expression** — the string we hand to
//!     `fts_match()` / `fts_score()` against the messages index.
//!     Operator-scoped terms (`from:alice`) become Tantivy column
//!     filters (`from_json:alice`) so a sender match doesn't have to
//!     compete with body / subject matches in BM25.
//!   - A **structured filter** — the predicates that don't live in
//!     the FTS index (date range, labels, unread state). The storage
//!     layer turns these into SQL `WHERE` clauses concatenated with
//!     the FTS predicate.
//!
//! Pure-string in, pure data out — no DB types here, no IPC. The
//! storage repo (`qsl_storage::repos::search`) and the desktop's
//! search command pull this crate in through `qsl-search`.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};

/// Which indexed column an operator like `from:alice` targets. Only
/// the FTS-indexed columns get an enum here; non-FTS predicates
/// (date range, unread flag, labels) live as their own typed fields
/// on [`Query`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchField {
    From,
    To,
    Subject,
}

impl SearchField {
    /// Tantivy column name. Must match the index DDL in
    /// `crates/storage/migrations/0005_search_fts.sql`.
    pub fn tantivy_column(self) -> &'static str {
        match self {
            SearchField::From => "from_json",
            SearchField::To => "to_json",
            SearchField::Subject => "subject",
        }
    }
}

/// Parsed query, ready for the storage layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// Free-text terms that go to `fts_match` against every column.
    pub fts_terms: Vec<String>,
    /// Field-scoped FTS predicates: `from:alice` → `(From, "alice")`.
    pub fts_fields: Vec<(SearchField, String)>,
    /// `is:unread` (true) or `is:read` (false). `None` = either.
    pub is_unread: Option<bool>,
    /// `has:attachment` (true) or `has:noattachment` (false). `None`
    /// = either.
    pub has_attachment: Option<bool>,
    /// `before:2026-01-01` → date is < midnight UTC of that day.
    pub before: Option<DateTime<Utc>>,
    /// `after:2026-01-01` → date is >= midnight UTC of that day.
    pub after: Option<DateTime<Utc>>,
    /// `in:label_name` — restrict to messages bearing this Gmail
    /// label / IMAP folder name. Plain string, not normalized.
    pub label: Option<String>,
}

impl Query {
    /// True when the query has at least one FTS predicate. Callers
    /// use this to decide whether to call `fts_match()` at all (a
    /// purely structured query like `is:unread before:2026-01-01`
    /// can short-circuit to a regular SELECT against `messages`).
    pub fn has_fts(&self) -> bool {
        !self.fts_terms.is_empty() || !self.fts_fields.is_empty()
    }

    /// True when the query has no FTS *and* no structured predicates
    /// — the parser saw nothing actionable. Callers use this to
    /// short-circuit to "no search" rather than running an unbounded
    /// SELECT against `messages`.
    pub fn is_empty(&self) -> bool {
        !self.has_fts()
            && self.is_unread.is_none()
            && self.has_attachment.is_none()
            && self.before.is_none()
            && self.after.is_none()
            && self.label.is_none()
    }

    /// Render the FTS-side predicates as a Tantivy query string.
    /// Returns `None` when the query has no FTS predicates.
    ///
    /// Multiple terms / field filters are joined with implicit AND
    /// (Tantivy's default-conjunction mode). Quoted phrases and
    /// other Tantivy syntax features pass through untouched — the
    /// parser only adds field scoping.
    pub fn to_tantivy_string(&self) -> Option<String> {
        if !self.has_fts() {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        for term in &self.fts_terms {
            parts.push(escape_for_tantivy(term));
        }
        for (field, value) in &self.fts_fields {
            parts.push(format!(
                "{}:{}",
                field.tantivy_column(),
                escape_for_tantivy(value)
            ));
        }
        Some(parts.join(" AND "))
    }
}

/// Parse one operator-laced query string into a [`Query`].
///
/// The parser recognises the following operators (all
/// case-insensitive on the operator name; values are kept as
/// the user typed them so display-name matching still works):
///
///   - `from:` / `to:` / `subject:` — field-scoped FTS terms.
///   - `is:unread` / `is:read` — flag predicate.
///   - `has:attachment` / `has:noattachment` — flag predicate.
///   - `before:YYYY-MM-DD` / `after:YYYY-MM-DD` — date range.
///   - `in:LABEL` — label / folder restriction.
///
/// Everything else (bare words, quoted phrases) becomes a free-text
/// FTS term. Unknown operators are treated as bare words so a
/// future `older:7d` syntax tweak doesn't break existing queries.
pub fn parse(input: &str) -> Query {
    let mut q = Query::default();
    for token in tokenize(input) {
        if let Some((op, value)) = split_operator(&token) {
            apply_operator(&mut q, op, value);
        } else {
            q.fts_terms.push(token);
        }
    }
    q
}

/// Split on whitespace, but respect `"…"` quoted runs. A `"` opens a
/// quoted token that continues (including its closing `"`) until
/// the next `"`.
fn tokenize(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => {
                current.push(ch);
                in_quotes = !in_quotes;
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Operator names the parser understands. Anything else with a colon
/// in it (`http://x`, `10:30`, `re:`) is an ordinary search term —
/// treating it as an operator used to re-emit it verbatim into the
/// Tantivy query, where `http:` parses as an unknown field and the
/// whole search errors out.
const KNOWN_OPERATORS: &[&str] = &[
    "from", "to", "subject", "is", "has", "before", "after", "in",
];

/// If `token` starts with `op:` where `op` is a known operator name,
/// return `(op, value)`. Otherwise `None`. Values can be empty
/// (`from:`) — those tokens just get dropped on the floor by
/// [`apply_operator`].
fn split_operator(token: &str) -> Option<(&str, &str)> {
    let (head, tail) = token.split_once(':')?;
    if head.is_empty()
        || !KNOWN_OPERATORS
            .iter()
            .any(|op| op.eq_ignore_ascii_case(head))
    {
        return None;
    }
    Some((head, tail))
}

fn apply_operator(q: &mut Query, op: &str, value: &str) {
    let op_lower = op.to_ascii_lowercase();
    let value = value.trim_matches('"');
    match op_lower.as_str() {
        "from" if !value.is_empty() => {
            q.fts_fields.push((SearchField::From, value.to_string()));
        }
        "to" if !value.is_empty() => {
            q.fts_fields.push((SearchField::To, value.to_string()));
        }
        "subject" if !value.is_empty() => {
            q.fts_fields.push((SearchField::Subject, value.to_string()));
        }
        "is" => match value.to_ascii_lowercase().as_str() {
            "unread" => q.is_unread = Some(true),
            "read" => q.is_unread = Some(false),
            // Unknown `is:` value: round-trip as a bare term so the
            // user gets a search hit on the literal text rather
            // than a silent no-op.
            other if !other.is_empty() => q.fts_terms.push(format!("is:{other}")),
            _ => {}
        },
        "has" => match value.to_ascii_lowercase().as_str() {
            "attachment" => q.has_attachment = Some(true),
            "noattachment" => q.has_attachment = Some(false),
            other if !other.is_empty() => q.fts_terms.push(format!("has:{other}")),
            _ => {}
        },
        "before" => {
            if let Some(dt) = parse_iso_date(value) {
                q.before = Some(dt);
            }
        }
        "after" => {
            if let Some(dt) = parse_iso_date(value) {
                q.after = Some(dt);
            }
        }
        "in" if !value.is_empty() => {
            q.label = Some(value.to_string());
        }
        // Unknown operator — keep the literal text as a term so
        // syntax we haven't taught the parser yet still surfaces
        // some result rather than a silent empty.
        _ => q.fts_terms.push(format!("{op}:{value}")),
    }
}

/// Parse `YYYY-MM-DD` to midnight UTC. Anything else returns `None`
/// — the caller drops the operator silently rather than aborting
/// the whole query, so a typo in `before:` doesn't blank the
/// results page.
fn parse_iso_date(s: &str) -> Option<DateTime<Utc>> {
    let date = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    let time = date.and_hms_opt(0, 0, 0)?;
    Utc.from_local_datetime(&time).single()
}

/// Render one user term as a Tantivy query atom that searches for the
/// literal text.
///
/// Tantivy's query grammar gives meaning to `: ^ ~ * ? + - ( ) [ ] { }
/// " \`, to the words `AND` / `OR` / `NOT`, and to leading `-`/`+`.
/// A user typing a URL, a time, a lone `(` or an unbalanced quote
/// would otherwise produce a parse error (surfaced as an IPC error)
/// or an empty result instead of a text match. Rule: plain
/// alphanumeric words pass through; everything else is wrapped in a
/// phrase query with embedded `"` and `\` escaped. A term the user
/// quoted themselves is normalised the same way (outer quotes
/// stripped, re-quoted) so an unbalanced `"` can't leak.
fn escape_for_tantivy(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // User-supplied quotes: take the inside, then re-quote below.
    let inner = trimmed.trim_matches('"');
    if inner.is_empty() {
        return String::new();
    }
    let is_plain_word = inner
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '_' | '@' | '.' | '\''))
        && !inner.starts_with('.')
        && !matches!(inner.to_ascii_uppercase().as_str(), "AND" | "OR" | "NOT");
    if is_plain_word {
        return inner.to_string();
    }
    let mut out = String::with_capacity(inner.len() + 2);
    out.push('"');
    for ch in inner.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ymd(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn empty_input_yields_empty_query() {
        let q = parse("");
        assert!(q.is_empty());
        assert!(!q.has_fts());
        assert!(q.is_unread.is_none());
        assert!(q.before.is_none());
        assert!(q.label.is_none());
        assert_eq!(q.to_tantivy_string(), None);
    }

    #[test]
    fn bare_words_are_fts_terms() {
        let q = parse("invoice quarter");
        assert_eq!(q.fts_terms, vec!["invoice", "quarter"]);
        assert!(q.fts_fields.is_empty());
        assert_eq!(
            q.to_tantivy_string().as_deref(),
            Some("invoice AND quarter")
        );
    }

    #[test]
    fn from_subject_operators_route_to_fts_fields() {
        let q = parse("from:alice subject:invoice");
        assert!(q.fts_terms.is_empty());
        assert_eq!(
            q.fts_fields,
            vec![
                (SearchField::From, "alice".to_string()),
                (SearchField::Subject, "invoice".to_string()),
            ]
        );
        assert_eq!(
            q.to_tantivy_string().as_deref(),
            Some("from_json:alice AND subject:invoice")
        );
    }

    #[test]
    fn structured_only_query_skips_fts() {
        let q = parse("is:unread before:2026-01-01");
        assert!(!q.has_fts());
        assert_eq!(q.is_unread, Some(true));
        assert_eq!(q.before, Some(ymd(2026, 1, 1)));
        assert_eq!(q.to_tantivy_string(), None);
        assert!(!q.is_empty());
    }

    #[test]
    fn after_and_before_combine() {
        let q = parse("after:2026-01-01 before:2026-02-01");
        assert_eq!(q.after, Some(ymd(2026, 1, 1)));
        assert_eq!(q.before, Some(ymd(2026, 2, 1)));
    }

    #[test]
    fn malformed_dates_drop_silently() {
        let q = parse("before:not-a-date");
        assert!(q.before.is_none());
        // Doesn't crash, doesn't move the malformed token to
        // fts_terms either — surfacing `before:not-a-date` as a
        // free-text search would be worse than silently ignoring
        // the bad operator.
    }

    #[test]
    fn has_attachment_variants() {
        let q = parse("has:attachment");
        assert_eq!(q.has_attachment, Some(true));
        let q = parse("has:noattachment");
        assert_eq!(q.has_attachment, Some(false));
    }

    #[test]
    fn in_label_round_trips() {
        let q = parse("in:Important");
        assert_eq!(q.label.as_deref(), Some("Important"));
    }

    #[test]
    fn quoted_phrase_is_one_token() {
        let q = parse("\"q1 invoice\" alice");
        assert_eq!(q.fts_terms, vec!["\"q1 invoice\"", "alice"]);
    }

    #[test]
    fn unknown_is_value_falls_back_to_bare_term() {
        // `is:starred` isn't supported (no flagged predicate). The
        // parser keeps the user's intent visible as a free-text
        // search rather than silently dropping it.
        let q = parse("is:starred invoice");
        assert!(q.fts_terms.iter().any(|t| t == "is:starred"));
        assert!(q.fts_terms.iter().any(|t| t == "invoice"));
    }

    #[test]
    fn mixed_query_combines_everything() {
        let q = parse("from:alice subject:invoice is:unread before:2026-01-01");
        assert_eq!(q.fts_fields.len(), 2);
        assert_eq!(q.is_unread, Some(true));
        assert_eq!(q.before, Some(ymd(2026, 1, 1)));
        let tantivy = q.to_tantivy_string().expect("has FTS");
        assert!(tantivy.contains("from_json:alice"));
        assert!(tantivy.contains("subject:invoice"));
    }

    #[test]
    fn whitespace_term_gets_quoted_for_tantivy() {
        let mut q = Query::default();
        q.fts_fields
            .push((SearchField::From, "Alice Cohen".to_string()));
        let s = q.to_tantivy_string().unwrap();
        assert_eq!(s, "from_json:\"Alice Cohen\"");
    }

    #[test]
    fn uppercase_operators_normalize() {
        let q = parse("FROM:alice IS:UNREAD");
        assert_eq!(q.fts_fields.len(), 1);
        assert_eq!(q.is_unread, Some(true));
    }

    #[test]
    fn unknown_colon_tokens_are_plain_terms() {
        // URLs, times, and `re:` are search text, not operators.
        let q = parse("http://example.com/x 10:30 re:");
        assert!(q.fts_fields.is_empty());
        assert_eq!(q.fts_terms.len(), 3);
        let s = q.to_tantivy_string().unwrap();
        assert_eq!(s, r#""http://example.com/x" AND "10:30" AND "re:""#);
    }

    #[test]
    fn tantivy_specials_are_quoted_and_escaped() {
        for (input, expected) in [
            ("(", r#""(""#),
            ("-foo", r#""-foo""#),
            ("a^2", r#""a^2""#),
            ("he said \"hi", r#""he said \"hi""#),
            ("back\\slash", r#""back\\slash""#),
            ("AND", r#""AND""#),
            ("plain", "plain"),
            ("alice@example.com", "alice@example.com"),
            ("\"q1 invoice\"", r#""q1 invoice""#),
            ("日本語", "日本語"),
        ] {
            assert_eq!(escape_for_tantivy(input), expected, "input {input:?}");
        }
    }
}
