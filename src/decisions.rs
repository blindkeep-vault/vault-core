//! Canonical hashing for decisions and decision query result sets (issue #5).
//!
//! The query API returns a *notarized receipt* alongside each result page so
//! a downstream consumer can prove "this exact set was returned at time T,
//! signed by the server" — replaying the same query later (or with the page
//! still in hand) and recomputing the canonical hash must yield the same
//! 32-byte digest, which is what the receipt's notarization signs over.
//!
//! Determinism is load-bearing: any change to the canonicalization breaks
//! every previously-issued receipt. The serialization is therefore explicit
//! (length-prefixed strings, big-endian fixed-width integers, an explicit
//! present/absent byte for `Option`) rather than via `serde_json`, whose
//! formatting (whitespace, key order, integer rendering) is not part of any
//! stable contract.
//!
//! `decided_at` is hashed as milliseconds since the Unix epoch — the same
//! resolution used by the existing notary signature input
//! (`merkle::leaf_hash`), so the canonical form survives the round-trip
//! through Postgres `TIMESTAMPTZ` (microsecond precision) without
//! introducing a third unit.
//!
//! `filter_summary` is treated as opaque bytes: the *caller* is responsible
//! for producing a stable serialization of the filter (the route handler
//! uses [`canonical_filter_summary`] below). This keeps the hash function
//! free of any DTO-shape coupling.

use sha2::{Digest, Sha256};

use crate::types::Decision;

/// Hash a single decision's structural fields. Used as a building block by
/// [`canonical_query_result_hash`] and also surfaced standalone so a client
/// can verify a single-row receipt without reconstructing the full set.
pub fn canonical_decision_hash(d: &Decision) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(d.id.as_bytes());
    h.update(d.approver_user_id.as_bytes());
    write_lp_string(&mut h, &d.approver);
    write_lp_string(&mut h, &d.action);
    write_lp_string(&mut h, &d.target);
    match d.supersedes {
        Some(s) => {
            h.update([1u8]);
            h.update(s.as_bytes());
        }
        None => {
            h.update([0u8]);
        }
    }
    h.update(d.decided_at.timestamp_millis().to_be_bytes());
    h.finalize().into()
}

/// Hash a paginated query result. The input slice is sorted by id before
/// hashing so the digest is stable under any DB ORDER BY change. The pinned
/// `filter_summary` and `count` close two replay loopholes:
///
/// - Without `filter_summary`, two distinct queries that happen to return
///   the same rows would produce identical receipts — a verifier could not
///   distinguish "the answer to question A" from "the answer to question B".
/// - Without `count`, the empty set hashes the same as any singleton whose
///   per-row digest happens to be all zeros (theoretically). Explicitly
///   binding the count makes the empty set distinguishable.
pub fn canonical_query_result_hash(filter_summary: &[u8], decisions: &[Decision]) -> [u8; 32] {
    let mut sorted: Vec<&Decision> = decisions.iter().collect();
    sorted.sort_by_key(|d| d.id);

    let mut h = Sha256::new();
    h.update(b"decision-query-v1");
    h.update((filter_summary.len() as u64).to_be_bytes());
    h.update(filter_summary);
    h.update((sorted.len() as u64).to_be_bytes());
    for d in &sorted {
        h.update(canonical_decision_hash(d));
    }
    h.finalize().into()
}

/// Stable serialization of the GET /decisions filter parameters. Sorted
/// `key=value\n` lines so adding a new optional filter later is a
/// non-breaking append-at-end-only change for receipts of queries that
/// don't use it.
///
/// Pass `None` for an unset filter; the field is omitted entirely. An empty
/// string and an absent field hash differently — `target=` vs no `target`
/// line — which matches their distinct semantics ("filter for the literal
/// empty string" vs "no target filter").
// TODO: pack into a `DecisionFilterSummary` struct to drop the allow. The
// call site (one place: `query_decisions` in vault-api) already names all
// fields inline so the parameter list is the shape of the call rather than
// a refactor opportunity, but the clippy threshold is 7.
#[allow(clippy::too_many_arguments)]
pub fn canonical_filter_summary(
    approver: Option<&str>,
    action: Option<&str>,
    target: Option<&str>,
    since_millis: Option<i64>,
    until_millis: Option<i64>,
    supersedes: Option<&str>,
    limit: i64,
    offset: i64,
) -> Vec<u8> {
    let mut lines: Vec<String> = Vec::new();
    if let Some(v) = action {
        lines.push(format!("action={v}"));
    }
    if let Some(v) = approver {
        lines.push(format!("approver={v}"));
    }
    lines.push(format!("limit={limit}"));
    lines.push(format!("offset={offset}"));
    if let Some(v) = since_millis {
        lines.push(format!("since_millis={v}"));
    }
    if let Some(v) = supersedes {
        lines.push(format!("supersedes={v}"));
    }
    if let Some(v) = target {
        lines.push(format!("target={v}"));
    }
    if let Some(v) = until_millis {
        lines.push(format!("until_millis={v}"));
    }
    lines.sort();
    lines.join("\n").into_bytes()
}

fn write_lp_string(h: &mut Sha256, s: &str) {
    let b = s.as_bytes();
    h.update((b.len() as u64).to_be_bytes());
    h.update(b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn fixed_decision(id: u128, approver: &str, action: &str, target: &str) -> Decision {
        Decision {
            id: Uuid::from_u128(id),
            approver_user_id: Uuid::from_u128(0xAAAA),
            approver: approver.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            supersedes: None,
            decided_at: chrono::Utc.timestamp_millis_opt(1_700_000_000_000).unwrap(),
            notarization_id: None,
            created_at: chrono::Utc.timestamp_millis_opt(1_700_000_000_000).unwrap(),
        }
    }

    #[test]
    fn decision_hash_is_deterministic() {
        let d = fixed_decision(1, "alice", "approve", "wire-1");
        assert_eq!(canonical_decision_hash(&d), canonical_decision_hash(&d));
    }

    #[test]
    fn decision_hash_changes_when_any_field_changes() {
        let base = fixed_decision(1, "alice", "approve", "wire-1");
        let h0 = canonical_decision_hash(&base);

        let mut d = base.clone();
        d.approver = "bob".into();
        assert_ne!(canonical_decision_hash(&d), h0, "approver");

        let mut d = base.clone();
        d.action = "deny".into();
        assert_ne!(canonical_decision_hash(&d), h0, "action");

        let mut d = base.clone();
        d.target = "wire-2".into();
        assert_ne!(canonical_decision_hash(&d), h0, "target");

        let mut d = base.clone();
        d.supersedes = Some(Uuid::from_u128(99));
        assert_ne!(canonical_decision_hash(&d), h0, "supersedes");

        let mut d = base.clone();
        d.decided_at = chrono::Utc.timestamp_millis_opt(1_700_000_001_000).unwrap();
        assert_ne!(canonical_decision_hash(&d), h0, "decided_at");
    }

    #[test]
    fn lp_strings_disambiguate_concatenation() {
        // Without length-prefixes, ("ab", "cd") and ("abc", "d") would collide
        // because both concatenate to "abcd".
        let a = fixed_decision(1, "x", "ab", "cd");
        let b = fixed_decision(1, "x", "abc", "d");
        assert_ne!(canonical_decision_hash(&a), canonical_decision_hash(&b));
    }

    #[test]
    fn query_hash_independent_of_input_order() {
        let d1 = fixed_decision(1, "alice", "approve", "x");
        let d2 = fixed_decision(2, "alice", "approve", "y");
        let s = b"limit=10\noffset=0";
        assert_eq!(
            canonical_query_result_hash(s, &[d1.clone(), d2.clone()]),
            canonical_query_result_hash(s, &[d2, d1]),
        );
    }

    #[test]
    fn query_hash_distinguishes_empty_from_absent_filter() {
        let s_with_target = canonical_filter_summary(None, None, Some(""), None, None, None, 10, 0);
        let s_without_target = canonical_filter_summary(None, None, None, None, None, None, 10, 0);
        assert_ne!(s_with_target, s_without_target);
    }

    #[test]
    fn query_hash_pins_filter_summary() {
        // Same rows, different filter → different receipt.
        let d = fixed_decision(1, "alice", "approve", "x");
        let s_a = canonical_filter_summary(Some("alice"), None, None, None, None, None, 10, 0);
        let s_b = canonical_filter_summary(Some("bob"), None, None, None, None, None, 10, 0);
        assert_ne!(
            canonical_query_result_hash(&s_a, &[d.clone()]),
            canonical_query_result_hash(&s_b, &[d]),
        );
    }

    #[test]
    fn empty_result_set_has_distinct_hash() {
        let s = canonical_filter_summary(None, None, None, None, None, None, 10, 0);
        let empty = canonical_query_result_hash(&s, &[]);
        let one = canonical_query_result_hash(&s, &[fixed_decision(1, "a", "b", "c")]);
        assert_ne!(empty, one);
    }

    #[test]
    fn filter_summary_keys_sort_alphabetically() {
        let s = canonical_filter_summary(
            Some("alice"),
            Some("approve"),
            Some("wire-1"),
            Some(1000),
            Some(2000),
            None,
            10,
            5,
        );
        let s_str = String::from_utf8(s).unwrap();
        // Each line as key=value; assert keys appear in alphabetical order.
        let keys: Vec<&str> = s_str
            .lines()
            .map(|l| l.split('=').next().unwrap())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "filter summary keys must be sorted: {keys:?}");
    }
}
