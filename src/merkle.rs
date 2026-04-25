//! Merkle-tree primitives shared between vault-api (which builds the tree)
//! and the offline verifiers in vault-cli, vault-wasm, and vault-python.
//!
//! Only the *pure* functions live here. Everything that talks to Postgres
//! (`append_leaf`, `compute_root`, `inclusion_proof`, `subtree_hash`,
//! `rebuild_tree`) stays in `vault-api/src/merkle.rs` because it depends on
//! sqlx and the schema.
//!
//! Domain-separation rule:
//! - **Leaves** are `SHA-256(id || content_hash || blob_hash || timestamp_be)`,
//!   no leading byte. The 32-byte `content_hash` and 32-byte `blob_hash` give
//!   the leaf its preimage; we accept the standard "leaf preimage starts with
//!   a 32-byte slot" CT-style framing rather than a leading 0x00 byte.
//! - **Internal nodes** are `SHA-256(0x01 || left || right)`. The leading
//!   `0x01` ensures `node_hash(L, R) != leaf_hash(...)` for any inputs, so a
//!   second-preimage attacker cannot pass off an interior subtree as a leaf.

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Error returned by [`canonical_json_bytes`] when the input contains a
/// payload shape that cannot be canonicalized deterministically across
/// implementations (currently: floating-point numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalJsonError {
    /// A `serde_json::Number` was not representable as an integer
    /// (i64 or u64). v0's canonical form is integer-only because the
    /// shortest-roundtrip serialization of floats varies between
    /// implementations (`1`, `1.0`, `1e0`, `100.0` from `1e2`, …),
    /// and a server/client mismatch would silently break signed-log
    /// `client_signature` verification with no actionable error.
    NonIntegerNumber,
}

impl std::fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonicalJsonError::NonIntegerNumber => f.write_str(
                "event payload contains a non-integer number; v0 canonical form is integer-only",
            ),
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

/// Canonicalize a JSON value to deterministic bytes for hashing.
///
/// **Normative spec is `doc/SPEC.md` §"Append-only Event Logs / Canonical-JSON
/// rules"** — that document pins the exact escape rules, lowercase-`\\u`
/// requirement, U+2028/U+2029 / DEL pass-through behavior, and the
/// integer-only number contract. This implementation matches those rules
/// using `serde_json::to_string` for strings (whose 1.x output happens to
/// match the spec); a future serde_json major-version change that diverges
/// from the spec would require a hand-rolled serializer here, *not* a spec
/// rewrite — the spec is the contract third-party verifiers rely on.
///
/// Floating-point numbers are rejected with [`CanonicalJsonError::NonIntegerNumber`]
/// (see its docs for why v0 is integer-only).
pub fn canonical_json_bytes(v: &serde_json::Value) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut out = String::new();
    write_canonical(v, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical(v: &serde_json::Value, out: &mut String) -> Result<(), CanonicalJsonError> {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("string Value serializes"));
                out.push(':');
                write_canonical(&map[k.as_str()], out)?;
            }
            out.push('}');
        }
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(e, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Number(n) => {
            // Reject non-integer numbers before they reach the wire. `is_i64` /
            // `is_u64` together cover every value `serde_json` represents as an
            // integer; everything else (floats, exponent-form parses) goes to
            // f64 internally and would canonicalize ambiguously.
            if !n.is_i64() && !n.is_u64() {
                return Err(CanonicalJsonError::NonIntegerNumber);
            }
            out.push_str(&n.to_string());
        }
        other => out.push_str(&serde_json::to_string(other).expect("scalar Value serializes")),
    }
    Ok(())
}

/// Compute the leaf hash for a Merkle leaf:
/// `SHA-256(id || content_hash || blob_hash || timestamp_millis_be)`.
///
/// `id` is whatever UUID identifies the row (a notarization id, an event-log
/// entry id, …). `blob_hash = None` substitutes 32 zero bytes — the hash
/// that `Some(&[0u8; 32])` would produce, so callers can interchangeably
/// pass either form.
pub fn leaf_hash(
    id: Uuid,
    content_hash: &[u8],
    blob_hash: Option<&[u8]>,
    timestamp_millis: i64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(content_hash);
    hasher.update(blob_hash.unwrap_or(&[0u8; 32]));
    hasher.update(timestamp_millis.to_be_bytes());
    hasher.finalize().into()
}

/// Hash two child nodes: `SHA-256(0x01 || left || right)`.
///
/// **Stability:** part of the offline-verification API contract documented
/// in `doc/SPEC.md` §"Append-only Event Logs". The leading `0x01` is the
/// leaf-vs-internal-node domain separator; changing the construction
/// would silently invalidate every historical inclusion proof. Any change
/// here must be coordinated with a versioned cert format.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Verify a Merkle inclusion proof. Pure function — no DB, no I/O.
///
/// Returns `true` iff the leaf at `tree_index` in a tree of `tree_size`
/// leaves combines via `proof` (sibling hashes from leaf level upward) into
/// `expected_root`. The proof must be exactly the right length: extras and
/// truncation both fail.
pub fn verify_inclusion(
    leaf: &[u8; 32],
    tree_index: i64,
    tree_size: i64,
    proof: &[Vec<u8>],
    expected_root: &[u8; 32],
) -> bool {
    let mut hash = *leaf;
    let mut idx = tree_index;
    let mut size = tree_size;
    let mut proof_idx = 0;

    while size > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

        if sibling_idx < size {
            if proof_idx >= proof.len() || proof[proof_idx].len() != 32 {
                return false;
            }
            let sibling: [u8; 32] = proof[proof_idx].as_slice().try_into().unwrap_or([0u8; 32]);
            proof_idx += 1;

            hash = if idx % 2 == 0 {
                node_hash(&hash, &sibling)
            } else {
                node_hash(&sibling, &hash)
            };
        }

        idx /= 2;
        size = (size + 1) / 2;
    }

    proof_idx == proof.len() && hash == *expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        let h1 = leaf_hash(id(), &[0xAB; 32], Some(&[0xCD; 32]), 1_700_000_000_000);
        let h2 = leaf_hash(id(), &[0xAB; 32], Some(&[0xCD; 32]), 1_700_000_000_000);
        assert_eq!(h1, h2);
    }

    #[test]
    fn leaf_none_blob_equals_zero_blob() {
        let ts = 1_700_000_000_000;
        assert_eq!(
            leaf_hash(id(), &[0xAB; 32], None, ts),
            leaf_hash(id(), &[0xAB; 32], Some(&[0u8; 32]), ts),
        );
    }

    #[test]
    fn node_hash_uses_domain_separator() {
        // Plain SHA-256(L || R) must NOT equal node_hash(L, R) — the leading
        // 0x01 is the second-preimage guard.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let plain: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(a);
            h.update(b);
            h.finalize().into()
        };
        assert_ne!(plain, node_hash(&a, &b));
    }

    #[test]
    fn verify_two_leaf_tree() {
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let root = node_hash(&l0, &l1);
        assert!(verify_inclusion(&l0, 0, 2, &[l1.to_vec()], &root));
        assert!(verify_inclusion(&l1, 1, 2, &[l0.to_vec()], &root));
    }

    #[test]
    fn verify_three_leaf_tree_unpaired() {
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let l2 = [3u8; 32];
        let n01 = node_hash(&l0, &l1);
        let root = node_hash(&n01, &l2);
        assert!(verify_inclusion(
            &l0,
            0,
            3,
            &[l1.to_vec(), l2.to_vec()],
            &root
        ));
        // Leaf 2 has no level-0 sibling within tree_size; the proof skips
        // straight to level-1 sibling n01.
        assert!(verify_inclusion(&l2, 2, 3, &[n01.to_vec()], &root));
    }

    #[test]
    fn verify_rejects_truncated_proof() {
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let root = node_hash(&l0, &l1);
        assert!(!verify_inclusion(&l0, 0, 2, &[], &root));
    }

    #[test]
    fn verify_rejects_extra_proof_element() {
        let l = [42u8; 32];
        // Single-leaf tree needs no sibling, so any proof element is excess.
        assert!(!verify_inclusion(&l, 0, 1, &[vec![0u8; 32]], &l));
    }

    #[test]
    fn verify_rejects_wrong_length_hash_in_proof() {
        let l0 = [1u8; 32];
        let l1 = [2u8; 32];
        let root = node_hash(&l0, &l1);
        assert!(!verify_inclusion(&l0, 0, 2, &[vec![0u8; 31]], &root));
    }

    // --- canonical_json_bytes ---

    use serde_json::json;

    #[test]
    fn canonical_sorts_object_keys() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(
            canonical_json_bytes(&a).unwrap(),
            canonical_json_bytes(&b).unwrap()
        );
        assert_eq!(canonical_json_bytes(&a).unwrap(), b"{\"a\":2,\"b\":1}");
    }

    #[test]
    fn canonical_recurses_into_arrays_and_objects() {
        let v = json!({
            "z": [{"y": 1, "x": 2}, {"b": 3, "a": 4}],
            "a": "hello",
        });
        assert_eq!(
            canonical_json_bytes(&v).unwrap(),
            br#"{"a":"hello","z":[{"x":2,"y":1},{"a":4,"b":3}]}"#.to_vec()
        );
    }

    #[test]
    fn canonical_scalars() {
        assert_eq!(canonical_json_bytes(&json!(null)).unwrap(), b"null");
        assert_eq!(canonical_json_bytes(&json!(true)).unwrap(), b"true");
        assert_eq!(canonical_json_bytes(&json!(42)).unwrap(), b"42");
        assert_eq!(canonical_json_bytes(&json!(-7)).unwrap(), b"-7");
        assert_eq!(canonical_json_bytes(&json!("hi")).unwrap(), b"\"hi\"");
        assert_eq!(
            canonical_json_bytes(&json!(i64::MAX)).unwrap(),
            b"9223372036854775807"
        );
        assert_eq!(
            canonical_json_bytes(&json!(u64::MAX)).unwrap(),
            b"18446744073709551615"
        );
    }

    #[test]
    fn canonical_array_order_preserved() {
        // Arrays are intrinsically ordered — canonicalization MUST NOT sort
        // them or equal payloads with reordered arrays would be considered
        // equal, breaking inclusion proofs.
        assert_ne!(
            canonical_json_bytes(&json!([1, 2, 3])).unwrap(),
            canonical_json_bytes(&json!([3, 2, 1])).unwrap(),
        );
    }

    #[test]
    fn canonical_rejects_floats() {
        assert_eq!(
            canonical_json_bytes(&json!(1.5)),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
        // Exponent form parses to f64 even when the value happens to be an
        // integer — reject it. Clients that want `100` must send `100`, not `1e2`.
        let from_exponent: serde_json::Value = serde_json::from_str("1e2").unwrap();
        assert_eq!(
            canonical_json_bytes(&from_exponent),
            Err(CanonicalJsonError::NonIntegerNumber)
        );
    }

    #[test]
    fn canonical_rejects_floats_inside_objects() {
        assert!(matches!(
            canonical_json_bytes(&json!({"a": {"b": [1, 2.5]}})),
            Err(CanonicalJsonError::NonIntegerNumber)
        ));
    }
}
