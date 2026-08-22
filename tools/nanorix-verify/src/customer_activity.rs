//! ADR-056 — `customer_declared_activity_root`: recompute the customer's
//! activity-record commitment from the raw record bytes and compare it with
//! the root the proof carries.
//!
//! ## What the root is
//!
//! A capsule that opted in has the bytes of its activity buffer
//! (`/data/activity_events.jsonl`, written by the customer's own SDK
//! integrations) committed to one SHA-512 Merkle root at destroy. The proof
//! carries the root only; the record itself goes back to the customer. Nanorix
//! never parses, validates or interprets the record (INVARIANTS #6) — the
//! commitment is over bytes, and the field name carries that provenance.
//!
//! ## The exact algorithm
//!
//! Pinned by `fixtures/customer_declared_activity_root_vectors.json`, which
//! every implementation (Rust, Go, Python, TypeScript) tests against:
//!
//! 1. Split the buffer on `0x0A`. Drop only a trailing empty segment — so a
//!    buffer that ends in a newline and one that does not produce the same
//!    lines. Nothing is trimmed: a leading space is content; an empty line in
//!    the middle is a leaf.
//! 2. Leaf = lowercase SHA-512 hex of the line's raw bytes.
//! 3. Root = the ADR-039 null-separated Merkle root over the leaves in order
//!    (pairs hashed as `SHA-512(left_hex || 0x00 || right_hex)`, odd last node
//!    duplicated), the same construction `record_receipts_merkle_root` and
//!    `parent_proofs_merkle_root` use.
//! 4. Zero lines = the genesis hash (SHA-512 of the empty string), so "opted in
//!    and declared nothing" is a distinct, signed value rather than an absent
//!    field.
//! 5. Wire form `sha512:<hex>`.
//!
//! ## Which proofs can carry it
//!
//! The root is bound only where the signed message is the canonical view —
//! cdp_version 2.1 and 2.2. In 1.0 the signed message is `final_hash` and in
//! 2.0 it is the `document_hash` field, so a root on either of those sits
//! outside the signature and anyone holding the document can write one. A
//! present, non-null root on any other version is therefore rejected as
//! `UnsignedFieldPopulated` before the chain walk — the same gate the
//! reserved attestation slots use — and is never reported as checked. The
//! standalone [`verify_customer_declared_activity`] applies the same gate
//! itself (a missing or non-string `cdp_version` counts as a version that
//! does not sign the root), so a caller that skips the ladder cannot be
//! handed a match for a root the signature never covered.
//!
//! ## What shape it must have
//!
//! On 2.1/2.2 a present, non-null root must be a JSON string of `sha512:` +
//! 128 lowercase hex characters; a bare 128-hex digest is also accepted, as
//! it is for every other root the verifier compares. Anything else — a
//! number, an object, an array, the empty string, uppercase or wrong-length
//! hex — is `FieldMalformed`, also before the chain walk and before any
//! recompute consumes the value. The empty string is malformed rather than
//! absent: the canonical view binds `""` as a value, and a verifier that read
//! it as "no root" would contradict its own recompute.
//!
//! ## What the verifier does with it
//!
//! The root is inside the canonical view, so the signature stage binds it to
//! the signer whether or not the record is present. Recomputing it needs the
//! record as a sidecar, and three situations follow:
//!
//! - record supplied, root present → recompute and compare;
//! - record supplied, root absent → `RequiredFieldMissing` (a record nothing
//!   anchors is not evidence, the same fail-closed shape as a receipt set
//!   without its root);
//! - root present, no record → disclosed as "declared, not checked". Not a
//!   failure: the proof is genuine; the reader simply has not supplied the
//!   record that would let this build check the customer's half.

use crate::{strip_hash_prefix, verifier_merkle_root, NANORIX_GENESIS_HASH};
use nanorix_verify_types::FailureReason;
use serde_json::Value;
use sha2::{Digest, Sha512};

/// The proof field that carries the root (ADR-056).
pub const CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD: &str = "customer_declared_activity_root";

/// The cdp_versions whose signed message is the canonical view, and so the
/// only ones on which `customer_declared_activity_root` is signed.
pub const CANONICAL_VIEW_SIGNED_VERSIONS: [&str; 2] = ["2.1", "2.2"];

/// `FieldMalformed.reason` when the root is present but not a JSON string.
pub const ROOT_MALFORMED_NOT_A_STRING: &str = "expected a JSON string";
/// `FieldMalformed.reason` when the root is the empty string.
pub const ROOT_MALFORMED_EMPTY: &str = "empty string";
/// `FieldMalformed.reason` for any other string that is not `sha512:` + 128
/// lowercase hex (bare 128-hex accepted).
pub const ROOT_MALFORMED_SHAPE: &str = "expected sha512: followed by 128 lowercase hex characters";

/// True when `proof` carries a `customer_declared_activity_root` that is not
/// JSON `null`. Absence and `null` are the same thing: no root declared.
pub fn declares_activity_root(proof: &Value) -> bool {
    proof
        .get(CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD)
        .is_some_and(|v| !v.is_null())
}

/// Whether `cdp_version` signs the canonical view, which is the only place
/// the root is bound.
pub fn version_signs_activity_root(cdp_version: &str) -> bool {
    CANONICAL_VIEW_SIGNED_VERSIONS.contains(&cdp_version)
}

/// The shape check a present, non-null root must pass before anything reads
/// it: a JSON string of `sha512:` + 128 lowercase hex characters, or a bare
/// 128-hex digest. Returns the string as written on success so the caller
/// can report it verbatim.
pub fn check_declared_activity_root_shape(value: &Value) -> Result<&str, FailureReason> {
    let malformed = |reason: &str| FailureReason::FieldMalformed {
        field: CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD.into(),
        reason: reason.into(),
    };
    let root = value
        .as_str()
        .ok_or_else(|| malformed(ROOT_MALFORMED_NOT_A_STRING))?;
    if root.is_empty() {
        return Err(malformed(ROOT_MALFORMED_EMPTY));
    }
    let hex = strip_hash_prefix(root);
    let well_formed = hex.len() == 128
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !well_formed {
        return Err(malformed(ROOT_MALFORMED_SHAPE));
    }
    Ok(root)
}

/// The pre-chain-walk gate for a declared root: `UnsignedFieldPopulated` on
/// a version that does not sign it, `FieldMalformed` on a shape no signer
/// emits, `Ok(())` when no root is declared or the declared one is
/// well-formed on a version that signs it. The version gate precedes the
/// shape gate: a root the signature never covered is the more fundamental
/// defect, whatever its shape. Shared with the standalone check, so the two
/// entry points cannot disagree about which roots are readable.
pub fn gate_declared_activity_root(proof: &Value, cdp_version: &str) -> Result<(), FailureReason> {
    let Some(value) = proof
        .get(CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD)
        .filter(|v| !v.is_null())
    else {
        return Ok(());
    };
    if !version_signs_activity_root(cdp_version) {
        return Err(FailureReason::UnsignedFieldPopulated {
            field: CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD.into(),
        });
    }
    check_declared_activity_root_shape(value).map(|_| ())
}

/// Split an activity record into its lines: on `0x0A`, dropping only a
/// trailing empty segment. No trimming, no parsing.
pub fn split_activity_lines(record: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = record.split(|&b| b == b'\n').collect();
    if lines.last().is_some_and(|last| last.is_empty()) {
        lines.pop();
    }
    lines
}

/// Lowercase SHA-512 hex of each line's raw bytes, in record order.
pub fn customer_declared_activity_leaf_hashes(record: &[u8]) -> Vec<String> {
    split_activity_lines(record)
        .into_iter()
        .map(|line| hex::encode(Sha512::digest(line)))
        .collect()
}

/// The root over a record, in wire form `sha512:<hex>`. Zero lines yield the
/// genesis hash.
pub fn compute_customer_declared_activity_root(record: &[u8]) -> String {
    let leaves = customer_declared_activity_leaf_hashes(record);
    let root = verifier_merkle_root(&leaves).unwrap_or_else(|| NANORIX_GENESIS_HASH.to_string());
    format!("sha512:{root}")
}

/// The root a proof declares, when it carries one. `null` is absent.
pub fn declared_activity_root(proof: &Value) -> Option<&str> {
    proof
        .get(CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD)
        .and_then(|v| v.as_str())
}

/// Recompute the root from `record` and compare it with the one `proof`
/// declares. `Ok` carries the recomputed root in wire form.
///
/// A proof without the field fails closed when a record is offered: there is
/// nothing the record can be checked against, and accepting it would let any
/// file be presented as "the record" of a proof that never committed to one.
/// A present root on a `cdp_version` that does not sign it (a missing or
/// non-string `cdp_version` included) is `UnsignedFieldPopulated`, and a
/// malformed one is `FieldMalformed` — both before any recompute, never a
/// mismatch against the record.
pub fn verify_customer_declared_activity(
    proof: &Value,
    record: &[u8],
) -> Result<String, FailureReason> {
    let cdp_version = proof
        .get("cdp_version")
        .and_then(Value::as_str)
        .unwrap_or("");
    gate_declared_activity_root(proof, cdp_version)?;
    let Some(claimed) = declared_activity_root(proof) else {
        return Err(FailureReason::RequiredFieldMissing {
            field: CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD.into(),
        });
    };
    let computed = compute_customer_declared_activity_root(record);
    if strip_hash_prefix(claimed) != strip_hash_prefix(&computed) {
        return Err(FailureReason::CustomerDeclaredActivityRootMismatch {
            claimed: claimed.to_string(),
            computed,
        });
    }
    Ok(computed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The cross-implementation vectors. Read from the committed file rather
    /// than copied here, so Rust cannot drift from what Go, Python and
    /// TypeScript test against.
    const VECTORS: &str = include_str!("../fixtures/customer_declared_activity_root_vectors.json");

    fn vectors() -> Vec<Value> {
        let doc: Value = serde_json::from_str(VECTORS).expect("vectors file parses");
        let vectors = doc["vectors"].as_array().expect("vectors array").clone();
        assert_eq!(vectors.len(), 5, "every pinned vector must be exercised");
        vectors
    }

    #[test]
    fn every_pinned_vector_reproduces_line_count_leaves_and_root() {
        for vector in vectors() {
            let name = vector["name"].as_str().unwrap();
            let input = vector["input_utf8"].as_str().unwrap().as_bytes();

            let lines = split_activity_lines(input);
            assert_eq!(
                lines.len() as u64,
                vector["line_count"].as_u64().unwrap(),
                "{name}: line_count"
            );

            let leaves = customer_declared_activity_leaf_hashes(input);
            let expected_leaves: Vec<&str> = vector["leaf_hashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(leaves, expected_leaves, "{name}: leaf_hashes");

            assert_eq!(
                compute_customer_declared_activity_root(input),
                vector["root"].as_str().unwrap(),
                "{name}: root"
            );
        }
    }

    #[test]
    fn the_empty_record_is_the_genesis_hash() {
        assert_eq!(
            compute_customer_declared_activity_root(b""),
            format!("sha512:{NANORIX_GENESIS_HASH}")
        );
    }

    /// A lone newline is one empty line, not zero lines — only the trailing
    /// empty segment is dropped. Its root nevertheless equals the genesis
    /// root: a single leaf is its own root, and the leaf of an empty line is
    /// SHA-512 of nothing, which is what genesis is. The pinned algorithm
    /// makes "declared nothing" and "declared one empty line" the same
    /// commitment; stated here so nobody reads the coincidence as a bug.
    #[test]
    fn a_lone_newline_is_one_empty_leaf() {
        assert_eq!(split_activity_lines(b"\n"), vec![&b""[..]]);
        assert_eq!(
            split_activity_lines(b"a\n\nb\n"),
            vec![&b"a"[..], &b""[..], &b"b"[..]]
        );
        assert_eq!(customer_declared_activity_leaf_hashes(b"\n").len(), 1);
        assert_eq!(
            compute_customer_declared_activity_root(b"\n"),
            compute_customer_declared_activity_root(b"")
        );
        assert_ne!(
            compute_customer_declared_activity_root(b"\n\n"),
            compute_customer_declared_activity_root(b"")
        );
    }

    #[test]
    fn any_byte_flip_in_any_line_moves_the_root() {
        let three = vectors()
            .into_iter()
            .find(|v| v["name"] == "three")
            .unwrap();
        let input = three["input_utf8"].as_str().unwrap().as_bytes().to_vec();
        let root = compute_customer_declared_activity_root(&input);
        for i in 0..input.len() {
            if input[i] == b'\n' {
                continue;
            }
            let mut flipped = input.clone();
            flipped[i] ^= 0x01;
            assert_ne!(
                compute_customer_declared_activity_root(&flipped),
                root,
                "flip at byte {i} left the root unchanged"
            );
        }
    }

    #[test]
    fn reordering_lines_moves_the_root() {
        let a = b"{\"a\":1}\n{\"b\":2}\n";
        let b = b"{\"b\":2}\n{\"a\":1}\n";
        assert_ne!(
            compute_customer_declared_activity_root(a),
            compute_customer_declared_activity_root(b)
        );
    }

    fn three_vector() -> (Vec<u8>, String) {
        let three = vectors()
            .into_iter()
            .find(|v| v["name"] == "three")
            .unwrap();
        (
            three["input_utf8"].as_str().unwrap().as_bytes().to_vec(),
            three["root"].as_str().unwrap().to_string(),
        )
    }

    /// A minimal proof on a version whose signed message covers the root.
    fn signed(root: Value) -> Value {
        json!({ "cdp_version": "2.2", "customer_declared_activity_root": root })
    }

    #[test]
    fn record_and_matching_root_verify() {
        let (record, root) = three_vector();
        let proof = signed(json!(root));
        assert_eq!(verify_customer_declared_activity(&proof, &record), Ok(root));
    }

    #[test]
    fn record_and_different_root_is_a_mismatch_naming_both_sides() {
        let (record, root) = three_vector();
        let genesis = format!("sha512:{NANORIX_GENESIS_HASH}");
        let proof = signed(json!(genesis));
        assert_eq!(
            verify_customer_declared_activity(&proof, &record),
            Err(FailureReason::CustomerDeclaredActivityRootMismatch {
                claimed: genesis,
                computed: root,
            })
        );
    }

    #[test]
    fn record_against_a_proof_without_a_root_fails_closed() {
        let (record, _) = three_vector();
        assert_eq!(
            verify_customer_declared_activity(&json!({}), &record),
            Err(FailureReason::RequiredFieldMissing {
                field: "customer_declared_activity_root".into()
            })
        );
        assert_eq!(
            verify_customer_declared_activity(&signed(Value::Null), &record),
            Err(FailureReason::RequiredFieldMissing {
                field: "customer_declared_activity_root".into()
            })
        );
        // No root is no version gate either: the verdict is the same on a
        // version that would not sign one.
        assert_eq!(
            verify_customer_declared_activity(&json!({ "cdp_version": "1.0" }), &record),
            Err(FailureReason::RequiredFieldMissing {
                field: "customer_declared_activity_root".into()
            })
        );
    }

    /// The claimed value is compared after prefix stripping, like every other
    /// root, and reported exactly as written.
    #[test]
    fn a_bare_hex_root_compares_equal_and_is_reported_verbatim() {
        let (record, root) = three_vector();
        let bare = strip_hash_prefix(&root).to_string();
        let proof = signed(json!(bare));
        assert_eq!(
            verify_customer_declared_activity(&proof, &record),
            Ok(root.clone())
        );
        let bare_genesis = signed(json!(NANORIX_GENESIS_HASH));
        assert_eq!(
            verify_customer_declared_activity(&bare_genesis, &record),
            Err(FailureReason::CustomerDeclaredActivityRootMismatch {
                claimed: NANORIX_GENESIS_HASH.into(),
                computed: root,
            })
        );
    }

    fn malformed(reason: &str) -> FailureReason {
        FailureReason::FieldMalformed {
            field: "customer_declared_activity_root".into(),
            reason: reason.into(),
        }
    }

    /// Every shape no signer emits is named as malformed, with the reason
    /// string the other implementations must reproduce byte-for-byte.
    #[test]
    fn a_malformed_root_is_field_malformed_with_the_pinned_reason() {
        let (_, root) = three_vector();
        let upper = format!("sha512:{}", strip_hash_prefix(&root).to_uppercase());
        let cases: Vec<(Value, &str)> = vec![
            (json!(7), ROOT_MALFORMED_NOT_A_STRING),
            (json!(true), ROOT_MALFORMED_NOT_A_STRING),
            (json!({}), ROOT_MALFORMED_NOT_A_STRING),
            (json!([]), ROOT_MALFORMED_NOT_A_STRING),
            (json!(""), ROOT_MALFORMED_EMPTY),
            (json!("abc"), ROOT_MALFORMED_SHAPE),
            (json!("sha512:"), ROOT_MALFORMED_SHAPE),
            (json!(&root[..root.len() - 1]), ROOT_MALFORMED_SHAPE),
            (json!(format!("{root}0")), ROOT_MALFORMED_SHAPE),
            (json!(upper), ROOT_MALFORMED_SHAPE),
            (
                json!(format!("sha256:{}", strip_hash_prefix(&root))),
                ROOT_MALFORMED_SHAPE,
            ),
        ];
        for (value, reason) in cases {
            assert_eq!(
                check_declared_activity_root_shape(&value),
                Err(malformed(reason)),
                "value {value}"
            );
        }
        assert_eq!(
            check_declared_activity_root_shape(&json!(root)),
            Ok(root.as_str())
        );
        let bare = strip_hash_prefix(&root).to_string();
        assert_eq!(
            check_declared_activity_root_shape(&json!(bare)),
            Ok(bare.as_str())
        );
    }

    /// A malformed root is named before any recompute — never reported as a
    /// mismatch against the record, which would blame the record.
    #[test]
    fn a_malformed_root_with_a_record_is_field_malformed_not_a_mismatch() {
        let (record, _) = three_vector();
        assert_eq!(
            verify_customer_declared_activity(&signed(json!("")), &record),
            Err(malformed(ROOT_MALFORMED_EMPTY))
        );
        assert_eq!(
            verify_customer_declared_activity(&signed(json!(42)), &record),
            Err(malformed(ROOT_MALFORMED_NOT_A_STRING))
        );
    }

    /// The standalone check applies the stage-2 version gate too: a 1.0
    /// proof with an attacker-added root and a record that reproduces it
    /// must not come back as a match — the signature never covered that
    /// root. A missing or non-string `cdp_version` counts as a version that
    /// does not sign it, and the version gate precedes the shape gate.
    #[test]
    fn a_root_the_version_does_not_sign_is_unsigned_not_verified() {
        let (record, root) = three_vector();
        let unsigned = Err(FailureReason::UnsignedFieldPopulated {
            field: "customer_declared_activity_root".into(),
        });
        let versions: Vec<Value> = vec![
            json!("1.0"),
            json!("2.0"),
            json!("2.3"),
            json!(""),
            Value::Null,
            json!(2.2),
        ];
        let roots: Vec<Value> = vec![json!(root), json!(""), json!(42), json!("not a hash")];
        for version in &versions {
            for value in &roots {
                let proof = json!({
                    "cdp_version": version,
                    "customer_declared_activity_root": value,
                });
                assert_eq!(
                    verify_customer_declared_activity(&proof, &record),
                    unsigned,
                    "version {version} root {value}"
                );
                assert_eq!(
                    verify_customer_declared_activity(&proof, b""),
                    unsigned,
                    "version {version} root {value}, empty record"
                );
            }
        }
        for value in &roots {
            let missing = json!({ "customer_declared_activity_root": value });
            assert_eq!(
                verify_customer_declared_activity(&missing, &record),
                unsigned,
                "no cdp_version, root {value}"
            );
        }
        for version in CANONICAL_VIEW_SIGNED_VERSIONS {
            let proof = json!({
                "cdp_version": version,
                "customer_declared_activity_root": root,
            });
            assert_eq!(
                verify_customer_declared_activity(&proof, &record),
                Ok(root.clone()),
                "{version} signs the root"
            );
        }
    }

    /// The pre-chain-walk gate: a root on a version that does not sign the
    /// canonical view is unsigned, whatever its shape; on 2.1/2.2 it is
    /// shape-checked; no root is no gate.
    #[test]
    fn the_gate_rejects_unsigned_versions_then_malformed_shapes() {
        let (_, root) = three_vector();
        let unsigned = FailureReason::UnsignedFieldPopulated {
            field: "customer_declared_activity_root".into(),
        };
        for version in ["1.0", "2.0", "3.0"] {
            assert_eq!(
                gate_declared_activity_root(
                    &json!({ "customer_declared_activity_root": root }),
                    version
                ),
                Err(unsigned.clone()),
                "{version}: well-formed root"
            );
            assert_eq!(
                gate_declared_activity_root(
                    &json!({ "customer_declared_activity_root": 7 }),
                    version
                ),
                Err(unsigned.clone()),
                "{version}: the version gate precedes the shape gate"
            );
            assert_eq!(
                gate_declared_activity_root(
                    &json!({ "customer_declared_activity_root": null }),
                    version
                ),
                Ok(()),
                "{version}: null is absent"
            );
        }
        for version in CANONICAL_VIEW_SIGNED_VERSIONS {
            assert_eq!(
                gate_declared_activity_root(
                    &json!({ "customer_declared_activity_root": root }),
                    version
                ),
                Ok(())
            );
            assert_eq!(
                gate_declared_activity_root(
                    &json!({ "customer_declared_activity_root": "" }),
                    version
                ),
                Err(malformed(ROOT_MALFORMED_EMPTY))
            );
            assert_eq!(gate_declared_activity_root(&json!({}), version), Ok(()));
        }
    }
}
