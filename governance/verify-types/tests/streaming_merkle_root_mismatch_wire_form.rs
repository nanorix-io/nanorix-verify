//! Wire-format-locked round-trip tests for
//! `FailureReason::StreamingMerkleRootMismatch` (B1.1 — verify the streaming
//! Merkle root when the chunk leaves are present).
//!
//! **Forever-Standard discipline (ADR-006 I0).** These tests pin the exact wire
//! form (variant tag + field names + serialization shape) so that:
//!
//! - any future rename of the variant or its fields fails CI immediately,
//! - the Rust / Python / TypeScript / Go verifier ports can copy the pinned
//!   bytes verbatim into their own conformance suites,
//! - the tag stays wire-stable when persisted as attestation metadata — an
//!   auditor who stored a `failure_reason` JSON blob years from now must still
//!   parse it correctly.
//!
//! The variant reports that `streaming_egress_completed.streaming_merkle_root`
//! disagrees with the RFC 6962 SHA-512 root recomputed from the
//! `streaming_egress_chunk` leaves disclosed beside it. It is deliberately NOT
//! `FinalHashMismatch`: that variant is bound to the 8-step destruction chain,
//! and routing an egress-trail disagreement through it would tell an auditor
//! the destruction chain failed when it reproduced exactly.
//!
//! Wire form: `{"type": "streaming_merkle_root_mismatch", "claimed": "...",
//! "computed": "..."}`.

use nanorix_verify_types::FailureReason;

const CLAIMED: &str = "sha512:28f59b1c8b9304b9a2d5c23d85aeee777b74655ee1104f0ec497c771ba85a9658b04969e7d1ab4c4793fb2eca3d62ad94020d29a79f0486bbf3ae828042a4e82";
const COMPUTED: &str = "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/// Test 1 — byte pin of the canonical serialization shape.
///
/// Both values carry the `sha512:` prefix, because both are emitted in the
/// document's own wire form so an auditor can compare them without knowing
/// which side the verifier stripped.
#[test]
fn streaming_merkle_root_mismatch_byte_pin() {
    let reason = FailureReason::StreamingMerkleRootMismatch {
        claimed: CLAIMED.into(),
        computed: COMPUTED.into(),
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let expected = format!(
        r#"{{"type":"streaming_merkle_root_mismatch","claimed":"{CLAIMED}","computed":"{COMPUTED}"}}"#
    );
    assert_eq!(
        json, expected,
        "StreamingMerkleRootMismatch wire-form drifted"
    );
}

/// Test 2 — round-trip via serde.
///
/// Serialize → deserialize → assert variant equality → re-serialize → assert
/// byte-identical. Exercises the full serde tagged-enum dispatch path.
#[test]
fn streaming_merkle_root_mismatch_roundtrip() {
    let original = FailureReason::StreamingMerkleRootMismatch {
        claimed: CLAIMED.into(),
        computed: COMPUTED.into(),
    };
    let json_first = serde_json::to_string(&original).expect("serialize");
    let restored: FailureReason = serde_json::from_str(&json_first).expect("deserialize");
    assert_eq!(original, restored, "PartialEq drift after roundtrip");
    let json_second = serde_json::to_string(&restored).expect("re-serialize");
    assert_eq!(json_first, json_second, "byte-form drift after roundtrip");
}

/// Test 3 — both payload fields are REQUIRED.
///
/// A hand-crafted payload missing either must hit a clean serde error rather
/// than a silent default-empty decode, which would report a mismatch against
/// an empty string and read as "computed nothing".
#[test]
fn streaming_merkle_root_mismatch_missing_required_fields_fails() {
    let missing_claimed = r#"{"type":"streaming_merkle_root_mismatch","computed":"sha512:aa"}"#;
    let result: Result<FailureReason, _> = serde_json::from_str(missing_claimed);
    assert!(
        result.is_err(),
        "missing claimed must fail to deserialize, got {result:?}"
    );

    let missing_computed = r#"{"type":"streaming_merkle_root_mismatch","claimed":"sha512:aa"}"#;
    let result: Result<FailureReason, _> = serde_json::from_str(missing_computed);
    assert!(
        result.is_err(),
        "missing computed must fail to deserialize, got {result:?}"
    );
}

/// Test 4 — a pre-B1.1 deserializer fails cleanly on the new variant tag.
///
/// **Forever-Standard discipline:** an older consumer that does not have
/// `StreamingMerkleRootMismatch` in its compiled enum MUST fail with serde's
/// "unknown variant" error rather than silently decoding to a default. This
/// simulates that surface with a local enum carrying the two variants whose
/// payload shape is closest — the ones a lax decoder might drift into.
#[test]
fn pre_b1_1_deserializer_rejects_new_variant_cleanly() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum PreB11FailureReason {
        FinalHashMismatch { claimed: String, computed: String },
        RequiredFieldMissing { field: String },
        Reserved,
    }

    let wire = format!(
        r#"{{"type":"streaming_merkle_root_mismatch","claimed":"{CLAIMED}","computed":"{COMPUTED}"}}"#
    );
    let result: Result<PreB11FailureReason, _> = serde_json::from_str(&wire);
    assert!(
        result.is_err(),
        "a pre-B1.1 deserializer must reject the new tag, got {result:?}"
    );
}
