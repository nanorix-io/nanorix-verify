//! Wire-format-locked round-trip tests for
//! `FailureReason::CustomerDeclaredActivityRootMismatch` (ADR-056 — the
//! customer-declared activity root recomputed from the customer's own record).
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
//! The variant reports that the proof's signed `customer_declared_activity_root`
//! disagrees with the Merkle root recomputed from the activity record supplied
//! beside it. It is deliberately NOT `FinalHashMismatch` (the destruction chain
//! reproduced) and NOT `StreamingMerkleRootMismatch` (that root commits to
//! egress Nanorix observed; this one commits to bytes Nanorix never read).
//!
//! Wire form: `{"type": "customer_declared_activity_root_mismatch",
//! "claimed": "...", "computed": "..."}`.

use nanorix_verify_types::FailureReason;

/// The "three" vector from
/// `tools/nanorix-verify/fixtures/customer_declared_activity_root_vectors.json`.
const CLAIMED: &str = "sha512:390d7d3a3c84f59c289a33e3f1848e7208036e31b2f83837ade9e55fd3ac504550cd73baed351b139c22df78d2b6c65efebd9c27a5a237b64d0c15088f4f9ef1";
/// The "empty" vector — the genesis root.
const COMPUTED: &str = "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/// Test 1 — byte pin of the canonical serialization shape.
///
/// Both values carry the `sha512:` prefix, because both are emitted in the
/// document's own wire form so an auditor can compare them without knowing
/// which side the verifier stripped.
#[test]
fn customer_declared_activity_root_mismatch_byte_pin() {
    let reason = FailureReason::CustomerDeclaredActivityRootMismatch {
        claimed: CLAIMED.into(),
        computed: COMPUTED.into(),
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let expected = format!(
        r#"{{"type":"customer_declared_activity_root_mismatch","claimed":"{CLAIMED}","computed":"{COMPUTED}"}}"#
    );
    assert_eq!(
        json, expected,
        "CustomerDeclaredActivityRootMismatch wire-form drifted"
    );
}

/// Test 2 — round-trip via serde.
#[test]
fn customer_declared_activity_root_mismatch_roundtrip() {
    let original = FailureReason::CustomerDeclaredActivityRootMismatch {
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
/// A payload missing either must hit a clean serde error rather than a
/// silent default-empty decode, which would report a mismatch against an
/// empty string and read as "computed nothing".
#[test]
fn customer_declared_activity_root_mismatch_missing_required_fields_fails() {
    let missing_claimed =
        r#"{"type":"customer_declared_activity_root_mismatch","computed":"sha512:aa"}"#;
    let result: Result<FailureReason, _> = serde_json::from_str(missing_claimed);
    assert!(
        result.is_err(),
        "missing claimed must fail to deserialize, got {result:?}"
    );

    let missing_computed =
        r#"{"type":"customer_declared_activity_root_mismatch","claimed":"sha512:aa"}"#;
    let result: Result<FailureReason, _> = serde_json::from_str(missing_computed);
    assert!(
        result.is_err(),
        "missing computed must fail to deserialize, got {result:?}"
    );
}

/// Test 4 — a pre-ADR-056 deserializer fails cleanly on the new variant tag.
///
/// **Forever-Standard discipline:** an older consumer that does not have
/// `CustomerDeclaredActivityRootMismatch` in its compiled enum MUST fail with
/// serde's "unknown variant" error rather than silently decoding to a default.
/// Simulated with a local enum carrying the variants whose payload shape is
/// closest — the ones a lax decoder might drift into.
#[test]
fn pre_adr_056_deserializer_rejects_new_variant_cleanly() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum PreAdr056FailureReason {
        FinalHashMismatch { claimed: String, computed: String },
        StreamingMerkleRootMismatch { claimed: String, computed: String },
        RequiredFieldMissing { field: String },
        Reserved,
    }

    let wire = format!(
        r#"{{"type":"customer_declared_activity_root_mismatch","claimed":"{CLAIMED}","computed":"{COMPUTED}"}}"#
    );
    let result: Result<PreAdr056FailureReason, _> = serde_json::from_str(&wire);
    assert!(
        result.is_err(),
        "a pre-ADR-056 deserializer must reject the new tag, got {result:?}"
    );
}
