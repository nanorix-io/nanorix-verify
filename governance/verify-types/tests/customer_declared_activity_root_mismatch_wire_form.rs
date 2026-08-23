//! Wire-format-locked round-trip tests for
//! `FailureReason::CustomerDeclaredActivityRootMismatch` (the specification — the
//! customer-declared activity root recomputed from the customer's own record).
//!
//! **Forever-Standard discipline (the Forever-Standard wire discipline).** These tests pin the exact wire
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
const CLAIMED: &str = "sha512:eeaf4d8e1236e12b43441daafff96d0cd178e2785664eea2ff261574522204a9f908540a12eac5a2292b487c49f2c24f008e8e6e07ea9b9508fb07dcec90f87b";
/// The "empty" vector — genesis with the line count `0` bound in.
const COMPUTED: &str = "sha512:e2e0379c1f7e2243f9459a9f3d1fb4fd0dbc810dfefc34b940e1bf0523a68a7fa704182112a1f5d3bd72951b8040c47f3330b1e79caddcef76abb5d647724434";

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

/// Test 4 — a pre-the specification deserializer fails cleanly on the new variant tag.
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
        "a pre-the specification deserializer must reject the new tag, got {result:?}"
    );
}
