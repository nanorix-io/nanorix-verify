//! Wire-format-locked round-trip tests for `FailureReason::AuthorityModeMismatch`
//! (the customer-authority specification / VP Security extended-review Area 4).
//!
//! **Forever-Standard discipline (the Forever-Standard wire discipline).** These tests pin the
//! exact wire form (variant tag + field names + serialization shape) so
//! that:
//!
//! - any future rename of the variant or its fields fails CI immediately,
//! - cross-impl Rust ↔ Python ↔ TypeScript verifier modules can copy the
//!   pinned bytes verbatim into their own conformance suites,
//! - the tag is wire-stable when stored as cryptographic-attestation
//!   metadata (auditors who persisted a `failure_reason` JSON field
//!   years from now must still parse it correctly).
//!
//! The variant disambiguates customer-attested authority signature
//! failures (per the customer-authority specification) from `SignatureMismatch` (which covers
//! Nanorix-authority-signed proof failures).
//!
//! Wire form: `{"type": "authority_mode_mismatch", "claimed_authority_id":
//! "...", "expected_algorithm": "Ed25519", "actual_algorithm": "..." | null}`.

use nanorix_verify_types::FailureReason;

/// Test 1 — full populated payload with `actual_algorithm = Some("...")`.
///
/// Byte-pins the canonical serialization shape: tag is `authority_mode_mismatch`,
/// fields are `claimed_authority_id` / `expected_algorithm` / `actual_algorithm`,
/// `actual_algorithm` carries the algorithm string when the customer
/// authority registry returned one.
#[test]
fn authority_mode_mismatch_full_payload_byte_pin() {
    let reason = FailureReason::AuthorityModeMismatch {
        claimed_authority_id: "auth_acme_co".into(),
        expected_algorithm: "Ed25519".into(),
        actual_algorithm: Some("ECDSA-P256".into()),
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let expected = r#"{"type":"authority_mode_mismatch","claimed_authority_id":"auth_acme_co","expected_algorithm":"Ed25519","actual_algorithm":"ECDSA-P256"}"#;
    assert_eq!(
        json, expected,
        "AuthorityModeMismatch wire-form (Some payload) drifted"
    );
}

/// Test 2 — `actual_algorithm = None` (legacy registration case).
///
/// Byte-pins how `Option<String>` serializes when the customer authority
/// registration predates Amendment 1 and the registry lookup did not
/// return an algorithm field. This is distinct from "wrong algorithm
/// declared" and consumers MUST be able to differentiate.
#[test]
fn authority_mode_mismatch_actual_algorithm_none_byte_pin() {
    let reason = FailureReason::AuthorityModeMismatch {
        claimed_authority_id: "auth_legacy_pre_amendment".into(),
        expected_algorithm: "Ed25519".into(),
        actual_algorithm: None,
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let expected = r#"{"type":"authority_mode_mismatch","claimed_authority_id":"auth_legacy_pre_amendment","expected_algorithm":"Ed25519","actual_algorithm":null}"#;
    assert_eq!(
        json, expected,
        "AuthorityModeMismatch wire-form (None payload) drifted"
    );
}

/// Test 3 — round-trip via serde (Some payload).
///
/// Serialize → byte-pin → deserialize → assert variant equality →
/// re-serialize → assert byte-identical. Exercises the full serde
/// tagged-enum dispatch path on the new variant.
#[test]
fn authority_mode_mismatch_roundtrip_some() {
    let original = FailureReason::AuthorityModeMismatch {
        claimed_authority_id: "auth_xyz_health".into(),
        expected_algorithm: "Ed25519".into(),
        actual_algorithm: Some("RSA-PSS-2048".into()),
    };
    let json_first = serde_json::to_string(&original).expect("serialize");
    let restored: FailureReason = serde_json::from_str(&json_first).expect("deserialize");
    assert_eq!(original, restored, "PartialEq drift after roundtrip");
    let json_second = serde_json::to_string(&restored).expect("re-serialize");
    assert_eq!(
        json_first, json_second,
        "byte-form drift after roundtrip (Some)"
    );
}

/// Test 4 — round-trip via serde (None payload).
///
/// Same as Test 3, but exercises the `actual_algorithm = None` branch
/// to confirm that `null` deserializes back into `Option::None`
/// (not `Some("null")` and not a missing-field error).
#[test]
fn authority_mode_mismatch_roundtrip_none() {
    let original = FailureReason::AuthorityModeMismatch {
        claimed_authority_id: "auth_legacy".into(),
        expected_algorithm: "Ed25519".into(),
        actual_algorithm: None,
    };
    let json_first = serde_json::to_string(&original).expect("serialize");
    let restored: FailureReason = serde_json::from_str(&json_first).expect("deserialize");
    assert_eq!(original, restored, "PartialEq drift after roundtrip");
    let json_second = serde_json::to_string(&restored).expect("re-serialize");
    assert_eq!(
        json_first, json_second,
        "byte-form drift after roundtrip (None)"
    );
}

/// Test 5 — required-fields enforcement on deserialization.
///
/// `claimed_authority_id` and `expected_algorithm` are REQUIRED.
/// `actual_algorithm` is `Option<String>` so it is allowed to be
/// missing OR explicitly `null`. This test asserts that a payload
/// missing the required fields fails to deserialize cleanly — older
/// verifiers that try to upgrade by hand-crafting AuditProofs without
/// these fields must hit a clear error rather than a default-zero
/// silent decode.
#[test]
fn authority_mode_mismatch_missing_required_fields_fails() {
    // Missing `claimed_authority_id`.
    let bad_a = r#"{"type":"authority_mode_mismatch","expected_algorithm":"Ed25519","actual_algorithm":null}"#;
    let result_a: Result<FailureReason, _> = serde_json::from_str(bad_a);
    assert!(
        result_a.is_err(),
        "missing claimed_authority_id must fail to deserialize, got {:?}",
        result_a
    );

    // Missing `expected_algorithm`.
    let bad_b = r#"{"type":"authority_mode_mismatch","claimed_authority_id":"auth_x","actual_algorithm":null}"#;
    let result_b: Result<FailureReason, _> = serde_json::from_str(bad_b);
    assert!(
        result_b.is_err(),
        "missing expected_algorithm must fail to deserialize, got {:?}",
        result_b
    );

    // Missing `actual_algorithm` is ALLOWED — `Option<String>` defaults to None.
    // This is correct because legacy registry lookups may pre-date Amendment 1.
    let lenient = r#"{"type":"authority_mode_mismatch","claimed_authority_id":"auth_x","expected_algorithm":"Ed25519"}"#;
    let result_lenient: Result<FailureReason, _> = serde_json::from_str(lenient);
    match result_lenient {
        Ok(FailureReason::AuthorityModeMismatch {
            claimed_authority_id,
            expected_algorithm,
            actual_algorithm,
        }) => {
            assert_eq!(claimed_authority_id, "auth_x");
            assert_eq!(expected_algorithm, "Ed25519");
            assert_eq!(
                actual_algorithm, None,
                "missing actual_algorithm must default to None"
            );
        }
        other => panic!(
            "missing actual_algorithm should decode with None, got {:?}",
            other
        ),
    }
}

/// Test 6 — pre-amendment 12-variant deserializers fail cleanly on the
/// new variant tag.
///
/// **Forever-Standard discipline:** older deserializers that don't have
/// `AuthorityModeMismatch` in their compiled enum MUST fail with serde's
/// "unknown variant" error rather than silently decoding to a default.
///
/// This test simulates the older surface by defining a local enum that
/// matches the pre-amendment 12-variant catalog and asserting that
/// feeding it the new wire form produces a clean error.
#[test]
fn pre_amendment_deserializer_rejects_new_variant_cleanly() {
    use serde::Deserialize;

    // 12-variant subset matching the pre-amendment FailureReason surface.
    // Field shapes copied from `governance/verify-types/src/lib.rs`
    // immediately before this amendment.
    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum PreAmendmentFailureReason {
        CdpVersionUnsupported {
            found: String,
        },
        RequiredFieldMissing {
            field: String,
        },
        StepCountInvalid {
            expected: usize,
            found: usize,
        },
        StepHashMismatch {
            step_idx: usize,
            subsystem: String,
        },
        GenesisHashMismatch,
        FinalHashMismatch {
            claimed: String,
            computed: String,
        },
        SignatureMismatch {
            // sub-reason elided — only tag-dispatch matters here
            reason: serde_json::Value,
        },
        SigningKeyVersionUnknown {
            version: String,
        },
        AuthorityRevoked,
        RegionMismatch {
            required: String,
            actual: String,
        },
        DiagnosticProofRefused,
        AlgorithmUnsupported {
            found: String,
        },
        Reserved,
    }

    let new_variant_json = r#"{"type":"authority_mode_mismatch","claimed_authority_id":"auth_x","expected_algorithm":"Ed25519","actual_algorithm":null}"#;

    let result: Result<PreAmendmentFailureReason, _> = serde_json::from_str(new_variant_json);
    assert!(
        result.is_err(),
        "pre-amendment deserializer must reject unknown variant tag, got {:?}",
        result
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("authority_mode_mismatch") || err_msg.contains("unknown variant"),
        "error message should reference the unknown variant; got: {}",
        err_msg
    );
}
