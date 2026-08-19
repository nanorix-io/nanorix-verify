//! Wire-format-locked round-trip tests for
//! `FailureReason::ChainStepIdentityMismatch` (B1.4 — the verifier enforces the
//! canonical identity of the eight chain entries, not merely their count).
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
//! The variant reports that a chain entry names a subsystem that is not the
//! canonical subsystem for its position in the fixed 8-step order
//! (INVARIANTS #1). It is deliberately NOT `StepHashMismatch`: that variant
//! says the recompute disagreed, and it is emitted only when it did. This one
//! is emitted when every hash reproduced and the label beside them is wrong —
//! reporting it as a hash mismatch would tell an auditor the chain arithmetic
//! failed when it reproduced exactly.
//!
//! Wire form: `{"type": "chain_step_identity_mismatch", "step_idx": N,
//! "expected_subsystem": "...", "found_subsystem": "..."}`.

use nanorix_verify_types::FailureReason;

/// Test 1 — byte pin of the canonical serialization shape.
#[test]
fn chain_step_identity_mismatch_byte_pin() {
    let reason = FailureReason::ChainStepIdentityMismatch {
        step_idx: 3,
        expected_subsystem: "dire_keys".into(),
        found_subsystem: "dire_identity".into(),
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    assert_eq!(
        json,
        r#"{"type":"chain_step_identity_mismatch","step_idx":3,"expected_subsystem":"dire_keys","found_subsystem":"dire_identity"}"#,
        "ChainStepIdentityMismatch wire-form drifted"
    );
}

/// Test 2 — round-trip via serde.
#[test]
fn chain_step_identity_mismatch_roundtrip() {
    let original = FailureReason::ChainStepIdentityMismatch {
        step_idx: 0,
        expected_subsystem: "eee_namespace".into(),
        found_subsystem: String::new(),
    };
    let json_first = serde_json::to_string(&original).expect("serialize");
    let restored: FailureReason = serde_json::from_str(&json_first).expect("deserialize");
    assert_eq!(original, restored, "PartialEq drift after roundtrip");
    let json_second = serde_json::to_string(&restored).expect("re-serialize");
    assert_eq!(json_first, json_second, "byte-form drift after roundtrip");
}

/// Test 3 — every payload field is REQUIRED.
///
/// An entry that omits `subsystem` entirely serializes `found_subsystem` as the
/// empty string, which is meaningful. A payload missing the field altogether is
/// a different thing and must hit a clean serde error rather than decode to the
/// same shape.
#[test]
fn chain_step_identity_mismatch_missing_required_fields_fails() {
    for wire in [
        r#"{"type":"chain_step_identity_mismatch","expected_subsystem":"dire_keys","found_subsystem":"x"}"#,
        r#"{"type":"chain_step_identity_mismatch","step_idx":3,"found_subsystem":"x"}"#,
        r#"{"type":"chain_step_identity_mismatch","step_idx":3,"expected_subsystem":"dire_keys"}"#,
    ] {
        let result: Result<FailureReason, _> = serde_json::from_str(wire);
        assert!(
            result.is_err(),
            "incomplete payload must fail to deserialize: {wire}"
        );
    }
}

/// Test 4 — a pre-B1.4 deserializer fails cleanly on the new variant tag.
///
/// **Forever-Standard discipline:** an older consumer that does not have
/// `ChainStepIdentityMismatch` in its compiled enum MUST fail with serde's
/// "unknown variant" error rather than silently decoding to a default. The
/// local enum carries the variant a lax decoder would most plausibly drift
/// into — the other step-indexed one.
#[test]
fn pre_b1_4_deserializer_rejects_new_variant_cleanly() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum PreB14FailureReason {
        StepHashMismatch { step_idx: usize, subsystem: String },
        StepCountInvalid { expected: usize, found: usize },
        Reserved,
    }

    let wire = r#"{"type":"chain_step_identity_mismatch","step_idx":3,"expected_subsystem":"dire_keys","found_subsystem":"dire_identity"}"#;
    let result: Result<PreB14FailureReason, _> = serde_json::from_str(wire);
    assert!(
        result.is_err(),
        "a pre-B1.4 deserializer must reject the new tag, got {result:?}"
    );
}
