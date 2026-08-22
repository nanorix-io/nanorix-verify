//! Wire-format-locked round-trip tests for `FailureReason::FieldMalformed`
//! (a field is present but is not the JSON type or shape the document format
//! defines for it; first use is `customer_declared_activity_root`, ADR-056).
//!
//! **Forever-Standard discipline (ADR-006 I0).** These tests pin the exact wire
//! form (variant tag + field names + serialization shape) so that:
//!
//! - any future rename of the variant or its fields fails CI immediately,
//! - the Python / TypeScript / Go / browser verifier ports can copy the pinned
//!   bytes verbatim into their own conformance suites,
//! - the tag stays wire-stable when persisted as attestation metadata.
//!
//! The variant is emitted BEFORE any recompute that would consume the field.
//! It is deliberately NOT `RequiredFieldMissing` (the field is there) and NOT
//! `CustomerDeclaredActivityRootMismatch` / `SignatureMismatch` (nothing was
//! recomputed — a malformed value must be named as the defect, not blamed on
//! the signature).
//!
//! Wire form: `{"type": "field_malformed", "field": "...", "reason": "..."}`.

use nanorix_verify_types::FailureReason;

const FIELD: &str = "customer_declared_activity_root";
const REASON: &str = "expected a JSON string of sha512: + 128 lowercase hex";

/// Test 1 — byte pin of the canonical serialization shape.
///
/// `field` precedes `reason`: consumers branch on `field`; `reason` is free
/// text for a human reader and is not a closed vocabulary.
#[test]
fn field_malformed_byte_pin() {
    let reason = FailureReason::FieldMalformed {
        field: FIELD.into(),
        reason: REASON.into(),
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let expected = format!(r#"{{"type":"field_malformed","field":"{FIELD}","reason":"{REASON}"}}"#);
    assert_eq!(json, expected, "FieldMalformed wire-form drifted");
}

/// Test 2 — round-trip via serde.
#[test]
fn field_malformed_roundtrip() {
    let original = FailureReason::FieldMalformed {
        field: FIELD.into(),
        reason: REASON.into(),
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
/// silent default-empty decode: a `FieldMalformed` with an empty `field`
/// would tell an auditor that "something" was malformed and nothing else.
#[test]
fn field_malformed_missing_required_fields_fails() {
    let missing_field = format!(r#"{{"type":"field_malformed","reason":"{REASON}"}}"#);
    let result: Result<FailureReason, _> = serde_json::from_str(&missing_field);
    assert!(
        result.is_err(),
        "missing field must fail to deserialize, got {result:?}"
    );

    let missing_reason = format!(r#"{{"type":"field_malformed","field":"{FIELD}"}}"#);
    let result: Result<FailureReason, _> = serde_json::from_str(&missing_reason);
    assert!(
        result.is_err(),
        "missing reason must fail to deserialize, got {result:?}"
    );
}

/// Test 4 — an older deserializer fails cleanly on the new variant tag.
///
/// **Forever-Standard discipline:** a consumer compiled without
/// `FieldMalformed` MUST fail with serde's "unknown variant" error rather than
/// silently decoding to a default. Simulated with a local enum carrying the
/// variants whose payload shape is closest — `RequiredFieldMissing` and
/// `UnsignedFieldPopulated` both carry a lone `field`, which is exactly what a
/// lax decoder would drift into.
#[test]
fn pre_field_malformed_deserializer_rejects_new_variant_cleanly() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum PreFieldMalformedFailureReason {
        RequiredFieldMissing { field: String },
        UnsignedFieldPopulated { field: String },
        CustomerDeclaredActivityRootMismatch { claimed: String, computed: String },
        Reserved,
    }

    let wire = format!(r#"{{"type":"field_malformed","field":"{FIELD}","reason":"{REASON}"}}"#);
    let result: Result<PreFieldMalformedFailureReason, _> = serde_json::from_str(&wire);
    assert!(
        result.is_err(),
        "an older deserializer must reject the new tag, got {result:?}"
    );
}
