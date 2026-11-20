//! Wire-format-locked tests for `FailureReason::SigningModeAuthorityMismatch`
//! (the signed `signing_mode` is `customer_only` while the signed
//! `authority_id` is Nanorix-classified; section 4).
//!
//! **Forever-Standard discipline.** The byte pins below are the
//! bytes the Go, Python, TypeScript and browser verifiers emit for the same
//! refusal, and the shared corpus compares them: one member,
//! `claimed_authority_id`, a string or `null`.

use nanorix_verify_types::FailureReason;

#[test]
fn signing_mode_authority_mismatch_byte_pin() {
    let named = FailureReason::SigningModeAuthorityMismatch {
        claimed_authority_id: Some("us-kms-nanorix-v1".into()),
    };
    assert_eq!(
        serde_json::to_string(&named).expect("serialize"),
        r#"{"type":"signing_mode_authority_mismatch","claimed_authority_id":"us-kms-nanorix-v1"}"#
    );
    let absent = FailureReason::SigningModeAuthorityMismatch {
        claimed_authority_id: None,
    };
    assert_eq!(
        serde_json::to_string(&absent).expect("serialize"),
        r#"{"type":"signing_mode_authority_mismatch","claimed_authority_id":null}"#
    );
}

#[test]
fn signing_mode_authority_mismatch_roundtrip() {
    for original in [
        FailureReason::SigningModeAuthorityMismatch {
            claimed_authority_id: Some("us-kms-nanorix-v1".into()),
        },
        FailureReason::SigningModeAuthorityMismatch {
            claimed_authority_id: None,
        },
    ] {
        let first = serde_json::to_string(&original).expect("serialize");
        let restored: FailureReason = serde_json::from_str(&first).expect("deserialize");
        assert_eq!(original, restored);
        assert_eq!(
            first,
            serde_json::to_string(&restored).expect("re-serialize")
        );
    }
}

/// A payload written by an engine that omits the null member decodes to the
/// same refusal, so the five engines agree on what an absent authority means.
#[test]
fn signing_mode_authority_mismatch_without_the_member_is_an_absent_authority() {
    let decoded: FailureReason =
        serde_json::from_str(r#"{"type":"signing_mode_authority_mismatch"}"#).expect("decode");
    assert_eq!(
        decoded,
        FailureReason::SigningModeAuthorityMismatch {
            claimed_authority_id: None
        }
    );
}

/// The tag is its own: it never decodes as `authority_mode_mismatch`, the
/// neighbouring reason for a customer signature that failed against its
/// registered key, and a consumer built before this variant fails cleanly on
/// it rather than decoding it as a neighbour.
#[test]
fn the_new_tag_is_not_a_neighbouring_variant() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum Older {
        AlgorithmUnsupported {
            found: String,
        },
        AuthorityIdMismatch {
            claimed_authority_id: Option<String>,
        },
        AuthorityModeMismatch {
            claimed_authority_id: String,
        },
        Reserved,
    }

    let result: Result<Older, _> = serde_json::from_str(
        r#"{"type":"signing_mode_authority_mismatch","claimed_authority_id":"us-kms-nanorix-v1"}"#,
    );
    assert!(result.is_err(), "got {result:?}");
}
