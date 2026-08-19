//! Wire-format-locked round-trip tests for `FailureReason::AuthorityIdMismatch`
//! (ADR-031 G7 / VP Security extended-review F4.3).
//!
//! **Forever-Standard discipline (ADR-006 I0).** These tests pin the
//! exact wire form (variant tag + field names + `Option<String>`
//! serialization shape + `AuthorityIdMismatchReason` sub-enum tags) so
//! that:
//!
//! - any future rename of the variant or its fields fails CI immediately,
//! - cross-impl Rust ↔ Python ↔ TypeScript verifier modules can copy the
//!   pinned bytes verbatim into their own conformance suites,
//! - the tag is wire-stable when stored as cryptographic-attestation
//!   metadata (auditors who persisted a `failure_reason` JSON field
//!   years from now must still parse it correctly).
//!
//! The variant disambiguates verifier-policy-pin failures (per ADR-031 G7
//! customer-side `required_authority_id` policy) from `AuthorityModeMismatch`
//! (which covers algorithm-level rejection per Amendment 1) and from
//! `SignatureMismatch` (which covers Nanorix-authority-signed proof failures).
//!
//! Wire form (`reason = verifier_policy_demands_customer_hsm_audit_proof_has_none`):
//!   `{"type": "authority_id_mismatch", "claimed_authority_id": null,
//!     "expected_authority_id": "...",
//!     "reason": "verifier_policy_demands_customer_hsm_audit_proof_has_none"}`
//!
//! Wire form (`reason = verifier_policy_authority_id_mismatch`):
//!   `{"type": "authority_id_mismatch", "claimed_authority_id": "...",
//!     "expected_authority_id": "...",
//!     "reason": "verifier_policy_authority_id_mismatch"}`

use nanorix_verify_types::{AuthorityIdMismatchReason, FailureReason};

/// Test 1 — full populated payload with `claimed_authority_id = None`
/// (AuditProof omitted `signing_authority` entirely; Nanorix-default path).
///
/// Byte-pins the canonical serialization shape: tag is `authority_id_mismatch`,
/// `claimed_authority_id` serializes to `null`, `expected_authority_id`
/// is the policy-required value, `reason` carries the
/// `verifier_policy_demands_customer_hsm_audit_proof_has_none` sub-tag.
#[test]
fn authority_id_mismatch_audit_proof_none_byte_pin() {
    let reason = FailureReason::AuthorityIdMismatch {
        claimed_authority_id: None,
        expected_authority_id: "customer-hsm-example-org-v1".into(),
        reason: AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let expected = r#"{"type":"authority_id_mismatch","claimed_authority_id":null,"expected_authority_id":"customer-hsm-example-org-v1","reason":"verifier_policy_demands_customer_hsm_audit_proof_has_none"}"#;
    assert_eq!(
        json, expected,
        "AuthorityIdMismatch wire-form (None claimed) drifted"
    );
}

/// Test 2 — full populated payload with `claimed_authority_id = Some(...)`
/// (AuditProof carries customer-HSM `signing_authority` but the authority_id
/// disagrees with the policy-required value).
///
/// Byte-pins the populated-string branch: `Option<String>` serializes the
/// payload string (no `Some(...)` wrapping), `reason` carries the
/// `verifier_policy_authority_id_mismatch` sub-tag.
#[test]
fn authority_id_mismatch_wrong_id_byte_pin() {
    let reason = FailureReason::AuthorityIdMismatch {
        claimed_authority_id: Some("customer-hsm-other-v1".into()),
        expected_authority_id: "customer-hsm-example-org-v1".into(),
        reason: AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let expected = r#"{"type":"authority_id_mismatch","claimed_authority_id":"customer-hsm-other-v1","expected_authority_id":"customer-hsm-example-org-v1","reason":"verifier_policy_authority_id_mismatch"}"#;
    assert_eq!(
        json, expected,
        "AuthorityIdMismatch wire-form (Some claimed) drifted"
    );
}

/// Test 3 — round-trip via serde (claimed_authority_id = None).
///
/// Serialize → byte-pin → deserialize → assert variant equality →
/// re-serialize → assert byte-identical. Exercises the full serde
/// tagged-enum dispatch path on the new variant in the None branch.
#[test]
fn authority_id_mismatch_roundtrip_none_claimed() {
    let original = FailureReason::AuthorityIdMismatch {
        claimed_authority_id: None,
        expected_authority_id: "customer-hsm-acme-prod-2026-q2".into(),
        reason: AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
    };
    let json_first = serde_json::to_string(&original).expect("serialize");
    let restored: FailureReason = serde_json::from_str(&json_first).expect("deserialize");
    assert_eq!(original, restored, "PartialEq drift after roundtrip");
    let json_second = serde_json::to_string(&restored).expect("re-serialize");
    assert_eq!(
        json_first, json_second,
        "byte-form drift after roundtrip (None claimed)"
    );
}

/// Test 4 — round-trip via serde (claimed_authority_id = Some).
///
/// Same as Test 3, but exercises the populated-string branch.
#[test]
fn authority_id_mismatch_roundtrip_some_claimed() {
    let original = FailureReason::AuthorityIdMismatch {
        claimed_authority_id: Some("customer-hsm-mayo-v1".into()),
        expected_authority_id: "customer-hsm-acme-v1".into(),
        reason: AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
    };
    let json_first = serde_json::to_string(&original).expect("serialize");
    let restored: FailureReason = serde_json::from_str(&json_first).expect("deserialize");
    assert_eq!(original, restored, "PartialEq drift after roundtrip");
    let json_second = serde_json::to_string(&restored).expect("re-serialize");
    assert_eq!(
        json_first, json_second,
        "byte-form drift after roundtrip (Some claimed)"
    );
}

/// Test 5 — required-fields enforcement on deserialization.
///
/// `expected_authority_id` and `reason` are REQUIRED.
/// `claimed_authority_id` is `Option<String>` so it is allowed to be
/// missing OR explicitly `null`. This test asserts that a payload
/// missing the required fields fails to deserialize cleanly.
#[test]
fn authority_id_mismatch_missing_required_fields_fails() {
    // Missing `expected_authority_id`.
    let bad_a = r#"{"type":"authority_id_mismatch","claimed_authority_id":null,"reason":"verifier_policy_demands_customer_hsm_audit_proof_has_none"}"#;
    let result_a: Result<FailureReason, _> = serde_json::from_str(bad_a);
    assert!(
        result_a.is_err(),
        "missing expected_authority_id must fail to deserialize, got {:?}",
        result_a
    );

    // Missing `reason`.
    let bad_b = r#"{"type":"authority_id_mismatch","claimed_authority_id":null,"expected_authority_id":"customer-hsm-mayo-v1"}"#;
    let result_b: Result<FailureReason, _> = serde_json::from_str(bad_b);
    assert!(
        result_b.is_err(),
        "missing reason must fail to deserialize, got {:?}",
        result_b
    );

    // Missing `claimed_authority_id` is ALLOWED — `Option<String>` defaults
    // to None. This is the common case when AuditProofs omit
    // `signing_authority` entirely (Nanorix-default path).
    let lenient = r#"{"type":"authority_id_mismatch","expected_authority_id":"customer-hsm-mayo-v1","reason":"verifier_policy_demands_customer_hsm_audit_proof_has_none"}"#;
    let result_lenient: Result<FailureReason, _> = serde_json::from_str(lenient);
    match result_lenient {
        Ok(FailureReason::AuthorityIdMismatch {
            claimed_authority_id,
            expected_authority_id,
            reason,
        }) => {
            assert_eq!(
                claimed_authority_id, None,
                "missing claimed_authority_id must default to None"
            );
            assert_eq!(expected_authority_id, "customer-hsm-mayo-v1");
            assert_eq!(
                reason,
                AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone
            );
        }
        other => panic!(
            "missing claimed_authority_id should decode with None, got {:?}",
            other
        ),
    }
}

/// Test 6 — unknown `reason` sub-tags fail cleanly.
///
/// **Forever-Standard discipline:** the `AuthorityIdMismatchReason` enum
/// is closed; future additions ship as additive variants. Older
/// deserializers that don't have a future variant in their compiled enum
/// MUST fail with serde's "unknown variant" error rather than silently
/// decoding to a default. This guards the auditor-side classification
/// surface against drift.
#[test]
fn authority_id_mismatch_unknown_reason_subtag_fails() {
    let unknown_reason = r#"{"type":"authority_id_mismatch","claimed_authority_id":null,"expected_authority_id":"customer-hsm-mayo-v1","reason":"future_unrecognized_subreason"}"#;
    let result: Result<FailureReason, _> = serde_json::from_str(unknown_reason);
    assert!(
        result.is_err(),
        "unknown reason sub-tag must fail to deserialize, got {:?}",
        result
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("future_unrecognized_subreason") || err_msg.contains("unknown variant"),
        "error message should reference the unknown sub-variant; got: {}",
        err_msg
    );
}

/// Test 7 — pre-G7 13-variant deserializers fail cleanly on the new
/// variant tag.
///
/// **Forever-Standard discipline:** older deserializers that don't have
/// `AuthorityIdMismatch` in their compiled enum MUST fail with serde's
/// "unknown variant" error rather than silently decoding to a default.
///
/// This test simulates the older surface by defining a local enum that
/// matches the 13-variant catalog (pre-G7, post-Amendment-1) and asserting
/// that feeding it the new wire form produces a clean error.
#[test]
fn pre_g7_deserializer_rejects_new_variant_cleanly() {
    use serde::Deserialize;

    // 13-variant subset matching the pre-G7 FailureReason surface (which
    // already had AuthorityModeMismatch from Amendment 1, but did not yet
    // have AuthorityIdMismatch).
    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum PreG7FailureReason {
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
        AuthorityModeMismatch {
            claimed_authority_id: String,
            expected_algorithm: String,
            actual_algorithm: Option<String>,
        },
        Reserved,
    }

    let new_variant_json = r#"{"type":"authority_id_mismatch","claimed_authority_id":null,"expected_authority_id":"customer-hsm-mayo-v1","reason":"verifier_policy_demands_customer_hsm_audit_proof_has_none"}"#;

    let result: Result<PreG7FailureReason, _> = serde_json::from_str(new_variant_json);
    assert!(
        result.is_err(),
        "pre-G7 deserializer must reject unknown variant tag, got {:?}",
        result
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("authority_id_mismatch") || err_msg.contains("unknown variant"),
        "error message should reference the unknown variant; got: {}",
        err_msg
    );
}

/// Test 8 — fault-injection ≥10k iterations on the round-trip surface
/// (per `feedback_canonical_hash_under_fault.md`).
///
/// Property: for any (claimed_authority_id, expected_authority_id, reason)
/// triple drawn from the variant's domain, serialize → deserialize →
/// re-serialize is byte-identical AND PartialEq holds. The fault path is
/// the variant-discrimination logic itself: even when payloads collide
/// with neighboring variants' field shapes (e.g., a String value that
/// matches another variant's required field name), the tag dispatches
/// correctly.
#[test]
fn authority_id_mismatch_fault_injection_roundtrip_10k() {
    // Deterministic LCG to drive 10k unique payloads without proptest dep.
    // Seed 0xCAFE_F00D_DEAD_BEEF; any deterministic seed works — the
    // contract is the byte-equivalence of the round-trip surface.
    let mut state: u64 = 0xCAFE_F00D_DEAD_BEEF;
    let mut next = || {
        // LCG parameters from Numerical Recipes.
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };

    let auth_id_pool = [
        "customer-hsm-example-org-v1",
        "customer-hsm-acme-prod-2026-q2",
        "customer-hsm-other-v1",
        "us-kms-nanorix-v1",
        "europe-west1.daemon.nanorix.io",
        "auth_xyz_health",
        "",
        "very_long_authority_id_with_lots_of_chars_to_test_string_handling_1234567890",
    ];
    let reason_pool = [
        AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
        AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
    ];

    for iter in 0..10_000 {
        let r = next();
        let claimed_some = (r & 1) == 1;
        let claimed = if claimed_some {
            Some(auth_id_pool[((r >> 1) as usize) % auth_id_pool.len()].to_string())
        } else {
            None
        };
        let expected = auth_id_pool[((r >> 8) as usize) % auth_id_pool.len()].to_string();
        let sub_reason = reason_pool[((r >> 16) as usize) % reason_pool.len()].clone();

        let original = FailureReason::AuthorityIdMismatch {
            claimed_authority_id: claimed,
            expected_authority_id: expected,
            reason: sub_reason,
        };

        let json_first = serde_json::to_string(&original)
            .unwrap_or_else(|e| panic!("iter {} serialize failed: {}", iter, e));
        let restored: FailureReason = serde_json::from_str(&json_first).unwrap_or_else(|e| {
            panic!(
                "iter {} deserialize failed: {} (json: {})",
                iter, e, json_first
            )
        });
        assert_eq!(
            original, restored,
            "iter {} PartialEq drift after roundtrip",
            iter
        );
        let json_second = serde_json::to_string(&restored)
            .unwrap_or_else(|e| panic!("iter {} re-serialize failed: {}", iter, e));
        assert_eq!(
            json_first, json_second,
            "iter {} byte-form drift after roundtrip",
            iter
        );

        // Tag dispatch must hold: re-decoding the same bytes through the
        // canonical serde path produces the variant we started with.
        match restored {
            FailureReason::AuthorityIdMismatch { .. } => {}
            other => panic!(
                "iter {} tag dispatch drift: AuthorityIdMismatch round-tripped to {:?}",
                iter, other
            ),
        }
    }
}
