//! Wire-format-locked tests for the population head types.
//!
//! **Forever-Standard discipline.** These tests pin the exact
//! wire form of the head, its signed form and the population result, so that
//! a rename fails CI, and so the Go, Python and TypeScript verifiers can copy
//! the pinned bytes into their own suites.

use nanorix_verify_types::population_head::*;
use nanorix_verify_types::SignatureFailureReason;
use serde_json::json;

fn hash(n: char) -> String {
    format!("sha512:{}", n.to_string().repeat(128))
}

fn head() -> PopulationHead {
    PopulationHead {
        head_type: POPULATION_HEAD_TYPE_V1.into(),
        authority_id: "customer-kms-example-v1".into(),
        proof_sequence: 3,
        prev_head_hash: hash('a'),
        tip_proof_hash: hash('b'),
        issued_at: "2026-10-28T00:00:00Z".into(),
    }
}

/// The head serializes `head_type` as `type` and carries exactly six fields.
#[test]
fn head_byte_pin() {
    let json = serde_json::to_string(&head()).unwrap();
    let expected = format!(
        r#"{{"type":"nanorix-population-head-v1","authority_id":"customer-kms-example-v1","proof_sequence":3,"prev_head_hash":"{}","tip_proof_hash":"{}","issued_at":"2026-10-28T00:00:00Z"}}"#,
        hash('a'),
        hash('b')
    );
    assert_eq!(json, expected);
}

/// A field outside the six is refused, and the signed form carries only the
/// head, the key version and the signature.
#[test]
fn unknown_fields_are_refused() {
    let mut v = serde_json::to_value(head()).unwrap();
    v["capsule_id"] = json!("cap_1");
    assert!(serde_json::from_value::<PopulationHead>(v).is_err());

    let mut signed = json!({
        "head": head(),
        "signing_key_version": "1",
        "signature": "base64:AA==",
    });
    assert!(serde_json::from_value::<SignedPopulationHead>(signed.clone()).is_ok());
    let mut beside = signed.clone();
    beside["authority_id"] = json!("customer-kms-example-v1");
    assert!(serde_json::from_value::<SignedPopulationHead>(beside).is_err());
    signed["note"] = json!("x");
    assert!(serde_json::from_value::<SignedPopulationHead>(signed).is_err());
}

/// A version 1 carrier serializes with no ML-DSA member, and a version 2
/// carrier's two members keep their wire names.
#[test]
fn the_version_2_carrier_members_are_absent_unless_carried() {
    let v1 = json!({
        "head": head(),
        "signing_key_version": "1",
        "signature": "base64:AA==",
    });
    let parsed: SignedPopulationHead = serde_json::from_value(v1.clone()).unwrap();
    assert_eq!(parsed.pqc_signing_key_version, None);
    assert_eq!(parsed.pqc_signature, None);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), v1);

    let mut v2 = v1;
    v2["head"]["type"] = json!(POPULATION_HEAD_TYPE_V2);
    v2["pqc_signing_key_version"] = json!("2");
    v2["pqc_signature"] = json!("base64:AA==");
    let parsed: SignedPopulationHead = serde_json::from_value(v2.clone()).unwrap();
    assert_eq!(parsed.pqc_signing_key_version.as_deref(), Some("2"));
    assert_eq!(serde_json::to_value(&parsed).unwrap(), v2);
    assert_eq!(POPULATION_HEAD_TYPE_V2, "nanorix-population-head-v2");
    assert_eq!(POPULATION_HEAD_PQC_TAG_V2, "nanorix-population-head-pqc-v2");
}

/// Every check outcome, tagged on `outcome`.
#[test]
fn check_outcome_byte_pins() {
    let cases = [
        (PopulationCheck::Ok, r#"{"outcome":"ok"}"#.to_string()),
        (
            PopulationCheck::NotChecked {
                reason: NotCheckedReason::NeedsTransparencyLog,
            },
            r#"{"outcome":"not_checked","reason":"needs a transparency log"}"#.to_string(),
        ),
        (
            PopulationCheck::Failed {
                reason: PopulationFailureReason::SequenceGap {
                    expected: 3,
                    found: 5,
                },
            },
            r#"{"outcome":"failed","reason":{"type":"sequence_gap","expected":3,"found":5}}"#
                .to_string(),
        ),
    ];
    for (check, expected) in cases {
        assert_eq!(serde_json::to_string(&check).unwrap(), expected);
        let back: PopulationCheck = serde_json::from_str(&expected).unwrap();
        assert_eq!(back, check);
    }
}

/// Every failure reason's wire tag.
#[test]
fn failure_reason_tags_are_locked() {
    let cases: Vec<(PopulationFailureReason, &str)> = vec![
        (
            PopulationFailureReason::HeadMalformed {
                head_index: 0,
                field: "head.type".into(),
                detail: "x".into(),
            },
            "head_malformed",
        ),
        (
            PopulationFailureReason::PrevHeadHashMismatch {
                proof_sequence: 2,
                expected: hash('a'),
                found: hash('b'),
            },
            "prev_head_hash_mismatch",
        ),
        (
            PopulationFailureReason::GenesisMisplaced { proof_sequence: 2 },
            "genesis_misplaced",
        ),
        (
            PopulationFailureReason::SequenceGap {
                expected: 2,
                found: 3,
            },
            "sequence_gap",
        ),
        (
            PopulationFailureReason::DuplicateSequence { proof_sequence: 2 },
            "duplicate_sequence",
        ),
        (
            PopulationFailureReason::HeadIssuedBeforePrevious {
                proof_sequence: 2,
                issued_at: "2026-10-28T00:00:00Z".into(),
                previous_issued_at: "2026-10-28T00:00:01Z".into(),
            },
            "head_issued_before_previous",
        ),
        (
            PopulationFailureReason::TipMatchesNoProof {
                proof_sequence: 2,
                tip_proof_hash: hash('c'),
            },
            "tip_matches_no_proof",
        ),
        (
            PopulationFailureReason::TipNamedTwice {
                tip_proof_hash: hash('c'),
                first_sequence: 1,
                second_sequence: 2,
            },
            "tip_named_twice",
        ),
        (
            PopulationFailureReason::NamedProofNotVerified {
                proof_sequence: 1,
                proof_index: 0,
                stage_reached: 4,
                failure_reason: None,
            },
            "named_proof_not_verified",
        ),
        (
            PopulationFailureReason::SignerNotMarkedForHeads {
                proof_sequence: 1,
                signer: HeadlessSigner::LocalSigner,
            },
            "signer_not_marked_for_heads",
        ),
        (
            PopulationFailureReason::ChainAuthorityMismatch {
                proof_sequence: 2,
                chain_authority: "a".into(),
                head_authority: "b".into(),
            },
            "chain_authority_mismatch",
        ),
        (
            PopulationFailureReason::NamedProofAuthorityMismatch {
                proof_sequence: 1,
                head_authority: "b".into(),
                proof_authority: "a".into(),
            },
            "named_proof_authority_mismatch",
        ),
        (
            PopulationFailureReason::NamedProofVersionUnsupported {
                proof_sequence: 1,
                proof_index: 0,
                cdp_version: Some("1.0".into()),
            },
            "named_proof_version_unsupported",
        ),
        (
            PopulationFailureReason::HeadSigningKeyUnknown {
                proof_sequence: 1,
                authority_id: "a".into(),
                signing_key_version: "9".into(),
            },
            "head_signing_key_unknown",
        ),
        (
            PopulationFailureReason::HeadAuthorityRevoked {
                proof_sequence: 1,
                authority_id: "a".into(),
            },
            "head_authority_revoked",
        ),
        (
            PopulationFailureReason::HeadAlgorithmUnsupported {
                proof_sequence: 1,
                found: "ML-DSA-65".into(),
            },
            "head_algorithm_unsupported",
        ),
        (
            PopulationFailureReason::KeyListRecordRefused {
                authority_id: "a".into(),
                signing_key_version: "1".into(),
                field: "algorithm".into(),
            },
            "key_list_record_refused",
        ),
        (
            PopulationFailureReason::HeadKeyUnderSeveralAuthorities {
                proof_sequence: 1,
                authority_ids: vec!["a".into(), "c".into()],
            },
            "head_key_under_several_authorities",
        ),
        (
            PopulationFailureReason::HeadSignatureMismatch {
                proof_sequence: 1,
                reason: SignatureFailureReason::DoesNotVerify,
            },
            "head_signature_mismatch",
        ),
        (
            PopulationFailureReason::HeadPqcSignatureInvalid {
                proof_sequence: 1,
                pqc_signing_key_version: "2".into(),
                reason: SignatureFailureReason::DoesNotVerify,
            },
            "head_pqc_signature_invalid",
        ),
        (
            PopulationFailureReason::NamedProofNotAnchored {
                proof_sequence: 1,
                proof_index: 0,
                stage_reached: 6,
                failure_reason: None,
            },
            "named_proof_not_anchored",
        ),
        (
            PopulationFailureReason::HeadOutsideKeyWindow {
                proof_sequence: 1,
                signing_key_version: "1".into(),
                issued_at: "2026-10-28T00:00:00Z".into(),
                effective_from: "2026-10-29T00:00:00Z".into(),
                archived_at: None,
            },
            "head_outside_key_window",
        ),
        (
            PopulationFailureReason::HeadIssuedBeforeProof {
                proof_sequence: 1,
                proof_index: 0,
                issued_at: "2026-10-28T00:00:00Z".into(),
                destroyed_at: "2026-10-28T00:00:01Z".into(),
            },
            "head_issued_before_proof",
        ),
    ];
    for (reason, tag) in cases {
        let v = serde_json::to_value(&reason).unwrap();
        assert_eq!(v["type"], tag, "{reason:?}");
        let back: PopulationFailureReason = serde_json::from_value(v).unwrap();
        assert_eq!(back, reason);
    }
}

/// Closed vocabularies whose wire value is fixed text.
#[test]
fn reason_label_verdict_and_signer_values_are_locked() {
    let text = |v: serde_json::Value| v.as_str().unwrap().to_string();
    assert_eq!(
        text(serde_json::to_value(NotCheckedReason::NeedsTransparencyLog).unwrap()),
        "needs a transparency log"
    );
    assert_eq!(
        text(serde_json::to_value(NotCheckedReason::NeedsRegisteredKeyList).unwrap()),
        "needs a registered key list"
    );
    assert_eq!(
        text(serde_json::to_value(NotCheckedReason::NoHeadsHanded).unwrap()),
        "no heads handed"
    );
    assert_eq!(
        text(serde_json::to_value(NotCheckedReason::HeadsMalformed).unwrap()),
        "a handed head is malformed"
    );
    assert_eq!(
        text(serde_json::to_value(NotCheckedReason::NamedProofNotHanded).unwrap()),
        "a named proof was not handed"
    );
    assert_eq!(
        text(serde_json::to_value(HonestyLabel::PopulationNotExternallyWitnessed).unwrap()),
        "population not externally witnessed"
    );
    assert_eq!(
        text(serde_json::to_value(PopulationVerdict::Failed).unwrap()),
        "failed"
    );
    assert_eq!(
        text(serde_json::to_value(PopulationVerdict::NotExternallyWitnessed).unwrap()),
        "not_externally_witnessed"
    );
    assert_eq!(
        text(serde_json::to_value(HeadlessSigner::UnmarkedAuthority).unwrap()),
        "unmarked_authority"
    );
    assert_eq!(
        text(serde_json::to_value(UnwitnessedReason::NoHandedHead).unwrap()),
        "no_handed_head"
    );
    assert_eq!(
        text(serde_json::to_value(UnwitnessedReason::ProofNotVerified).unwrap()),
        "proof_not_verified"
    );
}

/// The result names checks (a) to (f) by letter and has no `valid` flag.
#[test]
fn result_field_names_are_locked() {
    let nc = || PopulationCheck::NotChecked {
        reason: NotCheckedReason::NoHeadsHanded,
    };
    let result = PopulationResult {
        verdict: PopulationVerdict::NotExternallyWitnessed,
        honesty_label: Some(HonestyLabel::PopulationNotExternallyWitnessed),
        checks: PopulationChecks {
            a_chain_links: nc(),
            b_sequence_contiguous: nc(),
            c_tips_match_proofs: nc(),
            d_log_inclusion: nc(),
            e_log_population: nc(),
            f_head_signatures: nc(),
        },
        authority_id: None,
        head_count: 0,
        proof_count: 0,
        first_sequence: None,
        last_sequence: None,
        unwitnessed_proofs: vec![UnwitnessedProof {
            proof_index: 0,
            tip_proof_hash: None,
            reason: UnwitnessedReason::LocalSigner,
        }],
        key_list: Some(KeyListRead {
            issued_at: "2026-10-28T00:00:00Z".into(),
            identity_fingerprint: "sha256:ab".into(),
        }),
    };
    let v = serde_json::to_value(&result).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "authority_id",
            "checks",
            "first_sequence",
            "head_count",
            "honesty_label",
            "key_list",
            "last_sequence",
            "proof_count",
            "unwitnessed_proofs",
            "verdict"
        ]
    );
    let mut checks: Vec<&str> = v["checks"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    checks.sort_unstable();
    assert_eq!(
        checks,
        [
            "a_chain_links",
            "b_sequence_contiguous",
            "c_tips_match_proofs",
            "d_log_inclusion",
            "e_log_population",
            "f_head_signatures"
        ]
    );
    assert_eq!(
        v["unwitnessed_proofs"][0],
        json!({"proof_index": 0, "tip_proof_hash": null, "reason": "local_signer"})
    );
    assert_eq!(
        v["key_list"],
        json!({"issued_at": "2026-10-28T00:00:00Z", "identity_fingerprint": "sha256:ab"})
    );
    let back: PopulationResult = serde_json::from_value(v).unwrap();
    assert_eq!(back, result);
}
