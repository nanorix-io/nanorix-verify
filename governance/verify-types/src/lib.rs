//! Shared verification result types for AuditProof (CDP) verification.
//!
//! **Purpose:** Single source of truth for the `FailureReason` wire-form
//! enum used by:
//!
//! 1. `services/api` — at `POST /v1/verify` (server-side typed-failure
//!    response per the specification)
//! 2. `tools/nanorix-verify` — offline auditor CLI (per the verifier specification)
//!
//! Before trust-chain anchoring (this crate), each side maintained its own
//! definition with a "must stay in lockstep" comment — easy to drift,
//! breaking byte-identical typed-failure JSON. Extracting here closes
//! that drift surface forever.
//!
//! **Forever-Standard discipline (the Forever-Standard wire discipline):** every variant shipped
//! here is permanent. New failure modes ship as ADDITIVE variants.
//! Existing variants NEVER renamed, NEVER removed, NEVER repurposed.
//! The wire form (serde tag = "type", rename_all = "snake_case") is the
//! cryptographic-attestation contract auditors rely on.
//!
//! **Zero runtime dependencies:** this crate compiles to a thin
//! types-only library so adding it as a dependency to either consumer
//! costs zero binary bloat. No tokio, no async, no SDK transitives.

#![forbid(unsafe_code)]

pub mod chain;
pub mod output_bundle;

use serde::{Deserialize, Serialize};

/// Closed-enum verification failure reason emitted by AuditProof
/// verification paths. **Forever-stable per the Forever-Standard wire discipline** — additive only.
///
/// Wire form: `{"type": "<snake_case>", ...payload}` via serde tag dispatch.
///
/// ## Variant catalog (alphabetical by snake_case wire tag)
///
/// | Wire tag | When emitted |
/// |---|---|
/// | `algorithm_unsupported` | V1 only supports Ed25519; unknown algorithm string |
/// | `authority_id_mismatch` | Verifier policy demanded a specific `signing_authority.authority_id` and the AuditProof either omitted `signing_authority` (Nanorix-default) or named a different authority (the customer-authority specification G7) |
/// | `authority_mode_mismatch` | Customer-attested authority signature failed against registered Ed25519 key (the customer-authority specification) |
/// | `authority_revoked` | Trust-chain manifest marks the signing authority as revoked |
/// | `cdp_version_unsupported` | CDP version not in {1.0, 2.0, 2.1} |
/// | `diagnostic_proof_refused` | Verifier policy refused diagnostic-mode proof (the diagnostic-proof policy) |
/// | `final_hash_mismatch` | `final_hash` doesn't match last step's `chain_hash` |
/// | `genesis_hash_mismatch` | First step's `prev_hash` != SHA-512(empty) |
/// | `region_mismatch` | AuditProof region differs from policy required (the region policy) |
/// | `required_field_missing` | Structural field absent from AuditProof JSON |
/// | `reserved` | V2+ wire-surface reservation; never populated in V1 |
/// | `signature_mismatch` | Ed25519 signature verification failed (Nanorix-authority-signed proof) |
/// | `signing_key_version_unknown` | Signing key version not in trust-chain manifest |
/// | `step_count_invalid` | Chain has != 8 steps |
/// | `step_hash_mismatch` | Step at given index didn't reproduce when recomputed |
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FailureReason {
    /// CDP version not recognized (1.0 / 2.0 / 2.1).
    CdpVersionUnsupported { found: String },

    /// Required field absent from the AuditProof structure.
    RequiredFieldMissing { field: String },

    /// Step count != 8.
    StepCountInvalid { expected: usize, found: usize },

    /// Step at given index did not reproduce when recomputed from prev_hash.
    StepHashMismatch { step_idx: usize, subsystem: String },

    /// Genesis hash assumption violated (first step's prev_hash was not the
    /// canonical SHA-512 of empty input).
    GenesisHashMismatch,

    /// final_hash field doesn't match the last step's chain_hash.
    FinalHashMismatch { claimed: String, computed: String },

    /// Ed25519 signature is malformed or doesn't verify.
    SignatureMismatch { reason: SignatureFailureReason },

    /// signing_key_version present but not in the trust-chain manifest.
    SigningKeyVersionUnknown { version: String },

    /// Authority is in revoked state in the trust-chain manifest.
    AuthorityRevoked,

    /// AuditProof asserts a region that doesn't match the policy-required
    /// region (the specification G1 / the region policy). Customer setting
    /// `VerifierPolicy.required_region` rejects proofs from a different region.
    RegionMismatch { required: String, actual: String },

    /// Verifier policy refuses diagnostic-mode proofs (the specification / the diagnostic-proof policy).
    /// Customer setting `VerifierPolicy.reject_diagnostic = true` rejects
    /// proofs that carry a `DiagnosticModeEnabled` activity event.
    DiagnosticProofRefused,

    /// Algorithm not supported by this verifier version (e.g., V1 supports
    /// Ed25519 only; future PQC variants would require an SDK upgrade).
    AlgorithmUnsupported { found: String },

    /// Customer-attested authority signature did not verify against the
    /// registered customer authority's published Ed25519 public key
    /// (the customer-authority specification / Amendment 1).
    ///
    /// Distinct from `SignatureMismatch`, which covers Nanorix-authority-
    /// signed AuditProof failures. This variant disambiguates customer-
    /// authority failure from Nanorix-authority failure so verifier
    /// consumers can route the failure correctly.
    ///
    /// Per the customer-authority specification, customer authority signatures are
    /// Ed25519-only; algorithm mismatch (e.g., AuditProof claims Ed25519
    /// but the registered authority public key is not curve-25519) ALSO
    /// produces this variant — the resolution is identical (re-publish
    /// or correct the registered key) and routing the algorithm-mismatch
    /// case via `AlgorithmUnsupported` would mis-attribute it to a
    /// Nanorix-side encoding fault.
    ///
    /// Field semantics:
    /// - `claimed_authority_id`: the `signing_authority.authority_id`
    ///   value extracted from the AuditProof.
    /// - `expected_algorithm`: always `"Ed25519"` (per Amendment 1's lock).
    /// - `actual_algorithm`: the algorithm value observed in the
    ///   registered customer authority record. `None` when the registry
    ///   lookup itself returned no algorithm field (legacy registration
    ///   pre-Amendment 1) — distinct from "wrong algorithm declared".
    AuthorityModeMismatch {
        claimed_authority_id: String,
        expected_algorithm: String,
        actual_algorithm: Option<String>,
    },

    /// Verifier policy demanded a specific signing-authority-id pin, and the
    /// AuditProof's `signing_authority.authority_id` either is absent (the
    /// AuditProof was signed under Nanorix's default signing authority — i.e.
    /// `signing_authority` field is `None` / omitted) or names a different
    /// authority than the one demanded. Per the customer-authority specification G7 + VP Security extended
    /// review F4.3.
    ///
    /// This variant is **distinct from `AuthorityModeMismatch`**:
    ///
    /// - `AuthorityModeMismatch` covers ALGORITHM-level rejection (the
    ///   AuditProof claims customer-HSM authority but the registered key's
    ///   algorithm differs from Ed25519 — Amendment 1).
    /// - `AuthorityIdMismatch` covers POLICY-PIN-level rejection (the
    ///   AuditProof's signing authority — Nanorix-default OR customer-HSM —
    ///   does not match the verifier's `required_authority_id` policy pin).
    ///
    /// Routing the policy-pin failure through its own variant lets verifier
    /// consumers (auditor CLI, customer SDK, browser verifier) distinguish
    /// "customer's policy demands a specific authority and this AuditProof is
    /// signed by a different one" (operational misconfiguration; refresh
    /// policy or accept the proof under different terms) from "the registered
    /// authority's algorithm is wrong" (cryptographic concern; re-publish the
    /// key).
    ///
    /// Field semantics:
    /// - `claimed_authority_id`: the `signing_authority.authority_id` value
    ///   present in the AuditProof, if any. `None` when the AuditProof omits
    ///   `signing_authority` entirely (Nanorix-default signing path; the customer-authority specification
    ///   Forever-Standard pre-amendment shape).
    /// - `expected_authority_id`: the value of
    ///   `VerificationPolicy.required_authority_id` that the verifier was
    ///   initialized with. Always populated in this variant — if it were
    ///   `None`, no policy-pin gate would fire and this variant would not be
    ///   emitted.
    /// - `reason`: closed enum classifying which of the two failure shapes
    ///   produced this rejection (none-vs-policy or wrong-id-vs-policy).
    ///   Forever-stable per the Forever-Standard wire discipline; future additions are additive.
    AuthorityIdMismatch {
        claimed_authority_id: Option<String>,
        expected_authority_id: String,
        reason: AuthorityIdMismatchReason,
    },

    /// Reserved for V2+; never populated in V1. Existence reserves the wire
    /// surface for future extension without breaking serde tag dispatch.
    Reserved,
}

/// Sub-reason for `FailureReason::AuthorityIdMismatch`. Closed enum;
/// forever-stable per the Forever-Standard wire discipline. Additive only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityIdMismatchReason {
    /// Verifier policy pinned a specific `required_authority_id` and the
    /// AuditProof omitted `signing_authority` entirely (Nanorix-default
    /// signing path). Customer's policy demanded customer-HSM; AuditProof
    /// has no customer-HSM attestation.
    VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
    /// Verifier policy pinned a specific `required_authority_id` and the
    /// AuditProof carries a `signing_authority.authority_id` that does not
    /// match. Both sides intend customer-HSM; the IDs disagree.
    VerifierPolicyAuthorityIdMismatch,
}

/// Sub-reason for `FailureReason::SignatureMismatch`. Closed enum;
/// forever-stable per the Forever-Standard wire discipline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFailureReason {
    /// Signature bytes are malformed (wrong length, invalid base64).
    Malformed,
    /// Ed25519 signature did not verify against the public key + message.
    DoesNotVerify,
    /// Public key bytes are malformed (wrong length, invalid base64,
    /// not a valid Ed25519 point).
    PublicKeyMalformed,
    /// Message format mismatch (e.g., canonical_hash recompute didn't
    /// match the bytes the signature was over).
    MessageFormatMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin every wire-form tag for every variant. Drift on any variant
    /// breaks the cryptographic-attestation contract — auditors who
    /// stored a `failure_reason` JSON field years ago must still parse
    /// it correctly.
    #[test]
    fn failure_reason_wire_form_is_locked() {
        let cases: Vec<(FailureReason, &str)> = vec![
            (
                FailureReason::CdpVersionUnsupported {
                    found: "99.0".into(),
                },
                "cdp_version_unsupported",
            ),
            (
                FailureReason::RequiredFieldMissing { field: "x".into() },
                "required_field_missing",
            ),
            (
                FailureReason::StepCountInvalid {
                    expected: 8,
                    found: 7,
                },
                "step_count_invalid",
            ),
            (
                FailureReason::StepHashMismatch {
                    step_idx: 0,
                    subsystem: "x".into(),
                },
                "step_hash_mismatch",
            ),
            (FailureReason::GenesisHashMismatch, "genesis_hash_mismatch"),
            (
                FailureReason::FinalHashMismatch {
                    claimed: "x".into(),
                    computed: "y".into(),
                },
                "final_hash_mismatch",
            ),
            (
                FailureReason::SignatureMismatch {
                    reason: SignatureFailureReason::DoesNotVerify,
                },
                "signature_mismatch",
            ),
            (
                FailureReason::SigningKeyVersionUnknown {
                    version: "v7".into(),
                },
                "signing_key_version_unknown",
            ),
            (FailureReason::AuthorityRevoked, "authority_revoked"),
            (
                FailureReason::RegionMismatch {
                    required: "europe-west1".into(),
                    actual: "us-central1".into(),
                },
                "region_mismatch",
            ),
            (
                FailureReason::DiagnosticProofRefused,
                "diagnostic_proof_refused",
            ),
            (
                FailureReason::AlgorithmUnsupported {
                    found: "RSA-PSS".into(),
                },
                "algorithm_unsupported",
            ),
            (
                FailureReason::AuthorityModeMismatch {
                    claimed_authority_id: "auth_acme_co".into(),
                    expected_algorithm: "Ed25519".into(),
                    actual_algorithm: Some("ECDSA-P256".into()),
                },
                "authority_mode_mismatch",
            ),
            (
                FailureReason::AuthorityIdMismatch {
                    claimed_authority_id: None,
                    expected_authority_id: "customer-hsm-example-org-v1".into(),
                    reason:
                        AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
                },
                "authority_id_mismatch",
            ),
            (
                FailureReason::AuthorityIdMismatch {
                    claimed_authority_id: Some("customer-hsm-other-v1".into()),
                    expected_authority_id: "customer-hsm-example-org-v1".into(),
                    reason: AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
                },
                "authority_id_mismatch",
            ),
            (FailureReason::Reserved, "reserved"),
        ];
        for (reason, expected) in cases {
            let json = serde_json::to_string(&reason).expect("serialize");
            let expected_field = format!(r#""type":"{}""#, expected);
            assert!(
                json.contains(&expected_field),
                "variant wire-form tag drifted: expected {}, got {}",
                expected_field,
                json
            );
        }
    }

    /// Pin the closed-enum wire-form for `AuthorityIdMismatchReason`. Drift
    /// here breaks the auditor-side classification of policy-pin rejections.
    #[test]
    fn authority_id_mismatch_reason_wire_form_is_locked() {
        let cases: Vec<(AuthorityIdMismatchReason, &str)> = vec![
            (
                AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
                r#""verifier_policy_demands_customer_hsm_audit_proof_has_none""#,
            ),
            (
                AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
                r#""verifier_policy_authority_id_mismatch""#,
            ),
        ];
        for (reason, expected) in cases {
            let json = serde_json::to_string(&reason).expect("serialize");
            assert_eq!(
                json, expected,
                "AuthorityIdMismatchReason wire-form drift on {:?}",
                reason
            );
        }
    }

    #[test]
    fn signature_failure_reason_wire_form_is_locked() {
        let cases: Vec<(SignatureFailureReason, &str)> = vec![
            (SignatureFailureReason::Malformed, r#""malformed""#),
            (
                SignatureFailureReason::DoesNotVerify,
                r#""does_not_verify""#,
            ),
            (
                SignatureFailureReason::PublicKeyMalformed,
                r#""public_key_malformed""#,
            ),
            (
                SignatureFailureReason::MessageFormatMismatch,
                r#""message_format_mismatch""#,
            ),
        ];
        for (reason, expected) in cases {
            let json = serde_json::to_string(&reason).expect("serialize");
            assert_eq!(json, expected, "SignatureFailureReason wire-form drift");
        }
    }

    #[test]
    fn failure_reason_roundtrips_via_serde() {
        let cases = vec![
            FailureReason::CdpVersionUnsupported {
                found: "99.0".into(),
            },
            FailureReason::SignatureMismatch {
                reason: SignatureFailureReason::DoesNotVerify,
            },
            FailureReason::RegionMismatch {
                required: "europe-west1".into(),
                actual: "us-central1".into(),
            },
            FailureReason::DiagnosticProofRefused,
            FailureReason::AuthorityModeMismatch {
                claimed_authority_id: "auth_acme_co".into(),
                expected_algorithm: "Ed25519".into(),
                actual_algorithm: Some("ECDSA-P256".into()),
            },
            FailureReason::AuthorityModeMismatch {
                claimed_authority_id: "auth_legacy".into(),
                expected_algorithm: "Ed25519".into(),
                actual_algorithm: None,
            },
            FailureReason::AuthorityIdMismatch {
                claimed_authority_id: None,
                expected_authority_id: "customer-hsm-example-org-v1".into(),
                reason:
                    AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
            },
            FailureReason::AuthorityIdMismatch {
                claimed_authority_id: Some("customer-hsm-other-v1".into()),
                expected_authority_id: "customer-hsm-example-org-v1".into(),
                reason: AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
            },
            FailureReason::Reserved,
        ];
        for reason in cases {
            let json = serde_json::to_string(&reason).expect("serialize");
            let restored: FailureReason = serde_json::from_str(&json).expect("deserialize");
            let json_again = serde_json::to_string(&restored).expect("re-serialize");
            assert_eq!(json, json_again, "roundtrip drift on {:?}", reason);
            assert_eq!(reason, restored, "PartialEq drift on {:?}", reason);
        }
    }
}
