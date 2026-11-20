//! Shared verification result types for AuditProof (CDP) verification.
//!
//! **Purpose:** Single source of truth for the `FailureReason` wire-form
//! enum used by:
//!
//! 1. the reference server implementation — at `POST /v1/verify` (server-side typed-failure
//!    response per the specification)
//! 2. `tools/nanorix-verify` — offline auditor CLI (per the verifier specification)
//!
//! Before trust-chain anchoring (this crate), each side maintained its own
//! definition with a "must stay in lockstep" comment — easy to drift,
//! breaking byte-identical typed-failure JSON. Extracting here closes
//! that drift surface forever.
//!
//! **Forever-Standard discipline:** every variant shipped
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
pub mod population_head;
pub mod population_tick;
pub mod signed_tags;

use serde::{Deserialize, Serialize};

/// Closed-enum verification failure reason emitted by AuditProof
/// verification paths. **Forever-stable** — additive only.
///
/// Wire form: `{"type": "<snake_case>", ...payload}` via serde tag dispatch.
///
/// ## Variant catalog (alphabetical by snake_case wire tag)
///
/// | Wire tag | When emitted |
/// |---|---|
/// | `algorithm_unsupported` | V1 only supports Ed25519; unknown algorithm string |
/// | `authority_id_mismatch` | Verifier policy demanded a specific authority and the AuditProof's top-level `authority_id` (default `us-kms-nanorix-v1` when absent; signed only on cdp_version 2.1 and 2.2) differs, or an unsigned `signing_authority.authority_id` disagrees with it |
/// | `authority_mode_mismatch` | Customer-attested authority signature failed against registered Ed25519 key |
/// | `authority_revoked` | Trust-chain manifest marks the signing authority as revoked |
/// | `cdp_version_unsupported` | CDP version not in the verifier's supported set ({1.0, 2.1, 2.2} for the offline verifiers) |
/// | `chain_step_identity_mismatch` | A chain entry's `subsystem` is not the canonical subsystem for its position in the Forever-Standard 8-step order |
/// | `customer_declared_activity_root_mismatch` | The proof's `customer_declared_activity_root` disagreed with the root recomputed from the customer's activity record supplied beside it |
/// | `diagnostic_proof_refused` | Verifier policy refused diagnostic-mode proof |
/// | `field_malformed` | A field is present but its JSON type or shape is not the one the document format defines for it; rejected before any recompute that would consume it |
/// | `final_hash_mismatch` | `final_hash` doesn't match last step's `chain_hash` |
/// | `genesis_hash_mismatch` | First step's `prev_hash` != SHA-512(empty) |
/// | `region_mismatch` | AuditProof region differs from policy required |
/// | `required_field_missing` | Structural field absent from AuditProof JSON |
/// | `reserved` | V2+ wire-surface reservation; never populated in V1 |
/// | `signature_mismatch` | Ed25519 signature verification failed (Nanorix-authority-signed proof) |
/// | `signing_key_version_unknown` | Signing key version not in trust-chain manifest |
/// | `signing_mode_authority_mismatch` | The signed `signing_mode` is `customer_only` while the signed `authority_id` is Nanorix-classified: it contains none of `customer-hsm-`, `customer-kms-`, `customer-tee-`, `customer-byo-`, or it is absent, null or not a string (cdp_version 2.1 and 2.2; section 4) |
/// | `step_count_invalid` | Chain has != 8 steps |
/// | `step_hash_mismatch` | Step at given index didn't reproduce when recomputed |
/// | `streaming_merkle_root_mismatch` | A `streaming_egress_completed.streaming_merkle_root` in the activity trail disagreed with the RFC 6962 root recomputed from the `streaming_egress_chunk` leaves disclosed beside it |
/// | `unsigned_field_populated` | A field the signature does not cover carries a value no Nanorix signer emits (the attestation topology reserved attestation slots) |
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FailureReason {
    /// CDP version not in the verifier's supported set (offline: 1.0 / 2.1 / 2.2).
    CdpVersionUnsupported { found: String },

    /// Required field absent from the AuditProof structure.
    RequiredFieldMissing { field: String },

    /// Step count != 8.
    StepCountInvalid { expected: usize, found: usize },

    /// Step at given index did not reproduce when recomputed from prev_hash.
    StepHashMismatch { step_idx: usize, subsystem: String },

    /// A chain entry declares a `subsystem` that is not the canonical
    /// subsystem for its position in the Forever-Standard 8-step order
    /// :
    ///
    /// `eee_namespace, eee_tmpfs, eee_memory, dire_keys, dire_identity,
    /// fgx_forensic, rzl_audit, capsule_destroy`
    ///
    /// Emitted only when the step's `chain_hash` DID reproduce — i.e. the
    /// hashes are genuine and the label beside them is not. A chain whose
    /// hashes were computed over the non-canonical subsystem fails the
    /// per-step recompute first and reports `StepHashMismatch`, because the
    /// recompute takes its subsystem and method from the canonical table
    /// rather than from the document.
    ///
    /// Distinct from `StepHashMismatch`, which says the recompute disagreed.
    /// Routing this through it would tell an auditor the chain arithmetic
    /// failed when every hash reproduced exactly — the same mis-description
    /// `StreamingMerkleRootMismatch` exists to avoid.
    ///
    /// Field semantics:
    /// - `step_idx`: 0-based index of the offending entry.
    /// - `expected_subsystem`: the canonical subsystem for that index.
    /// - `found_subsystem`: the value the document declared. Empty string
    ///   when the entry omits `subsystem` entirely.
    ChainStepIdentityMismatch {
        step_idx: usize,
        expected_subsystem: String,
        found_subsystem: String,
    },

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
    /// region. Customer setting `VerifierPolicy.required_region` rejects proofs
    /// from a different region, and, with an empty `actual`, every proof whose
    /// region is unsigned: cdp_version 1.0, or 2.1 or 2.2 without a signature.
    RegionMismatch { required: String, actual: String },

    /// Verifier policy refuses diagnostic-mode proofs. With the customer
    /// setting `VerifierPolicy.reject_diagnostic = true`, the offline verifiers
    /// refuse at stage 2 a proof whose signed activity trail carries a
    /// `diagnostic_mode_enabled` event, and every proof whose activity is
    /// unsigned and so cannot show the event is absent: cdp_version 1.0, or 2.1
    /// or 2.2 without a signature. Only a stage 8 (`verified`) result ties the
    /// trail to a Nanorix key.
    DiagnosticProofRefused,

    /// Algorithm not supported by this verifier version (e.g., V1 supports
    /// Ed25519 only; future PQC variants would require an SDK upgrade).
    AlgorithmUnsupported { found: String },

    /// Customer-attested authority signature did not verify against the
    /// registered customer authority's published Ed25519 public key.
    ///
    /// Distinct from `SignatureMismatch`, which covers Nanorix-authority-
    /// signed AuditProof failures. This variant disambiguates customer-
    /// authority failure from Nanorix-authority failure so verifier
    /// consumers can route the failure correctly.
    ///
    /// Customer authority signatures are
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
    /// AuditProof's top-level `authority_id` (`us-kms-nanorix-v1` when absent)
    /// differs from it, or an unsigned `signing_authority.authority_id`
    /// disagrees with the top-level value. Per VP Security
    /// extended review F4.3. The signature covers the top-level
    /// `authority_id` only on cdp_version 2.1 and 2.2; on 1.0 nothing signed
    /// covers it, so there a string other than `us-kms-nanorix-v1` is refused
    /// and a pin accepts only the Nanorix default authority. cdp_version 2.0
    /// is refused with `CdpVersionUnsupported` before the pin is read. Without
    /// a trust-chain manifest the authority is only as trustworthy as the
    /// embedded key, so a pin is a full authority check only when the result
    /// reaches stage 8.
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
    /// consumers (auditor CLI, customer SDK, browser verifier) distinguish it
    /// from "the registered authority's algorithm is wrong" (cryptographic
    /// concern; re-publish the key). The variant itself carries two different
    /// situations:
    ///
    /// - a policy mismatch: the proof's authority is genuine and is not the
    ///   one the pin names (operational misconfiguration; refresh the policy
    ///   or accept the proof under different terms);
    /// - an unsigned or contradicting label: the top-level `authority_id` on
    ///   a cdp_version whose signature does not cover it, or a
    ///   `signing_authority.authority_id` that contradicts the proof's
    ///   authority (the document was altered after signing or is malformed;
    ///   do not accept it).
    ///
    /// `claimed_authority_id` below says how a consumer tells them apart.
    ///
    /// Field semantics:
    /// - `claimed_authority_id`: the offending authority id in the
    ///   AuditProof, chosen in the order the checks run. First, on a
    ///   cdp_version whose signature does not cover the top-level
    ///   `authority_id` (1.0), a top-level string other than
    ///   `us-kms-nanorix-v1` is refused and this is that top-level value.
    ///   Next, a `signing_authority.authority_id` that disagrees with the
    ///   proof's authority is refused and this is that unsigned value.
    ///   Otherwise it is the top-level `authority_id` that differs from the
    ///   pin. It is unsigned in the first two cases. `None` when the
    ///   top-level `authority_id` is absent or not a string (Nanorix-default
    ///   signing path; Forever-Standard pre-amendment shape). When it
    ///   equals `expected_authority_id`, the value was unsigned: one of the
    ///   first two checks refused it. A first-check refusal where it differs
    ///   from `expected_authority_id` is wire-identical to a plain mismatch of
    ///   the top-level value, so a consumer reads the proof's `cdp_version`
    ///   to tell them apart (only 2.1 and 2.2 sign the top-level field).
    /// - `expected_authority_id`: the value of
    ///   `VerificationPolicy.required_authority_id` that the verifier was
    ///   initialized with. Always populated in this variant — if it were
    ///   `None`, no policy-pin gate would fire and this variant would not be
    ///   emitted.
    /// - `reason`: closed enum classifying which of the two failure shapes
    ///   produced this rejection (none-vs-policy or wrong-id-vs-policy).
    ///   Forever-stable; future additions are additive.
    AuthorityIdMismatch {
        claimed_authority_id: Option<String>,
        expected_authority_id: String,
        reason: AuthorityIdMismatchReason,
    },

    /// A streaming-egress Merkle root in the activity trail does not equal the
    /// root recomputed from the chunk leaves disclosed alongside it.
    ///
    /// `streaming_egress_completed.streaming_merkle_root` is an RFC 6962
    /// SHA-512 commitment over the `chunk_hash` values of the
    /// `streaming_egress_chunk` events that precede it (leaf
    /// `SHA-512(0x00 || chunk_hash)`, inner `SHA-512(0x01 || l || r)`, odd tail
    /// promoted). Reference implementation:
    /// `merkle_root_from_leaves` in the capsule runtime.
    ///
    /// Emitted only when the leaves are actually present and complete — a
    /// document that discloses the root alone is a valid future shape (the
    /// commitment is what a Merkle root is for) and is carried past unchecked,
    /// not rejected.
    ///
    /// Distinct from `StepHashMismatch` / `FinalHashMismatch`, which are bound
    /// to the 8-step destruction chain and say nothing about egress. Routing
    /// this through either would tell an auditor the destruction chain failed
    /// when it reproduced exactly.
    ///
    /// Field semantics:
    /// - `claimed`: the `streaming_merkle_root` value as it appears in the
    ///   document, prefix included.
    /// - `computed`: the root recomputed from the disclosed leaves, emitted in
    ///   the same `sha512:`-prefixed form so the two are directly comparable.
    StreamingMerkleRootMismatch { claimed: String, computed: String },

    /// The proof's `customer_declared_activity_root` does not equal the root
    /// recomputed from the customer's own activity record.
    ///
    /// The root is a SHA-512 Merkle commitment over the raw bytes of the
    /// activity buffer the workload wrote — split on `0x0A`, one leaf per
    /// line, never parsed or trimmed. The proof carries the root only; the
    /// customer holds the record. Recomputation therefore needs the record as
    /// a sidecar, and this variant is emitted only when one was supplied.
    ///
    /// The root is inside the canonical view, so a proof whose root was
    /// altered after signing fails `SignatureMismatch` first. This variant is
    /// reached when the signed root is genuine and the bytes presented as the
    /// record are not the bytes that were committed — the record, not the
    /// proof, is what disagrees.
    ///
    /// Distinct from `StepHashMismatch` / `FinalHashMismatch` (the 8-step
    /// destruction chain, which reproduced) and from
    /// `StreamingMerkleRootMismatch` (egress evidence Nanorix observed). This
    /// root commits to bytes Nanorix never interpreted; the field name carries
    /// that provenance and the failure must carry it too.
    ///
    /// Field semantics:
    /// - `claimed`: the `customer_declared_activity_root` value as it appears
    ///   in the document, prefix included.
    /// - `computed`: the root recomputed from the supplied record, in the same
    ///   `sha512:`-prefixed form so the two are directly comparable.
    CustomerDeclaredActivityRootMismatch { claimed: String, computed: String },

    /// A field is present but is not the JSON type or shape the document
    /// format defines for it.
    ///
    /// Distinct from `RequiredFieldMissing` (the field is there) and from the
    /// mismatch variants (nothing was recomputed). A verifier emits this
    /// BEFORE any recompute that would consume the field, so a value that
    /// could never have been emitted by a Nanorix signer — a number where a
    /// `sha512:`-prefixed digest belongs, an empty string, uppercase hex, a
    /// wrong-length digest — is named as the defect rather than surfacing as
    /// a signature or root mismatch that blames the wrong thing.
    ///
    /// First use: `customer_declared_activity_root`, which must be
    /// a JSON string of `sha512:` + 128 lowercase hex characters (a bare
    /// 128-hex digest is also accepted). The empty string is malformed, not
    /// absent: the canonical view binds `""` as a value, so every verifier
    /// must read it the same way.
    ///
    /// Field semantics:
    /// - `field`: the JSON key that was malformed, verbatim.
    /// - `reason`: a short verifier-authored phrase naming what was wrong
    ///   (free text; not a closed vocabulary — consumers branch on `field`,
    ///   not on `reason`).
    FieldMalformed { field: String, reason: String },

    /// A field that the signature does NOT cover carries a value that no
    /// Nanorix signer emits.
    ///
    /// The eight reserved attestation slots
    /// sit outside `CanonicalCdpView`, so their contents are
    /// unsigned. Seven of them are hard-coded `None` at every emit site, and
    /// no verifier reads any of them. A document carrying one is therefore
    /// either from a schema this build does not know or was altered after
    /// signing by someone holding no key — and the signature cannot tell the
    /// difference, because it never covered the field. Rejecting is the only
    /// honest verdict: reporting "not tampered since signing" about such a
    /// document is false in exactly the case the sentence exists to rule out.
    ///
    /// `per_event_attestations` is deliberately NOT in the rejected set. It is
    /// the one reserved slot the server genuinely populates (drained from
    /// `capsule_event_attestations` at destroy). The slot sits outside the
    /// signed hash and is accepted unchecked: its entries prove nothing about
    /// who signed, and verifying or binding them is separate work.
    ///
    /// Field semantics: `field` is the JSON key that was populated, verbatim.
    UnsignedFieldPopulated { field: String },

    /// The proof's signed `signing_mode` is `customer_only` while its signed
    /// `authority_id` is Nanorix-classified (section 4).
    ///
    /// Both fields are inside the canonical view on cdp_version 2.1 and 2.2,
    /// so a signed proof refused here was signed with the contradiction in it.
    /// The refusal is a statement about the two labels only: it does not say
    /// which key signed or who holds it. Any key, Nanorix's included, is
    /// refused the same way, and the check also runs on a proof that carries
    /// no signature.
    ///
    /// "Customer-classified" is the issuer's test
    /// (`AuthorityKind::from_authority_id`): the id contains one of the byte
    /// strings `customer-hsm-`, `customer-kms-`, `customer-tee-` or
    /// `customer-byo-` anywhere, compared byte for byte and case-sensitively,
    /// with no normalization. Every other id is Nanorix-classified, and so is
    /// an absent, null or non-string `authority_id`. A `nanorix_only` proof
    /// under a customer-classified authority is not refused; the amendment's
    /// "Legacy proofs" section rules it.
    ///
    /// This variant is distinct from `AuthorityModeMismatch`, which reports a
    /// customer authority's signature that failed against its registered key.
    ///
    /// Field semantics: `claimed_authority_id` is the top-level
    /// `authority_id` the proof carries, verbatim, or `None` (serialized as
    /// `null`) when that field is absent, null or not a string.
    SigningModeAuthorityMismatch {
        claimed_authority_id: Option<String>,
    },

    /// Reserved for V2+; never populated in V1. Existence reserves the wire
    /// surface for future extension without breaking serde tag dispatch.
    Reserved,
}

/// Sub-reason for `FailureReason::AuthorityIdMismatch`. Closed enum;
/// forever-stable. Additive only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityIdMismatchReason {
    /// Verifier policy pinned a specific `required_authority_id` and the
    /// proof names no top-level `authority_id`, so the Nanorix default
    /// (`us-kms-nanorix-v1`) applies, and the pin names another authority.
    /// Customer's policy demanded customer-HSM; AuditProof has no
    /// customer-HSM attestation.
    VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
    /// Verifier policy pinned a specific `required_authority_id` and the
    /// AuditProof's top-level `authority_id` does not match it, or an
    /// unsigned `signing_authority.authority_id` disagrees with the top-level
    /// value, or the top-level `authority_id` is a string other than
    /// `us-kms-nanorix-v1` on a cdp_version (1.0) whose signature does not
    /// cover it. In the last two cases the claimed id may equal the pin; what
    /// is refused is the unsigned value, not a disagreement with the pin.
    VerifierPolicyAuthorityIdMismatch,
}

/// Sub-reason for `FailureReason::SignatureMismatch`. Closed enum;
/// forever-stable.
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
            (
                FailureReason::ChainStepIdentityMismatch {
                    step_idx: 3,
                    expected_subsystem: "dire_keys".into(),
                    found_subsystem: "rzl_audit".into(),
                },
                "chain_step_identity_mismatch",
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
            (
                FailureReason::StreamingMerkleRootMismatch {
                    claimed: "sha512:aa".into(),
                    computed: "sha512:bb".into(),
                },
                "streaming_merkle_root_mismatch",
            ),
            (
                FailureReason::CustomerDeclaredActivityRootMismatch {
                    claimed: "sha512:aa".into(),
                    computed: "sha512:bb".into(),
                },
                "customer_declared_activity_root_mismatch",
            ),
            (
                FailureReason::FieldMalformed {
                    field: "customer_declared_activity_root".into(),
                    reason: "expected a JSON string".into(),
                },
                "field_malformed",
            ),
            (
                FailureReason::UnsignedFieldPopulated {
                    field: "witness_signatures".into(),
                },
                "unsigned_field_populated",
            ),
            (
                FailureReason::SigningModeAuthorityMismatch {
                    claimed_authority_id: Some("us-kms-nanorix-v1".into()),
                },
                "signing_mode_authority_mismatch",
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
            FailureReason::StreamingMerkleRootMismatch {
                claimed: "sha512:aa".into(),
                computed: "sha512:bb".into(),
            },
            FailureReason::CustomerDeclaredActivityRootMismatch {
                claimed: "sha512:aa".into(),
                computed: "sha512:bb".into(),
            },
            FailureReason::FieldMalformed {
                field: "customer_declared_activity_root".into(),
                reason: "expected a JSON string".into(),
            },
            FailureReason::UnsignedFieldPopulated {
                field: "witness_signatures".into(),
            },
            FailureReason::SigningModeAuthorityMismatch {
                claimed_authority_id: Some("us-kms-nanorix-v1".into()),
            },
            FailureReason::SigningModeAuthorityMismatch {
                claimed_authority_id: None,
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
