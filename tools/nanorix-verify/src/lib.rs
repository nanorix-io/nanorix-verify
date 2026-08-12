//! Nanorix AuditProof verifier — standalone library.
//!
//! Implements the 8-step AuditProof specification verification pipeline against an AuditProof
//! JSON document. Independent of any Nanorix service: this crate has no HTTP
//! client, so every verification is local. The trust-chain manifest, when one
//! is used, is supplied as a local file and is itself signed.
//!
//! Per the verifier specification : "auditor
//! verification CLI — the literal moment-of-truth artifact when an OCR
//! auditor walks in."
//!
//! # Trust model
//!
//! The verifier needs ONE thing the customer cannot tamper with: a trusted
//! public key for the AuditProof's signing authority. Two paths:
//!
//! 1. **Trust-chain manifest** — supplied as a local file via `--trust-chain`,
//!    and pinned with `--identity-fingerprint`. The manifest is itself signed
//!    by a long-term identity key. Nothing is retrieved over the network; if
//!    you obtain a manifest from a published location, you fetch it yourself.
//! 2. **Direct override** (`--public-key`) — for offline / sovereign-auditor
//!    use cases where customer brings the public key themselves.
//!
//! # Verification stages
//!
//! Per the AuditProof specification:
//! 1. Schema validation (required fields present, types correct)
//! 2. cdp_version recognized (1.0 / 2.0 / 2.1)
//! 3. Chain reproducibility (recompute SHA-512 chain from genesis)
//! 4. Final hash binding (final_hash matches last step's chain_hash)
//! 5. Canonical hash binding (v2.x; canonical_hash recompute matches)
//! 6. Signing key resolution (signing_key_version → public key)
//! 7. Ed25519 signature verification
//! 8. Authority status (active / revoked / fingerprint stale)
//!
//! Each stage emits a typed `FailureReason` on failure (per the verifier specification).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub mod boundary;
pub mod bundle;
pub mod canonical_recompute;
pub mod checkpoint;
pub mod pubkey_bundle;
pub mod trust_chain;
pub use boundary::{
    recompute_activity_commitment, recompute_boundary_canonical_hash, verify_boundary_attestation,
    verify_boundary_chain, verify_disclosed_activity_trail, BoundaryChainResult,
    BoundaryFailureReason, BoundaryMetadata, BoundaryVerificationResult, BOUNDARY_ATTESTATION_KIND,
    BOUNDARY_CONTINUATION_STATEMENT, BOUNDARY_OBSERVATION_METHODS, BOUNDARY_SUPPORTED_VERSIONS,
};
pub use bundle::{
    bundle_verdict_text, extract_receipt_bundle, verify_receipt_bundle, AuditProofAnchors,
    BundleError, PortableReceiptBundle, PORTABLE_RECEIPT_BUNDLE_DISCLAIMER,
    SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH, SIGNATURE_TARGET_STEP8_CHAIN_HASH,
};
pub use pubkey_bundle::{
    build_pubkey_bundle, resolve_parent_key, resolve_parent_key_forever, verify_pubkey_bundle,
    BundleSignature, PortablePubkeyBundle, PubKeyEntry, PubkeyBundleError,
    PORTABLE_PUBKEY_BUNDLE_DISCLAIMER,
};
pub use trust_chain::{
    AuthorityRecord, KeyLookupResult, KeyStatus, KeyVersionRecord, TrustChainManifest,
};

pub const NANORIX_GENESIS_HASH: &str =
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
pub const NANORIX_CHAIN_STEPS: usize = 8;

/// Output of a verification attempt. Mirrors the wire shape that the
/// authenticated `POST /v1/verify` endpoint will return once the specification ships.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationResult {
    /// True if and only if every check stage passed.
    pub valid: bool,

    /// Populated when `valid` is false. Closed enum aligned with the API
    /// surface (per the specification).
    pub failure_reason: Option<FailureReason>,

    /// 1..=8 indicating the highest stage reached (advisory; matches the specification
    /// I8 step numbering).
    pub stage_reached: u8,

    /// Populated diagnostic metadata (no payload bytes; structural only).
    pub metadata: VerificationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationMetadata {
    pub cdp_version: Option<String>,
    pub capsule_id: Option<String>,
    pub region: Option<String>,
    pub signing_key_version: Option<String>,
    pub algorithm: Option<String>,
    pub step_count: Option<usize>,
    pub activity_event_count: Option<usize>,

    /// `Some(ts)` when the document carried no usable `destroyed_at` and the
    /// chain timestamp was recovered from `attestation.key_id` (the chain-timestamp recovery rule
    /// pre-restoration proofs). `None` means the timestamp was read from the
    /// document's own `destroyed_at` field. An auditor reading a verdict can
    /// therefore always tell which route produced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_chain_timestamp: Option<String>,
}

// trust-chain anchoring (commit landing this re-export): closed-enum verification
// failure reasons + signature sub-reasons extracted to the
// `nanorix-verify-types` workspace crate (governance/verify-types).
// Re-exporting here preserves the `nanorix_verify::{FailureReason,
// SignatureFailureReason}` public surface so existing callers (CLI
// `main.rs`, `tests/integration_tests.rs`, downstream auditor tooling)
// keep working with zero call-site change.
//
// services/api now consumes the SAME definition from this single source
// of truth — no more "must stay in lockstep" comment, no more drift
// surface. Forever-Standard wire form (serde tag = "type", rename_all =
// "snake_case") locked in the shared crate's tests.
pub use nanorix_verify_types::{AuthorityIdMismatchReason, FailureReason, SignatureFailureReason};

/// Verifier policy. Customer / auditor decides what to refuse.
///
/// Per the Forever-Standard wire discipline + the customer-authority specification G7: this struct is field-additive
/// Forever-Standard. Pre-amendment callers passing
/// `VerifierPolicy::default()` continue to behave identically — every
/// new field defaults to its "accept anything" semantics. New fields
/// land via the `..Default::default()` struct-update syntax, NEVER as
/// breaking-shape changes.
#[derive(Debug, Clone, Default)]
pub struct VerifierPolicy {
    /// If true, refuse AuditProofs whose attestation indicates
    /// `diagnostic_mode: true` (the specification). Default: false (accept diagnostic
    /// proofs).
    pub reject_diagnostic: bool,

    /// If Some, require the AuditProof's `region` field match. None = accept
    /// any region.
    pub required_region: Option<String>,

    /// If `Some(authority_id)`, require the AuditProof's
    /// `signing_authority.authority_id` match. AuditProofs that omit
    /// `signing_authority` entirely (Nanorix-default signing path) OR
    /// carry a different `authority_id` are rejected with
    /// `FailureReason::AuthorityIdMismatch`. Per the customer-authority specification G7 + VP Security
    /// extended-review F4.3 — closes the policy-mode-mismatch attack where
    /// a malicious AuditProof claims `signing_authority: None` while the
    /// customer's policy demands customer-HSM signing.
    ///
    /// Default `None` — no policy pin. AuditProofs with any signing
    /// authority (Nanorix-default OR customer-HSM) verify successfully
    /// against this gate.
    pub required_authority_id: Option<String>,

    /// trust-chain anchoring trust root. When `Some`, the verifier resolves the proof's
    /// signing key against this (already-verified) manifest and re-verifies the
    /// signature against the manifest key — reaching stage 8 ("verify without
    /// trusting Nanorix"). `main.rs` verifies the manifest's OWN signature
    /// against `pinned_identity_fingerprint` BEFORE placing it here, so by the
    /// time `verify_auditproof` sees it the trust root is established. `None`
    /// (default) → integrity-only stage 7 (embedded-key check).
    pub trust_chain: Option<crate::trust_chain::TrustChainManifest>,

    /// The out-of-band-pinned identity fingerprint the `trust_chain` manifest
    /// was verified against. Carried for provenance/auditability. `None` when
    /// no trust root is in use.
    pub pinned_identity_fingerprint: Option<String>,
}

/// Stub trusted-authority record. Real implementation reads from trust-chain
/// manifest or `--public-key` flag.
#[derive(Debug, Clone)]
pub struct TrustedAuthority {
    pub authority_id: String,
    pub signing_key_version: String,
    pub public_key_b64: String,
    pub revoked: bool,
}

/// Top-level verify entrypoint. Loads AuditProof JSON, runs 8-stage
/// verification per the AuditProof specification, returns structured result.
///
/// **NOTE:** This is the V1 implementation scaffold. Per the verifier specification ship plan, the
/// full the AuditProof specification stage 5 (canonical_hash recompute) and stage 6 (signing
/// key resolution from trust chain) need the shared verification crate
/// extracted from the AuditProof document builder to avoid divergence.
/// V1 provides chain integrity (stages 1-4) which catches the common
/// tamper cases.
pub fn verify_auditproof(
    json: &serde_json::Value,
    _trust: &[TrustedAuthority],
    policy: &VerifierPolicy,
) -> VerificationResult {
    let mut metadata = VerificationMetadata {
        cdp_version: None,
        capsule_id: None,
        region: None,
        signing_key_version: None,
        algorithm: None,
        step_count: None,
        activity_event_count: None,
        recovered_chain_timestamp: None,
    };

    // Stage 1: schema validation — cdp_version present
    let cdp_version = match json.get("cdp_version").and_then(|v| v.as_str()) {
        Some(v) => {
            metadata.cdp_version = Some(v.to_string());
            v.to_string()
        }
        None => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::RequiredFieldMissing {
                    field: "cdp_version".into(),
                }),
                stage_reached: 1,
                metadata,
            };
        }
    };

    // Stage 2: cdp_version recognized
    if !["1.0", "2.0", "2.1"].contains(&cdp_version.as_str()) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::CdpVersionUnsupported { found: cdp_version }),
            stage_reached: 2,
            metadata,
        };
    }

    metadata.capsule_id = json
        .get("capsule_id")
        .and_then(|v| v.as_str())
        .map(String::from);

    metadata.region = json
        .pointer("/environment/region")
        .or_else(|| json.get("region"))
        .and_then(|v| v.as_str())
        .map(String::from);

    metadata.signing_key_version = json
        .pointer("/attestation/signing_key_version")
        .or_else(|| json.get("signing_key_version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    metadata.algorithm = json
        .pointer("/attestation/algorithm")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Policy-pin gate (the customer-authority specification G7 / VP Security F4.3).
    //
    // When the customer / auditor pins `required_authority_id`, the
    // AuditProof's `signing_authority.authority_id` must match. The
    // AuditProof field is `Option<SigningAuthority>` per the customer-authority specification D2:
    //
    // - `signing_authority` field absent OR explicit JSON `null` →
    //   Nanorix-default signing path. Reject with reason
    //   `verifier_policy_demands_customer_hsm_audit_proof_has_none`.
    // - `signing_authority.authority_id` present and equals policy →
    //   accept; continue to chain integrity checks.
    // - `signing_authority.authority_id` present and differs from policy →
    //   reject with reason `verifier_policy_authority_id_mismatch`.
    //
    // The gate runs BEFORE chain integrity checks because the policy
    // decision is independent of chain validity — a customer who pinned
    // the wrong authority should learn that quickly, not after a 7-step
    // SHA-512 chain walk. Stage_reached carries the conventional value
    // 2 (post-version-check, pre-chain-walk).
    if let Some(required) = policy.required_authority_id.as_ref() {
        let claimed = json
            .pointer("/signing_authority/authority_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        match claimed {
            None => {
                return VerificationResult {
                    valid: false,
                    failure_reason: Some(FailureReason::AuthorityIdMismatch {
                        claimed_authority_id: None,
                        expected_authority_id: required.clone(),
                        reason:
                            AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
                    }),
                    stage_reached: 2,
                    metadata,
                };
            }
            Some(actual) if actual != *required => {
                return VerificationResult {
                    valid: false,
                    failure_reason: Some(FailureReason::AuthorityIdMismatch {
                        claimed_authority_id: Some(actual),
                        expected_authority_id: required.clone(),
                        reason: AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
                    }),
                    stage_reached: 2,
                    metadata,
                };
            }
            Some(_match) => {
                // Authority matches policy pin; fall through to chain checks.
            }
        }
    }

    // Residency-pin gate (the specification G1 / the region policy).
    //
    // Same shape and rationale as the authority pin above: when the auditor
    // pins `required_region`, a proof asserting a different region is rejected
    // before the chain walk. A proof that carries no region at all cannot
    // satisfy a residency pin — it is rejected with an empty `actual` rather
    // than accepted, so the pin fails closed.
    if let Some(required) = policy.required_region.as_ref() {
        let actual = metadata.region.clone().unwrap_or_default();
        if actual != *required {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::RegionMismatch {
                    required: required.clone(),
                    actual,
                }),
                stage_reached: 2,
                metadata,
            };
        }
    }

    // Stage 3: chain reproducibility
    let chain = match json.get("chain").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::RequiredFieldMissing {
                    field: "chain".into(),
                }),
                stage_reached: 3,
                metadata,
            };
        }
    };
    metadata.step_count = Some(chain.len());

    if chain.len() != NANORIX_CHAIN_STEPS {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::StepCountInvalid {
                expected: NANORIX_CHAIN_STEPS,
                found: chain.len(),
            }),
            stage_reached: 3,
            metadata,
        };
    }

    // the chain-timestamp recovery rule — proofs issued before `destroyed_at` was restored to the wire
    // document carry the chain timestamp only in `attestation.key_id`. Recover
    // it there so authentic pre-restoration proofs reproduce their chain; the
    // recovered value is disclosed in the verdict metadata, never silently
    // substituted.
    let (timestamp, recovered) = resolve_chain_timestamp(json);
    let timestamp = timestamp.as_str();
    metadata.recovered_chain_timestamp = recovered;

    // the per-record receipt specification + the receipt-batching specification the receipt pipeline (2026-05-12) — extract optional Merkle roots
    // for Step 8 amendment. None for pre-the receipt pipeline proofs (both branches collapse
    // to the legacy formula → byte-identical chain walk).
    let rrmr_opt = json
        .get("record_receipts_merkle_root")
        .and_then(|v| v.as_str());
    let ppmr_opt = json
        .get("parent_proofs_merkle_root")
        .and_then(|v| v.as_str());

    let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
    for (idx, step) in chain.iter().enumerate() {
        let subsystem = step.get("subsystem").and_then(|v| v.as_str()).unwrap_or("");
        let claimed_chain_hash = step
            .get("chain_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let method = lookup_method(subsystem);

        let recomputed = if idx == 7 && subsystem == "capsule_destroy" {
            // the per-record receipt specification + the receipt-batching specification Step 8 amendment — presence-conditional
            // Merkle-root incorporation. The (None, None) branch returns the
            // legacy formula bit-for-bit (Forever-Standard).
            compute_step_8_amended_verifier(&prev_hash, timestamp, rrmr_opt, ppmr_opt)
        } else {
            compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp)
        };

        if recomputed != strip_hash_prefix(claimed_chain_hash) {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::StepHashMismatch {
                    step_idx: idx,
                    subsystem: subsystem.to_string(),
                }),
                stage_reached: 3,
                metadata,
            };
        }
        prev_hash = recomputed;
    }

    // ── the per-record receipt specification receipt set verification (Mode A step 3) ──
    // If `record_receipts` is present, recompute the Merkle root from the
    // receipts in order and compare to the claimed `record_receipts_merkle_root`.
    // Each receipt's `record_chain_hash` is also recomputed from its fields.
    if let Some(receipts) = json.get("record_receipts").and_then(|v| v.as_array()) {
        if let Some(failure) = verify_record_receipts(
            receipts,
            metadata.capsule_id.as_deref().unwrap_or(""),
            rrmr_opt,
        ) {
            return VerificationResult {
                valid: false,
                failure_reason: Some(failure),
                stage_reached: 3,
                metadata,
            };
        }
    }

    // ── the receipt-batching specification parent-proof set verification ──
    // If `parent_proof_hashes` is present, recompute the parent Merkle root
    // from each link's `parent_chain_hash` and compare to the claimed root.
    // Per-link signature verification (independent pubkey resolution) is
    // out of Wave A scope — Wave B Portable Pubkey Bundle support.
    if let Some(parents) = json.get("parent_proof_hashes").and_then(|v| v.as_array()) {
        if let Some(failure) = verify_parent_proofs(parents, ppmr_opt) {
            return VerificationResult {
                valid: false,
                failure_reason: Some(failure),
                stage_reached: 3,
                metadata,
            };
        }
    }

    // Stage 4: final_hash binding
    let claimed_final = json
        .get("final_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let last_chain_hash = chain
        .last()
        .and_then(|s| s.get("chain_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if strip_hash_prefix(claimed_final) != strip_hash_prefix(last_chain_hash) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::FinalHashMismatch {
                claimed: claimed_final.to_string(),
                computed: last_chain_hash.to_string(),
            }),
            stage_reached: 4,
            metadata,
        };
    }

    // Algorithm dispatch precedes byte-shape checks (the specification C.1): a proof
    // declaring a non-Ed25519 signature algorithm fails typed as
    // AlgorithmUnsupported here — it must never fall through to the 64/32-byte
    // decode gates and report as "malformed". Absent or "Ed25519" proceeds
    // unchanged (every proof issued to date).
    if let Some(found) = declared_non_ed25519_algorithm(json) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::AlgorithmUnsupported { found }),
            stage_reached: 4,
            metadata,
        };
    }

    // Stages 5-8: signature verification. sub-A verifies the Ed25519 signature
    // over the version/mode-appropriate message (v1.0 final_hash, v2.0
    // document_hash, v2.1 nanorix_only canonical_hash) against the key EMBEDDED
    // in the proof — integrity (stage 7). sub-B then ANCHORS that to the Nanorix
    // trust root: if a verified trust-chain manifest is supplied, resolve the
    // signing key from it and re-verify against the manifest key — authenticity
    // (stage 8).
    match canonical_recompute::verify_signature(json, &cdp_version) {
        // Embedded-key signature valid → integrity proven. Attempt sub-B
        // trust-anchoring to reach stage 8.
        canonical_recompute::SignatureCheck::Verified => {
            anchor_to_trust_chain(json, &cdp_version, policy, metadata)
        }
        // Chain reproduced but no signature this build can check (unsigned
        // partial, or dual_signature/tee_attested). Honest: this is NOT a full
        // cryptographic verification — the CLI prints "Chain verified ·
        // signature NOT checked" at stage 4. Fail-closing the exit code in this
        // case is a policy decision deferred to sub-B.
        canonical_recompute::SignatureCheck::Absent => VerificationResult {
            valid: true,
            failure_reason: None,
            stage_reached: 4,
            metadata,
        },
        // A signature was present and did not verify → reject.
        // Declared a signing_mode this build cannot verify. NOT the same as
        // "no signature": signing_mode is inside the canonical hash and is
        // attacker-controllable, so treating an unrecognised mode as a partial
        // success turns a rejection into reassurance — a downgrade oracle.
        // AlgorithmUnsupported is the existing Forever-Standard reason for
        // "this build cannot perform the verification this document requires";
        // the resolution (upgrade the verifier) is identical.
        canonical_recompute::SignatureCheck::Unsupported(mode) => VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::AlgorithmUnsupported {
                found: format!("signing_mode={mode}"),
            }),
            stage_reached: 4,
            metadata,
        },
        canonical_recompute::SignatureCheck::Failed(reason) => VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::SignatureMismatch { reason }),
            stage_reached: 7,
            metadata,
        },
    }
}

/// The signature algorithm the proof declares, when it is not Ed25519.
///
/// Reads `attestation.algorithm` and the top-level `signature_algorithm`;
/// either declaring anything other than the exact canonical string `"Ed25519"`
/// makes the proof unverifiable by this build. Both absent is the pre-field
/// era, which is Ed25519 by definition.
fn declared_non_ed25519_algorithm(json: &serde_json::Value) -> Option<String> {
    [
        json.pointer("/attestation/algorithm"),
        json.get("signature_algorithm"),
    ]
    .into_iter()
    .flatten()
    .filter_map(|v| v.as_str())
    .find(|s| *s != "Ed25519")
    .map(str::to_string)
}

/// trust-chain anchoring — anchor an integrity-verified proof (sub-A passed, stage 7) to
/// the Nanorix trust root.
///
/// With a verified trust-chain manifest in `policy.trust_chain`, resolve the
/// proof's `(authority_id, signing_key_version)` to the manifest's published
/// key (archive-forever: resolves rotated-away versions too), re-verify the
/// signature against THAT key, and check the authority is not revoked. Success
/// is stage 8 — "verify without trusting Nanorix", and the point at which a
/// forged proof (carrying its own embedded key, not the manifest key) is
/// rejected. Without a manifest, the proof stays at honest stage 7 (integrity
/// only).
fn anchor_to_trust_chain(
    json: &serde_json::Value,
    cdp_version: &str,
    policy: &VerifierPolicy,
    metadata: VerificationMetadata,
) -> VerificationResult {
    let manifest = match &policy.trust_chain {
        Some(m) => m,
        None => {
            return VerificationResult {
                valid: true,
                failure_reason: None,
                stage_reached: 7,
                metadata,
            };
        }
    };

    let authority_id = json
        .get("authority_id")
        .and_then(|v| v.as_str())
        .unwrap_or("us-kms-nanorix-v1");
    let signing_key_version = json
        .pointer("/attestation/signing_key_version")
        .or_else(|| json.get("signing_key_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Stage 6: resolve the signing key against the trust chain.
    let lookup = match manifest.find_key(authority_id, signing_key_version) {
        Some(l) => l,
        None => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::SigningKeyVersionUnknown {
                    version: signing_key_version.to_string(),
                }),
                stage_reached: 6,
                metadata,
            };
        }
    };

    // Stage 7: re-verify the signature against the MANIFEST key (not embedded).
    // Genuine proof: embedded key == manifest key → verifies. Forged proof: its
    // own embedded key passed sub-A but is not the manifest key → fails here.
    match canonical_recompute::verify_signature_against(
        json,
        cdp_version,
        &lookup.record.public_key_b64,
    ) {
        canonical_recompute::SignatureCheck::Verified => {}
        canonical_recompute::SignatureCheck::Failed(reason) => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::SignatureMismatch { reason }),
                stage_reached: 7,
                metadata,
            };
        }
        // Defensive: sub-A already confirmed a signature is present and the
        // version/mode is verifiable, so neither is reachable here. Unsupported
        // in particular cannot occur — sub-A rejects it before stage 8.
        canonical_recompute::SignatureCheck::Unsupported(mode) => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::AlgorithmUnsupported {
                    found: format!("signing_mode={mode}"),
                }),
                stage_reached: 7,
                metadata,
            };
        }
        canonical_recompute::SignatureCheck::Absent => {
            return VerificationResult {
                valid: true,
                failure_reason: None,
                stage_reached: 7,
                metadata,
            };
        }
    }

    // Stage 8: authority status. A revoked authority's keys are untrusted.
    if lookup.authority_record.revoked {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::AuthorityRevoked),
            stage_reached: 8,
            metadata,
        };
    }

    // Signature verified against the trust-anchored key + authority active →
    // full "verify without trusting Nanorix".
    VerificationResult {
        valid: true,
        failure_reason: None,
        stage_reached: 8,
        metadata,
    }
}

/// Compute one step's hash. Mirrors `governance/rzl::compute_step_hash`.
///
/// Format: SHA-512(prev_hash \x00 subsystem \x00 action \x00 method \x00 timestamp)
pub fn compute_step_hash(
    prev_hash: &str,
    subsystem: &str,
    action: &str,
    method: &str,
    timestamp: &str,
) -> String {
    let mut hasher = Sha512::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\x00");
    hasher.update(subsystem.as_bytes());
    hasher.update(b"\x00");
    hasher.update(action.as_bytes());
    hasher.update(b"\x00");
    hasher.update(method.as_bytes());
    hasher.update(b"\x00");
    hasher.update(timestamp.as_bytes());
    hex::encode(hasher.finalize())
}

/// Recover the chain timestamp from an attestation `key_id`.
///
/// AuditProofs issued before the chain-timestamp recovery rule restored the document-level `destroyed_at`
/// field carry the chain timestamp in exactly one place: the attestation
/// `key_id`, built by the chain specification as
/// `nrx-verify-{terminated_at with ':' replaced by '-'}-{capsule_id[..8]}`.
/// Only the TIME portion ever held colons — the ISO-8601 date carries its own
/// dashes — so restoration splits at `T` and rewrites dashes on the right-hand
/// side only. Fractional seconds and the zone suffix (`Z`, `+00:00`) pass
/// through untouched.
///
/// Returns `None` unless the reconstruction has the exact ISO-8601
/// `YYYY-MM-DDTHH:MM:SS` shape.
///
/// # Why recovering from an attacker-mutable field is sound
///
/// `key_id` is covered by NEITHER signed message: v1.0 signs `final_hash`, and
/// the v2.x canonical view (the AuditProof document builder
/// `CanonicalCdpView` / `CanonicalAttestationSubset`) excludes the whole
/// attestation by construction. So `key_id` can be edited without invalidating
/// a signature — which is precisely why the recovered value is never trusted on
/// its own. It is an INPUT to the chain walk, and the chain hashes it must
/// reproduce ARE signature-bound (v1.0: `final_hash` is the signed message;
/// v2.x: `destruction_chain` sits inside the canonical hash). Exactly one
/// timestamp string reproduces a signed chain, so a mutated `key_id` yields a
/// mismatch and a rejection, never a false accept. This function never guesses:
/// an off-shape `key_id` yields `None` and the caller keeps the pre-existing
/// behaviour.
pub fn recover_timestamp_from_key_id(key_id: &str) -> Option<String> {
    let rest = key_id.strip_prefix("nrx-verify-")?;
    // Strip the trailing `-{capsule_id[..8]}` fragment. Capsule-id fragments
    // are hex, so the LAST dash is the delimiter.
    let (encoded, fragment) = rest.rsplit_once('-')?;
    if fragment.is_empty() {
        return None;
    }
    let (date, encoded_time) = encoded.split_once('T')?;
    let time = encoded_time.replace('-', ":");
    if !is_iso8601_shaped(date, &time) {
        return None;
    }
    Some(format!("{date}T{time}"))
}

/// `YYYY-MM-DD` date + `HH:MM:SS` time prefix. Anything after the seconds
/// (fractional part, zone designator) is a free-form tail.
fn is_iso8601_shaped(date: &str, time: &str) -> bool {
    let d = date.as_bytes();
    let t = time.as_bytes();
    d.len() == 10
        && t.len() >= 8
        && d[4] == b'-'
        && d[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|&i| d[i].is_ascii_digit())
        && t[2] == b':'
        && t[5] == b':'
        && [0, 1, 3, 4, 6, 7].iter().all(|&i| t[i].is_ascii_digit())
}

/// Resolve the timestamp every chain step hashes.
///
/// Returns `(timestamp, recovered)` where `recovered` is `Some` only on the
/// `key_id` recovery path — the caller records it so the verdict discloses
/// which route was taken.
fn resolve_chain_timestamp(json: &serde_json::Value) -> (String, Option<String>) {
    let declared = json
        .get("destroyed_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !declared.is_empty() {
        return (declared.to_string(), None);
    }
    match json
        .pointer("/attestation/key_id")
        .and_then(|v| v.as_str())
        .and_then(recover_timestamp_from_key_id)
    {
        Some(ts) => (ts.clone(), Some(ts)),
        // No usable key_id — keep the pre-recovery behaviour exactly (an empty
        // timestamp, which fails the chain walk for any real proof).
        None => (declared.to_string(), None),
    }
}

/// Look up the canonical method string for a given subsystem (per CLAUDE.md
/// CDP v1.0 chain spec). Forever-stable per the Forever-Standard wire discipline.
pub fn lookup_method(subsystem: &str) -> &'static str {
    match subsystem {
        "eee_namespace" => "procfs_verification",
        "eee_tmpfs" => "mountinfo_verification",
        "eee_memory" => "dod_5220_multipass_wipe",
        "dire_keys" => "ed25519_key_destruction",
        "dire_identity" => "credential_incineration",
        "fgx_forensic" => "merkle_tree_verification",
        "rzl_audit" => "hash_chain_validation",
        "capsule_destroy" => "capsule_lifecycle_verification",
        _ => "",
    }
}

/// Strip canonical prefix conventions: `sha512:` from hash fields, `base64:`
/// from key/signature fields. the specification forever-stable.
pub fn strip_hash_prefix(s: &str) -> &str {
    s.strip_prefix("sha512:").unwrap_or(s)
}

pub fn strip_base64_prefix(s: &str) -> &str {
    s.strip_prefix("base64:").unwrap_or(s)
}

// ─────────────────────────────────────────────────────────────────────────────
// the receipt pipeline (the per-record receipt specification + the receipt-batching specification) verifier extension
//
// Mirrors the reference chain implementation to keep the verifier independent of any
// service-side dependency (the verifier ships as a standalone auditor
// artifact per the verifier specification). The hash primitives are byte-identical to the
// service-side implementation — pinned by the cross-impl byte-equivalence
// test in the property-test suite.
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Step 8 amended hash per the per-record receipt specification + the receipt-batching specification combined formula. See
/// the reference chain implementation for the spec; this
/// is a verifier-side mirror.
pub fn compute_step_8_amended_verifier(
    prev_hash: &str,
    timestamp: &str,
    rrmr: Option<&str>,
    ppmr: Option<&str>,
) -> String {
    let base = compute_step_hash(
        prev_hash,
        "capsule_destroy",
        "destroy",
        "capsule_lifecycle_verification",
        timestamp,
    );

    match (rrmr, ppmr) {
        (None, None) => base,
        (Some(rr), None) => {
            let rr = strip_hash_prefix(rr);
            let mut data = Vec::new();
            data.extend_from_slice(base.as_bytes());
            data.push(0x00);
            data.extend_from_slice(rr.as_bytes());
            hex::encode(Sha512::digest(&data))
        }
        (None, Some(pp)) => {
            let pp = strip_hash_prefix(pp);
            let mut data = Vec::new();
            data.extend_from_slice(base.as_bytes());
            data.push(0x00);
            data.extend_from_slice(pp.as_bytes());
            hex::encode(Sha512::digest(&data))
        }
        (Some(rr), Some(pp)) => {
            let rr = strip_hash_prefix(rr);
            let pp = strip_hash_prefix(pp);
            let mut data = Vec::new();
            data.extend_from_slice(base.as_bytes());
            data.push(0x00);
            data.extend_from_slice(rr.as_bytes());
            data.push(0x00);
            data.extend_from_slice(pp.as_bytes());
            hex::encode(Sha512::digest(&data))
        }
    }
}

/// Canonical pair hash for the Merkle tree: `SHA-512(left ‖ \x00 ‖ right)`.
fn verifier_merkle_pair_hash(left: &str, right: &str) -> String {
    let left = strip_hash_prefix(left);
    let right = strip_hash_prefix(right);
    let mut data = Vec::with_capacity(left.len() + 1 + right.len());
    data.extend_from_slice(left.as_bytes());
    data.push(0x00);
    data.extend_from_slice(right.as_bytes());
    hex::encode(Sha512::digest(&data))
}

/// Compute the Merkle root over an ordered slice of SHA-512 leaves. Returns
/// None when leaves is empty; bare-hex root (no `sha512:` prefix) otherwise.
pub fn verifier_merkle_root(leaves: &[String]) -> Option<String> {
    if leaves.is_empty() {
        return None;
    }
    if leaves.len() == 1 {
        return Some(strip_hash_prefix(&leaves[0]).to_string());
    }
    let mut level: Vec<String> = leaves
        .iter()
        .map(|h| strip_hash_prefix(h).to_string())
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(verifier_merkle_pair_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(verifier_merkle_pair_hash(&level[i], &level[i]));
                i += 1;
            }
        }
        level = next;
    }
    Some(level.pop().unwrap())
}

/// Compute a per-record chain hash mirroring
/// the reference chain implementation.
fn verifier_compute_record_chain_hash(
    capsule_id: &str,
    record_index: u32,
    record_id: &str,
    record_input_hash: &str,
    record_output_hash: &str,
    activity_root: &str,
    pattern_tag_wire: Option<&str>,
) -> String {
    let input_h = strip_hash_prefix(record_input_hash);
    let output_h = strip_hash_prefix(record_output_hash);
    let activity_h = strip_hash_prefix(activity_root);
    let idx = record_index.to_string();

    let mut data = Vec::new();
    data.extend_from_slice(capsule_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(idx.as_bytes());
    data.push(0x00);
    data.extend_from_slice(record_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(input_h.as_bytes());
    data.push(0x00);
    data.extend_from_slice(output_h.as_bytes());
    data.push(0x00);
    data.extend_from_slice(activity_h.as_bytes());
    // the per-record receipt specification conformance: a declared pattern_tag is a signed primitive and
    // is bound into the chain hash (trailing segment appended only when the
    // receipt carries a tag; activity_root's fixed 128-hex length gives
    // domain separation, so tagged and untagged preimages cannot collide).
    if let Some(tag) = pattern_tag_wire {
        data.push(0x00);
        data.extend_from_slice(tag.as_bytes());
    }

    hex::encode(Sha512::digest(&data))
}

/// Verify the receipt set per the per-record receipt specification Mode A step 3. Returns `Some(failure)`
/// if any receipt's chain hash doesn't roundtrip OR the Merkle root doesn't
/// match the claimed root. Returns `None` if all receipts verify.
fn verify_record_receipts(
    receipts: &[serde_json::Value],
    capsule_id: &str,
    claimed_root_opt: Option<&str>,
) -> Option<FailureReason> {
    let claimed_root = claimed_root_opt?;

    // Recompute each receipt's chain hash from its fields and compare.
    let mut leaf_chain_hashes: Vec<String> = Vec::with_capacity(receipts.len());
    for (i, receipt) in receipts.iter().enumerate() {
        let record_index = receipt
            .get("record_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let record_id = receipt
            .get("record_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let in_h = receipt
            .get("record_input_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let out_h = receipt
            .get("record_output_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let claimed_chain = receipt
            .get("record_chain_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Activity-root recompute: SHA-512 chain over canonical-JSON events.
        let activity_root = receipt
            .get("record_activity_trail")
            .and_then(|v| v.as_array())
            .map(|trail| {
                let mut prev = NANORIX_GENESIS_HASH.to_string();
                for event in trail {
                    let canonical_bytes = serde_jcs_or_json_bytes(event);
                    let event_hash = hex::encode(Sha512::digest(&canonical_bytes));
                    let mut data = Vec::with_capacity(prev.len() + 1 + event_hash.len());
                    data.extend_from_slice(prev.as_bytes());
                    data.push(0x00);
                    data.extend_from_slice(event_hash.as_bytes());
                    prev = hex::encode(Sha512::digest(&data));
                }
                prev
            })
            .unwrap_or_else(|| NANORIX_GENESIS_HASH.to_string());

        let recomputed = verifier_compute_record_chain_hash(
            capsule_id,
            record_index,
            record_id,
            in_h,
            out_h,
            &activity_root,
            receipt.get("pattern_tag").and_then(|v| v.as_str()),
        );

        if recomputed != strip_hash_prefix(claimed_chain) {
            return Some(FailureReason::StepHashMismatch {
                step_idx: i,
                subsystem: format!("record_receipt[{i}]"),
            });
        }

        leaf_chain_hashes.push(recomputed);
    }

    // Recompute Merkle root and compare to claimed.
    let recomputed_root = verifier_merkle_root(&leaf_chain_hashes).unwrap_or_default();
    if recomputed_root != strip_hash_prefix(claimed_root) {
        return Some(FailureReason::FinalHashMismatch {
            claimed: claimed_root.to_string(),
            computed: format!("sha512:{recomputed_root}"),
        });
    }

    None
}

/// Verify the parent-proof set Merkle root per the receipt-batching specification. Returns
/// `Some(failure)` if the recomputed root doesn't match claimed.
fn verify_parent_proofs(
    parents: &[serde_json::Value],
    claimed_root_opt: Option<&str>,
) -> Option<FailureReason> {
    let claimed_root = claimed_root_opt?;

    let leaves: Vec<String> = parents
        .iter()
        .map(|p| {
            p.get("parent_chain_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect();

    let recomputed = verifier_merkle_root(&leaves).unwrap_or_default();
    if recomputed != strip_hash_prefix(claimed_root) {
        return Some(FailureReason::FinalHashMismatch {
            claimed: claimed_root.to_string(),
            computed: format!("sha512:{recomputed}"),
        });
    }

    None
}

/// Canonical JSON bytes for activity events — RFC 8785 JCS, byte-identical
/// to the service-side `compute_activity_root` canonical form. Falls back
/// to plain serde_json on the (unreachable in practice) JCS serialization
/// failure path.
fn serde_jcs_or_json_bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_jcs::to_vec(v).unwrap_or_else(|_| serde_json::to_vec(v).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_v1_proof() -> serde_json::Value {
        // Build a minimally-valid v1.0 AuditProof for unit testing the chain.
        let timestamp = "2026-05-06T12:00:00Z";
        let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
        let subsystems = [
            "eee_namespace",
            "eee_tmpfs",
            "eee_memory",
            "dire_keys",
            "dire_identity",
            "fgx_forensic",
            "rzl_audit",
            "capsule_destroy",
        ];
        let mut chain = Vec::new();
        for subsystem in subsystems {
            let method = lookup_method(subsystem);
            let chain_hash = compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
            chain.push(serde_json::json!({
                "subsystem": subsystem,
                "method": method,
                "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }

        let final_hash = chain
            .last()
            .and_then(|s| s.get("chain_hash"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        serde_json::json!({
            "cdp_version": "1.0",
            "capsule_id": "cap_test",
            "destroyed_at": timestamp,
            "chain": chain,
            "final_hash": final_hash,
        })
    }

    // ── the chain-timestamp recovery rule — chain-timestamp recovery from attestation key_id ────────
    //
    // Production issued AuditProofs before `destroyed_at` was restored to the
    // wire document. Those proofs are authentic and signed, but the timestamp
    // every chain step hashes survives only inside `attestation.key_id`.

    #[test]
    fn recovers_production_key_id_with_millis_and_z() {
        // The exact shape the chain specification emits for a production
        // `Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)` timestamp.
        assert_eq!(
            recover_timestamp_from_key_id("nrx-verify-2026-03-01T00-05-00.000Z-550e8400"),
            Some("2026-03-01T00:05:00.000Z".to_string())
        );
    }

    #[test]
    fn recovers_key_id_whose_colons_were_never_replaced() {
        // The fixture generator writes key_id without the ':' -> '-' pass.
        // Restoring ':' for '-' in the time portion is a no-op there, so the
        // same parser handles both encodings.
        assert_eq!(
            recover_timestamp_from_key_id("nrx-verify-2026-05-08T00:00:00Z-cap12345"),
            Some("2026-05-08T00:00:00Z".to_string())
        );
    }

    #[test]
    fn recovery_refuses_off_shape_key_ids() {
        // Every rejection here means "fall back to the pre-recovery behaviour",
        // i.e. reject the proof. The parser never guesses.
        for bad in [
            "",
            "nrx-verify-",
            "some-other-prefix-2026-03-01T00-05-00Z-550e8400",
            // No 'T' separator — cannot tell date from time.
            "nrx-verify-2026-03-01-00-05-00Z-550e8400",
            // No trailing capsule fragment.
            "nrx-verify-2026-03-01T00:05:00Z",
            // Trailing delimiter with an empty fragment.
            "nrx-verify-2026-03-01T00:05:00Z-",
            // Date portion not YYYY-MM-DD.
            "nrx-verify-26-3-1T00-05-00Z-550e8400",
            // Time portion not HH:MM:SS.
            "nrx-verify-2026-03-01Tnoon-550e8400",
            // Non-digit smuggled into the time portion.
            "nrx-verify-2026-03-01T0a-05-00Z-550e8400",
        ] {
            assert_eq!(
                recover_timestamp_from_key_id(bad),
                None,
                "must refuse to recover from {bad:?}"
            );
        }
    }

    /// A v1.0 proof exactly as production issued it before the restoration:
    /// authentic 8-step chain, signed, and NO `destroyed_at` key at all.
    fn make_pre_restoration_v1_proof() -> serde_json::Value {
        let mut proof = make_minimal_v1_proof();
        let timestamp = "2026-05-06T12:00:00Z";
        proof.as_object_mut().unwrap().remove("destroyed_at");
        proof["attestation"] = serde_json::json!({
            "algorithm": "Ed25519",
            "key_id": format!("nrx-verify-{}-cap_test", timestamp.replace(':', "-")),
        });
        proof
    }

    #[test]
    fn pre_restoration_proof_verifies_via_key_id_recovery() {
        let proof = make_pre_restoration_v1_proof();
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(
            result.valid,
            "authentic pre-restoration proof must verify; got {result:?}"
        );
        assert_eq!(
            result.metadata.recovered_chain_timestamp.as_deref(),
            Some("2026-05-06T12:00:00Z"),
            "the recovered route must be visible in the verdict, not silent"
        );
    }

    #[test]
    fn native_path_does_not_report_a_recovered_timestamp() {
        // A proof carrying its own `destroyed_at` must be indistinguishable
        // from pre-change behaviour, and must NOT claim recovery.
        let proof = make_minimal_v1_proof();
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid);
        assert_eq!(result.metadata.recovered_chain_timestamp, None);
    }

    #[test]
    fn recovery_without_a_key_id_still_rejects() {
        // Removing `destroyed_at` with nothing to recover from must keep the
        // pre-change verdict: reject. This is the control proving the recovery
        // path — not some weakened chain check — is what accepts the fixture.
        let mut proof = make_pre_restoration_v1_proof();
        proof.as_object_mut().unwrap().remove("attestation");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid, "no timestamp anywhere must reject");
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::StepHashMismatch { step_idx: 0, .. })
        ));
    }

    /// SECURITY-CRITICAL. `key_id` is covered by neither signed message, so an
    /// attacker can rewrite it freely. Recovery must therefore be unable to
    /// launder a mutated key_id into a passing verdict: the recovered value is
    /// an INPUT to the chain walk, and the chain hashes it must reproduce are
    /// signature-bound. Any key_id but the true one yields a mismatch.
    #[test]
    fn mutated_key_id_cannot_be_weaponised() {
        let authentic = make_pre_restoration_v1_proof();
        assert!(verify_auditproof(&authentic, &[], &VerifierPolicy::default()).valid);

        for forged_timestamp in [
            "2026-05-06T12:00:01Z", // one second later
            "2020-01-01T00:00:00Z", // backdated years
            "2099-12-31T23:59:59Z", // postdated
        ] {
            let mut tampered = authentic.clone();
            tampered["attestation"]["key_id"] = serde_json::Value::String(format!(
                "nrx-verify-{}-cap_test",
                forged_timestamp.replace(':', "-")
            ));
            let result = verify_auditproof(&tampered, &[], &VerifierPolicy::default());
            assert!(
                !result.valid,
                "key_id rewritten to {forged_timestamp} must NOT verify; got {result:?}"
            );
            assert!(
                matches!(
                    result.failure_reason,
                    Some(FailureReason::StepHashMismatch { step_idx: 0, .. })
                ),
                "must fail the chain walk at step 0; got {:?}",
                result.failure_reason
            );
        }
    }

    /// Recovery must not weaken tamper detection anywhere else in the chain.
    #[test]
    fn recovered_proof_still_fails_on_a_mutated_chain_step() {
        let mut proof = make_pre_restoration_v1_proof();
        proof["chain"][5]["chain_hash"] = serde_json::Value::String("0".repeat(128));
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::StepHashMismatch { step_idx: 5, .. })
        ));
    }

    /// A document-supplied `destroyed_at` always wins over `key_id`. An
    /// attacker cannot bypass a failing declared timestamp by ALSO supplying a
    /// key_id that would recover to a passing one.
    #[test]
    fn declared_destroyed_at_takes_precedence_over_key_id() {
        let mut proof = make_minimal_v1_proof();
        proof["destroyed_at"] = serde_json::Value::String("2020-01-01T00:00:00Z".into());
        proof["attestation"] = serde_json::json!({
            "algorithm": "Ed25519",
            // Recovers to the timestamp that WOULD reproduce the chain.
            "key_id": "nrx-verify-2026-05-06T12-00-00Z-cap_test",
        });
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(
            !result.valid,
            "a wrong declared destroyed_at must reject even when key_id would rescue it"
        );
        assert_eq!(result.metadata.recovered_chain_timestamp, None);
    }

    #[test]
    fn verify_minimal_v1_proof_succeeds() {
        let proof = make_minimal_v1_proof();
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.metadata.cdp_version.as_deref(), Some("1.0"));
        assert_eq!(result.metadata.step_count, Some(8));
    }

    // ── trust-chain anchoring: trust-chain anchoring (stage 8) ──────────────────────

    /// A chain-valid v2.1 `nanorix_only` proof whose `canonical_hash` is signed
    /// by `authority_key`. `embedded_pub_b64` is what lands in the attestation
    /// (the authority's own pubkey for a genuine proof; a different key models a
    /// forgery whose embedded key is not the manifest key).
    fn make_signed_v21_proof(
        authority_key: &ed25519_dalek::SigningKey,
        embedded_pub_b64: &str,
        signing_key_version: &str,
    ) -> serde_json::Value {
        use ed25519_dalek::Signer as _;
        let timestamp = "2026-05-06T12:00:00Z";
        let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
        let subsystems = [
            "eee_namespace",
            "eee_tmpfs",
            "eee_memory",
            "dire_keys",
            "dire_identity",
            "fgx_forensic",
            "rzl_audit",
            "capsule_destroy",
        ];
        let mut chain = Vec::new();
        for subsystem in subsystems {
            let method = lookup_method(subsystem);
            let chain_hash = compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
            chain.push(serde_json::json!({
                "subsystem": subsystem, "method": method, "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }
        let final_hash = chain
            .last()
            .and_then(|s| s.get("chain_hash"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let mut proof = serde_json::json!({
            "cdp_version": "2.1",
            "capsule_id": "cap_test_subb",
            "destroyed_at": timestamp,
            "chain": chain,
            "final_hash": final_hash,
            "signing_mode": "nanorix_only",
            "jurisdiction": "us",
            "authority_id": "us-kms-nanorix-v1",
            "org_id": "00000000-0000-0000-0000-000000000001",
            "signing_key_version": signing_key_version,
            "destruction_state": "complete",
            "hash_algorithm": "SHA-512",
            "signature_algorithm": "Ed25519",
            "activity": [],
        });

        let canonical = crate::canonical_recompute::recompute_canonical_hash(&proof);
        let sig = authority_key.sign(canonical.as_bytes());
        proof["attestation"] = serde_json::json!({
            "algorithm": "Ed25519",
            "public_key": embedded_pub_b64,
            "signature": base64_encode(&sig.to_bytes()),
            "signing_key_version": signing_key_version,
        });
        proof
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// A signed manifest trusting `authority_key` under
    /// `(us-kms-nanorix-v1, version)`. Returns (manifest, pinned fingerprint).
    fn manifest_trusting(
        identity_seed: [u8; 32],
        authority_key: &ed25519_dalek::SigningKey,
        version: &str,
        revoked: bool,
    ) -> (crate::trust_chain::TrustChainManifest, String) {
        let identity = ed25519_dalek::SigningKey::from_bytes(&identity_seed);
        let authority_pub = base64_encode(&authority_key.verifying_key().to_bytes());
        let mut authorities = std::collections::HashMap::new();
        authorities.insert(
            "us-kms-nanorix-v1".to_string(),
            crate::trust_chain::AuthorityRecord {
                display_name: "Test US KMS".to_string(),
                active_versions: vec![crate::trust_chain::KeyVersionRecord {
                    signing_key_version: version.to_string(),
                    public_key_b64: authority_pub,
                    public_key_fingerprint: "sha256:test".to_string(),
                    effective_from: "2026-01-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                }],
                archived_versions: vec![],
                revoked,
            },
        );
        let manifest = crate::trust_chain::TrustChainManifest::build_and_sign(
            "1",
            "2026-05-31T00:00:00Z",
            authorities,
            &identity,
        );
        let pin = manifest.identity_fingerprint.clone();
        (manifest, pin)
    }

    fn policy_with(
        manifest: crate::trust_chain::TrustChainManifest,
        pin: String,
    ) -> VerifierPolicy {
        VerifierPolicy {
            trust_chain: Some(manifest),
            pinned_identity_fingerprint: Some(pin),
            ..Default::default()
        }
    }

    #[test]
    fn subb_genuine_proof_reaches_stage_8() {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&authority, &authority_pub, "1");
        let (manifest, pin) = manifest_trusting([7u8; 32], &authority, "1", false);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(
            result.stage_reached, 8,
            "trust-anchored proof must reach stage 8"
        );
    }

    #[test]
    fn subb_without_manifest_stops_at_stage_7() {
        // sub-A only: integrity proven, but key not anchored to a Nanorix root.
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&authority, &authority_pub, "1");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid);
        assert_eq!(
            result.stage_reached, 7,
            "no manifest → integrity-only stage 7"
        );
    }

    #[test]
    fn subb_forged_proof_rejected_against_manifest_key() {
        // The attacker signs with their OWN key and embeds their own pubkey:
        // self-consistent, so it passes sub-A. But the manifest's authority key
        // is the REAL key, so the signature fails against it — forgery caught.
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        let attacker_pub = base64_encode(&attacker.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&attacker, &attacker_pub, "1");
        let real_authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let (manifest, pin) = manifest_trusting([7u8; 32], &real_authority, "1", false);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(
            !result.valid,
            "forged proof must be rejected; got {result:?}"
        );
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::SignatureMismatch { .. })
        ));
    }

    #[test]
    fn subb_unknown_key_version_rejected() {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        // Proof claims version "9" but the manifest only carries "1".
        let proof = make_signed_v21_proof(&authority, &authority_pub, "9");
        let (manifest, pin) = manifest_trusting([7u8; 32], &authority, "1", false);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::SigningKeyVersionUnknown { .. })
        ));
    }

    #[test]
    fn subb_revoked_authority_rejected() {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&authority, &authority_pub, "1");
        let (manifest, pin) = manifest_trusting([7u8; 32], &authority, "1", true);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::AuthorityRevoked)
        ));
    }

    #[test]
    fn verify_missing_cdp_version_fails_at_stage_1() {
        let proof = serde_json::json!({"foo": "bar"});
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 1);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::RequiredFieldMissing { ref field }) if field == "cdp_version"
        ));
    }

    #[test]
    fn verify_unsupported_cdp_version_fails_at_stage_2() {
        let proof = serde_json::json!({"cdp_version": "99.0"});
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 2);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::CdpVersionUnsupported { ref found }) if found == "99.0"
        ));
    }

    #[test]
    fn verify_missing_chain_fails_at_stage_3() {
        let proof = serde_json::json!({"cdp_version": "1.0"});
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 3);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::RequiredFieldMissing { ref field }) if field == "chain"
        ));
    }

    #[test]
    fn verify_wrong_step_count_fails_at_stage_3() {
        let proof = serde_json::json!({
            "cdp_version": "1.0",
            "chain": [{"subsystem": "x", "chain_hash": "y"}, {"subsystem": "x", "chain_hash": "y"}]
        });
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 3);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::StepCountInvalid {
                expected: 8,
                found: 2
            })
        ));
    }

    #[test]
    fn verify_tampered_step_hash_fails_at_stage_3() {
        let mut proof = make_minimal_v1_proof();
        // Tamper step 4's chain_hash
        proof["chain"][4]["chain_hash"] = serde_json::Value::String("0".repeat(128));

        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 3);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::StepHashMismatch { step_idx: 4, .. })
        ));
    }

    #[test]
    fn verify_mismatched_final_hash_fails_at_stage_4() {
        let mut proof = make_minimal_v1_proof();
        proof["final_hash"] = serde_json::Value::String("0".repeat(128));

        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 4);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::FinalHashMismatch { .. })
        ));
    }

    #[test]
    fn genesis_hash_constant_matches_sha512_of_empty() {
        // Per CLAUDE.md "Genesis: SHA-512('') = cf83e1357..."
        let mut hasher = Sha512::new();
        hasher.update(b"");
        let computed = hex::encode(hasher.finalize());
        assert_eq!(computed, NANORIX_GENESIS_HASH);
    }

    #[test]
    fn lookup_method_covers_all_8_subsystems() {
        let subsystems = [
            "eee_namespace",
            "eee_tmpfs",
            "eee_memory",
            "dire_keys",
            "dire_identity",
            "fgx_forensic",
            "rzl_audit",
            "capsule_destroy",
        ];
        for s in subsystems {
            assert!(!lookup_method(s).is_empty(), "no method for {s}");
        }
        assert_eq!(lookup_method("unknown_subsystem"), "");
    }

    #[test]
    fn strip_prefix_helpers_handle_present_and_absent_prefix() {
        assert_eq!(strip_hash_prefix("sha512:abc"), "abc");
        assert_eq!(strip_hash_prefix("abc"), "abc");
        assert_eq!(strip_base64_prefix("base64:xyz"), "xyz");
        assert_eq!(strip_base64_prefix("xyz"), "xyz");
    }

    // ── the customer-authority specification G7 — Verifier policy `required_authority_id` pin ──────
    //
    // Five deterministic fixtures matching the runbook G7 test plan:
    //
    //   - policy_pin_customer_hsm_audit_proof_none_rejected
    //   - policy_pin_customer_hsm_audit_proof_wrong_authority_rejected
    //   - policy_pin_customer_hsm_audit_proof_matches_authority_accepted
    //   - policy_none_audit_proof_none_accepted
    //   - policy_none_audit_proof_some_accepted
    //
    // Plus a property test asserting that for any (audit_proof) when the
    // policy is `None`, verification result is identical to the no-policy
    // verifier path (≥10k iterations).

    /// Fixture 1 — policy pins customer-HSM, AuditProof has no
    /// `signing_authority` field. Reject with
    /// `AuthorityIdMismatch { claimed: None, reason:...DemandsCustomerHsmAuditProofHasNone }`.
    #[test]
    fn policy_pin_customer_hsm_audit_proof_none_rejected() {
        let proof = make_minimal_v1_proof();
        // AuditProof is the v1 minimal shape; no `signing_authority` field.
        let policy = VerifierPolicy {
            required_authority_id: Some("customer-hsm-example-org-v1".into()),
            ..Default::default()
        };

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(!result.valid, "expected reject; got {result:?}");
        assert_eq!(result.stage_reached, 2);
        match result.failure_reason {
            Some(FailureReason::AuthorityIdMismatch {
                claimed_authority_id,
                expected_authority_id,
                reason,
            }) => {
                assert_eq!(claimed_authority_id, None);
                assert_eq!(expected_authority_id, "customer-hsm-example-org-v1");
                assert_eq!(
                    reason,
                    AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone
                );
            }
            other => panic!("expected AuthorityIdMismatch with None claimed; got {other:?}"),
        }
    }

    /// Fixture 2 — policy pins customer-HSM, AuditProof has
    /// `signing_authority.authority_id` that disagrees. Reject with
    /// `AuthorityIdMismatch { reason:...AuthorityIdMismatch }`.
    #[test]
    fn policy_pin_customer_hsm_audit_proof_wrong_authority_rejected() {
        let mut proof = make_minimal_v1_proof();
        proof["signing_authority"] = serde_json::json!({
            "authority_id": "customer-hsm-other-v1",
        });

        let policy = VerifierPolicy {
            required_authority_id: Some("customer-hsm-example-org-v1".into()),
            ..Default::default()
        };

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(!result.valid, "expected reject; got {result:?}");
        assert_eq!(result.stage_reached, 2);
        match result.failure_reason {
            Some(FailureReason::AuthorityIdMismatch {
                claimed_authority_id,
                expected_authority_id,
                reason,
            }) => {
                assert_eq!(claimed_authority_id, Some("customer-hsm-other-v1".into()));
                assert_eq!(expected_authority_id, "customer-hsm-example-org-v1");
                assert_eq!(
                    reason,
                    AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch
                );
            }
            other => panic!("expected AuthorityIdMismatch with Some claimed; got {other:?}"),
        }
    }

    /// Fixture 3 — policy pins customer-HSM, AuditProof has a matching
    /// `signing_authority.authority_id`. Accept (gate passes; continues to
    /// chain checks; minimal v1 proof passes those).
    #[test]
    fn policy_pin_customer_hsm_audit_proof_matches_authority_accepted() {
        let mut proof = make_minimal_v1_proof();
        proof["signing_authority"] = serde_json::json!({
            "authority_id": "customer-hsm-example-org-v1",
        });

        let policy = VerifierPolicy {
            required_authority_id: Some("customer-hsm-example-org-v1".into()),
            ..Default::default()
        };

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.stage_reached, 4);
    }

    // ── Residency pin (the specification G1 / the region policy) ────────────────────────────

    /// A pinned region that the proof does not match is rejected before the
    /// chain walk. Until this gate existed, `--required-region` parsed fine and
    /// then did nothing — an auditor pinning EU residency got a clean "valid"
    /// on a us-central1 proof.
    #[test]
    fn residency_pin_rejects_disagreeing_region() {
        let mut proof = make_minimal_v1_proof();
        proof["region"] = serde_json::json!("us-central1");

        let policy = VerifierPolicy {
            required_region: Some("europe-west1".into()),
            ..Default::default()
        };

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(!result.valid, "expected rejection; got {result:?}");
        assert_eq!(result.stage_reached, 2);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::RegionMismatch { ref required, ref actual })
                if required == "europe-west1" && actual == "us-central1"
        ));
    }

    /// A proof carrying no region at all cannot satisfy a residency pin — the
    /// pin fails closed rather than treating "absent" as "anything".
    #[test]
    fn residency_pin_fails_closed_when_proof_declares_no_region() {
        let proof = make_minimal_v1_proof();
        let policy = VerifierPolicy {
            required_region: Some("europe-west1".into()),
            ..Default::default()
        };

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(!result.valid, "expected rejection; got {result:?}");
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::RegionMismatch { ref actual, .. }) if actual.is_empty()
        ));
    }

    /// A matching pin is transparent — the proof continues to the chain checks.
    #[test]
    fn residency_pin_accepts_matching_region() {
        let mut proof = make_minimal_v1_proof();
        proof["region"] = serde_json::json!("europe-west1");

        let policy = VerifierPolicy {
            required_region: Some("europe-west1".into()),
            ..Default::default()
        };

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(result.valid, "expected valid; got {result:?}");
    }

    /// No pin means no residency opinion — the pre-gate behaviour of every
    /// existing caller is unchanged.
    #[test]
    fn no_residency_pin_accepts_any_region() {
        let mut proof = make_minimal_v1_proof();
        proof["region"] = serde_json::json!("asia-east1");

        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());

        assert!(result.valid, "expected valid; got {result:?}");
    }

    /// Fixture 4 — policy is None (default), AuditProof has no
    /// `signing_authority` field. Accept (Nanorix-default path; pre-G7
    /// behavior preserved).
    #[test]
    fn policy_none_audit_proof_none_accepted() {
        let proof = make_minimal_v1_proof();
        let policy = VerifierPolicy::default();

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.stage_reached, 4);
    }

    /// Fixture 5 — policy is None (default), AuditProof has a populated
    /// `signing_authority`. Accept (the gate doesn't fire when policy is
    /// None regardless of AuditProof shape).
    #[test]
    fn policy_none_audit_proof_some_accepted() {
        let mut proof = make_minimal_v1_proof();
        proof["signing_authority"] = serde_json::json!({
            "authority_id": "customer-hsm-example-org-v1",
        });

        let policy = VerifierPolicy::default();

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.stage_reached, 4);
    }

    /// Fault-injection property: for any AuditProof variant (with /
    /// without `signing_authority`, with arbitrary `authority_id`),
    /// when the policy is `None`, verification result is byte-equivalent
    /// to the no-policy verifier path. ≥10k iterations.
    ///
    /// Per `feedback_canonical_hash_under_fault.md`: locks the invariant
    /// that the policy-pin gate is a NO-OP when the gate is unconfigured.
    /// Any future change to the gate that accidentally activates it under
    /// `None` policy is caught here.
    #[test]
    fn policy_none_invariant_under_random_signing_authority_payloads_10k() {
        // Deterministic LCG seed; any deterministic seed works.
        let mut state: u64 = 0xC0DE_5117_FACE_FEED;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let auth_id_pool = [
            "customer-hsm-example-org-v1",
            "customer-hsm-other-v1",
            "us-kms-nanorix-v1",
            "europe-west1.daemon.nanorix.io",
            "auth_xyz_health",
            "",
        ];

        for iter in 0..10_000 {
            let r = next();
            let mut proof = make_minimal_v1_proof();

            let payload_kind = r % 4;
            match payload_kind {
                0 => {
                    // No `signing_authority` field at all.
                }
                1 => {
                    // `signing_authority` is JSON null.
                    proof["signing_authority"] = serde_json::Value::Null;
                }
                2 => {
                    // `signing_authority` populated with random authority_id.
                    let auth = auth_id_pool[((r >> 8) as usize) % auth_id_pool.len()];
                    proof["signing_authority"] = serde_json::json!({
                        "authority_id": auth,
                    });
                }
                _ => {
                    // `signing_authority` populated but missing the
                    // `authority_id` field — verifier should still tolerate it.
                    proof["signing_authority"] = serde_json::json!({
                        "other_field": "value",
                    });
                }
            }

            let policy = VerifierPolicy::default();
            let result = verify_auditproof(&proof, &[], &policy);

            assert!(
                result.valid,
                "iter {} (kind {}): policy=None must accept any signing_authority \
                 shape; got failure_reason {:?}",
                iter, payload_kind, result.failure_reason
            );
            assert_eq!(
                result.stage_reached, 4,
                "iter {} (kind {}): expected stage_reached=4 (chain checks pass) under \
                 policy=None",
                iter, payload_kind
            );
        }
    }

    /// Fault-injection property: for any pinned policy
    /// `required_authority_id` and arbitrary AuditProof signing_authority
    /// shape, the policy-pin gate fires correctly on (None | mismatch)
    /// and accepts on (match). ≥10k iterations.
    ///
    /// This is the dual of `policy_none_invariant_*` — confirms the gate
    /// fires deterministically under all input combinations.
    #[test]
    fn policy_pin_decision_under_random_inputs_10k() {
        let mut state: u64 = 0xBEEF_DEAD_C0DE_F00D;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let auth_id_pool = [
            "customer-hsm-example-org-v1",
            "customer-hsm-other-v1",
            "customer-hsm-acme-prod-2026-q2",
            "us-kms-nanorix-v1",
        ];

        for iter in 0..10_000 {
            let r = next();
            let mut proof = make_minimal_v1_proof();

            let pinned = auth_id_pool[((r >> 4) as usize) % auth_id_pool.len()].to_string();
            let policy = VerifierPolicy {
                required_authority_id: Some(pinned.clone()),
                ..Default::default()
            };

            let payload_kind = r & 3;
            let (expected_valid, expected_claimed) = match payload_kind {
                0 => {
                    // No `signing_authority` field — must reject (None claimed).
                    (false, None::<String>)
                }
                1 => {
                    // `signing_authority` is null — equivalent to omitted.
                    proof["signing_authority"] = serde_json::Value::Null;
                    (false, None)
                }
                2 => {
                    // Populated with the SAME authority — must accept.
                    proof["signing_authority"] = serde_json::json!({
                        "authority_id": pinned.clone(),
                    });
                    (true, Some(pinned.clone()))
                }
                _ => {
                    // Populated with a DIFFERENT authority — must reject (Some claimed).
                    let alt =
                        auth_id_pool[((r >> 16) as usize ^ 1) % auth_id_pool.len()].to_string();
                    let alt = if alt == pinned {
                        // Force a mismatch by appending a suffix.
                        format!("{}_alt", pinned)
                    } else {
                        alt
                    };
                    proof["signing_authority"] = serde_json::json!({
                        "authority_id": alt.clone(),
                    });
                    (false, Some(alt))
                }
            };

            let result = verify_auditproof(&proof, &[], &policy);

            assert_eq!(
                result.valid, expected_valid,
                "iter {} (kind {}): expected_valid={}; got valid={}, failure={:?}",
                iter, payload_kind, expected_valid, result.valid, result.failure_reason
            );

            if !expected_valid {
                match result.failure_reason {
                    Some(FailureReason::AuthorityIdMismatch {
                        claimed_authority_id,
                        expected_authority_id,
                        reason,
                    }) => {
                        assert_eq!(
                            claimed_authority_id, expected_claimed,
                            "iter {} (kind {}): claimed_authority_id mismatch",
                            iter, payload_kind
                        );
                        assert_eq!(
                            expected_authority_id, pinned,
                            "iter {} (kind {}): expected_authority_id mismatch",
                            iter, payload_kind
                        );
                        let want_reason = if expected_claimed.is_some() {
                            AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch
                        } else {
                            AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone
                        };
                        assert_eq!(
                            reason, want_reason,
                            "iter {} (kind {}): sub-reason mismatch",
                            iter, payload_kind
                        );
                    }
                    other => panic!(
                        "iter {} (kind {}): expected AuthorityIdMismatch; got {:?}",
                        iter, payload_kind, other
                    ),
                }
            }
        }
    }

    // ── the specification an earlier release-A cdp_kind verifier byte-equivalence pins ──────
    //
    // The cdp_kind reserved-slot lives at the FullCdp / VerificationCdp
    // canonical-hash layer (the AuditProof document builder), NOT in the
    // 8-step destruction chain that this verifier reproduces.
    //
    // Therefore: the verifier MUST process AuditProofs identically whether
    // `cdp_kind` is absent (V1 default), `Some("workload")`, `Some("request")`,
    // `Some("call")`, or `Some("batch")`. The chain hash + final_hash binding
    // are computed from `chain` array + `destroyed_at` only.
    //
    // These properties lock the invariant: cdp_kind is structurally invisible
    // to the chain-walk verifier. Any future regression that accidentally
    // makes cdp_kind participate in chain hash inputs trips these tests.

    /// Fault-injection property: for any cdp_kind value attached to an
    /// otherwise-valid AuditProof, verification result MUST be byte-equivalent
    /// to the same proof with cdp_kind omitted. ≥10k iterations.
    #[test]
    fn cdp_kind_is_invisible_to_chain_verification_10k() {
        let cdp_kind_pool = [
            None,
            Some("workload"),
            Some("request"),
            Some("call"),
            Some("batch"),
        ];

        let mut state: u64 = 0x0001_6ACD_C0DE_C0DE;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let baseline_proof = make_minimal_v1_proof();
        let baseline_result = verify_auditproof(&baseline_proof, &[], &VerifierPolicy::default());
        // Baseline must be valid; the proof is intentionally constructed valid.
        assert!(baseline_result.valid, "baseline must verify");

        for iter in 0..10_000 {
            let r = next();
            let kind = cdp_kind_pool[(r as usize) % cdp_kind_pool.len()];

            let mut proof = make_minimal_v1_proof();
            if let Some(k) = kind {
                proof["cdp_kind"] = serde_json::Value::String(k.into());
            }

            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());

            assert_eq!(
                result.valid, baseline_result.valid,
                "iter {iter}: cdp_kind={kind:?} must NOT change verification verdict"
            );
            assert_eq!(
                result.stage_reached, baseline_result.stage_reached,
                "iter {iter}: cdp_kind={kind:?} must NOT change stage_reached"
            );
            assert_eq!(
                result.failure_reason, baseline_result.failure_reason,
                "iter {iter}: cdp_kind={kind:?} must NOT change failure_reason"
            );
            // metadata fields are deterministic functions of the proof's
            // version / capsule_id / chain shape — none of which depend on
            // cdp_kind. They must match the baseline exactly.
            assert_eq!(
                result.metadata, baseline_result.metadata,
                "iter {iter}: cdp_kind={kind:?} must NOT change metadata"
            );
        }
    }

    /// cdp_kind populated → verifier still recomputes the same final_hash.
    /// Reason: cdp_kind is NOT in chain step inputs (subsystem / action /
    /// method / timestamp). The chain layer is upstream of cdp_kind binding.
    #[test]
    fn cdp_kind_does_not_perturb_chain_recompute() {
        let baseline = make_minimal_v1_proof();
        let baseline_result = verify_auditproof(&baseline, &[], &VerifierPolicy::default());
        let baseline_step_count = baseline_result.metadata.step_count;

        for k in ["workload", "request", "call", "batch"] {
            let mut proof = baseline.clone();
            proof["cdp_kind"] = serde_json::Value::String(k.into());
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert!(
                result.valid,
                "valid proof with cdp_kind={k:?} must remain valid"
            );
            assert_eq!(
                result.metadata.step_count, baseline_step_count,
                "step_count must be unchanged when only cdp_kind differs"
            );
        }
    }

    // ── the specification C.1-2 — algorithm dispatch + additive-evolution tolerance ─

    #[test]
    fn non_ed25519_attestation_algorithm_fails_typed_at_stage_4() {
        let mut proof = make_minimal_v1_proof();
        proof["attestation"] = serde_json::json!({ "algorithm": "ML-DSA-65" });
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 4);
        assert!(
            matches!(
                result.failure_reason,
                Some(FailureReason::AlgorithmUnsupported { ref found }) if found == "ML-DSA-65"
            ),
            "must fail typed as AlgorithmUnsupported, never as malformed; got {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn non_ed25519_top_level_signature_algorithm_fails_typed() {
        let mut proof = make_minimal_v1_proof();
        proof["signature_algorithm"] = serde_json::json!("ECDSA-P256");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::AlgorithmUnsupported { .. })
        ));
    }

    #[test]
    fn unknown_fields_do_not_disturb_verification() {
        // Additive-evolution insurance (the specification C.2): a proof carrying fields
        // this build has never heard of must verify exactly as without them.
        let mut proof = make_minimal_v1_proof();
        proof["future_sibling_artifact"] = serde_json::json!({ "anything": [1, 2, 3] });
        proof["pqc_signature_hint"] = serde_json::json!("reserved");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(
            result.valid,
            "unknown fields must be ignored; got {result:?}"
        );
    }
}
