//! ADR-050 D7 — offline BoundaryAttestation (retain mode) verification.
//!
//! A BoundaryAttestation is the sibling primitive to the AuditProof
//! (INVARIANTS #28): a point-in-time signed snapshot issued while the capsule
//! is LIVE. It is NOT a destruction claim — the fixed continuation statement
//! inside the signed bytes says so — and this verifier reports structural
//! results only, never a verdict about what the evidence means.
//!
//! Verification stages (per ADR-050 D7):
//! 1. Parse; `kind` + `version` + schema + fixed continuation statement +
//!    observation-method vocabulary (disjoint from the 8 destruction-chain
//!    method names by construction).
//! 2. Recompute RFC 8785 JCS canonical bytes (document minus `attestation`
//!    minus `canonical_hash`) → SHA-512 → compare `canonical_hash`.
//! 3. Verify Ed25519 over the canonical-hash 128-char ASCII-hex string:
//!    against the embedded key (integrity), then re-verified against the
//!    bounded trust-chain manifest key when one is supplied (authenticity).
//! 4. Chain walk when a set of attestations for one capsule is supplied:
//!    `prev_attestation_hash` linkage, strict `attestation_index`
//!    monotonicity, `cutoff_ts` strictly increasing, genesis rule at index 1.
//! 5. Disclosed activity trail: recompute the ADR-039-shaped SHA-512 chain
//!    over canonical-JSON event hashes and compare `activity_commitment` +
//!    `activity_event_count`.
//!
//! Like the AuditProof path, this module is deliberately independent of the
//! product crates (mirrors, locked by fixtures) so an auditor can compile and
//! read it standalone.

use crate::canonical_recompute::{verify_message_with_key, SignatureCheck};
use crate::{strip_hash_prefix, VerifierPolicy, NANORIX_GENESIS_HASH};
use nanorix_verify_types::SignatureFailureReason;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha512};

/// Fixed domain separator — no BoundaryAttestation can be parsed as an
/// AuditProof or vice versa (ADR-050 D2).
pub const BOUNDARY_ATTESTATION_KIND: &str = "boundary_attestation";

/// Document schema versions this build verifies. Unknown versions fail typed
/// (ADR-049 discipline).
pub const BOUNDARY_SUPPORTED_VERSIONS: &[&str] = &["1.0"];

/// The fixed continuation statement embedded in every BoundaryAttestation
/// (ADR-050 D3). The signature covers it; the verifier additionally checks
/// it verbatim so an issuer bug cannot ship a snapshot without the explicit
/// not-a-destruction-claim wording.
pub const BOUNDARY_CONTINUATION_STATEMENT: &str = "The capsule remained live at cutoff_ts; \
     this attestation records observations up to that instant and is NOT a destruction claim.";

/// Observation-method vocabulary (ADR-050 D2) — deliberately disjoint from
/// the 8 destruction-chain method names so no string in this document can be
/// mistaken for a destruction-chain step.
pub const BOUNDARY_OBSERVATION_METHODS: &[&str] = &[
    "procfs_observation",
    "mountinfo_observation",
    "cgroup_v2_observation",
];

/// Typed failure reasons for the BoundaryAttestation pipeline. Sibling enum
/// to `nanorix_verify_types::FailureReason` — a NEW document type gets its
/// own closed enum rather than widening the Forever-Standard AuditProof one
/// (verify-types additive-evolution policy, ADR-049 D3.3). Same wire form
/// discipline: `type` tag, snake_case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BoundaryFailureReason {
    /// `kind` is not `boundary_attestation`.
    KindMismatch { found: String },
    /// `version` is not one this build verifies.
    VersionUnsupported { found: String },
    /// A structurally required field is absent or of the wrong type.
    RequiredFieldMissing { field: String },
    /// `hash_algorithm` / `signature_algorithm` pin differs from sha512 /
    /// Ed25519 (ADR-049 D1 explicit pins).
    AlgorithmUnsupported { field: String, found: String },
    /// The fixed continuation statement is absent or altered.
    ContinuationStatementMismatch,
    /// A `boundary_evidence` entry carries a method outside the observation
    /// vocabulary (including any destruction-chain method name).
    MethodVocabularyViolation { found: String },
    /// Recomputed JCS canonical hash differs from the document's
    /// `canonical_hash`.
    CanonicalHashMismatch { claimed: String, computed: String },
    /// Ed25519 signature did not verify.
    SignatureMismatch { reason: SignatureFailureReason },
    /// Trust-chain manifest could not resolve the signing key.
    SigningKeyVersionUnknown { version: String },
    /// Trust-chain manifest marks the signing authority revoked.
    AuthorityRevoked,
    /// Chain: two supplied attestations name different capsules.
    CapsuleIdMismatch { expected: String, found: String },
    /// Chain: `attestation_index` did not increment by exactly 1 between
    /// adjacent supplied attestations (duplicate, gap, or reorder).
    IndexNotStrictlyIncremented { prev_index: u64, index: u64 },
    /// Chain: `prev_attestation_hash` does not equal the recomputed
    /// canonical hash of the preceding attestation.
    PrevAttestationHashMismatch {
        index: u64,
        claimed: String,
        computed: String,
    },
    /// Chain: index 1 must carry the genesis hash as its
    /// `prev_attestation_hash`.
    GenesisPrevHashMismatch { claimed: String },
    /// Chain: `cutoff_ts` failed to parse as RFC 3339.
    CutoffTimestampUnparseable { found: String },
    /// Chain: `cutoff_ts` is not strictly increasing along the chain.
    CutoffNotIncreasing { prev_cutoff: String, cutoff: String },
    /// Disclosed activity trail does not recompute to
    /// `activity_commitment`.
    ActivityCommitmentMismatch { claimed: String, computed: String },
    /// Disclosed trail length differs from `activity_event_count`.
    ActivityEventCountMismatch { claimed: u64, actual: u64 },
}

/// Structural metadata reported alongside every verdict — no payload bytes,
/// no capsule content (the document carries none by construction).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BoundaryMetadata {
    pub capsule_id: Option<String>,
    pub attestation_index: Option<u64>,
    pub cutoff_ts: Option<String>,
    pub signing_key_version: Option<String>,
    pub key_id: Option<String>,
    pub activity_event_count: Option<u64>,
}

/// Verdict for a single BoundaryAttestation document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BoundaryVerificationResult {
    /// True iff every check that ran was valid.
    pub valid: bool,
    pub failure_reason: Option<BoundaryFailureReason>,
    /// Highest ADR-050 D7 stage reached (1..=3 for a single document; the
    /// chain walk and activity-trail stages are reported on their own
    /// results).
    pub stage_reached: u8,
    /// True iff an Ed25519 signature was present AND verified. False with
    /// `valid = true` is the boundary analog of the AuditProof exit-3
    /// state: canonical form verified, integrity NOT established.
    pub signature_checked: bool,
    /// True iff the signing key also resolved + re-verified against the
    /// bounded trust-chain manifest ("verify without trusting Nanorix").
    pub trust_anchored: bool,
    pub metadata: BoundaryMetadata,
}

/// Verdict for a chain of attestations for one capsule (ADR-050 D5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BoundaryChainResult {
    pub valid: bool,
    pub failure_reason: Option<BoundaryFailureReason>,
    /// `attestation_index` of the document where the chain check failed.
    pub failed_at_index: Option<u64>,
    /// Per-document verdicts in walked (index) order.
    pub per_document: Vec<BoundaryVerificationResult>,
    /// `(lowest_index, highest_index)` covered by the supplied set.
    pub chain_span: Option<(u64, u64)>,
    /// True iff the lowest supplied attestation has index 1 with the genesis
    /// `prev_attestation_hash` — i.e. the chain is verified back to its
    /// origin rather than being a suffix whose head link is unverifiable.
    pub genesis_anchored: bool,
    /// True iff every supplied document's signature was checked and valid.
    pub all_signatures_checked: bool,
}

/// Recompute the JCS canonical hash of a BoundaryAttestation: RFC 8785 JCS
/// bytes of the document EXCLUDING the `attestation` block (a signature
/// cannot sign itself) and the `canonical_hash` field (a hash cannot contain
/// itself), then SHA-512 → lowercase 128-char hex.
pub fn recompute_boundary_canonical_hash(doc: &Value) -> String {
    let mut view = match doc.as_object() {
        Some(o) => o.clone(),
        None => return String::new(),
    };
    view.remove("attestation");
    view.remove("canonical_hash");
    match serde_jcs::to_vec(&Value::Object(view)) {
        Ok(bytes) => hex::encode(Sha512::digest(&bytes)),
        // Object always serializes; on the impossible failure return empty so
        // the comparison fails closed.
        Err(_) => String::new(),
    }
}

/// Recompute the ADR-039-shaped activity commitment over disclosed events:
/// `prev = genesis; prev = SHA-512(prev ‖ 0x00 ‖ SHA-512(JCS(event)).hex())`
/// per `governance/rzl/src/wave_n.rs::compute_activity_root`. Genesis when
/// the trail is empty. Lowercase hex, no prefix.
pub fn recompute_activity_commitment(events: &[Value]) -> String {
    let mut prev = NANORIX_GENESIS_HASH.to_string();
    for event in events {
        let canonical_bytes = serde_jcs::to_vec(event)
            .unwrap_or_else(|_| serde_json::to_vec(event).unwrap_or_default());
        let event_hash = hex::encode(Sha512::digest(&canonical_bytes));
        let mut data = Vec::with_capacity(prev.len() + 1 + event_hash.len());
        data.extend_from_slice(prev.as_bytes());
        data.push(0x00);
        data.extend_from_slice(event_hash.as_bytes());
        prev = hex::encode(Sha512::digest(&data));
    }
    prev
}

fn str_of(doc: &Value, field: &str) -> Option<String> {
    doc.get(field).and_then(|v| v.as_str()).map(String::from)
}

fn fail(
    reason: BoundaryFailureReason,
    stage: u8,
    metadata: BoundaryMetadata,
) -> BoundaryVerificationResult {
    BoundaryVerificationResult {
        valid: false,
        failure_reason: Some(reason),
        stage_reached: stage,
        signature_checked: false,
        trust_anchored: false,
        metadata,
    }
}

/// Verify one BoundaryAttestation document: stages 1-3 of ADR-050 D7.
///
/// With `policy.trust_chain` set (the manifest's own signature already
/// verified by the caller, exactly as for AuditProofs), the signing key is
/// resolved from the manifest and the signature re-verified against the
/// manifest key — `trust_anchored = true` on success. Without a manifest,
/// an embedded-key-valid signature yields integrity only.
pub fn verify_boundary_attestation(
    doc: &Value,
    policy: &VerifierPolicy,
) -> BoundaryVerificationResult {
    let mut metadata = BoundaryMetadata {
        capsule_id: str_of(doc, "capsule_id"),
        attestation_index: doc.get("attestation_index").and_then(|v| v.as_u64()),
        cutoff_ts: str_of(doc, "cutoff_ts"),
        signing_key_version: str_of(doc, "signing_key_version"),
        key_id: str_of(doc, "key_id"),
        activity_event_count: doc.get("activity_event_count").and_then(|v| v.as_u64()),
    };

    // ── Stage 1: kind + version + schema + continuation + vocabulary ──────
    let kind = str_of(doc, "kind").unwrap_or_default();
    if kind != BOUNDARY_ATTESTATION_KIND {
        return fail(
            BoundaryFailureReason::KindMismatch { found: kind },
            1,
            metadata,
        );
    }
    let version = match str_of(doc, "version") {
        Some(v) => v,
        None => {
            return fail(
                BoundaryFailureReason::RequiredFieldMissing {
                    field: "version".into(),
                },
                1,
                metadata,
            );
        }
    };
    if !BOUNDARY_SUPPORTED_VERSIONS.contains(&version.as_str()) {
        return fail(
            BoundaryFailureReason::VersionUnsupported { found: version },
            1,
            metadata,
        );
    }

    for field in [
        "capsule_id",
        "cutoff_ts",
        "activity_commitment",
        "prev_attestation_hash",
        "canonical_hash",
    ] {
        if str_of(doc, field).is_none() {
            return fail(
                BoundaryFailureReason::RequiredFieldMissing {
                    field: field.into(),
                },
                1,
                metadata,
            );
        }
    }
    if metadata.attestation_index.is_none() {
        return fail(
            BoundaryFailureReason::RequiredFieldMissing {
                field: "attestation_index".into(),
            },
            1,
            metadata,
        );
    }
    if metadata.activity_event_count.is_none() {
        return fail(
            BoundaryFailureReason::RequiredFieldMissing {
                field: "activity_event_count".into(),
            },
            1,
            metadata,
        );
    }

    // Explicit algorithm pins (ADR-049 D1 — the document is born agile, so
    // the pins are load-bearing, not decorative).
    let hash_alg = str_of(doc, "hash_algorithm").unwrap_or_default();
    if hash_alg != "sha512" {
        return fail(
            BoundaryFailureReason::AlgorithmUnsupported {
                field: "hash_algorithm".into(),
                found: hash_alg,
            },
            1,
            metadata,
        );
    }
    let sig_alg = str_of(doc, "signature_algorithm").unwrap_or_default();
    if sig_alg != "Ed25519" {
        return fail(
            BoundaryFailureReason::AlgorithmUnsupported {
                field: "signature_algorithm".into(),
                found: sig_alg,
            },
            1,
            metadata,
        );
    }

    // Fixed continuation statement, verbatim (ADR-050 D3).
    if str_of(doc, "continuation").as_deref() != Some(BOUNDARY_CONTINUATION_STATEMENT) {
        return fail(
            BoundaryFailureReason::ContinuationStatementMismatch,
            1,
            metadata,
        );
    }

    // boundary_evidence: required array; every method must come from the
    // observation vocabulary (disjoint from destruction-chain methods).
    let evidence = match doc.get("boundary_evidence").and_then(|v| v.as_array()) {
        Some(e) => e,
        None => {
            return fail(
                BoundaryFailureReason::RequiredFieldMissing {
                    field: "boundary_evidence".into(),
                },
                1,
                metadata,
            );
        }
    };
    for obs in evidence {
        let method = obs.get("method").and_then(|v| v.as_str()).unwrap_or("");
        if !BOUNDARY_OBSERVATION_METHODS.contains(&method) {
            return fail(
                BoundaryFailureReason::MethodVocabularyViolation {
                    found: method.to_string(),
                },
                1,
                metadata,
            );
        }
    }

    // ── Stage 2: canonical-hash recompute + compare ───────────────────────
    let computed = recompute_boundary_canonical_hash(doc);
    let claimed = str_of(doc, "canonical_hash").unwrap_or_default();
    if computed.is_empty() || computed != strip_hash_prefix(&claimed) {
        return fail(
            BoundaryFailureReason::CanonicalHashMismatch {
                claimed,
                computed: format!("sha512:{computed}"),
            },
            2,
            metadata,
        );
    }

    // ── Stage 3: Ed25519 over the canonical-hash hex string ───────────────
    let sig_b64 = doc
        .pointer("/attestation/signature")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let pub_b64 = doc
        .pointer("/attestation/public_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let (sig_b64, pub_b64) = match (sig_b64, pub_b64) {
        (Some(s), Some(p)) => (s, p),
        // No signature this build could check: canonical form verified,
        // integrity NOT established. `valid` stays true; the CLI maps this
        // to exit 3, never exit 0 (commit b372515 exit-code ladder).
        _ => {
            return BoundaryVerificationResult {
                valid: true,
                failure_reason: None,
                stage_reached: 2,
                signature_checked: false,
                trust_anchored: false,
                metadata,
            };
        }
    };

    // Integrity: embedded key.
    match verify_message_with_key(&computed, sig_b64, pub_b64) {
        SignatureCheck::Verified => {}
        SignatureCheck::Failed(reason) => {
            return fail(
                BoundaryFailureReason::SignatureMismatch { reason },
                3,
                metadata,
            );
        }
        // verify_message_with_key never returns Absent; fail closed.
        SignatureCheck::Absent | SignatureCheck::Unsupported(_) => {
            return fail(
                BoundaryFailureReason::SignatureMismatch {
                    reason: SignatureFailureReason::Malformed,
                },
                3,
                metadata,
            );
        }
    }

    // Authenticity: resolve + re-verify against the trust-chain manifest
    // (same ADR-011/ADR-033 machinery as AuditProofs — ADR-050 D4).
    let manifest = match &policy.trust_chain {
        Some(m) => m,
        None => {
            return BoundaryVerificationResult {
                valid: true,
                failure_reason: None,
                stage_reached: 3,
                signature_checked: true,
                trust_anchored: false,
                metadata,
            };
        }
    };
    let authority_id = str_of(doc, "authority_id").unwrap_or_else(|| "us-kms-nanorix-v1".into());
    let signing_key_version = metadata.signing_key_version.clone().unwrap_or_default();
    let lookup = match manifest.find_key(&authority_id, &signing_key_version) {
        Some(l) => l,
        None => {
            return fail(
                BoundaryFailureReason::SigningKeyVersionUnknown {
                    version: signing_key_version,
                },
                3,
                metadata,
            );
        }
    };
    match verify_message_with_key(&computed, sig_b64, &lookup.record.public_key_b64) {
        SignatureCheck::Verified => {}
        _ => {
            return fail(
                BoundaryFailureReason::SignatureMismatch {
                    reason: SignatureFailureReason::DoesNotVerify,
                },
                3,
                metadata,
            );
        }
    }
    if lookup.authority_record.revoked {
        return fail(BoundaryFailureReason::AuthorityRevoked, 3, metadata);
    }

    metadata.signing_key_version = Some(signing_key_version);
    BoundaryVerificationResult {
        valid: true,
        failure_reason: None,
        stage_reached: 3,
        signature_checked: true,
        trust_anchored: true,
        metadata,
    }
}

/// Verify a chain of BoundaryAttestations for ONE capsule (ADR-050 D5, D7
/// stage 4). Documents are walked in `attestation_index` order (the supplied
/// order does not matter). Any suffix of a chain is internally checkable;
/// `genesis_anchored` reports whether the walk reached the genesis origin.
pub fn verify_boundary_chain(docs: &[Value], policy: &VerifierPolicy) -> BoundaryChainResult {
    let mut ordered: Vec<&Value> = docs.iter().collect();
    ordered.sort_by_key(|d| {
        d.get("attestation_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    });

    let mut per_document = Vec::with_capacity(ordered.len());
    let mut all_signatures_checked = true;

    // Per-document verification first: a chain is only as good as its links.
    for doc in &ordered {
        let r = verify_boundary_attestation(doc, policy);
        if !r.valid {
            let failed_at_index = r.metadata.attestation_index;
            let failure_reason = r.failure_reason.clone();
            per_document.push(r);
            return BoundaryChainResult {
                valid: false,
                failure_reason,
                failed_at_index,
                per_document,
                chain_span: None,
                genesis_anchored: false,
                all_signatures_checked: false,
            };
        }
        all_signatures_checked &= r.signature_checked;
        per_document.push(r);
    }

    let fail_chain = |reason: BoundaryFailureReason,
                      failed_at_index: Option<u64>,
                      per_document: Vec<BoundaryVerificationResult>| {
        BoundaryChainResult {
            valid: false,
            failure_reason: Some(reason),
            failed_at_index,
            per_document,
            chain_span: None,
            genesis_anchored: false,
            all_signatures_checked,
        }
    };

    // Linkage walk.
    let mut prev_canonical: Option<String> = None;
    let mut prev_index: Option<u64> = None;
    let mut prev_cutoff: Option<chrono::DateTime<chrono::FixedOffset>> = None;
    let mut prev_cutoff_raw = String::new();
    let expected_capsule = ordered
        .first()
        .and_then(|d| d.get("capsule_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut genesis_anchored = false;

    for doc in &ordered {
        let index = doc
            .get("attestation_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let capsule = doc
            .get("capsule_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if capsule != expected_capsule {
            return fail_chain(
                BoundaryFailureReason::CapsuleIdMismatch {
                    expected: expected_capsule,
                    found: capsule,
                },
                Some(index),
                per_document,
            );
        }

        let claimed_prev = doc
            .get("prev_attestation_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if let Some(pi) = prev_index {
            if index != pi + 1 {
                return fail_chain(
                    BoundaryFailureReason::IndexNotStrictlyIncremented {
                        prev_index: pi,
                        index,
                    },
                    Some(index),
                    per_document,
                );
            }
            let computed_prev = prev_canonical.clone().unwrap_or_default();
            if strip_hash_prefix(&claimed_prev) != computed_prev {
                return fail_chain(
                    BoundaryFailureReason::PrevAttestationHashMismatch {
                        index,
                        claimed: claimed_prev,
                        computed: format!("sha512:{computed_prev}"),
                    },
                    Some(index),
                    per_document,
                );
            }
        } else if index == 1 {
            // Head of the supplied set IS the chain origin: genesis rule.
            if strip_hash_prefix(&claimed_prev) != NANORIX_GENESIS_HASH {
                return fail_chain(
                    BoundaryFailureReason::GenesisPrevHashMismatch {
                        claimed: claimed_prev,
                    },
                    Some(index),
                    per_document,
                );
            }
            genesis_anchored = true;
        }
        // Head with index > 1: a suffix — its prev link points at a document
        // we do not hold, so it cannot be checked here. Reported structurally
        // via `genesis_anchored = false`, never silently upgraded.

        let cutoff_raw = doc
            .get("cutoff_ts")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let cutoff = match chrono::DateTime::parse_from_rfc3339(&cutoff_raw) {
            Ok(t) => t,
            Err(_) => {
                return fail_chain(
                    BoundaryFailureReason::CutoffTimestampUnparseable { found: cutoff_raw },
                    Some(index),
                    per_document,
                );
            }
        };
        if let Some(pc) = prev_cutoff {
            if cutoff <= pc {
                return fail_chain(
                    BoundaryFailureReason::CutoffNotIncreasing {
                        prev_cutoff: prev_cutoff_raw.clone(),
                        cutoff: cutoff_raw,
                    },
                    Some(index),
                    per_document,
                );
            }
        }

        prev_canonical = Some(recompute_boundary_canonical_hash(doc));
        prev_index = Some(index);
        prev_cutoff = Some(cutoff);
        prev_cutoff_raw = cutoff_raw;
    }

    let chain_span = match (ordered.first(), ordered.last()) {
        (Some(f), Some(l)) => {
            let lo = f.get("attestation_index").and_then(|v| v.as_u64());
            let hi = l.get("attestation_index").and_then(|v| v.as_u64());
            lo.zip(hi)
        }
        _ => None,
    };

    BoundaryChainResult {
        valid: true,
        failure_reason: None,
        failed_at_index: None,
        per_document,
        chain_span,
        genesis_anchored,
        all_signatures_checked,
    }
}

/// Verify a disclosed activity trail against one attestation's commitment
/// (ADR-050 D7 stage 5). Returns `None` when the recomputed ADR-039-shaped
/// chain and the event count both match the document.
pub fn verify_disclosed_activity_trail(
    doc: &Value,
    events: &[Value],
) -> Option<BoundaryFailureReason> {
    let claimed_count = doc
        .get("activity_event_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if claimed_count != events.len() as u64 {
        return Some(BoundaryFailureReason::ActivityEventCountMismatch {
            claimed: claimed_count,
            actual: events.len() as u64,
        });
    }
    let claimed = doc
        .get("activity_commitment")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let computed = recompute_activity_commitment(events);
    if strip_hash_prefix(&claimed) != computed {
        return Some(BoundaryFailureReason::ActivityCommitmentMismatch {
            claimed,
            computed: format!("sha512:{computed}"),
        });
    }
    None
}
