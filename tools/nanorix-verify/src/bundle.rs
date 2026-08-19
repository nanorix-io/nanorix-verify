//! Portable Receipt Bundle (`.prb.json`) — Wave B Item 7 surface.
//!
//! A self-contained JSON document allowing a single `RecordReceipt` to be
//! verified independently of the parent AuditProof, at an adapter / auditor /
//! regulator endpoint. This module is the Rust reference implementation; the
//! Go / Python / TypeScript ports MUST produce byte-identical bundle JSON
//! against the canonical reference vectors.
//!
//! Per `feedback_narrowness_is_the_moat_resist_receipt_enrichment.md`: this
//! is a JSON convention + JSON Schema + SDK helper — NOT a new file format
//! with MIME registration / OS-level associations. Years of standards work
//! were explicitly OUT OF SCOPE for this batch.
//!
//! Per `feedback_signed_primitive_vs_derived_value.md`: the bundle is a
//! layer-2 transport artifact. The signed primitive (the receipt + outer
//! AuditProof Ed25519 signature) stays narrow; the bundle merely re-packages
//! them for portability.
//!
//! Per `feedback_narrow_signed_claim_auditor_certifies.md`: bundle disclaimer
//! cites; never asserts compliance. Vocabulary discipline forbids
//! COMPLIANT/SATISFIED/PASSED/MEETS in the disclaimer text.
//!
//! ## Verification flow
//!
//! 1. Extract bundle from a full AuditProof via `extract_receipt_bundle`,
//!    selecting the receipt at `record_index`.
//! 2. Ship bundle to consumer (auditor archive, GRC tool, regulator handoff).
//! 3. Consumer verifies bundle via `verify_receipt_bundle`:
//!    - Recompute receipt's `record_chain_hash` from its fields.
//!    - Verify Merkle inclusion proof binds receipt to outer `record_receipts_merkle_root`.
//!    - Recompute Step 8 amended hash from outer anchors + Merkle root.
//!    - Compare to `step_8_chain_hash`.
//!    - Verify the outer Ed25519 signature over the ASCII-hex bytes of the
//!      anchor named by `signature_target`: `step8_chain_hash` (legacy
//!      default — CDP v1.0/v2.0 signing model) or `document_canonical_hash`
//!      (CDP v2.1 — the producer signs the FullCdp canonical hash, so the
//!      bundle carries that hash as the signed message).
//!
//! ## v2.1 commitment semantics (never overclaim)
//!
//! When `signature_target = document_canonical_hash`, the signature proves
//! the producer attested to the exact document whose canonical hash the
//! bundle carries. The bundle cannot re-derive that hash (it does not carry
//! the full document), so binding the bundled `record_receipts_merkle_root`
//! to the SIGNED document requires the source AuditProof. See
//! [`bundle_verdict_text`] for the verdict wording that states this plainly.
//!
//! Cross-impl byte-equivalence: see `tests/bundle_cross_impl.rs` for the
//! reference vectors that anchor Rust/Go/Python/TypeScript bundle JSON
//! identity.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{strip_base64_prefix, strip_hash_prefix};

/// Mandatory bundle disclaimer — factual language only, no compliance verdicts.
///
/// Vocabulary discipline per `regulatory_context` rules + CONVENTIONS.md:
/// forbidden words include `COMPLIANT`, `SATISFIED`, `PASSED`, `MEETS`.
pub const PORTABLE_RECEIPT_BUNDLE_DISCLAIMER: &str = "This Portable Receipt Bundle carries cryptographic evidence of one record's structural execution. Verifying party uses the audit_proof_anchors to verify the receipt's merkle inclusion + outer Ed25519 signature. Control framework references are NOT included in this bundle; consult the ADR-040 mapping artifact at schema.nanorix.com/control-map/{framework_version}.json to apply current control mappings at consumption time.";

/// `signature_target` value for the legacy CDP v1.0/v2.0 signing model:
/// the outer Ed25519 signature covers the ASCII-hex bytes of
/// `step_8_chain_hash`. An absent `signature_target` means this.
pub const SIGNATURE_TARGET_STEP8_CHAIN_HASH: &str = "step8_chain_hash";

/// `signature_target` value for the CDP v2.1 signing model: the outer
/// Ed25519 signature covers the ASCII-hex bytes of the FullCdp document
/// canonical hash (RFC 8785 JCS → SHA-512 → lowercase hex), carried in
/// `document_canonical_hash`.
pub const SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH: &str = "document_canonical_hash";

/// Wave B Item 7 — Portable Receipt Bundle wire shape.
///
/// Forever-Standard ADR-006 I0: `bundle_version` is append-only; the V1.0
/// shape remains valid forever. Future bundle types land as new wire-format
/// versions, NEVER as breaking-shape changes to V1.0.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortableReceiptBundle {
    pub bundle_version: String,
    pub bundle_type: String,
    pub generated_at: String,
    pub receipt: serde_json::Value,
    pub audit_proof_anchors: AuditProofAnchors,
    pub disclaimer: String,
}

/// Minimal outer-AuditProof anchors carried inside a Portable Receipt Bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditProofAnchors {
    pub capsule_id: String,
    pub key_id: String,
    pub verification_key: String,
    pub step_8_chain_hash: String,
    pub signature: String,
    pub record_receipts_merkle_root: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework_version_at_emit: Option<String>,
    /// Which anchor the outer Ed25519 signature covers. Absent = legacy
    /// [`SIGNATURE_TARGET_STEP8_CHAIN_HASH`] (v1.0/v2.0 bundles predate this
    /// field). Additive per ADR-006 I0 — legacy bundle JSON is byte-unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_target: Option<String>,
    /// FullCdp document canonical hash (bare lowercase 128-char hex) — the
    /// signed message when `signature_target` is
    /// [`SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH`]. Absent on legacy bundles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_canonical_hash: Option<String>,
}

/// Bundle-extraction / verification errors.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("AuditProof has no record_receipts field; cannot extract receipt bundle from pre-Wave-N AuditProof")]
    NoReceipts,
    #[error("record index {0} out of bounds; AuditProof has {1} receipts")]
    IndexOutOfBounds(u32, usize),
    #[error("AuditProof is missing required field {0}")]
    MissingField(&'static str),
    #[error("record_chain_hash mismatch: claimed={claimed} recomputed={recomputed}")]
    RecordChainHashMismatch { claimed: String, recomputed: String },
    #[error("merkle inclusion proof does not bind receipt to claimed outer root {0}")]
    MerkleInclusionFailed(String),
    #[error("step_8_chain_hash mismatch: claimed={claimed} recomputed={recomputed}")]
    Step8Mismatch { claimed: String, recomputed: String },
    #[error("outer Ed25519 signature failed verification")]
    SignatureFailed,
    #[error("bundle declares signature_target=document_canonical_hash (CDP v2.1 signing model) but carries no document_canonical_hash value; re-extract the bundle from the source AuditProof with a v2.1-aware extractor")]
    MissingCanonicalHashAnchor,
    #[error("unknown signature_target {0:?}; this verifier understands step8_chain_hash and document_canonical_hash")]
    UnknownSignatureTarget(String),
    #[error("base64 decode error in field {field}: {reason}")]
    Base64Decode { field: &'static str, reason: String },
    #[error("bundle JSON shape error: {0}")]
    Shape(String),
}

/// Extract a single receipt + outer anchors into a Portable Receipt Bundle.
///
/// `audit_proof` is the full FullCdp/VerificationCdp JSON; `record_index`
/// selects the receipt within `record_receipts`. Returns
/// `Err(BundleError::NoReceipts)` if the AuditProof is pre-Wave-N (no
/// `record_receipts` field).
pub fn extract_receipt_bundle(
    audit_proof: &serde_json::Value,
    record_index: u32,
) -> Result<PortableReceiptBundle, BundleError> {
    let receipts = audit_proof
        .get("record_receipts")
        .and_then(|v| v.as_array())
        .ok_or(BundleError::NoReceipts)?;

    let receipt = receipts
        .get(record_index as usize)
        .cloned()
        .ok_or(BundleError::IndexOutOfBounds(record_index, receipts.len()))?;

    let capsule_id = audit_proof
        .get("capsule_id")
        .and_then(|v| v.as_str())
        .ok_or(BundleError::MissingField("capsule_id"))?
        .to_string();

    let timestamp = audit_proof
        .get("destroyed_at")
        .and_then(|v| v.as_str())
        .ok_or(BundleError::MissingField("destroyed_at"))?
        .to_string();

    let key_id = audit_proof
        .pointer("/attestation/key_id")
        .or_else(|| audit_proof.get("key_id"))
        .and_then(|v| v.as_str())
        .ok_or(BundleError::MissingField("attestation.key_id"))?
        .to_string();

    let verification_key = audit_proof
        .pointer("/attestation/verification_key")
        .or_else(|| audit_proof.pointer("/attestation/public_key"))
        .or_else(|| audit_proof.get("verification_key"))
        .and_then(|v| v.as_str())
        .ok_or(BundleError::MissingField("attestation.verification_key"))?
        .to_string();

    let signature = audit_proof
        .pointer("/attestation/signature")
        .or_else(|| audit_proof.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or(BundleError::MissingField("attestation.signature"))?
        .to_string();

    let record_receipts_merkle_root = audit_proof
        .get("record_receipts_merkle_root")
        .and_then(|v| v.as_str())
        .ok_or(BundleError::MissingField("record_receipts_merkle_root"))?
        .to_string();

    // Recompute Step 8 amended hash from chain. The last chain step's
    // chain_hash IS the Step 8 amended hash per the canonical 8-step shape.
    let step_8_chain_hash = audit_proof
        .get("chain")
        .and_then(|v| v.as_array())
        .and_then(|c| c.last())
        .and_then(|s| s.get("chain_hash"))
        .and_then(|v| v.as_str())
        .ok_or(BundleError::MissingField("chain[7].chain_hash"))?
        .to_string();

    let framework_version_at_emit = audit_proof
        .get("regulatory_context")
        .and_then(|v| v.get("framework_version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // CDP v2.1 signs the FullCdp document canonical hash, NOT the Step 8
    // chain hash. Populate the signature-target anchor from the source proof
    // version so `verify_receipt_bundle` verifies the correct message.
    // Recompute (same convention as `canonical_recompute::signed_message`)
    // rather than trusting an embedded field; fall back to the proof's
    // `canonical_hash` field only on the fail-closed empty recompute.
    let cdp_version = audit_proof
        .get("cdp_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (signature_target, document_canonical_hash) = if cdp_version == "2.1" {
        let recomputed = crate::canonical_recompute::recompute_canonical_hash(audit_proof);
        let canonical = if recomputed.is_empty() {
            audit_proof
                .get("canonical_hash")
                .and_then(|v| v.as_str())
                .map(|s| strip_hash_prefix(s).to_string())
                .filter(|s| !s.is_empty())
                .ok_or(BundleError::MissingCanonicalHashAnchor)?
        } else {
            recomputed
        };
        (
            Some(SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH.to_string()),
            Some(canonical),
        )
    } else {
        (None, None)
    };

    Ok(PortableReceiptBundle {
        bundle_version: "1.0".to_string(),
        bundle_type: "receipt".to_string(),
        generated_at: now_iso8601(),
        receipt,
        audit_proof_anchors: AuditProofAnchors {
            capsule_id,
            key_id,
            verification_key,
            step_8_chain_hash,
            signature,
            record_receipts_merkle_root,
            timestamp,
            framework_version_at_emit,
            signature_target,
            document_canonical_hash,
        },
        disclaimer: PORTABLE_RECEIPT_BUNDLE_DISCLAIMER.to_string(),
    })
}

/// Verify a Portable Receipt Bundle standalone — Mode B per ADR-039.
///
/// Steps (mirrors `extract_receipt_bundle` inverse semantics):
/// 1. Recompute the receipt's `record_chain_hash` from its fields.
/// 2. Verify Merkle inclusion proof binds receipt to `record_receipts_merkle_root`.
/// 3. Verify the outer Ed25519 signature using `verification_key` over the
///    ASCII-hex bytes of the anchor named by `signature_target`:
///    absent / `step8_chain_hash` → `step_8_chain_hash` (legacy v1.0/v2.0);
///    `document_canonical_hash` → the carried FullCdp canonical hash (v2.1).
///
/// On success returns `Ok(())`. On failure returns a typed `BundleError`.
/// Use [`bundle_verdict_text`] for the human verdict — for v2.1 bundles it
/// states the commitment semantics (binding the bundled Merkle root to the
/// signed document requires the source AuditProof).
pub fn verify_receipt_bundle(bundle: &PortableReceiptBundle) -> Result<(), BundleError> {
    if bundle.bundle_version != "1.0" {
        return Err(BundleError::Shape(format!(
            "unsupported bundle_version: {}",
            bundle.bundle_version
        )));
    }
    if bundle.bundle_type != "receipt" {
        return Err(BundleError::Shape(format!(
            "wrong bundle_type for Portable Receipt Bundle: {}",
            bundle.bundle_type
        )));
    }

    let anchors = &bundle.audit_proof_anchors;

    // (1) Recompute record_chain_hash from receipt fields.
    let record_index = bundle
        .receipt
        .get("record_index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| BundleError::Shape("receipt.record_index missing".to_string()))?
        as u32;
    let record_id = bundle
        .receipt
        .get("record_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BundleError::Shape("receipt.record_id missing".to_string()))?;
    let in_h = bundle
        .receipt
        .get("record_input_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BundleError::Shape("receipt.record_input_hash missing".to_string()))?;
    let out_h = bundle
        .receipt
        .get("record_output_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BundleError::Shape("receipt.record_output_hash missing".to_string()))?;
    let claimed_chain_hash = bundle
        .receipt
        .get("record_chain_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BundleError::Shape("receipt.record_chain_hash missing".to_string()))?;

    let activity_root = match bundle
        .receipt
        .get("record_activity_trail")
        .and_then(|v| v.as_array())
    {
        Some(trail) if !trail.is_empty() => compute_activity_root_local(trail),
        _ => crate::NANORIX_GENESIS_HASH.to_string(),
    };

    // ADR-039: a declared pattern_tag is a signed primitive — bind its wire
    // form into the recompute (mirrors the server's `wave_n.rs` and the
    // Go/Python/TypeScript bundle ports).
    let pattern_tag = bundle.receipt.get("pattern_tag").and_then(|v| v.as_str());

    let recomputed = compute_record_chain_hash_local(
        &anchors.capsule_id,
        record_index,
        record_id,
        in_h,
        out_h,
        &activity_root,
        pattern_tag,
    );

    if recomputed != strip_hash_prefix(claimed_chain_hash) {
        return Err(BundleError::RecordChainHashMismatch {
            claimed: claimed_chain_hash.to_string(),
            recomputed,
        });
    }

    // (2) Verify Merkle inclusion proof.
    let inclusion_proof: Vec<String> = bundle
        .receipt
        .get("merkle_inclusion_proof")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if !verify_merkle_inclusion_proof_local(
        claimed_chain_hash,
        record_index as usize,
        &inclusion_proof,
        &anchors.record_receipts_merkle_root,
    ) {
        return Err(BundleError::MerkleInclusionFailed(
            anchors.record_receipts_merkle_root.clone(),
        ));
    }

    // (3) Verify Ed25519 signature over the target named by signature_target.
    //
    // The bundle does NOT carry the full 8-step chain or the full signed
    // document (would defeat the portability purpose).
    //
    // Legacy target (step8_chain_hash — v1.0/v2.0 signing model):
    //   - Step 8's chain_hash transitively depends on Steps 1-7 (chain).
    //   - Step 8 amended ALSO incorporates record_receipts_merkle_root (which
    //     we verify against via Merkle inclusion in step (2) above).
    //   - The Ed25519 signature over step_8_chain_hash binds the producer's
    //     authority to the precise (chain + receipt set + timestamp).
    //
    // v2.1 target (document_canonical_hash): the producer signs the FullCdp
    // canonical hash. The bundle carries that hash as the signed message;
    // the signature proves authority over that exact document commitment.
    // Binding the bundled record_receipts_merkle_root to the SIGNED document
    // cannot be established from the bundle alone — the canonical hash is a
    // commitment over the whole document, which the bundle does not carry.
    // `bundle_verdict_text` states this plainly; for the full binding the
    // consumer verifies the source AuditProof (out of bundle scope).
    let signed_message: &str = match anchors.signature_target.as_deref() {
        None | Some(SIGNATURE_TARGET_STEP8_CHAIN_HASH) => {
            strip_hash_prefix(&anchors.step_8_chain_hash)
        }
        Some(SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH) => {
            let canonical = anchors
                .document_canonical_hash
                .as_deref()
                .ok_or(BundleError::MissingCanonicalHashAnchor)?;
            strip_hash_prefix(canonical)
        }
        Some(other) => {
            return Err(BundleError::UnknownSignatureTarget(other.to_string()));
        }
    };

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(strip_base64_prefix(&anchors.signature))
        .map_err(|e| BundleError::Base64Decode {
            field: "audit_proof_anchors.signature",
            reason: e.to_string(),
        })?;
    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(strip_base64_prefix(&anchors.verification_key))
        .map_err(|e| BundleError::Base64Decode {
            field: "audit_proof_anchors.verification_key",
            reason: e.to_string(),
        })?;

    if sig_bytes.len() != 64 {
        return Err(BundleError::SignatureFailed);
    }
    if pub_bytes.len() != 32 {
        return Err(BundleError::SignatureFailed);
    }

    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| BundleError::SignatureFailed)?;
    let pub_array: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| BundleError::SignatureFailed)?;

    let signature = Signature::from_bytes(&sig_array);
    let verifying_key =
        VerifyingKey::from_bytes(&pub_array).map_err(|_| BundleError::SignatureFailed)?;

    verifying_key
        .verify(signed_message.as_bytes(), &signature)
        .map_err(|_| BundleError::SignatureFailed)?;

    Ok(())
}

/// Human-readable verdict for a bundle that [`verify_receipt_bundle`]
/// accepted. Never overclaims: the v2.1 wording states the commitment
/// semantics — the signature covers the document canonical hash, and binding
/// the bundled Merkle root to that signed document requires the source
/// AuditProof, which the bundle does not carry.
pub fn bundle_verdict_text(bundle: &PortableReceiptBundle) -> String {
    match bundle.audit_proof_anchors.signature_target.as_deref() {
        Some(SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH) => {
            "Ed25519 signature verified over the document canonical hash (CDP v2.1 signing model). \
             The receipt chain hash was recomputed and its Merkle inclusion checked against the \
             bundled record_receipts_merkle_root. NOTE: the canonical hash is a commitment over \
             the entire source AuditProof document, which this bundle does not carry — so this \
             verification establishes (a) the signature is authentic over the carried canonical \
             hash and (b) the receipt is consistent with the bundled Merkle root. Binding that \
             Merkle root to the SIGNED document requires verifying the source AuditProof."
                .to_string()
        }
        _ => "Ed25519 signature verified over step_8_chain_hash. The receipt chain hash was \
             recomputed and its Merkle inclusion checked against the bundled \
             record_receipts_merkle_root, which the Step 8 amended hash incorporates."
            .to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Local hash primitives (mirror governance/rzl/src/wave_n.rs to keep the
// verifier independent of the service-side crate per EO-07 standalone artifact)
// ─────────────────────────────────────────────────────────────────────────────

/// `pattern_tag_wire` follows the server's conditional-append rule
/// (`governance/rzl/src/wave_n.rs`): the trailing `\x00 ‖ pattern_tag_wire`
/// segment is appended ONLY when the receipt declares a tag (ADR-039
/// signed-primitive binding).
fn compute_record_chain_hash_local(
    capsule_id: &str,
    record_index: u32,
    record_id: &str,
    in_h: &str,
    out_h: &str,
    activity_root: &str,
    pattern_tag_wire: Option<&str>,
) -> String {
    let in_h = strip_hash_prefix(in_h);
    let out_h = strip_hash_prefix(out_h);
    let activity_h = strip_hash_prefix(activity_root);
    let idx = record_index.to_string();

    let mut data = Vec::new();
    data.extend_from_slice(capsule_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(idx.as_bytes());
    data.push(0x00);
    data.extend_from_slice(record_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(in_h.as_bytes());
    data.push(0x00);
    data.extend_from_slice(out_h.as_bytes());
    data.push(0x00);
    data.extend_from_slice(activity_h.as_bytes());
    if let Some(tag) = pattern_tag_wire {
        data.push(0x00);
        data.extend_from_slice(tag.as_bytes());
    }

    hex::encode(Sha512::digest(&data))
}

fn compute_activity_root_local(trail: &[serde_json::Value]) -> String {
    let mut prev = crate::NANORIX_GENESIS_HASH.to_string();
    for event in trail {
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

fn merkle_pair_hash_local(left: &str, right: &str) -> String {
    let left = strip_hash_prefix(left);
    let right = strip_hash_prefix(right);
    let mut data = Vec::with_capacity(left.len() + 1 + right.len());
    data.extend_from_slice(left.as_bytes());
    data.push(0x00);
    data.extend_from_slice(right.as_bytes());
    hex::encode(Sha512::digest(&data))
}

fn verify_merkle_inclusion_proof_local(
    leaf: &str,
    leaf_index: usize,
    proof: &[String],
    claimed_root: &str,
) -> bool {
    let leaf_stripped = strip_hash_prefix(leaf).to_string();
    let claimed_stripped = strip_hash_prefix(claimed_root);

    if proof.is_empty() {
        return leaf_stripped == claimed_stripped;
    }

    let mut current = leaf_stripped;
    let mut idx = leaf_index;
    for sibling in proof {
        current = if idx.is_multiple_of(2) {
            merkle_pair_hash_local(&current, sibling)
        } else {
            merkle_pair_hash_local(sibling, &current)
        };
        idx /= 2;
    }
    current == claimed_stripped
}

fn now_iso8601() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha512};

    /// Synthesize a Wave-N AuditProof with N=2 receipts for testing.
    fn make_wave_n_proof_n2() -> (serde_json::Value, SigningKey) {
        let timestamp = "2026-05-12T00:00:00Z";
        let capsule_id = "cap_bundle_test_n2";

        // Two receipts
        let receipt_0_chain = compute_record_chain_hash_local(
            capsule_id,
            0,
            "rec_a",
            "sha512:11",
            "sha512:21",
            crate::NANORIX_GENESIS_HASH,
            None,
        );
        let receipt_1_chain = compute_record_chain_hash_local(
            capsule_id,
            1,
            "rec_b",
            "sha512:12",
            "sha512:22",
            crate::NANORIX_GENESIS_HASH,
            None,
        );

        let merkle_root = merkle_pair_hash_local(&receipt_0_chain, &receipt_1_chain);

        // Build 8-step chain
        let mut prev_hash = crate::NANORIX_GENESIS_HASH.to_string();
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
        for (i, subsystem) in subsystems.iter().enumerate() {
            let method = crate::lookup_method(subsystem);
            let chain_hash = if i == 7 {
                // Step 8 amended with merkle root
                let base =
                    crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
                let mut data = Vec::new();
                data.extend_from_slice(base.as_bytes());
                data.push(0x00);
                data.extend_from_slice(merkle_root.as_bytes());
                hex::encode(Sha512::digest(&data))
            } else {
                crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp)
            };
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

        // Sign the final hash (step 8 chain_hash) with a deterministic Ed25519 key.
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(final_hash.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let pub_b64 = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());

        let proof = serde_json::json!({
            "cdp_version": "2.0",
            "capsule_id": capsule_id,
            "destroyed_at": timestamp,
            "chain": chain,
            "final_hash": final_hash.clone(),
            "record_receipts": [
                {
                    "record_index": 0,
                    "record_id": "rec_a",
                    "record_input_hash": "sha512:11",
                    "record_output_hash": "sha512:21",
                    "record_chain_hash": format!("sha512:{}", receipt_0_chain),
                    "merkle_inclusion_proof": [receipt_1_chain.clone()],
                },
                {
                    "record_index": 1,
                    "record_id": "rec_b",
                    "record_input_hash": "sha512:12",
                    "record_output_hash": "sha512:22",
                    "record_chain_hash": format!("sha512:{}", receipt_1_chain),
                    "merkle_inclusion_proof": [receipt_0_chain.clone()],
                },
            ],
            "record_receipts_merkle_root": format!("sha512:{}", merkle_root),
            "attestation": {
                "key_id": "nrx-verify-test-key",
                "verification_key": pub_b64,
                "signature": sig_b64,
            },
        });

        (proof, signing_key)
    }

    #[test]
    fn extract_receipt_bundle_n2_index_0_succeeds() {
        let (proof, _) = make_wave_n_proof_n2();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        assert_eq!(bundle.bundle_version, "1.0");
        assert_eq!(bundle.bundle_type, "receipt");
        assert_eq!(bundle.audit_proof_anchors.capsule_id, "cap_bundle_test_n2");
        assert_eq!(
            bundle.receipt.get("record_id").and_then(|v| v.as_str()),
            Some("rec_a")
        );
    }

    #[test]
    fn extract_receipt_bundle_n2_index_1_succeeds() {
        let (proof, _) = make_wave_n_proof_n2();
        let bundle = extract_receipt_bundle(&proof, 1).unwrap();
        assert_eq!(
            bundle.receipt.get("record_id").and_then(|v| v.as_str()),
            Some("rec_b")
        );
    }

    #[test]
    fn extract_receipt_bundle_out_of_bounds_errors() {
        let (proof, _) = make_wave_n_proof_n2();
        let err = extract_receipt_bundle(&proof, 5).unwrap_err();
        assert!(matches!(err, BundleError::IndexOutOfBounds(5, 2)));
    }

    #[test]
    fn extract_receipt_bundle_pre_wave_n_errors_with_no_receipts() {
        let proof = serde_json::json!({
            "cdp_version": "1.0",
            "capsule_id": "cap_pre_wave_n",
            "destroyed_at": "2026-01-01T00:00:00Z",
            "chain": [],
            "final_hash": "",
        });
        let err = extract_receipt_bundle(&proof, 0).unwrap_err();
        assert!(matches!(err, BundleError::NoReceipts));
    }

    #[test]
    fn verify_receipt_bundle_roundtrip_succeeds() {
        let (proof, _key) = make_wave_n_proof_n2();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        verify_receipt_bundle(&bundle).expect("bundle verifies");
    }

    #[test]
    fn verify_receipt_bundle_n2_index_1_roundtrip() {
        let (proof, _key) = make_wave_n_proof_n2();
        let bundle = extract_receipt_bundle(&proof, 1).unwrap();
        verify_receipt_bundle(&bundle).expect("bundle verifies");
    }

    #[test]
    fn verify_receipt_bundle_tampered_chain_hash_rejected() {
        let (proof, _key) = make_wave_n_proof_n2();
        let mut bundle = extract_receipt_bundle(&proof, 0).unwrap();
        bundle.receipt["record_output_hash"] = serde_json::Value::String("sha512:bad".to_string());
        let err = verify_receipt_bundle(&bundle).unwrap_err();
        assert!(matches!(err, BundleError::RecordChainHashMismatch { .. }));
    }

    #[test]
    fn verify_receipt_bundle_tampered_inclusion_proof_rejected() {
        let (proof, _key) = make_wave_n_proof_n2();
        let mut bundle = extract_receipt_bundle(&proof, 0).unwrap();
        bundle.receipt["merkle_inclusion_proof"] =
            serde_json::Value::Array(vec![serde_json::Value::String("0".repeat(128))]);
        let err = verify_receipt_bundle(&bundle).unwrap_err();
        assert!(matches!(err, BundleError::MerkleInclusionFailed(_)));
    }

    #[test]
    fn verify_receipt_bundle_tampered_signature_rejected() {
        let (proof, _key) = make_wave_n_proof_n2();
        let mut bundle = extract_receipt_bundle(&proof, 0).unwrap();
        bundle.audit_proof_anchors.signature =
            base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let err = verify_receipt_bundle(&bundle).unwrap_err();
        assert!(matches!(err, BundleError::SignatureFailed));
    }

    #[test]
    fn bundle_disclaimer_factual_language() {
        let disclaimer = PORTABLE_RECEIPT_BUNDLE_DISCLAIMER;
        for forbidden in ["COMPLIANT", "SATISFIED", "PASSED", "MEETS"] {
            assert!(
                !disclaimer.contains(forbidden),
                "disclaimer must not contain forbidden term {forbidden}"
            );
        }
    }

    #[test]
    fn bundle_disclaimer_cites_adr_040_mapping() {
        assert!(PORTABLE_RECEIPT_BUNDLE_DISCLAIMER.contains("ADR-040"));
        assert!(PORTABLE_RECEIPT_BUNDLE_DISCLAIMER.contains("control-map"));
    }

    #[test]
    fn bundle_serializes_round_trips() {
        let (proof, _key) = make_wave_n_proof_n2();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let roundtripped: PortableReceiptBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, roundtripped);
    }

    #[test]
    fn bundle_version_is_pinned_to_1_0() {
        let (proof, _key) = make_wave_n_proof_n2();
        let mut bundle = extract_receipt_bundle(&proof, 0).unwrap();
        bundle.bundle_version = "2.0".to_string();
        let err = verify_receipt_bundle(&bundle).unwrap_err();
        assert!(matches!(err, BundleError::Shape(_)));
    }

    #[test]
    fn bundle_type_is_pinned_to_receipt() {
        let (proof, _key) = make_wave_n_proof_n2();
        let mut bundle = extract_receipt_bundle(&proof, 0).unwrap();
        bundle.bundle_type = "pubkey".to_string();
        let err = verify_receipt_bundle(&bundle).unwrap_err();
        assert!(matches!(err, BundleError::Shape(_)));
    }

    #[test]
    fn extract_n1_bundle_has_empty_inclusion_proof() {
        let timestamp = "2026-05-12T00:00:00Z";
        let capsule_id = "cap_n1";
        let receipt_chain = compute_record_chain_hash_local(
            capsule_id,
            0,
            "rec_only",
            "sha512:01",
            "sha512:02",
            crate::NANORIX_GENESIS_HASH,
            None,
        );
        let merkle_root = receipt_chain.clone();

        let mut prev_hash = crate::NANORIX_GENESIS_HASH.to_string();
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
        for (i, subsystem) in subsystems.iter().enumerate() {
            let method = crate::lookup_method(subsystem);
            let chain_hash = if i == 7 {
                let base =
                    crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
                let mut data = Vec::new();
                data.extend_from_slice(base.as_bytes());
                data.push(0x00);
                data.extend_from_slice(merkle_root.as_bytes());
                hex::encode(Sha512::digest(&data))
            } else {
                crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp)
            };
            chain.push(serde_json::json!({
                "subsystem": subsystem,
                "method": method,
                "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }

        let proof = serde_json::json!({
            "cdp_version": "2.0",
            "capsule_id": capsule_id,
            "destroyed_at": timestamp,
            "chain": chain,
            "record_receipts": [
                {
                    "record_index": 0,
                    "record_id": "rec_only",
                    "record_input_hash": "sha512:01",
                    "record_output_hash": "sha512:02",
                    "record_chain_hash": format!("sha512:{}", receipt_chain),
                    "merkle_inclusion_proof": [],
                },
            ],
            "record_receipts_merkle_root": format!("sha512:{}", merkle_root),
            "attestation": {
                "key_id": "k",
                "verification_key": "AA",
                "signature": "AA",
            },
        });

        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        let inclusion = bundle
            .receipt
            .get("merkle_inclusion_proof")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(inclusion.is_empty(), "N=1 bundle has empty inclusion proof");
    }

    #[test]
    fn extract_bundle_with_pattern_tag_carries_pattern_tag() {
        let timestamp = "2026-05-12T00:00:00Z";
        let capsule_id = "cap_with_tag";
        let receipt_chain = compute_record_chain_hash_local(
            capsule_id,
            0,
            "rec_pa",
            "sha512:in",
            "sha512:out",
            crate::NANORIX_GENESIS_HASH,
            Some("pa"),
        );
        let merkle_root = receipt_chain.clone();

        let mut prev_hash = crate::NANORIX_GENESIS_HASH.to_string();
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
        for (i, subsystem) in subsystems.iter().enumerate() {
            let method = crate::lookup_method(subsystem);
            let chain_hash = if i == 7 {
                let base =
                    crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
                let mut data = Vec::new();
                data.extend_from_slice(base.as_bytes());
                data.push(0x00);
                data.extend_from_slice(merkle_root.as_bytes());
                hex::encode(Sha512::digest(&data))
            } else {
                crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp)
            };
            chain.push(serde_json::json!({
                "subsystem": subsystem,
                "method": method,
                "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }

        let proof = serde_json::json!({
            "cdp_version": "2.0",
            "capsule_id": capsule_id,
            "destroyed_at": timestamp,
            "chain": chain,
            "record_receipts": [
                {
                    "record_index": 0,
                    "record_id": "rec_pa",
                    "record_input_hash": "sha512:in",
                    "record_output_hash": "sha512:out",
                    "record_chain_hash": format!("sha512:{}", receipt_chain),
                    "pattern_tag": "pa",
                    "merkle_inclusion_proof": [],
                },
            ],
            "record_receipts_merkle_root": format!("sha512:{}", merkle_root),
            "attestation": {
                "key_id": "k",
                "verification_key": "AA",
                "signature": "AA",
            },
        });

        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        assert_eq!(
            bundle.receipt.get("pattern_tag").and_then(|v| v.as_str()),
            Some("pa")
        );
    }

    #[test]
    fn extract_bundle_carries_framework_version_when_present() {
        let mut proof = make_wave_n_proof_n2().0;
        proof["regulatory_context"] = serde_json::json!({"framework_version": "2026-02"});
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        assert_eq!(
            bundle
                .audit_proof_anchors
                .framework_version_at_emit
                .as_deref(),
            Some("2026-02")
        );
    }

    #[test]
    fn extract_bundle_omits_framework_version_when_absent() {
        let (proof, _) = make_wave_n_proof_n2();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        assert!(bundle
            .audit_proof_anchors
            .framework_version_at_emit
            .is_none());
    }

    #[test]
    fn bundle_json_no_forbidden_compliance_terms() {
        let (proof, _) = make_wave_n_proof_n2();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        for forbidden in ["COMPLIANT", "SATISFIED", "PASSED", "MEETS"] {
            assert!(
                !json.contains(forbidden),
                "bundle JSON must not contain {forbidden}"
            );
        }
    }

    // ── CDP v2.1 signature-target anchor ────────────────────────────────────

    /// Synthesize a v2.1 AuditProof (N=1 receipt) whose attestation signs the
    /// FullCdp document canonical hash — the production v2.1 signing model
    /// (`services/api/src/routes/capsules.rs` Phase 2: Ed25519 over the ASCII
    /// bytes of the bare lowercase hex canonical hash).
    fn make_v21_proof() -> (serde_json::Value, SigningKey) {
        let timestamp = "2026-06-01T00:00:00Z";
        let capsule_id = "cap_v21_bundle_test";

        let receipt_chain = compute_record_chain_hash_local(
            capsule_id,
            0,
            "rec_v21",
            "sha512:aa",
            "sha512:bb",
            crate::NANORIX_GENESIS_HASH,
            None,
        );
        let merkle_root = receipt_chain.clone();

        let mut prev_hash = crate::NANORIX_GENESIS_HASH.to_string();
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
        for (i, subsystem) in subsystems.iter().enumerate() {
            let method = crate::lookup_method(subsystem);
            let chain_hash = if i == 7 {
                let base =
                    crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
                let mut data = Vec::new();
                data.extend_from_slice(base.as_bytes());
                data.push(0x00);
                data.extend_from_slice(merkle_root.as_bytes());
                hex::encode(Sha512::digest(&data))
            } else {
                crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp)
            };
            chain.push(serde_json::json!({
                "subsystem": subsystem,
                "method": method,
                "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }

        let mut proof = serde_json::json!({
            "cdp_version": "2.1",
            "signing_mode": "nanorix_only",
            "jurisdiction": "US",
            "authority_id": "us-kms-nanorix-v1",
            "signing_key_version": "1",
            "capsule_id": capsule_id,
            "org_id": "org_v21_test",
            "activity": [],
            "chain": chain,
            "destruction_state": "destroyed",
            "destroyed_at": timestamp,
            "hash_algorithm": "sha512",
            "signature_algorithm": "Ed25519",
            "record_receipts": [
                {
                    "record_index": 0,
                    "record_id": "rec_v21",
                    "record_input_hash": "sha512:aa",
                    "record_output_hash": "sha512:bb",
                    "record_chain_hash": format!("sha512:{}", receipt_chain),
                    "merkle_inclusion_proof": [],
                },
            ],
            "record_receipts_merkle_root": format!("sha512:{}", merkle_root),
        });

        // Sign the recomputed document canonical hash (bare lowercase hex,
        // ASCII bytes) — the confirmed v2.1 signed-byte-form.
        let canonical = crate::canonical_recompute::recompute_canonical_hash(&proof);
        assert_eq!(canonical.len(), 128, "canonical hash is 128-char hex");
        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(canonical.as_bytes());
        proof["attestation"] = serde_json::json!({
            "key_id": "nrx-verify-v21-test-key",
            "verification_key": base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes()),
            "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        });

        (proof, signing_key)
    }

    #[test]
    fn extract_v21_populates_signature_target_and_canonical_hash() {
        let (proof, _) = make_v21_proof();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        assert_eq!(
            bundle.audit_proof_anchors.signature_target.as_deref(),
            Some(SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH)
        );
        let carried = bundle
            .audit_proof_anchors
            .document_canonical_hash
            .as_deref()
            .expect("v2.1 bundle carries the canonical hash");
        assert_eq!(
            carried,
            crate::canonical_recompute::recompute_canonical_hash(&proof)
        );
    }

    #[test]
    fn extract_legacy_omits_signature_target_bytes_unchanged() {
        let (proof, _) = make_wave_n_proof_n2();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        assert!(bundle.audit_proof_anchors.signature_target.is_none());
        assert!(bundle.audit_proof_anchors.document_canonical_hash.is_none());
        // Byte-compat guard: legacy bundle JSON must not gain the new keys.
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(!json.contains("signature_target"));
        assert!(!json.contains("document_canonical_hash"));
    }

    #[test]
    fn verify_v21_bundle_roundtrip_succeeds() {
        let (proof, _key) = make_v21_proof();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        verify_receipt_bundle(&bundle).expect("v2.1 bundle verifies");
    }

    #[test]
    fn v21_bundle_missing_canonical_hash_is_structured_error() {
        let (proof, _key) = make_v21_proof();
        let mut bundle = extract_receipt_bundle(&proof, 0).unwrap();
        bundle.audit_proof_anchors.document_canonical_hash = None;
        let err = verify_receipt_bundle(&bundle).unwrap_err();
        assert!(
            matches!(err, BundleError::MissingCanonicalHashAnchor),
            "expected MissingCanonicalHashAnchor, got {err:?}"
        );
    }

    #[test]
    fn unknown_signature_target_is_structured_error() {
        let (proof, _key) = make_v21_proof();
        let mut bundle = extract_receipt_bundle(&proof, 0).unwrap();
        bundle.audit_proof_anchors.signature_target = Some("sha3_sponge".to_string());
        let err = verify_receipt_bundle(&bundle).unwrap_err();
        assert!(
            matches!(err, BundleError::UnknownSignatureTarget(ref t) if t == "sha3_sponge"),
            "expected UnknownSignatureTarget, got {err:?}"
        );
    }

    #[test]
    fn v21_tampered_canonical_hash_rejected() {
        let (proof, _key) = make_v21_proof();
        let mut bundle = extract_receipt_bundle(&proof, 0).unwrap();
        let tampered = "0".repeat(128);
        bundle.audit_proof_anchors.document_canonical_hash = Some(tampered);
        let err = verify_receipt_bundle(&bundle).unwrap_err();
        assert!(matches!(err, BundleError::SignatureFailed));
    }

    #[test]
    fn v21_bundle_serializes_round_trips() {
        let (proof, _key) = make_v21_proof();
        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let roundtripped: PortableReceiptBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, roundtripped);
        verify_receipt_bundle(&roundtripped).expect("roundtripped v2.1 bundle verifies");
    }

    #[test]
    fn verdict_text_states_commitment_semantics_never_overclaims() {
        let (v21_proof, _) = make_v21_proof();
        let v21_bundle = extract_receipt_bundle(&v21_proof, 0).unwrap();
        let v21_verdict = bundle_verdict_text(&v21_bundle);
        assert!(v21_verdict.contains("source AuditProof"));
        assert!(v21_verdict.contains("commitment"));

        let (legacy_proof, _) = make_wave_n_proof_n2();
        let legacy_bundle = extract_receipt_bundle(&legacy_proof, 0).unwrap();
        let legacy_verdict = bundle_verdict_text(&legacy_bundle);
        assert!(legacy_verdict.contains("step_8_chain_hash"));

        for verdict in [&v21_verdict, &legacy_verdict] {
            for forbidden in ["COMPLIANT", "SATISFIED", "PASSED", "MEETS"] {
                assert!(
                    !verdict.contains(forbidden),
                    "verdict must not contain {forbidden}"
                );
            }
        }
    }

    // ── ADR-039 pattern_tag signed-primitive binding (regression) ───────────

    /// A tagged receipt's record_chain_hash binds the pattern_tag wire form —
    /// the bundle verify path must recompute WITH the tag (mirrors the server
    /// and the Go/Python/TypeScript ports; this was previously missing here).
    #[test]
    fn verify_tagged_receipt_bundle_roundtrip_and_tamper_rejected() {
        let timestamp = "2026-05-12T00:00:00Z";
        let capsule_id = "cap_tagged_verify";
        let receipt_chain = compute_record_chain_hash_local(
            capsule_id,
            0,
            "rec_tagged",
            "sha512:in",
            "sha512:out",
            crate::NANORIX_GENESIS_HASH,
            Some("rcm_claim"),
        );
        let merkle_root = receipt_chain.clone();

        let mut prev_hash = crate::NANORIX_GENESIS_HASH.to_string();
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
        for (i, subsystem) in subsystems.iter().enumerate() {
            let method = crate::lookup_method(subsystem);
            let chain_hash = if i == 7 {
                let base =
                    crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
                let mut data = Vec::new();
                data.extend_from_slice(base.as_bytes());
                data.push(0x00);
                data.extend_from_slice(merkle_root.as_bytes());
                hex::encode(Sha512::digest(&data))
            } else {
                crate::compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp)
            };
            chain.push(serde_json::json!({
                "subsystem": subsystem,
                "method": method,
                "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }
        let final_hash = prev_hash;

        let seed = [9u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(final_hash.as_bytes());

        let proof = serde_json::json!({
            "cdp_version": "2.0",
            "capsule_id": capsule_id,
            "destroyed_at": timestamp,
            "chain": chain,
            "record_receipts": [
                {
                    "record_index": 0,
                    "record_id": "rec_tagged",
                    "record_input_hash": "sha512:in",
                    "record_output_hash": "sha512:out",
                    "record_chain_hash": format!("sha512:{}", receipt_chain),
                    "pattern_tag": "rcm_claim",
                    "merkle_inclusion_proof": [],
                },
            ],
            "record_receipts_merkle_root": format!("sha512:{}", merkle_root),
            "attestation": {
                "key_id": "k-tagged",
                "verification_key": base64::engine::general_purpose::STANDARD
                    .encode(signing_key.verifying_key().to_bytes()),
                "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            },
        });

        let bundle = extract_receipt_bundle(&proof, 0).unwrap();
        verify_receipt_bundle(&bundle).expect("tagged bundle verifies with tag bound");

        // Tampering the tag breaks the signed binding.
        let mut tampered = bundle.clone();
        tampered.receipt["pattern_tag"] = serde_json::Value::String("annotation".to_string());
        let err = verify_receipt_bundle(&tampered).unwrap_err();
        assert!(matches!(err, BundleError::RecordChainHashMismatch { .. }));
    }
}
