"""
Portable Receipt Bundle (.prb.json) — Wave B Item 7 surface, Python port.

Pure Python port of ``tools/nanorix-verify/src/bundle.rs``. Cross-impl
byte-equivalence with Rust/Go/TypeScript on the canonical reference vectors.

Per feedback_narrowness_is_the_moat_resist_receipt_enrichment.md: this is a
JSON convention + JSON Schema + SDK helper — NOT a new file format with MIME
registration / OS-level associations.

Per feedback_narrow_signed_claim_auditor_certifies.md: bundle disclaimer
cites; never asserts compliance. Vocabulary discipline forbids
COMPLIANT/SATISFIED/PASSED/MEETS in the disclaimer text.

Verification flow:

1. Extract bundle from a full AuditProof via ``extract_receipt_bundle``,
   selecting the receipt at ``record_index``.
2. Ship bundle to consumer (auditor archive, GRC tool, regulator handoff).
3. Consumer verifies bundle via ``verify_receipt_bundle``:
   - Recompute receipt's record_chain_hash from its fields.
   - Verify Merkle inclusion proof binds receipt to outer
     record_receipts_merkle_root.
   - Verify outer Ed25519 signature over step_8_chain_hash ASCII-hex using
     verification_key.
"""
from __future__ import annotations

import base64
import datetime
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nanorix.verifier.wave_n import (
    GENESIS_SHA512_HEX,
    compute_activity_root,
    compute_record_chain_hash,
    verify_merkle_inclusion_proof,
)

# Mandatory bundle disclaimer — factual language only, no compliance verdicts.
# Vocabulary discipline forbids COMPLIANT/SATISFIED/PASSED/MEETS.
PORTABLE_RECEIPT_BUNDLE_DISCLAIMER = (
    "This Portable Receipt Bundle carries cryptographic evidence of one "
    "record's structural execution. Verifying party uses the audit_proof_anchors "
    "to verify the receipt's merkle inclusion + outer Ed25519 signature. "
    "Control framework references are NOT included in this bundle; consult "
    "the ADR-040 mapping artifact at "
    "schema.nanorix.com/control-map/{framework_version}.json to apply current "
    "control mappings at consumption time."
)


@dataclass
class AuditProofAnchors:
    """Minimal outer-AuditProof anchors carried in a Portable Receipt Bundle."""

    capsule_id: str
    key_id: str
    verification_key: str
    step_8_chain_hash: str
    signature: str
    record_receipts_merkle_root: str
    timestamp: str
    framework_version_at_emit: Optional[str] = None


@dataclass
class PortableReceiptBundle:
    """Wave B Item 7 wire shape mirroring Rust ``PortableReceiptBundle``.

    Forever-Standard ADR-006 I0: ``bundle_version`` is append-only; the V1.0
    shape remains valid forever.
    """

    bundle_version: str
    bundle_type: str
    generated_at: str
    receipt: Dict[str, Any]
    audit_proof_anchors: AuditProofAnchors
    disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "bundle_version": self.bundle_version,
            "bundle_type": self.bundle_type,
            "generated_at": self.generated_at,
            "receipt": self.receipt,
            "audit_proof_anchors": {
                "capsule_id": self.audit_proof_anchors.capsule_id,
                "key_id": self.audit_proof_anchors.key_id,
                "verification_key": self.audit_proof_anchors.verification_key,
                "step_8_chain_hash": self.audit_proof_anchors.step_8_chain_hash,
                "signature": self.audit_proof_anchors.signature,
                "record_receipts_merkle_root": (
                    self.audit_proof_anchors.record_receipts_merkle_root
                ),
                "timestamp": self.audit_proof_anchors.timestamp,
            },
            "disclaimer": self.disclaimer,
        }
        if self.audit_proof_anchors.framework_version_at_emit is not None:
            out["audit_proof_anchors"]["framework_version_at_emit"] = (
                self.audit_proof_anchors.framework_version_at_emit
            )
        return out

    def to_json(self, *, pretty: bool = False) -> str:
        if pretty:
            return json.dumps(self.to_dict(), indent=2)
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> "PortableReceiptBundle":
        anchors_raw = doc.get("audit_proof_anchors", {}) or {}
        anchors = AuditProofAnchors(
            capsule_id=str(anchors_raw.get("capsule_id", "")),
            key_id=str(anchors_raw.get("key_id", "")),
            verification_key=str(anchors_raw.get("verification_key", "")),
            step_8_chain_hash=str(anchors_raw.get("step_8_chain_hash", "")),
            signature=str(anchors_raw.get("signature", "")),
            record_receipts_merkle_root=str(
                anchors_raw.get("record_receipts_merkle_root", "")
            ),
            timestamp=str(anchors_raw.get("timestamp", "")),
            framework_version_at_emit=anchors_raw.get("framework_version_at_emit"),
        )
        return cls(
            bundle_version=str(doc.get("bundle_version", "")),
            bundle_type=str(doc.get("bundle_type", "")),
            generated_at=str(doc.get("generated_at", "")),
            receipt=dict(doc.get("receipt", {}) or {}),
            audit_proof_anchors=anchors,
            disclaimer=str(doc.get("disclaimer", "")),
        )


class BundleError(Exception):
    """Bundle extraction / verification error.

    Attributes:
        kind: Error discriminator matching Rust BundleError variants.
        reason: Detail string.
    """

    def __init__(self, kind: str, reason: str = "") -> None:
        self.kind = kind
        self.reason = reason
        super().__init__(f"[{kind}] {reason}" if reason else kind)


# Error kinds — match Rust BundleError variants for cross-impl diffability.
BUNDLE_ERR_NO_RECEIPTS = "no_receipts"
BUNDLE_ERR_INDEX_OUT_OF_BOUNDS = "index_out_of_bounds"
BUNDLE_ERR_MISSING_FIELD = "missing_field"
BUNDLE_ERR_RECORD_CHAIN_HASH_MISMATCH = "record_chain_hash_mismatch"
BUNDLE_ERR_MERKLE_INCLUSION_FAILED = "merkle_inclusion_failed"
BUNDLE_ERR_SIGNATURE_FAILED = "signature_failed"
BUNDLE_ERR_BASE64_DECODE = "base64_decode"
BUNDLE_ERR_SHAPE = "shape"


def _strip_base64_prefix(s: str) -> str:
    if isinstance(s, str) and s.startswith("base64:"):
        return s[len("base64:"):]
    return s


def _strip_sha512_prefix(s: str) -> str:
    if isinstance(s, str) and s.startswith("sha512:"):
        return s[len("sha512:"):]
    return s


def _now_iso8601() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_receipt_bundle(
    audit_proof: Mapping[str, Any], record_index: int
) -> PortableReceiptBundle:
    """Extract a single receipt + outer anchors into a Portable Receipt Bundle.

    Args:
        audit_proof: The full FullCdp/VerificationCdp JSON dict.
        record_index: Zero-indexed position within ``record_receipts``.

    Returns:
        A populated ``PortableReceiptBundle``.

    Raises:
        BundleError: With kind ``no_receipts`` if AuditProof is pre-Wave-N;
            ``index_out_of_bounds`` if index outside receipt set;
            ``missing_field`` if a required outer field is absent.
    """
    receipts = audit_proof.get("record_receipts")
    if not isinstance(receipts, list):
        raise BundleError(BUNDLE_ERR_NO_RECEIPTS, "AuditProof has no record_receipts field")
    if record_index >= len(receipts):
        raise BundleError(
            BUNDLE_ERR_INDEX_OUT_OF_BOUNDS,
            f"index {record_index} out of bounds; {len(receipts)} receipts",
        )

    receipt = dict(receipts[record_index])

    capsule_id = audit_proof.get("capsule_id")
    if not isinstance(capsule_id, str):
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "capsule_id")
    timestamp = audit_proof.get("destroyed_at")
    if not isinstance(timestamp, str):
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "destroyed_at")

    attestation = audit_proof.get("attestation") or {}
    key_id = attestation.get("key_id") or audit_proof.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "attestation.key_id")

    verification_key = (
        attestation.get("verification_key")
        or attestation.get("public_key")
        or audit_proof.get("verification_key")
    )
    if not isinstance(verification_key, str) or not verification_key:
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "attestation.verification_key")

    signature = attestation.get("signature") or audit_proof.get("signature")
    if not isinstance(signature, str) or not signature:
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "attestation.signature")

    merkle_root = audit_proof.get("record_receipts_merkle_root")
    if not isinstance(merkle_root, str):
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "record_receipts_merkle_root")

    chain = audit_proof.get("chain")
    if not isinstance(chain, list) or not chain:
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "chain")
    last_step = chain[-1]
    if not isinstance(last_step, dict):
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "chain[last]")
    step_8_chain_hash = last_step.get("chain_hash")
    if not isinstance(step_8_chain_hash, str):
        raise BundleError(BUNDLE_ERR_MISSING_FIELD, "chain[last].chain_hash")

    fvae = None
    rc = audit_proof.get("regulatory_context")
    if isinstance(rc, dict):
        fv = rc.get("framework_version")
        if isinstance(fv, str):
            fvae = fv

    return PortableReceiptBundle(
        bundle_version="1.0",
        bundle_type="receipt",
        generated_at=_now_iso8601(),
        receipt=receipt,
        audit_proof_anchors=AuditProofAnchors(
            capsule_id=capsule_id,
            key_id=key_id,
            verification_key=verification_key,
            step_8_chain_hash=step_8_chain_hash,
            signature=signature,
            record_receipts_merkle_root=merkle_root,
            timestamp=timestamp,
            framework_version_at_emit=fvae,
        ),
        disclaimer=PORTABLE_RECEIPT_BUNDLE_DISCLAIMER,
    )


def verify_receipt_bundle(bundle: PortableReceiptBundle) -> None:
    """Verify a Portable Receipt Bundle (Mode B standalone).

    Steps:
        1. Recompute receipt's record_chain_hash from its fields.
        2. Verify Merkle inclusion proof binds receipt to record_receipts_merkle_root.
        3. Verify outer Ed25519 signature over step_8_chain_hash ASCII-hex using
           verification_key.

    Raises:
        BundleError: On verification failure with kind discriminator + reason.
    """
    if bundle.bundle_version != "1.0":
        raise BundleError(BUNDLE_ERR_SHAPE, f"unsupported bundle_version: {bundle.bundle_version}")
    if bundle.bundle_type != "receipt":
        raise BundleError(
            BUNDLE_ERR_SHAPE,
            f"wrong bundle_type for Portable Receipt Bundle: {bundle.bundle_type}",
        )

    anchors = bundle.audit_proof_anchors

    # (1) Recompute record_chain_hash.
    record_index_raw = bundle.receipt.get("record_index")
    if record_index_raw is None:
        raise BundleError(BUNDLE_ERR_SHAPE, "receipt.record_index missing")
    record_index = int(record_index_raw)
    record_id = bundle.receipt.get("record_id")
    if not isinstance(record_id, str):
        raise BundleError(BUNDLE_ERR_SHAPE, "receipt.record_id missing")
    in_h = str(bundle.receipt.get("record_input_hash", ""))
    out_h = str(bundle.receipt.get("record_output_hash", ""))
    claimed_chain_hash = bundle.receipt.get("record_chain_hash")
    if not isinstance(claimed_chain_hash, str):
        raise BundleError(BUNDLE_ERR_SHAPE, "receipt.record_chain_hash missing")

    trail = bundle.receipt.get("record_activity_trail")
    if isinstance(trail, list) and trail:
        activity_root = compute_activity_root(trail)
    else:
        activity_root = GENESIS_SHA512_HEX

    # Declared pattern_tag is a signed primitive (ADR-039) — it binds into
    # the chain hash. Wire form = the receipt JSON "pattern_tag" string;
    # enum wire forms are never empty, so "" is treated as undeclared.
    tag_raw = bundle.receipt.get("pattern_tag")
    pattern_tag = tag_raw if isinstance(tag_raw, str) and tag_raw else None

    recomputed = compute_record_chain_hash(
        anchors.capsule_id,
        record_index,
        record_id,
        in_h,
        out_h,
        activity_root,
        pattern_tag_wire=pattern_tag,
    )
    if _strip_sha512_prefix(recomputed) != _strip_sha512_prefix(claimed_chain_hash):
        raise BundleError(
            BUNDLE_ERR_RECORD_CHAIN_HASH_MISMATCH,
            f"claimed={claimed_chain_hash} recomputed={recomputed}",
        )

    # (2) Merkle inclusion proof.
    inclusion = bundle.receipt.get("merkle_inclusion_proof") or []
    if not isinstance(inclusion, list):
        inclusion = []
    if not verify_merkle_inclusion_proof(
        claimed_chain_hash,
        record_index,
        [str(s) for s in inclusion],
        anchors.record_receipts_merkle_root,
    ):
        raise BundleError(
            BUNDLE_ERR_MERKLE_INCLUSION_FAILED, anchors.record_receipts_merkle_root
        )

    # (3) Outer Ed25519 signature over step_8_chain_hash ASCII-hex.
    #
    # The bundle does NOT carry the full 8-step chain (would defeat
    # portability). The Ed25519 signature transitively binds chain + receipt
    # set integrity via the producer's outer authority. For full chain re-
    # verification, the consumer uses the original AuditProof.
    try:
        sig_bytes = base64.b64decode(_strip_base64_prefix(anchors.signature))
    except (ValueError, TypeError) as e:
        raise BundleError(BUNDLE_ERR_BASE64_DECODE, f"audit_proof_anchors.signature: {e}") from e
    if len(sig_bytes) != 64:
        raise BundleError(BUNDLE_ERR_SIGNATURE_FAILED, f"signature wrong size: {len(sig_bytes)}")
    try:
        pub_bytes = base64.b64decode(_strip_base64_prefix(anchors.verification_key))
    except (ValueError, TypeError) as e:
        raise BundleError(
            BUNDLE_ERR_BASE64_DECODE, f"audit_proof_anchors.verification_key: {e}"
        ) from e
    if len(pub_bytes) != 32:
        raise BundleError(
            BUNDLE_ERR_SIGNATURE_FAILED, f"verification_key wrong size: {len(pub_bytes)}"
        )

    try:
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except (ValueError, TypeError) as e:
        raise BundleError(BUNDLE_ERR_SIGNATURE_FAILED, f"invalid pubkey: {e}") from e

    chain_hash_ascii = _strip_sha512_prefix(anchors.step_8_chain_hash).encode("ascii")
    try:
        pub_key.verify(sig_bytes, chain_hash_ascii)
    except InvalidSignature as e:
        raise BundleError(BUNDLE_ERR_SIGNATURE_FAILED, "Ed25519 verify failed") from e


__all__ = [
    "PORTABLE_RECEIPT_BUNDLE_DISCLAIMER",
    "AuditProofAnchors",
    "BundleError",
    "PortableReceiptBundle",
    "BUNDLE_ERR_NO_RECEIPTS",
    "BUNDLE_ERR_INDEX_OUT_OF_BOUNDS",
    "BUNDLE_ERR_MISSING_FIELD",
    "BUNDLE_ERR_RECORD_CHAIN_HASH_MISMATCH",
    "BUNDLE_ERR_MERKLE_INCLUSION_FAILED",
    "BUNDLE_ERR_SIGNATURE_FAILED",
    "BUNDLE_ERR_BASE64_DECODE",
    "BUNDLE_ERR_SHAPE",
    "extract_receipt_bundle",
    "verify_receipt_bundle",
]
