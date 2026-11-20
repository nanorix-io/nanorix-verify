"""
Portable Receipt Bundle (.prb.json) — Python port.

Pure Python port of ``tools/nanorix-verify/src/bundle.rs``. Cross-impl
byte-equivalence with Rust/Go/TypeScript on the canonical reference vectors.

Per the rule that a signed record's fields are not widened beyond what happened: this is a
JSON convention + JSON Schema + SDK helper — NOT a new file format with MIME
registration / OS-level associations.

Per the rule that the signed record states what happened and the
customer's auditor decides what it means: bundle disclaimer cites; never
asserts compliance. The verdict words in
``nanorix.grc.FORBIDDEN_VOCAB`` never appear in the disclaimer text.

Verification flow:

1. Extract bundle from a full AuditProof via ``extract_receipt_bundle``,
   selecting the receipt at ``record_index``.
2. Ship bundle to consumer (auditor archive, GRC tool, regulator handoff).
3. Consumer verifies bundle via ``verify_receipt_bundle``:
   - Recompute receipt's record_chain_hash from its fields.
   - Verify Merkle inclusion proof binds receipt to outer
     record_receipts_merkle_root.
   - Recompute Steps 1-7 from genesis at ``audit_proof_anchors.timestamp``
     over the canonical (subsystem, method) table, then the amended Step 8
     with record_receipts_merkle_root (and parent_proofs_merkle_root when the
     bundle carries one), and require equality with ``step_8_chain_hash``.
   - Verify the outer Ed25519 signature using verification_key over the
     ASCII-hex bytes of the anchor named by ``signature_target``:
     ``step8_chain_hash`` (legacy default) or ``document_canonical_hash``.

For the legacy target the signature covers the recomputed Step 8 hash, so a
successful verification means the receipt is bound to the signed value. For
the ``document_canonical_hash`` target the signed value commits to the whole
source AuditProof, which the bundle does not carry: the signature can be
authentic while the receipt is not bound. ``verify_receipt_bundle`` raises
``receipt_not_bound`` in that case and ``verify_receipt_bundle_detailed``
reports ``signature_authentic=True, receipt_bound=False``.
"""
from __future__ import annotations

import base64
import datetime
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ._ed25519_strict import verify_strict

from nanorix.verifier.wave_n import (
    GENESIS_SHA512_HEX,
    _CANONICAL_METHODS,
    _CANONICAL_SUBSYSTEMS,
    _compute_step_hash,
    compute_activity_root,
    compute_record_chain_hash,
    compute_step_8_amended,
    verify_merkle_inclusion_proof,
)

# ``signature_target`` values: which anchor the outer Ed25519 signature
# covers. An absent ``signature_target`` means the legacy target.
SIGNATURE_TARGET_STEP8_CHAIN_HASH = "step8_chain_hash"
SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH = "document_canonical_hash"

# Mandatory bundle disclaimer — factual language only, no compliance verdicts.
# The verdict words in nanorix.grc.FORBIDDEN_VOCAB never appear in this text.
PORTABLE_RECEIPT_BUNDLE_DISCLAIMER = (
    "This Portable Receipt Bundle carries cryptographic evidence of one "
    "record's structural execution. Verifying party uses the audit_proof_anchors "
    "to verify the receipt's merkle inclusion + outer Ed25519 signature. "
    "Control framework references are NOT included in this bundle; consult "
    "the mapping artifact at "
    "https://nanorix.io/v1/control-map?framework_version={framework_version} to apply current "
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
    # Which anchor the outer signature covers. None = legacy
    # ``step8_chain_hash`` (bundles from v1.0/v2.0 proofs predate the field).
    signature_target: Optional[str] = None
    # Document canonical hash (bare lowercase hex): the signed message when
    # ``signature_target`` is ``document_canonical_hash``.
    document_canonical_hash: Optional[str] = None
    # Parent-proofs Merkle root (``sha512:``-prefixed). Present only when the
    # source proof has parent links; Step 8 commits to it.
    parent_proofs_merkle_root: Optional[str] = None


@dataclass(frozen=True)
class BundleVerification:
    """Outcome of ``verify_receipt_bundle_detailed``.

    ``signature_authentic``: the outer Ed25519 signature verifies over the
    anchor named by ``signature_target``.
    ``receipt_bound``: the bundle alone ties the receipt to the signed value.
    True for the legacy target; False for ``document_canonical_hash``, whose
    signed value commits to a document the bundle does not carry.
    """

    signature_authentic: bool
    receipt_bound: bool
    signature_target: str

    @property
    def valid(self) -> bool:
        """True when the signature is authentic and the receipt is bound.

        Integrity only: the signature is checked against the key the bundle
        carries, so ``True`` never says who signed. ``status`` says so.
        """
        return self.signature_authentic and self.receipt_bound

    @property
    def status(self) -> str:
        """``"not_anchored"`` when ``valid``, otherwise ``"not_verified"``.

        Never ``"verified"``: no key list is read, so the signing key is only
        the one the bundle carries.
        """
        return "not_anchored" if self.valid else "not_verified"


@dataclass
class PortableReceiptBundle:
    """Wire shape mirroring Rust ``PortableReceiptBundle``.

    Forever-Standard: ``bundle_version`` is append-only; the V1.0
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
        anchors_out = out["audit_proof_anchors"]
        if self.audit_proof_anchors.framework_version_at_emit is not None:
            anchors_out["framework_version_at_emit"] = (
                self.audit_proof_anchors.framework_version_at_emit
            )
        if self.audit_proof_anchors.signature_target is not None:
            anchors_out["signature_target"] = self.audit_proof_anchors.signature_target
        if self.audit_proof_anchors.document_canonical_hash is not None:
            anchors_out["document_canonical_hash"] = (
                self.audit_proof_anchors.document_canonical_hash
            )
        if self.audit_proof_anchors.parent_proofs_merkle_root is not None:
            anchors_out["parent_proofs_merkle_root"] = (
                self.audit_proof_anchors.parent_proofs_merkle_root
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
            signature_target=_optional_str(anchors_raw, "signature_target"),
            document_canonical_hash=_optional_str(anchors_raw, "document_canonical_hash"),
            parent_proofs_merkle_root=_optional_str(
                anchors_raw, "parent_proofs_merkle_root"
            ),
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


_SHA512_LOWERCASE_HEX = re.compile(r"[0-9a-f]{128}")

# Error kinds — match Rust BundleError variants for cross-impl diffability.
BUNDLE_ERR_NO_RECEIPTS = "no_receipts"
BUNDLE_ERR_INDEX_OUT_OF_BOUNDS = "index_out_of_bounds"
BUNDLE_ERR_MISSING_FIELD = "missing_field"
BUNDLE_ERR_RECORD_CHAIN_HASH_MISMATCH = "record_chain_hash_mismatch"
BUNDLE_ERR_MERKLE_INCLUSION_FAILED = "merkle_inclusion_failed"
BUNDLE_ERR_SIGNATURE_FAILED = "signature_failed"
BUNDLE_ERR_BASE64_DECODE = "base64_decode"
BUNDLE_ERR_SHAPE = "shape"
# The Merkle root the bundle carries is not the one the signed Step 8 hash
# commits to.
BUNDLE_ERR_STEP_8_MISMATCH = "step_8_mismatch"
BUNDLE_ERR_MISSING_CANONICAL_HASH_ANCHOR = "missing_canonical_hash_anchor"
BUNDLE_ERR_MALFORMED_CANONICAL_HASH_ANCHOR = "malformed_canonical_hash_anchor"
BUNDLE_ERR_UNKNOWN_SIGNATURE_TARGET = "unknown_signature_target"
# Raised by ``verify_receipt_bundle`` when the signature is authentic but the
# bundle alone cannot bind the receipt to the signed value.
BUNDLE_ERR_RECEIPT_NOT_BOUND = "receipt_not_bound"


def _optional_str(raw: Mapping[str, Any], key: str) -> Optional[str]:
    value = raw.get(key)
    return None if value is None else str(value)


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
        BundleError: With kind ``no_receipts`` if AuditProof is legacy;
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

    parent_root = audit_proof.get("parent_proofs_merkle_root")
    if not isinstance(parent_root, str):
        parent_root = None

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
            parent_proofs_merkle_root=parent_root,
        ),
        disclaimer=PORTABLE_RECEIPT_BUNDLE_DISCLAIMER,
    )


def _recompute_step_8(
    timestamp: str, record_receipts_merkle_root: str, parent_proofs_merkle_root: Optional[str]
) -> str:
    """Rebuild the amended Step 8 hash from genesis.

    Walks Steps 1-7 over the canonical (subsystem, method) table at
    ``timestamp``, then applies the Step 8 amendment with the receipts root
    and the optional parent-proofs root.
    """
    prev = GENESIS_SHA512_HEX
    for subsystem in _CANONICAL_SUBSYSTEMS[:7]:
        prev = _compute_step_hash(
            prev, subsystem, "destroy", _CANONICAL_METHODS[subsystem], timestamp
        )
    return compute_step_8_amended(
        prev, timestamp, record_receipts_merkle_root, parent_proofs_merkle_root
    )


def _parse_record_index(raw: Any) -> int:
    """Accept only a real integer (not a bool, float or string)."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise BundleError(BUNDLE_ERR_SHAPE, "receipt.record_index is not an integer")
    if raw < 0 or raw > 0xFFFFFFFF:
        raise BundleError(BUNDLE_ERR_SHAPE, "receipt.record_index out of range")
    return int(raw)


def verify_receipt_bundle_detailed(bundle: PortableReceiptBundle) -> BundleVerification:
    """Verify a Portable Receipt Bundle (Mode B standalone) and report both
    whether the signature is authentic and whether the receipt is bound.

    Steps:
        1. Recompute receipt's record_chain_hash from its fields.
        2. Verify Merkle inclusion proof binds receipt to record_receipts_merkle_root.
        3. Recompute Steps 1-7 from genesis at the bundle timestamp, then the
           amended Step 8 with record_receipts_merkle_root (and
           parent_proofs_merkle_root when present); require equality with
           step_8_chain_hash.
        4. Verify the outer Ed25519 signature over the ASCII-hex bytes of the
           anchor named by signature_target, using verification_key.

    Returns:
        ``BundleVerification``. For the legacy target ``receipt_bound`` is True
        (the signed Step 8 hash was recomputed from the bundled root). For the
        ``document_canonical_hash`` target it is False: the signed value
        commits to a document the bundle does not carry.

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
    record_index = _parse_record_index(record_index_raw)
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

    # Declared pattern_tag is a signed primitive — it binds into
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

    # (3) Step 8 recompute. The bundle does not carry the 8-step chain, but
    # every step hashes the same timestamp over the canonical (subsystem,
    # method) table, so Steps 1-7 are derivable. Requiring the amended Step 8
    # to equal step_8_chain_hash ties the bundled Merkle root (and the
    # parent-proofs root, when present) to the Step 8 value. Runs for every
    # signature_target.
    step_8 = _recompute_step_8(
        anchors.timestamp,
        anchors.record_receipts_merkle_root,
        anchors.parent_proofs_merkle_root,
    )
    if step_8 != _strip_sha512_prefix(anchors.step_8_chain_hash):
        raise BundleError(
            BUNDLE_ERR_STEP_8_MISMATCH,
            f"claimed={anchors.step_8_chain_hash} recomputed={step_8}",
        )

    # (4) Outer Ed25519 signature over the ASCII-hex bytes of the anchor
    # named by signature_target.
    target = anchors.signature_target
    if target is None or target == SIGNATURE_TARGET_STEP8_CHAIN_HASH:
        signed_message = _strip_sha512_prefix(anchors.step_8_chain_hash)
        receipt_bound = True
        effective_target = SIGNATURE_TARGET_STEP8_CHAIN_HASH
    elif target == SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH:
        if not anchors.document_canonical_hash:
            raise BundleError(
                BUNDLE_ERR_MISSING_CANONICAL_HASH_ANCHOR,
                "signature_target=document_canonical_hash but no document_canonical_hash value",
            )
        signed_message = _strip_sha512_prefix(anchors.document_canonical_hash)
        # The same key signs other message shapes, such as a population head,
        # so a signature over anything but a bare hash proves nothing here.
        if not _SHA512_LOWERCASE_HEX.fullmatch(signed_message):
            raise BundleError(
                BUNDLE_ERR_MALFORMED_CANONICAL_HASH_ANCHOR,
                "document_canonical_hash is not 128 lowercase hex characters after its sha512: prefix",
            )
        # The canonical hash commits to the whole source document, which the
        # bundle does not carry, so the bundle alone cannot bind the receipt.
        receipt_bound = False
        effective_target = SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH
    else:
        raise BundleError(BUNDLE_ERR_UNKNOWN_SIGNATURE_TARGET, target)

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

    try:
        verify_strict(pub_key, sig_bytes, signed_message.encode("ascii"))
    except InvalidSignature as e:
        raise BundleError(BUNDLE_ERR_SIGNATURE_FAILED, "Ed25519 verify failed") from e

    return BundleVerification(
        signature_authentic=True,
        receipt_bound=receipt_bound,
        signature_target=effective_target,
    )


def verify_receipt_bundle(bundle: PortableReceiptBundle) -> None:
    """Verify a Portable Receipt Bundle; return only when the receipt is bound.

    Runs ``verify_receipt_bundle_detailed``. A bundle whose signature is
    authentic but whose receipt the bundle alone cannot bind (the
    ``document_canonical_hash`` target) raises ``BundleError`` with kind
    ``receipt_not_bound`` instead of returning, so a caller that treats a
    normal return as "verified" is never told so for an unbound receipt.
    Use ``verify_receipt_bundle_detailed`` to read the distinction.

    A normal return is integrity only: the signature is checked against the
    key the bundle carries, so it never says who signed (the detailed result
    for the same bundle has ``status`` ``"not_anchored"``).

    Raises:
        BundleError: On verification failure with kind discriminator + reason.
    """
    result = verify_receipt_bundle_detailed(bundle)
    if not result.receipt_bound:
        raise BundleError(
            BUNDLE_ERR_RECEIPT_NOT_BOUND,
            "signature is authentic over the document canonical hash, but the bundle "
            "alone cannot bind the receipt to that signed document; verify the source "
            "AuditProof",
        )


__all__ = [
    "PORTABLE_RECEIPT_BUNDLE_DISCLAIMER",
    "AuditProofAnchors",
    "BundleError",
    "BundleVerification",
    "PortableReceiptBundle",
    "SIGNATURE_TARGET_STEP8_CHAIN_HASH",
    "SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH",
    "BUNDLE_ERR_NO_RECEIPTS",
    "BUNDLE_ERR_INDEX_OUT_OF_BOUNDS",
    "BUNDLE_ERR_MISSING_FIELD",
    "BUNDLE_ERR_RECORD_CHAIN_HASH_MISMATCH",
    "BUNDLE_ERR_MERKLE_INCLUSION_FAILED",
    "BUNDLE_ERR_SIGNATURE_FAILED",
    "BUNDLE_ERR_BASE64_DECODE",
    "BUNDLE_ERR_SHAPE",
    "BUNDLE_ERR_STEP_8_MISMATCH",
    "BUNDLE_ERR_MISSING_CANONICAL_HASH_ANCHOR",
    "BUNDLE_ERR_UNKNOWN_SIGNATURE_TARGET",
    "BUNDLE_ERR_RECEIPT_NOT_BOUND",
    "extract_receipt_bundle",
    "verify_receipt_bundle",
    "verify_receipt_bundle_detailed",
]
