"""
The AuditProof verification stage ladder — the single Python implementation.

Python mirror of `tools/nanorix-verify/src/lib.rs::verify_auditproof`, which is
the reference verifier and the spec. Agreement is enforced against the 100
pinned documents in `tools/nanorix-verify/fixtures/corpus/`, which are the
public cross-implementation contract; a disagreement with the corpus is a
defect in this file, never in the corpus.

Stage ladder:

| Stage | Check |
|---|---|
| 1 | `cdp_version` present |
| 2 | `cdp_version` recognised; authority-id pin; region pin |
| 3 | chain present, 8 steps, every step hash reproduces; the receipt pipeline receipt + parent sets |
| 4 | `final_hash` binds to the last step's `chain_hash` |
| 5–7 | Ed25519 signature over the version-appropriate message, against the embedded key |

Stage 8 (anchoring the key to a signed trust-chain manifest, trust-chain anchoring) needs
an operator-supplied manifest and is not implemented here; a proof whose
embedded-key signature verifies tops out at the honest stage 7 — integrity
proven, authenticity not established.

## The chain hash formula (Forever-Standard, the Forever-Standard wire discipline)

    chain_hash[n] = SHA-512(prev || 0x00 || subsystem || 0x00 || "destroy"
                            || 0x00 || method || 0x00 || timestamp)

`method` is a FIXED per-step canonical constant looked up from the subsystem
name — it is NOT the serialized `operation` field and NOT a per-step JSON
field. `timestamp` is the document's `destroyed_at` (or the value recovered
from `attestation.key_id` per the chain-timestamp recovery rule), the same value for every step.
Production `CdpChainStep` carries only `step`, `subsystem`, `operation`,
`evidence_hash`, and `chain_hash`; a verifier that reads per-step `method` or
`timestamp` fields reproduces nothing on a real proof.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Union

from nanorix.verifier import _canonical
from nanorix.verifier._canonical import (
    SUPPORTED_CDP_VERSIONS,
    SignatureOutcome,
    strip_hash_prefix,
)
from nanorix.verifier.wave_n import (
    compute_activity_root,
    compute_record_chain_hash,
    compute_step_8_amended,
    merkle_root_sha512_null_separated,
)

# Canonical genesis hash — SHA-512("") (Forever-Standard, the Forever-Standard wire discipline)
GENESIS_HASH = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)

# Canonical method strings per subsystem (Forever-Standard, the Forever-Standard wire discipline).
METHOD_MAP: Dict[str, str] = {
    "eee_namespace": "procfs_verification",
    "eee_tmpfs": "mountinfo_verification",
    "eee_memory": "dod_5220_multipass_wipe",
    "dire_keys": "ed25519_key_destruction",
    "dire_identity": "credential_incineration",
    "fgx_forensic": "merkle_tree_verification",
    "rzl_audit": "hash_chain_validation",
    "capsule_destroy": "capsule_lifecycle_verification",
}

# Canonical 8-step subsystem order (must match CHAIN_DEFS in cdp.rs).
CANONICAL_SUBSYSTEMS = [
    "eee_namespace",
    "eee_tmpfs",
    "eee_memory",
    "dire_keys",
    "dire_identity",
    "fgx_forensic",
    "rzl_audit",
    "capsule_destroy",
]

CHAIN_STEP_COUNT = 8


class FailureReasonType:
    """Closed-set wire-form discriminators (Forever-Standard, the Forever-Standard wire discipline).

    New variants ADDITIVE ONLY. Existing variants never renamed/removed.
    """

    ALGORITHM_UNSUPPORTED = "algorithm_unsupported"
    AUTHORITY_ID_MISMATCH = "authority_id_mismatch"
    AUTHORITY_MODE_MISMATCH = "authority_mode_mismatch"
    AUTHORITY_REVOKED = "authority_revoked"
    CDP_VERSION_UNSUPPORTED = "cdp_version_unsupported"
    DIAGNOSTIC_PROOF_REFUSED = "diagnostic_proof_refused"
    FINAL_HASH_MISMATCH = "final_hash_mismatch"
    GENESIS_HASH_MISMATCH = "genesis_hash_mismatch"
    REGION_MISMATCH = "region_mismatch"
    REQUIRED_FIELD_MISSING = "required_field_missing"
    RESERVED = "reserved"
    SIGNATURE_MISMATCH = "signature_mismatch"
    SIGNING_KEY_VERSION_UNKNOWN = "signing_key_version_unknown"
    STEP_COUNT_INVALID = "step_count_invalid"
    STEP_HASH_MISMATCH = "step_hash_mismatch"


@dataclass
class FailureReason:
    """Structured failure reason from the verifier pipeline.

    Wire form: ``{"type": "<snake_case>", ...payload}`` — matches the Rust/Go
    serde tag dispatch.
    """

    type: str

    # Per-variant payload fields (None when not applicable to this variant).
    # `found` is a string for the version variants and an integer for
    # step_count_invalid, matching the reference wire form in each case.
    found: Optional[Union[str, int]] = None
    field: Optional[str] = None  # required_field_missing
    expected: Optional[int] = None  # step_count_invalid
    step_idx: Optional[int] = None  # step_hash_mismatch
    subsystem: Optional[str] = None  # step_hash_mismatch
    claimed: Optional[str] = None  # final_hash_mismatch
    computed: Optional[str] = None  # final_hash_mismatch
    reason: Optional[str] = None  # signature_mismatch
    version: Optional[str] = None  # signing_key_version_unknown
    required: Optional[str] = None  # region_mismatch
    actual: Optional[str] = None  # region_mismatch
    claimed_authority_id: Optional[str] = None  # authority_id_mismatch
    expected_authority_id: Optional[str] = None  # authority_id_mismatch
    auth_id_reason: Optional[str] = None  # authority_id_mismatch (wire: "reason")

    def to_wire_dict(self) -> Dict[str, Any]:
        """Produce the wire-form dict the corpus `.expected.json` files pin."""
        t = self.type
        d: Dict[str, Any] = {"type": t}
        if t in (
            FailureReasonType.CDP_VERSION_UNSUPPORTED,
            FailureReasonType.ALGORITHM_UNSUPPORTED,
        ):
            if self.found is not None:
                d["found"] = self.found
        elif t == FailureReasonType.REQUIRED_FIELD_MISSING:
            if self.field is not None:
                d["field"] = self.field
        elif t == FailureReasonType.STEP_COUNT_INVALID:
            if self.expected is not None:
                d["expected"] = self.expected
            if self.found is not None:
                d["found"] = self.found
        elif t == FailureReasonType.STEP_HASH_MISMATCH:
            if self.step_idx is not None:
                d["step_idx"] = self.step_idx
            if self.subsystem is not None:
                d["subsystem"] = self.subsystem
        elif t == FailureReasonType.FINAL_HASH_MISMATCH:
            if self.claimed is not None:
                d["claimed"] = self.claimed
            if self.computed is not None:
                d["computed"] = self.computed
        elif t == FailureReasonType.SIGNATURE_MISMATCH:
            if self.reason is not None:
                d["reason"] = self.reason
        elif t == FailureReasonType.SIGNING_KEY_VERSION_UNKNOWN:
            if self.version is not None:
                d["version"] = self.version
        elif t == FailureReasonType.REGION_MISMATCH:
            if self.required is not None:
                d["required"] = self.required
            if self.actual is not None:
                d["actual"] = self.actual
        elif t == FailureReasonType.AUTHORITY_ID_MISMATCH:
            d["claimed_authority_id"] = self.claimed_authority_id
            if self.expected_authority_id is not None:
                d["expected_authority_id"] = self.expected_authority_id
            if self.auth_id_reason is not None:
                d["reason"] = self.auth_id_reason
        # No payload for: genesis_hash_mismatch, authority_revoked,
        #                 diagnostic_proof_refused, reserved
        return d


@dataclass
class VerificationMetadata:
    """Structural metadata extracted during verification (no payload bytes)."""

    cdp_version: Optional[str] = None
    capsule_id: Optional[str] = None
    region: Optional[str] = None
    signing_key_version: Optional[str] = None
    algorithm: Optional[str] = None
    step_count: Optional[int] = None
    activity_event_count: Optional[int] = None

    # Set only when the document carried no usable `destroyed_at` and the chain
    # timestamp was recovered from `attestation.key_id` (the chain-timestamp recovery rule). An auditor
    # can therefore always tell which route produced a verdict.
    recovered_chain_timestamp: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of AuditProof verification.

    ``valid`` + ``failure_reason`` + ``stage_reached`` are the cross-impl
    agreement surface compared against the fixture corpus and the Rust
    reference verifier.
    """

    valid: bool
    failure_reason: Optional[FailureReason]
    stage_reached: int
    metadata: VerificationMetadata = field(default_factory=VerificationMetadata)

    def to_wire_dict(self) -> Dict[str, Any]:
        """Produce the fixture-corpus wire form."""
        return {
            "valid": self.valid,
            "failure_reason": (
                self.failure_reason.to_wire_dict() if self.failure_reason is not None else None
            ),
        }


@dataclass
class VerifierPolicy:
    """Customer-side policy configuration for AuditProof verification.

    Field-additive per the Forever-Standard wire discipline + the customer-authority specification G7. Every field defaults to its
    "accept anything" semantics, so a default policy behaves identically to no
    policy at all.
    """

    reject_diagnostic: bool = False
    required_region: str = ""
    required_authority_id: str = ""


def _str_or_empty(v: Any) -> str:
    return v if isinstance(v, str) else ""


def compute_step_hash(
    prev_hash: str,
    subsystem: str,
    method: str,
    timestamp: str,
) -> str:
    """Reproduce one chain step's SHA-512 hash.

    Formula (Forever-Standard, the Forever-Standard wire discipline):
        SHA-512(prev_hash || 0x00 || subsystem || 0x00 ||
                "destroy"  || 0x00 || method    || 0x00 || timestamp)
    """
    parts = (
        prev_hash.encode()
        + b"\x00"
        + subsystem.encode()
        + b"\x00"
        + b"destroy"
        + b"\x00"
        + method.encode()
        + b"\x00"
        + timestamp.encode()
    )
    return hashlib.sha512(parts).hexdigest()


def lookup_method(subsystem: str) -> str:
    """Return the canonical method string for a subsystem. Forever-stable."""
    return METHOD_MAP.get(subsystem, "")


def _pointer_str(proof: Mapping[str, Any], parent: str, key: str) -> Optional[str]:
    """Read `proof[parent][key]` as a string, or None."""
    node = proof.get(parent)
    if isinstance(node, Mapping):
        value = node.get(key)
        if isinstance(value, str):
            return value
    return None


def _declared_non_ed25519_algorithm(proof: Mapping[str, Any]) -> Optional[str]:
    """The signature algorithm the proof declares, when it is not Ed25519.

    Reads ``attestation.algorithm`` and the top-level ``signature_algorithm``;
    either declaring anything other than the exact canonical string
    ``"Ed25519"`` makes the proof unverifiable by this build. Both absent is
    the pre-field era, which is Ed25519 by definition.
    """
    for value in (
        _pointer_str(proof, "attestation", "algorithm"),
        proof.get("signature_algorithm"),
    ):
        if isinstance(value, str) and value != "Ed25519":
            return value
    return None


def _verify_record_receipts(
    receipts: Sequence[Any],
    capsule_id: str,
    claimed_root: Optional[str],
) -> Optional[FailureReason]:
    """the per-record receipt specification Mode A step 3 — recompute each receipt's chain hash + the root.

    Returns None when there is nothing to check or everything reproduces.
    """
    if claimed_root is None:
        return None

    leaves = []
    for i, receipt in enumerate(receipts):
        if not isinstance(receipt, Mapping):
            return FailureReason(
                type=FailureReasonType.STEP_HASH_MISMATCH,
                step_idx=i,
                subsystem=f"record_receipt[{i}]",
            )
        raw_index = receipt.get("record_index")
        record_index = raw_index if isinstance(raw_index, int) and raw_index >= 0 else 0
        trail = receipt.get("record_activity_trail")
        activity_root = compute_activity_root(trail if isinstance(trail, list) else None)
        pattern_tag = receipt.get("pattern_tag")

        recomputed = strip_hash_prefix(
            compute_record_chain_hash(
                capsule_id,
                record_index,
                _str_or_empty(receipt.get("record_id")),
                _str_or_empty(receipt.get("record_input_hash")),
                _str_or_empty(receipt.get("record_output_hash")),
                activity_root,
                pattern_tag if isinstance(pattern_tag, str) else None,
            )
        )
        claimed_chain = strip_hash_prefix(_str_or_empty(receipt.get("record_chain_hash")))
        if recomputed != claimed_chain:
            return FailureReason(
                type=FailureReasonType.STEP_HASH_MISMATCH,
                step_idx=i,
                subsystem=f"record_receipt[{i}]",
            )
        leaves.append(recomputed)

    recomputed_root = merkle_root_sha512_null_separated(leaves) or ""
    if recomputed_root != strip_hash_prefix(claimed_root):
        return FailureReason(
            type=FailureReasonType.FINAL_HASH_MISMATCH,
            claimed=claimed_root,
            computed=f"sha512:{recomputed_root}",
        )
    return None


def _verify_parent_proofs(
    parents: Sequence[Any],
    claimed_root: Optional[str],
) -> Optional[FailureReason]:
    """the receipt-batching specification — recompute the parent-proof Merkle root and compare to claimed."""
    if claimed_root is None:
        return None

    leaves = [
        _str_or_empty(p.get("parent_chain_hash")) if isinstance(p, Mapping) else "" for p in parents
    ]
    recomputed = merkle_root_sha512_null_separated(leaves) or ""
    if recomputed != strip_hash_prefix(claimed_root):
        return FailureReason(
            type=FailureReasonType.FINAL_HASH_MISMATCH,
            claimed=claimed_root,
            computed=f"sha512:{recomputed}",
        )
    return None


def verify_auditproof(
    json_bytes: Union[bytes, str, Dict[str, Any]],
    policy: Optional[VerifierPolicy] = None,
) -> VerificationResult:
    """Verify an AuditProof through the stage ladder.

    Args:
        json_bytes: AuditProof as bytes, JSON string, or already-parsed dict.
        policy: Optional VerifierPolicy for the authority-id and region pins.

    Returns:
        VerificationResult whose ``valid`` / ``failure_reason`` /
        ``stage_reached`` agree with the Rust reference verifier on every
        document in the reference corpus.

    A proof whose signature this build cannot check — an unsigned partial, or a
    ``dual_signature`` / ``tee_attested`` v2.1 proof — returns ``valid=True`` at
    stage 4, which reads as "chain verified, signature NOT checked". That is
    the reference verifier's honest verdict, not a pass: callers that require
    cryptographic proof must check ``stage_reached >= 7``.
    """
    pol = policy or VerifierPolicy()
    meta = VerificationMetadata()

    # Stage 0: parse JSON
    if isinstance(json_bytes, dict):
        proof: Dict[str, Any] = json_bytes
    else:
        raw = (
            json_bytes if isinstance(json_bytes, (bytes, bytearray)) else json_bytes.encode("utf-8")
        )
        try:
            proof = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return VerificationResult(
                valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.REQUIRED_FIELD_MISSING,
                    field="json_root",
                ),
                stage_reached=1,
                metadata=meta,
            )
    if not isinstance(proof, dict):
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.REQUIRED_FIELD_MISSING,
                field="json_root",
            ),
            stage_reached=1,
            metadata=meta,
        )

    # Stage 1: schema — cdp_version present
    cdp_version = proof.get("cdp_version")
    if not isinstance(cdp_version, str):
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.REQUIRED_FIELD_MISSING,
                field="cdp_version",
            ),
            stage_reached=1,
            metadata=meta,
        )
    meta.cdp_version = cdp_version

    # Stage 2: cdp_version recognized
    if cdp_version not in SUPPORTED_CDP_VERSIONS:
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.CDP_VERSION_UNSUPPORTED,
                found=cdp_version,
            ),
            stage_reached=2,
            metadata=meta,
        )

    # Populate metadata
    if isinstance(proof.get("capsule_id"), str):
        meta.capsule_id = proof["capsule_id"]
    meta.region = _pointer_str(proof, "environment", "region")
    if meta.region is None and isinstance(proof.get("region"), str):
        meta.region = proof["region"]
    meta.signing_key_version = _pointer_str(proof, "attestation", "signing_key_version")
    if meta.signing_key_version is None and isinstance(proof.get("signing_key_version"), str):
        meta.signing_key_version = proof["signing_key_version"]
    meta.algorithm = _pointer_str(proof, "attestation", "algorithm")

    # Policy-pin gate — authority ID (the customer-authority specification G7 / VP Security F4.3).
    #
    # Runs BEFORE the chain walk because the policy decision is independent of
    # chain validity: a customer who pinned the wrong authority should learn
    # that immediately, not after an 8-step SHA-512 walk. A proof that omits
    # `signing_authority` was signed under the Nanorix-default path and cannot
    # satisfy a customer-HSM pin, so the gate fails closed.
    if pol.required_authority_id:
        claimed_id = _pointer_str(proof, "signing_authority", "authority_id")
        if claimed_id is None:
            return VerificationResult(
                valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.AUTHORITY_ID_MISMATCH,
                    claimed_authority_id=None,
                    expected_authority_id=pol.required_authority_id,
                    auth_id_reason="verifier_policy_demands_customer_hsm_audit_proof_has_none",
                ),
                stage_reached=2,
                metadata=meta,
            )
        if claimed_id != pol.required_authority_id:
            return VerificationResult(
                valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.AUTHORITY_ID_MISMATCH,
                    claimed_authority_id=claimed_id,
                    expected_authority_id=pol.required_authority_id,
                    auth_id_reason="verifier_policy_authority_id_mismatch",
                ),
                stage_reached=2,
                metadata=meta,
            )

    # Residency-pin gate (the specification G1 / the region policy). A proof carrying no region at
    # all cannot satisfy a residency pin — it is rejected with an empty
    # `actual` rather than accepted, so the pin fails closed.
    if pol.required_region:
        actual_region = meta.region or ""
        if actual_region != pol.required_region:
            return VerificationResult(
                valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.REGION_MISMATCH,
                    required=pol.required_region,
                    actual=actual_region,
                ),
                stage_reached=2,
                metadata=meta,
            )

    # Stage 3: chain reproducibility
    chain_raw = proof.get("chain")
    if not isinstance(chain_raw, list):
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.REQUIRED_FIELD_MISSING,
                field="chain",
            ),
            stage_reached=3,
            metadata=meta,
        )
    step_count = len(chain_raw)
    meta.step_count = step_count

    if step_count != CHAIN_STEP_COUNT:
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.STEP_COUNT_INVALID,
                expected=CHAIN_STEP_COUNT,
                found=step_count,
            ),
            stage_reached=3,
            metadata=meta,
        )

    timestamp, recovered = _canonical.resolve_chain_timestamp(proof)
    meta.recovered_chain_timestamp = recovered

    # the per-record receipt specification + the receipt-batching specification the receipt pipeline — optional Merkle roots amend step 8. Absent on
    # pre-the receipt pipeline proofs, where both branches collapse to the legacy formula.
    rrmr = proof.get("record_receipts_merkle_root")
    rrmr = rrmr if isinstance(rrmr, str) else None
    ppmr = proof.get("parent_proofs_merkle_root")
    ppmr = ppmr if isinstance(ppmr, str) else None

    prev_hash = GENESIS_HASH
    for idx, step_raw in enumerate(chain_raw):
        if not isinstance(step_raw, dict):
            return VerificationResult(
                valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.STEP_HASH_MISMATCH,
                    step_idx=idx,
                    subsystem="",
                ),
                stage_reached=3,
                metadata=meta,
            )
        subsystem = _str_or_empty(step_raw.get("subsystem"))
        claimed_chain_hash = _str_or_empty(step_raw.get("chain_hash"))

        if idx == 7 and subsystem == "capsule_destroy":
            recomputed = compute_step_8_amended(prev_hash, timestamp, rrmr, ppmr)
        else:
            recomputed = compute_step_hash(
                prev_hash, subsystem, lookup_method(subsystem), timestamp
            )

        if recomputed != strip_hash_prefix(claimed_chain_hash):
            return VerificationResult(
                valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.STEP_HASH_MISMATCH,
                    step_idx=idx,
                    subsystem=subsystem,
                ),
                stage_reached=3,
                metadata=meta,
            )
        prev_hash = recomputed

    receipts = proof.get("record_receipts")
    if isinstance(receipts, list):
        failure = _verify_record_receipts(receipts, meta.capsule_id or "", rrmr)
        if failure is not None:
            return VerificationResult(
                valid=False, failure_reason=failure, stage_reached=3, metadata=meta
            )

    parents = proof.get("parent_proof_hashes")
    if isinstance(parents, list):
        failure = _verify_parent_proofs(parents, ppmr)
        if failure is not None:
            return VerificationResult(
                valid=False, failure_reason=failure, stage_reached=3, metadata=meta
            )

    # Stage 4: final_hash binding
    claimed_final = _str_or_empty(proof.get("final_hash"))
    last_step = chain_raw[-1]
    last_chain_hash = _str_or_empty(
        last_step.get("chain_hash") if isinstance(last_step, dict) else ""
    )

    if strip_hash_prefix(claimed_final) != strip_hash_prefix(last_chain_hash):
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.FINAL_HASH_MISMATCH,
                claimed=claimed_final,
                computed=last_chain_hash,
            ),
            stage_reached=4,
            metadata=meta,
        )

    # Algorithm dispatch precedes byte-shape checks (the specification C.1): a proof
    # declaring a non-Ed25519 signature algorithm fails typed as
    # algorithm_unsupported here — it must never fall through to the 64/32-byte
    # decode gates and report as "malformed". Absent or "Ed25519" proceeds
    # unchanged (every proof issued to date).
    declared_algorithm = _declared_non_ed25519_algorithm(proof)
    if declared_algorithm is not None:
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.ALGORITHM_UNSUPPORTED,
                found=declared_algorithm,
            ),
            stage_reached=4,
            metadata=meta,
        )

    # Stages 5-7: signature over the version/mode-appropriate message, checked
    # against the key EMBEDDED in the proof. This proves integrity — the
    # document has not been altered since signing — not authenticity.
    check = _canonical.verify_signature(proof, cdp_version)
    if check.outcome is SignatureOutcome.VERIFIED:
        return VerificationResult(valid=True, failure_reason=None, stage_reached=7, metadata=meta)
    if check.outcome is SignatureOutcome.UNSUPPORTED:
        # The document declares a signing_mode this build cannot verify. NOT the
        # same as "no signature": signing_mode is inside the canonical hash and
        # is attacker-controllable, so treating an unrecognised mode as a partial
        # success turns a rejection into reassurance — a downgrade oracle.
        # algorithm_unsupported is the existing Forever-Standard reason for "this
        # build cannot perform the verification this document requires"; the
        # resolution (upgrade the verifier) is identical. Mirrors Rust and Go.
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.ALGORITHM_UNSUPPORTED,
                found=f"signing_mode={check.mode}",
            ),
            stage_reached=4,
            metadata=meta,
        )
    if check.outcome is SignatureOutcome.ABSENT:
        return VerificationResult(valid=True, failure_reason=None, stage_reached=4, metadata=meta)
    return VerificationResult(
        valid=False,
        failure_reason=FailureReason(
            type=FailureReasonType.SIGNATURE_MISMATCH,
            reason=check.reason,
        ),
        stage_reached=7,
        metadata=meta,
    )
