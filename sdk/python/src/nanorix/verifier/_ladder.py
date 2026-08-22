"""
The AuditProof verification stage ladder — the single Python implementation.

Python mirror of `tools/nanorix-verify/src/lib.rs::verify_auditproof`, which is
the reference verifier and the spec. Agreement is enforced against every
pinned document in `tools/nanorix-verify/fixtures/corpus/`, which are the
public cross-implementation contract; a disagreement with the corpus is a
defect in this file, never in the corpus.

Stage ladder:

| Stage | Check |
|---|---|
| 1 | `cdp_version` present |
| 2 | `cdp_version` recognised (1.0 / 2.0 / 2.1 / 2.2); authority-id pin; region pin |
| 3 | chain present, 8 steps, every step hash reproduces; Wave-N receipt + parent sets |
| 4 | `final_hash` binds to the last step's `chain_hash` |
| 5–7 | Ed25519 signature over the version-appropriate message, against the embedded key |

Stage 8 (anchoring the key to a signed trust-chain manifest, EO-07 sub-B) needs
an operator-supplied manifest and is not implemented here; a proof whose
embedded-key signature verifies tops out at the honest stage 7 — integrity
proven, authenticity not established.

## The chain hash formula (Forever-Standard, ADR-006 I0)

    chain_hash[n] = SHA-512(prev || 0x00 || subsystem || 0x00 || "destroy"
                            || 0x00 || method || 0x00 || timestamp)

`method` is a FIXED per-step canonical constant looked up from the subsystem
name — it is NOT the serialized `operation` field and NOT a per-step JSON
field. `timestamp` is the document's `destroyed_at` (or the value recovered
from `attestation.key_id` per ADR-047), the same value for every step.
Production `CdpChainStep` carries only `step`, `subsystem`, `operation`,
`evidence_hash`, and `chain_hash`; a verifier that reads per-step `method` or
`timestamp` fields reproduces nothing on a real proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

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

# Canonical genesis hash — SHA-512("") (Forever-Standard, ADR-006 I0)
GENESIS_HASH = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)

# Canonical method strings per subsystem (Forever-Standard, ADR-006 I0).
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

# Reserved attestation slots outside CanonicalCdpView (ADR-011 I18-I21, I24-I25
# + ADR-012 D2/D3) that no Nanorix signer populates. Every construction site
# hard-codes them to None, so the signature never covered them and a genuine
# document never carries them; a populated one was added after signing by
# someone holding no key, and the signature cannot tell, because it never
# covered the field.
#
# `per_event_attestations` is the ninth reserved slot and is deliberately
# absent: the server drains capsule_event_attestations into it at destroy, so
# genuine proofs do carry it, and each entry is signed by the customer's own
# key. Mirrors the Rust, Go and TypeScript verifiers.
UNSIGNED_RESERVED_SLOTS = (
    "customer_attestation",
    "policy_attestation",
    "third_party_attestation",
    "retention_policy_attestation",
    "witness_signatures",
    "pqc_attestation",
    "customer_pqc_attestation",
)

_PARENT_ATTRIBUTION_FIELDS = (
    "parent_key_id",
    "parent_signature",
    "parent_role",
    "parent_jurisdiction",
    "parent_organization_tag",
)


class FailureReasonType:
    """Closed-set wire-form discriminators (Forever-Standard, ADR-006 I0).

    New variants ADDITIVE ONLY. Existing variants never renamed/removed.
    """

    ALGORITHM_UNSUPPORTED = "algorithm_unsupported"
    AUTHORITY_ID_MISMATCH = "authority_id_mismatch"
    AUTHORITY_MODE_MISMATCH = "authority_mode_mismatch"
    AUTHORITY_REVOKED = "authority_revoked"
    CDP_VERSION_UNSUPPORTED = "cdp_version_unsupported"
    CHAIN_STEP_IDENTITY_MISMATCH = "chain_step_identity_mismatch"
    CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH = "customer_declared_activity_root_mismatch"
    DIAGNOSTIC_PROOF_REFUSED = "diagnostic_proof_refused"
    FIELD_MALFORMED = "field_malformed"
    FINAL_HASH_MISMATCH = "final_hash_mismatch"
    GENESIS_HASH_MISMATCH = "genesis_hash_mismatch"
    REGION_MISMATCH = "region_mismatch"
    REQUIRED_FIELD_MISSING = "required_field_missing"
    RESERVED = "reserved"
    SIGNATURE_MISMATCH = "signature_mismatch"
    SIGNING_KEY_VERSION_UNKNOWN = "signing_key_version_unknown"
    STEP_COUNT_INVALID = "step_count_invalid"
    STEP_HASH_MISMATCH = "step_hash_mismatch"
    STREAMING_MERKLE_ROOT_MISMATCH = "streaming_merkle_root_mismatch"
    UNSIGNED_FIELD_POPULATED = "unsigned_field_populated"


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
    # required_field_missing, unsigned_field_populated, field_malformed
    field: Optional[str] = None
    expected: Optional[int] = None  # step_count_invalid
    step_idx: Optional[int] = None  # step_hash_mismatch, chain_step_identity_mismatch
    subsystem: Optional[str] = None  # step_hash_mismatch
    expected_subsystem: Optional[str] = None  # chain_step_identity_mismatch
    found_subsystem: Optional[str] = None  # chain_step_identity_mismatch
    # final_hash_mismatch, streaming_merkle_root_mismatch,
    # customer_declared_activity_root_mismatch
    claimed: Optional[str] = None
    computed: Optional[str] = None
    reason: Optional[str] = None  # signature_mismatch, field_malformed
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
        elif t in (
            FailureReasonType.REQUIRED_FIELD_MISSING,
            FailureReasonType.UNSIGNED_FIELD_POPULATED,
        ):
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
        elif t == FailureReasonType.CHAIN_STEP_IDENTITY_MISMATCH:
            if self.step_idx is not None:
                d["step_idx"] = self.step_idx
            if self.expected_subsystem is not None:
                d["expected_subsystem"] = self.expected_subsystem
            if self.found_subsystem is not None:
                d["found_subsystem"] = self.found_subsystem
        elif t in (
            FailureReasonType.FINAL_HASH_MISMATCH,
            FailureReasonType.STREAMING_MERKLE_ROOT_MISMATCH,
            FailureReasonType.CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH,
        ):
            if self.claimed is not None:
                d["claimed"] = self.claimed
            if self.computed is not None:
                d["computed"] = self.computed
        elif t == FailureReasonType.SIGNATURE_MISMATCH:
            if self.reason is not None:
                d["reason"] = self.reason
        elif t == FailureReasonType.FIELD_MALFORMED:
            if self.field is not None:
                d["field"] = self.field
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
    # timestamp was recovered from `attestation.key_id` (ADR-047). An auditor
    # can therefore always tell which route produced a verdict.
    recovered_chain_timestamp: Optional[str] = None

    # Set to the number of parent links carrying attribution the signature does
    # not cover — parent_key_id, parent_signature, parent_role,
    # parent_jurisdiction, parent_organization_tag. Only parent_chain_hash feeds
    # the signed Merkle root, so an outsider can rewrite the rest of a genuine
    # proof's declared lineage. The lineage UI renders exactly those fields, so
    # a verdict that stays silent invites them to be read as attested.
    unattested_parent_attribution: Optional[int] = None

    # ADR-056. The `customer_declared_activity_root` the proof carries, as
    # written; None when it declares none. Disclosed whether or not the record
    # was supplied — a verdict that stays silent about a declared root invites
    # a reader to assume it was checked.
    customer_declared_activity_root: Optional[str] = None

    # True when the customer's activity record was supplied through
    # `VerifierPolicy.customer_activity` and its recomputed root matched;
    # False when the proof declares a root but no record was supplied —
    # declared, not checked. None when the proof declares no root. A mismatch
    # is a failure, never a False here.
    customer_declared_activity_checked: Optional[bool] = None


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

    Field-additive per ADR-006 I0 + ADR-031 G7. Every field defaults to its
    "accept anything" semantics, so a default policy behaves identically to no
    policy at all.
    """

    reject_diagnostic: bool = False
    required_region: str = ""
    required_authority_id: str = ""

    # ADR-056. The raw bytes of the customer's activity record
    # (`activity_events.jsonl`), when the reader holds it. Recomputed and
    # compared with the proof's `customer_declared_activity_root`; a record
    # supplied against a proof that declares no root fails closed as
    # `required_field_missing`. None leaves a declared root disclosed as
    # "declared, not checked" rather than failed.
    customer_activity: Optional[bytes] = None


def _str_or_empty(v: Any) -> str:
    return v if isinstance(v, str) else ""


# Matched with `fullmatch`, never `match`: `$` accepts a trailing "\n" and a
# root with one is not a root any signer emits.
_ACTIVITY_ROOT_SHAPE = re.compile(r"(sha512:)?[0-9a-f]{128}")

CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD = "customer_declared_activity_root"


def customer_declared_activity_root_shape_failure(raw: Any) -> Optional[FailureReason]:
    """The shape a present, non-null `customer_declared_activity_root` must have.

    A JSON string of `sha512:` + 128 lowercase hex (bare 128-hex accepted, as
    for every other root the verifier compares); anything else is
    `field_malformed`. The empty string is malformed rather than absent: the
    canonical view binds `""` as a value, and a reader that called it "no
    root" would contradict its own recompute. Reason strings are the
    reference verifier's exact text — the corpus compares the whole object.
    """
    if not isinstance(raw, str):
        reason = "expected a JSON string"
    elif raw == "":
        reason = "empty string"
    elif not _ACTIVITY_ROOT_SHAPE.fullmatch(raw):
        reason = "expected sha512: followed by 128 lowercase hex characters"
    else:
        return None
    return FailureReason(
        type=FailureReasonType.FIELD_MALFORMED,
        field=CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
        reason=reason,
    )


def customer_declared_activity_root_gate(
    proof: Mapping[str, Any], cdp_version: str
) -> Optional[FailureReason]:
    """The two stage-2 gates on `customer_declared_activity_root`.

    Fires only when the field is present and not null. The root is signed
    only where the signed message is the canonical view (2.1 / 2.2); on any
    other version a populated one is the reserved-slot shape. The version
    gate precedes the shape gate: a root the signature never covered is the
    more fundamental defect, whatever its shape.

    Shared with the standalone sidecar check in `customer_activity`, so the
    two entry points cannot disagree about which roots are readable.
    """
    field = CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD
    if field not in proof or proof[field] is None:
        return None
    if cdp_version not in _canonical.CANONICAL_VIEW_SIGNED_VERSIONS:
        return FailureReason(type=FailureReasonType.UNSIGNED_FIELD_POPULATED, field=field)
    return customer_declared_activity_root_shape_failure(proof[field])


def compute_step_hash(
    prev_hash: str,
    subsystem: str,
    method: str,
    timestamp: str,
) -> str:
    """Reproduce one chain step's SHA-512 hash.

    Formula (Forever-Standard, ADR-006 I0):
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
    """ADR-039 Mode A step 3 — recompute each receipt's chain hash + the root.

    Returns None when there is nothing to check or everything reproduces. A
    non-empty receipt set with no root is refused rather than skipped: the
    emitter sets ``record_receipts_merkle_root`` iff ``record_receipts`` is set,
    so a rootless set is one nothing anchors.
    """
    if claimed_root is None:
        if not receipts:
            return None
        return FailureReason(
            type=FailureReasonType.REQUIRED_FIELD_MISSING,
            field="record_receipts_merkle_root",
        )

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
    """ADR-041 — recompute the parent-proof Merkle root and compare to claimed.

    A parent set with no root is anchored by nothing, and the emitter never
    produces one: ``parent_proofs_merkle_root`` is set iff ``parent_proof_hashes``
    is. Skipping the check when the root is absent — which this used to do — let
    an outsider append an entire fabricated lineage to a genuine proof, since the
    array is outside the canonical hash and the signature therefore still
    verified.
    """
    if claimed_root is None:
        if not parents:
            return None
        return FailureReason(
            type=FailureReasonType.REQUIRED_FIELD_MISSING,
            field="parent_proofs_merkle_root",
        )

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


EMPTY_SHA512_HEX = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)


def merkle_root_from_leaves(leaves: Sequence[bytes]) -> str:
    """Byte-for-byte mirror of ``merkle_root_from_leaves``.

    Reference: ``runtime/eee/src/daemon/streaming.rs`` (the emitter) and
    ``tools/nanorix-verify/src/streaming_merkle.rs`` (the reference verifier).

    RFC 6962 §2.1 domain separation over SHA-512: empty leaf set is SHA-512 of
    the empty string; one leaf is ``SHA-512(0x00 || leaf)``; an inner node is
    ``SHA-512(0x01 || left || right)``; an odd tail node is promoted unchanged.
    Each leaf is the raw 64-byte SHA-512 of one chunk body, in ``seq`` order.

    Returns 128 lowercase hex characters, unprefixed.

    Forever-Standard (ADR-006 I0): changing any of those three rules
    invalidates every streaming Merkle root ever emitted.
    """
    if not leaves:
        return EMPTY_SHA512_HEX

    level = [hashlib.sha512(b"\x00" + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        nxt: List[bytes] = []
        i = 0
        while i + 1 < len(level):
            nxt.append(hashlib.sha512(b"\x01" + level[i] + level[i + 1]).digest())
            i += 2
        if i < len(level):
            nxt.append(level[i])
        level = nxt
    return level[0].hex()


def _streaming_leaf_bytes(chunk_hash: str) -> Optional[bytes]:
    """One ``chunk_hash`` as a 64-byte Merkle leaf, or None when unusable."""
    try:
        raw = bytes.fromhex(strip_hash_prefix(chunk_hash))
    except ValueError:
        return None
    return raw if len(raw) == 64 else None


def _close_stream(
    chunks: List[Tuple[int, str]],
    malformed: bool,
    completed: Mapping[str, Any],
) -> Optional[FailureReason]:
    """Check one closed stream's root. None when there is nothing to check."""
    claimed = completed.get("streaming_merkle_root")
    if not isinstance(claimed, str):
        return None

    # A disclosed chunk event with no usable chunk_hash is a structural defect
    # in the trail, not a root disagreement. Checked first so one unusable leaf
    # cannot shrink the set into the "truncated, do not check" shape.
    if malformed:
        return FailureReason(
            type=FailureReasonType.REQUIRED_FIELD_MISSING,
            field="activity_trail.streaming_egress_chunk.chunk_hash",
        )

    total = completed.get("total_chunks")
    if not isinstance(total, int) or isinstance(total, bool):
        total = len(chunks)

    # Partial disclosure — the truncated shape. Not a defect; not checkable.
    if len(chunks) != total:
        return None

    leaves = [_streaming_leaf_bytes(h) for _, h in sorted(chunks, key=lambda c: c[0])]
    computed = merkle_root_from_leaves([leaf for leaf in leaves if leaf is not None])
    if strip_hash_prefix(claimed) != computed:
        return FailureReason(
            type=FailureReasonType.STREAMING_MERKLE_ROOT_MISMATCH,
            claimed=claimed,
            computed="sha512:" + computed,
        )
    return None


def _verify_streaming_merkle_roots(activity: Sequence[Any]) -> Optional[FailureReason]:
    """Recompute every fully-disclosed streaming-egress Merkle root.

    ``streaming_egress_completed.streaming_merkle_root`` is an RFC 6962 SHA-512
    commitment over the ``streaming_egress_chunk`` leaves emitted beside it
    (reference: ``runtime/eee/src/daemon/streaming.rs::merkle_root_from_leaves``).
    It was signed from the day it shipped and read by no verifier in any of the
    four implementations.

    Recomputed only when the leaves are present AND complete: a root standing
    alone is the truncated shape, and rejecting it would reject every truncated
    proof. Mirrors ``tools/nanorix-verify/src/streaming_merkle.rs``.
    """
    chunks: List[Tuple[int, str]] = []
    malformed = False

    for event in activity:
        if not isinstance(event, Mapping):
            continue
        kind = event.get("event")
        if kind == "streaming_egress_started":
            chunks, malformed = [], False
        elif kind == "streaming_egress_chunk":
            seq = event.get("seq")
            chunk_hash = event.get("chunk_hash")
            if (
                isinstance(seq, int)
                and not isinstance(seq, bool)
                and isinstance(chunk_hash, str)
                and _streaming_leaf_bytes(chunk_hash) is not None
            ):
                chunks.append((seq, chunk_hash))
            else:
                # Flagged rather than dropped — dropping would let a malformed
                # leaf shrink the set into a different tree, or into the
                # "truncated" shape.
                malformed = True
        elif kind == "streaming_egress_completed":
            failure = _close_stream(chunks, malformed, event)
            if failure is not None:
                return failure
            chunks, malformed = [], False

    return None
def _populated_unsigned_slot(proof: Mapping[str, Any]) -> Optional[str]:
    """First reserved slot carrying anything other than JSON ``null``.

    Genuine documents emit these keys with an explicit ``null`` (the fields have
    no ``skip_serializing_if``), so absence and ``null`` are both normal.
    Anything else — an empty list included — is a shape no signer produces.
    Iteration follows ``UNSIGNED_RESERVED_SLOTS`` order so a document with
    several populated slots always names the same one, in every language.
    """
    for slot in UNSIGNED_RESERVED_SLOTS:
        if proof.get(slot, None) is not None:
            return slot
    return None


def _count_unattested_parent_attribution(parents: Sequence[Any]) -> Optional[int]:
    """Parent links carrying attribution the signed Merkle root does not bind."""
    n = sum(
        1
        for p in parents
        if isinstance(p, Mapping)
        and any(p.get(f, None) is not None for f in _PARENT_ATTRIBUTION_FIELDS)
    )
    return n or None


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

    # Reserved-slot gate. A slot outside the signature carrying a value no
    # signer emits means the bytes in front of us are not the bytes that were
    # signed, even though the signature over the covered subset still checks
    # out. Runs before the policy pins and the chain walk because the document
    # is structurally impossible on its own terms, independent of what any
    # customer policy asks for.
    populated_slot = _populated_unsigned_slot(proof)
    if populated_slot is not None:
        return VerificationResult(
            valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.UNSIGNED_FIELD_POPULATED,
                field=populated_slot,
            ),
            stage_reached=2,
            metadata=meta,
        )

    # ADR-056 D2/D3 — customer_declared_activity_root shape gates. Off 2.1/2.2
    # the field is outside every signed view, so a populated one is the
    # reserved-slot shape above; on 2.1/2.2 it must be a string the recompute
    # can consume. Rejected here so no later stage ever reads a malformed root.
    activity_gate = customer_declared_activity_root_gate(proof, cdp_version)
    if activity_gate is not None:
        return VerificationResult(
            valid=False, failure_reason=activity_gate, stage_reached=2, metadata=meta
        )

    # Populate metadata
    if isinstance(proof.get("capsule_id"), str):
        meta.capsule_id = proof["capsule_id"]
    # Region resolves from the SIGNED capsule_started activity event only.
    # The activity trail is inside CanonicalCdpView, so a region carried there
    # cannot be altered without breaking the signature. `environment.region`
    # and top-level `region` are both outside the canonical hash — reading
    # either let an outsider satisfy a residency pin by appending a region to a
    # genuine signed proof, with no key. Mirrors the Rust, Go and TS verifiers.
    meta.region = None
    activity = proof.get("activity")
    if isinstance(activity, list):
        for event in activity:
            if not isinstance(event, dict) or event.get("event") != "capsule_started":
                continue
            if isinstance(event.get("region"), str):
                meta.region = event["region"]
            break
    meta.signing_key_version = _pointer_str(proof, "attestation", "signing_key_version")
    if meta.signing_key_version is None and isinstance(proof.get("signing_key_version"), str):
        meta.signing_key_version = proof["signing_key_version"]
    meta.algorithm = _pointer_str(proof, "attestation", "algorithm")

    # Policy-pin gate — authority ID (ADR-031 G7 / VP Security F4.3).
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

    # Residency-pin gate (EO-03 G1 / ADR-018 D3). A proof carrying no region at
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

    # ADR-039 + ADR-041 Wave-N — optional Merkle roots amend step 8. Absent on
    # pre-Wave-N proofs, where both branches collapse to the legacy formula.
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
        # Canonical-identity walk: the hash inputs come from
        # CANONICAL_SUBSYSTEMS by INDEX, never from the document. A document
        # cannot choose what a step is; it can only fail to match.
        canonical_subsystem = CANONICAL_SUBSYSTEMS[idx]
        declared_subsystem = _str_or_empty(step_raw.get("subsystem"))
        claimed_chain_hash = _str_or_empty(step_raw.get("chain_hash"))

        if idx == CHAIN_STEP_COUNT - 1:
            recomputed = compute_step_8_amended(prev_hash, timestamp, rrmr, ppmr)
        else:
            recomputed = compute_step_hash(
                prev_hash,
                canonical_subsystem,
                lookup_method(canonical_subsystem),
                timestamp,
            )

        if recomputed != strip_hash_prefix(claimed_chain_hash):
            return VerificationResult(
                valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.STEP_HASH_MISMATCH,
                    step_idx=idx,
                    subsystem=declared_subsystem,
                ),
                stage_reached=3,
                metadata=meta,
            )

        # Hashes reproduced; the label beside them still has to be the right
        # one. Genuine hashes under a forged subsystem name would otherwise
        # verify clean and read as attesting to a step they do not describe.
        if declared_subsystem != canonical_subsystem:
            return VerificationResult(
                valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.CHAIN_STEP_IDENTITY_MISMATCH,
                    step_idx=idx,
                    expected_subsystem=canonical_subsystem,
                    found_subsystem=declared_subsystem,
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
        # The root binds parent_chain_hash and nothing else, so the verdict
        # carries the count rather than let a reader infer coverage.
        meta.unattested_parent_attribution = _count_unattested_parent_attribution(parents)

    # Streaming-egress Merkle roots. Placed with the other sub-structure Merkle
    # checks and therefore before the signature stages, so it also covers the
    # path where a chain reproduces with no signature to check at all.
    activity = proof.get("activity")
    if isinstance(activity, list):
        failure = _verify_streaming_merkle_roots(activity)
        if failure is not None:
            return VerificationResult(
                valid=False, failure_reason=failure, stage_reached=3, metadata=meta
            )

    # ADR-056 customer-declared activity root. The root is canonical-bound, so
    # the signature stages below bind it to the signer regardless; recomputing
    # it needs the customer's record, which the reader supplies through the
    # policy. Sits with the other sub-structure Merkle checks so it also covers
    # the path where a chain reproduces with no signature to check at all.
    # Imported here because customer_activity builds on this module's
    # FailureReason types.
    from nanorix.verifier.customer_activity import (
        CustomerDeclaredActivityStatus,
        verify_customer_declared_activity,
    )

    activity_check = verify_customer_declared_activity(proof, pol.customer_activity)
    meta.customer_declared_activity_root = activity_check.claimed
    if activity_check.status is CustomerDeclaredActivityStatus.FAILED:
        return VerificationResult(
            valid=False,
            failure_reason=activity_check.failure_reason,
            stage_reached=3,
            metadata=meta,
        )
    if activity_check.status is CustomerDeclaredActivityStatus.VERIFIED:
        meta.customer_declared_activity_checked = True
    elif activity_check.status is CustomerDeclaredActivityStatus.DECLARED_NOT_CHECKED:
        meta.customer_declared_activity_checked = False

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

    # Algorithm dispatch precedes byte-shape checks (ADR-051 C.1): a proof
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
