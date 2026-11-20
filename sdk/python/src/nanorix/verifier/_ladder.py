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
| 2 | `cdp_version` recognised (1.0 / 2.1 / 2.2); authority-id pin; region pin |
| 3 | chain present, 8 steps, every step hash reproduces; per-record receipt + parent sets |
| 4 | `final_hash` binds to the last step's `chain_hash` |
| 5–7 | Ed25519 signature over the version-appropriate message, against the embedded key |
| 8 | the signing key resolved in a signed key list, and the signature checked against the listed key (only with `VerifierPolicy.trust_chain`) |

Stage 8 needs a key list and the identity fingerprint that must have signed it:
`TrustChain.from_key_list(key_list, pinned_fingerprint)` checks the list once and
returns the value for `VerifierPolicy.trust_chain`. Without one, a proof whose
embedded-key signature verifies tops out at the honest stage 7 — integrity
proven, authenticity not established.

## The chain hash formula (Forever-Standard)

    chain_hash[n] = SHA-512(prev || 0x00 || subsystem || 0x00 || "destroy"
                            || 0x00 || method || 0x00 || timestamp)

`method` is a FIXED per-step canonical constant looked up from the subsystem
name — it is NOT the serialized `operation` field and NOT a per-step JSON
field. `timestamp` is the document's `destroyed_at` (or the value recovered
from `attestation.key_id`), the same value for every step.
Production `CdpChainStep` carries only `step`, `subsystem`, `operation`,
`evidence_hash`, and `chain_hash`; a verifier that reads per-step `method` or
`timestamp` fields reproduces nothing on a real proof.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Mapping, Optional, Sequence, Tuple, Union

from nanorix.verifier import _canonical
from nanorix.verifier._trust_chain import HYBRID_RECORD_CHECK_MISSING, TrustChain, is_hybrid_pin
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

# Canonical genesis hash — SHA-512("") (Forever-Standard)
GENESIS_HASH = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)

# Canonical method strings per subsystem (Forever-Standard).
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

# Canonical 8-step subsystem order (must match CHAIN_DEFS in the reference implementation).
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

# Reserved attestation slots outside CanonicalCdpView
# that no Nanorix signer populates. Every construction site
# hard-codes them to None, so the signature never covered them and a genuine
# document never carries them; a populated one was added after signing by
# someone holding no key, and the signature cannot tell, because it never
# covered the field.
#
# `per_event_attestations` is the ninth reserved slot and is deliberately
# absent: the server drains capsule_event_attestations into it at destroy, so
# genuine proofs do carry it. The slot sits outside the signed hash and is
# accepted unchecked: its entries prove nothing about who signed. Mirrors the Rust, Go and TypeScript verifiers.
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
    """Closed-set wire-form discriminators (Forever-Standard).

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
    SIGNING_MODE_AUTHORITY_MISMATCH = "signing_mode_authority_mismatch"
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
    # authority_id_mismatch, signing_mode_authority_mismatch
    claimed_authority_id: Optional[str] = None
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
        elif t == FailureReasonType.SIGNING_MODE_AUTHORITY_MISMATCH:
            d["claimed_authority_id"] = self.claimed_authority_id
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
    # timestamp was recovered from `attestation.key_id`. An auditor
    # can therefore always tell which route produced a verdict.
    recovered_chain_timestamp: Optional[str] = None

    # Set to the number of parent links carrying attribution the signature does
    # not cover — parent_key_id, parent_signature, parent_role,
    # parent_jurisdiction, parent_organization_tag. Only parent_chain_hash feeds
    # the signed Merkle root, so an outsider can rewrite the rest of a genuine
    # proof's declared lineage. The lineage UI renders exactly those fields, so
    # a verdict that stays silent invites them to be read as attested.
    unattested_parent_attribution: Optional[int] = None

    # The `customer_declared_activity_root` the proof carries, as
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


# The three result states. The names are the same in the TypeScript SDK, the
# nanorix-verify JSON output and the MCP tool.
VerifyStatus = Literal["verified", "not_anchored", "not_verified"]
STATUS_VERIFIED: VerifyStatus = "verified"
STATUS_NOT_ANCHORED: VerifyStatus = "not_anchored"
STATUS_NOT_VERIFIED: VerifyStatus = "not_verified"


def verification_status_for(valid: bool, stage_reached: int) -> VerifyStatus:
    """Derive the result state for an offline verdict.

    ``verified`` only at stage 8: the signing key resolved in a trust-chain
    manifest checked against its pinned identity fingerprint, and the signature
    verified against that key. ``not_anchored`` at stage 7: the chain
    reproduced and the signature verified against the key embedded in the
    proof, which a proof signed with a fresh key also does. Everything else,
    including a reproduced chain with no signature checked, is
    ``not_verified``.
    """
    if valid and stage_reached >= 8:
        return STATUS_VERIFIED
    if valid and stage_reached == 7:
        return STATUS_NOT_ANCHORED
    return STATUS_NOT_VERIFIED


def _warn_valid_deprecated(owner: str) -> None:
    warnings.warn(
        f"{owner}.valid is deprecated: it is also True when who signed is not established "
        "(status 'not_anchored' at stage 7, and a chain with no signature checked at "
        "stage 4). Read .status, which is 'verified' only at stage 8, or .ok.",
        FutureWarning,
        stacklevel=3,
    )


@dataclass
class VerificationResult:
    """Result of AuditProof verification.

    ``valid`` + ``failure_reason`` + ``stage_reached`` are the cross-impl
    agreement surface compared against the fixture corpus and the Rust
    reference verifier; the corpus pins ``status`` with them.

    ``valid`` is deprecated as an attribute and warns with ``FutureWarning``:
    it is true when the chain and the signature hold under the key used, and
    on its own it says nothing about who signed (it is also true at stage 7,
    ``not_anchored``, and at stage 4, no signature checked). Read ``status``,
    which is ``"verified"`` only at stage 8, or ``ok``. The wire form keeps
    the ``valid`` field unchanged. The constructor takes the value as
    ``_valid``.
    """

    _valid: bool
    failure_reason: Optional[FailureReason]
    stage_reached: int
    metadata: VerificationMetadata = field(default_factory=VerificationMetadata)

    @property
    def valid(self) -> bool:
        """Deprecated: read ``status`` or ``ok``. True at stages 4, 7 and 8."""
        _warn_valid_deprecated("VerificationResult")
        return self._valid

    @property
    def status(self) -> VerifyStatus:
        """``"verified"`` (stage 8), ``"not_anchored"`` (stage 7) or ``"not_verified"``."""
        return verification_status_for(self._valid, self.stage_reached)

    @property
    def ok(self) -> bool:
        """True only when ``status`` is ``"verified"``."""
        return self.status == STATUS_VERIFIED

    def to_wire_dict(self) -> Dict[str, Any]:
        """Produce the fixture-corpus wire form."""
        return {
            "valid": self._valid,
            "failure_reason": (
                self.failure_reason.to_wire_dict() if self.failure_reason is not None else None
            ),
        }


@dataclass
class VerifierPolicy:
    """Customer-side policy configuration for AuditProof verification.

    Field-additive. Every field defaults to its
    "accept anything" semantics, so a default policy behaves identically to no
    policy at all.
    """

    # Refuse at stage 2, with `diagnostic_proof_refused`, an AuditProof whose
    # signed activity trail records diagnostic mode (a `diagnostic_mode_enabled`
    # event), and every AuditProof that cannot show it does not: one whose
    # trail is unsigned, which is cdp_version 1.0, or 2.1 or 2.2 without a
    # signature, so the event could be removed and the proof would still
    # verify. Only a stage 8 (``"verified"``) result ties the trail to a
    # Nanorix key; at stage 7 the key is the one the proof carries. False
    # accepts diagnostic-mode proofs.
    reject_diagnostic: bool = False
    # Compared with the region on the signed `capsule_started` activity event;
    # a disagreeing proof is refused at stage 2 with `region_mismatch`. A proof
    # whose trail is unsigned (cdp_version 1.0, or 2.1 or 2.2 without a
    # signature) is refused with an empty `actual`. Only a stage 8
    # (``"verified"``) result ties the region to a Nanorix key.
    required_region: str = ""
    # Compared with the proof's top-level `authority_id`, never with an unsigned
    # `signing_authority`. The signature covers that field only on cdp_version
    # 2.1 and 2.2; on 1.0 a string other than `us-kms-nanorix-v1` is refused,
    # so a pin accepts only the default there, and 2.0 is refused at the
    # version gate before the pin is read. A pin is a full authority check only
    # together with `trust_chain`, which resolves the signing key in a key list
    # instead of trusting the key in the proof.
    required_authority_id: str = ""

    # The signed key list the proof's signing key is resolved against (stage 8).
    # Make it with `TrustChain.from_key_list(key_list, pinned_fingerprint)`, which
    # checks the list's signature against the identity fingerprint you pin and
    # refuses any other. None leaves the ladder ending at stage 7. Mirrors
    # `VerifierPolicy::trust_chain` in the Rust verifier.
    trust_chain: Optional[TrustChain] = None

    # The raw bytes of the customer's activity record
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

    Formula (Forever-Standard):
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


# Authority a proof anchors under when it carries no top-level `authority_id`
# (the Nanorix-hosted signing path).
DEFAULT_AUTHORITY_ID = "us-kms-nanorix-v1"


def _effective_authority_id(proof: Mapping[str, Any]) -> str:
    """The top-level `authority_id`, or DEFAULT_AUTHORITY_ID when absent or not a string."""
    value = proof.get("authority_id")
    return value if isinstance(value, str) else DEFAULT_AUTHORITY_ID


# Activity event an issuer writes when a capsule ran in diagnostic mode.
DIAGNOSTIC_MODE_EVENT = "diagnostic_mode_enabled"


def _records_diagnostic_mode(proof: Mapping[str, Any]) -> bool:
    """Whether the activity trail holds an entry whose `event` is DIAGNOSTIC_MODE_EVENT.

    The trail is signed only on 2.1 and 2.2 with a signature, so False proves
    nothing on 1.0 or on an unsigned 2.1 or 2.2 proof; the diagnostic gate
    refuses those outright for that reason. Mirrors Rust
    `records_diagnostic_mode`.
    """
    activity = proof.get("activity")
    if not isinstance(activity, list):
        return False
    return any(
        isinstance(event, Mapping) and event.get("event") == DIAGNOSTIC_MODE_EVENT
        for event in activity
    )


def _pointer_str(proof: Mapping[str, Any], parent: str, key: str) -> Optional[str]:
    """Read `proof[parent][key]` as a string, or None."""
    node = proof.get(parent)
    if isinstance(node, Mapping):
        value = node.get(key)
        if isinstance(value, str):
            return value
    return None


#: The byte strings that make an authority id customer-classified: the
#: issuer's own test, a substring match anywhere in the id, byte-exact and
#: case-sensitive, with no normalization.
CUSTOMER_AUTHORITY_SEGMENTS = (
    "customer-hsm-",
    "customer-kms-",
    "customer-tee-",
    "customer-byo-",
)


def is_customer_authority(authority_id: str) -> bool:
    """Whether ``authority_id`` is customer-classified.

    Every other id is Nanorix-classified.
    """
    return any(segment in authority_id for segment in CUSTOMER_AUTHORITY_SEGMENTS)


def signing_mode_authority_mismatch(
    proof: Mapping[str, Any], cdp_version: str
) -> Optional[FailureReason]:
    """The signing-mode consistency rule.

    On ``cdp_version`` 2.1 and 2.2, a ``signing_mode`` of exactly
    ``customer_only`` under a Nanorix-classified ``authority_id`` (an absent,
    null or non-string one included) is refused with
    ``signing_mode_authority_mismatch``. Returns None when the pair is
    consistent or the version signs neither label. The rule tests the two
    labels, not which key signed: a ``nanorix_only`` proof under a
    customer-classified authority passes (the amendment's "Legacy proofs").
    """
    if cdp_version not in _canonical.CANONICAL_VIEW_SIGNED_VERSIONS:
        return None
    if proof.get("signing_mode") != _canonical.SIGNING_MODE_CUSTOMER_ONLY:
        return None
    claimed = proof.get("authority_id")
    if isinstance(claimed, str) and is_customer_authority(claimed):
        return None
    return FailureReason(
        type=FailureReasonType.SIGNING_MODE_AUTHORITY_MISMATCH,
        claimed_authority_id=claimed if isinstance(claimed, str) else None,
    )


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
    """Mode A step 3 — recompute each receipt's chain hash + the root.

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
    """Recompute the parent-proof Merkle root and compare to claimed.

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

    Reference: the capsule runtime (the emitter) and
    ``tools/nanorix-verify/src/streaming_merkle.rs`` (the reference verifier).

    RFC 6962 §2.1 domain separation over SHA-512: empty leaf set is SHA-512 of
    the empty string; one leaf is ``SHA-512(0x00 || leaf)``; an inner node is
    ``SHA-512(0x01 || left || right)``; an odd tail node is promoted unchanged.
    Each leaf is the raw 64-byte SHA-512 of one chunk body, in ``seq`` order.

    Returns 128 lowercase hex characters, unprefixed.

    Forever-Standard: changing any of those three rules
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
    (reference: ``merkle_root_from_leaves`` in the capsule runtime).
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


def _hybrid_record_refusal(stage: int, meta: VerificationMetadata) -> VerificationResult:
    """The refusal a record gets under a hybrid pin, at the stage where it would
    otherwise have ended valid, signed or unsigned."""
    return VerificationResult(
        _valid=False,
        failure_reason=FailureReason(
            type=FailureReasonType.ALGORITHM_UNSUPPORTED,
            found=HYBRID_RECORD_CHECK_MISSING,
        ),
        stage_reached=stage,
        metadata=meta,
    )


def _anchor_to_trust_chain(
    proof: Mapping[str, Any],
    cdp_version: str,
    chain: TrustChain,
    meta: VerificationMetadata,
) -> VerificationResult:
    """Stage 8: resolve the signing key in the verified key list and re-check.

    Resolves the proof's `(authority_id, signing_key_version)` in the list
    (archived versions resolve too), checks the signature against the LISTED key
    rather than the key the proof carries, and refuses a revoked authority.
    Mirrors `anchor_to_trust_chain` in the Rust library: a chain that did not
    come from `TrustChain.from_key_list` was not checked against its pin, so a
    success ends at stage 7.
    """
    authority_id = _effective_authority_id(proof)
    attestation = proof.get("attestation")
    raw_version: Any = None
    if isinstance(attestation, dict) and "signing_key_version" in attestation:
        raw_version = attestation["signing_key_version"]
    elif "signing_key_version" in proof:
        raw_version = proof["signing_key_version"]
    version = raw_version if isinstance(raw_version, str) else ""

    listed = chain.find_key(authority_id, version)
    if listed is None:
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.SIGNING_KEY_VERSION_UNKNOWN, version=version
            ),
            stage_reached=6,
            metadata=meta,
        )
    public_key_b64, revoked = listed

    check = _canonical.verify_signature_against(proof, cdp_version, public_key_b64)
    if check.outcome is SignatureOutcome.FAILED:
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.SIGNATURE_MISMATCH, reason=check.reason
            ),
            stage_reached=7,
            metadata=meta,
        )
    if check.outcome is SignatureOutcome.UNSUPPORTED:
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.ALGORITHM_UNSUPPORTED,
                found=f"signing_mode={check.mode}",
            ),
            stage_reached=7,
            metadata=meta,
        )
    if check.outcome is SignatureOutcome.ABSENT:
        if is_hybrid_pin(chain.pinned_identity_fingerprint):
            return _hybrid_record_refusal(7, meta)
        return VerificationResult(_valid=True, failure_reason=None, stage_reached=7, metadata=meta)

    if revoked:
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(type=FailureReasonType.AUTHORITY_REVOKED),
            stage_reached=8,
            metadata=meta,
        )
    # A 1.0 signature covers final_hash alone, which binds destroyed_at and the
    # two optional Merkle roots. It does not bind the capsule_id itself (only
    # through record receipts, which a holder can remove), the region or the
    # key id. So a key list cannot tie it to a capsule: a 1.0 proof runs the
    # lookup, the re-verify and the revocation check above as 2.x does, and
    # where 2.x would reach stage 8 it ends at stage 7, never anchored. Under a
    # hybrid pin it is refused there, as every record is. Mirrors Rust.
    if cdp_version == "1.0":
        if is_hybrid_pin(chain.pinned_identity_fingerprint):
            return _hybrid_record_refusal(7, meta)
        return VerificationResult(_valid=True, failure_reason=None, stage_reached=7, metadata=meta)
    # the hybrid-pin gate: under a hybrid pin a record is
    # anchored only with its ML-DSA-65 half checked, which this verifier does
    # not do yet.
    if is_hybrid_pin(chain.pinned_identity_fingerprint):
        return _hybrid_record_refusal(8, meta)
    return VerificationResult(
        _valid=True,
        failure_reason=None,
        stage_reached=8 if type(chain) is TrustChain and chain._pin_checked else 7,
        metadata=meta,
    )


# serde_json, the parser in front of the Rust reference verifier, starts
# remaining_depth at 128 and refuses the container that brings it to zero, so
# 127 nested containers parse and 128 do not.
_REFERENCE_MAX_DEPTH = 127
_SURROGATE = re.compile("[\ud800-\udfff]")
_UNPARSEABLE = object()

# Matches a whole JSON string (so brackets inside it are skipped) or one
# bracket. The scan below runs on text json.loads already accepted.
_STRING_OR_BRACKET = re.compile(r'"(?:[^"\\]+|\\.)*"|[\[\]{}]', re.DOTALL)
# One escape at a time, so an escaped backslash is not read as the start of a
# \u escape. "pair" is a high surrogate escape followed at once by a low one;
# "lone" is a surrogate escape that is not part of such a pair.
_ESCAPE = re.compile(
    r"\\(?:(?P<pair>u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2})"
    r"|(?P<lone>u[dD][89a-fA-F][0-9a-fA-F]{2})|.)",
    re.DOTALL,
)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number the reference accepts")


def _reference_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("number past the 64-bit float range")
    return value


def _reference_int(token: str) -> int:
    value = int(token)
    try:
        float(value)
    except OverflowError:
        raise ValueError("integer past the 64-bit float range") from None
    return value


def _text_beyond_reference_parser(text: str) -> bool:
    """True if well-formed JSON ``text`` holds a nesting depth or a surrogate
    escape that serde_json refuses.

    This reads every copy of a repeated key, which ``json.loads`` does not keep.
    """
    if _SURROGATE.search(text) is not None:
        return True
    depth = 0
    for m in _STRING_OR_BRACKET.finditer(text):
        c = m.group()
        if c == "[" or c == "{":
            depth += 1
            if depth > _REFERENCE_MAX_DEPTH:
                return True
        elif c == "]" or c == "}":
            depth -= 1
        elif "\\" in c:
            for e in _ESCAPE.finditer(c):
                if e.lastgroup == "lone":
                    return True
    return False


def parse_document(raw: Union[bytes, bytearray, str]) -> Any:
    """Parse an AuditProof document from bytes or text.

    Bytes must be UTF-8: ``json.loads`` on bytes would also take a BOM, UTF-16,
    UTF-32 and surrogate code points, which the reference refuses. Raises
    ``ValueError`` or ``RecursionError`` for a document the reference refuses.
    ``json.loads`` keeps only the last copy of a repeated key, so the number
    hooks see every number as it is parsed and a scan of the text reads
    every nesting depth and surrogate escape, in earlier copies too. Repeated
    keys are not refused: serde_json keeps the last copy as well.
    """
    text = raw if isinstance(raw, str) else bytes(raw).decode("utf-8")
    value = json.loads(
        text,
        parse_constant=_reject_constant,
        parse_float=_reference_float,
        parse_int=_reference_int,
    )
    if _text_beyond_reference_parser(text):
        raise ValueError("nesting or surrogate escape the reference refuses")
    return value


def beyond_reference_parser(value: Any, depth: int = 0) -> bool:
    """True if ``value`` holds what serde_json refuses and ``json.loads`` keeps.

    That is a container nested deeper than ``_REFERENCE_MAX_DEPTH``, a string
    or key holding half of a surrogate pair (``json.loads`` joins a whole pair
    into one code point), and a number a 64-bit float cannot hold (``NaN``,
    ``Infinity``, ``1e400``, an integer past the float range).
    """
    if isinstance(value, str):
        return _SURROGATE.search(value) is not None
    if isinstance(value, (int, float)):
        try:
            return not math.isfinite(float(value))
        except OverflowError:
            return True
    if isinstance(value, (dict, list)):
        if depth >= _REFERENCE_MAX_DEPTH:
            return True
        if isinstance(value, dict):
            return any(
                beyond_reference_parser(k) or beyond_reference_parser(v, depth + 1)
                for k, v in value.items()
            )
        return any(beyond_reference_parser(v, depth + 1) for v in value)
    return False


def verify_auditproof(
    json_bytes: Union[bytes, str, Dict[str, Any]],
    policy: Optional[VerifierPolicy] = None,
) -> VerificationResult:
    """Verify an AuditProof through the stage ladder.

    Args:
        json_bytes: AuditProof as bytes, JSON string, or already-parsed dict.
            Give the file's bytes: a dict has lost the original bytes and the
            earlier copies of a repeated key, so a document the reference
            refuses can verify.
        policy: Optional VerifierPolicy for the authority-id and region pins,
            the `reject_diagnostic` setting, and `trust_chain` for stage 8.

    Returns:
        VerificationResult whose ``valid`` / ``failure_reason`` /
        ``stage_reached`` agree with the Rust reference verifier on every
        document in the reference corpus, given its bytes.

    An unsigned partial returns ``_valid=True`` at stage 4, which reads as
    "chain verified, signature NOT checked", except under a ``hybrid1-sha256:``
    pin (``policy.trust_chain`` loaded under one), where every record, signed
    or not, is refused with ``algorithm_unsupported``; a ``dual_signature`` /
    ``tee_attested`` proof is refused as ``algorithm_unsupported``. That is
    the reference verifier's honest verdict, not a pass. A valid stage 7 result
    is ``not_anchored``: the signature checks only against the key the proof
    carries, which a proof signed with a fresh key also does. Callers that gate
    on the result must require ``result.status == "verified"`` (or
    ``result.ok``), which needs ``policy.trust_chain`` and stage 8, never
    ``valid`` alone.
    """
    # Stage 0: parse JSON
    document: Any = json_bytes
    if isinstance(json_bytes, (bytes, bytearray, str)):
        try:
            document = parse_document(json_bytes)
        except (ValueError, RecursionError):
            document = _UNPARSEABLE
    return verify_document(document, policy)


def verify_document(document: Any, policy: Optional[VerifierPolicy] = None) -> VerificationResult:
    """Run the stage ladder on an already-parsed JSON value of any type.

    ``verify_auditproof`` parses bytes and text; this takes the parsed value, so
    a document whose top level is a JSON string is not parsed a second time.
    """
    pol = policy or VerifierPolicy()
    meta = VerificationMetadata()

    if document is _UNPARSEABLE or beyond_reference_parser(document):
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.REQUIRED_FIELD_MISSING,
                field="json_root",
            ),
            stage_reached=1,
            metadata=meta,
        )
    # A top-level value that is not an object parsed, so it is not json_root:
    # like the reference, it has no cdp_version.
    if not isinstance(document, dict):
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.REQUIRED_FIELD_MISSING,
                field="cdp_version",
            ),
            stage_reached=1,
            metadata=meta,
        )
    proof: Dict[str, Any] = document

    # Stage 1: schema — cdp_version present
    cdp_version = proof.get("cdp_version")
    if not isinstance(cdp_version, str):
        return VerificationResult(
            _valid=False,
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
            _valid=False,
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
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.UNSIGNED_FIELD_POPULATED,
                field=populated_slot,
            ),
            stage_reached=2,
            metadata=meta,
        )

    # customer_declared_activity_root shape gates. Off 2.1/2.2
    # the field is outside every signed view, so a populated one is the
    # reserved-slot shape above; on 2.1/2.2 it must be a string the recompute
    # can consume. Rejected here so no later stage ever reads a malformed root.
    activity_gate = customer_declared_activity_root_gate(proof, cdp_version)
    if activity_gate is not None:
        return VerificationResult(
            _valid=False, failure_reason=activity_gate, stage_reached=2, metadata=meta
        )

    # Populate metadata. The metadata names a capsule and a region only on a
    # version whose signature covers them. A 1.0 signature covers final_hash
    # alone, which binds destroyed_at and the two optional Merkle roots. It
    # does not bind the capsule_id itself (only through record receipts, which
    # a holder can remove), the region or the key id, so on 1.0 neither is
    # reported. The record-receipt check below hashes the capsule id as the
    # document states it, on every version.
    document_capsule_id = proof.get("capsule_id")
    if not isinstance(document_capsule_id, str):
        document_capsule_id = ""
    names_signed_fields = cdp_version in _canonical.CANONICAL_VIEW_SIGNED_VERSIONS
    # The region is read from the activity trail, so it is reported only when
    # the signature step below will check a signature over that trail: on a
    # proof without a signature or key, no return names it. Mirrors Rust.
    trail_checked = (
        names_signed_fields
        and _canonical.verify_signature(proof, cdp_version).outcome
        is not SignatureOutcome.ABSENT
    )
    if isinstance(proof.get("capsule_id"), str) and names_signed_fields:
        meta.capsule_id = proof["capsule_id"]
    # Region resolves from the capsule_started activity event only, on 2.1
    # and 2.2 carrying a signature. There the activity trail is inside
    # CanonicalCdpView, so a region carried there cannot be altered without
    # breaking the signature; an unsigned 2.1 or 2.2 proof reports no region.
    # `environment.region`
    # and top-level `region` are both outside the canonical hash — reading
    # either let an outsider satisfy a residency pin by appending a region to a
    # genuine signed proof, with no key. Mirrors the Rust, Go and TS verifiers.
    meta.region = None
    activity = proof.get("activity")
    if isinstance(activity, list) and trail_checked:
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

    # Policy-pin gate — authority ID.
    #
    # The pin is compared with the top-level `authority_id`; absent or
    # non-string means DEFAULT_AUTHORITY_ID. Only cdp_version 2.1 and 2.2 sign
    # that field (the canonical view binds it): 1.0 signs final_hash, so on 1.0
    # a top-level string other than DEFAULT_AUTHORITY_ID (the empty string
    # included) is refused first, claimed = that value, and the effective
    # authority can only be the default. 2.0 never reaches this gate: the
    # version gate above refuses it first. An unsigned
    # `signing_authority.authority_id` that differs from it is refused
    # (claimed = that value) and can never make a proof match;
    # `signing_authority` absent, null or without `authority_id` is ignored.
    # With the top-level field absent, a non-matching pin reports claimed None
    # and the has-none reason. A pin alone is never a full authority check;
    # `trust_chain` resolves the signing key in a signed key list (stage 8).
    #
    # Runs BEFORE the chain walk because the policy decision is independent of
    # chain validity: a customer who pinned the wrong authority should learn
    # that immediately, not after an 8-step SHA-512 walk.
    if pol.required_authority_id:
        top_level = proof.get("authority_id")
        effective = _effective_authority_id(proof)
        if (
            cdp_version not in _canonical.CANONICAL_VIEW_SIGNED_VERSIONS
            and isinstance(top_level, str)
            and top_level != DEFAULT_AUTHORITY_ID
        ):
            return VerificationResult(
                _valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.AUTHORITY_ID_MISMATCH,
                    claimed_authority_id=top_level,
                    expected_authority_id=pol.required_authority_id,
                    auth_id_reason="verifier_policy_authority_id_mismatch",
                ),
                stage_reached=2,
                metadata=meta,
            )
        unsigned_id = _pointer_str(proof, "signing_authority", "authority_id")
        if unsigned_id is not None and unsigned_id != effective:
            return VerificationResult(
                _valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.AUTHORITY_ID_MISMATCH,
                    claimed_authority_id=unsigned_id,
                    expected_authority_id=pol.required_authority_id,
                    auth_id_reason="verifier_policy_authority_id_mismatch",
                ),
                stage_reached=2,
                metadata=meta,
            )
        if effective != pol.required_authority_id:
            has_top_level = isinstance(top_level, str)
            return VerificationResult(
                _valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.AUTHORITY_ID_MISMATCH,
                    claimed_authority_id=top_level if has_top_level else None,
                    expected_authority_id=pol.required_authority_id,
                    auth_id_reason=(
                        "verifier_policy_authority_id_mismatch"
                        if has_top_level
                        else "verifier_policy_demands_customer_hsm_audit_proof_has_none"
                    ),
                ),
                stage_reached=2,
                metadata=meta,
            )

    # The residency pin and the diagnostic gate read the activity trail, so
    # each trusts it only when the signature step below will check a signature
    # over it: the version's signed message is the canonical view (2.1 / 2.2)
    # and that step does not end as ABSENT. A 1.0 trail, and the trail of a
    # 2.1 or 2.2 proof without a signature or key, is unsigned: anyone could
    # add a region equal to the pin, or delete a diagnostic_mode_enabled event,
    # and the proof would still verify. Computed only under a policy that reads
    # the trail. Mirrors Rust.
    trail_signed = (bool(pol.required_region) or pol.reject_diagnostic) and trail_checked

    # Residency-pin gate. A proof carrying no region at
    # all cannot satisfy a residency pin — it is rejected with an empty
    # `actual` rather than accepted, so the pin fails closed. Only a signed
    # region counts: on an unsigned trail the pin reads no region and refuses.
    if pol.required_region:
        if trail_signed:
            actual_region = meta.region or ""
        else:
            actual_region = ""
        if actual_region != pol.required_region:
            return VerificationResult(
                _valid=False,
                failure_reason=FailureReason(
                    type=FailureReasonType.REGION_MISMATCH,
                    required=pol.required_region,
                    actual=actual_region,
                ),
                stage_reached=2,
                metadata=meta,
            )

    # Diagnostic-mode gate, after the residency pin and before the
    # chain walk, like the other policy pins. A proof whose trail is unsigned
    # (1.0, or 2.1 or 2.2 without a signature) cannot show it was not run in
    # diagnostic mode, since the event could be deleted and the proof would
    # still verify: the setting refuses every one. Mirrors Rust.
    if pol.reject_diagnostic and (not trail_signed or _records_diagnostic_mode(proof)):
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(type=FailureReasonType.DIAGNOSTIC_PROOF_REFUSED),
            stage_reached=2,
            metadata=meta,
        )

    # Stage 3: chain reproducibility
    chain_raw = proof.get("chain")
    if not isinstance(chain_raw, list):
        return VerificationResult(
            _valid=False,
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
            _valid=False,
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

    # Optional Merkle roots amend step 8. Absent on
    # legacy proofs, where both branches collapse to the legacy formula.
    rrmr = proof.get("record_receipts_merkle_root")
    rrmr = rrmr if isinstance(rrmr, str) else None
    ppmr = proof.get("parent_proofs_merkle_root")
    ppmr = ppmr if isinstance(ppmr, str) else None

    prev_hash = GENESIS_HASH
    for idx, step_raw in enumerate(chain_raw):
        if not isinstance(step_raw, dict):
            return VerificationResult(
                _valid=False,
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
                _valid=False,
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
                _valid=False,
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
        failure = _verify_record_receipts(receipts, document_capsule_id, rrmr)
        if failure is not None:
            return VerificationResult(
                _valid=False, failure_reason=failure, stage_reached=3, metadata=meta
            )

    parents = proof.get("parent_proof_hashes")
    if isinstance(parents, list):
        failure = _verify_parent_proofs(parents, ppmr)
        if failure is not None:
            return VerificationResult(
                _valid=False, failure_reason=failure, stage_reached=3, metadata=meta
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
                _valid=False, failure_reason=failure, stage_reached=3, metadata=meta
            )

    # Customer-declared activity root. The root is canonical-bound, so
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
            _valid=False,
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
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.FINAL_HASH_MISMATCH,
                claimed=claimed_final,
                computed=last_chain_hash,
            ),
            stage_reached=4,
            metadata=meta,
        )

    # Algorithm dispatch precedes byte-shape checks: a proof
    # declaring a non-Ed25519 signature algorithm fails typed as
    # algorithm_unsupported here — it must never fall through to the 64/32-byte
    # decode gates and report as "malformed". Absent or "Ed25519" proceeds
    # unchanged (every proof issued to date).
    declared_algorithm = _declared_non_ed25519_algorithm(proof)
    if declared_algorithm is not None:
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.ALGORITHM_UNSUPPORTED,
                found=declared_algorithm,
            ),
            stage_reached=4,
            metadata=meta,
        )

    # The signing-mode consistency rule: after the
    # algorithm check and before the signature-presence check, so an unsigned
    # customer_only document under a Nanorix-classified authority is refused
    # too. Mirrors signing_mode_authority_mismatch in the Rust verifier.
    mismatch = signing_mode_authority_mismatch(proof, cdp_version)
    if mismatch is not None:
        return VerificationResult(
            _valid=False, failure_reason=mismatch, stage_reached=4, metadata=meta
        )

    # Stages 5-7: signature over the version/mode-appropriate message, checked
    # against the key EMBEDDED in the proof. This proves integrity — no signed
    # byte of the document has changed since signing — not authenticity.
    check = _canonical.verify_signature(proof, cdp_version)
    if check.outcome is SignatureOutcome.VERIFIED:
        if policy is not None and policy.trust_chain is not None:
            return _anchor_to_trust_chain(proof, cdp_version, policy.trust_chain, meta)
        return VerificationResult(_valid=True, failure_reason=None, stage_reached=7, metadata=meta)
    if check.outcome is SignatureOutcome.UNSUPPORTED:
        # The document declares a signing_mode this build cannot verify. NOT the
        # same as "no signature": signing_mode is inside the canonical hash and
        # is attacker-controllable, so treating an unrecognised mode as a partial
        # success turns a rejection into reassurance — a downgrade oracle.
        # algorithm_unsupported is the existing Forever-Standard reason for "this
        # build cannot perform the verification this document requires"; the
        # resolution (upgrade the verifier) is identical. Mirrors Rust and Go.
        return VerificationResult(
            _valid=False,
            failure_reason=FailureReason(
                type=FailureReasonType.ALGORITHM_UNSUPPORTED,
                found=f"signing_mode={check.mode}",
            ),
            stage_reached=4,
            metadata=meta,
        )
    if check.outcome is SignatureOutcome.ABSENT:
        # Under a hybrid pin an unsigned record is refused here, not left
        # valid with its signature unchecked.
        if (
            policy is not None
            and policy.trust_chain is not None
            and is_hybrid_pin(policy.trust_chain.pinned_identity_fingerprint)
        ):
            return _hybrid_record_refusal(4, meta)
        # No signature covers the activity trail here, so the region read from
        # it is not reported.
        meta.region = None
        return VerificationResult(_valid=True, failure_reason=None, stage_reached=4, metadata=meta)
    return VerificationResult(
        _valid=False,
        failure_reason=FailureReason(
            type=FailureReasonType.SIGNATURE_MISMATCH,
            reason=check.reason,
        ),
        stage_reached=7,
        metadata=meta,
    )
