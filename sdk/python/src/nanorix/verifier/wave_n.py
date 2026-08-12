"""
the receipt pipeline (the per-record receipt specification + the receipt-batching specification) per-record receipt + parent-proof verification.

Pure Python port of the reference chain implementation plus the verifier-side
extension in `tools/nanorix-verify/src/lib.rs`. Cross-impl byte-equivalent
with Rust + Go ports on the 110-fixture extended corpus.

**Forever-Standard discipline (the Forever-Standard wire discipline):** every primitive here is part
of the cryptographic-attestation contract. Cross-impl divergence from the
canonical Rust output is a P0 finding.

**Distinct from `nanorix._merkle`**: that module implements RFC 6962 binary
Merkle (leaf prefix 0x00 + inner prefix 0x01) used by `Capsule.batch()`.
the receipt pipeline uses the per-record receipt specification canonical pair-hash form:
`SHA-512(left_hex_bytes || \\x00 || right_hex_bytes)` with NO domain prefix,
because the children are themselves already SHA-512 outputs serialized as hex.

Cross-impl reference vectors (locked in `test_verifier_wave_n.py`):

  GENESIS_SHA512_HEX = cf83e1...da3e
  merkle_pair_hash("aaa", "bbb") = 04ed285c...bf9bd264
  compute_step_8_amended(GENESIS, "2026-05-12T00:00:00Z", None, None) = 3b6a0c8f...129b3fbf
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Genesis SHA-512 hash of the empty string. Re-exported here so this module is
# self-contained — mirrors Rust the reference chain implementation512_HEX`.
GENESIS_SHA512_HEX = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)

# Pre-the receipt pipeline legacy formula constants — must remain in lockstep with
# the chain specification::compute_step_hash` Step 8 arguments.
_STEP_8_SUBSYSTEM = "capsule_destroy"
_STEP_8_ACTION = "destroy"
_STEP_8_METHOD = "capsule_lifecycle_verification"

# Maximum supported parent-proof chain depth per the receipt-batching specification §"Depth limit".
PARENT_PROOF_MAX_DEPTH = 32

# Closed-enum pattern tag wire values (mirror Rust
# the reference chain implementation and `nanorix.capsule_record.PATTERN_TAGS`).
# Used by downstream consumers; the verifier itself does NOT reject unknown
# pattern_tag values (forward-compatibility per the Forever-Standard wire discipline).
PATTERN_TAGS_WIRE = frozenset(
    [
        "pa",
        "extraction",
        "annotation",
        "agent_step",
        "agent_turn",
        "rcm_claim",
        "rcm_eligibility",
        "rcm_remit",
        "ncpdp_script",
        "dicom_study",
        "dicom_sr",
        "screening_hit",
        "fhir_record",
        "ehr_document",
        "custom",
    ]
)


# ─────────────────────────────────────────────────────────────────────────────
# the receipt pipeline types — mirror the reference chain implementation{RecordReceipt, ParentProofLink}`.
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class RecordReceipt:
    """Per-record receipt mirroring Rust `RecordReceipt`.

    Forever-Standard discipline (the Forever-Standard wire discipline): field shape is permanent.
    New fields land as additive Optional — existing fields NEVER renamed,
    NEVER removed, NEVER repurposed.

    **No `control_tags` field by design.** Per the per-record receipt specification §"Receipt as direct
    evidence primitive" + the specification RE-SCOPED: control IDs are NEVER stamped
    into the signed receipt; adapters apply the specification mapping artifact at
    ingestion time.
    """

    record_index: int
    record_id: str
    record_input_hash: str
    record_output_hash: str
    record_chain_hash: str
    record_activity_trail: Optional[List[Any]] = None
    pattern_tag: Optional[str] = None
    merkle_inclusion_proof: List[str] = field(default_factory=list)


@dataclass
class ParentProofLink:
    """Cross-org parent-proof link mirroring Rust `ParentProofLink`.

    Forever-Standard (the Forever-Standard wire discipline): optional fields skip-serialize when None.
    """

    parent_chain_hash: str
    parent_key_id: str
    parent_signature: str
    parent_role: Optional[str] = None
    parent_jurisdiction: Optional[str] = None
    parent_organization_tag: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Prefix helpers
# ─────────────────────────────────────────────────────────────────────────────


def _strip_sha512_prefix(s: str) -> str:
    """Strip leading `sha512:` from a hash string. Idempotent."""
    if isinstance(s, str) and s.startswith("sha512:"):
        return s[len("sha512:") :]
    return s


def _strip_base64_prefix(s: str) -> str:
    """Strip leading `base64:` from a base64-encoded string. Idempotent."""
    if isinstance(s, str) and s.startswith("base64:"):
        return s[len("base64:") :]
    return s


# ─────────────────────────────────────────────────────────────────────────────
# Merkle pair-hash + root construction (the per-record receipt specification)
# ─────────────────────────────────────────────────────────────────────────────


def merkle_pair_hash(left: str, right: str) -> str:
    """Compute `SHA-512(left_hex_bytes || \\x00 || right_hex_bytes)`.

    Per the per-record receipt specification §"Sibling pair hashing rule": both inputs are interpreted as
    their hex-string byte values (UTF-8 of the hex chars). Either MAY carry
    a `sha512:` prefix; stripped before hashing.

    Output: lowercase 128-char hex (no prefix). Cross-impl byte-equivalent
    with Rust `merkle_pair_hash` in the reference chain implementation.
    """
    left_s = _strip_sha512_prefix(left)
    right_s = _strip_sha512_prefix(right)
    return hashlib.sha512(left_s.encode("utf-8") + b"\x00" + right_s.encode("utf-8")).hexdigest()


def merkle_root_sha512_null_separated(leaves: Sequence[str]) -> Optional[str]:
    """Build the canonical Merkle root over `leaves` per the per-record receipt specification §"Merkle tree
    construction".

    - N=0 → None
    - N=1 → leaves[0] with `sha512:` prefix stripped
    - N≥2 → binary tree with odd-level duplication

    Output: bare lowercase hex (no `sha512:` prefix); caller prepends for
    wire form. Cross-impl byte-equivalent with Rust counterpart.
    """
    if not leaves:
        return None
    if len(leaves) == 1:
        return _strip_sha512_prefix(leaves[0])
    level: List[str] = [_strip_sha512_prefix(h) for h in leaves]
    while len(level) > 1:
        nxt: List[str] = []
        i = 0
        while i < len(level):
            if i + 1 < len(level):
                nxt.append(merkle_pair_hash(level[i], level[i + 1]))
                i += 2
            else:
                # Odd-level last node: duplicate per the per-record receipt specification.
                nxt.append(merkle_pair_hash(level[i], level[i]))
                i += 1
        level = nxt
    return level[0]


def compute_record_receipts_merkle_root(
    receipts: Sequence[RecordReceipt],
) -> Optional[str]:
    """Public the per-record receipt specification surface for the receipt Merkle root.

    Returns `None` for empty input (field skip-serializes in canonical JSON);
    otherwise returns `sha512:{hex}` matching the per-record receipt specification wire form.
    """
    if not receipts:
        return None
    leaves = [r.record_chain_hash for r in receipts]
    root = merkle_root_sha512_null_separated(leaves)
    return f"sha512:{root}" if root is not None else None


def compute_parent_proofs_merkle_root(
    parents: Sequence[ParentProofLink],
) -> Optional[str]:
    """Public the receipt-batching specification surface for the parent-proof Merkle root."""
    if not parents:
        return None
    leaves = [p.parent_chain_hash for p in parents]
    root = merkle_root_sha512_null_separated(leaves)
    return f"sha512:{root}" if root is not None else None


def build_merkle_inclusion_proof(
    leaves: Sequence[str], leaf_index: int
) -> Optional[List[str]]:
    """Build a Merkle inclusion proof for `leaf_index` per the per-record receipt specification.

    Returns siblings on the path from leaf → root in bottom-up order (each
    as bare hex). Empty list when N=1. None when out of range or empty.
    """
    if not leaves or leaf_index < 0 or leaf_index >= len(leaves):
        return None
    if len(leaves) == 1:
        return []
    level: List[str] = [_strip_sha512_prefix(h) for h in leaves]
    proof: List[str] = []
    idx = leaf_index
    while len(level) > 1:
        if idx % 2 == 0:
            sibling_idx = idx + 1 if idx + 1 < len(level) else idx
        else:
            sibling_idx = idx - 1
        proof.append(level[sibling_idx])

        nxt: List[str] = []
        i = 0
        while i < len(level):
            if i + 1 < len(level):
                nxt.append(merkle_pair_hash(level[i], level[i + 1]))
                i += 2
            else:
                nxt.append(merkle_pair_hash(level[i], level[i]))
                i += 1
        level = nxt
        idx //= 2
    return proof


def verify_merkle_inclusion_proof(
    leaf: str, leaf_index: int, proof: Sequence[str], claimed_root: str
) -> bool:
    """Recompute root from leaf + proof + leaf_index; compare to claimed."""
    leaf_stripped = _strip_sha512_prefix(leaf)
    claimed_stripped = _strip_sha512_prefix(claimed_root)

    # N=1 fast path: leaf IS root.
    if not proof:
        return leaf_stripped == claimed_stripped

    current = leaf_stripped
    idx = leaf_index
    for sibling in proof:
        if idx % 2 == 0:
            current = merkle_pair_hash(current, sibling)
        else:
            current = merkle_pair_hash(sibling, current)
        idx //= 2
    return current == claimed_stripped


# ─────────────────────────────────────────────────────────────────────────────
# JCS canonical bytes (RFC 8785) — minimal, byte-equivalent with serde_jcs.
# ─────────────────────────────────────────────────────────────────────────────


def _jcs_canonicalize(value: Any) -> bytes:
    """Minimal RFC 8785 JSON canonicalization.

    Cross-impl byte-equivalent with `serde_jcs::to_vec` for the activity-event
    canonical forms emitted by the reference chain implementation.
    Mirror of the Go port's `JCSCanonicalize` minus stream-decoding overhead;
    Python's `json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False)`
    matches JCS for the value types the receipt pipeline receipts emit (objects of scalar /
    array members).

    For non-trivial JCS edge cases (string control-char escaping, number
    canonicalization), this implementation follows the JCS spec exactly via
    the recursive emitter below.
    """
    # `sort_keys=True` + UTF-16 code-unit sort: for ASCII-only keys these
    # match, which is the case for every wave-N activity event in production.
    # Numeric handling uses Python's shortest-round-trip via `repr` of float;
    # integer values keep their integer form.
    return _jcs_emit(value).encode("utf-8")


def _jcs_emit(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value:  # NaN
            raise ValueError("JCS: NaN not allowed")
        if value == 0.0:
            return "0"
        s = repr(value)
        # Python's repr uses 'e+' / 'e-'; JCS strips the '+' on positive exponents.
        if "e+" in s:
            s = s.replace("e+", "e")
        return s
    if isinstance(value, str):
        return _jcs_emit_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_emit(e) for e in value) + "]"
    if isinstance(value, Mapping):
        # Sort by UTF-16 code units — for ASCII keys this matches str sort.
        items = sorted(value.items(), key=lambda kv: kv[0])
        return (
            "{"
            + ",".join(
                f"{_jcs_emit_string(k)}:{_jcs_emit(v)}" for k, v in items
            )
            + "}"
        )
    raise TypeError(f"JCS: unsupported type {type(value).__name__}")


def _jcs_emit_string(s: str) -> str:
    """Emit a JSON string with JCS minimal escape set per RFC 8785 §3.2.2.2."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append("\\\"")
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        elif cp < 0x10000:
            out.append(ch)
        else:
            # Surrogate pair encoding for code points > U+FFFF.
            cp_adj = cp - 0x10000
            high = 0xD800 + (cp_adj >> 10)
            low = 0xDC00 + (cp_adj & 0x3FF)
            out.append(f"\\u{high:04x}\\u{low:04x}")
    out.append('"')
    return "".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Activity root (per-record SHA-512 chain over canonical JCS events)
# ─────────────────────────────────────────────────────────────────────────────


def compute_activity_root(trail: Optional[Sequence[Any]]) -> str:
    """Compute per-record activity root mirroring Rust `compute_activity_root`.

    SHA-512 chain over canonical-JSON event hashes; genesis hash when trail
    is None / empty. Returns lowercase 128-char hex (no prefix).
    """
    if not trail:
        return GENESIS_SHA512_HEX
    prev = GENESIS_SHA512_HEX
    for event in trail:
        canonical_bytes = _jcs_canonicalize(event)
        event_hash = hashlib.sha512(canonical_bytes).hexdigest()
        prev = hashlib.sha512(
            prev.encode("utf-8") + b"\x00" + event_hash.encode("utf-8")
        ).hexdigest()
    return prev


# ─────────────────────────────────────────────────────────────────────────────
# Record chain hash (the per-record receipt specification per-record chain hash formula)
# ─────────────────────────────────────────────────────────────────────────────


def compute_record_chain_hash(
    capsule_id: str,
    record_index: int,
    record_id: str,
    record_input_hash: str,
    record_output_hash: str,
    activity_root_or_genesis: str,
    pattern_tag_wire: Optional[str] = None,
) -> str:
    """Compute per-record chain hash mirroring Rust `compute_record_chain_hash`.

    `pattern_tag_wire` is the snake_case wire string exactly as serialized in
    the receipt JSON `pattern_tag` field; the trailing `\\x00 || pattern_tag_wire`
    segment is appended ONLY when the receipt declares a tag (the per-record receipt specification — the
    tag is a signed primitive, so it must bind into the chain hash). Domain
    separation is sound because `activity_root_or_genesis` is always exactly
    128 stripped hex chars: a tagged preimage is strictly longer than every
    untagged preimage, so the conditional append cannot collide. Untagged
    receipts keep the pre-fix byte formula (clean-cut; zero external
    consumers at fix time).

    Returns chain hash WITH `sha512:` prefix — directly assignable to
    `RecordReceipt.record_chain_hash`.
    """
    in_h = _strip_sha512_prefix(record_input_hash)
    out_h = _strip_sha512_prefix(record_output_hash)
    act_h = _strip_sha512_prefix(activity_root_or_genesis)
    idx = str(record_index)

    parts = [
        capsule_id.encode("utf-8"),
        b"\x00",
        idx.encode("utf-8"),
        b"\x00",
        record_id.encode("utf-8"),
        b"\x00",
        in_h.encode("utf-8"),
        b"\x00",
        out_h.encode("utf-8"),
        b"\x00",
        act_h.encode("utf-8"),
    ]
    if pattern_tag_wire is not None:
        parts.append(b"\x00")
        parts.append(pattern_tag_wire.encode("utf-8"))
    digest = hashlib.sha512(b"".join(parts)).hexdigest()
    return f"sha512:{digest}"


# ─────────────────────────────────────────────────────────────────────────────
# Step 8 base + amended (presence-conditional 4-arm formula)
# ─────────────────────────────────────────────────────────────────────────────


def _compute_step_hash(
    prev_hash: str, subsystem: str, action: str, method: str, timestamp: str
) -> str:
    """Pre-the receipt pipeline legacy chain-step formula. Mirrors Rust `compute_step_hash`."""
    parts = [
        prev_hash.encode("utf-8"),
        b"\x00",
        subsystem.encode("utf-8"),
        b"\x00",
        action.encode("utf-8"),
        b"\x00",
        method.encode("utf-8"),
        b"\x00",
        timestamp.encode("utf-8"),
    ]
    return hashlib.sha512(b"".join(parts)).hexdigest()


def compute_step_8_base(prev_hash: str, timestamp: str) -> str:
    """Pre-the receipt pipeline legacy Step 8 hash (no amendment). Mirrors Rust
    `compute_step_8_base`."""
    return _compute_step_hash(
        prev_hash, _STEP_8_SUBSYSTEM, _STEP_8_ACTION, _STEP_8_METHOD, timestamp
    )


def compute_step_8_amended(
    prev_hash: str,
    timestamp: str,
    record_receipts_merkle_root: Optional[str],
    parent_proofs_merkle_root: Optional[str],
) -> str:
    """The presence-conditional Step 8 amendment formula (the per-record receipt specification + the receipt-batching specification).

    Mirrors Rust `compute_step_8_amended`. Output: bare lowercase hex.

    **Forever-Standard (the Forever-Standard wire discipline):** the (None, None) branch returns
    `compute_step_8_base(...)` UNMODIFIED — byte-identical to every
    pre-the receipt pipeline production AuditProof.
    """
    base = compute_step_8_base(prev_hash, timestamp)
    rr = record_receipts_merkle_root
    pp = parent_proofs_merkle_root

    if rr is None and pp is None:
        return base
    if rr is not None and pp is None:
        rr_stripped = _strip_sha512_prefix(rr)
        return hashlib.sha512(
            base.encode("utf-8") + b"\x00" + rr_stripped.encode("utf-8")
        ).hexdigest()
    if rr is None and pp is not None:
        pp_stripped = _strip_sha512_prefix(pp)
        return hashlib.sha512(
            base.encode("utf-8") + b"\x00" + pp_stripped.encode("utf-8")
        ).hexdigest()
    # both
    rr_stripped = _strip_sha512_prefix(rr)  # type: ignore[arg-type]
    pp_stripped = _strip_sha512_prefix(pp)  # type: ignore[arg-type]
    return hashlib.sha512(
        base.encode("utf-8")
        + b"\x00"
        + rr_stripped.encode("utf-8")
        + b"\x00"
        + pp_stripped.encode("utf-8")
    ).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Cycle prevention + depth cap
# ─────────────────────────────────────────────────────────────────────────────


def detect_parent_proof_cycle(
    parents: Sequence[ParentProofLink], self_chain_hash: str
) -> Optional[int]:
    """Reject cycles per the receipt-batching specification §"Cycle prevention".

    Returns the index of the cyclic parent if any `parent_chain_hash` equals
    `self_chain_hash`; returns None otherwise. Both inputs prefix-tolerant.
    """
    self_stripped = _strip_sha512_prefix(self_chain_hash)
    for i, p in enumerate(parents):
        if _strip_sha512_prefix(p.parent_chain_hash) == self_stripped:
            return i
    return None


def enforce_depth_cap(parents: Sequence[ParentProofLink]) -> None:
    """Raise ValueError if parent count exceeds PARENT_PROOF_MAX_DEPTH=32."""
    if len(parents) > PARENT_PROOF_MAX_DEPTH:
        raise ValueError(
            f"parent chain depth {len(parents)} exceeds "
            f"PARENT_PROOF_MAX_DEPTH={PARENT_PROOF_MAX_DEPTH} (the receipt-batching specification)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Mode B — Standalone receipt verification
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class WaveNVerifyError(Exception):
    """Raised when a the receipt pipeline verification step fails. Carries a stage hint and
    a short reason string for diagnostics."""

    reason: str
    stage: str = "wave_n"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.stage}] {self.reason}"


def verify_record_receipt(
    receipt: RecordReceipt,
    *,
    capsule_id: str,
    outer_merkle_root: str,
    outer_chain_hash: str,
    outer_signature_b64: str,
    outer_public_key: Ed25519PublicKey,
) -> None:
    """Mode B (standalone) verification per the per-record receipt specification.

    1. Recompute `record_chain_hash` from receipt fields + capsule_id.
    2. Verify Merkle inclusion proof binds receipt → outer_merkle_root.
    3. Verify outer Ed25519 signature over outer_chain_hash ASCII-hex.

    Raises WaveNVerifyError on first failure.
    """
    # (1) Chain hash recompute.
    activity_root = compute_activity_root(receipt.record_activity_trail)
    recomputed = compute_record_chain_hash(
        capsule_id,
        receipt.record_index,
        receipt.record_id,
        receipt.record_input_hash,
        receipt.record_output_hash,
        activity_root,
        pattern_tag_wire=receipt.pattern_tag,
    )
    if _strip_sha512_prefix(recomputed) != _strip_sha512_prefix(receipt.record_chain_hash):
        raise WaveNVerifyError(
            reason=f"record_chain_hash mismatch: recomputed={recomputed} claimed={receipt.record_chain_hash}",
            stage="record_chain_hash",
        )

    # (2) Merkle inclusion proof binds to outer root.
    if not verify_merkle_inclusion_proof(
        receipt.record_chain_hash,
        receipt.record_index,
        receipt.merkle_inclusion_proof,
        outer_merkle_root,
    ):
        raise WaveNVerifyError(
            reason=f"merkle inclusion proof does NOT bind receipt to outer root {outer_merkle_root}",
            stage="merkle_inclusion",
        )

    # (3) Outer Ed25519 signature over outer_chain_hash ASCII-hex.
    sig_raw = _strip_base64_prefix(outer_signature_b64)
    try:
        sig_bytes = base64.b64decode(sig_raw)
    except (ValueError, TypeError) as e:
        raise WaveNVerifyError(
            reason=f"outer signature base64 decode failed: {e}",
            stage="signature_decode",
        ) from e
    chain_hash_ascii = _strip_sha512_prefix(outer_chain_hash).encode("ascii")
    try:
        outer_public_key.verify(sig_bytes, chain_hash_ascii)
    except InvalidSignature as e:
        raise WaveNVerifyError(
            reason="outer Ed25519 signature does NOT verify against outer chain_hash",
            stage="signature_verify",
        ) from e


# ─────────────────────────────────────────────────────────────────────────────
# Mode A — Full the receipt pipeline AuditProof verification (extends V1 chain pipeline)
# ─────────────────────────────────────────────────────────────────────────────

# Canonical 8-step subsystem order (mirrors `nanorix.verifier._verify`).
_CANONICAL_SUBSYSTEMS = [
    "eee_namespace",
    "eee_tmpfs",
    "eee_memory",
    "dire_keys",
    "dire_identity",
    "fgx_forensic",
    "rzl_audit",
    "capsule_destroy",
]

_CANONICAL_METHODS = {
    "eee_namespace": "procfs_verification",
    "eee_tmpfs": "mountinfo_verification",
    "eee_memory": "dod_5220_multipass_wipe",
    "dire_keys": "ed25519_key_destruction",
    "dire_identity": "credential_incineration",
    "fgx_forensic": "merkle_tree_verification",
    "rzl_audit": "hash_chain_validation",
    "capsule_destroy": "capsule_lifecycle_verification",
}


@dataclass
class WaveNVerifyResult:
    """Result of `verify_full_audit_proof`. Carries a structural success / fail
    + a short reason string for diagnostics.

    For full V1 8-stage result detail (closed-set FailureReason), callers
    should use `nanorix.verifier.verify` (`_verify.py`) which doesn't yet
    surface the receipt pipeline fields. This module's `verify_full_audit_proof` extends
    V1 to handle the receipt pipeline fields with the same `valid: bool` contract.
    """

    valid: bool
    failure_reason: str = ""
    stage_reached: int = 0


def _verify_record_receipts_array(
    receipts: Sequence[Dict[str, Any]],
    capsule_id: str,
    claimed_root: Optional[str],
) -> Optional[str]:
    """Recompute each receipt's chain hash + Merkle root; compare to claimed.

    Returns None on success, error string on first failure.
    """
    if claimed_root is None:
        return None  # No claimed root; nothing to bind against.

    leaf_chain_hashes: List[str] = []
    for i, receipt in enumerate(receipts):
        record_index = int(receipt.get("record_index", 0))
        record_id = str(receipt.get("record_id", ""))
        in_h = str(receipt.get("record_input_hash", ""))
        out_h = str(receipt.get("record_output_hash", ""))
        claimed_chain = str(receipt.get("record_chain_hash", ""))
        trail = receipt.get("record_activity_trail")
        # Wire form exactly as serialized in the receipt JSON "pattern_tag"
        # field. Enum wire forms are never empty, so "" is treated as
        # undeclared (mirrors Rust Option<PatternTag> — None skip-serializes).
        tag_raw = receipt.get("pattern_tag")
        pattern_tag = tag_raw if isinstance(tag_raw, str) and tag_raw else None

        activity_root = (
            compute_activity_root(trail)
            if isinstance(trail, list) and len(trail) > 0
            else GENESIS_SHA512_HEX
        )
        recomputed = compute_record_chain_hash(
            capsule_id,
            record_index,
            record_id,
            in_h,
            out_h,
            activity_root,
            pattern_tag_wire=pattern_tag,
        )
        if _strip_sha512_prefix(recomputed) != _strip_sha512_prefix(claimed_chain):
            return f"record_receipt[{i}] chain hash mismatch"
        leaf_chain_hashes.append(_strip_sha512_prefix(recomputed))

    recomputed_root = merkle_root_sha512_null_separated(leaf_chain_hashes) or ""
    if recomputed_root != _strip_sha512_prefix(claimed_root):
        return (
            f"record_receipts_merkle_root mismatch: "
            f"claimed={claimed_root} computed=sha512:{recomputed_root}"
        )
    return None


def _verify_parent_proofs_array(
    parents: Sequence[Dict[str, Any]], claimed_root: Optional[str]
) -> Optional[str]:
    """Recompute parent Merkle root over each parent_chain_hash; compare."""
    if claimed_root is None:
        return None
    leaves = [str(p.get("parent_chain_hash", "")) for p in parents]
    recomputed = merkle_root_sha512_null_separated(leaves) or ""
    if recomputed != _strip_sha512_prefix(claimed_root):
        return (
            f"parent_proofs_merkle_root mismatch: "
            f"claimed={claimed_root} computed=sha512:{recomputed}"
        )
    return None


def verify_full_audit_proof(proof: Mapping[str, Any]) -> WaveNVerifyResult:
    """Mode A — full the receipt pipeline AuditProof verification.

    Extends the V1 8-stage pipeline with:
    - Step 8 amended chain walk (the per-record receipt specification + the receipt-batching specification 4-arm formula)
    - Per-receipt chain hash roundtrip
    - record_receipts_merkle_root binding
    - parent_proofs_merkle_root binding
    - parent depth-cap-32 enforcement

    Forever-Standard: pre-the receipt pipeline AuditProofs (no record_receipts, no
    parent_proof_hashes) verify byte-identically via the (None, None) Step 8
    branch collapsing to the legacy formula.
    """
    # Stage 1-2: cdp_version present + recognized.
    cdp_version = proof.get("cdp_version")
    if not isinstance(cdp_version, str):
        return WaveNVerifyResult(valid=False, failure_reason="cdp_version missing", stage_reached=1)
    if cdp_version not in {"1.0", "2.0", "2.1"}:
        return WaveNVerifyResult(
            valid=False, failure_reason=f"cdp_version unsupported: {cdp_version}", stage_reached=2
        )

    chain = proof.get("chain")
    if not isinstance(chain, list):
        return WaveNVerifyResult(valid=False, failure_reason="chain missing", stage_reached=3)
    if len(chain) != 8:
        return WaveNVerifyResult(
            valid=False, failure_reason=f"chain step count {len(chain)} != 8", stage_reached=3
        )

    timestamp = proof.get("destroyed_at", "")
    if not isinstance(timestamp, str):
        timestamp = ""

    # the receipt pipeline — optional Merkle roots.
    rrmr = proof.get("record_receipts_merkle_root")
    ppmr = proof.get("parent_proofs_merkle_root")
    rrmr_str: Optional[str] = rrmr if isinstance(rrmr, str) else None
    ppmr_str: Optional[str] = ppmr if isinstance(ppmr, str) else None

    prev_hash = GENESIS_SHA512_HEX
    for idx, step in enumerate(chain):
        subsystem = step.get("subsystem", "")
        claimed_chain_hash = step.get("chain_hash", "")
        method = _CANONICAL_METHODS.get(subsystem, "")
        if idx == 7 and subsystem == "capsule_destroy":
            recomputed = compute_step_8_amended(prev_hash, timestamp, rrmr_str, ppmr_str)
        else:
            recomputed = _compute_step_hash(prev_hash, subsystem, "destroy", method, timestamp)
        if recomputed != _strip_sha512_prefix(claimed_chain_hash):
            return WaveNVerifyResult(
                valid=False,
                failure_reason=f"chain step {idx} ({subsystem}) hash mismatch",
                stage_reached=3,
            )
        prev_hash = recomputed

    # the per-record receipt specification receipt-set verification.
    capsule_id = str(proof.get("capsule_id", ""))
    if isinstance(proof.get("record_receipts"), list):
        err = _verify_record_receipts_array(proof["record_receipts"], capsule_id, rrmr_str)
        if err is not None:
            return WaveNVerifyResult(valid=False, failure_reason=err, stage_reached=3)

    # the receipt-batching specification parent-proof set verification.
    parents = proof.get("parent_proof_hashes")
    if isinstance(parents, list):
        err = _verify_parent_proofs_array(parents, ppmr_str)
        if err is not None:
            return WaveNVerifyResult(valid=False, failure_reason=err, stage_reached=3)
        if len(parents) > PARENT_PROOF_MAX_DEPTH:
            return WaveNVerifyResult(
                valid=False,
                failure_reason=f"parent_proof_hashes depth {len(parents)} exceeds {PARENT_PROOF_MAX_DEPTH}",
                stage_reached=3,
            )

    # Stage 4: final_hash binding.
    claimed_final = proof.get("final_hash", "")
    last_chain_hash = chain[-1].get("chain_hash", "") if isinstance(chain[-1], dict) else ""
    if _strip_sha512_prefix(claimed_final) != _strip_sha512_prefix(last_chain_hash):
        return WaveNVerifyResult(
            valid=False,
            failure_reason=f"final_hash mismatch: claimed={claimed_final} computed={last_chain_hash}",
            stage_reached=4,
        )

    return WaveNVerifyResult(valid=True, stage_reached=4)


__all__ = [
    "GENESIS_SHA512_HEX",
    "PARENT_PROOF_MAX_DEPTH",
    "PATTERN_TAGS_WIRE",
    "RecordReceipt",
    "ParentProofLink",
    "WaveNVerifyError",
    "WaveNVerifyResult",
    "merkle_pair_hash",
    "merkle_root_sha512_null_separated",
    "compute_record_receipts_merkle_root",
    "compute_parent_proofs_merkle_root",
    "build_merkle_inclusion_proof",
    "verify_merkle_inclusion_proof",
    "compute_activity_root",
    "compute_record_chain_hash",
    "compute_step_8_base",
    "compute_step_8_amended",
    "detect_parent_proof_cycle",
    "enforce_depth_cap",
    "verify_record_receipt",
    "verify_full_audit_proof",
]


# Helper for inline JSON-canonical bytes if a caller needs to anchor
# event-hash semantics independently.
def _canonical_event_hash(event: Any) -> str:  # pragma: no cover - convenience
    """Return SHA-512 hex of canonical JCS bytes for a single activity event."""
    return hashlib.sha512(_jcs_canonicalize(event)).hexdigest()


# json import retained at top for fixture loading in tests; ensure module-level
# `json` symbol resolves for callers that re-export.
_ = json
