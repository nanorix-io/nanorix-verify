"""
Core verification logic — the convenience wrapper over the stage ladder.

The verification itself lives in `nanorix.verifier._ladder`, the single Python
implementation, held to the pinned reference corpus at
`tools/nanorix-verify/fixtures/corpus/`. This module adds the ergonomic
`verify(proof)` surface: flexible input (dict / JSON string / path / bytes) and
a flat result object.

## The chain hash formula (Forever-Standard)

    chain_hash[n] = SHA-512(prev \\x00 subsystem \\x00 "destroy"
                            \\x00 method \\x00 timestamp)

Genesis (prev for step 1) = SHA-512("").

`method` is a FIXED per-step canonical constant derived from the subsystem
name, and `timestamp` is the document's `destroyed_at` — the same value for
every step. Neither is a per-step JSON field: a production `CdpChainStep`
carries only `step`, `subsystem`, `operation`, `evidence_hash`, and
`chain_hash`. `operation` is descriptive and does NOT participate in the hash;
the action segment is always the literal `"destroy"`.

## The signed message is version-dependent

v1.0 signs `final_hash`. v2.1 `nanorix_only` — what production emits — signs
the canonical-view hash. Verifying a v2.1 proof against
`final_hash` never validates. cdp_version 2.0 is retired and refused at the
version gate. See `_canonical.py`.

The signature covers the ASCII hex characters of that hash (128 bytes), not
its 64 raw digest bytes.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from nanorix.verifier._canonical import strip_base64_prefix, strip_hash_prefix
from nanorix.verifier._ladder import (
    CANONICAL_SUBSYSTEMS,
    GENESIS_HASH,
    STATUS_NOT_ANCHORED,
    STATUS_NOT_VERIFIED,
    STATUS_VERIFIED,
    FailureReasonType,
    VerifierPolicy,
    VerifyStatus,
    compute_step_hash,
    parse_document,
    verification_status_for,
    verify_document,
)

__all__ = [
    "GENESIS_HASH",
    "CANONICAL_SUBSYSTEMS",
    "STATUS_NOT_ANCHORED",
    "STATUS_NOT_VERIFIED",
    "STATUS_VERIFIED",
    "VerifyResult",
    "VerifyStatus",
    "verification_status_for",
    "verify",
]

# Back-compat aliases for the pre-consolidation private helpers.
_strip_sha512_prefix = strip_hash_prefix
_strip_base64_prefix = strip_base64_prefix


def _compute_step_hash(
    prev_hash: str,
    subsystem: str,
    method: str,
    timestamp: str,
) -> str:
    """Re-implement compute_step_hash from the chain specification.

    `action` is always "destroy" — hardcoded per CDP spec.
    """
    return compute_step_hash(prev_hash, subsystem, method, timestamp)


# Scope strings for the offline verdict. The token before the first ":" is the
# machine-readable discriminator; a client treats a verdict as anchored if and
# only if it is valid and the scope starts with "trust_chain_anchored:". The
# text is byte-identical in the Python, TypeScript and Go SDKs (each has a
# literal-string test), so a wording change must touch all three.
TRUST_CHAIN_ANCHORED_SCOPE = (
    "trust_chain_anchored: the signing key resolved to an authority in a trust-chain "
    "manifest that verified against its pinned identity fingerprint, and the signature "
    "verified against that key (stage 8). This establishes which published authority's "
    "key produced the signature over the signed message (the final chain hash for a 1.0 proof, "
    "and for 2.1 and 2.2 the canonical-view hash "
    "recomputed from the document's fields); content that message does not cover is not attested "
    "by the signature, and the signature does not by itself establish that "
    "the events the document describes occurred."
)
OFFLINE_EMBEDDED_KEY_SCOPE = (
    "embedded_key_integrity: the 8-step chain reproduced and the Ed25519 signature "
    "verified against the key embedded in this proof. No trust-chain manifest was checked, "
    "so that key was not resolved against a published authority (stage 7, not "
    "stage 8); who signed is not established here. To anchor the key, set a trust-chain "
    "manifest and its pinned identity fingerprint in the verifier policy, or run nanorix-verify "
    "<proof.json> --trust-chain <trust-chain.json> --identity-fingerprint <pin>; it "
    "anchors only when the proof's signing_key_version, under its authority_id "
    "(us-kms-nanorix-v1 if it names none), resolves in that manifest."
)
# The scope of a valid 1.0 verdict. It keeps the embedded_key_integrity token
# (stage 7) and says what a 1.0 signature covers, which no key list changes.
OFFLINE_V1_0_SCOPE = (
    "embedded_key_integrity: the 8-step chain reproduced and the Ed25519 signature over "
    "final_hash verified against the key embedded in this 1.0 proof. A 1.0 signature covers "
    "final_hash alone, which binds destroyed_at and the two optional Merkle roots "
    "(record_receipts_merkle_root and parent_proofs_merkle_root). It does not bind the "
    "capsule_id itself (only through record receipts, which a holder can remove), the "
    "region or the key id, so this verdict names no capsule. A 1.0 proof is "
    "never anchored to a key list (stage 7, not stage 8), with or without a trust-chain "
    "manifest."
)
OFFLINE_CHAIN_ONLY_SCOPE = (
    "chain_only: the 8-step chain reproduced, but the proof carries no signature this "
    "verifier checks (no attestation, a missing signature or key, or a version with no "
    "signed message), so neither the signer nor that the document is unaltered since "
    "signing is established."
)


def verification_scope_for(valid: bool, stage_reached: int, cdp_version: str = "") -> str:
    """Derive the scope string for an offline verdict.

    Total over every (valid, stage_reached) pair. An invalid verdict has no
    scope (empty string). Stage 8 is reached only when the policy carries a
    `TrustChain`; without one a verified signature is stage 7. A 1.0 proof
    never reaches stage 8, and its stage-7 scope says why: a caller deriving
    the scope of a 1.0 result must pass its `cdp_version`, or it gets the
    2.x embedded-key scope.
    """
    if not valid:
        return ""
    if stage_reached >= 8:
        return TRUST_CHAIN_ANCHORED_SCOPE
    if stage_reached >= 7:
        return OFFLINE_V1_0_SCOPE if cdp_version == "1.0" else OFFLINE_EMBEDDED_KEY_SCOPE
    return OFFLINE_CHAIN_ONLY_SCOPE


@dataclass
class VerifyResult:
    """Outcome of verifying an AuditProof.

    Attributes:
        ok: True only when ``status`` is ``"verified"``: the signing key
            resolved in the trust-chain manifest given as
            ``VerifierPolicy.trust_chain`` (checked against its pinned identity
            fingerprint) and the signature verified against that key (stage
            8). Without a trust chain a good proof is ``"not_anchored"`` and
            ``ok`` is False: its signature matches the key the proof carries,
            which a proof signed with a fresh key also does.
        status: ``"verified"`` (stage 8, as above), ``"not_anchored"``
            (stage 7: the chain reproduced and the signature verified against
            the embedded key only; ``failure_reason`` is empty) or
            ``"not_verified"`` (invalid, or a reproduced chain with no
            signature checked).
        valid: Deprecated; reading it warns with ``FutureWarning``. The
            reference verifier's wire field, which the fixture corpus pins
            with ``status``: True when the chain and the signature hold under
            the key used, so it is also True for a stage 7 proof and for
            "chain verified, signature NOT checked" (stage 4), and on its own
            it says nothing about who signed. Read ``status`` (or ``ok``).
            The constructor takes it as ``_valid``.
        stage_reached: Highest stage reached, 1..8. 7 means the signature
            verified against the key embedded in the proof; 8 means the signing
            key was also resolved in a signed key list
            (`VerifierPolicy.trust_chain`) and the signature verified against
            the listed key.
        chain_valid: True iff every step's stored chain_hash matched the
            recomputed value and `final_hash` bound to the last step.
        signature_valid: True iff the Ed25519 signature verified over the
            version-appropriate signed message.
        subsystems_attested: Subsystem names found in the chain, in order.
            For a valid CDP this equals CANONICAL_SUBSYSTEMS.
        failed_step: 1-indexed step number where chain integrity broke, None
            if no chain failure.
        failure_reason: Human-readable diagnostic. Empty string when
            ``status`` is ``"verified"`` or ``"not_anchored"``.
        failure: The structured wire-form failure reason
            (`{"type": ..., ...}`), or None. This is the cross-implementation
            surface; `failure_reason` is the prose rendering of it.
        chain_hash: The final (step 8) chain_hash if the chain reproduced,
            else "".
        customer_declared_activity_root: The `customer_declared_activity_root`
            the proof carries, as written; None when it declares
            none. Disclosed whether or not the record was supplied, so a
            reader never has to assume a declared root was checked.
        customer_declared_activity_checked: True when the customer's record
            was supplied through `VerifierPolicy.customer_activity` and its
            recomputed root matched; False when the proof declares a root but
            no record was supplied (declared, not checked); None when the
            proof declares no root. A mismatch is a failure, never a False.
        verification_scope: What a valid verdict does and does not establish,
            as a string whose token before the first ":" is the discriminator
            (`embedded_key_integrity`, `chain_only`, `trust_chain_anchored`).
            Empty when the result is invalid. Without a `VerifierPolicy.trust_chain`
            a verified signature reads `embedded_key_integrity:` (stage 7),
            never anchored; with one, a proof that resolves reads
            `trust_chain_anchored:` (stage 8). Outside the corpus-compared
            fields.
    """

    ok: bool
    chain_valid: bool
    signature_valid: bool
    subsystems_attested: List[str] = field(default_factory=list)
    failed_step: Optional[int] = None
    failure_reason: str = ""
    chain_hash: str = ""
    _valid: bool = False
    stage_reached: int = 0
    failure: Optional[Dict[str, Any]] = None
    customer_declared_activity_root: Optional[str] = None
    customer_declared_activity_checked: Optional[bool] = None
    verification_scope: str = ""
    status: VerifyStatus = STATUS_NOT_VERIFIED

    @property
    def valid(self) -> bool:
        """Deprecated: read ``status`` or ``ok``. True at stages 4, 7 and 8."""
        warnings.warn(
            "VerifyResult.valid is deprecated: it is also True when who signed is not "
            "established (status 'not_anchored' at stage 7, and a chain with no signature "
            "checked at stage 4). Read .status, which is 'verified' only at stage 8, or .ok.",
            FutureWarning,
            stacklevel=2,
        )
        return self._valid


def _load_proof(input_data: Union[Dict[str, Any], str, Path, bytes]) -> Any:
    """Accept dict, JSON string, file path, or bytes and return the parsed value.

    Heuristic: if `Path` instance OR string with no `{`/`[` prefix, treat
    as path; if string starts with `{`/`[` or `"`, parse as JSON. Avoids
    `Path(<long json string>).exists()` raising ENAMETOOLONG on long
    strings. Files and bytes are read as UTF-8 and nothing else.
    """
    if isinstance(input_data, dict):
        return input_data
    if isinstance(input_data, bytes):
        return parse_document(input_data)
    if isinstance(input_data, Path):
        return parse_document(input_data.read_bytes())
    if isinstance(input_data, str):
        stripped = input_data.lstrip()
        if stripped.startswith(("{", "[", '"')):
            return parse_document(input_data)
        # Treat as path
        p = Path(input_data)
        if p.exists() and p.is_file():
            return parse_document(p.read_bytes())
        # Last-resort: try JSON anyway (caller may have supplied an
        # unprefixed JSON-encoded number/literal)
        return parse_document(input_data)
    raise TypeError(
        f"verify() expected dict / path / JSON string / bytes; got {type(input_data).__name__}"
    )


#: How the prose names a `claimed_authority_id` of null: the proof's
#: `authority_id` was absent or not a string, and the default stood in.
_NULL_CLAIMED_AUTHORITY = "absent or not a string, so the Nanorix default applies"

_SIGNATURE_PROSE = {
    "does_not_verify": "Ed25519 signature did not verify against the signed message",
    "malformed": "Ed25519 signature is malformed (bad base64 or wrong length)",
    "public_key_malformed": "Ed25519 public key is malformed (bad base64 or wrong length)",
    "message_format_mismatch": "signed message format did not match",
}


def _prose(wire: Dict[str, Any]) -> str:
    """Render a wire failure reason as a one-line human diagnostic."""
    t = wire.get("type")
    if t == FailureReasonType.REQUIRED_FIELD_MISSING:
        field_name = wire.get("field")
        if field_name == "json_root":
            return "Could not parse proof input: not valid JSON"
        return f"Proof missing required field {field_name!r}"
    if t == FailureReasonType.CDP_VERSION_UNSUPPORTED:
        return f"Unsupported cdp_version: {wire.get('found')!r}"
    if t == FailureReasonType.STEP_COUNT_INVALID:
        return f"Chain has {wire.get('found')} steps, expected {wire.get('expected')}"
    if t == FailureReasonType.STEP_HASH_MISMATCH:
        idx = wire.get("step_idx")
        step_no = idx + 1 if isinstance(idx, int) else "?"
        return f"Chain hash mismatch at step {step_no} ({wire.get('subsystem')})"
    if t == FailureReasonType.CHAIN_STEP_IDENTITY_MISMATCH:
        idx = wire.get("step_idx")
        step_no = idx + 1 if isinstance(idx, int) else "?"
        return (
            f"Chain step {step_no} names subsystem {wire.get('found_subsystem')!r}; "
            f"the canonical subsystem for that position is "
            f"{wire.get('expected_subsystem')!r}"
        )
    if t == FailureReasonType.FINAL_HASH_MISMATCH:
        return "final_hash does not match the last step's chain_hash"
    if t == FailureReasonType.SIGNATURE_MISMATCH:
        reason = wire.get("reason")
        return _SIGNATURE_PROSE.get(str(reason), f"Ed25519 signature check failed: {reason}")
    if t == FailureReasonType.REGION_MISMATCH:
        return f"Region {wire.get('actual')!r} does not match required {wire.get('required')!r}"
    if t == FailureReasonType.AUTHORITY_ID_MISMATCH:
        claimed = wire.get("claimed_authority_id")
        if claimed is not None and claimed == wire.get("expected_authority_id"):
            return (
                f"authority_id {claimed!r} is not covered by this proof's signature, "
                "or contradicts signing_authority"
            )
        return (
            f"Signing authority {claimed!r} does not match "
            f"required {wire.get('expected_authority_id')!r}"
        )
    if t == FailureReasonType.SIGNING_MODE_AUTHORITY_MISMATCH:
        claimed = wire.get("claimed_authority_id")
        named = repr(claimed) if isinstance(claimed, str) else "(%s)" % _NULL_CLAIMED_AUTHORITY
        return (
            f"signing_mode is customer_only, but authority_id {named} is not "
            "customer-classified (it contains none of customer-hsm-, customer-kms-, "
            "customer-tee- or customer-byo-, compared case-sensitively)"
        )
    if t == FailureReasonType.CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH:
        return (
            "customer_declared_activity_root does not reproduce from the supplied "
            "activity record (the chain itself reproduced)"
        )
    if t == FailureReasonType.UNSIGNED_FIELD_POPULATED:
        return f"Field {wire.get('field')!r} is populated but is outside the signature"
    if t == FailureReasonType.FIELD_MALFORMED:
        return f"Field {wire.get('field')!r} is malformed: {wire.get('reason')}"
    return f"Verification failed: {t}"


# Stage-3 failures raised by the sub-structure checks that run AFTER the chain
# walk. A verdict carrying one of these means every step hash reproduced; the
# flat result must not read it as a chain failure.
_POST_CHAIN_WALK_FAILURES = frozenset(
    {
        FailureReasonType.CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH,
        FailureReasonType.STREAMING_MERKLE_ROOT_MISMATCH,
    }
)


def _chain_reproduced(stage_reached: int, wire: Optional[Dict[str, Any]]) -> bool:
    """Whether every chain step reproduced, from the ladder's verdict.

    Settled by stage 4 for anything that got past it. A stage-3 verdict is a
    chain failure unless its reason is one only the post-walk sub-structure
    checks raise — the sidecar check among them, which also fails
    closed as ``required_field_missing`` for its own field.
    """
    if stage_reached >= 4:
        return not (wire is not None and wire.get("type") == FailureReasonType.FINAL_HASH_MISMATCH)
    if stage_reached == 3 and wire is not None:
        t = wire.get("type")
        if t in _POST_CHAIN_WALK_FAILURES:
            return True
        if (
            t == FailureReasonType.REQUIRED_FIELD_MISSING
            and wire.get("field") == "customer_declared_activity_root"
        ):
            return True
    return False


def verify(
    proof: Union[Dict[str, Any], str, Path, bytes],
    policy: Optional[VerifierPolicy] = None,
) -> VerifyResult:
    """Verify an AuditProof (CDP) offline.

    Runs the same stage ladder as `nanorix.debug.verify_auditproof`: chain
    reproduction from the canonical per-step method constants, `final_hash`
    binding, and the Ed25519 signature over the version-appropriate message.

    Args:
        proof: AuditProof as dict, JSON string, file path, or bytes.
        policy: Optional VerifierPolicy for the authority-id and region pins,
            the `reject_diagnostic` setting, and `trust_chain` for stage 8.

    Returns:
        VerifyResult. `.ok` is True only when `.status` is ``"verified"``:
        the policy carried a `trust_chain` and the signing key resolved in it
        (stage 8). Without one a good proof is ``"not_anchored"`` with
        `.ok` False. `.valid` is deprecated and warns: it is True when the
        chain and the signature hold under the key used, including stage 7,
        so on its own it says nothing about who signed. Read `.status` or
        `.ok`.
    """
    try:
        proof_dict = _load_proof(proof)
    except (TypeError, ValueError, RecursionError, OSError) as e:
        return VerifyResult(
            ok=False,
            chain_valid=False,
            signature_valid=False,
            failure_reason=f"Could not parse proof input: {e}",
            failure={"type": FailureReasonType.REQUIRED_FIELD_MISSING, "field": "json_root"},
            stage_reached=1,
        )

    result = verify_document(proof_dict, policy)
    wire = result.failure_reason.to_wire_dict() if result.failure_reason is not None else None

    chain_raw = proof_dict.get("chain") if isinstance(proof_dict, dict) else None
    subsystems = (
        [s.get("subsystem", "") for s in chain_raw if isinstance(s, dict)]
        if isinstance(chain_raw, list)
        else []
    )

    failed_step: Optional[int] = None
    if wire is not None and wire.get("type") in (
        FailureReasonType.STEP_HASH_MISMATCH,
        FailureReasonType.CHAIN_STEP_IDENTITY_MISMATCH,
    ):
        idx = wire.get("step_idx")
        if isinstance(idx, int):
            failed_step = idx + 1

    chain_valid = _chain_reproduced(result.stage_reached, wire)
    signature_valid = result.stage_reached >= 7 and result._valid
    status = result.status

    chain_hash = ""
    if chain_valid and isinstance(chain_raw, list) and chain_raw:
        last = chain_raw[-1]
        if isinstance(last, dict):
            chain_hash = strip_hash_prefix(str(last.get("chain_hash", "")))

    return VerifyResult(
        ok=status == STATUS_VERIFIED,
        chain_valid=chain_valid,
        signature_valid=signature_valid,
        subsystems_attested=subsystems,
        failed_step=failed_step,
        failure_reason=(
            _prose(wire)
            if wire is not None
            else (
                ""
                if signature_valid
                else "Chain verified; no signature was checked (the proof carries no signature "
                "or no public key; "
                "a signing mode this build cannot verify is refused as algorithm_unsupported)"
            )
        ),
        chain_hash=chain_hash,
        _valid=result._valid,
        stage_reached=result.stage_reached,
        failure=wire,
        customer_declared_activity_root=result.metadata.customer_declared_activity_root,
        customer_declared_activity_checked=result.metadata.customer_declared_activity_checked,
        verification_scope=verification_scope_for(
            result._valid, result.stage_reached, result.metadata.cdp_version or ""
        ),
        status=status,
    )
