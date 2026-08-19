"""
Core verification logic — the convenience wrapper over the stage ladder.

The verification itself lives in `nanorix.verifier._ladder`, the single Python
implementation, held to the 100-document reference corpus at
`tools/nanorix-verify/fixtures/corpus/`. This module adds the ergonomic
`verify(proof)` surface: flexible input (dict / JSON string / path / bytes) and
a flat result object.

## The chain hash formula (Forever-Standard, ADR-006 I0)

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

v1.0 signs `final_hash`. v2.0 signs `document_hash`. v2.1 `nanorix_only` — what
production emits — signs the ADR-011 Part-3 canonical-view hash. Verifying a
v2.1 proof against `final_hash` never validates. See `_canonical.py`.

The signature covers the ASCII hex characters of that hash (128 bytes), not
its 64 raw digest bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast

from nanorix.verifier._canonical import strip_base64_prefix, strip_hash_prefix
from nanorix.verifier._ladder import (
    CANONICAL_SUBSYSTEMS,
    GENESIS_HASH,
    FailureReasonType,
    VerifierPolicy,
    compute_step_hash,
    verify_auditproof,
)

__all__ = [
    "GENESIS_HASH",
    "CANONICAL_SUBSYSTEMS",
    "VerifyResult",
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
    """Re-implement compute_step_hash from governance/rzl/src/proofs/mod.rs.

    `action` is always "destroy" — hardcoded per CDP spec.
    """
    return compute_step_hash(prev_hash, subsystem, method, timestamp)


@dataclass
class VerifyResult:
    """Outcome of verifying an AuditProof.

    Attributes:
        ok: True iff the proof is cryptographically proven — the chain
            reproduced AND the Ed25519 signature verified. Strictly stronger
            than `valid`: a proof whose signature this build cannot check
            (unsigned, or a `dual_signature` / `tee_attested` v2.1 proof) has
            `valid=True` but `ok=False`, because nothing was proven about it.
        valid: The reference verifier's verdict — what the fixture corpus
            pins. True for "chain verified, signature NOT checked".
        stage_reached: Highest stage reached, 1..7. 7 means the signature
            verified against the key embedded in the proof.
        chain_valid: True iff every step's stored chain_hash matched the
            recomputed value and `final_hash` bound to the last step.
        signature_valid: True iff the Ed25519 signature verified over the
            version-appropriate signed message.
        subsystems_attested: Subsystem names found in the chain, in order.
            For a valid CDP this equals CANONICAL_SUBSYSTEMS.
        failed_step: 1-indexed step number where chain integrity broke, None
            if no chain failure.
        failure_reason: Human-readable diagnostic. Empty string if ok.
        failure: The structured wire-form failure reason
            (`{"type": ..., ...}`), or None. This is the cross-implementation
            surface; `failure_reason` is the prose rendering of it.
        chain_hash: The final (step 8) chain_hash if the chain reproduced,
            else "".
    """

    ok: bool
    chain_valid: bool
    signature_valid: bool
    subsystems_attested: List[str] = field(default_factory=list)
    failed_step: Optional[int] = None
    failure_reason: str = ""
    chain_hash: str = ""
    valid: bool = False
    stage_reached: int = 0
    failure: Optional[Dict[str, Any]] = None


def _load_proof(input_data: Union[Dict[str, Any], str, Path, bytes]) -> Dict[str, Any]:
    """Accept dict, JSON string, file path, or bytes and return parsed dict.

    Heuristic: if `Path` instance OR string with no `{`/`[` prefix, treat
    as path; if string starts with `{`/`[` or `"`, parse as JSON. Avoids
    `Path(<long json string>).exists()` raising ENAMETOOLONG on long
    strings.
    """
    if isinstance(input_data, dict):
        return input_data
    if isinstance(input_data, bytes):
        return cast(Dict[str, Any], json.loads(input_data))
    if isinstance(input_data, Path):
        return cast(Dict[str, Any], json.loads(input_data.read_text()))
    if isinstance(input_data, str):
        stripped = input_data.lstrip()
        if stripped.startswith(("{", "[", '"')):
            return cast(Dict[str, Any], json.loads(input_data))
        # Treat as path
        p = Path(input_data)
        if p.exists() and p.is_file():
            return cast(Dict[str, Any], json.loads(p.read_text()))
        # Last-resort: try JSON anyway (caller may have passed an
        # unprefixed JSON-encoded number/literal)
        return cast(Dict[str, Any], json.loads(input_data))
    raise TypeError(
        f"verify() expected dict / path / JSON string / bytes; got {type(input_data).__name__}"
    )


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
        return (
            f"Signing authority {wire.get('claimed_authority_id')!r} does not match "
            f"required {wire.get('expected_authority_id')!r}"
        )
    return f"Verification failed: {t}"


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
        policy: Optional VerifierPolicy for the authority-id and region pins.

    Returns:
        VerifyResult. `.ok` is True only when the signature actually verified;
        `.valid` carries the reference verifier's verdict, which is True for
        a reproduced chain whose signature this build cannot check.
    """
    try:
        proof_dict = _load_proof(proof)
    except (TypeError, json.JSONDecodeError, OSError) as e:
        return VerifyResult(
            ok=False,
            chain_valid=False,
            signature_valid=False,
            failure_reason=f"Could not parse proof input: {e}",
            failure={"type": FailureReasonType.REQUIRED_FIELD_MISSING, "field": "json_root"},
            stage_reached=1,
        )

    result = verify_auditproof(proof_dict, policy)
    wire = result.failure_reason.to_wire_dict() if result.failure_reason is not None else None

    chain_raw = proof_dict.get("chain")
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

    # The chain and its final_hash binding are settled by stage 4; anything
    # that got past it reproduced, whatever the signature then did.
    chain_valid = result.stage_reached >= 4 and not (
        wire is not None and wire.get("type") == FailureReasonType.FINAL_HASH_MISMATCH
    )
    signature_valid = result.stage_reached >= 7 and result.valid

    chain_hash = ""
    if chain_valid and isinstance(chain_raw, list) and chain_raw:
        last = chain_raw[-1]
        if isinstance(last, dict):
            chain_hash = strip_hash_prefix(str(last.get("chain_hash", "")))

    return VerifyResult(
        ok=result.valid and signature_valid,
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
                else "Chain verified; signature NOT checked (unsigned, or a signing mode "
                "this build cannot verify)"
            )
        ),
        chain_hash=chain_hash,
        valid=result.valid,
        stage_reached=result.stage_reached,
        failure=wire,
    )
