"""
ADR-056 — `customer_declared_activity_root` recompute-and-compare.

The proof carries ONE field about the customer's own activity record: a root
over the raw bytes of the file the SDK's activity helpers append to inside the
capsule. The events themselves are never absorbed into the proof; the customer
keeps the file and presents it here as a sidecar. Nanorix never parses those
bytes — the root is a commitment to content, not a statement about it.

## Algorithm (pinned by `tools/nanorix-verify/fixtures/customer_declared_activity_root_vectors.json`)

1. Split the sidecar on `0x0A`. Drop only a trailing empty segment (a file
   that ends in a newline has no extra empty line). Never trim, never parse.
2. Leaf = SHA-512 hex of each line's raw bytes.
3. Root = `merkle_root_sha512_null_separated(leaves)` — pairs hashed as
   `SHA-512(left_hex || 0x00 || right_hex)`, odd last node duplicated.
4. Zero lines → GENESIS (SHA-512 of the empty string), so "opted in, wrote
   nothing" is distinguishable from "did not opt in" (field absent).
5. Wire form `sha512:<hex>`.

## The three verdicts

| sidecar | root in proof | outcome |
|---|---|---|
| given | present | recompute and compare; mismatch is a failure |
| given | absent | `required_field_missing` — a sidecar presented against a proof that never declared one is the fail-closed shape |
| absent | present | "declared, not checked" — disclosed, NOT a failure; most readers of a proof never hold the sidecar |
| absent | absent | nothing was declared; nothing to do |
| any | present, `cdp_version` not 2.1 / 2.2 | `unsigned_field_populated` — the root is signed only where the signed message is the canonical view; on any other version (a missing or non-string `cdp_version` included) a populated root is a value anyone holding the document can write, so it is never compared and never disclosed as "declared" |
| any | malformed | `field_malformed` — a present, non-null root that is not a `sha512:` + 128-lowercase-hex string (bare hex accepted) is never compared and never disclosed as "declared"; `""` is malformed, not absent |

The ladder runs this check with the other sub-structure Merkle checks at
stage 3, after the chain walk, and only on cdp_version 2.1 / 2.2: those are
the versions whose signed message is the canonical view, so the root is
already signature-bound there and the signature stages establish that it is
the one the deployment signed. On any other version the ladder rejects a
present root at stage 2 as `unsigned_field_populated` before this check
runs. The standalone entry point below applies the same two stage-2 gates
itself, in the same order, so a caller that skips the ladder cannot be
handed "verified" for a root the signature never covered. This module
establishes the remaining half — that the bytes in hand are the bytes that
root commits to.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Mapping, Optional, Union

from nanorix.verifier._canonical import strip_hash_prefix
from nanorix.verifier._ladder import (
    FailureReason,
    FailureReasonType,
    customer_declared_activity_root_gate,
)
from nanorix.verifier.wave_n import GENESIS_SHA512_HEX, merkle_root_sha512_null_separated

CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD = "customer_declared_activity_root"

_LINE_SEPARATOR = b"\n"


def split_customer_declared_activity_lines(data: Union[bytes, bytearray]) -> List[bytes]:
    """Split the sidecar bytes on `0x0A`, dropping only a trailing empty segment.

    Whitespace is content: a leading space or an empty interior line is a
    line of its own. `b""` yields no lines; `b"\\n"` yields one empty line.
    """
    segments = bytes(data).split(_LINE_SEPARATOR)
    if segments and segments[-1] == b"":
        segments.pop()
    return segments


def customer_declared_activity_leaf_hashes(data: Union[bytes, bytearray]) -> List[str]:
    """SHA-512 hex of each line's raw bytes, in file order. No prefix."""
    return [
        hashlib.sha512(line).hexdigest() for line in split_customer_declared_activity_lines(data)
    ]


def compute_customer_declared_activity_root(data: Union[bytes, bytearray]) -> str:
    """The ADR-056 root over a sidecar's raw bytes, in wire form `sha512:<hex>`.

    Byte-equivalent with the Rust, Go, TypeScript and browser verifiers; every
    vector in `customer_declared_activity_root_vectors.json` pins it.
    """
    leaves = customer_declared_activity_leaf_hashes(data)
    root = merkle_root_sha512_null_separated(leaves)
    if root is None:
        root = GENESIS_SHA512_HEX
    return f"sha512:{root}"


class CustomerDeclaredActivityStatus(Enum):
    """Which of the four verdicts the sidecar check reached."""

    NOT_DECLARED = "not_declared"
    """The proof carries no root and no sidecar was offered."""

    DECLARED_NOT_CHECKED = "declared_not_checked"
    """The proof carries a root but no sidecar was offered.

    Disclosed rather than failed: the signature already binds the root, and a
    verifier without the customer's file cannot say anything more.
    """

    VERIFIED = "verified"
    """The sidecar's recomputed root equals the signed root."""

    FAILED = "failed"
    """A sidecar was offered and the check failed; see `failure_reason`."""


@dataclass(frozen=True)
class CustomerDeclaredActivityCheck:
    """Outcome of `verify_customer_declared_activity`."""

    status: CustomerDeclaredActivityStatus
    #: The root as it appears in the proof, when present.
    claimed: Optional[str] = None
    #: The root recomputed from the sidecar, when one was offered.
    computed: Optional[str] = None
    #: Lines the sidecar split into, when one was offered.
    line_count: Optional[int] = None
    #: Set only for FAILED.
    failure_reason: Optional[FailureReason] = None

    @property
    def ok(self) -> bool:
        """True unless a sidecar was offered and the check failed.

        `DECLARED_NOT_CHECKED` counts as ok on purpose — it is a disclosure,
        not a defect. Callers that require the sidecar to have been checked
        must test `status is VERIFIED`.
        """
        return self.status is not CustomerDeclaredActivityStatus.FAILED

    @property
    def checked(self) -> bool:
        return self.status is CustomerDeclaredActivityStatus.VERIFIED


def _claimed_root(proof: Mapping[str, Any]) -> Union[str, FailureReason, None]:
    """The declared root as written, None when absent or null, or the stage-2
    reason when present but unsigned on this `cdp_version` or not in the
    shape a signer emits.

    A `cdp_version` that is missing or not a string is treated as a version
    that does not sign the root: the gate cannot take a document's word that
    its root is covered when the document does not even say what it is.
    """
    value = proof.get(CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD)
    if value is None:
        return None
    cdp_version = proof.get("cdp_version")
    failure = customer_declared_activity_root_gate(
        proof, cdp_version if isinstance(cdp_version, str) else ""
    )
    return failure if failure is not None else str(value)


def verify_customer_declared_activity(
    proof: Mapping[str, Any],
    data: Optional[Union[bytes, bytearray]],
) -> CustomerDeclaredActivityCheck:
    """Compare a sidecar of raw activity bytes against the proof's declared root.

    `data` is the exact byte content of the customer's activity file
    (`activity_events.jsonl`), or None when the caller does not hold it. The
    bytes are hashed as-is — no decoding, no trimming, no JSON parsing.

    This does not verify the proof's signature. Run the stage ladder first: a
    matching sidecar against an unsigned or tampered proof proves nothing.

    It does apply the ladder's two stage-2 gates on the root, in the ladder's
    order. A present, non-null root on a `cdp_version` other than 2.1 / 2.2
    (a missing `cdp_version` counts as "other") is `unsigned_field_populated`,
    and a present root that is not well-formed is `field_malformed` — in both
    cases whether or not a sidecar is offered, and in both cases the root is
    never compared against a record and never disclosed as "declared".
    """
    claimed = _claimed_root(proof)
    if isinstance(claimed, FailureReason):
        return CustomerDeclaredActivityCheck(
            CustomerDeclaredActivityStatus.FAILED, failure_reason=claimed
        )

    if data is None:
        if claimed is None:
            return CustomerDeclaredActivityCheck(CustomerDeclaredActivityStatus.NOT_DECLARED)
        return CustomerDeclaredActivityCheck(
            CustomerDeclaredActivityStatus.DECLARED_NOT_CHECKED, claimed=claimed
        )

    line_count = len(split_customer_declared_activity_lines(data))
    computed = compute_customer_declared_activity_root(data)

    if claimed is None:
        return CustomerDeclaredActivityCheck(
            CustomerDeclaredActivityStatus.FAILED,
            computed=computed,
            line_count=line_count,
            failure_reason=FailureReason(
                type=FailureReasonType.REQUIRED_FIELD_MISSING,
                field=CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
            ),
        )

    if strip_hash_prefix(claimed) != strip_hash_prefix(computed):
        return CustomerDeclaredActivityCheck(
            CustomerDeclaredActivityStatus.FAILED,
            claimed=claimed,
            computed=computed,
            line_count=line_count,
            failure_reason=FailureReason(
                type=FailureReasonType.CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH,
                claimed=claimed,
                computed=computed,
            ),
        )

    return CustomerDeclaredActivityCheck(
        CustomerDeclaredActivityStatus.VERIFIED,
        claimed=claimed,
        computed=computed,
        line_count=line_count,
    )
