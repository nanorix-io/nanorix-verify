"""
Offline AuditProof (CDP) verifier — pure Python, no network.

Re-implements the canonical 8-step SHA-512 chain + Ed25519 attestation defined
in `governance/rzl/src/cdp.rs` and `governance/rzl/src/proofs/mod.rs`.
Customers, auditors, and air-gapped systems can verify any AuditProof
independently without trusting the Nanorix API.

Usage:
    from nanorix.verifier import verify

    result = verify(proof_dict)         # accepts dict / path / JSON string / bytes
    if result.ok:
        print("VERIFIED:", result.chain_hash)
    else:
        print("FAIL:", result.failure_reason)

`verify()` and `nanorix.debug.verify_auditproof()` are two surfaces over one
implementation (`_ladder.py`), held to the pinned reference corpus at
`tools/nanorix-verify/fixtures/corpus/` — the same contract as the Rust
verifier. `verify()` returns a flat result with an `.ok` that requires a verified
signature; `verify_auditproof()` returns the staged wire verdict
(`valid` / `failure_reason` / `stage_reached`) and takes a `VerifierPolicy`.

The stages:

1. **Chain integrity** — re-compute every step's `chain_hash` via
   `SHA-512(prev \\x00 subsystem \\x00 "destroy" \\x00 method \\x00 timestamp)`,
   where `method` is the canonical constant for that subsystem and `timestamp`
   is the document's `destroyed_at` (neither is a per-step JSON field).

2. **final_hash binding** — the document's `final_hash` must equal step 8's
   `chain_hash`.

3. **Ed25519 attestation** — verify `signature` over the message that version
   signs: `final_hash` for v1.0, `document_hash` for v2.0, and the ADR-011
   Part-3 canonical-view hash for v2.1 `nanorix_only`, which is what
   production emits.

Stage 8 — anchoring the signing key to a signed trust-chain manifest — needs
an operator-supplied manifest and is not implemented here, so a proof whose
embedded-key signature verifies tops out at stage 7: integrity proven,
authenticity not established.
"""

from __future__ import annotations

from nanorix.verifier._canonical import (
    recompute_canonical_hash,
    recover_timestamp_from_key_id,
    signed_message,
)
from nanorix.verifier._ladder import (
    CANONICAL_SUBSYSTEMS,
    GENESIS_HASH,
    FailureReason,
    FailureReasonType,
    VerificationMetadata,
    VerificationResult,
    VerifierPolicy,
    verify_auditproof,
)
from nanorix.verifier._verify import VerifyResult, verify
from nanorix.verifier.customer_activity import (
    CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
    CustomerDeclaredActivityCheck,
    CustomerDeclaredActivityStatus,
    compute_customer_declared_activity_root,
    customer_declared_activity_leaf_hashes,
    split_customer_declared_activity_lines,
    verify_customer_declared_activity,
)
from nanorix.verifier.bundle import (
    PORTABLE_RECEIPT_BUNDLE_DISCLAIMER,
    AuditProofAnchors,
    BundleError,
    PortableReceiptBundle,
    extract_receipt_bundle,
    verify_receipt_bundle,
)
from nanorix.verifier.pubkey_bundle import (
    PORTABLE_PUBKEY_BUNDLE_DISCLAIMER,
    BundleSignature,
    PortablePubkeyBundle,
    PubKeyEntry,
    PubkeyBundleError,
    build_pubkey_bundle,
    resolve_parent_key,
    resolve_parent_key_forever,
    verify_pubkey_bundle,
)
from nanorix.verifier.wave_n import (
    GENESIS_SHA512_HEX,
    PARENT_PROOF_MAX_DEPTH,
    PATTERN_TAGS_WIRE,
    ParentProofLink,
    RecordReceipt,
    WaveNVerifyError,
    WaveNVerifyResult,
    build_merkle_inclusion_proof,
    compute_activity_root,
    compute_parent_proofs_merkle_root,
    compute_record_chain_hash,
    compute_record_receipts_merkle_root,
    compute_step_8_amended,
    compute_step_8_base,
    detect_parent_proof_cycle,
    enforce_depth_cap,
    merkle_pair_hash,
    merkle_root_sha512_null_separated,
    verify_full_audit_proof,
    verify_merkle_inclusion_proof,
    verify_record_receipt,
)

__all__ = [
    # Original V1 surface.
    "verify",
    "VerifyResult",
    # Stage-ladder surface (shared with `nanorix.debug`).
    "verify_auditproof",
    "VerificationResult",
    "VerificationMetadata",
    "VerifierPolicy",
    "FailureReason",
    "FailureReasonType",
    "CANONICAL_SUBSYSTEMS",
    "GENESIS_HASH",
    "recompute_canonical_hash",
    "signed_message",
    "recover_timestamp_from_key_id",
    # ADR-056 — customer_declared_activity_root sidecar check.
    "CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD",
    "CustomerDeclaredActivityCheck",
    "CustomerDeclaredActivityStatus",
    "compute_customer_declared_activity_root",
    "customer_declared_activity_leaf_hashes",
    "split_customer_declared_activity_lines",
    "verify_customer_declared_activity",
    # Wave-N (ADR-039 + ADR-041) surface.
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
    # Wave B Item 7 — Portable Receipt Bundle surface.
    "PORTABLE_RECEIPT_BUNDLE_DISCLAIMER",
    "AuditProofAnchors",
    "BundleError",
    "PortableReceiptBundle",
    "extract_receipt_bundle",
    "verify_receipt_bundle",
    # Wave B Item 8 — Portable Pubkey Bundle surface.
    "PORTABLE_PUBKEY_BUNDLE_DISCLAIMER",
    "BundleSignature",
    "PortablePubkeyBundle",
    "PubKeyEntry",
    "PubkeyBundleError",
    "build_pubkey_bundle",
    "resolve_parent_key",
    "resolve_parent_key_forever",
    "verify_pubkey_bundle",
]
