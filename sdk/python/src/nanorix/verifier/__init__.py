"""
Offline AuditProof (CDP) verifier — pure Python, no network.

Re-implements the canonical 8-step SHA-512 chain + Ed25519 attestation defined
in the chain specification.
Customers, auditors, and air-gapped systems can verify any AuditProof
independently without trusting the Nanorix API.

Usage:
    from nanorix.verifier import TrustChain, VerifierPolicy, verify

    # The key list and its pinned identity fingerprint, obtained yourself:
    # https://verify.nanorix.io/.well-known/trust-chain.json and
    # https://verify.nanorix.io/.well-known/identity.txt
    chain = TrustChain.from_key_list(key_list_json, "sha256:<pinned fingerprint>")
    result = verify(proof_dict, VerifierPolicy(trust_chain=chain))  # dict / path / JSON string / bytes
    if result.ok:                       # status == "verified" (stage 8)
        print("VERIFIED:", result.chain_hash)
    elif result.status == "not_anchored":
        print("SIGNATURE VALID, key not anchored:", result.verification_scope)
    else:
        print("NOT VERIFIED:", result.failure_reason)

`verify()` and `nanorix.debug.verify_auditproof()` are two surfaces over one
implementation (`_ladder.py`), held to the pinned reference corpus at
`tools/nanorix-verify/fixtures/corpus/` — the same contract as the Rust
verifier. `verify()` returns a flat result whose `.status` is `verified`,
`not_anchored` or `not_verified`, and whose `.ok` is True only for `verified`;
`verify_auditproof()` returns the staged wire verdict
(`valid` / `failure_reason` / `stage_reached`) and takes a `VerifierPolicy`.

The stages:

1. **Chain integrity** — re-compute every step's `chain_hash` via
   `SHA-512(prev \\x00 subsystem \\x00 "destroy" \\x00 method \\x00 timestamp)`,
   where `method` is the canonical constant for that subsystem and `timestamp`
   is the document's `destroyed_at` (neither is a per-step JSON field).

2. **final_hash binding** — the document's `final_hash` must equal step 8's
   `chain_hash`.

3. **Ed25519 attestation** — verify `signature` over the message that version
   signs: `final_hash` for v1.0 and the canonical-view hash
   for v2.1 `nanorix_only`, which is what production emits. A document that
   declares cdp_version 2.0 is retired and refused at stage 2.

4. **Trust-chain anchoring (stage 8)** — with a signed key list and the identity
   fingerprint that must have signed it, resolve the proof's authority and key
   version in the list and check the signature against the listed key:

       from nanorix.verifier import TrustChain, VerifierPolicy, verify_auditproof

       chain = TrustChain.from_key_list(key_list_json, "sha256:<pinned fingerprint>")
       result = verify_auditproof(proof, VerifierPolicy(trust_chain=chain))

   A list the pinned identity did not sign raises `TrustChainError` before any
   proof is read. Without a key list a proof whose embedded-key signature
   verifies tops out at stage 7: integrity proven, authenticity not established.
   The flat `verify()` takes the same policy; without a trust chain its result
   is `not_anchored` and `.ok` is False.
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
from nanorix.verifier._trust_chain import (
    HYBRID_PIN_PREFIX,
    TrustChain,
    TrustChainError,
    compare_partners,
    hybrid_pin,
    is_hybrid_pin,
    mldsa_available,
)
from nanorix.verifier._verify import (
    OFFLINE_CHAIN_ONLY_SCOPE,
    OFFLINE_EMBEDDED_KEY_SCOPE,
    OFFLINE_V1_0_SCOPE,
    STATUS_NOT_ANCHORED,
    STATUS_NOT_VERIFIED,
    STATUS_VERIFIED,
    TRUST_CHAIN_ANCHORED_SCOPE,
    VerifyResult,
    VerifyStatus,
    verification_scope_for,
    verification_status_for,
    verify,
)
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
    SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH,
    SIGNATURE_TARGET_STEP8_CHAIN_HASH,
    AuditProofAnchors,
    BundleError,
    BundleVerification,
    PortableReceiptBundle,
    extract_receipt_bundle,
    verify_receipt_bundle,
    verify_receipt_bundle_detailed,
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
    "VerifyStatus",
    "STATUS_VERIFIED",
    "STATUS_NOT_ANCHORED",
    "STATUS_NOT_VERIFIED",
    "verification_status_for",
    "verification_scope_for",
    "OFFLINE_EMBEDDED_KEY_SCOPE",
    "OFFLINE_V1_0_SCOPE",
    "OFFLINE_CHAIN_ONLY_SCOPE",
    "TRUST_CHAIN_ANCHORED_SCOPE",
    # Stage-ladder surface (shared with `nanorix.debug`).
    "verify_auditproof",
    "VerificationResult",
    "VerificationMetadata",
    "VerifierPolicy",
    "HYBRID_PIN_PREFIX",
    "TrustChain",
    "TrustChainError",
    "compare_partners",
    "hybrid_pin",
    "is_hybrid_pin",
    "mldsa_available",
    "FailureReason",
    "FailureReasonType",
    "CANONICAL_SUBSYSTEMS",
    "GENESIS_HASH",
    "recompute_canonical_hash",
    "signed_message",
    "recover_timestamp_from_key_id",
    # customer_declared_activity_root sidecar check.
    "CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD",
    "CustomerDeclaredActivityCheck",
    "CustomerDeclaredActivityStatus",
    "compute_customer_declared_activity_root",
    "customer_declared_activity_leaf_hashes",
    "split_customer_declared_activity_lines",
    "verify_customer_declared_activity",
    # Per-record receipt surface.
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
    # Portable Receipt Bundle surface.
    "PORTABLE_RECEIPT_BUNDLE_DISCLAIMER",
    "SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH",
    "SIGNATURE_TARGET_STEP8_CHAIN_HASH",
    "AuditProofAnchors",
    "BundleError",
    "BundleVerification",
    "PortableReceiptBundle",
    "extract_receipt_bundle",
    "verify_receipt_bundle",
    "verify_receipt_bundle_detailed",
    # Portable Pubkey Bundle surface.
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
