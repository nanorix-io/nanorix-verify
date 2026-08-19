/**
 * Offline AuditProof (CDP) verifier — pure TypeScript, no network.
 *
 * Customers, auditors, and air-gapped systems can verify any AuditProof
 * independently without trusting the Nanorix API.
 *
 * Two entry points, one implementation:
 *
 * - `verifyAuditProof()` — the full 8-stage pipeline with structured,
 *   wire-form failure reasons and policy pins. Byte-equivalent with the Rust
 *   reference verifier across the 100-fixture cross-impl corpus. Prefer this.
 * - `verify()` — the original convenience wrapper returning a flat boolean
 *   result. Kept for the published v0.5.0 surface; it delegates to the same
 *   core so the two can never drift apart again.
 *
 * Uses Web Crypto subtle API for Ed25519 (Node 18+ and modern browsers).
 *
 * Usage:
 * ```ts
 * import { verify } from "@nanorix/sdk/verifier";
 *
 * const result = await verify(proof);
 * if (result.ok) {
 *   console.log("VERIFIED:", result.chainHash);
 * } else {
 *   console.log("FAIL:", result.failureReason);
 * }
 * ```
 */

import {
  CANONICAL_SUBSYSTEMS,
  GENESIS_HASH,
  computeStepHash,
  lookupMethod,
  resolveChainTimestamp,
  stripSha512Prefix,
  verifySignature,
} from "./auditproof.js";
import { computeStep8Amended } from "./wave_n.js";

export { GENESIS_HASH, CANONICAL_SUBSYSTEMS };

// ── Full-pipeline surface (structured verdicts, policy pins) ────────────────
export {
  CHAIN_STEP_COUNT,
  FailureReasonType,
  METHOD_MAP,
  SUPPORTED_CDP_VERSIONS,
  SignatureFailureReason,
  computeStepHash,
  lookupMethod,
  recomputeCanonicalHash,
  recoverTimestampFromKeyId,
  resolveChainTimestamp,
  stripBase64Prefix,
  stripSha512Prefix,
  toWireForm,
  verifyAuditProof,
  verifySignature,
} from "./auditproof.js";
export type {
  FailureReason,
  FailureReasonTypeValue,
  SignatureCheck,
  SignatureFailureReasonValue,
  VerificationMetadata,
  VerificationResult,
  VerificationWireForm,
  VerifierPolicy,
} from "./auditproof.js";

export interface VerifyResult {
  ok: boolean;
  chainValid: boolean;
  signatureValid: boolean;
  subsystemsAttested: string[];
  failedStep: number | null;
  failureReason: string;
  chainHash: string;
}

/**
 * ADR-006 Wave 16-A reserved-slot scope discriminator (2026-05-10).
 *
 * AuditProof scope. V1 always undefined / absent (workload scope is implicit).
 * Future Items 2 (sealed-proxy = "call") and 4 (sealed-middleware = "request")
 * populate this; Pattern 4 high-volume per-record AuditProofs use "batch".
 *
 * Forever-Standard discipline (ADR-006 I0): field-additive Optional with
 * skip_serializing_if mechanic on the Rust side. The verifier MUST treat
 * this as opaque — chain integrity verification is independent of cdp_kind.
 */
export type CdpKind = "workload" | "request" | "call" | "batch";

/**
 * Verify an AuditProof (CDP) offline.
 *
 * Three checks: subsystem coverage, chain integrity, Ed25519 signature.
 *
 * Note that `method` and the chain timestamp are NOT read off the chain steps
 * — `method` is a fixed per-subsystem constant and the timestamp is the
 * document's `destroyed_at` (recovered from `attestation.key_id` on
 * pre-ADR-047 proofs). A serialized step carries only
 * `step / subsystem / operation / evidence_hash / chain_hash`.
 *
 * @param proof  AuditProof as parsed JSON object.
 * @returns VerifyResult with `.ok=true` iff all three checks pass.
 */
export async function verify(proof: unknown): Promise<VerifyResult> {
  const result: VerifyResult = {
    ok: false,
    chainValid: false,
    signatureValid: false,
    subsystemsAttested: [],
    failedStep: null,
    failureReason: "",
    chainHash: "",
  };

  if (typeof proof !== "object" || proof === null || Array.isArray(proof)) {
    result.failureReason = `verify() expected object; got ${typeof proof}`;
    return result;
  }
  const p = proof as Record<string, unknown>;
  const chain = p["chain"];

  if (!Array.isArray(chain)) {
    result.failureReason = "Proof missing 'chain' array";
    return result;
  }

  // Subsystem coverage
  const subsystems = chain.map((s) =>
    s && typeof s === "object" && typeof (s as Record<string, unknown>)["subsystem"] === "string"
      ? ((s as Record<string, unknown>)["subsystem"] as string)
      : "",
  );
  result.subsystemsAttested = subsystems;
  if (
    subsystems.length !== CANONICAL_SUBSYSTEMS.length ||
    !subsystems.every((s, i) => s === CANONICAL_SUBSYSTEMS[i])
  ) {
    result.failureReason = `Subsystem mismatch: expected ${JSON.stringify(CANONICAL_SUBSYSTEMS)}, got ${JSON.stringify(subsystems)}`;
    return result;
  }

  const { timestamp } = resolveChainTimestamp(p);
  const rrmr =
    typeof p["record_receipts_merkle_root"] === "string"
      ? (p["record_receipts_merkle_root"] as string)
      : null;
  const ppmr =
    typeof p["parent_proofs_merkle_root"] === "string"
      ? (p["parent_proofs_merkle_root"] as string)
      : null;

  // Chain integrity
  let prevHash = GENESIS_HASH;
  for (let idx = 0; idx < chain.length; idx++) {
    const step = chain[idx] as Record<string, unknown>;
    const subsystem = subsystems[idx];
    const stored = stripSha512Prefix(
      typeof step["chain_hash"] === "string" ? (step["chain_hash"] as string) : "",
    );
    const computed =
      idx === 7 && subsystem === "capsule_destroy"
        ? await computeStep8Amended(prevHash, timestamp, rrmr, ppmr)
        : await computeStepHash(
            prevHash,
            subsystem,
            lookupMethod(subsystem),
            timestamp,
          );
    if (stored !== computed) {
      result.failedStep = idx + 1;
      result.failureReason = `Chain hash mismatch at step ${idx + 1} (${subsystem}): stored=${stored.slice(0, 16)}... computed=${computed.slice(0, 16)}...`;
      result.chainHash = stored;
      return result;
    }
    prevHash = computed;
  }
  const claimedFinal = stripSha512Prefix(
    typeof p["final_hash"] === "string" ? (p["final_hash"] as string) : "",
  );
  if (claimedFinal !== "" && claimedFinal !== prevHash) {
    result.failedStep = chain.length;
    result.failureReason = `final_hash does not bind the chain: claimed=${claimedFinal.slice(0, 16)}... computed=${prevHash.slice(0, 16)}...`;
    result.chainHash = prevHash;
    return result;
  }

  result.chainValid = true;
  result.chainHash = prevHash;

  // Ed25519 signature over the version-appropriate message.
  const att =
    p["attestation"] && typeof p["attestation"] === "object"
      ? (p["attestation"] as Record<string, unknown>)
      : {};
  if (att["algorithm"] !== "Ed25519") {
    result.failureReason = `Unsupported signature algorithm: ${JSON.stringify(att["algorithm"])} (expected Ed25519)`;
    return result;
  }

  const cdpVersion =
    typeof p["cdp_version"] === "string" ? (p["cdp_version"] as string) : "";
  const check = await verifySignature(p, cdpVersion);
  if (check.kind === "failed") {
    result.failureReason = `Ed25519 signature did not verify (${check.reason})`;
    return result;
  }
  if (check.kind === "unsupported") {
    // A declared signing_mode this build cannot verify is a REJECTION, not a
    // partial result. Without this branch the check falls through to ok = true
    // and the downgrade is silently accepted.
    result.failureReason = `Unsupported signing_mode "${check.mode}" — this build cannot verify proofs signed under that mode`;
    return result;
  }
  if (check.kind === "absent") {
    result.failureReason = "No verifiable signature present (unsigned proof)";
    return result;
  }

  result.signatureValid = true;
  result.ok = true;
  return result;
}

// ── Wave-N (ADR-039 + ADR-041) re-exports ───────────────────────────────────
//
// Per-record receipt + cross-org parent-proof composition surface. The Wave-N
// primitives live in `./wave_n.ts` and are re-exported here so consumers can
// `import { verifyFullAuditProof, verifyRecordReceipt } from "@nanorix/sdk/verifier"`.
//
// Forever-Standard (ADR-006 I0): pre-Wave-N AuditProofs verify byte-identically
// via the (null, null) Step 8 branch in `computeStep8Amended`.
export {
  GENESIS_SHA512_HEX,
  PARENT_PROOF_MAX_DEPTH,
  PATTERN_TAGS_WIRE,
  WaveNVerifyError,
  merklePairHash,
  merkleRootSha512NullSeparated,
  computeRecordReceiptsMerkleRoot,
  computeParentProofsMerkleRoot,
  buildMerkleInclusionProof,
  verifyMerkleInclusionProof,
  computeActivityRoot,
  computeRecordChainHash,
  computeStep8Base,
  computeStep8Amended,
  detectParentProofCycle,
  enforceDepthCap,
  verifyRecordReceipt,
  verifyFullAuditProof,
} from "./wave_n.js";
export type {
  WaveNRecordReceipt,
  WaveNParentProofLink,
  WaveNVerifyResult,
  VerifyRecordReceiptOptions,
} from "./wave_n.js";

// Wave B Item 7 — Portable Receipt Bundle (.prb.json) surface.
export {
  PORTABLE_RECEIPT_BUNDLE_DISCLAIMER,
  BundleError,
  extractReceiptBundle,
  verifyReceiptBundle,
} from "./bundle.js";
export type { AuditProofAnchors, BundleErrorKind, PortableReceiptBundle } from "./bundle.js";

// Wave B Item 8 — Portable Pubkey Bundle (.ppb.json) surface.
export {
  PORTABLE_PUBKEY_BUNDLE_DISCLAIMER,
  PubkeyBundleError,
  buildPubkeyBundle,
  resolveParentKey,
  resolveParentKeyForever,
  verifyPubkeyBundle,
} from "./pubkey_bundle.js";
export type {
  BundleSignature,
  PortablePubkeyBundle,
  PubKeyEntry,
  PubkeyBundleErrorKind,
} from "./pubkey_bundle.js";
