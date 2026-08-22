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
  FailureReasonType,
  GENESIS_HASH,
  computeStepHash,
  gateDeclaredActivityRoot,
  lookupMethod,
  resolveChainTimestamp,
  stripSha512Prefix,
  verifySignature,
  type FailureReason,
  type VerifierPolicy,
} from "./auditproof.js";
import { computeStep8Amended } from "./wave_n.js";
import {
  CustomerDeclaredActivityStatus,
  verifyCustomerDeclaredActivity,
} from "./customer_activity.js";

export { GENESIS_HASH, CANONICAL_SUBSYSTEMS };

// ── Full-pipeline surface (structured verdicts, policy pins) ────────────────
export {
  CANONICAL_VIEW_SIGNED_VERSIONS,
  CHAIN_STEP_COUNT,
  FailureReasonType,
  ROOT_MALFORMED_EMPTY,
  ROOT_MALFORMED_NOT_A_STRING,
  ROOT_MALFORMED_SHAPE,
  checkDeclaredActivityRootShape,
  gateDeclaredActivityRoot,
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
  /**
   * True iff the chain reproduced, the Ed25519 signature verified, and — when
   * an activity record was supplied — its recomputed root matched the
   * proof's `customer_declared_activity_root`.
   */
  ok: boolean;
  chainValid: boolean;
  signatureValid: boolean;
  subsystemsAttested: string[];
  failedStep: number | null;
  failureReason: string;
  chainHash: string;
  /**
   * ADR-056. The `customer_declared_activity_root` the proof carries, as
   * written; null when it declares none. Disclosed whether or not the record
   * was supplied, so a reader never has to assume a declared root was
   * checked.
   */
  customerDeclaredActivityRoot: string | null;
  /**
   * True when the record was supplied and its recomputed root matched; false
   * when the proof declares a root but no record was supplied — declared,
   * not checked; null when the proof declares no root. A mismatch is a
   * failure (`ok=false`), never a false here.
   */
  customerDeclaredActivityChecked: boolean | null;
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

/** One-line prose for the ADR-056 failure reasons the flat result can carry. */
function renderActivityFailure(reason: FailureReason, cdpVersion: string): string {
  switch (reason.type) {
    case FailureReasonType.UNSIGNED_FIELD_POPULATED:
      return `Field '${reason.field}' is populated but is outside the signature on cdp_version ${JSON.stringify(cdpVersion)}`;
    case FailureReasonType.FIELD_MALFORMED:
      return `Field '${reason.field}' is malformed: ${reason.reason}`;
    case FailureReasonType.CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH:
      return "customer_declared_activity_root does not reproduce from the supplied activity record (the chain itself reproduced)";
    case FailureReasonType.REQUIRED_FIELD_MISSING:
      return `An activity record was supplied but the proof declares no '${reason.field}'`;
    default:
      return `Verification failed: ${reason.type}`;
  }
}

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
 * A declared `customer_declared_activity_root` (ADR-056) is gated and
 * disclosed the way the stage ladder does it: on a version that does not sign
 * it, or of a shape no signer emits, the proof is rejected before the chain
 * walk; with `policy.customerActivity` supplied the root is recomputed from
 * those bytes after the walk and a mismatch fails the verdict without
 * blaming the chain.
 *
 * @param proof  AuditProof as parsed JSON object.
 * @param policy Optional; only `customerActivity` (the record's raw bytes)
 *   is read here — the other pins belong to `verifyAuditProof`.
 * @returns VerifyResult with `.ok=true` iff no check that ran failed.
 */
export async function verify(
  proof: unknown,
  policy?: Pick<VerifierPolicy, "customerActivity">,
): Promise<VerifyResult> {
  const result: VerifyResult = {
    ok: false,
    chainValid: false,
    signatureValid: false,
    subsystemsAttested: [],
    failedStep: null,
    failureReason: "",
    chainHash: "",
    customerDeclaredActivityRoot: null,
    customerDeclaredActivityChecked: null,
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

  const cdpVersion =
    typeof p["cdp_version"] === "string" ? (p["cdp_version"] as string) : "";

  // ADR-056 stage-2 gate, before the walk: a root on a version that does not
  // sign it, or of a shape no signer emits, names the field as the defect
  // rather than letting a recompute blame the signature or the record.
  const rootGate = gateDeclaredActivityRoot(p, cdpVersion);
  if (rootGate !== null) {
    result.failureReason = renderActivityFailure(rootGate, cdpVersion);
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

  // ADR-056 sidecar check, after the walk: every step hash reproduced, so a
  // failure here is reported without a failedStep and with chainValid true.
  const activity = await verifyCustomerDeclaredActivity(
    p,
    policy?.customerActivity,
  );
  result.customerDeclaredActivityRoot = activity.claimed;
  if (activity.status === CustomerDeclaredActivityStatus.FAILED) {
    result.failureReason = renderActivityFailure(
      activity.failure_reason as FailureReason,
      cdpVersion,
    );
    return result;
  }
  if (activity.status === CustomerDeclaredActivityStatus.VERIFIED) {
    result.customerDeclaredActivityChecked = true;
  } else if (
    activity.status === CustomerDeclaredActivityStatus.DECLARED_NOT_CHECKED
  ) {
    result.customerDeclaredActivityChecked = false;
  }

  // Ed25519 signature over the version-appropriate message.
  const att =
    p["attestation"] && typeof p["attestation"] === "object"
      ? (p["attestation"] as Record<string, unknown>)
      : {};
  if (att["algorithm"] !== "Ed25519") {
    result.failureReason = `Unsupported signature algorithm: ${JSON.stringify(att["algorithm"])} (expected Ed25519)`;
    return result;
  }

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

// ADR-056 — customer_declared_activity_root sidecar check. The root is
// signature-bound by the canonical view; this surface checks that a file of
// raw activity bytes in hand is the one that root commits to.
export {
  CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
  CustomerDeclaredActivityStatus,
  computeCustomerDeclaredActivityRoot,
  customerDeclaredActivityLeafHashes,
  splitCustomerDeclaredActivityLines,
  verifyCustomerDeclaredActivity,
} from "./customer_activity.js";
export type {
  CustomerDeclaredActivityCheck,
  CustomerDeclaredActivityStatusValue,
} from "./customer_activity.js";

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
