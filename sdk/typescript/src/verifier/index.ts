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
 *   reference verifier across the reference corpus. Prefer this.
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
 * // trustChain: await TrustChain.fromKeyList(keyList, pinnedFingerprint), from the key
 * // list and fingerprint you obtain yourself (the Nanorix ones are published at
 * // https://verify.nanorix.io/.well-known/trust-chain.json and /.well-known/identity.txt).
 * const result = await verify(proof, { trustChain });
 * if (result.ok) {
 *   // status "verified" (stage 8)
 *   console.log("VERIFIED, key anchored:", result.chainHash);
 * } else if (result.status === "not_anchored") {
 *   console.log("SIGNATURE VALID, key not anchored:", result.verificationScope);
 * } else {
 *   console.log("NOT VERIFIED:", result.failureReason);
 * }
 * ```
 */

import {
  CANONICAL_SUBSYSTEMS,
  FailureReasonType,
  GENESIS_HASH,
  stripSha512Prefix,
  verificationStatusFor,
  verifyAuditProof,
  type FailureReason,
  type VerifierPolicy,
  type VerifyStatus,
} from "./auditproof.js";

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
  verificationStatusFor,
  verifyAuditProof,
  verifySignature,
} from "./auditproof.js";
export {
  HYBRID_PIN_PREFIX,
  HYBRID_RECORD_CHECK_MISSING,
  comparePartners,
  hybridPin,
  isHybridPin,
  TrustChain,
  TrustChainError,
} from "./trustChain.js";
export type { TrustChainErrorKind } from "./trustChain.js";
export type {
  FailureReason,
  FailureReasonTypeValue,
  SignatureCheck,
  SignatureFailureReasonValue,
  VerificationMetadata,
  VerificationResult,
  VerificationWireForm,
  VerifierPolicy,
  VerifyStatus,
} from "./auditproof.js";

export interface VerifyResult {
  /**
   * True only when `status` is `"verified"`: `verifyAuditProof` returned valid
   * at stage 8, so the version gate, chain walk, receipt and parent sets,
   * reserved slots, streaming roots, activity root, `final_hash` binding and
   * Ed25519 signature all held, and the signing key resolved in the signed key
   * list given as `policy.trustChain`. Without a key list a valid proof ends at
   * stage 7: the signature matches the key the proof carries, which a proof
   * signed with a fresh key also does, so `status` is `"not_anchored"` and `ok`
   * is false.
   */
  ok: boolean;
  /**
   * `"verified"` (stage 8, as for `ok`), `"not_anchored"` (stage 7: the chain
   * reproduced and the signature verified against the key embedded in the
   * proof only; `failureReason` is empty) or `"not_verified"` (invalid, or a
   * reproduced chain with no signature this build can check).
   */
  status: VerifyStatus;
  /**
   * True when the 8-step chain was walked and reproduced. False means "not
   * established": the chain failed to reproduce, or was never walked because an
   * earlier gate (version, reserved slot, declared root) refused the proof.
   */
  chainValid: boolean;
  /**
   * True when the Ed25519 signature verified against a key: the key embedded in
   * the proof (stage 7) or the key resolved in the key list (stage 8). It is
   * false when the proof was refused earlier, and also when a key list was given
   * and refused the key (unknown key version, revoked authority); the reason is
   * in `failureReason`. It says nothing about who signed: read `ok` for that.
   */
  signatureValid: boolean;
  subsystemsAttested: string[];
  failedStep: number | null;
  /**
   * Why the proof is not verified. Empty when `status` is `"verified"` or
   * `"not_anchored"`: a not_anchored result has no failure, only its status
   * and `verificationScope`.
   */
  failureReason: string;
  chainHash: string;
  /**
   * The `customer_declared_activity_root` the proof carries, as
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
  /**
   * What a verdict does and does not establish. The token before the first
   * ":" is the discriminator (`embedded_key_integrity`, `chain_only`,
   * `trust_chain_anchored`). Set once the signature was checked: to
   * `OFFLINE_EMBEDDED_KEY_SCOPE` at stage 7 (integrity against the key embedded
   * in the proof, not anchored) and `TRUST_CHAIN_ANCHORED_SCOPE` at stage 8.
   * Empty string otherwise.
   */
  verificationScope: string;
}

// Scope strings for the offline verdict. The text is byte-identical in the
// Python, TypeScript and Go SDKs (each has a literal-string test), so a
// wording change must touch all three.
export const TRUST_CHAIN_ANCHORED_SCOPE =
  "trust_chain_anchored: the signing key resolved to an authority in a trust-chain " +
  "manifest that verified against its pinned identity fingerprint, and the signature " +
  "verified against that key (stage 8). This establishes which published authority's " +
  "key produced the signature over the signed message (the final chain hash for a 1.0 proof, " +
  "and for 2.1 and 2.2 the canonical-view hash " +
  "recomputed from the document's fields); content that message does not cover is not attested " +
  "by the signature, and the signature does not by itself establish that " +
  "the events the document describes occurred.";
export const OFFLINE_EMBEDDED_KEY_SCOPE =
  "embedded_key_integrity: the 8-step chain reproduced and the Ed25519 signature " +
  "verified against the key embedded in this proof. No trust-chain manifest was checked, " +
  "so that key was not resolved against a published authority (stage 7, not " +
  "stage 8); who signed is not established here. To anchor the key, set a trust-chain " +
  "manifest and its pinned identity fingerprint in the verifier policy, or run nanorix-verify " +
  "<proof.json> --trust-chain <trust-chain.json> --identity-fingerprint <pin>; it " +
  "anchors only when the proof's signing_key_version, under its authority_id " +
  "(us-kms-nanorix-v1 if it names none), resolves in that manifest.";
/**
 * The scope of a valid 1.0 verdict. It keeps the embedded_key_integrity token
 * (stage 7) and says what a 1.0 signature covers, which no key list changes.
 */
export const OFFLINE_V1_0_SCOPE =
  "embedded_key_integrity: the 8-step chain reproduced and the Ed25519 signature over " +
  "final_hash verified against the key embedded in this 1.0 proof. A 1.0 signature covers " +
  "final_hash alone, which binds destroyed_at and the two optional Merkle roots " +
  "(record_receipts_merkle_root and parent_proofs_merkle_root). It does not bind the " +
  "capsule_id itself (only through record receipts, which a holder can remove), the " +
  "region or the key id, so this verdict names no capsule. A 1.0 proof is " +
  "never anchored to a key list (stage 7, not stage 8), with or without a trust-chain " +
  "manifest.";
export const OFFLINE_CHAIN_ONLY_SCOPE =
  "chain_only: the 8-step chain reproduced, but the proof carries no signature this " +
  "verifier checks (no attestation, a missing signature or key, or a version with no " +
  "signed message), so neither the signer nor that the document is unaltered since " +
  "signing is established.";

/**
 * Derive the scope string for an offline verdict. Total over every
 * (valid, stageReached) pair; an invalid verdict has no scope (empty string).
 * The flat `verify()` reaches stage 8 only when given a
 * `trustChain` in its policy; a caller holding a `verifyAuditProof` result can
 * pass its stage here to get the matching scope. A 1.0 proof never reaches
 * stage 8, and its stage-7 scope says why: a caller deriving the scope of a
 * 1.0 result must pass its `cdpVersion`, or it gets the 2.x embedded-key scope.
 */
export function verificationScopeFor(valid: boolean, stageReached: number, cdpVersion = ""): string {
  if (!valid) return "";
  if (stageReached >= 8) return TRUST_CHAIN_ANCHORED_SCOPE;
  if (stageReached >= 7) return cdpVersion === "1.0" ? OFFLINE_V1_0_SCOPE : OFFLINE_EMBEDDED_KEY_SCOPE;
  return OFFLINE_CHAIN_ONLY_SCOPE;
}

/**
 * Reserved-slot scope discriminator.
 *
 * AuditProof scope. Absent means workload scope. The sealed-proxy ("call") and
 * sealed-middleware ("request") scopes populate it; high-volume per-record
 * AuditProofs use "batch".
 *
 * Forever-Standard discipline: field-additive Optional with
 * skip_serializing_if mechanic on the Rust side. The verifier MUST treat
 * this as opaque — chain integrity verification is independent of cdp_kind.
 */
export type CdpKind = "workload" | "request" | "call" | "batch";

/**
 * True when the failure says the 8-step chain itself did not reproduce, or was
 * never walked. The full verifier reuses `step_hash_mismatch` for a receipt
 * (subsystem `record_receipt[i]`) and `final_hash_mismatch` at stage 3 for a
 * receipt or parent set whose Merkle root does not reproduce; neither is a
 * chain defect.
 */
function isChainDefect(reason: FailureReason, stage: number, chain: unknown): boolean {
  if (stage < 3) return true;
  switch (reason.type) {
    case FailureReasonType.STEP_COUNT_INVALID:
    case FailureReasonType.CHAIN_STEP_IDENTITY_MISMATCH:
    case FailureReasonType.GENESIS_HASH_MISMATCH:
      return true;
    case FailureReasonType.STEP_HASH_MISMATCH:
      return !isReceiptFailure(reason, chain);
    case FailureReasonType.FINAL_HASH_MISMATCH:
      return stage === 4;
    case FailureReasonType.REQUIRED_FIELD_MISSING:
      return reason.field === "chain";
    default:
      return false;
  }
}

/**
 * A receipt failure carries `record_receipt[i]` as its subsystem. A chain step
 * failure carries the label the document gave that step, so a forged chain can
 * name a core step `record_receipt[0]`. When any chain step bears that same
 * label the string came from the document, not from a receipt walk.
 */
function isReceiptFailure(reason: FailureReason, chain: unknown): boolean {
  const subsystem = reason.subsystem ?? "";
  if (!subsystem.startsWith("record_receipt[")) return false;
  if (!Array.isArray(chain)) return true;
  return !chain.some(
    (st) =>
      st !== null &&
      typeof st === "object" &&
      (st as Record<string, unknown>)["subsystem"] === subsystem,
  );
}

/** One-line prose for a structured failure reason, carrying its payload. */
function renderFailure(reason: FailureReason, cdpVersion: string, stage: number, chain: unknown): string {
  switch (reason.type) {
    case FailureReasonType.UNSIGNED_FIELD_POPULATED:
      return `Field '${reason.field}' is populated but is outside the signature on cdp_version ${JSON.stringify(cdpVersion)}`;
    case FailureReasonType.FIELD_MALFORMED:
      return `Field '${reason.field}' is malformed: ${reason.reason}`;
    case FailureReasonType.CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH:
      return "customer_declared_activity_root does not reproduce from the supplied activity record (the chain itself reproduced)";
    case FailureReasonType.REQUIRED_FIELD_MISSING:
      return reason.field === "customer_declared_activity_root"
        ? `An activity record was supplied but the proof declares no '${reason.field}'`
        : `Required field '${reason.field}' is missing or inconsistent with the proof`;
    case FailureReasonType.CDP_VERSION_UNSUPPORTED:
      return `${FailureReasonType.CDP_VERSION_UNSUPPORTED}: found ${JSON.stringify(reason.found)}`;
    case FailureReasonType.CHAIN_STEP_IDENTITY_MISMATCH:
      return `Subsystem mismatch at step ${(reason.step_idx ?? 0) + 1}: expected ${JSON.stringify(reason.expected_subsystem)}, got ${JSON.stringify(reason.found_subsystem)}`;
    case FailureReasonType.STEP_COUNT_INVALID:
      return `Subsystem mismatch: expected ${reason.expected} chain steps, got ${reason.found}`;
    case FailureReasonType.STEP_HASH_MISMATCH:
      if (isReceiptFailure(reason, chain)) {
        return `Receipt ${reason.subsystem} does not reproduce its chain hash`;
      }
      return `Chain hash mismatch at step ${(reason.step_idx ?? 0) + 1} (${JSON.stringify(reason.subsystem ?? "")})`;
    case FailureReasonType.FINAL_HASH_MISMATCH:
      return stage === 4
        ? "final_hash does not bind the chain"
        : "A receipt set or parent set does not reproduce its Merkle root";
    case FailureReasonType.SIGNING_KEY_VERSION_UNKNOWN:
      return "The key list has no entry for this proof's authority and signing key version, so the key is not anchored";
    case FailureReasonType.AUTHORITY_REVOKED:
      return "The key list marks this proof's authority as revoked, so the key is not anchored";
    case FailureReasonType.SIGNATURE_MISMATCH:
      return `Ed25519 signature did not verify (${reason.reason})`;
    case FailureReasonType.ALGORITHM_UNSUPPORTED:
      return typeof reason.found === "string" && reason.found.startsWith("signing_mode=")
        ? `Unsupported signing_mode "${reason.found.slice("signing_mode=".length)}" — this build cannot verify proofs signed under that mode`
        : `Unsupported signature algorithm: ${JSON.stringify(reason.found)} (expected Ed25519)`;
    case FailureReasonType.SIGNING_MODE_AUTHORITY_MISMATCH:
      return `signing_mode is customer_only but authority_id ${
        typeof reason.claimed_authority_id === "string"
          ? JSON.stringify(reason.claimed_authority_id)
          : "(absent or not a string, so the Nanorix default applies)"
      } is not a customer authority; the two labels disagree and no signature was checked, which says nothing about who signed`;
    default:
      return `Verification failed: ${JSON.stringify(reason)}`;
  }
}

/**
 * Verify an AuditProof (CDP) offline.
 *
 * A thin adapter over `verifyAuditProof()`: the full staged pipeline runs
 * (version gate, chain walk, receipt set, parent set, reserved slots,
 * streaming roots, activity root, final-hash binding, signature) and its
 * verdict is projected onto the flat result. `ok` is true only when `status`
 * is `"verified"`: the pipeline reached stage 8 with `valid`, so the signing
 * key resolved in the `trustChain` given in `policy`. A valid signature without
 * a key list (stage 7) is `status: "not_anchored"`, `signatureValid` and
 * `ok: false`; a chain with no signature this build can check stops at stage 4
 * and is `"not_verified"`.
 *
 * @param proof  AuditProof as parsed JSON object. A parsed object has lost the
 *   original bytes and the earlier copies of a repeated key, so a document the
 *   reference refuses for those reasons can verify here; pass the file's bytes
 *   to `verifyAuditProof` for a verdict that agrees with the reference.
 * @param policy Optional `VerifierPolicy`, forwarded whole to `verifyAuditProof`
 *   (`trustChain`, the pins, the `rejectDiagnostic` setting, the activity
 *   record).
 * @returns VerifyResult with `.ok=true` only when `verifyAuditProof` returns
 *   valid at stage 8.
 */
export async function verify(
  proof: unknown,
  policy?: VerifierPolicy,
): Promise<VerifyResult> {
  const result: VerifyResult = {
    ok: false,
    status: "not_verified",
    chainValid: false,
    signatureValid: false,
    subsystemsAttested: [],
    failedStep: null,
    failureReason: "",
    chainHash: "",
    customerDeclaredActivityRoot: null,
    customerDeclaredActivityChecked: null,
    verificationScope: "",
  };

  if (
    typeof proof !== "object" ||
    proof === null ||
    Array.isArray(proof) ||
    ArrayBuffer.isView(proof)
  ) {
    result.failureReason = `verify() expected object (a parsed JSON object); got ${typeof proof}`;
    return result;
  }
  const p = proof as Record<string, unknown>;
  const chain = p["chain"];
  if (Array.isArray(chain)) {
    result.subsystemsAttested = chain.map((s) =>
      s && typeof s === "object" && typeof (s as Record<string, unknown>)["subsystem"] === "string"
        ? ((s as Record<string, unknown>)["subsystem"] as string)
        : "",
    );
  }

  const full = await verifyAuditProof(p, policy);
  const cdpVersion = typeof p["cdp_version"] === "string" ? (p["cdp_version"] as string) : "";
  const reason = full.failure_reason;

  result.customerDeclaredActivityRoot = full.metadata.customerDeclaredActivityRoot ?? null;
  result.customerDeclaredActivityChecked = full.metadata.customerDeclaredActivityChecked ?? null;

  const chainDefect = reason !== null && isChainDefect(reason, full.stage_reached, chain);
  result.chainValid = !chainDefect && (full.valid || full.stage_reached >= 3);

  const chainStepDefect =
    reason !== null &&
    (reason.type === FailureReasonType.STEP_HASH_MISMATCH ||
      reason.type === FailureReasonType.CHAIN_STEP_IDENTITY_MISMATCH) &&
    chainDefect;
  if (Array.isArray(chain) && chain.length > 0) {
    const idx = chainStepDefect ? (reason.step_idx ?? 0) : chain.length - 1;
    const step = chain[idx] as Record<string, unknown> | undefined;
    if (result.chainValid || reason?.type === FailureReasonType.STEP_HASH_MISMATCH) {
      result.chainHash = stripSha512Prefix(
        step && typeof step["chain_hash"] === "string" ? (step["chain_hash"] as string) : "",
      );
    }
  }
  if (chainStepDefect) {
    result.failedStep = (reason.step_idx ?? 0) + 1;
  } else if (chainDefect && reason?.type === FailureReasonType.FINAL_HASH_MISMATCH && Array.isArray(chain)) {
    result.failedStep = chain.length;
  }

  if (!full.valid) {
    result.failureReason = reason ? renderFailure(reason, cdpVersion, full.stage_reached, chain) : "Verification failed";
    return result;
  }
  if (full.stage_reached < 7) {
    result.failureReason = "No verifiable signature present (unsigned proof)";
    return result;
  }

  result.signatureValid = true;
  result.verificationScope = verificationScopeFor(true, full.stage_reached, cdpVersion);
  result.status = verificationStatusFor(true, full.stage_reached);
  result.ok = result.status === "verified";
  return result;
}

// ── Per-record receipt re-exports ───────────────────────
//
// Per-record receipt + cross-org parent-proof composition surface. The receipt
// primitives live in `./wave_n.ts` and are re-exported here so consumers can
// `import { verifyFullAuditProof, verifyRecordReceipt } from "@nanorix/sdk/verifier"`.
//
// Forever-Standard: legacy AuditProofs verify byte-identically
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

// customer_declared_activity_root sidecar check. The root is
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

// Portable Receipt Bundle (.prb.json) surface.
export {
  PORTABLE_RECEIPT_BUNDLE_DISCLAIMER,
  BundleError,
  bundleVerificationStatus,
  extractReceiptBundle,
  isValid,
  SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH,
  SIGNATURE_TARGET_STEP8_CHAIN_HASH,
  verifyReceiptBundle,
  verifyReceiptBundleDetailed,
} from "./bundle.js";
export type {
  AuditProofAnchors,
  BundleErrorKind,
  BundleVerification,
  PortableReceiptBundle,
} from "./bundle.js";

// Portable Pubkey Bundle (.ppb.json) surface.
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
