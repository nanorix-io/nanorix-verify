/**
 * Portable Receipt Bundle (.prb.json) — TypeScript port.
 *
 * Pure TypeScript port of `tools/nanorix-verify/src/bundle.rs`. Cross-impl
 * byte-equivalence with Rust/Go/Python on the canonical reference vectors.
 *
 * Per the rule that a signed record's fields are not widened beyond what happened: this is
 * a JSON convention + JSON Schema + SDK helper — NOT a new file format with
 * MIME registration / OS-level associations.
 *
 * Per the rule that the signed record states what happened and the
 * customer's auditor decides what it means: bundle disclaimer cites; never
 * asserts compliance. The verdict words in
 * `GRC_FORBIDDEN_VOCAB` never appear in the disclaimer text.
 *
 * Uses Web Crypto SubtleCrypto for SHA-512 + Ed25519 verify.
 */

import { CANONICAL_SUBSYSTEMS, computeStepHash, METHOD_MAP } from "./auditproof.js";
import {
  computeActivityRoot,
  computeRecordChainHash,
  computeStep8Amended,
  GENESIS_SHA512_HEX,
  verifyMerkleInclusionProof,
  type WaveNRecordReceipt,
} from "./wave_n.js";
import { hasSmallOrderKeyOrR } from "./_ed25519_strict.js";

/**
 * `signature_target` values: which anchor the outer Ed25519 signature covers.
 * An absent `signature_target` means the legacy target.
 */
export const SIGNATURE_TARGET_STEP8_CHAIN_HASH = "step8_chain_hash";
export const SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH = "document_canonical_hash";

/**
 * Mandatory bundle disclaimer — factual language only.
 * The verdict words in `GRC_FORBIDDEN_VOCAB` never appear in this text.
 */
export const PORTABLE_RECEIPT_BUNDLE_DISCLAIMER =
  "This Portable Receipt Bundle carries cryptographic evidence of one record's structural execution. " +
  "Verifying party uses the audit_proof_anchors to verify the receipt's merkle inclusion + outer Ed25519 signature. " +
  "Control framework references are NOT included in this bundle; consult the mapping artifact at " +
  "https://nanorix.io/v1/control-map?framework_version={framework_version} to apply current control mappings at consumption time.";

/**
 * Minimal outer-AuditProof anchors carried in a Portable Receipt Bundle.
 */
export interface AuditProofAnchors {
  capsule_id: string;
  key_id: string;
  verification_key: string;
  step_8_chain_hash: string;
  signature: string;
  record_receipts_merkle_root: string;
  timestamp: string;
  framework_version_at_emit?: string;
  /**
   * Which anchor the outer signature covers. Absent = legacy
   * `step8_chain_hash` (bundles from v1.0/v2.0 proofs predate the field).
   */
  signature_target?: string;
  /**
   * Document canonical hash (bare lowercase hex): the signed message when
   * `signature_target` is `document_canonical_hash`.
   */
  document_canonical_hash?: string;
  /**
   * Parent-proofs Merkle root (`sha512:`-prefixed). Present only when the
   * source proof has parent links; Step 8 commits to it.
   */
  parent_proofs_merkle_root?: string;
}

/**
 * Outcome of `verifyReceiptBundleDetailed`.
 *
 * `signature_authentic`: the outer Ed25519 signature verifies over the anchor
 * named by `signature_target`. `receipt_bound`: the bundle alone ties the
 * receipt to the signed value. True for the legacy target; false for
 * `document_canonical_hash`, whose signed value commits to a document the
 * bundle does not carry.
 */
export interface BundleVerification {
  signature_authentic: boolean;
  receipt_bound: boolean;
  signature_target: string;
}

/**
 * True only when the signature is authentic and the receipt is bound.
 * Matches Rust `is_valid()`, Go `Valid()` and Python `valid`.
 *
 * Integrity only: the signature is checked against the key the bundle carries,
 * so `true` never says who signed. `bundleVerificationStatus` says so.
 */
export function isValid(result: BundleVerification): boolean {
  return result.signature_authentic && result.receipt_bound;
}

/**
 * `"not_anchored"` when `isValid(result)`, otherwise `"not_verified"`. Never
 * `"verified"`: no key list is read, so the signing key is only the one the
 * bundle carries. Matches Rust `status()`, Go `Status()` and Python `status`.
 */
export function bundleVerificationStatus(result: BundleVerification): "not_anchored" | "not_verified" {
  return isValid(result) ? "not_anchored" : "not_verified";
}

/**
 * Wire shape mirroring Rust `PortableReceiptBundle`.
 *
 * Forever-Standard: `bundle_version` is append-only; the V1.0
 * shape remains valid forever.
 */
export interface PortableReceiptBundle {
  bundle_version: string;
  bundle_type: string;
  generated_at: string;
  receipt: Record<string, unknown> & WaveNRecordReceipt;
  audit_proof_anchors: AuditProofAnchors;
  disclaimer: string;
}

/** Error kinds — match Rust BundleError variants for cross-impl diffability. */
export type BundleErrorKind =
  | "no_receipts"
  | "index_out_of_bounds"
  | "missing_field"
  | "record_chain_hash_mismatch"
  | "merkle_inclusion_failed"
  | "signature_failed"
  | "base64_decode"
  | "shape"
  /** The bundled Merkle root is not the one the signed Step 8 hash commits to. */
  | "step_8_mismatch"
  | "missing_canonical_hash_anchor"
  | "malformed_canonical_hash_anchor"
  | "unknown_signature_target"
  /** Signature authentic, but the bundle alone cannot bind the receipt. */
  | "receipt_not_bound";

export class BundleError extends Error {
  readonly kind: BundleErrorKind;
  readonly reason: string;
  constructor(kind: BundleErrorKind, reason = "") {
    super(reason ? `[${kind}] ${reason}` : kind);
    this.name = "BundleError";
    this.kind = kind;
    this.reason = reason;
  }
}

function stripSha512Prefix(s: string): string {
  return s.startsWith("sha512:") ? s.slice("sha512:".length) : s;
}

function stripBase64Prefix(s: string): string {
  return s.startsWith("base64:") ? s.slice("base64:".length) : s;
}

function nowIso8601(): string {
  const d = new Date();
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function getSubtle(): SubtleCrypto {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (g.crypto?.subtle) return g.crypto.subtle as SubtleCrypto;
  throw new Error("Web Crypto SubtleCrypto not available");
}

function base64Decode(b64: string): Uint8Array {
  const stripped = stripBase64Prefix(b64);
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(stripped, "base64"));
  }
  const bin = atob(stripped);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * Extract a single receipt + outer anchors into a Portable Receipt Bundle.
 *
 * @param auditProof Full FullCdp/VerificationCdp JSON object.
 * @param recordIndex Zero-indexed position within `record_receipts`.
 * @throws BundleError with kind `no_receipts` if AuditProof is legacy;
 *         `index_out_of_bounds` if index outside receipt set;
 *         `missing_field` if a required outer field is absent.
 */
export function extractReceiptBundle(
  auditProof: Record<string, unknown>,
  recordIndex: number,
): PortableReceiptBundle {
  const receipts = auditProof.record_receipts;
  if (!Array.isArray(receipts)) {
    throw new BundleError("no_receipts", "AuditProof has no record_receipts field");
  }
  if (recordIndex >= receipts.length) {
    throw new BundleError(
      "index_out_of_bounds",
      `index ${recordIndex} out of bounds; ${receipts.length} receipts`,
    );
  }
  const receipt = receipts[recordIndex] as Record<string, unknown> & WaveNRecordReceipt;

  const capsuleId = auditProof.capsule_id;
  if (typeof capsuleId !== "string") {
    throw new BundleError("missing_field", "capsule_id");
  }
  const timestamp = auditProof.destroyed_at;
  if (typeof timestamp !== "string") {
    throw new BundleError("missing_field", "destroyed_at");
  }
  const attestation = (auditProof.attestation as Record<string, unknown>) ?? {};

  const keyId =
    (typeof attestation.key_id === "string" && attestation.key_id) ||
    (typeof auditProof.key_id === "string" && auditProof.key_id) ||
    "";
  if (!keyId) throw new BundleError("missing_field", "attestation.key_id");

  const verificationKey =
    (typeof attestation.verification_key === "string" && attestation.verification_key) ||
    (typeof attestation.public_key === "string" && attestation.public_key) ||
    (typeof auditProof.verification_key === "string" && auditProof.verification_key) ||
    "";
  if (!verificationKey) throw new BundleError("missing_field", "attestation.verification_key");

  const signature =
    (typeof attestation.signature === "string" && attestation.signature) ||
    (typeof auditProof.signature === "string" && auditProof.signature) ||
    "";
  if (!signature) throw new BundleError("missing_field", "attestation.signature");

  const merkleRoot = auditProof.record_receipts_merkle_root;
  if (typeof merkleRoot !== "string") {
    throw new BundleError("missing_field", "record_receipts_merkle_root");
  }

  const chain = auditProof.chain;
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new BundleError("missing_field", "chain");
  }
  const lastStep = chain[chain.length - 1] as Record<string, unknown>;
  if (typeof lastStep !== "object" || lastStep === null) {
    throw new BundleError("missing_field", "chain[last]");
  }
  const step8ChainHash = lastStep.chain_hash;
  if (typeof step8ChainHash !== "string") {
    throw new BundleError("missing_field", "chain[last].chain_hash");
  }

  let fvae: string | undefined;
  const rc = auditProof.regulatory_context;
  if (rc && typeof rc === "object" && typeof (rc as Record<string, unknown>).framework_version === "string") {
    fvae = (rc as Record<string, string>).framework_version;
  }

  const parentRoot = auditProof.parent_proofs_merkle_root;

  const anchors: AuditProofAnchors = {
    capsule_id: capsuleId,
    key_id: keyId,
    verification_key: verificationKey,
    step_8_chain_hash: step8ChainHash,
    signature,
    record_receipts_merkle_root: merkleRoot,
    timestamp,
  };
  if (fvae !== undefined) {
    anchors.framework_version_at_emit = fvae;
  }
  if (typeof parentRoot === "string") {
    anchors.parent_proofs_merkle_root = parentRoot;
  }

  return {
    bundle_version: "1.0",
    bundle_type: "receipt",
    generated_at: nowIso8601(),
    receipt,
    audit_proof_anchors: anchors,
    disclaimer: PORTABLE_RECEIPT_BUNDLE_DISCLAIMER,
  };
}

/**
 * Rebuild the amended Step 8 hash from genesis: Steps 1-7 over the canonical
 * (subsystem, method) table at `timestamp`, then the Step 8 amendment with the
 * receipts root and the optional parent-proofs root.
 */
async function recomputeStep8(
  timestamp: string,
  recordReceiptsMerkleRoot: string,
  parentProofsMerkleRoot: string | undefined,
): Promise<string> {
  let prev = GENESIS_SHA512_HEX;
  for (const subsystem of CANONICAL_SUBSYSTEMS.slice(0, 7)) {
    prev = await computeStepHash(prev, subsystem, METHOD_MAP[subsystem] as string, timestamp);
  }
  return computeStep8Amended(prev, timestamp, recordReceiptsMerkleRoot, parentProofsMerkleRoot);
}

/**
 * Verify a Portable Receipt Bundle (Mode B standalone) and report both whether
 * the signature is authentic and whether the receipt is bound.
 *
 * Steps:
 *   1. Recompute receipt's record_chain_hash from its fields.
 *   2. Verify Merkle inclusion proof binds receipt to record_receipts_merkle_root.
 *   3. Recompute Steps 1-7 from genesis at the bundle timestamp, then the
 *      amended Step 8 with record_receipts_merkle_root (and
 *      parent_proofs_merkle_root when present); require equality with
 *      step_8_chain_hash.
 *   4. Verify the outer Ed25519 signature over the ASCII-hex bytes of the
 *      anchor named by signature_target, using verification_key.
 *
 * For the legacy target `receipt_bound` is true (the signed Step 8 hash was
 * recomputed from the bundled root). For `document_canonical_hash` it is
 * false: the signed value commits to a document the bundle does not carry.
 *
 * @throws BundleError on verification failure.
 */
export async function verifyReceiptBundleDetailed(
  bundle: PortableReceiptBundle,
): Promise<BundleVerification> {
  if (bundle.bundle_version !== "1.0") {
    throw new BundleError("shape", `unsupported bundle_version: ${bundle.bundle_version}`);
  }
  if (bundle.bundle_type !== "receipt") {
    throw new BundleError(
      "shape",
      `wrong bundle_type for Portable Receipt Bundle: ${bundle.bundle_type}`,
    );
  }

  const anchors = bundle.audit_proof_anchors;
  const r = bundle.receipt;

  // (1) Recompute record_chain_hash.
  if (typeof r.record_index !== "number") {
    throw new BundleError("shape", "receipt.record_index missing");
  }
  if (!Number.isInteger(r.record_index) || r.record_index < 0 || r.record_index > 0xffffffff) {
    throw new BundleError("shape", "receipt.record_index is not an integer in range");
  }
  if (typeof r.record_id !== "string") {
    throw new BundleError("shape", "receipt.record_id missing");
  }
  if (typeof r.record_chain_hash !== "string") {
    throw new BundleError("shape", "receipt.record_chain_hash missing");
  }
  const trail = Array.isArray(r.record_activity_trail) ? r.record_activity_trail : undefined;
  const activityRoot =
    trail && trail.length > 0 ? await computeActivityRoot(trail) : GENESIS_SHA512_HEX;
  // A declared pattern_tag is a SIGNED primitive — bind it into
  // the recomputed hash so a swapped/stripped tag fails verification.
  const recomputed = await computeRecordChainHash(
    anchors.capsule_id,
    r.record_index,
    r.record_id,
    r.record_input_hash,
    r.record_output_hash,
    activityRoot,
    typeof r.pattern_tag === "string" ? r.pattern_tag : undefined,
  );
  if (stripSha512Prefix(recomputed) !== stripSha512Prefix(r.record_chain_hash)) {
    throw new BundleError(
      "record_chain_hash_mismatch",
      `claimed=${r.record_chain_hash} recomputed=${recomputed}`,
    );
  }

  // (2) Merkle inclusion proof.
  const inclusion = Array.isArray(r.merkle_inclusion_proof) ? r.merkle_inclusion_proof : [];
  const inclusionOk = await verifyMerkleInclusionProof(
    r.record_chain_hash,
    r.record_index,
    inclusion,
    anchors.record_receipts_merkle_root,
  );
  if (!inclusionOk) {
    throw new BundleError("merkle_inclusion_failed", anchors.record_receipts_merkle_root);
  }

  // (3) Step 8 recompute. The bundle does not carry the 8-step chain, but
  // every step hashes the same timestamp over the canonical (subsystem,
  // method) table, so Steps 1-7 are derivable. Requiring the amended Step 8
  // to equal step_8_chain_hash ties the bundled Merkle root (and the
  // parent-proofs root, when present) to the Step 8 value. Runs for every
  // signature_target.
  const step8 = await recomputeStep8(
    anchors.timestamp,
    anchors.record_receipts_merkle_root,
    anchors.parent_proofs_merkle_root,
  );
  if (step8 !== stripSha512Prefix(anchors.step_8_chain_hash)) {
    throw new BundleError(
      "step_8_mismatch",
      `claimed=${anchors.step_8_chain_hash} recomputed=${step8}`,
    );
  }

  // (4) Outer Ed25519 signature over the ASCII-hex bytes of the anchor named
  // by signature_target.
  const target = anchors.signature_target;
  let signedMessage: string;
  let receiptBound: boolean;
  let effectiveTarget: string;
  if (
    target === undefined ||
    target === null ||
    target === SIGNATURE_TARGET_STEP8_CHAIN_HASH
  ) {
    signedMessage = stripSha512Prefix(anchors.step_8_chain_hash);
    receiptBound = true;
    effectiveTarget = SIGNATURE_TARGET_STEP8_CHAIN_HASH;
  } else if (target === SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH) {
    if (!anchors.document_canonical_hash) {
      throw new BundleError(
        "missing_canonical_hash_anchor",
        "signature_target=document_canonical_hash but no document_canonical_hash value",
      );
    }
    signedMessage = stripSha512Prefix(anchors.document_canonical_hash);
    // The same key signs other message shapes, such as a population head, so
    // a signature over anything but a bare hash proves nothing here.
    if (!/^[0-9a-f]{128}$/.test(signedMessage)) {
      throw new BundleError(
        "malformed_canonical_hash_anchor",
        "document_canonical_hash is not 128 lowercase hex characters after its sha512: prefix",
      );
    }
    // The canonical hash commits to the whole source document, which the
    // bundle does not carry, so the bundle alone cannot bind the receipt.
    receiptBound = false;
    effectiveTarget = SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH;
  } else {
    throw new BundleError("unknown_signature_target", String(target));
  }

  const sigBytes = base64Decode(anchors.signature);
  if (sigBytes.length !== 64) {
    throw new BundleError("signature_failed", `signature wrong size: ${sigBytes.length}`);
  }
  const pubBytes = base64Decode(anchors.verification_key);
  if (pubBytes.length !== 32) {
    throw new BundleError("signature_failed", `verification_key wrong size: ${pubBytes.length}`);
  }

  if (hasSmallOrderKeyOrR(pubBytes, sigBytes)) {
    throw new BundleError(
      "signature_failed",
      `outer Ed25519 signature does NOT verify against ${effectiveTarget}`,
    );
  }

  const subtle = getSubtle();
  let pubKey: CryptoKey;
  try {
    pubKey = await subtle.importKey(
      "raw",
      pubBytes.buffer as ArrayBuffer,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (err) {
    throw new BundleError(
      "signature_failed",
      `could not import Ed25519 pubkey: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const enc = new TextEncoder();
  const signedBytes = enc.encode(signedMessage);
  let ok: boolean;
  try {
    ok = await subtle.verify(
      { name: "Ed25519" },
      pubKey,
      sigBytes.buffer as ArrayBuffer,
      signedBytes.buffer as ArrayBuffer,
    );
  } catch (err) {
    throw new BundleError(
      "signature_failed",
      `Ed25519 verify error: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!ok) {
    throw new BundleError(
      "signature_failed",
      `outer Ed25519 signature does NOT verify against ${effectiveTarget}`,
    );
  }

  return {
    signature_authentic: true,
    receipt_bound: receiptBound,
    signature_target: effectiveTarget,
  };
}

/**
 * Verify a Portable Receipt Bundle; resolve only when the receipt is bound.
 *
 * Runs `verifyReceiptBundleDetailed`. A bundle whose signature is authentic
 * but whose receipt the bundle alone cannot bind (the `document_canonical_hash`
 * target) rejects with kind `receipt_not_bound` instead of resolving, so a
 * caller that treats a resolved promise as "verified" is never told so for an
 * unbound receipt. Use `verifyReceiptBundleDetailed` to read the distinction.
 *
 * A resolved promise is integrity only: the signature is checked against the
 * key the bundle carries, so it never says who signed (the detailed result for
 * the same bundle has `bundleVerificationStatus` `"not_anchored"`).
 *
 * @throws BundleError on verification failure.
 */
export async function verifyReceiptBundle(
  bundle: PortableReceiptBundle,
): Promise<void> {
  const result = await verifyReceiptBundleDetailed(bundle);
  if (!result.receipt_bound) {
    throw new BundleError(
      "receipt_not_bound",
      "signature is authentic over the document canonical hash, but the bundle alone " +
        "cannot bind the receipt to that signed document; verify the source AuditProof",
    );
  }
}
