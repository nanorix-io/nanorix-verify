/**
 * Portable Receipt Bundle (.prb.json) — Wave B Item 7 surface, TypeScript port.
 *
 * Pure TypeScript port of `tools/nanorix-verify/src/bundle.rs`. Cross-impl
 * byte-equivalence with Rust/Go/Python on the canonical reference vectors.
 *
 * Per feedback_narrowness_is_the_moat_resist_receipt_enrichment.md: this is
 * a JSON convention + JSON Schema + SDK helper — NOT a new file format with
 * MIME registration / OS-level associations.
 *
 * Per feedback_narrow_signed_claim_auditor_certifies.md: bundle disclaimer
 * cites; never asserts compliance. Vocabulary discipline forbids
 * COMPLIANT/SATISFIED/PASSED/MEETS in the disclaimer text.
 *
 * Uses Web Crypto SubtleCrypto for SHA-512 + Ed25519 verify.
 */

import {
  computeActivityRoot,
  computeRecordChainHash,
  GENESIS_SHA512_HEX,
  verifyMerkleInclusionProof,
  type WaveNRecordReceipt,
} from "./wave_n.js";

/**
 * Mandatory bundle disclaimer — factual language only.
 * Vocabulary discipline forbids COMPLIANT/SATISFIED/PASSED/MEETS.
 */
export const PORTABLE_RECEIPT_BUNDLE_DISCLAIMER =
  "This Portable Receipt Bundle carries cryptographic evidence of one record's structural execution. " +
  "Verifying party uses the audit_proof_anchors to verify the receipt's merkle inclusion + outer Ed25519 signature. " +
  "Control framework references are NOT included in this bundle; consult the specification mapping artifact at " +
  "schema.nanorix.com/control-map/{framework_version}.json to apply current control mappings at consumption time.";

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
}

/**
 * Wave B Item 7 wire shape mirroring Rust `PortableReceiptBundle`.
 *
 * Forever-Standard the Forever-Standard wire discipline: `bundle_version` is append-only; the V1.0
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
  | "shape";

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
 * @throws BundleError with kind `no_receipts` if AuditProof is pre-the receipt pipeline;
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
 * Verify a Portable Receipt Bundle (Mode B standalone).
 *
 * Steps:
 *   1. Recompute receipt's record_chain_hash from its fields.
 *   2. Verify Merkle inclusion proof binds receipt to record_receipts_merkle_root.
 *   3. Verify outer Ed25519 signature over step_8_chain_hash ASCII-hex using
 *      verification_key.
 *
 * @throws BundleError on verification failure.
 */
export async function verifyReceiptBundle(
  bundle: PortableReceiptBundle,
): Promise<void> {
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
  if (typeof r.record_id !== "string") {
    throw new BundleError("shape", "receipt.record_id missing");
  }
  if (typeof r.record_chain_hash !== "string") {
    throw new BundleError("shape", "receipt.record_chain_hash missing");
  }
  const trail = Array.isArray(r.record_activity_trail) ? r.record_activity_trail : undefined;
  const activityRoot =
    trail && trail.length > 0 ? await computeActivityRoot(trail) : GENESIS_SHA512_HEX;
  // A declared pattern_tag is a SIGNED primitive (the per-record receipt specification) — bind it into
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

  // (3) Outer Ed25519 signature over step_8_chain_hash ASCII-hex.
  //
  // Bundle does NOT carry the full 8-step chain (would defeat portability).
  // Ed25519 signature transitively binds chain + receipt set integrity via the
  // producer's outer authority. For full chain re-verification, the consumer
  // uses the original AuditProof.
  const sigBytes = base64Decode(anchors.signature);
  if (sigBytes.length !== 64) {
    throw new BundleError("signature_failed", `signature wrong size: ${sigBytes.length}`);
  }
  const pubBytes = base64Decode(anchors.verification_key);
  if (pubBytes.length !== 32) {
    throw new BundleError("signature_failed", `verification_key wrong size: ${pubBytes.length}`);
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
  const chainHashAscii = enc.encode(stripSha512Prefix(anchors.step_8_chain_hash));
  let ok: boolean;
  try {
    ok = await subtle.verify(
      { name: "Ed25519" },
      pubKey,
      sigBytes.buffer as ArrayBuffer,
      chainHashAscii.buffer as ArrayBuffer,
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
      "outer Ed25519 signature does NOT verify against step_8_chain_hash",
    );
  }
}
