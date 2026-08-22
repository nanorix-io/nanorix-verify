/**
 * Wave-N (ADR-039 + ADR-041) per-record receipt + parent-proof verification.
 *
 * Pure TypeScript port of `governance/rzl/src/wave_n.rs` plus the verifier-side
 * extension in `tools/nanorix-verify/src/lib.rs`. Cross-impl byte-equivalent
 * with Rust + Go + Python ports on the 110-fixture extended corpus.
 *
 * **Forever-Standard discipline (ADR-006 I0):** every primitive here is part
 * of the cryptographic-attestation contract. Cross-impl divergence from the
 * canonical Rust output is a P0 finding.
 *
 * Uses Web Crypto SubtleCrypto for SHA-512 + Ed25519. The Wave-N hash primitives
 * are async because SubtleCrypto.digest returns a Promise.
 *
 * Distinct from `merkle.ts`: that module implements RFC 6962 binary Merkle
 * (leaf prefix 0x00 + inner prefix 0x01) used by `Capsule.batch()`. Wave-N
 * uses the ADR-039 canonical pair-hash form:
 * `SHA-512(left_hex_bytes || \x00 || right_hex_bytes)` with NO domain prefix.
 *
 * Cross-impl reference vectors (locked in `verifier_wave_n.test.ts`):
 *
 *   GENESIS_SHA512_HEX = cf83e135...da3e
 *   merkle_pair_hash("aaa", "bbb") = 04ed285c...bf9bd264
 *   compute_step_8_amended(GENESIS, "2026-05-12T00:00:00Z", null, null) =
 *     3b6a0c8f...129b3fbf
 */

import { canonicalizeBytes } from "../_jcs.js";

/**
 * Genesis SHA-512 hash of the empty string. Re-exported so this module is
 * self-contained — mirrors Rust `nanorix_rzl::wave_n::GENESIS_SHA512_HEX`.
 */
export const GENESIS_SHA512_HEX =
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/**
 * Maximum supported parent-proof chain depth per ADR-041 §"Depth limit". V1: 32.
 */
export const PARENT_PROOF_MAX_DEPTH = 32;

/**
 * Closed-enum pattern tag wire values (mirror Rust
 * `nanorix_rzl::types::PatternTag` and `nanorix.capsule_record.PATTERN_TAGS`).
 *
 * Used by downstream consumers; the verifier itself does NOT reject unknown
 * pattern_tag values (forward-compatibility per ADR-006 I0).
 */
export const PATTERN_TAGS_WIRE: readonly string[] = [
  "pa",
  "extraction",
  "annotation",
  "agent_step",
  "agent_turn",
  "rcm_claim",
  "rcm_eligibility",
  "rcm_remit",
  "ncpdp_script",
  "dicom_study",
  "dicom_sr",
  "screening_hit",
  "fhir_record",
  "ehr_document",
  "custom",
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// Pre-Wave-N legacy formula constants
// ─────────────────────────────────────────────────────────────────────────────

const STEP_8_SUBSYSTEM = "capsule_destroy";
const STEP_8_ACTION = "destroy";
const STEP_8_METHOD = "capsule_lifecycle_verification";

// ─────────────────────────────────────────────────────────────────────────────
// Wave-N types — mirror `nanorix_rzl::types::{RecordReceipt, ParentProofLink}`
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Per-record receipt mirroring Rust `RecordReceipt`.
 *
 * Forever-Standard discipline (ADR-006 I0): field shape is permanent.
 * New fields land as additive optional — existing fields NEVER renamed,
 * NEVER removed, NEVER repurposed.
 *
 * **No `control_tags` field by design.** Per ADR-039 §"Receipt as direct
 * evidence primitive" + ADR-040 RE-SCOPED: control IDs are NEVER stamped
 * into the signed receipt; adapters apply ADR-040 mapping artifact at
 * ingestion time.
 */
export interface WaveNRecordReceipt {
  record_index: number;
  record_id: string;
  record_input_hash: string;
  record_output_hash: string;
  record_chain_hash: string;
  record_activity_trail?: unknown[];
  pattern_tag?: string;
  merkle_inclusion_proof?: string[];
}

/**
 * Cross-org parent-proof link mirroring Rust `ParentProofLink`.
 *
 * Forever-Standard (ADR-006 I0): optional fields skip-serialize when undefined.
 */
export interface WaveNParentProofLink {
  parent_chain_hash: string;
  parent_key_id: string;
  parent_signature: string;
  parent_role?: string;
  parent_jurisdiction?: string;
  parent_organization_tag?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// SubtleCrypto helpers
// ─────────────────────────────────────────────────────────────────────────────

function getSubtle(): SubtleCrypto {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (g.crypto?.subtle) return g.crypto.subtle as SubtleCrypto;
  throw new Error(
    "Web Crypto SubtleCrypto not available (need Node 18+ or modern browser)",
  );
}

function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function base64Decode(b64: string): Uint8Array {
  const stripped = b64.startsWith("base64:") ? b64.slice("base64:".length) : b64;
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(stripped, "base64"));
  }
  const bin = atob(stripped);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function stripSha512Prefix(s: string): string {
  return s.startsWith("sha512:") ? s.slice("sha512:".length) : s;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

async function sha512Hex(data: Uint8Array): Promise<string> {
  const subtle = getSubtle();
  // ArrayBuffer-typed Buffer slice required for tsc strict types
  const digest = await subtle.digest("SHA-512", data.buffer as ArrayBuffer);
  return bytesToHex(digest);
}

// ─────────────────────────────────────────────────────────────────────────────
// Merkle pair-hash + root construction (ADR-039)
// ─────────────────────────────────────────────────────────────────────────────

const ENC = new TextEncoder();
const NULL = new Uint8Array([0]);

/**
 * Compute SHA-512(left_hex_bytes || \x00 || right_hex_bytes).
 *
 * Per ADR-039 §"Sibling pair hashing rule": both inputs are interpreted as
 * their hex-string byte values (UTF-8 of the hex chars). Either MAY carry a
 * `sha512:` prefix; stripped before hashing.
 *
 * Output: lowercase 128-char hex (no prefix). Cross-impl byte-equivalent with
 * Rust + Go + Python `merkle_pair_hash`.
 */
export async function merklePairHash(left: string, right: string): Promise<string> {
  const l = stripSha512Prefix(left);
  const r = stripSha512Prefix(right);
  return sha512Hex(concatBytes(ENC.encode(l), NULL, ENC.encode(r)));
}

/**
 * Build the canonical Merkle root over an ordered slice of SHA-512 leaf
 * hashes per ADR-039 §"Merkle tree construction".
 *
 *   - leaves.length === 0 → null
 *   - leaves.length === 1 → leaves[0] with `sha512:` prefix stripped
 *   - leaves.length >= 2 → binary tree with odd-level duplication
 *
 * Output: bare lowercase hex (no `sha512:` prefix); caller prepends for
 * wire form. Cross-impl byte-equivalent with Rust counterpart.
 */
export async function merkleRootSha512NullSeparated(
  leaves: readonly string[],
): Promise<string | null> {
  if (leaves.length === 0) return null;
  if (leaves.length === 1) return stripSha512Prefix(leaves[0]);

  let level: string[] = leaves.map(stripSha512Prefix);
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; ) {
      if (i + 1 < level.length) {
        next.push(await merklePairHash(level[i], level[i + 1]));
        i += 2;
      } else {
        // Odd-level last node: duplicate per ADR-039.
        next.push(await merklePairHash(level[i], level[i]));
        i += 1;
      }
    }
    level = next;
  }
  return level[0];
}

/**
 * Public ADR-039 surface for the receipt Merkle root.
 *
 * Returns `null` for empty input (field skip-serializes in canonical JSON);
 * otherwise returns `sha512:{hex}` matching the ADR-039 wire form.
 */
export async function computeRecordReceiptsMerkleRoot(
  receipts: readonly WaveNRecordReceipt[],
): Promise<string | null> {
  if (receipts.length === 0) return null;
  const leaves = receipts.map((r) => r.record_chain_hash);
  const root = await merkleRootSha512NullSeparated(leaves);
  return root === null ? null : `sha512:${root}`;
}

/** Public ADR-041 surface for the parent-proof Merkle root. */
export async function computeParentProofsMerkleRoot(
  parents: readonly WaveNParentProofLink[],
): Promise<string | null> {
  if (parents.length === 0) return null;
  const leaves = parents.map((p) => p.parent_chain_hash);
  const root = await merkleRootSha512NullSeparated(leaves);
  return root === null ? null : `sha512:${root}`;
}

/**
 * Build a Merkle inclusion proof for `leafIndex` per ADR-039.
 *
 * Returns siblings on the path from leaf → root in bottom-up order (each
 * as bare hex). Empty array when N=1. `null` when out of range or empty.
 */
export async function buildMerkleInclusionProof(
  leaves: readonly string[],
  leafIndex: number,
): Promise<string[] | null> {
  if (leaves.length === 0 || leafIndex < 0 || leafIndex >= leaves.length) {
    return null;
  }
  if (leaves.length === 1) return [];
  let idx = leafIndex;
  let level: string[] = leaves.map(stripSha512Prefix);
  const proof: string[] = [];
  while (level.length > 1) {
    let siblingIdx: number;
    if (idx % 2 === 0) {
      siblingIdx = idx + 1 < level.length ? idx + 1 : idx;
    } else {
      siblingIdx = idx - 1;
    }
    proof.push(level[siblingIdx]);

    const next: string[] = [];
    for (let i = 0; i < level.length; ) {
      if (i + 1 < level.length) {
        next.push(await merklePairHash(level[i], level[i + 1]));
        i += 2;
      } else {
        next.push(await merklePairHash(level[i], level[i]));
        i += 1;
      }
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return proof;
}

/** Recompute root from leaf + proof + leafIndex; compare to claimed root. */
export async function verifyMerkleInclusionProof(
  leaf: string,
  leafIndex: number,
  proof: readonly string[],
  claimedRoot: string,
): Promise<boolean> {
  const leafStripped = stripSha512Prefix(leaf);
  const claimedStripped = stripSha512Prefix(claimedRoot);

  // N=1 fast path.
  if (proof.length === 0) return leafStripped === claimedStripped;

  let current = leafStripped;
  let idx = leafIndex;
  for (const sibling of proof) {
    if (idx % 2 === 0) {
      current = await merklePairHash(current, sibling);
    } else {
      current = await merklePairHash(sibling, current);
    }
    idx = Math.floor(idx / 2);
  }
  return current === claimedStripped;
}

// ─────────────────────────────────────────────────────────────────────────────
// Activity root (per-record SHA-512 chain over canonical JCS events)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute per-record activity root mirroring Rust `compute_activity_root`.
 *
 * SHA-512 chain over canonical-JSON (RFC 8785 JCS) event hashes; genesis hash
 * fallback when trail is null/empty. Output: lowercase 128-char hex (no prefix).
 */
export async function computeActivityRoot(
  trail: readonly unknown[] | undefined | null,
): Promise<string> {
  if (!trail || trail.length === 0) return GENESIS_SHA512_HEX;
  let prev = GENESIS_SHA512_HEX;
  for (const event of trail) {
    const canonical = canonicalizeBytes(event);
    const eventHash = await sha512Hex(canonical);
    prev = await sha512Hex(
      concatBytes(ENC.encode(prev), NULL, ENC.encode(eventHash)),
    );
  }
  return prev;
}

// ─────────────────────────────────────────────────────────────────────────────
// Record chain hash (ADR-039 per-record chain hash formula)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute per-record chain hash mirroring Rust `compute_record_chain_hash`.
 *
 *   SHA-512(capsule_id || \x00 || record_index || \x00 || record_id || \x00
 *           || record_input_hash || \x00 || record_output_hash || \x00
 *           || activity_root_or_genesis [|| \x00 || pattern_tag_wire])
 *
 * `record_index` is decimal-formatted. Hash inputs MAY carry `sha512:`; stripped.
 *
 * `patternTagWire` is the snake_case wire string exactly as serialized in the
 * receipt JSON `pattern_tag` field. The trailing `\x00 || pattern_tag_wire`
 * segment is appended ONLY when the receipt declares a tag (ADR-039: the tag
 * is a signed primitive, so it must be bound here, not merely carried in the
 * JSON). Domain separation is sound because `activity_root_or_genesis` is
 * always exactly 128 stripped hex chars: a tagged preimage is strictly longer
 * than every untagged preimage, so the conditional append cannot collide.
 * Untagged receipts keep the pre-fix byte formula (clean-cut, zero external
 * consumers at fix time).
 *
 * Returns chain hash WITH `sha512:` prefix.
 */
export async function computeRecordChainHash(
  capsuleId: string,
  recordIndex: number,
  recordId: string,
  recordInputHash: string,
  recordOutputHash: string,
  activityRootOrGenesis: string,
  patternTagWire?: string | null,
): Promise<string> {
  const inH = stripSha512Prefix(recordInputHash);
  const outH = stripSha512Prefix(recordOutputHash);
  const actH = stripSha512Prefix(activityRootOrGenesis);
  const idx = String(recordIndex);

  const chunks = [
    ENC.encode(capsuleId),
    NULL,
    ENC.encode(idx),
    NULL,
    ENC.encode(recordId),
    NULL,
    ENC.encode(inH),
    NULL,
    ENC.encode(outH),
    NULL,
    ENC.encode(actH),
  ];
  if (patternTagWire !== undefined && patternTagWire !== null) {
    chunks.push(NULL, ENC.encode(patternTagWire));
  }
  const digest = await sha512Hex(concatBytes(...chunks));
  return `sha512:${digest}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 8 base + amended (presence-conditional 4-arm formula)
// ─────────────────────────────────────────────────────────────────────────────

async function computeStepHash(
  prevHash: string,
  subsystem: string,
  action: string,
  method: string,
  timestamp: string,
): Promise<string> {
  const data = concatBytes(
    ENC.encode(prevHash),
    NULL,
    ENC.encode(subsystem),
    NULL,
    ENC.encode(action),
    NULL,
    ENC.encode(method),
    NULL,
    ENC.encode(timestamp),
  );
  return sha512Hex(data);
}

/** Pre-Wave-N legacy Step 8 base hash. Mirrors Rust `compute_step_8_base`. */
export async function computeStep8Base(
  prevHash: string,
  timestamp: string,
): Promise<string> {
  return computeStepHash(
    prevHash,
    STEP_8_SUBSYSTEM,
    STEP_8_ACTION,
    STEP_8_METHOD,
    timestamp,
  );
}

/**
 * The presence-conditional Step 8 amendment formula (ADR-039 + ADR-041).
 *
 * Mirrors Rust `compute_step_8_amended` byte-for-byte. Output: bare lowercase
 * hex (no prefix). The (null, null) arm returns `computeStep8Base(...)`
 * UNMODIFIED — byte-identical to every pre-Wave-N production AuditProof.
 *
 * Forever-Standard (ADR-006 I0).
 */
export async function computeStep8Amended(
  prevHash: string,
  timestamp: string,
  recordReceiptsMerkleRoot: string | null | undefined,
  parentProofsMerkleRoot: string | null | undefined,
): Promise<string> {
  const base = await computeStep8Base(prevHash, timestamp);
  const rr = recordReceiptsMerkleRoot ?? null;
  const pp = parentProofsMerkleRoot ?? null;

  if (rr === null && pp === null) return base;

  if (rr !== null && pp === null) {
    const rrStripped = stripSha512Prefix(rr);
    return sha512Hex(
      concatBytes(ENC.encode(base), NULL, ENC.encode(rrStripped)),
    );
  }
  if (rr === null && pp !== null) {
    const ppStripped = stripSha512Prefix(pp);
    return sha512Hex(
      concatBytes(ENC.encode(base), NULL, ENC.encode(ppStripped)),
    );
  }
  // both
  const rrStripped = stripSha512Prefix(rr as string);
  const ppStripped = stripSha512Prefix(pp as string);
  return sha512Hex(
    concatBytes(
      ENC.encode(base),
      NULL,
      ENC.encode(rrStripped),
      NULL,
      ENC.encode(ppStripped),
    ),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cycle prevention + depth cap (ADR-041)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Reject cycles per ADR-041 §"Cycle prevention".
 *
 * Returns the index of the cyclic parent if any `parent_chain_hash` equals
 * `selfChainHash`; returns -1 otherwise. Both inputs prefix-tolerant.
 */
export function detectParentProofCycle(
  parents: readonly WaveNParentProofLink[],
  selfChainHash: string,
): number {
  const selfStripped = stripSha512Prefix(selfChainHash);
  for (let i = 0; i < parents.length; i++) {
    if (stripSha512Prefix(parents[i].parent_chain_hash) === selfStripped) {
      return i;
    }
  }
  return -1;
}

/** Throws RangeError if parent count exceeds PARENT_PROOF_MAX_DEPTH=32. */
export function enforceDepthCap(parents: readonly WaveNParentProofLink[]): void {
  if (parents.length > PARENT_PROOF_MAX_DEPTH) {
    throw new RangeError(
      `parent chain depth ${parents.length} exceeds PARENT_PROOF_MAX_DEPTH=${PARENT_PROOF_MAX_DEPTH} (ADR-041)`,
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode B — Standalone receipt verification
// ─────────────────────────────────────────────────────────────────────────────

/** Inputs needed to verify a standalone receipt detached from its AuditProof. */
export interface VerifyRecordReceiptOptions {
  /** The outer AuditProof's `capsule_id` field. */
  capsuleId: string;
  /** The AuditProof's `record_receipts_merkle_root`. May carry `sha512:`. */
  outerMerkleRoot: string;
  /** The AuditProof's Step 8 amended chain_hash. */
  outerChainHash: string;
  /** The outer attestation.signature, base64-encoded. May carry `base64:`. */
  outerSignatureB64: string;
  /** The trusted signing authority's Ed25519 public key (raw 32 bytes). */
  outerPublicKey: Uint8Array;
}

export class WaveNVerifyError extends Error {
  readonly stage: string;
  constructor(reason: string, stage = "wave_n") {
    super(`[${stage}] ${reason}`);
    this.name = "WaveNVerifyError";
    this.stage = stage;
  }
}

/**
 * Mode B (standalone) verification per ADR-039.
 *
 *   1. Recompute the receipt's `record_chain_hash` from its fields.
 *   2. Verify the Merkle inclusion proof binds the receipt to outerMerkleRoot.
 *   3. Verify the outer Ed25519 signature over outerChainHash ASCII-hex.
 *
 * Throws WaveNVerifyError on first failure.
 */
export async function verifyRecordReceipt(
  receipt: WaveNRecordReceipt,
  opts: VerifyRecordReceiptOptions,
): Promise<void> {
  // (1) Recompute chain hash. A declared pattern_tag is a SIGNED primitive
  // (ADR-039) — it binds into the recomputed hash so a swapped/stripped tag
  // fails verification. Non-string values fail closed via the untagged arm.
  const activityRoot = await computeActivityRoot(receipt.record_activity_trail);
  const recomputed = await computeRecordChainHash(
    opts.capsuleId,
    receipt.record_index,
    receipt.record_id,
    receipt.record_input_hash,
    receipt.record_output_hash,
    activityRoot,
    typeof receipt.pattern_tag === "string" ? receipt.pattern_tag : undefined,
  );
  if (stripSha512Prefix(recomputed) !== stripSha512Prefix(receipt.record_chain_hash)) {
    throw new WaveNVerifyError(
      `record_chain_hash mismatch: recomputed=${recomputed} claimed=${receipt.record_chain_hash}`,
      "record_chain_hash",
    );
  }

  // (2) Inclusion proof binds to outer root.
  const inclusionOk = await verifyMerkleInclusionProof(
    receipt.record_chain_hash,
    receipt.record_index,
    receipt.merkle_inclusion_proof ?? [],
    opts.outerMerkleRoot,
  );
  if (!inclusionOk) {
    throw new WaveNVerifyError(
      `merkle inclusion proof does NOT bind receipt to outer root ${opts.outerMerkleRoot}`,
      "merkle_inclusion",
    );
  }

  // (3) Outer Ed25519 signature over outer chain_hash ASCII-hex.
  const subtle = getSubtle();
  const sigBytes = base64Decode(opts.outerSignatureB64);
  if (sigBytes.length !== 64) {
    throw new WaveNVerifyError(
      `outer signature wrong size: got ${sigBytes.length}, want 64`,
      "signature_decode",
    );
  }
  if (opts.outerPublicKey.length !== 32) {
    throw new WaveNVerifyError(
      `outer public key wrong size: got ${opts.outerPublicKey.length}, want 32`,
      "signature_decode",
    );
  }

  let pubKey: CryptoKey;
  try {
    pubKey = await subtle.importKey(
      "raw",
      opts.outerPublicKey.buffer as ArrayBuffer,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (err) {
    throw new WaveNVerifyError(
      `could not import Ed25519 public key: ${err instanceof Error ? err.message : String(err)}`,
      "signature_decode",
    );
  }

  const chainHashAscii = ENC.encode(stripSha512Prefix(opts.outerChainHash));
  let ok: boolean;
  try {
    ok = await subtle.verify(
      { name: "Ed25519" },
      pubKey,
      sigBytes.buffer as ArrayBuffer,
      chainHashAscii.buffer as ArrayBuffer,
    );
  } catch (err) {
    throw new WaveNVerifyError(
      `Ed25519 verify error: ${err instanceof Error ? err.message : String(err)}`,
      "signature_verify",
    );
  }
  if (!ok) {
    throw new WaveNVerifyError(
      "outer Ed25519 signature does NOT verify against outer chain_hash",
      "signature_verify",
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode A — Full Wave-N AuditProof verification (extends V1 chain pipeline)
// ─────────────────────────────────────────────────────────────────────────────

/** Canonical 8-step subsystem order; mirrors `nanorix.verifier`. */
const CANONICAL_SUBSYSTEMS = [
  "eee_namespace",
  "eee_tmpfs",
  "eee_memory",
  "dire_keys",
  "dire_identity",
  "fgx_forensic",
  "rzl_audit",
  "capsule_destroy",
] as const;

const CANONICAL_METHODS: Record<string, string> = {
  eee_namespace: "procfs_verification",
  eee_tmpfs: "mountinfo_verification",
  eee_memory: "dod_5220_multipass_wipe",
  dire_keys: "ed25519_key_destruction",
  dire_identity: "credential_incineration",
  fgx_forensic: "merkle_tree_verification",
  rzl_audit: "hash_chain_validation",
  capsule_destroy: "capsule_lifecycle_verification",
};

export interface WaveNVerifyResult {
  valid: boolean;
  failureReason: string;
  stageReached: number;
}

interface ChainStepLike {
  subsystem?: string;
  method?: string;
  chain_hash?: string;
}

interface ProofLike {
  cdp_version?: string;
  capsule_id?: string;
  destroyed_at?: string;
  chain?: ChainStepLike[];
  final_hash?: string;
  record_receipts?: WaveNRecordReceipt[];
  record_receipts_merkle_root?: string;
  parent_proof_hashes?: WaveNParentProofLink[];
  parent_proofs_merkle_root?: string;
}

async function verifyRecordReceiptsArray(
  receipts: readonly WaveNRecordReceipt[],
  capsuleId: string,
  claimedRoot: string | undefined | null,
): Promise<string | null> {
  if (!claimedRoot) return null;
  const leafChainHashes: string[] = [];
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    const trail = r.record_activity_trail;
    const activityRoot =
      Array.isArray(trail) && trail.length > 0
        ? await computeActivityRoot(trail)
        : GENESIS_SHA512_HEX;
    const recomputed = await computeRecordChainHash(
      capsuleId,
      r.record_index,
      r.record_id,
      r.record_input_hash,
      r.record_output_hash,
      activityRoot,
      typeof r.pattern_tag === "string" ? r.pattern_tag : undefined,
    );
    if (stripSha512Prefix(recomputed) !== stripSha512Prefix(r.record_chain_hash)) {
      return `record_receipt[${i}] chain hash mismatch`;
    }
    leafChainHashes.push(stripSha512Prefix(recomputed));
  }
  const recomputedRoot =
    (await merkleRootSha512NullSeparated(leafChainHashes)) ?? "";
  if (recomputedRoot !== stripSha512Prefix(claimedRoot)) {
    return `record_receipts_merkle_root mismatch: claimed=${claimedRoot} computed=sha512:${recomputedRoot}`;
  }
  return null;
}

async function verifyParentProofsArray(
  parents: readonly WaveNParentProofLink[],
  claimedRoot: string | undefined | null,
): Promise<string | null> {
  if (!claimedRoot) return null;
  const leaves = parents.map((p) => p.parent_chain_hash);
  const recomputed = (await merkleRootSha512NullSeparated(leaves)) ?? "";
  if (recomputed !== stripSha512Prefix(claimedRoot)) {
    return `parent_proofs_merkle_root mismatch: claimed=${claimedRoot} computed=sha512:${recomputed}`;
  }
  return null;
}

/**
 * Mode A — full Wave-N AuditProof verification.
 *
 * Extends the V1 8-stage pipeline with:
 *   - Step 8 amended chain walk (ADR-039 + ADR-041 4-arm formula)
 *   - Per-receipt chain hash roundtrip
 *   - `record_receipts_merkle_root` binding
 *   - `parent_proofs_merkle_root` binding
 *   - parent depth-cap-32 enforcement
 *
 * Forever-Standard: pre-Wave-N AuditProofs (no record_receipts, no
 * parent_proof_hashes) verify byte-identically via the (null, null) Step 8
 * branch collapsing to the legacy formula.
 */
export async function verifyFullAuditProof(
  proof: unknown,
): Promise<WaveNVerifyResult> {
  if (typeof proof !== "object" || proof === null) {
    return {
      valid: false,
      failureReason: `verifyFullAuditProof expected object; got ${typeof proof}`,
      stageReached: 1,
    };
  }
  const p = proof as ProofLike;

  const cdpVersion = p.cdp_version;
  if (typeof cdpVersion !== "string") {
    return { valid: false, failureReason: "cdp_version missing", stageReached: 1 };
  }
  if (!["1.0", "2.0", "2.1", "2.2"].includes(cdpVersion)) {
    return {
      valid: false,
      failureReason: `cdp_version unsupported: ${cdpVersion}`,
      stageReached: 2,
    };
  }

  const chain = p.chain;
  if (!Array.isArray(chain)) {
    return { valid: false, failureReason: "chain missing", stageReached: 3 };
  }
  if (chain.length !== 8) {
    return {
      valid: false,
      failureReason: `chain step count ${chain.length} != 8`,
      stageReached: 3,
    };
  }
  const timestamp = typeof p.destroyed_at === "string" ? p.destroyed_at : "";

  const rrmr =
    typeof p.record_receipts_merkle_root === "string"
      ? p.record_receipts_merkle_root
      : null;
  const ppmr =
    typeof p.parent_proofs_merkle_root === "string"
      ? p.parent_proofs_merkle_root
      : null;

  let prevHash = GENESIS_SHA512_HEX;
  for (let idx = 0; idx < chain.length; idx++) {
    // Canonical-identity walk: hash inputs come from CANONICAL_SUBSYSTEMS by
    // INDEX, never from the document.
    const step = chain[idx] ?? {};
    const canonicalSubsystem = CANONICAL_SUBSYSTEMS[idx] as string;
    const declaredSubsystem = step.subsystem ?? "";
    const claimedChainHash = step.chain_hash ?? "";
    const method = CANONICAL_METHODS[canonicalSubsystem] ?? "";
    let recomputed: string;
    if (idx === CANONICAL_SUBSYSTEMS.length - 1) {
      recomputed = await computeStep8Amended(prevHash, timestamp, rrmr, ppmr);
    } else {
      recomputed = await computeStepHash(
        prevHash,
        canonicalSubsystem,
        "destroy",
        method,
        timestamp,
      );
    }
    if (recomputed !== stripSha512Prefix(claimedChainHash)) {
      return {
        valid: false,
        failureReason: `chain step ${idx} (${declaredSubsystem}) hash mismatch`,
        stageReached: 3,
      };
    }
    if (declaredSubsystem !== canonicalSubsystem) {
      return {
        valid: false,
        failureReason:
          `chain step ${idx} names subsystem "${declaredSubsystem}"; ` +
          `canonical is "${canonicalSubsystem}"`,
        stageReached: 3,
      };
    }
    prevHash = recomputed;
  }

  // ADR-039 record-receipt-set verification.
  const capsuleId = typeof p.capsule_id === "string" ? p.capsule_id : "";
  const receipts = p.record_receipts;
  if (Array.isArray(receipts)) {
    const err = await verifyRecordReceiptsArray(receipts, capsuleId, rrmr);
    if (err !== null) {
      return { valid: false, failureReason: err, stageReached: 3 };
    }
  }

  // ADR-041 parent-proof-set verification.
  const parents = p.parent_proof_hashes;
  if (Array.isArray(parents)) {
    const err = await verifyParentProofsArray(parents, ppmr);
    if (err !== null) {
      return { valid: false, failureReason: err, stageReached: 3 };
    }
    if (parents.length > PARENT_PROOF_MAX_DEPTH) {
      return {
        valid: false,
        failureReason: `parent_proof_hashes depth ${parents.length} exceeds ${PARENT_PROOF_MAX_DEPTH}`,
        stageReached: 3,
      };
    }
  }

  // Stage 4: final_hash binding.
  const claimedFinal = typeof p.final_hash === "string" ? p.final_hash : "";
  const lastStep = chain[chain.length - 1] ?? {};
  const lastChainHash =
    typeof lastStep.chain_hash === "string" ? lastStep.chain_hash : "";
  if (stripSha512Prefix(claimedFinal) !== stripSha512Prefix(lastChainHash)) {
    return {
      valid: false,
      failureReason: `final_hash mismatch: claimed=${claimedFinal} computed=${lastChainHash}`,
      stageReached: 4,
    };
  }

  return { valid: true, failureReason: "", stageReached: 4 };
}
