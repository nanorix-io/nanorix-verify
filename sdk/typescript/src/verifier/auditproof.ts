/**
 * Offline AuditProof verification core — byte-equivalent with the Rust
 * reference verifier at `tools/nanorix-verify/src/`.
 *
 * This module is the single TypeScript implementation of the 8-stage pipeline.
 * `./index.ts` (legacy `verify()`) and `../debug.ts` (`verifyAuditProof()`)
 * both adapt to it rather than carrying their own chain walk — two independent
 * walks is how the SDK came to ship one surface that rejected every genuine
 * proof and another that accepted forged signatures.
 *
 * Held to `tools/nanorix-verify/fixtures/corpus/` (100 fixtures, committed
 * `.expected.json` verdicts) by `tests/verifier_corpus.test.ts`.
 *
 * Two facts the wire format does not make obvious, and that every
 * reimplementation has gotten wrong:
 *
 * 1. `method` is a FIXED per-subsystem constant (see `METHOD_MAP`), not a
 *    field of the chain step. The serialized step carries
 *    `step / subsystem / operation / evidence_hash / chain_hash` — no
 *    `method`, no `timestamp`. Reading them off the step yields empty strings
 *    and a chain that reproduces nothing.
 * 2. The signed message depends on the CDP version: v1.0 signs `final_hash`,
 *    v2.0 signs `document_hash`, v2.1 `nanorix_only` signs the ADR-011 Part-3
 *    canonical-view hash. Verifying the wrong message accepts a downgraded
 *    proof.
 *
 * Pure Web Crypto — no Node built-ins, so the browser verifier can consume it.
 */

import { canonicalizeBytes } from "../_jcs.js";
import {
  computeActivityRoot,
  computeRecordChainHash,
  computeStep8Amended,
  merkleRootSha512NullSeparated,
} from "./wave_n.js";
import { verifyStreamingMerkleRoots } from "./streaming_merkle.js";

/** Genesis hash — SHA-512(""). Forever-stable per ADR-006 I0. */
export const GENESIS_HASH =
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/** Canonical method strings per subsystem. Forever-stable per ADR-006 I0. */
export const METHOD_MAP: Record<string, string> = {
  eee_namespace: "procfs_verification",
  eee_tmpfs: "mountinfo_verification",
  eee_memory: "dod_5220_multipass_wipe",
  dire_keys: "ed25519_key_destruction",
  dire_identity: "credential_incineration",
  fgx_forensic: "merkle_tree_verification",
  rzl_audit: "hash_chain_validation",
  capsule_destroy: "capsule_lifecycle_verification",
};

/** Canonical 8-step subsystem order (must match CHAIN_DEFS in cdp.rs). */
export const CANONICAL_SUBSYSTEMS = [
  "eee_namespace",
  "eee_tmpfs",
  "eee_memory",
  "dire_keys",
  "dire_identity",
  "fgx_forensic",
  "rzl_audit",
  "capsule_destroy",
] as const;

export const SUPPORTED_CDP_VERSIONS: ReadonlySet<string> = new Set([
  "1.0",
  "2.0",
  "2.1",
]);
export const CHAIN_STEP_COUNT = 8;

/**
 * Reserved attestation slots outside CanonicalCdpView (ADR-011 I18-I21,
 * I24-I25 + ADR-012 D2/D3) that no Nanorix signer populates. Every
 * construction site hard-codes them to None, so the signature never covered
 * them and a genuine document never carries them; a populated one was added
 * after signing by someone holding no key, and the signature cannot tell,
 * because it never covered the field.
 *
 * `per_event_attestations` is the ninth reserved slot and is deliberately
 * absent: the server drains capsule_event_attestations into it at destroy, so
 * genuine proofs do carry it, and each entry is signed by the customer's own
 * key. Mirrors the Rust, Go and Python verifiers.
 */
export const UNSIGNED_RESERVED_SLOTS: readonly string[] = [
  "customer_attestation",
  "policy_attestation",
  "third_party_attestation",
  "retention_policy_attestation",
  "witness_signatures",
  "pqc_attestation",
  "customer_pqc_attestation",
];

const PARENT_ATTRIBUTION_FIELDS: readonly string[] = [
  "parent_key_id",
  "parent_signature",
  "parent_role",
  "parent_jurisdiction",
  "parent_organization_tag",
];

/** Closed-set failure reason wire types. Forever-stable per ADR-006 I0. Additive only. */
export const FailureReasonType = {
  ALGORITHM_UNSUPPORTED: "algorithm_unsupported",
  AUTHORITY_ID_MISMATCH: "authority_id_mismatch",
  AUTHORITY_MODE_MISMATCH: "authority_mode_mismatch",
  AUTHORITY_REVOKED: "authority_revoked",
  CDP_VERSION_UNSUPPORTED: "cdp_version_unsupported",
  CHAIN_STEP_IDENTITY_MISMATCH: "chain_step_identity_mismatch",
  DIAGNOSTIC_PROOF_REFUSED: "diagnostic_proof_refused",
  FINAL_HASH_MISMATCH: "final_hash_mismatch",
  GENESIS_HASH_MISMATCH: "genesis_hash_mismatch",
  REGION_MISMATCH: "region_mismatch",
  REQUIRED_FIELD_MISSING: "required_field_missing",
  RESERVED: "reserved",
  SIGNATURE_MISMATCH: "signature_mismatch",
  SIGNING_KEY_VERSION_UNKNOWN: "signing_key_version_unknown",
  STEP_COUNT_INVALID: "step_count_invalid",
  STEP_HASH_MISMATCH: "step_hash_mismatch",
  STREAMING_MERKLE_ROOT_MISMATCH: "streaming_merkle_root_mismatch",
  UNSIGNED_FIELD_POPULATED: "unsigned_field_populated",
} as const;

export type FailureReasonTypeValue =
  (typeof FailureReasonType)[keyof typeof FailureReasonType];

/**
 * Sub-reason for `signature_mismatch`. Mirrors the Rust
 * `SignatureFailureReason` wire form.
 */
export const SignatureFailureReason = {
  MALFORMED: "malformed",
  DOES_NOT_VERIFY: "does_not_verify",
  PUBLIC_KEY_MALFORMED: "public_key_malformed",
  MESSAGE_FORMAT_MISMATCH: "message_format_mismatch",
} as const;

export type SignatureFailureReasonValue =
  (typeof SignatureFailureReason)[keyof typeof SignatureFailureReason];

/** Structured failure reason. Wire form: {"type": "<snake_case>", ...payload}. */
export interface FailureReason {
  type: string;
  // Per-variant payload fields (omitted when not applicable).
  found?: string | number;
  field?: string;
  expected?: number;
  step_idx?: number;
  subsystem?: string;
  claimed?: string;
  computed?: string;
  reason?: string;
  version?: string;
  required?: string;
  actual?: string;
  claimed_authority_id?: string | null;
  expected_authority_id?: string;
  expected_subsystem?: string;
  found_subsystem?: string;
  drift_position?: number;
  drift_field?: string;
}

/** Structural metadata extracted during verification. */
export interface VerificationMetadata {
  cdpVersion: string | null;
  capsuleId: string | null;
  region: string | null;
  signingKeyVersion: string | null;
  algorithm: string | null;
  stepCount: number | null;
  activityEventCount: number | null;
  /**
   * Set when the document carried no `destroyed_at` and the chain timestamp
   * was recovered from `attestation.key_id` (ADR-047 pre-restoration proofs).
   * Never silently substituted — an auditor can always tell which route
   * produced the verdict.
   */
  recoveredChainTimestamp?: string | null;
  /**
   * Number of parent links carrying attribution the signature does not cover —
   * parent_key_id, parent_signature, parent_role, parent_jurisdiction,
   * parent_organization_tag. Only parent_chain_hash feeds the signed Merkle
   * root, so an outsider can rewrite the rest of a genuine proof's declared
   * lineage. The lineage UI renders exactly those fields, so a verdict that
   * stays silent invites them to be read as attested.
   */
  unattestedParentAttribution?: number | null;
}

/** Result of AuditProof verification. */
export interface VerificationResult {
  valid: boolean;
  failure_reason: FailureReason | null;
  stage_reached: number;
  metadata: VerificationMetadata;
}

/** Wire-form projection matching fixture corpus expected.json. */
export interface VerificationWireForm {
  valid: boolean;
  failure_reason: FailureReason | null;
}

/** Customer-side policy configuration. Field-additive per ADR-006 I0. */
export interface VerifierPolicy {
  rejectDiagnostic?: boolean;
  requiredRegion?: string;
  requiredAuthorityId?: string;
}

/** Return the wire-form projection for fixture corpus comparison. */
export function toWireForm(result: VerificationResult): VerificationWireForm {
  return {
    valid: result.valid,
    failure_reason: result.failure_reason,
  };
}

// ─── Primitives ─────────────────────────────────────────────────────────────

/** Get a SubtleCrypto instance (Node 18+ / browser). */
function getSubtle(): SubtleCrypto {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (g.crypto?.subtle) return g.crypto.subtle as SubtleCrypto;
  throw new Error(
    "Web Crypto subtle not available (need Node 18+ or modern browser)",
  );
}

/** Hex-encode ArrayBuffer or Uint8Array. */
function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/** Strip the `sha512:` prefix used in API JSON output. */
export function stripSha512Prefix(value: string): string {
  return value.startsWith("sha512:") ? value.slice("sha512:".length) : value;
}

/** Strip the `base64:` prefix used in key/signature fields. */
export function stripBase64Prefix(value: string): string {
  return value.startsWith("base64:") ? value.slice("base64:".length) : value;
}

/** Base64 → Uint8Array. Returns null when the input is not decodable. */
function base64Decode(b64: string): Uint8Array | null {
  const stripped = stripBase64Prefix(b64);
  try {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(stripped, "base64"));
    }
    const bin = atob(stripped);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Reproduce one chain step's SHA-512 hash. Forever-stable per ADR-006 I0.
 * Formula: SHA-512(prev || 0x00 || subsystem || 0x00 || "destroy" || 0x00 || method || 0x00 || timestamp)
 */
export async function computeStepHash(
  prevHash: string,
  subsystem: string,
  method: string,
  timestamp: string,
): Promise<string> {
  const enc = new TextEncoder();
  const NULL = new Uint8Array([0]);
  const parts: Uint8Array[] = [
    enc.encode(prevHash),
    NULL,
    enc.encode(subsystem),
    NULL,
    enc.encode("destroy"),
    NULL,
    enc.encode(method),
    NULL,
    enc.encode(timestamp),
  ];
  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const buf = new Uint8Array(totalLen);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  const subtle = getSubtle();
  const digest = await subtle.digest("SHA-512", buf.buffer as ArrayBuffer);
  return bytesToHex(digest);
}

/** Return the canonical method string for a subsystem. Forever-stable. */
export function lookupMethod(subsystem: string): string {
  return METHOD_MAP[subsystem] ?? "";
}

// ─── Chain timestamp resolution (ADR-047) ───────────────────────────────────

/**
 * Recover the chain timestamp from an attestation `key_id` of the form
 * `nrx-verify-{terminated_at with ':' -> '-'}-{capsule_id[..8]}`.
 *
 * Only the TIME portion ever held colons, so restoration splits at `T` and
 * rewrites dashes on the right-hand side only. Returns null unless the
 * reconstruction has the exact ISO-8601 `YYYY-MM-DDTHH:MM:SS` shape.
 *
 * `key_id` sits in neither signed message, so it is attacker-mutable — which
 * is why the recovered value is never trusted on its own. It is an INPUT to
 * the chain walk, and the chain hashes it must reproduce are signature-bound.
 * Exactly one timestamp reproduces a signed chain, so a mutated `key_id`
 * yields a mismatch and a rejection, never a false accept.
 */
export function recoverTimestampFromKeyId(keyId: string): string | null {
  if (!keyId.startsWith("nrx-verify-")) return null;
  const rest = keyId.slice("nrx-verify-".length);
  const lastDash = rest.lastIndexOf("-");
  if (lastDash < 0) return null;
  const encoded = rest.slice(0, lastDash);
  const fragment = rest.slice(lastDash + 1);
  if (fragment.length === 0) return null;
  const tIdx = encoded.indexOf("T");
  if (tIdx < 0) return null;
  const date = encoded.slice(0, tIdx);
  const time = encoded.slice(tIdx + 1).replace(/-/g, ":");
  if (!isIso8601Shaped(date, time)) return null;
  return `${date}T${time}`;
}

/** `YYYY-MM-DD` date + `HH:MM:SS` time prefix; anything after is a free tail. */
function isIso8601Shaped(date: string, time: string): boolean {
  if (date.length !== 10 || time.length < 8) return false;
  if (date[4] !== "-" || date[7] !== "-") return false;
  if (time[2] !== ":" || time[5] !== ":") return false;
  const digits = (s: string, idx: number[]) =>
    idx.every((i) => s[i] >= "0" && s[i] <= "9");
  return (
    digits(date, [0, 1, 2, 3, 5, 6, 8, 9]) && digits(time, [0, 1, 3, 4, 6, 7])
  );
}

/**
 * The timestamp the chain walk must use: the document's own `destroyed_at`,
 * or — for pre-ADR-047 proofs that omit it — the value recovered from
 * `attestation.key_id`. Returns the recovered value separately so the verdict
 * can disclose which route produced it.
 */
export function resolveChainTimestamp(proof: Record<string, unknown>): {
  timestamp: string;
  recovered: string | null;
} {
  const declared = strOrEmpty(proof["destroyed_at"]);
  if (declared !== "") return { timestamp: declared, recovered: null };
  const keyId = strOrEmpty(pointer(proof, "attestation", "key_id"));
  const recovered = keyId === "" ? null : recoverTimestampFromKeyId(keyId);
  return { timestamp: recovered ?? "", recovered };
}

// ─── ADR-011 Part-3 canonical view ──────────────────────────────────────────

/**
 * Rebuild the ADR-011 Part-3 canonical view from a proof and return its
 * RFC-8785 JCS SHA-512 hex digest — byte-identical to the server's
 * `canonical_hash()` and to the Rust verifier's `recompute_canonical_hash`.
 *
 * The AuditProof JSON already contains every value in its exact serialized
 * shape, so only the *view* is rebuilt: wire field names are mapped to
 * canonical-view keys and the two server-side transforms are applied
 * (`signing_key_version` string -> integer; the `attestation` subset). Under
 * JCS the physical key order is irrelevant, so a key-reorder tamper is either
 * semantically identical or changes a hashed value.
 */
export async function recomputeCanonicalHash(
  proof: Record<string, unknown>,
): Promise<string> {
  const view: Record<string, unknown> = {};
  const orNull = (k: string) => (k in proof ? (proof[k] ?? null) : null);

  view["version"] = orNull("cdp_version");
  view["signing_mode"] = orNull("signing_mode");
  view["jurisdiction"] = orNull("jurisdiction");
  view["authority_id"] = orNull("authority_id");
  // FullCdp stores signing_key_version as a String; the canonical view emits
  // an integer (server parses; unparseable -> 0).
  view["signing_key_version"] = parseI64(proof["signing_key_version"]);
  view["capsule_id"] = orNull("capsule_id");
  // org_id defaults to "" on the server (#[serde(default)] String).
  view["org_id"] = "org_id" in proof ? (proof["org_id"] ?? "") : "";

  // skip_serializing_if = Option::is_none -> OMIT when absent/null.
  insertIfPresent(view, "parent_audit_proof_id", proof);
  insertIfPresent(view, "cdp_kind", proof);

  // Arrays carried verbatim (canonical-view key differs from wire name).
  view["activity_trail"] = "activity" in proof ? (proof["activity"] ?? []) : [];
  view["destruction_chain"] = "chain" in proof ? (proof["chain"] ?? []) : [];
  view["destruction_state"] = orNull("destruction_state");

  // No skip attribute -> serialized as null when absent (NOT omitted).
  view["destruction_failure_step"] = orNull("destruction_failure_step");

  insertIfPresent(view, "parent_proofs_merkle_root", proof);
  insertIfPresent(view, "record_receipts_merkle_root", proof);

  view["runtime_attestation"] = orNull("runtime_attestation");

  // attestation subset. An empty fingerprint canonicalizes to null, matching
  // the server's `if fingerprint.is_empty() { None }`.
  const fingerprint = proof["attestation_chain_fingerprint"];
  view["attestation"] = {
    timestamp_attestation: orNull("timestamp_attestation"),
    attestation_chain_fingerprint:
      typeof fingerprint === "string" && fingerprint !== ""
        ? fingerprint
        : null,
  };

  view["hash_algorithm"] = orNull("hash_algorithm");
  view["signature_algorithm"] = orNull("signature_algorithm");

  const subtle = getSubtle();
  const bytes = canonicalizeBytes(view);
  const digest = await subtle.digest("SHA-512", bytes.buffer as ArrayBuffer);
  return bytesToHex(digest);
}

function insertIfPresent(
  view: Record<string, unknown>,
  key: string,
  proof: Record<string, unknown>,
): void {
  const v = proof[key];
  if (v !== undefined && v !== null) view[key] = v;
}

/** Rust `str.parse::<i64>().ok().unwrap_or(0)` over a String field. */
function parseI64(value: unknown): number {
  if (typeof value !== "string" || !/^[+-]?\d+$/.test(value)) return 0;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : 0;
}

// ─── Signature stage ────────────────────────────────────────────────────────

/**
 * Marks a `signedMessage` result as "this build cannot verify the declared
 * signing_mode" rather than a message to sign over. The NUL prefix can never
 * occur in a hex digest. Mirrors the Rust, Go and Python verifiers.
 */
const UNSUPPORTED_MODE_SENTINEL = "\u0000unsupported-signing-mode:";

/** Outcome of the signature stage (stages 5–8). */
export type SignatureCheck =
  | { kind: "verified" }
  /**
   * No signature present (unsigned partial). Nothing to check — the caller
   * keeps the honest stage-4 "chain verified, signature NOT checked" verdict.
   */
  | { kind: "absent" }
  /**
   * The document declares a `signing_mode` this build cannot verify.
   *
   * Distinct from `absent` on purpose: `signing_mode` is inside the canonical
   * hash and is attacker-controllable, so if an unrecognised mode produced the
   * same verdict as a missing signature, flipping the field would convert a
   * rejection into reassurance — a downgrade oracle. Mirrors the Rust, Go and
   * Python verifiers.
   */
  | { kind: "unsupported"; mode: string }
  | { kind: "failed"; reason: SignatureFailureReasonValue };

/**
 * Select the signed message for a proof by version/mode:
 * - `1.0` -> `final_hash`
 * - `2.0` -> `document_hash`
 * - `2.1` + `nanorix_only` -> recomputed canonical hash
 * - `2.1` + `dual_signature` / `tee_attested` -> null (not verifiable here)
 */
async function signedMessage(
  proof: Record<string, unknown>,
  cdpVersion: string,
): Promise<string | null> {
  switch (cdpVersion) {
    case "1.0":
      return stripSha512Prefix(strOrEmpty(proof["final_hash"]));
    case "2.0":
      return stripSha512Prefix(strOrEmpty(proof["document_hash"]));
    case "2.1": {
      const mode = proof["signing_mode"];
      const signingMode = typeof mode === "string" ? mode : "nanorix_only";
      // Any other declared mode is one this build cannot verify. NOT the same as
      // "no signature" — signalled with a sentinel the callers translate.
      if (signingMode !== "nanorix_only") {
        return UNSUPPORTED_MODE_SENTINEL + signingMode;
      }
      return recomputeCanonicalHash(proof);
    }
    default:
      return null;
  }
}

/** Decode base64 signature + public key and verify `message` under them. */
async function verifyMessageWithKey(
  message: string,
  sigB64: string,
  pubB64: string,
): Promise<SignatureCheck> {
  const sigBytes = base64Decode(sigB64);
  if (sigBytes === null || sigBytes.length !== 64) {
    return { kind: "failed", reason: SignatureFailureReason.MALFORMED };
  }
  const pubBytes = base64Decode(pubB64);
  if (pubBytes === null || pubBytes.length !== 32) {
    return {
      kind: "failed",
      reason: SignatureFailureReason.PUBLIC_KEY_MALFORMED,
    };
  }

  const subtle = getSubtle();
  let publicKey: CryptoKey;
  try {
    publicKey = await subtle.importKey(
      "raw",
      pubBytes.buffer as ArrayBuffer,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch {
    return {
      kind: "failed",
      reason: SignatureFailureReason.PUBLIC_KEY_MALFORMED,
    };
  }

  try {
    const ok = await subtle.verify(
      { name: "Ed25519" },
      publicKey,
      sigBytes.buffer as ArrayBuffer,
      new TextEncoder().encode(message).buffer as ArrayBuffer,
    );
    return ok
      ? { kind: "verified" }
      : { kind: "failed", reason: SignatureFailureReason.DOES_NOT_VERIFY };
  } catch {
    return { kind: "failed", reason: SignatureFailureReason.DOES_NOT_VERIFY };
  }
}

/**
 * Verify the proof's signature against the public key EMBEDDED in its
 * attestation. Proves integrity (not tampered since signing), NOT
 * authenticity — binding the key to a Nanorix-rooted trust anchor needs the
 * trust-chain manifest, which this SDK surface does not carry.
 */
export async function verifySignature(
  proof: Record<string, unknown>,
  cdpVersion: string,
): Promise<SignatureCheck> {
  const rawPub =
    strOrEmpty(pointer(proof, "attestation", "public_key")) ||
    strOrEmpty(pointer(proof, "attestation", "verification_key"));
  const rawSig = strOrEmpty(pointer(proof, "attestation", "signature"));
  if (rawPub === "" || rawSig === "") return { kind: "absent" };

  const message = await signedMessage(proof, cdpVersion);
  if (message === null) return { kind: "absent" };
  if (message.startsWith(UNSUPPORTED_MODE_SENTINEL)) {
    return {
      kind: "unsupported",
      mode: message.slice(UNSUPPORTED_MODE_SENTINEL.length),
    };
  }
  return verifyMessageWithKey(message, rawSig, rawPub);
}

// ─── The 8-stage pipeline ───────────────────────────────────────────────────

function makeEmptyMetadata(): VerificationMetadata {
  return {
    cdpVersion: null,
    capsuleId: null,
    region: null,
    signingKeyVersion: null,
    algorithm: null,
    stepCount: null,
    activityEventCount: null,
    recoveredChainTimestamp: null,
    unattestedParentAttribution: null,
  };
}

/**
 * First reserved slot carrying anything other than JSON `null`.
 *
 * Genuine documents emit these keys with an explicit `null` (the fields have no
 * `skip_serializing_if`), so absence and `null` are both normal. Anything else —
 * an empty array included — is a shape no signer produces. Iteration follows
 * UNSIGNED_RESERVED_SLOTS order so a document with several populated slots
 * always names the same one, in every language.
 */
function populatedUnsignedSlot(proof: Record<string, unknown>): string | null {
  for (const slot of UNSIGNED_RESERVED_SLOTS) {
    const v = proof[slot];
    if (v !== undefined && v !== null) return slot;
  }
  return null;
}

/** Parent links carrying attribution the signed Merkle root does not bind. */
function countUnattestedParentAttribution(
  parents: readonly unknown[],
): number | null {
  let n = 0;
  for (const p of parents) {
    if (!p || typeof p !== "object" || Array.isArray(p)) continue;
    const link = p as Record<string, unknown>;
    if (
      PARENT_ATTRIBUTION_FIELDS.some(
        (f) => link[f] !== undefined && link[f] !== null,
      )
    )
      n++;
  }
  return n === 0 ? null : n;
}

function strOrEmpty(v: unknown): string {
  return typeof v === "string" ? v : "";
}

/**
 * The signature algorithm the proof declares, when it is not Ed25519.
 *
 * Reads `attestation.algorithm` and the top-level `signature_algorithm`;
 * either declaring anything other than the exact canonical string `"Ed25519"`
 * makes the proof unverifiable by this build. Both absent is the pre-field
 * era, which is Ed25519 by definition.
 */
function declaredNonEd25519Algorithm(proof: Record<string, unknown>): string | null {
  for (const value of [pointer(proof, "attestation", "algorithm"), proof["signature_algorithm"]]) {
    if (typeof value === "string" && value !== "Ed25519") return value;
  }
  return null;
}

function pointer(root: unknown, ...path: string[]): unknown {
  let cur: unknown = root;
  for (const key of path) {
    if (!cur || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

/**
 * Verify an AuditProof offline through the full 8-stage pipeline.
 *
 * Mirrors `nanorix_verify::verify_auditproof`. Stage 7 ("chain reproduced and
 * the signature verifies against the embedded key") is the ceiling here:
 * stage 8 requires a trust-chain manifest, which only the auditor CLI carries.
 *
 * @param jsonBytes AuditProof as Uint8Array, Buffer, or already-parsed object.
 * @param policy Optional VerifierPolicy for authority / region pins.
 */
export async function verifyAuditProof(
  jsonBytes: Uint8Array | ArrayBufferView | Record<string, unknown>,
  policy?: VerifierPolicy,
): Promise<VerificationResult> {
  const pol = policy ?? {};
  const meta = makeEmptyMetadata();

  // Stage 0: parse
  let proof: Record<string, unknown>;
  if (ArrayBuffer.isView(jsonBytes)) {
    try {
      const bytes = new Uint8Array(
        jsonBytes.buffer,
        jsonBytes.byteOffset,
        jsonBytes.byteLength,
      );
      proof = JSON.parse(new TextDecoder().decode(bytes)) as Record<
        string,
        unknown
      >;
    } catch {
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.REQUIRED_FIELD_MISSING,
          field: "json_root",
        },
        stage_reached: 1,
        metadata: meta,
      };
    }
  } else {
    proof = jsonBytes;
  }

  // Stage 1: cdp_version present
  const cdpVersion = proof["cdp_version"];
  if (typeof cdpVersion !== "string") {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.REQUIRED_FIELD_MISSING,
        field: "cdp_version",
      },
      stage_reached: 1,
      metadata: meta,
    };
  }
  meta.cdpVersion = cdpVersion;

  // Stage 2: cdp_version recognized
  if (!SUPPORTED_CDP_VERSIONS.has(cdpVersion)) {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.CDP_VERSION_UNSUPPORTED,
        found: cdpVersion,
      },
      stage_reached: 2,
      metadata: meta,
    };
  }

  // Reserved-slot gate. A slot outside the signature carrying a value no
  // signer emits means the bytes in front of us are not the bytes that were
  // signed, even though the signature over the covered subset still checks out.
  // Runs before the policy pins and the chain walk because the document is
  // structurally impossible on its own terms, independent of what any customer
  // policy asks for.
  const populatedSlot = populatedUnsignedSlot(proof);
  if (populatedSlot !== null) {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.UNSIGNED_FIELD_POPULATED,
        field: populatedSlot,
      },
      stage_reached: 2,
      metadata: meta,
    };
  }

  if (typeof proof["capsule_id"] === "string")
    meta.capsuleId = proof["capsule_id"];
  // Region resolves from the SIGNED capsule_started activity event only.
  // The activity trail is inside CanonicalCdpView, so a region there cannot be
  // altered without breaking the signature. `environment.region` and top-level
  // `region` are both outside the canonical hash — reading either let an
  // outsider satisfy a residency pin by appending a region to a genuine signed
  // proof, with no key. Mirrors the Rust and Go verifiers.
  const regionEvents = proof["activity"];
  if (Array.isArray(regionEvents)) {
    const started = regionEvents.find(
      (e) => e && typeof e === "object" && (e as Record<string, unknown>)["event"] === "capsule_started",
    ) as Record<string, unknown> | undefined;
    if (started && typeof started["region"] === "string") meta.region = started["region"];
  }
  const attSkv = pointer(proof, "attestation", "signing_key_version");
  if (typeof attSkv === "string") meta.signingKeyVersion = attSkv;
  else if (typeof proof["signing_key_version"] === "string")
    meta.signingKeyVersion = proof["signing_key_version"];
  const algo = pointer(proof, "attestation", "algorithm");
  if (typeof algo === "string") meta.algorithm = algo;

  // Policy-pin gate (ADR-031 G7 / VP Security F4.3). Runs BEFORE the chain
  // walk: the policy decision is independent of chain validity, so a customer
  // who pinned the wrong authority learns it without a 7-step SHA-512 walk.
  if (pol.requiredAuthorityId) {
    const claimed = pointer(proof, "signing_authority", "authority_id");
    const claimedId = typeof claimed === "string" ? claimed : null;
    if (claimedId === null) {
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.AUTHORITY_ID_MISMATCH,
          claimed_authority_id: null,
          expected_authority_id: pol.requiredAuthorityId,
          reason: "verifier_policy_demands_customer_hsm_audit_proof_has_none",
        },
        stage_reached: 2,
        metadata: meta,
      };
    }
    if (claimedId !== pol.requiredAuthorityId) {
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.AUTHORITY_ID_MISMATCH,
          claimed_authority_id: claimedId,
          expected_authority_id: pol.requiredAuthorityId,
          reason: "verifier_policy_authority_id_mismatch",
        },
        stage_reached: 2,
        metadata: meta,
      };
    }
  }

  // Residency-pin gate (EO-03 G1 / ADR-018 D3). A proof carrying no region at
  // all cannot satisfy a residency pin — rejected with an empty `actual`, so
  // the pin fails closed.
  if (pol.requiredRegion !== undefined) {
    const actual = meta.region ?? "";
    if (actual !== pol.requiredRegion) {
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.REGION_MISMATCH,
          required: pol.requiredRegion,
          actual,
        },
        stage_reached: 2,
        metadata: meta,
      };
    }
  }

  // Stage 3: chain reproducibility
  const chainRaw = proof["chain"];
  if (!Array.isArray(chainRaw)) {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.REQUIRED_FIELD_MISSING,
        field: "chain",
      },
      stage_reached: 3,
      metadata: meta,
    };
  }
  meta.stepCount = chainRaw.length;

  if (chainRaw.length !== CHAIN_STEP_COUNT) {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.STEP_COUNT_INVALID,
        expected: CHAIN_STEP_COUNT,
        found: chainRaw.length,
      },
      stage_reached: 3,
      metadata: meta,
    };
  }

  const activity = proof["activity"];
  if (Array.isArray(activity)) meta.activityEventCount = activity.length;

  const { timestamp, recovered } = resolveChainTimestamp(proof);
  meta.recoveredChainTimestamp = recovered;

  // ADR-039 + ADR-041 Wave-N — optional Merkle roots for the Step 8 amendment.
  // Absent on pre-Wave-N proofs, where both branches collapse to the legacy
  // formula (byte-identical chain walk).
  const rrmr =
    typeof proof["record_receipts_merkle_root"] === "string"
      ? (proof["record_receipts_merkle_root"] as string)
      : null;
  const ppmr =
    typeof proof["parent_proofs_merkle_root"] === "string"
      ? (proof["parent_proofs_merkle_root"] as string)
      : null;

  let prevHash = GENESIS_HASH;
  for (let idx = 0; idx < chainRaw.length; idx++) {
    const stepRaw: unknown = chainRaw[idx];
    const step =
      stepRaw && typeof stepRaw === "object" && !Array.isArray(stepRaw)
        ? (stepRaw as Record<string, unknown>)
        : {};
    // Canonical-identity walk: hash inputs come from CANONICAL_SUBSYSTEMS by
    // INDEX, never from the document. A document cannot choose what a step is;
    // it can only fail to match.
    const canonicalSubsystem = CANONICAL_SUBSYSTEMS[idx] as string;
    const declaredSubsystem = strOrEmpty(step["subsystem"]);
    const claimedChainHash = strOrEmpty(step["chain_hash"]);

    const recomputed =
      idx === CHAIN_STEP_COUNT - 1
        ? await computeStep8Amended(prevHash, timestamp, rrmr, ppmr)
        : await computeStepHash(
            prevHash,
            canonicalSubsystem,
            lookupMethod(canonicalSubsystem),
            timestamp,
          );

    if (recomputed !== stripSha512Prefix(claimedChainHash)) {
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.STEP_HASH_MISMATCH,
          step_idx: idx,
          subsystem: declaredSubsystem,
        },
        stage_reached: 3,
        metadata: meta,
      };
    }

    // Hashes reproduced; the label beside them still has to be the right one.
    if (declaredSubsystem !== canonicalSubsystem) {
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.CHAIN_STEP_IDENTITY_MISMATCH,
          step_idx: idx,
          expected_subsystem: canonicalSubsystem,
          found_subsystem: declaredSubsystem,
        },
        stage_reached: 3,
        metadata: meta,
      };
    }
    prevHash = recomputed;
  }

  // ADR-039 receipt-set verification (Mode A step 3).
  const receipts = proof["record_receipts"];
  if (Array.isArray(receipts)) {
    const failure = await verifyRecordReceipts(
      receipts,
      meta.capsuleId ?? "",
      rrmr,
    );
    if (failure) {
      return {
        valid: false,
        failure_reason: failure,
        stage_reached: 3,
        metadata: meta,
      };
    }
  }

  // ADR-041 parent-proof-set verification.
  const parents = proof["parent_proof_hashes"];
  if (Array.isArray(parents)) {
    const failure = await verifyParentProofs(parents, ppmr);
    if (failure) {
      return {
        valid: false,
        failure_reason: failure,
        stage_reached: 3,
        metadata: meta,
      };
    }
    // The root binds parent_chain_hash and nothing else, so the verdict
    // carries the count rather than let a reader infer coverage.
    meta.unattestedParentAttribution = countUnattestedParentAttribution(parents);
  }

  // Streaming-egress Merkle roots. `streaming_egress_completed.
  // streaming_merkle_root` commits to the `streaming_egress_chunk` leaves
  // emitted beside it; it was signed from the day it shipped and read by
  // nothing. Placed with the other sub-structure Merkle checks and therefore
  // BEFORE the signature stages, so it also covers the path where a chain
  // reproduces with no signature to check at all.
  if (Array.isArray(activity)) {
    const failure = await verifyStreamingMerkleRoots(activity);
    if (failure) {
      return {
        valid: false,
        failure_reason: failure,
        stage_reached: 3,
        metadata: meta,
      };
    }
  }

  // Stage 4: final_hash binding
  const claimedFinal = strOrEmpty(proof["final_hash"]);
  const lastStep = chainRaw[chainRaw.length - 1];
  const lastChainHash =
    lastStep && typeof lastStep === "object" && !Array.isArray(lastStep)
      ? strOrEmpty((lastStep as Record<string, unknown>)["chain_hash"])
      : "";

  if (stripSha512Prefix(claimedFinal) !== stripSha512Prefix(lastChainHash)) {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.FINAL_HASH_MISMATCH,
        claimed: claimedFinal,
        computed: lastChainHash,
      },
      stage_reached: 4,
      metadata: meta,
    };
  }

  // Algorithm dispatch precedes byte-shape checks (ADR-051 C.1): a proof
  // declaring a non-Ed25519 signature algorithm fails typed as
  // algorithm_unsupported here — it must never fall through to the 64/32-byte
  // decode gates and report as "malformed". Absent or "Ed25519" proceeds
  // unchanged (every proof issued to date).
  const declaredAlgorithm = declaredNonEd25519Algorithm(proof);
  if (declaredAlgorithm !== null) {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.ALGORITHM_UNSUPPORTED,
        found: declaredAlgorithm,
      },
      stage_reached: 4,
      metadata: meta,
    };
  }

  // Stages 5–7: signature verification over the version/mode-appropriate
  // message against the key embedded in the proof.
  const sig = await verifySignature(proof, cdpVersion);
  if (sig.kind === "failed") {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.SIGNATURE_MISMATCH,
        reason: sig.reason,
      },
      stage_reached: 7,
      metadata: meta,
    };
  }
  if (sig.kind === "unsupported") {
    // Declared a signing_mode this build cannot verify. NOT the same as "no
    // signature": signing_mode is inside the canonical hash and is
    // attacker-controllable, so a partial-success verdict would be a downgrade
    // oracle. algorithm_unsupported is the existing Forever-Standard reason; the
    // resolution (upgrade the verifier) is identical.
    return {
      valid: false,
      failure_reason: {
        type: "algorithm_unsupported",
        found: `signing_mode=${sig.mode}`,
      },
      stage_reached: 4,
      metadata: meta,
    };
  }
  if (sig.kind === "absent") {
    // Chain reproduced but no signature this build can check. Honest: this is
    // NOT a full cryptographic verification, and the stage number says so.
    return {
      valid: true,
      failure_reason: null,
      stage_reached: 4,
      metadata: meta,
    };
  }

  // Stage 8 needs a trust-chain manifest to anchor the embedded key to the
  // Nanorix trust root; without one the honest ceiling is integrity-only.
  return {
    valid: true,
    failure_reason: null,
    stage_reached: 7,
    metadata: meta,
  };
}

/**
 * Verify the receipt set per ADR-039 Mode A step 3 — each receipt's chain hash
 * must roundtrip and the Merkle root must match the claimed root. Returns null
 * when every receipt verifies (or no root is claimed).
 */
async function verifyRecordReceipts(
  receipts: readonly unknown[],
  capsuleId: string,
  claimedRoot: string | null,
): Promise<FailureReason | null> {
  // A non-empty receipt set with no root is anchored by nothing, and the
  // emitter never produces one: record_receipts_merkle_root is set iff
  // record_receipts is. Skipping the check when the root is absent let an
  // outsider append a whole fabricated set to a genuine proof, since the array
  // is outside the canonical hash and the signature therefore still verified.
  if (claimedRoot === null) {
    if (receipts.length === 0) return null;
    return {
      type: FailureReasonType.REQUIRED_FIELD_MISSING,
      field: "record_receipts_merkle_root",
    };
  }

  const leaves: string[] = [];
  for (let i = 0; i < receipts.length; i++) {
    const raw = receipts[i];
    const r =
      raw && typeof raw === "object" && !Array.isArray(raw)
        ? (raw as Record<string, unknown>)
        : {};
    const recordIndex =
      typeof r["record_index"] === "number" ? r["record_index"] : 0;
    const trail = r["record_activity_trail"];
    const activityRoot = await computeActivityRoot(
      Array.isArray(trail) ? trail : null,
    );
    const recomputed = await computeRecordChainHash(
      capsuleId,
      recordIndex,
      strOrEmpty(r["record_id"]),
      strOrEmpty(r["record_input_hash"]),
      strOrEmpty(r["record_output_hash"]),
      activityRoot,
      typeof r["pattern_tag"] === "string" ? r["pattern_tag"] : undefined,
    );

    if (recomputed !== stripSha512Prefix(strOrEmpty(r["record_chain_hash"]))) {
      return {
        type: FailureReasonType.STEP_HASH_MISMATCH,
        step_idx: i,
        subsystem: `record_receipt[${i}]`,
      };
    }
    leaves.push(recomputed);
  }

  const recomputedRoot = (await merkleRootSha512NullSeparated(leaves)) ?? "";
  if (recomputedRoot !== stripSha512Prefix(claimedRoot)) {
    return {
      type: FailureReasonType.FINAL_HASH_MISMATCH,
      claimed: claimedRoot,
      computed: `sha512:${recomputedRoot}`,
    };
  }
  return null;
}

/** Verify the parent-proof-set Merkle root per ADR-041. */
async function verifyParentProofs(
  parents: readonly unknown[],
  claimedRoot: string | null,
): Promise<FailureReason | null> {
  // Same fail-closed reasoning as verifyRecordReceipts: a parent set with no
  // root is one nothing anchors, and leaving it unchecked made the entire
  // declared lineage of a genuine proof forgeable by anyone holding it.
  if (claimedRoot === null) {
    if (parents.length === 0) return null;
    return {
      type: FailureReasonType.REQUIRED_FIELD_MISSING,
      field: "parent_proofs_merkle_root",
    };
  }

  const leaves = parents.map((p) =>
    p && typeof p === "object" && !Array.isArray(p)
      ? strOrEmpty((p as Record<string, unknown>)["parent_chain_hash"])
      : "",
  );
  const recomputed = (await merkleRootSha512NullSeparated(leaves)) ?? "";
  if (recomputed !== stripSha512Prefix(claimedRoot)) {
    return {
      type: FailureReasonType.FINAL_HASH_MISMATCH,
      claimed: claimedRoot,
      computed: `sha512:${recomputed}`,
    };
  }
  return null;
}
