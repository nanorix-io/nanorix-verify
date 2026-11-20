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
 * Held to `tools/nanorix-verify/fixtures/corpus/` (committed `.expected.json`
 * verdicts) by `corpus-sweep.ts` in this directory.
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
 *    v2.1 and v2.2 `nanorix_only` and `customer_only` sign the
 *    canonical-view hash. cdp_version 2.0 is retired and
 *    refused at the version gate. Verifying the wrong message accepts
 *    a downgraded proof. v2.2 changes what a document may
 *    carry, not how it is canonicalised, hashed or signed; the version label
 *    is itself inside the canonical view, so a 2.1 document re-labelled 2.2
 *    clears the allowlist and then fails the signature.
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
import {
  CustomerDeclaredActivityStatus,
  verifyCustomerDeclaredActivity,
} from "./customer_activity.js";
import { hasSmallOrderKeyOrR } from "./_ed25519_strict.js";
import { HYBRID_RECORD_CHECK_MISSING, isHybridPin, isPinChecked, type TrustChain } from "./trustChain.js";

/** Genesis hash — SHA-512(""). Forever-stable. */
export const GENESIS_HASH =
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/** Canonical method strings per subsystem. Forever-stable. */
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

/** Canonical 8-step subsystem order (must match CHAIN_DEFS in the reference implementation). */
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
  "2.1",
  "2.2",
]);

/**
 * Versions whose signature covers the canonical-view hash.
 * `cdp_version` is inside that view, so re-labelling a document across
 * these is accepted by the allowlist and rejected by the signature.
 */
export const CANONICAL_VIEW_SIGNED_VERSIONS: ReadonlySet<string> = new Set([
  "2.1",
  "2.2",
]);

/** Activity event an issuer writes when a capsule ran in diagnostic mode. */
export const DIAGNOSTIC_MODE_EVENT = "diagnostic_mode_enabled";

/**
 * Whether the activity trail holds an entry whose `event` is
 * `DIAGNOSTIC_MODE_EVENT`. The trail is signed only on 2.1 and 2.2 with a
 * signature, so `false` proves nothing on 1.0 or on an unsigned 2.1 or 2.2
 * proof; the diagnostic gate refuses those outright for that reason. Mirrors
 * Rust `records_diagnostic_mode`.
 */
function recordsDiagnosticMode(proof: Record<string, unknown>): boolean {
  const events = proof["activity"];
  return (
    Array.isArray(events) &&
    events.some(
      (e) =>
        e !== null &&
        typeof e === "object" &&
        (e as Record<string, unknown>)["event"] === DIAGNOSTIC_MODE_EVENT,
    )
  );
}
export const CHAIN_STEP_COUNT = 8;

/**
 * Reserved attestation slots outside CanonicalCdpView
 * that no Nanorix signer populates. Every
 * construction site hard-codes them to None, so the signature never covered
 * them and a genuine document never carries them; a populated one was added
 * after signing by someone holding no key, and the signature cannot tell,
 * because it never covered the field.
 *
 * `per_event_attestations` is the ninth reserved slot and is deliberately
 * absent: the server drains capsule_event_attestations into it at destroy, so
 * genuine proofs do carry it. The slot sits outside the signed hash and is
 * accepted unchecked: its entries prove nothing about who signed. Mirrors the Rust, Go and Python verifiers.
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

/** Closed-set failure reason wire types. Forever-stable. Additive only. */
export const FailureReasonType = {
  ALGORITHM_UNSUPPORTED: "algorithm_unsupported",
  AUTHORITY_ID_MISMATCH: "authority_id_mismatch",
  AUTHORITY_MODE_MISMATCH: "authority_mode_mismatch",
  AUTHORITY_REVOKED: "authority_revoked",
  CDP_VERSION_UNSUPPORTED: "cdp_version_unsupported",
  CHAIN_STEP_IDENTITY_MISMATCH: "chain_step_identity_mismatch",
  CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH:
    "customer_declared_activity_root_mismatch",
  DIAGNOSTIC_PROOF_REFUSED: "diagnostic_proof_refused",
  FIELD_MALFORMED: "field_malformed",
  FINAL_HASH_MISMATCH: "final_hash_mismatch",
  GENESIS_HASH_MISMATCH: "genesis_hash_mismatch",
  REGION_MISMATCH: "region_mismatch",
  REQUIRED_FIELD_MISSING: "required_field_missing",
  RESERVED: "reserved",
  SIGNATURE_MISMATCH: "signature_mismatch",
  SIGNING_KEY_VERSION_UNKNOWN: "signing_key_version_unknown",
  SIGNING_MODE_AUTHORITY_MISMATCH: "signing_mode_authority_mismatch",
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
   * was recovered from `attestation.key_id` (pre-restoration proofs).
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
  /**
   * The `customer_declared_activity_root` the proof carries, as
   * written; null when it declares none. Disclosed whether or not the record
   * was supplied — a verdict that stays silent about a declared root invites
   * a reader to assume it was checked.
   */
  customerDeclaredActivityRoot?: string | null;
  /**
   * True when the customer's activity record was supplied through
   * `VerifierPolicy.customerActivity` and its recomputed root matched; false
   * when the proof declares a root but no record was supplied — declared,
   * not checked. Null when the proof declares no root. A mismatch is a
   * failure, never a false here.
   */
  customerDeclaredActivityChecked?: boolean | null;
}

/**
 * The three result states. The names are the same in the Python SDK, the
 * nanorix-verify `--json` output and the MCP tool.
 */
export type VerifyStatus = "verified" | "not_anchored" | "not_verified";

/**
 * Derive the result state for an offline verdict: `"verified"` only at stage 8
 * (the signing key resolved in a trust-chain manifest checked against its
 * pinned identity fingerprint, and the signature verified against that key),
 * `"not_anchored"` at stage 7 (the signature verified against the key embedded
 * in the proof), `"not_verified"` for everything else, including a reproduced
 * chain with no signature checked.
 */
export function verificationStatusFor(valid: boolean, stageReached: number): VerifyStatus {
  if (valid && stageReached >= 8) return "verified";
  if (valid && stageReached === 7) return "not_anchored";
  return "not_verified";
}

/** Result of AuditProof verification. */
export interface VerificationResult {
  /**
   * `"verified"` only at stage 8: the signing key resolved in the signed key
   * list given as `policy.trustChain`, checked against its pinned identity.
   * `"not_anchored"` at stage 7 (the signature verified against the key the
   * proof carries, which a proof signed with a fresh key also does) and
   * `"not_verified"` for everything else. Gate on this or on `ok`.
   */
  status: VerifyStatus;
  /** True only when `status` is `"verified"`. */
  ok: boolean;
  /**
   * True when the chain and the signature hold under the key used, and on its
   * own it says nothing about who signed: it is also true at stage 7
   * (`not_anchored`: the key the proof carries) and at stage 4 (no signature
   * checked). Read `status` or `ok` instead. The wire field keeps this meaning.
   *
   * @deprecated `valid` is not a verdict. Read `status` (`"verified"` only at
   * stage 8) or `ok`.
   */
  valid: boolean;
  failure_reason: FailureReason | null;
  stage_reached: number;
  metadata: VerificationMetadata;
}

/** The ladder's own result, before its status is derived. */
type LadderResult = Omit<VerificationResult, "status" | "ok">;

/** Wire-form projection matching fixture corpus expected.json. */
export interface VerificationWireForm {
  valid: boolean;
  failure_reason: FailureReason | null;
}

/** Customer-side policy configuration. Field-additive. */
export interface VerifierPolicy {
  /**
   * Refuse at stage 2, with `diagnostic_proof_refused`, an AuditProof whose
   * signed activity trail records diagnostic mode (a `diagnostic_mode_enabled`
   * event), and every AuditProof that cannot show it does not: one whose trail
   * is unsigned, which is cdp_version 1.0, or 2.1 or 2.2 without a signature,
   * so the event could be removed and the proof would still verify. Only a
   * stage 8 (`"verified"`) result ties the trail to a Nanorix key; at stage 7
   * the key is the one the proof carries. Omitted or false accepts
   * diagnostic-mode proofs.
   */
  rejectDiagnostic?: boolean;
  /**
   * Compared with the region on the signed `capsule_started` activity event;
   * a disagreeing proof is refused at stage 2 with `region_mismatch`. A proof
   * whose trail is unsigned (cdp_version 1.0, or 2.1 or 2.2 without a
   * signature) is refused with an empty `actual`. Only a stage 8
   * (`"verified"`) result ties the region to a Nanorix key.
   */
  requiredRegion?: string;
  /**
   * Compared with the proof's top-level `authority_id` (absent means
   * `us-kms-nanorix-v1`), never with an unsigned `signing_authority`. The
   * signature covers that field only on cdp_version 2.1 and 2.2; on 1.0 a
   * string other than `us-kms-nanorix-v1` is refused, so a pin accepts only
   * the default there, and 2.0 is refused at the version gate before the pin
   * is read. A pin alone checks only what the proof says about itself; set
   * `trustChain` as well to resolve the signing key in a signed key list.
   */
  requiredAuthorityId?: string;
  /**
   * A signed key list the proof's signing key is resolved against (stage 8).
   * Build one with `TrustChain.fromKeyList(keyList, pinnedIdentityFingerprint)`,
   * which refuses any list the pinned identity did not sign. With one, a proof
   * whose signature verifies reaches stage 8 only when its
   * `(authority_id, signing_key_version)` resolves in the list, the signature
   * verifies against the listed key, and the authority is not revoked. Without
   * one the ladder ends at stage 7. Mirrors `VerifierPolicy::trust_chain` in the
   * Rust verifier.
   */
  trustChain?: TrustChain;
  /**
   * The raw bytes of the customer's activity record
   * (`activity_events.jsonl`), when the reader holds it. Recomputed and
   * compared with the proof's `customer_declared_activity_root`; a record
   * supplied against a proof that declares no root fails closed as
   * `required_field_missing`. Omitted, a declared root is disclosed as
   * "declared, not checked" rather than failed.
   */
  customerActivity?: Uint8Array;
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
 * Reproduce one chain step's SHA-512 hash. Forever-stable.
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

// ─── Chain timestamp resolution ───────────────────────────────────

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
 * or — for earlier proofs that omit it — the value recovered from
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

// ─── canonical view ──────────────────────────────────────────

/**
 * Rebuild the canonical view from a proof and return its
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
  // A root over bytes the customer wrote and Nanorix never parsed.
  // Same skip-when-absent mechanic as the two Merkle roots, so a proof that
  // did not opt in hashes to exactly what it did before the field existed.
  insertIfPresent(view, "customer_declared_activity_root", proof);

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
 * - `2.1` / `2.2` + `nanorix_only` or `customer_only` -> recomputed canonical hash
 *   (the mode decides which authority the proof claims, not which bytes were signed)
 * - `2.1` / `2.2` + any other mode -> the unsupported-mode sentinel (not verifiable here)
 */
async function signedMessage(
  proof: Record<string, unknown>,
  cdpVersion: string,
): Promise<string | null> {
  switch (cdpVersion) {
    case "1.0":
      return stripSha512Prefix(strOrEmpty(proof["final_hash"]));
    case "2.1":
    case "2.2": {
      const mode = proof["signing_mode"];
      const signingMode = typeof mode === "string" ? mode : "nanorix_only";
      // Any other declared mode is one this build cannot verify. NOT the same as
      // "no signature" — signalled with a sentinel the callers translate.
      if (signingMode !== "nanorix_only" && signingMode !== SIGNING_MODE_CUSTOMER_ONLY) {
        return UNSUPPORTED_MODE_SENTINEL + signingMode;
      }
      return recomputeCanonicalHash(proof);
    }
    default:
      return null;
  }
}

/** Decode base64 signature + public key and verify `message` under them. */
export async function verifyMessageWithKey(
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

  if (hasSmallOrderKeyOrR(pubBytes, sigBytes)) {
    return { kind: "failed", reason: SignatureFailureReason.DOES_NOT_VERIFY };
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
 * attestation. Proves integrity (no signed byte changed since signing), NOT
 * authenticity: a forger signs with a key of their own and embeds it. Binding
 * the key to a published authority is stage 8, which `verifyAuditProof` does
 * when its policy carries a `trustChain`.
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

/**
 * Verify the proof's signature against a key RESOLVED from a trust chain, not
 * the key the proof carries. This is what establishes authenticity: a forged
 * proof carrying its own embedded key passes the embedded-key check and fails
 * here.
 */
async function verifySignatureAgainst(
  proof: Record<string, unknown>,
  cdpVersion: string,
  pubB64: string,
): Promise<SignatureCheck> {
  const rawSig = strOrEmpty(pointer(proof, "attestation", "signature"));
  if (rawSig === "") return { kind: "absent" };
  const message = await signedMessage(proof, cdpVersion);
  if (message === null) return { kind: "absent" };
  if (message.startsWith(UNSUPPORTED_MODE_SENTINEL)) {
    return {
      kind: "unsupported",
      mode: message.slice(UNSUPPORTED_MODE_SENTINEL.length),
    };
  }
  return verifyMessageWithKey(message, rawSig, pubB64);
}

/**
 * Stage 8: resolve the signing key in the verified key list and re-check.
 *
 * Resolves the proof's `(authority_id, signing_key_version)` in the list
 * (archived versions resolve too), checks the signature against the LISTED key
 * rather than the key the proof carries, and refuses a revoked authority.
 * Mirrors `anchor_to_trust_chain` in the Rust library: a chain that did not
 * come from `TrustChain.fromKeyList` was not checked against its pin, so a
 * success ends at stage 7.
 */
async function anchorToTrustChain(
  proof: Record<string, unknown>,
  cdpVersion: string,
  chain: TrustChain,
  meta: VerificationMetadata,
): Promise<LadderResult> {
  const authorityId = effectiveAuthorityId(proof);
  const attestation = pointer(proof, "attestation");
  const rawVersion =
    attestation && typeof attestation === "object" && !Array.isArray(attestation) && "signing_key_version" in attestation
      ? (attestation as Record<string, unknown>)["signing_key_version"]
      : proof["signing_key_version"];
  const version = typeof rawVersion === "string" ? rawVersion : "";

  const listed = chain.findKey(authorityId, version);
  if (listed === null) {
    return {
      valid: false,
      failure_reason: { type: FailureReasonType.SIGNING_KEY_VERSION_UNKNOWN, version },
      stage_reached: 6,
      metadata: meta,
    };
  }
  const [publicKeyB64, revoked] = listed;

  const check = await verifySignatureAgainst(proof, cdpVersion, publicKeyB64);
  if (check.kind === "failed") {
    return {
      valid: false,
      failure_reason: { type: FailureReasonType.SIGNATURE_MISMATCH, reason: check.reason },
      stage_reached: 7,
      metadata: meta,
    };
  }
  if (check.kind === "unsupported") {
    return {
      valid: false,
      failure_reason: {
        type: FailureReasonType.ALGORITHM_UNSUPPORTED,
        found: `signing_mode=${check.mode}`,
      },
      stage_reached: 7,
      metadata: meta,
    };
  }
  if (check.kind === "absent") {
    if (isHybridPin(chain.pinnedIdentityFingerprint)) return hybridRecordRefusal(7, meta);
    return { valid: true, failure_reason: null, stage_reached: 7, metadata: meta };
  }

  if (revoked) {
    return {
      valid: false,
      failure_reason: { type: FailureReasonType.AUTHORITY_REVOKED },
      stage_reached: 8,
      metadata: meta,
    };
  }
  // A 1.0 signature covers final_hash alone, which binds destroyed_at and the
  // two optional Merkle roots. It does not bind the capsule_id itself (only
  // through record receipts, which a holder can remove), the region or the key
  // id. So a key list cannot tie it to a capsule: a 1.0 proof runs the lookup,
  // the re-verify and the revocation check above as 2.x does, and where 2.x
  // would reach stage 8 it ends at stage 7, never anchored. Under a hybrid pin
  // it is refused there, as every record is. Mirrors Rust.
  if (cdpVersion === "1.0") {
    if (isHybridPin(chain.pinnedIdentityFingerprint)) return hybridRecordRefusal(7, meta);
    return { valid: true, failure_reason: null, stage_reached: 7, metadata: meta };
  }
  // the hybrid-pin gate: under a hybrid pin a record is
  // anchored only with its ML-DSA-65 half checked, which this verifier does
  // not do yet.
  if (isHybridPin(chain.pinnedIdentityFingerprint)) return hybridRecordRefusal(8, meta);
  return { valid: true, failure_reason: null, stage_reached: isPinChecked(chain) ? 8 : 7, metadata: meta };
}

/**
 * The refusal a record gets under a hybrid pin, at the stage where it would
 * otherwise have ended valid, signed or unsigned.
 */
function hybridRecordRefusal(stage: number, meta: VerificationMetadata): LadderResult {
  return {
    valid: false,
    failure_reason: { type: FailureReasonType.ALGORITHM_UNSUPPORTED, found: HYBRID_RECORD_CHECK_MISSING },
    stage_reached: stage,
    metadata: meta,
  };
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
    customerDeclaredActivityRoot: null,
    customerDeclaredActivityChecked: null,
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

export const CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD =
  "customer_declared_activity_root";

/** `field_malformed.reason` when the root is present but not a JSON string. */
export const ROOT_MALFORMED_NOT_A_STRING = "expected a JSON string";
/** `field_malformed.reason` when the root is the empty string. */
export const ROOT_MALFORMED_EMPTY = "empty string";
/**
 * `field_malformed.reason` for any other string that is not `sha512:` + 128
 * lowercase hex (bare 128-hex accepted).
 */
export const ROOT_MALFORMED_SHAPE =
  "expected sha512: followed by 128 lowercase hex characters";

const LOWERCASE_HEX_128 = /^[0-9a-f]{128}$/;

/**
 * The shape check a present, non-null `customer_declared_activity_root` must
 * pass before anything reads it: a JSON string of `sha512:` + 128 lowercase
 * hex characters, or a bare 128-hex digest. Anything else — a number, an
 * object, an array, the empty string, uppercase or wrong-length hex — is
 * `field_malformed`, named before any recompute would consume the value and
 * blame a signature or a record instead. The empty string is malformed, not
 * absent: the canonical view binds `""` as a value, and a verifier that read
 * it as "no root" would contradict its own recompute.
 *
 * Returns the string as written on success so the caller can report it
 * verbatim. Reason strings mirror the Rust reference byte-for-byte because
 * corpus verdicts compare the whole failure object.
 */
export function checkDeclaredActivityRootShape(
  value: unknown,
): { root: string } | { failure: FailureReason } {
  const malformed = (reason: string): { failure: FailureReason } => ({
    failure: {
      type: FailureReasonType.FIELD_MALFORMED,
      field: CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
      reason,
    },
  });
  if (typeof value !== "string") return malformed(ROOT_MALFORMED_NOT_A_STRING);
  if (value === "") return malformed(ROOT_MALFORMED_EMPTY);
  if (!LOWERCASE_HEX_128.test(stripSha512Prefix(value))) {
    return malformed(ROOT_MALFORMED_SHAPE);
  }
  return { root: value };
}

/**
 * The pre-chain-walk gate for a declared root, run at stage 2 in
 * the same position and on the same reasoning as the reserved-slot gate.
 *
 * The root is signed only where the signed message is the canonical view
 * (2.1 / 2.2); on 1.0 the message is `final_hash`, so a root there is a
 * value anyone can write and the signature cannot tell —
 * `unsigned_field_populated`. On 2.1 / 2.2 a root of a shape no signer emits
 * is `field_malformed`. Absent or JSON `null` is
 * "did not opt in" and passes. The version gate precedes the shape gate: a
 * root the signature never covered is the more fundamental defect, whatever
 * its shape. Shared with the standalone sidecar check in
 * `customer_activity.ts`, so the two entry points cannot disagree about which
 * roots are readable.
 */
export function gateDeclaredActivityRoot(
  proof: Record<string, unknown>,
  cdpVersion: string,
): FailureReason | null {
  const value = proof[CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD];
  if (value === undefined || value === null) return null;
  if (!CANONICAL_VIEW_SIGNED_VERSIONS.has(cdpVersion)) {
    return {
      type: FailureReasonType.UNSIGNED_FIELD_POPULATED,
      field: CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
    };
  }
  const shape = checkDeclaredActivityRootShape(value);
  return "failure" in shape ? shape.failure : null;
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

/** The `signing_mode` value for a customer-classified authority. */
export const SIGNING_MODE_CUSTOMER_ONLY = "customer_only";

/**
 * The segments that make an authority id customer-classified, the issuer's own
 * test: any of them anywhere in the id, byte-exact and case-sensitive.
 */
export const CUSTOMER_AUTHORITY_SEGMENTS: readonly string[] = [
  "customer-hsm-",
  "customer-kms-",
  "customer-tee-",
  "customer-byo-",
];

/** Whether the issuer would treat `authorityId` as a customer authority. */
export function isCustomerAuthority(authorityId: string): boolean {
  return CUSTOMER_AUTHORITY_SEGMENTS.some((segment) => authorityId.includes(segment));
}

/**
 * The stage-4 consistency gate: on 2.1 and 2.2 a
 * document whose `signing_mode` is `customer_only`, signed or not, must name a
 * customer-classified `authority_id`. An absent, null or non-string id is
 * Nanorix-classified. The two fields are labels; this gate says they disagree,
 * never who signed.
 */
export function signingModeAuthorityMismatch(
  proof: Record<string, unknown>,
  cdpVersion: string,
): FailureReason | null {
  if (!CANONICAL_VIEW_SIGNED_VERSIONS.has(cdpVersion)) return null;
  if (proof["signing_mode"] !== SIGNING_MODE_CUSTOMER_ONLY) return null;
  const claimed = proof["authority_id"];
  if (typeof claimed === "string" && isCustomerAuthority(claimed)) return null;
  return {
    type: FailureReasonType.SIGNING_MODE_AUTHORITY_MISMATCH,
    claimed_authority_id: typeof claimed === "string" ? claimed : null,
  };
}

/** Authority a proof anchors under when it carries no top-level `authority_id`. */
export const DEFAULT_AUTHORITY_ID = "us-kms-nanorix-v1";

/** The top-level `authority_id`, or DEFAULT_AUTHORITY_ID when absent or not a string. */
function effectiveAuthorityId(proof: Record<string, unknown>): string {
  const v = proof["authority_id"];
  return typeof v === "string" ? v : DEFAULT_AUTHORITY_ID;
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
 * serde_json, the parser in front of the reference verifier, starts
 * remaining_depth at 128 and refuses the container that brings it to zero, so
 * 127 nested containers parse and 128 do not.
 */
const REFERENCE_MAX_DEPTH = 127;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?:^|[^\ud800-\udbff])[\udc00-\udfff]/;

/**
 * True when `value` holds what serde_json refuses and JSON.parse keeps: a
 * container nested deeper than REFERENCE_MAX_DEPTH, a string or key holding
 * half of a surrogate pair, or a number past the float range (JSON.parse
 * turns 1e400 into Infinity).
 */
function beyondReferenceParser(value: unknown, depth = 0): boolean {
  if (typeof value === "string") return LONE_SURROGATE.test(value);
  if (typeof value === "number") return !Number.isFinite(value);
  if (typeof value !== "object" || value === null) return false;
  if (depth >= REFERENCE_MAX_DEPTH) return true;
  if (Array.isArray(value)) {
    return value.some((v) => beyondReferenceParser(v, depth + 1));
  }
  return Object.entries(value).some(
    ([k, v]) => LONE_SURROGATE.test(k) || beyondReferenceParser(v, depth + 1),
  );
}

/**
 * True when well-formed JSON `text` holds what serde_json refuses: nesting
 * deeper than REFERENCE_MAX_DEPTH, a surrogate escape that is not half of a
 * pair, or a number token past the float range. It reads every copy of a
 * repeated key, which JSON.parse does not keep (it keeps the last).
 */
function textBeyondReferenceParser(text: string): boolean {
  let depth = 0;
  let inString = false;
  const n = text.length;
  const hexUnit = (at: number): number => {
    if (at + 4 > n) return -1;
    const h = text.slice(at, at + 4);
    return /^[0-9a-fA-F]{4}$/.test(h) ? parseInt(h, 16) : -1;
  };
  for (let i = 0; i < n; i++) {
    const c = text[i];
    if (!inString) {
      if (c === '"') {
        inString = true;
      } else if (c === "[" || c === "{") {
        depth++;
        if (depth > REFERENCE_MAX_DEPTH) return true;
      } else if (c === "]" || c === "}") {
        depth--;
      } else if (c === "-" || (c >= "0" && c <= "9")) {
        let j = i + 1;
        while (j < n && /[0-9.eE+-]/.test(text[j])) j++;
        if (!Number.isFinite(Number(text.slice(i, j)))) return true;
        i = j - 1;
      }
      continue;
    }
    if (c === '"') {
      inString = false;
    } else if (c === "\\") {
      i++;
      if (text[i] !== "u") continue;
      const unit = hexUnit(i + 1);
      if (unit < 0) return true;
      i += 4;
      if (unit >= 0xdc00 && unit <= 0xdfff) return true;
      if (unit >= 0xd800 && unit <= 0xdbff) {
        if (text[i + 1] !== "\\" || text[i + 2] !== "u") return true;
        const low = hexUnit(i + 3);
        if (low < 0xdc00 || low > 0xdfff) return true;
        i += 6;
      }
    }
  }
  return false;
}

/**
 * Verify an AuditProof offline through the full 8-stage pipeline.
 *
 * Mirrors `nanorix_verify::verify_auditproof`. Stage 7 ("chain reproduced and
 * the signature verifies against the embedded key") is the ceiling unless the
 * policy carries a `trustChain`: with a signed key list and the identity
 * fingerprint that must have signed it, stage 8 resolves the signing key in the
 * list and checks the signature against the listed key.
 *
 * @param jsonBytes AuditProof as Uint8Array, Buffer, or already-parsed object.
 *   Give the file's bytes: a parsed object has lost the original bytes and the
 *   earlier copies of a repeated key, so a document the reference refuses can
 *   verify.
 * @param policy Optional VerifierPolicy for the authority and region pins,
 *   the `rejectDiagnostic` setting, and `trustChain` for stage 8.
 */
export async function verifyAuditProof(
  jsonBytes: Uint8Array | ArrayBufferView | Record<string, unknown>,
  policy?: VerifierPolicy,
): Promise<VerificationResult> {
  const result = await runLadder(jsonBytes, policy);
  const status = verificationStatusFor(result.valid, result.stage_reached);
  return { status, ok: status === "verified", ...result };
}

async function runLadder(
  jsonBytes: Uint8Array | ArrayBufferView | Record<string, unknown>,
  policy?: VerifierPolicy,
): Promise<LadderResult> {
  const pol = policy ?? {};
  const meta = makeEmptyMetadata();

  // Stage 0: parse
  let proof: Record<string, unknown>;
  let parsed = true;
  if (ArrayBuffer.isView(jsonBytes)) {
    try {
      const bytes = new Uint8Array(
        jsonBytes.buffer,
        jsonBytes.byteOffset,
        jsonBytes.byteLength,
      );
      // fatal: invalid UTF-8 is refused, not replaced. ignoreBOM: a BOM stays
      // in the text, where JSON.parse refuses it as the reference does.
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      proof = JSON.parse(text) as Record<string, unknown>;
      if (textBeyondReferenceParser(text)) throw new Error("beyond the reference parser");
    } catch {
      parsed = false;
      proof = {};
    }
  } else {
    proof = jsonBytes;
  }
  if (!parsed || beyondReferenceParser(proof)) {
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

  // Stage 1: cdp_version present. A top-level value that is not an object
  // has none, as in the reference.
  const cdpVersion =
    typeof proof === "object" && proof !== null ? proof["cdp_version"] : undefined;
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

  // Gate on `customer_declared_activity_root`, same position and
  // same reasoning as the reserved-slot gate: a root on a version that does
  // not sign it, or of a shape no signer emits, is named here before any
  // recompute consumes it so the verdict blames the field and not the
  // signature or the record.
  const rootGate = gateDeclaredActivityRoot(proof, cdpVersion);
  if (rootGate !== null) {
    return {
      valid: false,
      failure_reason: rootGate,
      stage_reached: 2,
      metadata: meta,
    };
  }

  // The metadata names a capsule and a region only on a version whose
  // signature covers them. A 1.0 signature covers final_hash alone, which binds
  // destroyed_at and the two optional Merkle roots. It does not bind the
  // capsule_id itself (only through record receipts, which a holder can
  // remove), the region or the key id, so on 1.0 neither is reported. The
  // record-receipt check below hashes the capsule id as the document states
  // it, on every version.
  const documentCapsuleId = typeof proof["capsule_id"] === "string" ? proof["capsule_id"] : "";
  const namesSignedFields = CANONICAL_VIEW_SIGNED_VERSIONS.has(cdpVersion);
  // The region is read from the activity trail, so it is reported only when
  // the signature step below will check a signature over that trail: on a
  // proof without a signature or key, no return names it. Mirrors Rust.
  const trailChecked = namesSignedFields && (await verifySignature(proof, cdpVersion)).kind !== "absent";
  if (typeof proof["capsule_id"] === "string" && namesSignedFields)
    meta.capsuleId = proof["capsule_id"];
  // Region resolves from the capsule_started activity event only, on 2.1 and
  // 2.2 carrying a signature. There the activity trail is inside
  // CanonicalCdpView, so a region there cannot be altered without breaking the
  // signature; an unsigned 2.1 or 2.2 proof reports no region. `environment.region` and top-level
  // `region` are both outside the canonical hash — reading either let an
  // outsider satisfy a residency pin by appending a region to a genuine signed
  // proof, with no key. Mirrors the Rust and Go verifiers.
  const regionEvents = proof["activity"];
  if (Array.isArray(regionEvents) && trailChecked) {
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

  // Policy-pin gate. Runs BEFORE the chain walk: the policy decision
  // is independent of chain validity, so a customer who pinned the wrong
  // authority learns it without a 7-step SHA-512 walk.
  //
  // The pin is compared with the top-level `authority_id`; absent or
  // non-string means DEFAULT_AUTHORITY_ID. Only cdp_version 2.1 and 2.2 sign
  // that field (the canonical view binds it): 1.0 signs final_hash, so on 1.0
  // a top-level string other than DEFAULT_AUTHORITY_ID (the empty string
  // included) is refused first, claimed = that value, and the effective
  // authority can only be the default. 2.0 never reaches this gate: the
  // version gate above refuses it first. An unsigned
  // `signing_authority.authority_id` that differs from it is refused
  // (claimed = that value) and can never make a proof match; `signing_authority`
  // absent, null or without `authority_id` is ignored. With the top-level
  // field absent, a non-matching pin reports claimed null and the has-none
  // reason. A pin alone checks only what the proof says about itself; the
  // key-list check at stage 8 (`pol.trustChain`) is the full check.
  if (pol.requiredAuthorityId) {
    const topLevel = proof["authority_id"];
    const effective = effectiveAuthorityId(proof);
    if (
      !CANONICAL_VIEW_SIGNED_VERSIONS.has(cdpVersion) &&
      typeof topLevel === "string" &&
      topLevel !== DEFAULT_AUTHORITY_ID
    ) {
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.AUTHORITY_ID_MISMATCH,
          claimed_authority_id: topLevel,
          expected_authority_id: pol.requiredAuthorityId,
          reason: "verifier_policy_authority_id_mismatch",
        },
        stage_reached: 2,
        metadata: meta,
      };
    }
    const unsigned = pointer(proof, "signing_authority", "authority_id");
    if (typeof unsigned === "string" && unsigned !== effective) {
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.AUTHORITY_ID_MISMATCH,
          claimed_authority_id: unsigned,
          expected_authority_id: pol.requiredAuthorityId,
          reason: "verifier_policy_authority_id_mismatch",
        },
        stage_reached: 2,
        metadata: meta,
      };
    }
    if (effective !== pol.requiredAuthorityId) {
      const hasTopLevel = typeof topLevel === "string";
      return {
        valid: false,
        failure_reason: {
          type: FailureReasonType.AUTHORITY_ID_MISMATCH,
          claimed_authority_id: hasTopLevel ? topLevel : null,
          expected_authority_id: pol.requiredAuthorityId,
          reason: hasTopLevel
            ? "verifier_policy_authority_id_mismatch"
            : "verifier_policy_demands_customer_hsm_audit_proof_has_none",
        },
        stage_reached: 2,
        metadata: meta,
      };
    }
  }

  // The residency pin and the diagnostic gate read the activity trail, so
  // each trusts it only when the signature step below will check a signature
  // over it: the version's signed message is the canonical view (2.1 / 2.2)
  // and that step does not end as "absent". A 1.0 trail, and the trail of a
  // 2.1 or 2.2 proof without a signature or key, is unsigned: anyone could add
  // a region equal to the pin, or delete a diagnostic_mode_enabled event, and
  // the proof would still verify. Computed only under a policy that reads the
  // trail. Mirrors Rust.
  const trailSigned = (pol.requiredRegion !== undefined || Boolean(pol.rejectDiagnostic)) && trailChecked;

  // Residency-pin gate. A proof carrying no region at
  // all cannot satisfy a residency pin — rejected with an empty `actual`, so
  // the pin fails closed. Only a signed region counts: on an unsigned trail
  // the pin reads no region and refuses.
  if (pol.requiredRegion !== undefined) {
    const actual = trailSigned ? (meta.region ?? "") : "";
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

  // Diagnostic-mode gate, after the residency pin and before the
  // chain walk, like the other policy pins. A proof whose trail is unsigned
  // (1.0, or 2.1 or 2.2 without a signature) cannot show it was not run in
  // diagnostic mode, since the event could be deleted and the proof would
  // still verify: the setting refuses every one. Mirrors Rust.
  if (pol.rejectDiagnostic && (!trailSigned || recordsDiagnosticMode(proof))) {
    return {
      valid: false,
      failure_reason: { type: FailureReasonType.DIAGNOSTIC_PROOF_REFUSED },
      stage_reached: 2,
      metadata: meta,
    };
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

  // Optional Merkle roots for the Step 8 amendment.
  // Absent on legacy proofs, where both branches collapse to the legacy
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

  // Receipt-set verification (Mode A step 3).
  const receipts = proof["record_receipts"];
  if (Array.isArray(receipts)) {
    const failure = await verifyRecordReceipts(
      receipts,
      documentCapsuleId,
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

  // Parent-proof-set verification.
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

  // Customer-declared activity root. The stage-2 gate has already
  // rejected a root on a version that does not sign it and a root of any
  // shape no signer emits, so a root read here is a well-formed string on
  // 2.1 / 2.2 and is canonical-bound: the signature stages below bind it to
  // the signer regardless. Recomputing it needs the customer's record, which
  // the reader supplies through the policy. Sits with the other
  // sub-structure Merkle checks so it also covers the path where a chain
  // reproduces with no signature to check at all.
  const activityCheck = await verifyCustomerDeclaredActivity(
    proof,
    pol.customerActivity,
  );
  meta.customerDeclaredActivityRoot = activityCheck.claimed;
  if (activityCheck.status === CustomerDeclaredActivityStatus.FAILED) {
    return {
      valid: false,
      failure_reason: activityCheck.failure_reason,
      stage_reached: 3,
      metadata: meta,
    };
  }
  if (activityCheck.status === CustomerDeclaredActivityStatus.VERIFIED) {
    meta.customerDeclaredActivityChecked = true;
  } else if (
    activityCheck.status === CustomerDeclaredActivityStatus.DECLARED_NOT_CHECKED
  ) {
    meta.customerDeclaredActivityChecked = false;
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

  // Algorithm dispatch precedes byte-shape checks: a proof
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

  const modeMismatch = signingModeAuthorityMismatch(proof, cdpVersion);
  if (modeMismatch !== null) {
    return {
      valid: false,
      failure_reason: modeMismatch,
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
    // Under a hybrid pin it is refused there instead.
    if (pol.trustChain !== undefined && isHybridPin(pol.trustChain.pinnedIdentityFingerprint)) {
      return hybridRecordRefusal(4, meta);
    }
    // No signature covers the activity trail here, so the region read from it
    // is not reported.
    meta.region = null;
    return {
      valid: true,
      failure_reason: null,
      stage_reached: 4,
      metadata: meta,
    };
  }

  // Stage 8 anchors the key in a signed key list; without one the honest
  // ceiling is integrity-only.
  if (pol.trustChain !== undefined) {
    return anchorToTrustChain(proof, cdpVersion, pol.trustChain, meta);
  }
  return {
    valid: true,
    failure_reason: null,
    stage_reached: 7,
    metadata: meta,
  };
}

/**
 * Verify the receipt set (Mode A step 3) — each receipt's chain hash
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

/** Verify the parent-proof-set Merkle root. */
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
