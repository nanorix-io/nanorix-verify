/**
 * ADR-056 — `customer_declared_activity_root` recompute-and-compare.
 *
 * The proof carries ONE field about the customer's own activity record: a
 * root over the raw bytes of the file the SDK's activity helpers append to
 * inside the capsule. The events themselves are never absorbed into the
 * proof; the customer keeps the file and presents it here as a sidecar.
 * Nanorix never parses those bytes — the root is a commitment to content,
 * not a statement about it.
 *
 * ## Algorithm (pinned by `tools/nanorix-verify/fixtures/customer_declared_activity_root_vectors.json`)
 *
 * 1. Split the sidecar on `0x0A`. Drop only a trailing empty segment (a file
 *    that ends in a newline has no extra empty line). Never trim, never parse.
 * 2. Leaf = SHA-512 hex of each line's raw bytes.
 * 3. Root = `merkleRootSha512NullSeparated(leaves)` — pairs hashed as
 *    `SHA-512(left_hex || 0x00 || right_hex)`, odd last node duplicated.
 * 4. Zero lines → GENESIS (SHA-512 of the empty string), so "opted in, wrote
 *    nothing" is distinguishable from "did not opt in" (field absent).
 * 5. Wire form `sha512:<hex>`.
 *
 * ## The four outcomes
 *
 * | sidecar | root in proof | outcome |
 * |---|---|---|
 * | given | present | recompute and compare; mismatch is a failure |
 * | given | absent | `required_field_missing` — a sidecar presented against a proof that never declared one is the fail-closed shape |
 * | absent | present | "declared, not checked" — disclosed, NOT a failure; most readers of a proof never hold the sidecar |
 * | absent | absent | nothing was declared; nothing to do |
 * | any | present, `cdp_version` not 2.1 / 2.2 | `unsigned_field_populated` — the root is signed only where the signed message is the canonical view; elsewhere (a missing `cdp_version` included) a populated root is a value anyone holding the document can write, so it is never compared and never disclosed as "declared" |
 * | any | malformed | `field_malformed` — never compared, never disclosed as "declared"; `""` is malformed, not absent |
 *
 * This check sits beside the stage ladder, not inside it: the root is already
 * signature-bound (it is in the canonical view), so the ladder establishes
 * that the root is the one the deployment signed, and this module establishes
 * that the bytes in hand are the bytes that root commits to. It applies the
 * ladder's two stage-2 gates on the root itself, in the ladder's order, so a
 * caller that skips the ladder cannot be handed "verified" for a root the
 * signature never covered.
 *
 * Pure Web Crypto, like the rest of the verifier. Mirrors the Python SDK's
 * `nanorix.verifier.customer_activity` and the Rust verifier's sidecar check.
 */

import {
  CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
  FailureReasonType,
  gateDeclaredActivityRoot,
  stripSha512Prefix,
  type FailureReason,
} from "./auditproof.js";
import {
  GENESIS_SHA512_HEX,
  merkleRootSha512NullSeparated,
} from "./wave_n.js";

export { CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD };

const LINE_SEPARATOR = 0x0a;

function getSubtle(): SubtleCrypto {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (g.crypto?.subtle) return g.crypto.subtle as SubtleCrypto;
  throw new Error(
    "Web Crypto subtle not available (need Node 18+ or modern browser)",
  );
}

function bytesToHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Split the sidecar bytes on `0x0A`, dropping only a trailing empty segment.
 *
 * Whitespace is content: a leading space or an empty interior line is a line
 * of its own. An empty input yields no lines; a lone `\n` yields one empty
 * line. Each returned line is a fresh copy whose `.buffer` is exactly the
 * line: `Buffer.prototype.slice` is a view, not a copy, and a `Buffer` from
 * the shared pool would otherwise hand SubtleCrypto the whole pool.
 */
export function splitCustomerDeclaredActivityLines(
  data: Uint8Array,
): Uint8Array[] {
  const lines: Uint8Array[] = [];
  let start = 0;
  for (let i = 0; i < data.length; i++) {
    if (data[i] === LINE_SEPARATOR) {
      lines.push(new Uint8Array(data.subarray(start, i)));
      start = i + 1;
    }
  }
  // Only a trailing segment that is non-empty is a line; a file ending in
  // `\n` contributes nothing after its last separator.
  if (start < data.length) lines.push(new Uint8Array(data.subarray(start)));
  return lines;
}

/** SHA-512 hex of each line's raw bytes, in file order. No prefix. */
export async function customerDeclaredActivityLeafHashes(
  data: Uint8Array,
): Promise<string[]> {
  const subtle = getSubtle();
  const leaves: string[] = [];
  for (const line of splitCustomerDeclaredActivityLines(data)) {
    const digest = await subtle.digest("SHA-512", line.buffer as ArrayBuffer);
    leaves.push(bytesToHex(digest));
  }
  return leaves;
}

/**
 * The ADR-056 root over a sidecar's raw bytes, in wire form `sha512:<hex>`.
 *
 * Byte-equivalent with the Rust, Go, Python and browser verifiers; every
 * vector in `customer_declared_activity_root_vectors.json` pins it.
 */
export async function computeCustomerDeclaredActivityRoot(
  data: Uint8Array,
): Promise<string> {
  const leaves = await customerDeclaredActivityLeafHashes(data);
  const root =
    (await merkleRootSha512NullSeparated(leaves)) ?? GENESIS_SHA512_HEX;
  return `sha512:${root}`;
}

/** Which of the four outcomes the sidecar check reached. */
export const CustomerDeclaredActivityStatus = {
  /** The proof carries no root and no sidecar was offered. */
  NOT_DECLARED: "not_declared",
  /**
   * The proof carries a root but no sidecar was offered. Disclosed rather
   * than failed: the signature already binds the root, and a verifier
   * without the customer's file cannot say anything more.
   */
  DECLARED_NOT_CHECKED: "declared_not_checked",
  /** The sidecar's recomputed root equals the signed root. */
  VERIFIED: "verified",
  /** A sidecar was offered and the check failed; see `failure_reason`. */
  FAILED: "failed",
} as const;

export type CustomerDeclaredActivityStatusValue =
  (typeof CustomerDeclaredActivityStatus)[keyof typeof CustomerDeclaredActivityStatus];

/** Outcome of `verifyCustomerDeclaredActivity`. */
export interface CustomerDeclaredActivityCheck {
  status: CustomerDeclaredActivityStatusValue;
  /** The root as it appears in the proof, when present. */
  claimed: string | null;
  /** The root recomputed from the sidecar, when one was offered. */
  computed: string | null;
  /** Lines the sidecar split into, when one was offered. */
  lineCount: number | null;
  /** Set only for `failed`. */
  failure_reason: FailureReason | null;
  /**
   * True unless a sidecar was offered and the check failed.
   * `declared_not_checked` counts as ok on purpose — it is a disclosure, not
   * a defect. Callers that require the sidecar to have been checked must test
   * `checked`.
   */
  ok: boolean;
  /** True only for `verified`. */
  checked: boolean;
}

/**
 * The root as the proof carries it: `{ root }` when present, well-formed and
 * on a version that signs it; `{ failure }` when present but unsigned on this
 * `cdp_version` (`unsigned_field_populated` — a missing or non-string
 * `cdp_version` counts as a version that does not sign it) or of a shape no
 * signer emits (`field_malformed`, including the empty string — the canonical
 * view binds `""` as a value, so it is never "absent"); null when absent or
 * JSON `null`.
 */
function claimedRoot(
  proof: Record<string, unknown>,
): { root: string } | { failure: FailureReason } | null {
  const value = proof[CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD];
  if (value === undefined || value === null) return null;
  const cdpVersion = proof["cdp_version"];
  const failure = gateDeclaredActivityRoot(
    proof,
    typeof cdpVersion === "string" ? cdpVersion : "",
  );
  return failure === null ? { root: value as string } : { failure };
}

/**
 * Compare a sidecar of raw activity bytes against the proof's declared root.
 *
 * `data` is the exact byte content of the customer's activity file
 * (`activity_events.jsonl`), or undefined when the caller does not hold it.
 * The bytes are hashed as-is — no decoding, no trimming, no JSON parsing.
 *
 * This does not verify the proof's signature. Run `verifyAuditProof` first;
 * a matching sidecar against an unsigned or tampered proof proves nothing.
 * It does apply the ladder's stage-2 gates on the root: a present root on a
 * `cdp_version` other than 2.1 / 2.2 is `unsigned_field_populated` and a
 * malformed one is `field_malformed`, with or without a record, and neither
 * is ever compared or disclosed as "declared".
 */
export async function verifyCustomerDeclaredActivity(
  proof: Record<string, unknown>,
  data?: Uint8Array | null,
): Promise<CustomerDeclaredActivityCheck> {
  const declared = claimedRoot(proof);
  // A malformed root is `field_malformed` before any recompute, never a
  // mismatch against it — whether or not a record was offered.
  if (declared !== null && "failure" in declared) {
    return {
      status: CustomerDeclaredActivityStatus.FAILED,
      claimed: null,
      computed: null,
      lineCount: null,
      failure_reason: declared.failure,
      ok: false,
      checked: false,
    };
  }
  const claimed = declared === null ? null : declared.root;

  if (data === undefined || data === null) {
    if (claimed === null) {
      return {
        status: CustomerDeclaredActivityStatus.NOT_DECLARED,
        claimed: null,
        computed: null,
        lineCount: null,
        failure_reason: null,
        ok: true,
        checked: false,
      };
    }
    return {
      status: CustomerDeclaredActivityStatus.DECLARED_NOT_CHECKED,
      claimed,
      computed: null,
      lineCount: null,
      failure_reason: null,
      ok: true,
      checked: false,
    };
  }

  const lineCount = splitCustomerDeclaredActivityLines(data).length;
  const computed = await computeCustomerDeclaredActivityRoot(data);

  if (claimed === null) {
    return {
      status: CustomerDeclaredActivityStatus.FAILED,
      claimed: null,
      computed,
      lineCount,
      failure_reason: {
        type: FailureReasonType.REQUIRED_FIELD_MISSING,
        field: CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
      },
      ok: false,
      checked: false,
    };
  }

  if (stripSha512Prefix(claimed) !== stripSha512Prefix(computed)) {
    return {
      status: CustomerDeclaredActivityStatus.FAILED,
      claimed,
      computed,
      lineCount,
      failure_reason: {
        type: FailureReasonType.CUSTOMER_DECLARED_ACTIVITY_ROOT_MISMATCH,
        claimed,
        computed,
      },
      ok: false,
      checked: false,
    };
  }

  return {
    status: CustomerDeclaredActivityStatus.VERIFIED,
    claimed,
    computed,
    lineCount,
    failure_reason: null,
    ok: true,
    checked: true,
  };
}
