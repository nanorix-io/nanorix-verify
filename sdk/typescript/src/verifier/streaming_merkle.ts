/**
 * Streaming-egress Merkle root verification — TypeScript mirror of
 * `tools/nanorix-verify/src/streaming_merkle.rs`.
 *
 * A capsule that streams a response records one `streaming_egress_chunk`
 * activity event per chunk and closes the stream with a
 * `streaming_egress_completed` event carrying `streaming_merkle_root` — an
 * RFC 6962 SHA-512 commitment over exactly those chunk hashes, emitted by
 * `runtime/eee/src/daemon/streaming.rs::merkle_root_from_leaves`.
 *
 * Until this module, no verifier in any implementation read that root. It was
 * signed and carried past. A commitment nothing recomputes is not evidence.
 *
 * The root is recomputed only when the leaves are present AND complete — the
 * number of chunk events collected equals the stream's `total_chunks`. A
 * document disclosing the root with fewer leaves is the future truncation
 * shape, not a defect; recomputing from a partial set would fail every
 * truncated proof. Leaves are ordered by their `seq` field rather than by
 * document order, per the contract at `streaming.rs:150`.
 *
 * Pure Web Crypto — no Node built-ins, so the browser verifier can consume it.
 */

/** RFC 6962 leaf-domain prefix. */
const MERKLE_LEAF_PREFIX = 0x00;
/** RFC 6962 inner-node domain prefix. */
const MERKLE_INNER_PREFIX = 0x01;

/** SHA-512 of the empty input — the root of a zero-leaf tree. */
const EMPTY_SHA512_HEX =
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

function getSubtle(): SubtleCrypto {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (g.crypto?.subtle) return g.crypto.subtle as SubtleCrypto;
  throw new Error(
    "Web Crypto SubtleCrypto not available (need Node 18+ or modern browser)",
  );
}

function stripSha512Prefix(s: string): string {
  return s.startsWith("sha512:") ? s.slice("sha512:".length) : s;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/** Digest a domain byte followed by one or two 64-byte nodes. */
async function domainDigest(
  prefix: number,
  ...nodes: Uint8Array[]
): Promise<Uint8Array> {
  const total = nodes.reduce((acc, n) => acc + n.length, 1);
  const buf = new Uint8Array(total);
  buf[0] = prefix;
  let off = 1;
  for (const n of nodes) {
    buf.set(n, off);
    off += n.length;
  }
  const digest = await getSubtle().digest(
    "SHA-512",
    buf.buffer as ArrayBuffer,
  );
  return new Uint8Array(digest);
}

/**
 * Byte-for-byte mirror of
 * `runtime/eee/src/daemon/streaming.rs::merkle_root_from_leaves`.
 *
 * Empty → SHA-512 of empty. Single leaf → `SHA-512(0x00 || leaf)`. Inner →
 * `SHA-512(0x01 || left || right)`. An odd tail node is promoted unchanged.
 * Returns 128 lowercase hex characters, unprefixed.
 *
 * Forever-Standard (ADR-006 I0): changing any of those three rules
 * invalidates every streaming Merkle root ever emitted.
 */
export async function merkleRootFromLeaves(
  leaves: readonly Uint8Array[],
): Promise<string> {
  if (leaves.length === 0) return EMPTY_SHA512_HEX;

  let level: Uint8Array[] = [];
  for (const leaf of leaves) {
    level.push(await domainDigest(MERKLE_LEAF_PREFIX, leaf));
  }

  while (level.length > 1) {
    const next: Uint8Array[] = [];
    let i = 0;
    while (i + 1 < level.length) {
      next.push(
        await domainDigest(MERKLE_INNER_PREFIX, level[i], level[i + 1]),
      );
      i += 2;
    }
    if (i < level.length) next.push(level[i]);
    level = next;
  }

  return bytesToHex(level[0]);
}

/**
 * One `chunk_hash` as a 64-byte Merkle leaf, or `null` when the value is not a
 * `sha512:`-prefixed (or bare) 128-hex string.
 */
function leafBytes(chunkHash: string): Uint8Array | null {
  const hex = stripSha512Prefix(chunkHash);
  if (hex.length !== 128 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Minimal shape of a structured failure reason, to avoid a circular import. */
interface StreamingFailure {
  type: string;
  field?: string;
  claimed?: string;
  computed?: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** Check one closed stream's root. `null` when there is nothing to check. */
async function closeStream(
  chunks: Array<[number, string]>,
  malformed: boolean,
  completed: Record<string, unknown>,
): Promise<StreamingFailure | null> {
  const claimed = completed["streaming_merkle_root"];
  if (typeof claimed !== "string") return null;

  // A disclosed chunk event with no usable `chunk_hash` is a structural defect
  // in the trail, not a root disagreement — and is reported as one. Checked
  // before the completeness gate so a single unusable leaf cannot shrink the
  // set into the "truncated, do not check" shape.
  if (malformed) {
    return {
      type: "required_field_missing",
      field: "activity_trail.streaming_egress_chunk.chunk_hash",
    };
  }

  // Absent `total_chunks` is treated as "as many as were disclosed", so a
  // document that omits the count still gets checked when its leaves are all
  // there.
  const rawTotal = completed["total_chunks"];
  const total =
    typeof rawTotal === "number" && Number.isInteger(rawTotal)
      ? rawTotal
      : chunks.length;

  // Partial disclosure — the truncated shape. Not a defect; not checkable. A
  // zero-chunk stream lands here with an empty leaf set and total 0, which IS
  // checkable: its root is SHA-512 of empty.
  if (chunks.length !== total) return null;

  const ordered = [...chunks].sort((a, b) => a[0] - b[0]);
  const leaves: Uint8Array[] = [];
  for (const [, hash] of ordered) {
    const leaf = leafBytes(hash);
    // Cannot be null here — `malformed` already rejected every unparseable
    // hash above.
    if (leaf) leaves.push(leaf);
  }

  const computed = await merkleRootFromLeaves(leaves);
  if (stripSha512Prefix(claimed) !== computed) {
    return {
      type: "streaming_merkle_root_mismatch",
      claimed,
      computed: `sha512:${computed}`,
    };
  }
  return null;
}

/**
 * Walk the activity trail and verify every streaming Merkle root whose leaves
 * are fully disclosed. Returns the first failure, or `null`.
 *
 * Streams are delimited by their events: `streaming_egress_started` opens a
 * fresh accumulator, `streaming_egress_chunk` adds a leaf,
 * `streaming_egress_completed` closes and checks. Events of any other kind are
 * ignored.
 */
export async function verifyStreamingMerkleRoots(
  activity: readonly unknown[],
): Promise<StreamingFailure | null> {
  let chunks: Array<[number, string]> = [];
  let malformed = false;

  for (const raw of activity) {
    const event = asRecord(raw);
    if (!event) continue;

    switch (event["event"]) {
      case "streaming_egress_started":
        chunks = [];
        malformed = false;
        break;
      case "streaming_egress_chunk": {
        const seq = event["seq"];
        const hash = event["chunk_hash"];
        if (
          typeof seq === "number" &&
          Number.isInteger(seq) &&
          typeof hash === "string" &&
          leafBytes(hash) !== null
        ) {
          chunks.push([seq, hash]);
        } else {
          // Flagged rather than dropped: dropping would let a malformed leaf
          // shrink the set into a different tree, or into the "truncated"
          // shape.
          malformed = true;
        }
        break;
      }
      case "streaming_egress_completed": {
        const failure = await closeStream(chunks, malformed, event);
        if (failure) return failure;
        chunks = [];
        malformed = false;
        break;
      }
      default:
        break;
    }
  }

  return null;
}
