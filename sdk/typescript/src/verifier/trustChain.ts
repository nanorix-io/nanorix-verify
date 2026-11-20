/**
 * Stage 8 trust root: a signed key list pinned by its identity fingerprint.
 *
 * TypeScript mirror of `tools/nanorix-verify/src/trust_chain.rs`, which is the
 * reference. The vectors under `tools/nanorix-verify/fixtures/trust_chain/` and
 * `tools/nanorix-verify/fixtures/trust_chain_hybrid/` hold this file to it.
 *
 * A list is checked once, when it is loaded, against the pinned fingerprint. A
 * list that is not the pinned identity's is refused there, before any proof is
 * read, and never becomes a policy that could be applied by mistake.
 *
 * Web Crypto for Ed25519 and SHA-256; the ML-DSA-87 list signature of a hybrid
 * key list goes through `verifyMlDsa`.
 */

import { canonicalizeBytes } from "../_jcs.js";
import { hasSmallOrderKeyOrR } from "./_ed25519_strict.js";
import { ML_DSA_87, verifyMlDsa } from "./_mldsa.js";

/**
 * Why a key list was refused. The names match the Rust `ManifestError::kind`
 * names, plus `load_failed` for bytes that are not a key list.
 */
export type TrustChainErrorKind =
  | "load_failed"
  | "malformed"
  | "fingerprint_mismatch"
  | "signature_invalid"
  | "pqc_identity_missing"
  | "pqc_algorithm_unsupported"
  | "pqc_signature_missing"
  | "pqc_signature_invalid"
  | "non_canonical_encoding"
  | "key_label_unknown"
  | "record_key_length"
  | "version_repeated"
  | "fingerprint_not_of_key"
  | "partner_missing"
  | "partner_invalid"
  | "partner_shared"
  | "key_in_two_roles"
  | "partner_changed"
  | "pqc_identity_under_classical_pin"
  | "authority_id_malformed"
  | "byoc_authority_id_malformed"
  | "byoc_authority_needs_hybrid_pin"
  | "byoc_authority_pin_mismatch";

const MESSAGES: Record<TrustChainErrorKind, string> = {
  load_failed: "trust-chain key list does not parse as a key list",
  malformed: "trust-chain key list is malformed (bad identity key)",
  fingerprint_mismatch:
    "trust-chain key list is not signed by the pinned identity (fingerprint mismatch)",
  signature_invalid: "trust-chain key list signature is invalid",
  pqc_identity_missing: "the hybrid key list has no ML-DSA-87 identity key",
  pqc_algorithm_unsupported: "the hybrid key list's post-quantum identity is not ML-DSA-87",
  pqc_signature_missing: "the hybrid key list has no ML-DSA-87 signature",
  pqc_signature_invalid: "the hybrid key list's ML-DSA-87 signature does not verify",
  non_canonical_encoding: "a key or signature in the hybrid key list is not canonical base64",
  key_label_unknown: "a record in the hybrid key list has an algorithm other than Ed25519 or ML-DSA-65",
  record_key_length: "a record's key in the hybrid key list is not the length its algorithm needs",
  version_repeated: "a key version is listed twice in one authority",
  fingerprint_not_of_key: "a record's fingerprint is not the SHA-256 of its key",
  partner_missing: "an Ed25519 key version names no ML-DSA-65 partner",
  partner_invalid: "a partner is not an ML-DSA-65 version of the same authority",
  partner_shared: "two Ed25519 key versions name the same ML-DSA-65 partner",
  key_in_two_roles: "one key appears twice in the hybrid key list",
  partner_changed: "two key lists from one identity disagree about a record or its partner",
  pqc_identity_under_classical_pin:
    "the key list carries a post-quantum identity, so it needs its install's hybrid1-sha256: pin, not a sha256: pin",
  authority_id_malformed: "an authority id is outside the authority id alphabet",
  byoc_authority_id_malformed: "an authority id contains hybrid1 but is not <base>-hybrid1.<pin hex>-v<n>",
  byoc_authority_needs_hybrid_pin: "an authority id is a BYOC id, so it needs its install's hybrid1-sha256: pin",
  byoc_authority_pin_mismatch: "an authority id does not carry the hybrid pin the key list verified under",
};

/** The prefix of a hybrid identity pin. */
export const HYBRID_PIN_PREFIX = "hybrid1-sha256:";

/** The domain tag in front of the ML-DSA-87 list signature's message. */
const KEY_LIST_PQC_TAG = "nanorix-key-list-pqc-v1";

/**
 * The `found` text of the refusal every record gets under a hybrid pin until
 * this verifier checks the record's ML-DSA-65 half (the hybrid-pin gate).
 */
export const HYBRID_RECORD_CHECK_MISSING = "ML-DSA-65 record check (hybrid pin)";

const PQC_IDENTITY_ALGORITHM = "ML-DSA-87";
const ML_DSA_65 = "ML-DSA-65";
const ML_DSA_87_PUBLIC_KEY_LEN = 2592;
const KEY_LENGTHS: Record<string, number> = { Ed25519: 32, [ML_DSA_65]: 1952 };

/** True when `pin` is of the hybrid kind, read from the pin string alone. */
export function isHybridPin(pin: unknown): boolean {
  return typeof pin === "string" && pin.startsWith(HYBRID_PIN_PREFIX);
}

const UTF8 = new TextEncoder();

/** A before B in the byte order of their UTF-8 encodings, as the reference's BTreeMap. */
function byteOrder(a: string, b: string): number {
  const x = UTF8.encode(a);
  const y = UTF8.encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    if (x[i] !== y[i]) return x[i]! - y[i]!;
  }
  return x.length - y.length;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The hybrid pin of an identity: both keys under one SHA-256. */
export async function hybridPin(ed25519Identity: Uint8Array, mldsa87Identity: Uint8Array): Promise<string> {
  const preimage = concat(
    UTF8.encode("nanorix-identity-hybrid-v1\x00Ed25519\x00"),
    ed25519Identity,
    UTF8.encode("\x00ML-DSA-87\x00"),
    mldsa87Identity,
  );
  return HYBRID_PIN_PREFIX + (await sha256Hex(preimage));
}

/**
 * The pin hex an authority id of BYOC form carries, when the id is exactly
 * `<base>-hybrid1.<p>-v<n>` with `hybrid1` once; otherwise null.
 */
function byocPinHex(id: string): string | null {
  if (id.split("hybrid1").length !== 2) return null;
  const m = /^[\s\S]+-hybrid1\.([0-9a-f]{64})-v[1-9][0-9]*$/.exec(id);
  return m === null ? null : m[1]!;
}

function isAuthorityIdentifier(id: string): boolean {
  return /^[a-z0-9._-]{1,128}$/.test(id);
}

/**
 * The key list's authority id rules, each id in byte order: the id alphabet
 * under a hybrid pin only, then the BYOC form of an id containing `hybrid1`,
 * then the pin's kind. `pinHex` is the hybrid pin's 64 hex digits, or null
 * under a classical pin.
 */
function checkAuthorityIds(ids: Iterable<string>, pinHex: string | null): void {
  for (const id of [...ids].sort(byteOrder)) {
    if (pinHex !== null && !isAuthorityIdentifier(id)) throw new TrustChainError("authority_id_malformed");
    const byoc = id.includes("hybrid1");
    const carried = byoc ? byocPinHex(id) : null;
    if (byoc && carried === null) throw new TrustChainError("byoc_authority_id_malformed");
    if (pinHex === null && byoc) throw new TrustChainError("byoc_authority_needs_hybrid_pin");
    if (pinHex !== null && carried !== pinHex) throw new TrustChainError("byoc_authority_pin_mismatch");
  }
}

/**
 * A key list was refused. A setup error, not a verdict on a proof.
 *
 * `kind` names the refusal: `load_failed` (the bytes are not a key list of the
 * expected shape), `malformed` (the identity public key is missing or
 * unusable), `fingerprint_mismatch` (the identity keys do not hash to both the
 * list's own fingerprint and the pinned one), `signature_invalid` (the list's
 * Ed25519 signature does not verify, strictly), or one of the hybrid key
 * list's refusals.
 */
export class TrustChainError extends Error {
  readonly kind: TrustChainErrorKind;

  constructor(kind: TrustChainErrorKind) {
    super(MESSAGES[kind]);
    this.name = "TrustChainError";
    this.kind = kind;
  }
}

interface KeyRecord {
  version: string;
  publicKeyB64: string;
  fingerprint: string;
  algorithm: string | null;
  partner: string | null;
}

function label(record: KeyRecord): string {
  return record.algorithm ?? "Ed25519";
}

interface Authority {
  active: KeyRecord[];
  archived: KeyRecord[];
  revoked: boolean;
}

type Obj = Record<string, unknown>;

function isObject(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function getSubtle(): SubtleCrypto {
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (!subtle) throw new Error("Web Crypto (crypto.subtle) is not available");
  return subtle;
}

function bufferOf(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(await getSubtle().digest("SHA-256", bufferOf(bytes)));
}

const B64_ALPHABET = /^[A-Za-z0-9+/]*={0,2}$/;

function encodeB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function stripPrefix(value: string): string {
  return value.startsWith("base64:") ? value.slice("base64:".length) : value;
}

/**
 * Canonical standard padded base64 after an optional `base64:` prefix: padding
 * is required and the trailing bits must be zero, so the decoded bytes encode
 * back to the same text. Null otherwise.
 */
function canonicalB64(value: string): Uint8Array | null {
  const stripped = stripPrefix(value);
  if (stripped.length % 4 !== 0 || !B64_ALPHABET.test(stripped)) return null;
  let bin: string;
  try {
    bin = atob(stripped);
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return encodeB64(out) === stripped ? out : null;
}

/** `canonicalB64` of an exact length. */
function strictB64(value: string, expectedLen: number): Uint8Array | null {
  const out = canonicalB64(value);
  return out !== null && out.length === expectedLen ? out : null;
}

/** The decoded bytes as a binary string, for comparing two keys; null when undecodable. */
function decodedKey(value: string): string | null {
  try {
    return atob(stripPrefix(value));
  } catch {
    return null;
  }
}

function toHex(bytes: ArrayBuffer): string {
  let out = "";
  for (const b of new Uint8Array(bytes)) out += b.toString(16).padStart(2, "0");
  return out;
}

/** A string or null/absent; any other present value fails, as serde's `Option<String>`. */
function optStr(rec: Obj, key: string): { ok: boolean; value: string | null } {
  const v = rec[key];
  if (v === undefined || v === null) return { ok: true, value: null };
  if (typeof v === "string") return { ok: true, value: v };
  return { ok: false, value: null };
}

function parseRecords(raw: unknown): { records: KeyRecord[]; views: Obj[] } | null {
  if (!Array.isArray(raw)) return null;
  const records: KeyRecord[] = [];
  const views: Obj[] = [];
  for (const entry of raw) {
    if (!isObject(entry)) return null;
    const version = entry["signing_key_version"];
    const pub = entry["public_key_b64"];
    const fingerprint = entry["public_key_fingerprint"];
    const effectiveFrom = entry["effective_from"];
    if (
      typeof version !== "string" ||
      typeof pub !== "string" ||
      typeof fingerprint !== "string" ||
      typeof effectiveFrom !== "string"
    ) {
      return null;
    }
    const archivedAt = optStr(entry, "archived_at");
    const algorithm = optStr(entry, "algorithm");
    const partner = optStr(entry, "pqc_partner_version");
    if (!archivedAt.ok || !algorithm.ok || !partner.ok) return null;
    const view: Obj = {
      signing_key_version: version,
      public_key_b64: pub,
      public_key_fingerprint: fingerprint,
      effective_from: effectiveFrom,
    };
    if (archivedAt.value !== null) view["archived_at"] = archivedAt.value;
    if (algorithm.value !== null) view["algorithm"] = algorithm.value;
    if (partner.value !== null) view["pqc_partner_version"] = partner.value;
    records.push({ version, publicKeyB64: pub, fingerprint, algorithm: algorithm.value, partner: partner.value });
    views.push(view);
  }
  return { records, views };
}

interface Parsed {
  authorities: Map<string, Authority>;
  signedView: Obj;
  identityFingerprint: string;
  identityKeyB64: string;
  signature: string;
  pqcAlgorithm: string | null;
  pqcKeyB64: string | null;
  pqcSignature: string | null;
}

/**
 * The authorities, the signed view, and the identity fields, or null.
 *
 * The signed view holds every field the reference reads with its defaults
 * filled in (`archived_versions`, `revoked`, the identity key). Anything else in
 * the document is outside the signature, as in the reference.
 */
function parse(root: unknown): Parsed | null {
  if (!isObject(root)) return null;
  const schema = root["schema_version"];
  const issued = root["issued_at"];
  const fingerprint = root["identity_fingerprint"];
  const signature = root["manifest_signature"];
  if (
    typeof schema !== "string" ||
    typeof issued !== "string" ||
    typeof fingerprint !== "string" ||
    typeof signature !== "string"
  ) {
    return null;
  }
  const identityKey = "identity_public_key_b64" in root ? root["identity_public_key_b64"] : "";
  if (typeof identityKey !== "string") return null;
  const pqcSignature = optStr(root, "pqc_manifest_signature");
  const pqcAlgorithm = optStr(root, "pqc_identity_algorithm");
  const pqcKey = optStr(root, "pqc_identity_public_key_b64");
  if (!pqcSignature.ok || !pqcAlgorithm.ok || !pqcKey.ok) return null;

  const rawAuthorities = root["authorities"];
  if (!isObject(rawAuthorities)) return null;
  const authorities = new Map<string, Authority>();
  const signedAuthorities: Obj = Object.create(null) as Obj;
  for (const authorityId of Object.keys(rawAuthorities)) {
    const rec = rawAuthorities[authorityId];
    if (!isObject(rec)) return null;
    const displayName = rec["display_name"];
    if (typeof displayName !== "string") return null;
    const active = parseRecords(rec["active_versions"]);
    if (active === null) return null;
    let archived: { records: KeyRecord[]; views: Obj[] } = { records: [], views: [] };
    if ("archived_versions" in rec) {
      const parsedArchived = parseRecords(rec["archived_versions"]);
      if (parsedArchived === null) return null;
      archived = parsedArchived;
    }
    let revoked = false;
    if ("revoked" in rec) {
      if (typeof rec["revoked"] !== "boolean") return null;
      revoked = rec["revoked"];
    }
    let emitsHeads = false;
    if ("emits_population_heads" in rec) {
      if (typeof rec["emits_population_heads"] !== "boolean") return null;
      emitsHeads = rec["emits_population_heads"];
    }
    authorities.set(authorityId, {
      active: active.records,
      archived: archived.records,
      revoked,
    });
    signedAuthorities[authorityId] = {
      display_name: displayName,
      active_versions: active.views,
      archived_versions: archived.views,
      revoked,
      ...(emitsHeads ? { emits_population_heads: true } : {}),
    };
  }

  return {
    authorities,
    signedView: {
      schema_version: schema,
      issued_at: issued,
      authorities: signedAuthorities,
      identity_fingerprint: fingerprint,
      identity_public_key_b64: identityKey,
      ...(pqcAlgorithm.value !== null ? { pqc_identity_algorithm: pqcAlgorithm.value } : {}),
      ...(pqcKey.value !== null ? { pqc_identity_public_key_b64: pqcKey.value } : {}),
    },
    identityFingerprint: fingerprint,
    identityKeyB64: identityKey,
    signature,
    pqcAlgorithm: pqcAlgorithm.value,
    pqcKeyB64: pqcKey.value,
    pqcSignature: pqcSignature.value,
  };
}

/**
 * Whether a JSON text, already accepted by `JSON.parse`, holds one member name
 * twice in any object but the root's `authorities` map: the reference reads
 * that map last-wins and refuses a repeat in every other object, while
 * `JSON.parse` silently keeps the last copy, which no signature covers.
 */
function hasRepeatedMember(text: string): boolean {
  let i = 0;
  const skipSpace = () => {
    while (i < text.length && " \t\n\r".includes(text[i]!)) i++;
  };
  const readString = (): string => {
    const start = i;
    i++;
    while (text[i] !== '"') {
      if (text[i] === "\\") i++;
      i++;
    }
    i++;
    return JSON.parse(text.slice(start, i)) as string;
  };
  const value = (top: boolean, authorityMap: boolean): boolean => {
    skipSpace();
    const c = text[i];
    if (c === "{") {
      i++;
      skipSpace();
      if (text[i] === "}") {
        i++;
        return false;
      }
      const names = new Set<string>();
      for (;;) {
        skipSpace();
        const name = readString();
        if (names.has(name) && !authorityMap) return true;
        names.add(name);
        skipSpace();
        i++; // the colon
        if (value(false, top && name === "authorities")) return true;
        skipSpace();
        if (text[i++] !== ",") return false;
      }
    }
    if (c === "[") {
      i++;
      skipSpace();
      if (text[i] === "]") {
        i++;
        return false;
      }
      for (;;) {
        if (value(false, false)) return true;
        skipSpace();
        if (text[i++] !== ",") return false;
      }
    }
    if (c === '"') {
      readString();
      return false;
    }
    while (i < text.length && !",}] \t\n\r".includes(text[i]!)) i++;
    return false;
  };
  return value(true, false);
}

function load(keyList: Uint8Array | string | Record<string, unknown>, refuseRepeated: boolean): unknown {
  // A parsed object has already dropped the other copies of a repeated member,
  // so where repeats are refused only text or bytes are taken.
  if (refuseRepeated && typeof keyList !== "string" && !(keyList instanceof Uint8Array)) {
    throw new Error("not text");
  }
  if (typeof keyList === "string" || keyList instanceof Uint8Array) {
    // ignoreBOM keeps a byte order mark in the text, so JSON.parse refuses it as
    // the reference's serde_json::from_slice does.
    const text =
      typeof keyList === "string"
        ? keyList
        : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(keyList);
    const root = JSON.parse(text) as unknown;
    if (refuseRepeated && hasRepeatedMember(text)) throw new Error("repeated member");
    return root;
  }
  return keyList;
}

async function importEd25519(pub: Uint8Array): Promise<CryptoKey> {
  try {
    return await getSubtle().importKey("raw", bufferOf(pub), { name: "Ed25519" }, false, ["verify"]);
  } catch {
    throw new TrustChainError("malformed");
  }
}

/** The strict Ed25519 check of the list's signature over `payload`. */
async function ed25519Verifies(publicKey: CryptoKey, pub: Uint8Array, sig: Uint8Array, payload: Uint8Array): Promise<boolean> {
  // A small-order key or R, a second encoding of a point, or S >= L is
  // refused before the check the platform would otherwise accept.
  if (hasSmallOrderKeyOrR(pub, sig)) return false;
  try {
    return await getSubtle().verify({ name: "Ed25519" }, publicKey, bufferOf(sig), bufferOf(payload));
  } catch {
    return false;
  }
}

/** The version as digits without leading zeros, so "1" and "01" are one version; null when not decimal. */
function versionNumber(version: string): string | null {
  if (!/^[0-9]+$/.test(version)) return null;
  return version.replace(/^0+/, "");
}

/** The record rules under a hybrid pin, in the reference's order. */
async function checkHybridRecords(authorities: Map<string, Authority>, identityKeys: Uint8Array[]): Promise<void> {
  const seen = new Set<string>(identityKeys.map((k) => String.fromCharCode(...k)));
  for (const id of [...authorities.keys()].sort(byteOrder)) {
    const authority = authorities.get(id)!;
    const records = [...authority.active, ...authority.archived];
    const texts = new Set<string>();
    const numbers = new Set<string>();
    const algorithms = new Map<string, string>();
    for (const record of records) {
      if (!Object.prototype.hasOwnProperty.call(KEY_LENGTHS, label(record))) {
        throw new TrustChainError("key_label_unknown");
      }
      const length = KEY_LENGTHS[label(record)]!;
      const key = canonicalB64(record.publicKeyB64);
      if (key === null) throw new TrustChainError("non_canonical_encoding");
      if (key.length !== length) throw new TrustChainError("record_key_length");
      if (record.fingerprint !== "sha256:" + (await sha256Hex(key))) {
        throw new TrustChainError("fingerprint_not_of_key");
      }
      const number = versionNumber(record.version);
      if (texts.has(record.version) || (number !== null && numbers.has(number))) {
        throw new TrustChainError("version_repeated");
      }
      texts.add(record.version);
      if (number !== null) numbers.add(number);
      const keyText = String.fromCharCode(...key);
      if (seen.has(keyText)) throw new TrustChainError("key_in_two_roles");
      seen.add(keyText);
      algorithms.set(record.version, label(record));
    }
    const partners = new Set<string>();
    for (const record of records) {
      if (label(record) !== "Ed25519") {
        if (record.partner !== null) throw new TrustChainError("partner_invalid");
        continue;
      }
      if (record.partner === null) throw new TrustChainError("partner_missing");
      if (algorithms.get(record.partner) !== ML_DSA_65) throw new TrustChainError("partner_invalid");
      if (partners.has(record.partner)) throw new TrustChainError("partner_shared");
      partners.add(record.partner);
    }
  }
}

/** The hybrid check, in the reference's order. */
async function verifyHybrid(parsed: Parsed, pin: string): Promise<void> {
  const edIdentity = strictB64(parsed.identityKeyB64, 32);
  if (edIdentity === null) throw new TrustChainError("malformed");
  const publicKey = await importEd25519(edIdentity);
  if (parsed.pqcAlgorithm === null) throw new TrustChainError("pqc_identity_missing");
  if (parsed.pqcAlgorithm !== PQC_IDENTITY_ALGORITHM) throw new TrustChainError("pqc_algorithm_unsupported");
  if (parsed.pqcKeyB64 === null) throw new TrustChainError("pqc_identity_missing");
  const mlIdentity = canonicalB64(parsed.pqcKeyB64);
  if (mlIdentity === null) throw new TrustChainError("non_canonical_encoding");
  if (mlIdentity.length !== ML_DSA_87_PUBLIC_KEY_LEN) throw new TrustChainError("malformed");

  const computed = await hybridPin(edIdentity, mlIdentity);
  if (computed !== parsed.identityFingerprint || computed !== pin) {
    throw new TrustChainError("fingerprint_mismatch");
  }

  const sig = strictB64(parsed.signature, 64);
  if (sig === null) throw new TrustChainError("signature_invalid");
  const payload = canonicalizeBytes(parsed.signedView);
  if (!(await ed25519Verifies(publicKey, edIdentity, sig, payload))) {
    throw new TrustChainError("signature_invalid");
  }
  if (parsed.pqcSignature === null) throw new TrustChainError("pqc_signature_missing");
  const pqcSig = canonicalB64(parsed.pqcSignature);
  if (pqcSig === null) throw new TrustChainError("non_canonical_encoding");
  try {
    await verifyMlDsa(ML_DSA_87, mlIdentity, concat(UTF8.encode(KEY_LIST_PQC_TAG + "\x00"), payload), pqcSig);
  } catch {
    throw new TrustChainError("pqc_signature_invalid");
  }

  await checkHybridRecords(parsed.authorities, [edIdentity, mlIdentity]);
  checkAuthorityIds(parsed.authorities.keys(), computed.slice(HYBRID_PIN_PREFIX.length));
}

/** The classical check, then the authority id rules and the refusal of post-quantum identity members. */
async function verifyClassical(parsed: Parsed, pin: string): Promise<void> {
  const pub = strictB64(parsed.identityKeyB64, 32);
  if (pub === null) throw new TrustChainError("malformed");
  const publicKey = await importEd25519(pub);

  const computed = "sha256:" + (await sha256Hex(pub));
  if (computed !== parsed.identityFingerprint || computed !== pin) {
    throw new TrustChainError("fingerprint_mismatch");
  }

  const sig = strictB64(parsed.signature, 64);
  if (sig === null) throw new TrustChainError("signature_invalid");
  if (!(await ed25519Verifies(publicKey, pub, sig, canonicalizeBytes(parsed.signedView)))) {
    throw new TrustChainError("signature_invalid");
  }
  if (parsed.pqcAlgorithm !== null || parsed.pqcKeyB64 !== null) {
    throw new TrustChainError("pqc_identity_under_classical_pin");
  }
  checkAuthorityIds(parsed.authorities.keys(), null);
}

// Chains `fromKeyList` returned, so checked against their pin. Anything else
// handed to the verifier as a trust chain ends at stage 7.
const PIN_CHECKED = new WeakSet<object>();

/** True only for a chain `TrustChain.fromKeyList` returned. */
export function isPinChecked(chain: unknown): boolean {
  return typeof chain === "object" && chain !== null && PIN_CHECKED.has(chain);
}

/**
 * A key list whose signature has been verified against a pinned identity.
 *
 * Make one with `TrustChain.fromKeyList`; pass it as `VerifierPolicy.trustChain`.
 * Any other object given there was not checked against a pin, so a proof it
 * resolves ends at stage 7 (`not_anchored`), never stage 8. A chain
 * `fromKeyList` returns is frozen, and so is `TrustChain.prototype`.
 */
export class TrustChain {
  readonly pinnedIdentityFingerprint: string;
  readonly #authorities: ReadonlyMap<string, Authority>;

  private constructor(pinnedIdentityFingerprint: string, authorities: ReadonlyMap<string, Authority>) {
    this.pinnedIdentityFingerprint = pinnedIdentityFingerprint;
    this.#authorities = authorities;
  }

  /**
   * Parse a signed key list and verify it against the pinned fingerprint.
   *
   * `pinnedIdentityFingerprint` is `sha256:<hex of SHA-256 over the identity
   * public key>`, or a BYOC install's `hybrid1-sha256:` pin. Rejects with a
   * `TrustChainError` on every refusal, in the Rust reference's order.
   *
   * A `sha256:` pin: shape, then the identity key, then the fingerprint against
   * both the list's own claim and the pin, then the signature, then the
   * refusal of post-quantum identity members and the authority id rules.
   *
   * A `hybrid1-sha256:` pin: both identity keys (Ed25519 and ML-DSA-87), the
   * pin recomputed from both, both list signatures, the record, partner and
   * role rules, and the authority id rules. The list must be given as text or
   * bytes: a parsed object is refused (`load_failed`). It is also refused
   * (`load_failed`) when any object in it but the authority map
   * repeats a member name. Under a hybrid pin no record is verified yet: a
   * record whose key resolves fails at stage 8 with `algorithm_unsupported`.
   */
  static async fromKeyList(
    keyList: Uint8Array | string | Record<string, unknown>,
    pinnedIdentityFingerprint: string,
  ): Promise<TrustChain> {
    const hybrid = isHybridPin(pinnedIdentityFingerprint);
    let root: unknown;
    try {
      root = load(keyList, hybrid);
    } catch {
      throw new TrustChainError("load_failed");
    }
    const parsed = parse(root);
    if (parsed === null) throw new TrustChainError("load_failed");
    if (hybrid) await verifyHybrid(parsed, pinnedIdentityFingerprint);
    else await verifyClassical(parsed, pinnedIdentityFingerprint);

    const chain = new TrustChain(pinnedIdentityFingerprint, parsed.authorities);
    // Frozen, and the class's prototype below, so the chain's own methods
    // cannot be swapped. Code in the caller's own process that patches
    // built-ins (such as Map.prototype.get) is outside what the mark defends.
    Object.freeze(chain);
    PIN_CHECKED.add(chain);
    return chain;
  }

  /**
   * The listed `[publicKeyB64, authorityRevoked]` for a version, or null when
   * the authority or the version is not in the list. Active versions are
   * searched before archived ones, so a rotated-away version still resolves.
   */
  findKey(authorityId: string, signingKeyVersion: string): [string, boolean] | null {
    const record = this.#record(authorityId, signingKeyVersion);
    if (record === null) return null;
    return [record.publicKeyB64, this.#authorities.get(authorityId)!.revoked];
  }

  #record(authorityId: string, version: string): KeyRecord | null {
    const authority = this.#authorities.get(authorityId);
    if (authority === undefined) return null;
    for (const record of authority.active) if (record.version === version) return record;
    for (const record of authority.archived) if (record.version === version) return record;
    return null;
  }

  /**
   * The `[version, publicKeyB64]` of an Ed25519 version's ML-DSA-65 partner:
   * the record of the same authority its `pqc_partner_version` names. A
   * record's ML-DSA-65 key id is `nrx-pqc-v` followed by its version. Null
   * when there is none. Meaningful only for a chain loaded under a hybrid pin,
   * where the partner rules were applied.
   */
  hybridPartner(authorityId: string, ed25519Version: string): [string, string] | null {
    const ed = this.#record(authorityId, ed25519Version);
    if (ed === null || label(ed) !== "Ed25519" || ed.partner === null) return null;
    const partner = this.#record(authorityId, ed.partner);
    if (partner === null || partner.algorithm !== ML_DSA_65) return null;
    return [partner.version, partner.publicKeyB64];
  }

  /**
   * Refuse two lists from one identity that disagree: every record of
   * `earlier` must be in `later` under the same authority and version,
   * algorithm and decoded key, and every partner `earlier` names must be named
   * again with the same decoded key. Throws `TrustChainError`
   * (`partner_changed`) on a difference.
   */
  static comparePartners(earlier: TrustChain, later: TrustChain): void {
    for (const id of [...earlier.#authorities.keys()].sort(byteOrder)) {
      const authority = earlier.#authorities.get(id)!;
      for (const record of [...authority.active, ...authority.archived]) {
        const now = later.#record(id, record.version);
        if (
          now === null ||
          label(now) !== label(record) ||
          decodedKey(now.publicKeyB64) !== decodedKey(record.publicKeyB64)
        ) {
          throw new TrustChainError("partner_changed");
        }
        if (record.partner !== null) {
          const thenPartner = earlier.hybridPartner(id, record.version);
          const nowPartner = later.hybridPartner(id, record.version);
          if (
            thenPartner === null ||
            nowPartner === null ||
            decodedKey(thenPartner[1]) !== decodedKey(nowPartner[1])
          ) {
            throw new TrustChainError("partner_changed");
          }
        }
      }
    }
  }
}

Object.freeze(TrustChain.prototype);

/** `TrustChain.comparePartners`. */
export function comparePartners(earlier: TrustChain, later: TrustChain): void {
  TrustChain.comparePartners(earlier, later);
}
