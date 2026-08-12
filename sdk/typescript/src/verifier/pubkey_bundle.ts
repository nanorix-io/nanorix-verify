/**
 * Portable Pubkey Bundle (.ppb.json) — Wave B Item 8 surface, TypeScript port.
 *
 * Pure TypeScript port of the Rust verifiersrc/pubkey_bundle.rs`.
 * Cross-impl byte-equivalence with Rust/Go/Python on the canonical reference
 * vectors.
 *
 * Per feedback_open_verifier_bounded_manifest.md: the bundle algorithm is open
 * + portable; the trust root (publisher pubkey) is bounded out-of-band.
 *
 * Forever-Standard discipline: bundles are append-only — key rotation = new
 * bundle generation. Old AuditProofs signed under rotated keys must remain
 * verifiable in perpetuity (healthcare 7-30 year retention).
 */

import { canonicalizeBytes } from "../_jcs.js";

/** Mandatory disclaimer — factual language only. */
export const PORTABLE_PUBKEY_BUNDLE_DISCLAIMER =
  "This Portable Pubkey Bundle is a key-discovery aid for cross-org chain verification. " +
  "The bundle_signature confirms publisher integrity. The bundle issuer attests that the listed pubkeys were valid as of generated_at; " +
  "subsequent key rotation or revocation MUST be verified out-of-band by the consuming party.";

/** Single pubkey entry within a Portable Pubkey Bundle. */
export interface PubKeyEntry {
  key_id: string;
  algorithm: string;
  public_key: string;
  valid_from: string;
  valid_until?: string | null;
  issued_by_org: string;
}

/** Bundle self-signature attestation. */
export interface BundleSignature {
  algorithm: string;
  signed_by_key_id: string;
  signature: string;
}

/** Wave B Item 8 wire shape. */
export interface PortablePubkeyBundle {
  bundle_version: string;
  bundle_type: string;
  generated_at: string;
  issuer_organization: string;
  pubkeys: PubKeyEntry[];
  bundle_signature: BundleSignature;
  disclaimer: string;
}

export type PubkeyBundleErrorKind =
  | "unsupported_version"
  | "wrong_bundle_type"
  | "bundle_signature_failed"
  | "invalid_publisher_key"
  | "base64_decode"
  | "canonicalization"
  | "invalid_entry"
  | "empty_bundle";

export class PubkeyBundleError extends Error {
  readonly kind: PubkeyBundleErrorKind;
  readonly reason: string;
  constructor(kind: PubkeyBundleErrorKind, reason = "") {
    super(reason ? `[${kind}] ${reason}` : kind);
    this.name = "PubkeyBundleError";
    this.kind = kind;
    this.reason = reason;
  }
}

function stripBase64Prefix(s: string): string {
  return s.startsWith("base64:") ? s.slice("base64:".length) : s;
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

function base64Encode(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function nowIso8601(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function getSubtle(): SubtleCrypto {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (g.crypto?.subtle) return g.crypto.subtle as SubtleCrypto;
  throw new Error("Web Crypto SubtleCrypto not available");
}

function validateEntry(entry: PubKeyEntry, idx: number): void {
  if (entry.algorithm !== "Ed25519") {
    throw new PubkeyBundleError(
      "invalid_entry",
      `idx ${idx}: unsupported algorithm ${entry.algorithm}`,
    );
  }
  let pubBytes: Uint8Array;
  try {
    pubBytes = base64Decode(entry.public_key);
  } catch (e) {
    throw new PubkeyBundleError(
      "invalid_entry",
      `idx ${idx}: base64 decode: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (pubBytes.length !== 32) {
    throw new PubkeyBundleError(
      "invalid_entry",
      `idx ${idx}: public_key wrong size ${pubBytes.length}`,
    );
  }
  if (!entry.key_id || !entry.key_id.trim()) {
    throw new PubkeyBundleError("invalid_entry", `idx ${idx}: key_id empty`);
  }
}

function bundleToDict(bundle: PortablePubkeyBundle): Record<string, unknown> {
  return {
    bundle_version: bundle.bundle_version,
    bundle_type: bundle.bundle_type,
    generated_at: bundle.generated_at,
    issuer_organization: bundle.issuer_organization,
    pubkeys: bundle.pubkeys.map((p) => {
      const out: Record<string, unknown> = {
        key_id: p.key_id,
        algorithm: p.algorithm,
        public_key: p.public_key,
        valid_from: p.valid_from,
        issued_by_org: p.issued_by_org,
      };
      if (p.valid_until !== undefined && p.valid_until !== null) {
        out.valid_until = p.valid_until;
      }
      return out;
    }),
    bundle_signature: {
      algorithm: bundle.bundle_signature.algorithm,
      signed_by_key_id: bundle.bundle_signature.signed_by_key_id,
      signature: bundle.bundle_signature.signature,
    },
    disclaimer: bundle.disclaimer,
  };
}

function canonicalBytesForSigning(bundle: PortablePubkeyBundle): Uint8Array {
  const doc = bundleToDict(bundle);
  (doc.bundle_signature as Record<string, unknown>).signature = "";
  try {
    return canonicalizeBytes(doc);
  } catch (e) {
    throw new PubkeyBundleError(
      "canonicalization",
      e instanceof Error ? e.message : String(e),
    );
  }
}

/**
 * Construct and sign a Portable Pubkey Bundle.
 *
 * @param keys Pubkey entries to include.
 * @param signerKey Raw 32-byte Ed25519 seed OR a CryptoKey of type "private".
 * @param signerKeyId Authority key identifier of the publisher.
 * @param issuerOrganization Opaque issuer organization tag.
 */
export async function buildPubkeyBundle(
  keys: readonly PubKeyEntry[],
  signerKey: Uint8Array | CryptoKey,
  signerKeyId: string,
  issuerOrganization: string,
): Promise<PortablePubkeyBundle> {
  if (keys.length === 0) {
    throw new PubkeyBundleError("empty_bundle");
  }
  for (let i = 0; i < keys.length; i++) {
    validateEntry(keys[i], i);
  }

  const bundle: PortablePubkeyBundle = {
    bundle_version: "1.0",
    bundle_type: "pubkey",
    generated_at: nowIso8601(),
    issuer_organization: issuerOrganization,
    pubkeys: keys.map((k) => ({ ...k })),
    bundle_signature: {
      algorithm: "Ed25519",
      signed_by_key_id: signerKeyId,
      signature: "",
    },
    disclaimer: PORTABLE_PUBKEY_BUNDLE_DISCLAIMER,
  };

  const subtle = getSubtle();
  const canonical = canonicalBytesForSigning(bundle);

  let cryptoKey: CryptoKey;
  if (signerKey instanceof Uint8Array) {
    if (signerKey.length !== 32) {
      throw new PubkeyBundleError(
        "invalid_publisher_key",
        `signer seed must be 32 bytes, got ${signerKey.length}`,
      );
    }
    // PKCS#8 wrapper for 32-byte Ed25519 raw seed.
    const pkcs8Header = new Uint8Array([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    const pkcs8 = new Uint8Array(pkcs8Header.length + 32);
    pkcs8.set(pkcs8Header, 0);
    pkcs8.set(signerKey, pkcs8Header.length);
    try {
      cryptoKey = await subtle.importKey(
        "pkcs8",
        pkcs8.buffer as ArrayBuffer,
        { name: "Ed25519" },
        false,
        ["sign"],
      );
    } catch (e) {
      throw new PubkeyBundleError(
        "invalid_publisher_key",
        `failed to import signer key: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  } else {
    cryptoKey = signerKey;
  }

  const sigBuf = await subtle.sign(
    { name: "Ed25519" },
    cryptoKey,
    canonical.buffer as ArrayBuffer,
  );
  bundle.bundle_signature.signature = base64Encode(new Uint8Array(sigBuf));
  return bundle;
}

/**
 * Verify a Portable Pubkey Bundle's publisher signature.
 *
 * @param bundle The bundle to verify.
 * @param publisherPubkey Raw 32-byte Ed25519 public key (trust-anchor; MUST be
 *                        delivered out-of-band).
 */
export async function verifyPubkeyBundle(
  bundle: PortablePubkeyBundle,
  publisherPubkey: Uint8Array,
): Promise<void> {
  if (bundle.bundle_version !== "1.0") {
    throw new PubkeyBundleError("unsupported_version", bundle.bundle_version);
  }
  if (bundle.bundle_type !== "pubkey") {
    throw new PubkeyBundleError("wrong_bundle_type", bundle.bundle_type);
  }
  if (bundle.pubkeys.length === 0) {
    throw new PubkeyBundleError("empty_bundle");
  }
  for (let i = 0; i < bundle.pubkeys.length; i++) {
    validateEntry(bundle.pubkeys[i], i);
  }
  if (publisherPubkey.length !== 32) {
    throw new PubkeyBundleError(
      "invalid_publisher_key",
      `pubkey wrong size: ${publisherPubkey.length}`,
    );
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64Decode(bundle.bundle_signature.signature);
  } catch (e) {
    throw new PubkeyBundleError(
      "base64_decode",
      `bundle_signature.signature: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (sigBytes.length !== 64) {
    throw new PubkeyBundleError(
      "bundle_signature_failed",
      `signature wrong size: ${sigBytes.length}`,
    );
  }

  const canonical = canonicalBytesForSigning(bundle);

  const subtle = getSubtle();
  let pubKey: CryptoKey;
  try {
    pubKey = await subtle.importKey(
      "raw",
      publisherPubkey.buffer as ArrayBuffer,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (e) {
    throw new PubkeyBundleError(
      "invalid_publisher_key",
      `could not import publisher pubkey: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  let ok: boolean;
  try {
    ok = await subtle.verify(
      { name: "Ed25519" },
      pubKey,
      sigBytes.buffer as ArrayBuffer,
      canonical.buffer as ArrayBuffer,
    );
  } catch (e) {
    throw new PubkeyBundleError(
      "bundle_signature_failed",
      `Ed25519 verify error: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
  if (!ok) {
    throw new PubkeyBundleError("bundle_signature_failed");
  }
}

/**
 * Resolve a pubkey by key_id with validity-window check.
 *
 * Note: "outside validity window" does NOT mean "untrusted for historical
 * verification". Use `resolveParentKeyForever` for historical AuditProofs.
 */
export function resolveParentKey(
  bundle: PortablePubkeyBundle,
  keyId: string,
  atTimestamp: Date,
): PubKeyEntry | null {
  for (const entry of bundle.pubkeys) {
    if (entry.key_id !== keyId) continue;
    const validFrom = new Date(entry.valid_from);
    if (isNaN(validFrom.getTime())) continue;
    if (atTimestamp < validFrom) continue;
    if (entry.valid_until !== undefined && entry.valid_until !== null) {
      const validUntil = new Date(entry.valid_until);
      if (isNaN(validUntil.getTime())) continue;
      if (atTimestamp > validUntil) continue;
    }
    return entry;
  }
  return null;
}

/**
 * Resolve a pubkey by key_id regardless of validity window.
 *
 * Used for historical AuditProof verification (forever-archive).
 */
export function resolveParentKeyForever(
  bundle: PortablePubkeyBundle,
  keyId: string,
): PubKeyEntry | null {
  return bundle.pubkeys.find((e) => e.key_id === keyId) ?? null;
}
