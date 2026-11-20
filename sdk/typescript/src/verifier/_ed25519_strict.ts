/**
 * Strict Ed25519 pre-checks. WebCrypto verifies like RFC 8032 and accepts a
 * small-order public key or a small-order `R`; under such a key one signature
 * verifies for many messages. A verifier rejects those inputs before calling
 * `subtle.verify` (ed25519-dalek `verify_strict` semantics).
 */

/**
 * Every 32-byte encoding (hex) of a point whose order divides 8, including the
 * non-canonical y+p forms. Mirrors tests/vectors/ed25519_strict_negative.json.
 */
export const SMALL_ORDER_ENCODINGS: ReadonlySet<string> = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]);

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** True when the 255-bit y coordinate is >= p = 2^255-19 (a non-canonical encoding). */
export function isNonCanonicalEncoding(b: Uint8Array): boolean {
  if (b.length < 32 || (b[31]! & 0x7f) !== 0x7f || b[0]! < 0xed) return false;
  for (let i = 1; i < 31; i++) if (b[i] !== 0xff) return false;
  return true;
}

/** Group order L of the Ed25519 base point, little-endian. */
const ED25519_L_LE = new Uint8Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10]);

/** True when the signature's scalar S (bytes 32..64) is >= L. */
export function scalarAtLeastL(signature: Uint8Array): boolean {
  if (signature.length < 64) return false;
  for (let i = 31; i >= 0; i--) {
    const a = signature[32 + i]!;
    if (a !== ED25519_L_LE[i]!) return a > ED25519_L_LE[i]!;
  }
  return true;
}

/**
 * True when the public key, or the signature's `R` (first 32 bytes), is a
 * small-order or non-canonical point, or the signature's S is >= L.
 */
export function hasSmallOrderKeyOrR(publicKey: Uint8Array, signature: Uint8Array): boolean {
  const rejected = (b: Uint8Array) =>
    SMALL_ORDER_ENCODINGS.has(toHex(b.subarray(0, 32))) || isNonCanonicalEncoding(b);
  return rejected(publicKey) || rejected(signature) || scalarAtLeastL(signature);
}
