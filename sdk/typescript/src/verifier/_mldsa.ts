/**
 * ML-DSA (FIPS 204) signature verification, the primitive only.
 *
 * `verifyMlDsa` checks one signature over one message with one public key,
 * for ML-DSA-65 or ML-DSA-87. It is pure ML-DSA (not HashML-DSA) with an empty
 * context string, the external `ML-DSA.Verify` of FIPS 204 Algorithm 3: the
 * same contract as `verify_ml_dsa` in `tools/nanorix-verify/src/mldsa.rs` and
 * in the Python SDK's `nanorix/verifier/_mldsa.py`.
 *
 * A success says only that the signature is valid for that key and message.
 * It says nothing about a record, a key list, a checkpoint, or whether the key
 * is anchored to any authority: the caller decides what the key and the
 * message are and what a valid signature means for them. One module under
 * `src/` imports this one: `verifier/trustChain.ts`, for the hybrid key list's
 * ML-DSA-87 signature. `tests/mldsa_vectors.test.ts` fails when any other
 * does, so wiring it into another verdict has to change that test too.
 *
 * Decoding is strict. The public key and the signature must be raw FIPS 204
 * encodings of exactly the parameter set's length, checked here before the
 * backend is called. The backend is asked to read the key as the asked set's
 * raw key, never as DER and never as another set's key. Every refusal by the
 * backend, of the key or of the signature, is a refusal here, and only a
 * verify result of exactly `true` is a success.
 *
 * The backend sits behind one seam (`MlDsaBackend`). `defaultMlDsaBackend()`
 * is `@noble/post-quantum` (pinned exactly in `package.json`), a pure
 * JavaScript implementation; Node's own ML-DSA starts at 24.6. noble is ES
 * modules only, so the SDK's `engines` admits only the Node versions whose
 * `require()` loads an ES module by default (`^20.19.0 || >=22.12.0`), and
 * the CommonJS build can load it on each of them. Changing the backend means
 * the shared-vector replay in `tests/mldsa_vectors.test.ts` must still give
 * every verdict.
 *
 * noble is imported statically. If it is missing or cannot load, importing
 * this module fails; that is a load error, never `algorithm_unsupported`,
 * which only `verifyMlDsaWith` given no backend returns. The one exception is
 * the run-from-source resolver (`ts-resolve-hook.mjs`), which serves a missing
 * package from the vendored, sha256-pinned copy.
 */

import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

/** ML-DSA-65 (FIPS 204 Table 1, security category 3). */
export const ML_DSA_65 = "ML-DSA-65";
/** ML-DSA-87 (FIPS 204 Table 1, security category 5). */
export const ML_DSA_87 = "ML-DSA-87";

/** An ML-DSA parameter set this module verifies. */
export type MlDsaParameterSet = typeof ML_DSA_65 | typeof ML_DSA_87;

/** A parameter set's raw public key and signature lengths, in bytes. */
export interface MlDsaLengths {
  readonly publicKey: number;
  readonly signature: number;
}

const LENGTHS_65: MlDsaLengths = Object.freeze({ publicKey: 1952, signature: 3309 });
const LENGTHS_87: MlDsaLengths = Object.freeze({ publicKey: 2592, signature: 4627 });

/**
 * The lengths of `parameterSet` (FIPS 204 Table 2), or `undefined` for a value
 * that is not a set this module verifies, which `verifyMlDsa` refuses as an
 * unknown set. The objects returned are frozen.
 */
export function mlDsaLengths(parameterSet: unknown): MlDsaLengths | undefined {
  if (parameterSet === ML_DSA_65) return LENGTHS_65;
  if (parameterSet === ML_DSA_87) return LENGTHS_87;
  return undefined;
}

/** `MlDsaError.kind` values. Compare a kind against these names, never a literal. */
export const UNKNOWN_PARAMETER_SET = "unknown_parameter_set";
export const ALGORITHM_UNSUPPORTED = "algorithm_unsupported";
export const PUBLIC_KEY_LENGTH = "public_key_length";
export const SIGNATURE_LENGTH = "signature_length";
export const PUBLIC_KEY_REJECTED = "public_key_rejected";
export const SIGNATURE_INVALID = "signature_invalid";

/** Why `verifyMlDsa` refused a signature. */
export type MlDsaErrorKind =
  | typeof UNKNOWN_PARAMETER_SET
  | typeof ALGORITHM_UNSUPPORTED
  | typeof PUBLIC_KEY_LENGTH
  | typeof SIGNATURE_LENGTH
  | typeof PUBLIC_KEY_REJECTED
  | typeof SIGNATURE_INVALID;

function setName(parameterSet: unknown): string {
  if (parameterSet === ML_DSA_65 || parameterSet === ML_DSA_87) return parameterSet;
  try {
    return typeof parameterSet === "string" ? JSON.stringify(parameterSet) : String(parameterSet);
  } catch {
    // An object with no usable toString still has to be refused by kind.
    return "a value with no string form";
  }
}

function messageFor(
  kind: MlDsaErrorKind,
  parameterSet: unknown,
  expected: number | undefined,
  actual: number | undefined,
): string {
  const name = setName(parameterSet);
  switch (kind) {
    case PUBLIC_KEY_LENGTH:
      return `${name} public key must be ${expected} bytes, got ${actual}`;
    case SIGNATURE_LENGTH:
      return `${name} signature must be ${expected} bytes, got ${actual}`;
    case PUBLIC_KEY_REJECTED:
      return `${name} public key was refused by the decoder`;
    case SIGNATURE_INVALID:
      return `${name} signature does not verify`;
    case ALGORITHM_UNSUPPORTED:
      return `${name} is unsupported: no ML-DSA backend is available`;
    case UNKNOWN_PARAMETER_SET:
      return `${name} is not a parameter set this verifier checks`;
  }
}

/**
 * Why `verifyMlDsa` refused a signature.
 *
 * - `unknown_parameter_set`: the set is not one this module verifies.
 * - `algorithm_unsupported`: no ML-DSA backend is available. Nothing was
 *   checked.
 * - `public_key_length`: the key is not exactly the set's raw length.
 * - `signature_length`: the signature is not exactly the set's length.
 * - `public_key_rejected`: the backend refused a key of the right length.
 * - `signature_invalid`: the signature does not verify for this key and
 *   message, or its encoding is not canonical.
 *
 * Any `MlDsaError`, whatever its kind, means the signature was not verified.
 * A verdict that requires an ML-DSA signature must treat every kind,
 * `algorithm_unsupported` included, as a failure of that verdict, never as
 * leave to skip the ML-DSA check.
 *
 * `expected` and `actual` are set only for the two length kinds. The text is
 * the Rust verifier's for the four kinds it has, and the Go verifier's,
 * adapted to this SDK, for the other two.
 */
export class MlDsaError extends Error {
  readonly kind: MlDsaErrorKind;
  readonly parameterSet: unknown;
  readonly expected: number | undefined;
  readonly actual: number | undefined;

  constructor(kind: MlDsaErrorKind, parameterSet: unknown, expected?: number, actual?: number) {
    super(messageFor(kind, parameterSet, expected, actual));
    this.name = "MlDsaError";
    this.kind = kind;
    this.parameterSet = parameterSet;
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * The library behind `verifyMlDsa`. `importPublicKey` reads `publicKey` as the
 * raw FIPS 204 key of `parameterSet` and nothing else; it throws to refuse the
 * key. `verify` checks pure ML-DSA with an empty context and returns `true`
 * only for a valid signature; any other result, or a throw, is a refusal.
 */
export interface MlDsaBackend {
  importPublicKey(parameterSet: MlDsaParameterSet, publicKey: Uint8Array): unknown;
  verify(
    parameterSet: MlDsaParameterSet,
    key: unknown,
    message: Uint8Array,
    signature: Uint8Array,
  ): boolean | Promise<boolean>;
}

const EMPTY_CONTEXT = new Uint8Array(0);

function nobleFor(parameterSet: MlDsaParameterSet): typeof ml_dsa65 {
  switch (parameterSet) {
    case ML_DSA_65:
      return ml_dsa65;
    case ML_DSA_87:
      return ml_dsa87;
  }
  throw new TypeError(`no ML-DSA implementation for ${setName(parameterSet)}`);
}

/**
 * `@noble/post-quantum`'s `ml_dsa65` and `ml_dsa87`. The key is read only as
 * the asked set's raw encoding: `importPublicKey` refuses any other length,
 * and noble's own decoder refuses a key of another set's length. Noble decodes
 * the key inside `verify`, so a key it cannot read surfaces there, as
 * `signature_invalid`.
 */
const NOBLE_BACKEND: MlDsaBackend = {
  importPublicKey(parameterSet, publicKey) {
    if (publicKey.length !== nobleFor(parameterSet).lengths.publicKey) {
      throw new RangeError(`not a ${parameterSet} public key`);
    }
    return publicKey;
  },
  verify(parameterSet, key, message, signature) {
    return nobleFor(parameterSet).verify(signature, message, key as Uint8Array, {
      context: EMPTY_CONTEXT,
    });
  },
};

/**
 * The backend `verifyMlDsa` uses: `@noble/post-quantum`. Typed to allow
 * `null`, which `verifyMlDsaWith` refuses as `algorithm_unsupported`.
 */
export function defaultMlDsaBackend(): MlDsaBackend | null {
  return NOBLE_BACKEND;
}

function bytesOf(value: unknown, what: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`ML-DSA ${what} must be a Uint8Array`);
  }
  // A copy, so the caller cannot change the bytes between the checks and the
  // backend; Buffer's own slice() would share memory.
  return new Uint8Array(value);
}

/**
 * `verifyMlDsa` with the backend given, or `null` (or `undefined`) for none. Exported for the
 * tests that hold the refusal order behind the seam; not part of the SDK's
 * public surface.
 */
export async function verifyMlDsaWith(
  backend: MlDsaBackend | null | undefined,
  parameterSet: MlDsaParameterSet,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<void> {
  const lengths = mlDsaLengths(parameterSet);
  if (lengths === undefined) {
    throw new MlDsaError(UNKNOWN_PARAMETER_SET, parameterSet);
  }
  const key = bytesOf(publicKey, "public key");
  const msg = bytesOf(message, "message");
  const sig = bytesOf(signature, "signature");
  if (backend == null) {
    throw new MlDsaError(ALGORITHM_UNSUPPORTED, parameterSet);
  }
  const { publicKey: keyLength, signature: signatureLength } = lengths;
  if (key.length !== keyLength) {
    throw new MlDsaError(PUBLIC_KEY_LENGTH, parameterSet, keyLength, key.length);
  }
  if (sig.length !== signatureLength) {
    throw new MlDsaError(SIGNATURE_LENGTH, parameterSet, signatureLength, sig.length);
  }
  let imported: unknown;
  try {
    imported = await backend.importPublicKey(parameterSet, key);
  } catch {
    throw new MlDsaError(PUBLIC_KEY_REJECTED, parameterSet);
  }
  let valid: unknown;
  try {
    valid = await backend.verify(parameterSet, imported, msg, sig);
  } catch {
    throw new MlDsaError(SIGNATURE_INVALID, parameterSet);
  }
  if (valid !== true) {
    throw new MlDsaError(SIGNATURE_INVALID, parameterSet);
  }
}

/**
 * Verifies an ML-DSA `signature` over `message` with `publicKey`, pure ML-DSA
 * with an empty context.
 *
 * Resolving means the signature is valid for this key and message under
 * `parameterSet`, and nothing more: it is a primitive check that says nothing
 * about a record, a key list, or whether the key is anchored.
 *
 * Every refusal rejects with an `MlDsaError`, checked in this order:
 * `unknown_parameter_set`; `algorithm_unsupported`; `public_key_length` then
 * `signature_length`, before the backend is called; `public_key_rejected`;
 * `signature_invalid`. A key, message or signature that is not a `Uint8Array`
 * rejects with a `TypeError`.
 */
export async function verifyMlDsa(
  parameterSet: MlDsaParameterSet,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<void> {
  return verifyMlDsaWith(defaultMlDsaBackend(), parameterSet, publicKey, message, signature);
}
