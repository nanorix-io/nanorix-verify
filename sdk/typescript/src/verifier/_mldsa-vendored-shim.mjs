/**
 * Stands in for `@noble/post-quantum/ml-dsa.js` when the run-from-source
 * resolver (`ts-resolve-hook.mjs`) cannot find that package, so the offline
 * verifier runs from a checkout with nothing installed.
 *
 * The bytes are `auditor-portal/ml-dsa.js`, the noble 0.7.1 ML-DSA backend the
 * browser verifiers ship. They are checked against `VENDORED_MLDSA_SHA256`
 * before they run, and run in a fresh vm context so the global they define
 * stays out of this realm. A missing file, a changed byte or a load failure
 * throws at import: a load error, never a verdict.
 *
 * Only `ml_dsa65` and `ml_dsa87` with `lengths.publicKey` and
 * `verify(signature, message, publicKey, { context })` are exported, the members
 * `_mldsa.ts` uses. The vendored backend verifies with an empty context, so any
 * other context is refused, and so is any option other than `context`.
 *
 * Development tooling only. Nothing in the published npm package loads it; the
 * public verifier bundle ships it together with `auditor-portal/ml-dsa.js`.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

/** sha256 of auditor-portal/ml-dsa.js, the whole file (its fifth-script text plus a newline). */
export const VENDORED_MLDSA_SHA256 = "b26417ae93049a83500232b9b5114fa6309fedcb3f50d364bbc76aafb99e1bb9";

/** Checks `source` against the pin, runs it, and returns the backend it defines. */
export function loadVendoredMlDsa(source) {
  const digest = createHash("sha256").update(source).digest("hex");
  if (digest !== VENDORED_MLDSA_SHA256) {
    throw new Error(`auditor-portal/ml-dsa.js does not match its pinned sha256 (got ${digest})`);
  }
  const context = vm.createContext({});
  vm.runInContext(source.toString("utf8"), context, { filename: "auditor-portal/ml-dsa.js" });
  const backend = context.NanorixMlDsaBackend;
  if (backend === undefined || backend === null) {
    throw new Error("auditor-portal/ml-dsa.js did not define NanorixMlDsaBackend");
  }
  const wrap = (set) => {
    const impl = backend[set];
    if (impl === undefined || typeof impl.verify !== "function") {
      throw new Error(`the vendored ML-DSA backend has no ${set}`);
    }
    return Object.freeze({
      lengths: Object.freeze({ publicKey: impl.publicKeyLength, signature: impl.signatureLength }),
      verify(signature, message, publicKey, opts) {
        if (opts !== undefined && opts !== null) {
          for (const key of Object.keys(opts)) {
            if (key !== "context") throw new TypeError(`the vendored ML-DSA backend does not support the option "${key}"`);
          }
        }
        const context = opts?.context;
        if (context !== undefined && !(context instanceof Uint8Array && context.length === 0)) {
          throw new TypeError("the vendored ML-DSA backend verifies with an empty context only");
        }
        return impl.verify(signature, message, publicKey);
      },
    });
  };
  return { ml_dsa65: wrap("ML-DSA-65"), ml_dsa87: wrap("ML-DSA-87") };
}

const VENDORED_PATH = new URL("../../../../auditor-portal/ml-dsa.js", import.meta.url);

export const { ml_dsa65, ml_dsa87 } = loadVendoredMlDsa(readFileSync(VENDORED_PATH));
