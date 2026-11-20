/**
 * Resolve `.js` specifiers to the `.ts` sources beside them.
 *
 * The library imports with `.js` extensions because that is what the compiled
 * ESM output needs. Running the sources directly under Node's type-stripping
 * therefore fails on every internal import. This hook retries a failed `.js`
 * resolution as `.ts`, so the corpus sweep can run against the sources with no
 * build step and no edit to the library's imports.
 *
 * It also serves `@noble/post-quantum/ml-dsa.js` from the sha256-pinned copy
 * in `_mldsa-vendored-shim.mjs`, only when all of these hold: the specifier is
 * exactly that one, Node reports ERR_MODULE_NOT_FOUND for the package itself
 * ("Cannot find package '@noble/post-quantum'"), and the importer is
 * `verifier/_mldsa.ts`. An installed package is always used as it is: for that
 * specifier, an installed package whose file is missing ("Cannot find module
 * '...'"), every other error and every other importer get Node's own error,
 * never the `.js` to `.ts` retry.
 *
 * Development tooling only. Nothing in the published npm package loads it; the
 * public verifier bundle ships it.
 */
const NOBLE_MLDSA = "@noble/post-quantum/ml-dsa.js";
const SHIM_URL = new URL("./_mldsa-vendored-shim.mjs", import.meta.url).href;

export async function resolve(specifier, context, next) {
  try {
    return await next(specifier, context);
  } catch (err) {
    if (
      specifier === NOBLE_MLDSA &&
      err?.code === "ERR_MODULE_NOT_FOUND" &&
      String(err.message).includes("Cannot find package '@noble/post-quantum'") &&
      typeof context?.parentURL === "string" &&
      context.parentURL.endsWith("/verifier/_mldsa.ts")
    ) {
      return { url: SHIM_URL, shortCircuit: true };
    }
    if (specifier === NOBLE_MLDSA) {
      throw err;
    }
    if (typeof specifier === "string" && specifier.endsWith(".js")) {
      return next(`${specifier.slice(0, -3)}.ts`, context);
    }
    throw err;
  }
}
