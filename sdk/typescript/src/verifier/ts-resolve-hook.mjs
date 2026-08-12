/**
 * Resolve `.js` specifiers to the `.ts` sources beside them.
 *
 * The library imports with `.js` extensions because that is what the compiled
 * ESM output needs. Running the sources directly under Node's type-stripping
 * therefore fails on every internal import. This hook retries a failed `.js`
 * resolution as `.ts`, so the corpus sweep can run against the sources with no
 * build step and no edit to the library's imports.
 *
 * Development tooling only. Nothing in the published package loads it.
 */
export async function resolve(specifier, context, next) {
  try {
    return await next(specifier, context);
  } catch (err) {
    if (typeof specifier === "string" && specifier.endsWith(".js")) {
      return next(`${specifier.slice(0, -3)}.ts`, context);
    }
    throw err;
  }
}
