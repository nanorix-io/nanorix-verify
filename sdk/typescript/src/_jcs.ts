/**
 * JCS (RFC 8785) canonical JSON serialization — pure TypeScript, no external deps.
 *
 * Implements the JSON Canonicalization Scheme as defined in RFC 8785:
 *   https://www.rfc-editor.org/rfc/rfc8785
 *
 * The output is a UTF-8 encoded string where:
 *   - Object keys are sorted lexicographically (Unicode code-point order)
 *   - No insignificant whitespace
 *   - Numbers serialized in ES2019 numeric format (native JSON.stringify)
 *   - Strings: only the six mandatory escapes (\b \f \n \r \t) plus
 *     \uXXXX for code points U+0000–U+001F and the surrogate range
 *
 * Used by SDK verifier helpers for AuditProof canonical hash computation.
 * Cross-impl byte-equivalence with Rust serde_jcs and Python _jcs.py.
 *
 * Limitations (by design — matches serde_jcs + fixture scope):
 *   - NaN and Infinity are not valid JSON values; throw RangeError if encountered.
 *   - TypeScript types accepted: string, number, boolean, null, object, array.
 */

/** RFC 8785 canonicalized JSON as a string (UTF-8 safe via TextEncoder). */
export function canonicalize(value: unknown): string {
  return serializeValue(value);
}

/** Return a Uint8Array of the RFC 8785 canonical form. */
export function canonicalizeBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

// ─── Internal helpers ───────────────────────────────────────────────────────

function serializeValue(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "string") return serializeString(value);
  if (Array.isArray(value)) return serializeArray(value);
  if (typeof value === "object")
    return serializeObject(value as Record<string, unknown>);
  throw new TypeError(
    `JCS: value of type "${typeof value}" is not JSON serializable`,
  );
}

function serializeNumber(v: number): string {
  if (Number.isNaN(v))
    throw new RangeError("JCS: NaN is not a valid JSON value");
  if (!Number.isFinite(v))
    throw new RangeError("JCS: Infinity is not a valid JSON value");
  // JSON.stringify produces ES2019 Number::toString compatible output for finite numbers.
  return JSON.stringify(v);
}

function serializeString(s: string): string {
  // RFC 8785 §3.2.2.2: only the 6 mandatory escapes + \uXXXX for U+0000–U+001F
  // and surrogates. No \/ escaping.
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (s[i] === '"') {
      out += '\\"';
    } else if (s[i] === "\\") {
      out += "\\\\";
    } else if (s[i] === "\b") {
      out += "\\b";
    } else if (s[i] === "\f") {
      out += "\\f";
    } else if (s[i] === "\n") {
      out += "\\n";
    } else if (s[i] === "\r") {
      out += "\\r";
    } else if (s[i] === "\t") {
      out += "\\t";
    } else if (cp >= 0x0000 && cp <= 0x001f) {
      out += "\\u" + cp.toString(16).padStart(4, "0");
    } else if (cp >= 0xd800 && cp <= 0xdfff) {
      // Surrogate — must escape per RFC 8785 §3.2.2.2
      out += "\\u" + cp.toString(16).padStart(4, "0");
    } else {
      out += s[i];
    }
  }
  out += '"';
  return out;
}

function serializeArray(arr: unknown[]): string {
  if (arr.length === 0) return "[]";
  return "[" + arr.map((item) => serializeValue(item)).join(",") + "]";
}

function serializeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  if (keys.length === 0) return "{}";
  const parts = keys.map(
    (k) => serializeString(k) + ":" + serializeValue(obj[k]),
  );
  return "{" + parts.join(",") + "}";
}
