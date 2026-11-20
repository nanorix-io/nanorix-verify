/**
 * JCS (RFC 8785) canonical JSON serialization — pure TypeScript, no external deps.
 *
 * Implements the JSON Canonicalization Scheme as defined in RFC 8785:
 *   https://www.rfc-editor.org/rfc/rfc8785
 *
 * The output is a UTF-8 encoded string where:
 *   - Object keys are sorted lexicographically by UTF-16 code unit (RFC 8785
 *     §3.2.3) — the default Array.prototype.sort() order, which differs from
 *     code-point order once a key contains an astral-plane character
 *   - No insignificant whitespace
 *   - Numbers serialized in ES2019 numeric format (native JSON.stringify)
 *   - Strings: only the six mandatory escapes (\b \f \n \r \t) plus
 *     \uXXXX for code points U+0000–U+001F and lone (unpaired) surrogates;
 *     astral-plane characters (U+10000+) are emitted literally as UTF-8
 *
 * Used by SDK verifier helpers for AuditProof canonical hash computation.
 * Cross-impl byte-equivalence with Rust serde_jcs and Python _jcs.py.
 *
 * Limitations (by design — matches serde_jcs + fixture scope):
 *   - NaN and Infinity are not valid JSON values; `canonicalize` throws RangeError
 *     if encountered (`canonicalizeJsonValue` with "exact" writes them as null).
 *   - A `bigint` is accepted only by `canonicalizeJsonValue`. It also calls a
 *     `BigInt.prototype.toJSON` that an application installed, as JSON.stringify does.
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
  // and lone surrogates. No \/ escaping. Astral-plane characters are literal.
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
    } else if (cp >= 0xd800 && cp <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        // Well-formed surrogate pair — an astral-plane character
        // (U+10000+). RFC 8785 §3.2.2.2: characters outside the escape
        // set are emitted literally (TextEncoder yields their UTF-8).
        // Escaping the pair as \uXXXX\uXXXX diverged from Rust
        // serde_jcs and the Python SDK and broke byte-equivalence.
        out += s[i] + s[i + 1];
        i++;
      } else {
        // Lone high surrogate — not representable in UTF-8; escape,
        // matching the Python SDK's handling of invalid input.
        out += "\\u" + cp.toString(16).padStart(4, "0");
      }
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      // Lone low surrogate — same as above.
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
  // Default sort compares UTF-16 code units — exactly RFC 8785 §3.2.3.
  const keys = Object.keys(obj).sort();
  if (keys.length === 0) return "{}";
  const parts = keys.map(
    (k) => serializeString(k) + ":" + serializeValue(obj[k]),
  );
  return "{" + parts.join(",") + "}";
}

// ─── Payload and signing paths ──────────────────────────────────────────────

/** What to do with a `bigint` outside +-2^53. */
export type BigIntMode = "exact" | "refuse";

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const LONE_SURROGATE =
  /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/**
 * RFC 8785 bytes of a value after JSON's own value mapping, for hashes and
 * signatures of data that comes from application code.
 *
 * The mapping is what `JSON.stringify` would apply: `toJSON` is called where
 * present (a `Date` becomes its ISO string), `undefined`, functions and
 * symbols are dropped from objects and written as `null` in arrays and at the
 * top, array holes are `null`, and other objects (including `Map` and `Set`,
 * which become `{}`) contribute their own enumerable string-keyed properties.
 * With `exact`, NaN and Infinity are written as `null`, as `JSON.stringify`
 * writes them, so every value that call accepted still hashes; with `refuse`
 * they throw `RangeError`.
 *
 * A `bigint` outside +-2^53 is written as its exact decimal digits with
 * `exact` (payload hashes) and throws `TypeError` with `refuse` (signed
 * events, which the server canonicalizes again and would round). With
 * `refuse`, a lone surrogate also throws `TypeError`, and so does an object
 * that is not a plain object or an array (a `Map`, a typed array, a class
 * instance, a boxed `BigInt`), whose bytes the server would not reproduce.
 */
export function canonicalizeJsonValue(value: unknown, bigint: BigIntMode): string {
  return mapped(value, "", bigint);
}

/** UTF-8 bytes of {@link canonicalizeJsonValue}. */
export function canonicalizeJsonValueBytes(value: unknown, bigint: BigIntMode): Uint8Array {
  return new TextEncoder().encode(canonicalizeJsonValue(value, bigint));
}

function checkText(s: string, bigint: BigIntMode): string {
  if (bigint === "refuse" && LONE_SURROGATE.test(s)) {
    throw new TypeError("JCS: lone surrogate in a string; a JSON parser cannot read it");
  }
  return serializeString(s);
}

function resolve(input: unknown, key: string): unknown {
  let value = input;
  if (
    value !== null &&
    (typeof value === "object" || typeof value === "bigint") &&
    typeof (value as { toJSON?: unknown }).toJSON === "function"
  ) {
    value = (value as { toJSON: (k: string) => unknown }).toJSON(key);
  }
  if (value !== null && typeof value === "object") {
    // Unwrap by internal slot, as JSON.stringify does, so a cross-realm box
    // and a subclass of Number or String are unwrapped too.
    switch (Object.prototype.toString.call(value)) {
      case "[object Number]":
        value = Number.prototype.valueOf.call(value);
        break;
      case "[object String]":
        value = String.prototype.valueOf.call(value);
        break;
      case "[object Boolean]":
        value = Boolean.prototype.valueOf.call(value);
        break;
      case "[object BigInt]":
        value = BigInt.prototype.valueOf.call(value);
        break;
    }
  }
  return value;
}

function isOmitted(value: unknown): boolean {
  return value === undefined || typeof value === "function" || typeof value === "symbol";
}

function mapped(input: unknown, key: string, bigint: BigIntMode): string {
  return write(resolve(input, key), bigint);
}

function write(value: unknown, bigint: BigIntMode): string {
  if (isOmitted(value) || value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (bigint === "exact" && !Number.isFinite(value)) return "null";
    return serializeNumber(value);
  }
  if (typeof value === "string") return checkText(value, bigint);
  if (typeof value === "bigint") {
    if (value >= -MAX_SAFE && value <= MAX_SAFE) return value.toString();
    if (bigint === "refuse") {
      throw new TypeError(
        `JCS: bigint outside +-2^53 cannot be signed exactly: ${value}; pass it as a string`,
      );
    }
    return value.toString();
  }
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      parts.push(mapped(value[i], String(i), bigint));
    }
    return "[" + parts.join(",") + "]";
  }
  if (bigint === "refuse") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError(
        "JCS: only plain objects and arrays can be signed; convert this value to JSON data first",
      );
    }
  }
  const obj = value as Record<string, unknown>;
  const parts: string[] = [];
  for (const k of Object.keys(obj).sort()) {
    const member = resolve(obj[k], k);
    if (isOmitted(member)) continue;
    parts.push(checkText(k, bigint) + ":" + write(member, bigint));
  }
  return "{" + parts.join(",") + "}";
}
