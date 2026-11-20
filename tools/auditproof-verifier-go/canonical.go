// JSON Canonicalization Scheme (RFC 8785) — implements byte-equivalent
// canonicalization to Rust `serde_jcs`.
//
// Why inline: the Go standard library does not provide JCS; introducing a
// third-party JCS library would create supply-chain coupling between Nanorix
// AuditProof verification and an external maintainer. Cross-implementation
// byte-equivalence is the binding contract — we own this code.
//
// Reference: https://www.rfc-editor.org/rfc/rfc8785
//
// Algorithm summary:
//   1. Numbers serialize per ECMAScript Number-to-String: every number is read
//      as an IEEE 754 double and written in its shortest round-trip form.
//   2. Strings serialize per RFC 8259 §7 with the minimal escape set:
//      \" \\ \b \f \n \r \t  for control chars < 0x20, \uXXXX (lowercase hex).
//   3. Objects emit keys in lexicographic order of UTF-16 code units.
//   4. Arrays emit elements in input order.
//   5. No whitespace, no trailing commas.
//
// Forever-Standard discipline: the canonical form is the
// cryptographic-attestation contract. Any future Go-side change to this
// implementation must produce byte-identical output to the Rust verifier on
// the reference corpus, otherwise it's a P0.

package auditproof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// JCSCanonicalize accepts a JSON document as bytes and returns the RFC 8785
// canonical-form bytes. Cross-impl byte-equivalent with Rust `serde_jcs`.
func JCSCanonicalize(input []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("JCS: decode input: %w", err)
	}
	var buf bytes.Buffer
	if err := jcsEmit(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func jcsEmit(buf *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case json.Number:
		return jcsEmitNumber(buf, x.String())
	case float64:
		// Falls through if caller bypasses UseNumber(). Convert to canonical
		// number form via strconv.
		return jcsEmitNumber(buf, strconv.FormatFloat(x, 'g', -1, 64))
	case string:
		return jcsEmitString(buf, x)
	case []interface{}:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := jcsEmit(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]interface{}:
		// RFC 8785 §3.2.3: keys ordered by UTF-16 code unit lexicographic order.
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortKeysUTF16(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := jcsEmitString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := jcsEmit(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("JCS: unsupported type %T", v)
	}
}

// jcsEmitNumber emits a JSON number per RFC 8785 §3.2.2.3 (ECMAScript
// Number-to-String). Every number is read as an IEEE 754 double, as serde_jcs
// does with integers too, so an integer beyond 2^53 is written rounded to the
// nearest double. Integers within 2^53 are exact doubles and are written as
// integer literals directly.
func jcsEmitNumber(buf *bytes.Buffer, raw string) error {
	const maxExactInt = 1 << 53
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil && -maxExactInt <= i && i <= maxExactInt {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fmt.Errorf("JCS: invalid number %q: %w", raw, err)
	}
	if f != f { // NaN
		return fmt.Errorf("JCS: NaN not allowed by RFC 8785")
	}
	if math.IsInf(f, 0) {
		return fmt.Errorf("JCS: infinite number not allowed by RFC 8785")
	}
	if f == 0 {
		// -0.0 normalizes to "0" per RFC 8785.
		buf.WriteString("0")
		return nil
	}
	buf.WriteString(es6FloatToString(f))
	return nil
}

// es6FloatToString renders a finite, non-zero float64 exactly as ECMAScript
// Number::toString (ECMA-262 §6.1.6.1.20) does, which is what RFC 8785
// §3.2.2.3 requires. Go's 'g' format is NOT equivalent: it uses exponential
// notation from a different threshold (|x| < 1e-4 rather than < 1e-6), zero-
// pads the exponent to two digits ("1e-07"), and — with the sign stripped —
// omits the mandatory '+' on positive exponents ("1e21"). All three diverge
// from ECMAScript, e.g. String(1e21) === "1e+21", String(1e-7) === "1e-7",
// String(1e-5) === "0.00001".
//
// The shortest round-tripping digit sequence and its decimal exponent are
// taken from strconv (format 'e', precision -1); the ES6 positional-vs-
// exponential rules are then applied to those digits.
func es6FloatToString(f float64) string {
	neg := f < 0
	if neg {
		f = -f
	}
	// e.g. "1.5e+19", "5e-324", "1e+21"; always one digit before the point.
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	ePos := strings.IndexByte(sci, 'e')
	exp, _ := strconv.Atoi(sci[ePos+1:])
	digits := strings.Replace(sci[:ePos], ".", "", 1) // significant digits only
	k := len(digits)
	n := exp + 1 // position of the decimal point relative to the first digit

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		expStr := strconv.Itoa(e) // Itoa keeps the leading '-' for negatives
		if e >= 0 {
			expStr = "+" + expStr
		}
		if k == 1 {
			out = digits + "e" + expStr
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + expStr
		}
	}
	if neg {
		out = "-" + out
	}
	return out
}

// jcsEmitString emits a JSON string per RFC 8785 §3.2.2.2 with minimal
// escaping. Cross-impl byte-equivalent with serde_json's default string
// emission as used by serde_jcs.
func jcsEmitString(buf *bytes.Buffer, s string) error {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				// RFC 8785 §3.2.2.2: every character outside the escape set
				// is emitted literally as UTF-8 — including astral-plane
				// code points (U+10000+). Escaping those as \uXXXX surrogate
				// pairs diverged from Rust serde_jcs and the Python SDK and
				// broke cross-implementation byte-equivalence.
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// sortKeysUTF16 sorts string keys by UTF-16 code-unit value per RFC 8785 §3.2.3.
// For ASCII-only keys this is identical to sort.Strings; the distinction
// matters only when keys contain code points >= U+10000 (surrogate pairs).
func sortKeysUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		ai := utf16.Encode([]rune(keys[i]))
		aj := utf16.Encode([]rune(keys[j]))
		n := len(ai)
		if len(aj) < n {
			n = len(aj)
		}
		for k := 0; k < n; k++ {
			if ai[k] != aj[k] {
				return ai[k] < aj[k]
			}
		}
		return len(ai) < len(aj)
	})
}
