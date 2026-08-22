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
//   1. Numbers serialize per ECMAScript Number-to-String (IEEE 754 double
//      shortest-round-trip), with integer-valued doubles emitted as integers.
//   2. Strings serialize per RFC 8259 §7 with the minimal escape set:
//      \" \\ \b \f \n \r \t  for control chars < 0x20, \uXXXX (lowercase hex).
//   3. Objects emit keys in lexicographic order of UTF-16 code units.
//   4. Arrays emit elements in input order.
//   5. No whitespace, no trailing commas.
//
// Forever-Standard discipline (ADR-006 I0): the canonical form is the
// cryptographic-attestation contract. Any future Go-side change to this
// implementation must produce byte-identical output to the Rust verifier on
// the reference corpus, otherwise it's a P0.

package auditproof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
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
// Number-to-String). For integer-valued numbers within int64 range, emit as
// integer literals. For non-integer floats, emit shortest-round-trip via
// strconv.FormatFloat with the 'g' format (Go's shortest-round-trip).
func jcsEmitNumber(buf *bytes.Buffer, raw string) error {
	// Try int64 first; preserves "0", "1", "-7", etc.
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	// Try float — match ECMAScript Number-to-String shortest-round-trip.
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fmt.Errorf("JCS: invalid number %q: %w", raw, err)
	}
	if f != f { // NaN
		return fmt.Errorf("JCS: NaN not allowed by RFC 8785")
	}
	if f == 0 {
		// -0.0 normalizes to "0" per RFC 8785.
		buf.WriteString("0")
		return nil
	}
	// strconv.FormatFloat with -1 precision + 'g' produces shortest-round-trip.
	// However Go uses lowercase 'e' and ECMAScript produces signed exponents
	// without leading zeros — the 'g' format already complies.
	s := strconv.FormatFloat(f, 'g', -1, 64)
	// Strip the '+' from positive exponents (Go: "1e+20"; ECMAScript: "1e20").
	// Per RFC 8785 §3.2.2.3 the "+" sign is omitted for positive exponents.
	if idx := bytes.IndexByte([]byte(s), 'e'); idx >= 0 && idx+1 < len(s) && s[idx+1] == '+' {
		s = s[:idx+1] + s[idx+2:]
	}
	buf.WriteString(s)
	return nil
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
			} else if r < 0x10000 {
				buf.WriteRune(r)
			} else {
				// Emit surrogate pair per RFC 8785 §3.2.2.2.
				lead, trail := utf16.EncodeRune(r)
				fmt.Fprintf(buf, `\u%04x\u%04x`, lead, trail)
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
