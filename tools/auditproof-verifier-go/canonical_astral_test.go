// Cross-implementation JCS astral-plane vector — byte-equivalence lock.
//
// The same vector, with the same expected canonical bytes, is pinned in the Rust and Go
// verifiers:
//   - Rust:       tools/nanorix-verify/tests/jcs_astral.rs (serde_jcs — the reference)
//   - Go:         this file
//
// Two RFC 8785 properties only astral-plane characters (U+10000+) exercise:
//   - §3.2.2.2: characters outside the escape set are emitted literally as
//     UTF-8 — 4 bytes, never a \uXXXX\uXXXX surrogate-pair escape. The Go
//     emitter used to escape them.
//   - §3.2.3: keys sort by UTF-16 code unit, not code point — the astral key
//     U+1F600 (D83D DE00) sorts BEFORE the BMP key U+FB33.

package auditproof

import (
	"encoding/hex"
	"testing"
)

// Canonical bytes of the vector, hex-encoded:
// {"a":"x😀y𝄞","controls":"\u0001\"\\","é":"latin","😀":"astral-key","דּ":"bmp-key-after-astral"}
const astralExpectedHex = "7b2261223a2278f09f988079f09d849e222c22636f6e74726f6c73223a225c75303030315c225c5c222c22c3a9223a226c6174696e222c22f09f9880223a2261737472616c2d6b6579222c22efacb3223a22626d702d6b65792d61667465722d61737472616c227d"

func TestJCSAstralPlaneLiteralUTF8AndUTF16KeyOrder(t *testing.T) {
	// Input deliberately mixes escaped and literal spellings of the same
	// astral character so the decoder path is exercised too.
	input := []byte(`{"\ud83d\ude00":"astral-key","é":"latin","\ufb33":"bmp-key-after-astral","controls":"\u0001\"\\","a":"x😀y\ud834\udd1e"}`)
	got, err := JCSCanonicalize(input)
	if err != nil {
		t.Fatalf("JCSCanonicalize: %v", err)
	}
	if hex.EncodeToString(got) != astralExpectedHex {
		t.Fatalf("canonical form diverged from serde_jcs\n got: %s\nwant: %s", got, mustHex(astralExpectedHex))
	}
}

func TestJCSAstralKeySortsBeforeHighBMPKey(t *testing.T) {
	got, err := JCSCanonicalize([]byte(`{"\ufb33":1,"\ud83d\ude00":2}`))
	if err != nil {
		t.Fatalf("JCSCanonicalize: %v", err)
	}
	// Code-point order would put U+FB33 first; RFC 8785 UTF-16 order does not.
	want := "{\"\U0001F600\":2,\"\uFB33\":1}"
	if string(got) != want {
		t.Fatalf("key order\n got: %s\nwant: %s", got, want)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
