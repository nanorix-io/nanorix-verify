// Shared canonical JSON vectors — the Go test that loads tests/fixtures/jcs_vectors.json.
//
// The fixture is generated from the Rust canonicalizer and loaded by this
// Go test and by a Rust test in tools/nanorix-verify, so those
// implementations are held to one output
// (RFC 8785 §3.2.2.3). Each vector goes through three Go paths: raw text to
// JCSCanonicalize (the json.Number path a proof takes), a float64 tree to
// jcsEmit (the float64 branch), and json.Marshal of that tree to JCSCanonicalize
// (the activity-root path in wave_n.go and bundle.go).
//
// A missing or empty fixture fails the test; it never skips.

package auditproof

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// jcsVectorsPath is the shared fixture, reached relative to this module.
const jcsVectorsPath = "../../tests/fixtures/jcs_vectors.json"

type jcsVector struct {
	Name               string          `json:"name"`
	Input              json.RawMessage `json:"input"`
	CanonicalBytesUTF8 string          `json:"canonical_bytes_utf8"`
	SHA512Hex          string          `json:"sha512_hex"`
}

func TestJCSSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(jcsVectorsPath)
	if err != nil {
		t.Fatalf("shared vector fixture %s is required: %v", jcsVectorsPath, err)
	}
	var vectors []jcsVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse %s: %v", jcsVectorsPath, err)
	}
	if len(vectors) == 0 {
		t.Fatalf("%s holds no vectors; the test would pass vacuously", jcsVectorsPath)
	}
	for _, v := range vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			got, err := JCSCanonicalize(v.Input)
			if err != nil {
				t.Fatalf("JCSCanonicalize: %v", err)
			}
			if string(got) != v.CanonicalBytesUTF8 {
				t.Errorf("canonical bytes\n got: %s\nwant: %s", got, v.CanonicalBytesUTF8)
			}
			sum := sha512.Sum512(got)
			if h := hex.EncodeToString(sum[:]); h != v.SHA512Hex {
				t.Errorf("sha512\n got: %s\nwant: %s", h, v.SHA512Hex)
			}

			var tree interface{}
			if err := json.Unmarshal(v.Input, &tree); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			var buf bytes.Buffer
			if err := jcsEmit(&buf, tree); err != nil {
				t.Fatalf("jcsEmit(float64 tree): %v", err)
			}
			if buf.String() != v.CanonicalBytesUTF8 {
				t.Errorf("float64 tree\n got: %s\nwant: %s", buf.String(), v.CanonicalBytesUTF8)
			}
			marshaled, err := json.Marshal(tree)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			viaMarshal, err := JCSCanonicalize(marshaled)
			if err != nil {
				t.Fatalf("JCSCanonicalize(marshaled): %v", err)
			}
			if string(viaMarshal) != v.CanonicalBytesUTF8 {
				t.Errorf("marshal path\n got: %s\nwant: %s", viaMarshal, v.CanonicalBytesUTF8)
			}
		})
	}
}
