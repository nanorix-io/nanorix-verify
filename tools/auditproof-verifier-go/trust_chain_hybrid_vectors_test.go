// Hybrid key-list vectors authored by the Rust reference.
//
// `tools/nanorix-verify/fixtures/trust_chain_hybrid/cases.json` lists each
// case: a kind (key_list, record or two_lists), its files, the pin, the result
// the Rust library gives (expected) and the result a verifier without an
// ML-DSA check gives (expected_without_ml_dsa). A Go 1.27 build checks ML-DSA
// and is held to the first; an earlier build to the second.

package auditproof

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

const hybridVectorsRoot = "../nanorix-verify/fixtures/trust_chain_hybrid"

type hybridCase struct {
	Name                 string                 `json:"name"`
	Kind                 string                 `json:"kind"`
	KeyList              string                 `json:"key_list"`
	Proof                string                 `json:"proof"`
	Earlier              string                 `json:"earlier"`
	Later                string                 `json:"later"`
	Pin                  string                 `json:"pin"`
	Expected             map[string]interface{} `json:"expected"`
	ExpectedWithoutMLDSA map[string]interface{} `json:"expected_without_ml_dsa"`
	// ExpectedByVerifier holds, on a few cases, the refusal a verifier gives
	// where its kind differs from the reference's today.
	ExpectedByVerifier map[string]map[string]interface{} `json:"expected_by_verifier"`
}

func readHybridFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(hybridVectorsRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func refusalOf(t *testing.T, err error) map[string]interface{} {
	t.Helper()
	var tce *TrustChainError
	if !errors.As(err, &tce) {
		t.Fatalf("not a TrustChainError: %v", err)
	}
	return map[string]interface{}{"refusal": string(tce.Kind)}
}

func partnersOf(chain *TrustChain) map[string]interface{} {
	out := map[string]interface{}{}
	for id, a := range chain.authorities {
		m := map[string]interface{}{}
		for _, k := range append(append([]trustChainKey{}, a.active...), a.archived...) {
			if p, ok := chain.HybridPartner(id, k.version); ok {
				m[k.version] = p.Version
			}
		}
		out[id] = m
	}
	return out
}

func hybridResult(t *testing.T, c hybridCase) map[string]interface{} {
	switch c.Kind {
	case "key_list":
		chain, err := LoadTrustChain(readHybridFile(t, c.KeyList), c.Pin)
		if err != nil {
			return refusalOf(t, err)
		}
		return map[string]interface{}{"loaded": true, "partners": partnersOf(chain)}
	case "record":
		chain, err := LoadTrustChain(readHybridFile(t, c.KeyList), c.Pin)
		if err != nil {
			return refusalOf(t, err)
		}
		r := Verify(readHybridFile(t, c.Proof), VerifierPolicy{TrustChain: chain})
		var reason interface{}
		if r.FailureReason != nil {
			b, _ := json.Marshal(r.FailureReason)
			_ = json.Unmarshal(b, &reason)
		}
		return map[string]interface{}{
			"valid": r.Valid, "stage_reached": float64(r.StageReached), "status": r.Status(), "failure_reason": reason,
		}
	case "two_lists":
		earlier, err := LoadTrustChain(readHybridFile(t, c.Earlier), c.Pin)
		if err != nil {
			return refusalOf(t, err)
		}
		later, err := LoadTrustChain(readHybridFile(t, c.Later), c.Pin)
		if err != nil {
			return refusalOf(t, err)
		}
		if err := ComparePartners(earlier, later); err != nil {
			return refusalOf(t, err)
		}
		return map[string]interface{}{"same_partners": true}
	}
	t.Fatalf("unknown kind %q", c.Kind)
	return nil
}

func TestHybridKeyListVectorsMatchTheRustReference(t *testing.T) {
	var doc struct {
		Cases []hybridCase `json:"cases"`
	}
	if err := json.Unmarshal(readHybridFile(t, "cases.json"), &doc); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	kinds := map[string]int{}
	for _, c := range doc.Cases {
		kinds[c.Kind]++
	}
	// The floor: the set holds every kind, a hybrid list that loads, and a
	// refusal, so a regeneration that drops a kind fails here.
	if len(doc.Cases) < 50 || kinds["key_list"] == 0 || kinds["record"] == 0 || kinds["two_lists"] == 0 {
		t.Fatalf("expected the full hybrid vector set, found %d cases %v", len(doc.Cases), kinds)
	}
	for _, c := range doc.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			want := c.Expected
			if own, ok := c.ExpectedByVerifier["go"]; ok {
				want = own
			}
			if !mldsaAvailable {
				want = c.ExpectedWithoutMLDSA
			}
			if got := hybridResult(t, c); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

// A hybrid pin is refused up front by a build without ML-DSA, and never by one
// with it.
func TestHybridPinNeedsMLDSA(t *testing.T) {
	_, err := LoadTrustChain([]byte(`{}`), HybridPinPrefix+"00")
	var tce *TrustChainError
	if !errors.As(err, &tce) {
		t.Fatalf("want a TrustChainError, got %v", err)
	}
	if got := tce.Kind == TrustChainHybridCheckUnavailable; got == mldsaAvailable {
		t.Fatalf("hybrid_check_unavailable=%v with mldsaAvailable=%v", got, mldsaAvailable)
	}
}

func TestRepeatedMemberScanSkipsOnlyTheAuthorityMap(t *testing.T) {
	cases := map[string]bool{
		`{"a":1,"a":2}`:                              true,
		`{"authorities":{"x":{},"x":{}}}`:            false,
		`{"authorities":{"x":{"k":1,"k":2}}}`:        true,
		`{"b":{"authorities":{"x":1,"x":2}}}`:        true,
		`{"a":[{"v":1,"v":2}]}`:                      true,
		`{"a":"authorities","authorities":{"y":[]}}`: false,
	}
	names := make([]string, 0, len(cases))
	for k := range cases {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, in := range names {
		if got := hasRepeatedMember([]byte(in)); got != cases[in] {
			t.Errorf("%s: got %v, want %v", in, got, cases[in])
		}
	}
}
