// Stage 8 vectors authored by the Rust reference.
//
// `tools/nanorix-verify/fixtures/trust_chain/cases.json` lists every case: a
// signed key list, a proof, the pinned fingerprint, an optional required
// authority id, and the verdict or refusal the Rust library gives. This test
// replays all of them and requires the same `valid`, `stage_reached`, `status`
// and `failure_reason`, or the same refusal before any proof is read.

package auditproof

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const trustChainVectorsRoot = "../nanorix-verify/fixtures/trust_chain"

type trustChainCase struct {
	Name                string                 `json:"name"`
	KeyList             string                 `json:"key_list"`
	Proof               string                 `json:"proof"`
	Pin                 string                 `json:"pin"`
	RequiredAuthorityID *string                `json:"required_authority_id"`
	Expected            map[string]interface{} `json:"expected"`
}

func TestTrustChainVectorsMatchTheRustReference(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(trustChainVectorsRoot, "cases.json"))
	if err != nil {
		t.Fatalf("read cases.json: %v", err)
	}
	var doc struct {
		Cases []trustChainCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("expected the full vector set, found %d cases", len(doc.Cases))
	}
	pinsVerified := false
	for _, c := range doc.Cases {
		if c.Expected["status"] == "verified" {
			pinsVerified = true
		}
	}
	if !pinsVerified {
		t.Fatal("no case pins status verified")
	}

	for _, c := range doc.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			list, err := os.ReadFile(filepath.Join(trustChainVectorsRoot, c.KeyList))
			if err != nil {
				t.Fatalf("read key list: %v", err)
			}
			proof, err := os.ReadFile(filepath.Join(trustChainVectorsRoot, c.Proof))
			if err != nil {
				t.Fatalf("read proof: %v", err)
			}

			chain, loadErr := LoadTrustChain(list, c.Pin)
			if want, refused := c.Expected["refusal"]; refused {
				var tce *TrustChainError
				if !errors.As(loadErr, &tce) {
					t.Fatalf("want refusal %v, key list was accepted (err=%v)", want, loadErr)
				}
				if string(tce.Kind) != want {
					t.Fatalf("refusal: got %s, want %v", tce.Kind, want)
				}
				return
			}
			if loadErr != nil {
				t.Fatalf("key list refused: %v", loadErr)
			}

			policy := VerifierPolicy{TrustChain: chain}
			if c.RequiredAuthorityID != nil {
				policy.RequiredAuthorityID = *c.RequiredAuthorityID
			}
			result := Verify(proof, policy)

			if got, want := result.Valid, c.Expected["valid"]; got != want {
				t.Errorf("valid: got %v, want %v", got, want)
			}
			if got, want := float64(result.StageReached), c.Expected["stage_reached"]; got != want {
				t.Errorf("stage_reached: got %v, want %v", got, want)
			}
			if got, want := result.Status(), c.Expected["status"]; got != want {
				t.Errorf("status: got %v, want %v", got, want)
			}
			if got, want := result.OK(), c.Expected["status"] == "verified"; got != want {
				t.Errorf("ok: got %v, want %v", got, want)
			}
			var gotReason interface{}
			if result.FailureReason != nil {
				b, err := json.Marshal(result.FailureReason)
				if err != nil {
					t.Fatalf("marshal failure_reason: %v", err)
				}
				if err := json.Unmarshal(b, &gotReason); err != nil {
					t.Fatalf("reparse failure_reason: %v", err)
				}
			}
			if want := c.Expected["failure_reason"]; !reflect.DeepEqual(gotReason, want) {
				t.Errorf("failure_reason: got %v, want %v", gotReason, want)
			}
			// A 1.0 signature covers final_hash alone: the result names no
			// capsule and no region.
			if result.Metadata.CdpVersion != nil && *result.Metadata.CdpVersion == "1.0" {
				if result.Metadata.CapsuleID != nil || result.Metadata.Region != nil {
					t.Errorf("a 1.0 result names a capsule or region: %+v", result.Metadata)
				}
			}
		})
	}
}

// A key list that is not JSON is refused as load_failed, not as a verdict.
func TestLoadTrustChainRefusesNonJSON(t *testing.T) {
	if _, err := LoadTrustChain([]byte(`not json`), "sha256:00"); err == nil {
		t.Fatal("a non-JSON key list was accepted")
	} else {
		var tce *TrustChainError
		if !errors.As(err, &tce) || tce.Kind != TrustChainLoadFailed {
			t.Fatalf("want load_failed, got %v", err)
		}
	}
}
