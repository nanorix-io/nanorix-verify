// Cross-implementation fixture-corpus sweep — the Go peer of
// `tools/nanorix-verify/tests/corpus_sweep.rs`.
//
// The corpus at `tools/nanorix-verify/fixtures/corpus/` is the public
// byte-equivalence artifact: it is what a skeptic runs first, and it is the
// oracle both verifiers are held to. Every fixture must produce the same
// `valid` / `stage_reached` / `failure_reason` in Go as the committed verdict
// the Rust verifier produces, under the policy the fixture itself declares.
//
// A divergence here is a P0 finding per the module contract in `go.mod`.

package auditproof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// corpusRoot is the committed corpus, reached relative to this module.
const corpusRoot = "../nanorix-verify/fixtures/corpus"

// collectFixtures returns every corpus `*.json` that is a fixture — not an
// expected-verdict sibling, not the index manifest — sorted for determinism.
func collectFixtures(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		if !strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".expected.json") ||
			name == "index.json" {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk corpus %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

func readCorpusJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v map[string]interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return v
}

// policyFromExpected builds the policy a fixture declares it needs. A
// region_mismatch / authority_id_mismatch verdict is only reachable under the
// matching pin, so the pin travels with the fixture rather than living in this
// harness where the other language implementations cannot see it. Mirrors
// `corpus_sweep.rs::policy_from_expected`.
func policyFromExpected(expected map[string]interface{}) VerifierPolicy {
	pin := func(key string) string {
		p, ok := expected["policy"].(map[string]interface{})
		if !ok {
			return ""
		}
		s, _ := p[key].(string)
		return s
	}
	return VerifierPolicy{
		RequiredRegion:      pin("required_region"),
		RequiredAuthorityID: pin("required_authority_id"),
	}
}

// failureReasonAsValue renders a Go FailureReason through its wire marshaller
// and back into a generic value, so it can be compared against the committed
// JSON the same way `corpus_sweep.rs` compares `serde_json::Value`s.
func failureReasonAsValue(t *testing.T, r *FailureReason) interface{} {
	t.Helper()
	if r == nil {
		return nil
	}
	raw, err := r.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal failure reason: %v", err)
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("re-parse failure reason %s: %v", raw, err)
	}
	return v
}

// TestEveryCorpusFixtureVerifiesToItsCommittedVerdict is the binding
// cross-implementation contract: full agreement with the Rust-authored
// expected verdicts.
func TestEveryCorpusFixtureVerifiesToItsCommittedVerdict(t *testing.T) {
	fixtures := collectFixtures(t, corpusRoot)
	if len(fixtures) == 0 {
		t.Fatalf("corpus at %s is empty — the sweep would vacuously pass", corpusRoot)
	}

	var divergences []string
	agreed := 0

	for _, fixture := range fixtures {
		rel, _ := filepath.Rel(corpusRoot, fixture)
		expectedPath := strings.TrimSuffix(fixture, ".json") + ".expected.json"
		if _, err := os.Stat(expectedPath); err != nil {
			t.Fatalf("fixture %s has no .expected.json sibling", rel)
		}

		raw, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		expected := readCorpusJSON(t, expectedPath)
		result := Verify(raw, policyFromExpected(expected))

		fixtureDiverged := false

		wantValid, _ := expected["valid"].(bool)
		if result.Valid != wantValid {
			divergences = append(divergences,
				rel+": valid — expected "+boolStr(wantValid)+", got "+boolStr(result.Valid))
			fixtureDiverged = true
		}

		wantStage, _ := expected["stage_reached"].(float64)
		if float64(result.StageReached) != wantStage {
			divergences = append(divergences,
				rel+": stage_reached — expected "+numStr(wantStage)+", got "+numStr(float64(result.StageReached)))
			fixtureDiverged = true
		}

		gotReason := failureReasonAsValue(t, result.FailureReason)
		wantReason := expected["failure_reason"]
		if !reflect.DeepEqual(gotReason, wantReason) {
			divergences = append(divergences,
				rel+": failure_reason — expected "+jsonStr(wantReason)+", got "+jsonStr(gotReason))
			fixtureDiverged = true
		}

		if !fixtureDiverged {
			agreed++
		}
	}

	t.Logf("corpus agreement: %d/%d fixtures", agreed, len(fixtures))

	if len(divergences) > 0 {
		t.Fatalf("Cross-impl byte-equivalence FAILED — %d of %d fixtures diverge from their committed verdict:\n  %s",
			len(fixtures)-agreed, len(fixtures), strings.Join(divergences, "\n  "))
	}
}

// TestForgedSignatureIsRejected is the headline security property: replacing a
// genuine signature with attacker-chosen bytes must be rejected. The chain and
// final_hash are untouched, so a verifier that stops at stage 4 accepts this.
func TestForgedSignatureIsRejected(t *testing.T) {
	fixture := filepath.Join(corpusRoot, "01_single_capsule_success", "0000_v2_1_signed.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read %s: %v", fixture, err)
	}

	genuine := Verify(raw, VerifierPolicy{})
	if !genuine.Valid || genuine.StageReached != 7 {
		t.Fatalf("baseline: genuine proof must verify at stage 7, got valid=%v stage=%d reason=%+v",
			genuine.Valid, genuine.StageReached, genuine.FailureReason)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	att, ok := doc["attestation"].(map[string]interface{})
	if !ok {
		t.Fatalf("fixture has no attestation object to forge")
	}
	// 64 zero bytes, base64 — a well-formed but attacker-chosen signature.
	att["signature"] = "base64:" + strings.Repeat("A", 86) + "=="

	forged, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-marshal forged doc: %v", err)
	}
	result := Verify(forged, VerifierPolicy{})

	if result.Valid {
		t.Fatalf("FORGED SIGNATURE ACCEPTED — verifier returned valid=true at stage %d", result.StageReached)
	}
	if result.FailureReason == nil || result.FailureReason.Type != ReasonSignatureMismatch {
		t.Fatalf("forged signature must fail with signature_mismatch, got %+v", result.FailureReason)
	}
	if result.StageReached != 7 {
		t.Errorf("forged signature should be caught at stage 7, got %d", result.StageReached)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func numStr(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func jsonStr(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
