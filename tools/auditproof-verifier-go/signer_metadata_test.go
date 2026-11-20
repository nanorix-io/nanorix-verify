package auditproof

import (
	"encoding/json"
	"os"
	"testing"
)

// metadataJSON is the result's metadata as compact JSON with its keys sorted,
// so it compares as text with the Rust verifier's metadata for the same proof
// (signer_metadata_json_matches_the_go_verifier in
// tools/nanorix-verify/tests/customer_only_output.rs holds the same literals).
func metadataJSON(t *testing.T, r AuditProofVerificationResult) string {
	t.Helper()
	wire, err := json.Marshal(r.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]interface{}
	if err := json.Unmarshal(wire, &all); err != nil {
		t.Fatal(err)
	}
	sorted, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return string(sorted)
}

func corpusProof(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../nanorix-verify/fixtures/corpus/" + path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func withoutAttestation(t *testing.T, raw []byte) []byte {
	t.Helper()
	var proof map[string]interface{}
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	delete(proof, "attestation")
	out, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSignerMetadataJSONMatchesTheRustVerifier(t *testing.T) {
	customer := corpusProof(t, "13_customer_only/0000_v2_1_customer_only_signed.json")
	for _, c := range []struct {
		name  string
		proof []byte
		stage uint8
		want  string
	}{
		{"customer_only", customer, 7,
			`{"activity_event_count":null,"algorithm":"Ed25519","authority_id":"us-customer-kms-acme-v1","authority_signed":true,"capsule_id":"cap_00000000000000000000000000000514","cdp_version":"2.1","region":"us-central1","signing_key_version":"1","signing_mode":"customer_only","step_count":8}`},
		{"legacy pair", corpusProof(t, "13_customer_only/0005_v2_1_legacy_nanorix_only_customer_authority.json"), 7,
			`{"activity_event_count":null,"algorithm":"Ed25519","authority_id":"us-customer-kms-acme-v1","authority_signed":true,"capsule_id":"cap_00000000000000000000000000000519","cdp_version":"2.1","region":"us-central1","signing_key_version":"1","signing_mode":"nanorix_only","step_count":8}`},
		{"1.0 signs final_hash only", corpusProof(t, "06_failure_authority_unknown/0014_v1_0_signed_default_authority_pin.json"), 7,
			`{"activity_event_count":null,"algorithm":"Ed25519","authority_signed":false,"capsule_id":null,"cdp_version":"1.0","region":null,"signing_key_version":null,"step_count":8}`},
		{"absent labels are absent, not the default", resignedFixture(t, func(p map[string]interface{}) {
			delete(p, "authority_id")
			delete(p, "signing_mode")
		}), 7, `{"activity_event_count":null,"algorithm":"Ed25519","authority_signed":true,"capsule_id":"cap_00000000000000000000000000000000","cdp_version":"2.1","region":"us-central1","signing_key_version":"1","step_count":8}`},
		{"no signature checked", withoutAttestation(t, customer), 4,
			`{"activity_event_count":null,"algorithm":null,"authority_id":"us-customer-kms-acme-v1","capsule_id":"cap_00000000000000000000000000000514","cdp_version":"2.1","region":null,"signing_key_version":"1","signing_mode":"customer_only","step_count":8}`},
	} {
		r := Verify(c.proof, VerifierPolicy{})
		if r.StageReached != c.stage {
			t.Fatalf("%s: stage %d, want %d (%+v)", c.name, r.StageReached, c.stage, r.FailureReason)
		}
		if got := metadataJSON(t, r); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

// A customer_only proof anchored under its customer authority's key list from
// the shared vectors (case customer_only_corpus_proof_resolves) reports the
// list it was checked against, with the fields and values the Rust verifier
// gives at stage 8 (customer_only_stage_8_json_golden in
// tools/nanorix-verify/tests/customer_only_output.rs).
func TestSignerMetadataJSONAtStage8MatchesTheRustVerifier(t *testing.T) {
	raw, err := os.ReadFile(trustChainVectorsRoot + "/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Cases []struct {
			Name    string `json:"name"`
			KeyList string `json:"key_list"`
			Pin     string `json:"pin"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	var keyList, pin string
	for _, c := range cases.Cases {
		if c.Name == "customer_only_corpus_proof_resolves" {
			keyList, pin = c.KeyList, c.Pin
		}
	}
	if keyList == "" {
		t.Fatal("the shared vectors hold no customer_only_corpus_proof_resolves")
	}
	list, err := os.ReadFile(trustChainVectorsRoot + "/" + keyList)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := LoadTrustChain(list, pin)
	if err != nil {
		t.Fatal(err)
	}
	r := Verify(corpusProof(t, "13_customer_only/0000_v2_1_customer_only_signed.json"), VerifierPolicy{TrustChain: tc})
	if !r.Valid || r.StageReached != 8 {
		t.Fatalf("stage %d valid %v (%+v), want stage 8", r.StageReached, r.Valid, r.FailureReason)
	}
	want := `{"activity_event_count":null,"algorithm":"Ed25519","authority_id":"us-customer-kms-acme-v1","authority_signed":true,"capsule_id":"cap_00000000000000000000000000000514","cdp_version":"2.1","region":"us-central1","signing_key_version":"1","signing_mode":"customer_only","step_count":8,` +
		`"trust_chain_identity_fingerprint":"` + pin + `","trust_chain_issued_at":"` + tc.IssuedAt() + `"}`
	if got := metadataJSON(t, r); got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}
