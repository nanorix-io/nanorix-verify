package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	auditproof "github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go"
)

// fixtureSigningSeed signs the corpus's 01_single_capsule_success fixtures
// (FIXTURE_SIGNING_SEED in tools/nanorix-verify/fixtures/generator.rs).
var fixtureSigningSeed = []byte{
	0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
	0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
}

// fixtureWithout is the corpus's first signed 2.1 proof with field removed,
// re-signed over its canonical view with the fixture key.
func fixtureWithout(t *testing.T, field string) []byte {
	t.Helper()
	raw, err := os.ReadFile(corpusRoot + "/01_single_capsule_success/0000_v2_1_signed.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var proof map[string]interface{}
	if err := dec.Decode(&proof); err != nil {
		t.Fatal(err)
	}
	delete(proof, field)
	signer := ed25519.NewKeyFromSeed(fixtureSigningSeed)
	att := proof["attestation"].(map[string]interface{})
	if att["public_key"] != "base64:"+base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)) {
		t.Fatal("the fixture is not signed with the fixture key")
	}
	message := auditproof.RecomputeCanonicalHash(proof)
	att["signature"] = "base64:" + base64.StdEncoding.EncodeToString(ed25519.Sign(signer, []byte(message)))
	out, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func signerOutput(t *testing.T, proof []byte) (auditproof.AuditProofVerificationResult, string, map[string]interface{}) {
	t.Helper()
	r := auditproof.Verify(proof, auditproof.VerifierPolicy{})
	if !r.Valid || r.StageReached != 7 {
		t.Fatalf("stage %d valid %v (%+v), want a valid stage 7", r.StageReached, r.Valid, r.FailureReason)
	}
	var out bytes.Buffer
	printSigner(&out, r, proof, nil)
	wire, err := json.Marshal(r.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(wire, &metadata); err != nil {
		t.Fatal(err)
	}
	return r, out.String(), metadata
}

// An absent authority_id prints the default as a default and says the
// signature covers its absence; the JSON carries no authority_id.
func TestAbsentAuthorityIDPrintsTheDefaultAsADefault(t *testing.T) {
	_, text, metadata := signerOutput(t, fixtureWithout(t, "authority_id"))
	const want = "  Signer: authority us-kms-nanorix-v1 (default: absent from the proof; the signature covers its absence), key version 1 (covered by the signature)\n"
	if !strings.HasPrefix(text, want) {
		t.Errorf("got %q\nwant prefix %q", text, want)
	}
	if _, ok := metadata["authority_id"]; ok {
		t.Errorf("authority_id is in the JSON: %v", metadata)
	}
	if metadata["authority_signed"] != true || metadata["signing_mode"] != "nanorix_only" {
		t.Errorf("metadata %v", metadata)
	}
}

// An absent signing_mode prints the default as a default; the JSON carries no
// signing_mode.
func TestAbsentSigningModePrintsTheDefaultAsADefault(t *testing.T) {
	_, text, metadata := signerOutput(t, fixtureWithout(t, "signing_mode"))
	const want = "  Signing mode: nanorix_only (default: absent from the proof; the signature covers its absence)\n"
	if !strings.Contains(text, want) {
		t.Errorf("got %q\nwant a line %q", text, want)
	}
	if _, ok := metadata["signing_mode"]; ok {
		t.Errorf("signing_mode is in the JSON: %v", metadata)
	}
	if metadata["authority_signed"] != true || metadata["authority_id"] != "us-kms-nanorix-v1" {
		t.Errorf("metadata %v", metadata)
	}
}
