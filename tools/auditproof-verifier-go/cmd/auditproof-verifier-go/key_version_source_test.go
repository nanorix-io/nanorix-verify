package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	auditproof "github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go"
)

const trustChainRoot = "../../../nanorix-verify/fixtures/trust_chain"

// customerCorpusProof is the shared trust-chain vector's customer_only proof
// (13_customer_only/0000) with edit applied, re-signed over its canonical
// view with the fixture key, which is the key that proof is signed with.
func customerCorpusProof(t *testing.T, edit func(proof map[string]interface{})) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(trustChainRoot, "proofs", "customer_only_corpus_0000.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var proof map[string]interface{}
	if err := dec.Decode(&proof); err != nil {
		t.Fatal(err)
	}
	edit(proof)
	signer := ed25519.NewKeyFromSeed(fixtureSigningSeed)
	att := proof["attestation"].(map[string]interface{})
	if att["public_key"] != "base64:"+base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)) {
		t.Fatal("the proof is not signed with the fixture key")
	}
	att["signature"] = "base64:" + base64.StdEncoding.EncodeToString(ed25519.Sign(signer, []byte(auditproof.RecomputeCanonicalHash(proof))))
	out, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runWithCustomerKeyList runs the command on proof under the shared customer
// key list and its pin.
func runWithCustomerKeyList(t *testing.T, proof string) (int, string, string) {
	t.Helper()
	return runCLI(t, "-trust-chain", filepath.Join(trustChainRoot, "key_lists", "customer_only_authority.json"),
		"-identity-fingerprint", "sha256:86091e73ba6e8f4d570505c632698b5e015e9663948b09f2e61e4f17b8dd13ac", proof)
}

// The stage-6 lookup reads attestation.signing_key_version first. The key
// list holds version 1 only, so a proof whose signed top-level version is 2
// and whose attestation names 1 reaches stage 8 only through the attestation
// value; the output names both, and says which one the signature covers.
func TestStage8LookupUsesTheAttestationKeyVersion(t *testing.T) {
	proof := customerCorpusProof(t, func(p map[string]interface{}) {
		p["signing_key_version"] = "2"
		p["attestation"].(map[string]interface{})["signing_key_version"] = "1"
	})
	code, stdout, stderr := runWithCustomerKeyList(t, proof)
	if code != 0 || !strings.HasPrefix(stdout, "Verified") {
		t.Fatalf("exit %d, want 0 and Verified\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"  Signing key version (attestation, not covered by the signature): 1\n",
		"  Signer: authority us-customer-kms-acme-v1, key version 2 (covered by the signature)\n",
		"  Key list resolved key version 1 (read from attestation.signing_key_version, which the signature does not cover)\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "  Signing key version: ") {
		t.Errorf("the attestation's key version is printed without its label:\n%s", stdout)
	}
}

// Without an attestation key version the metadata value is the top-level one,
// and the line keeps its plain label.
func TestTopLevelKeyVersionKeepsThePlainLabel(t *testing.T) {
	proof := customerCorpusProof(t, func(map[string]interface{}) {})
	code, stdout, stderr := runWithCustomerKeyList(t, proof)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "  Signing key version: 1\n") || strings.Contains(stdout, "(attestation, not covered") {
		t.Errorf("output:\n%s", stdout)
	}
}

// The legacy pair at stage 8 points the reader to the key-list line, which is
// printed after it.
func TestLegacyAnchoredLinePointsDownToTheKeyList(t *testing.T) {
	proof := customerCorpusProof(t, func(p map[string]interface{}) { p["signing_mode"] = "nanorix_only" })
	code, stdout, stderr := runWithCustomerKeyList(t, proof)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	const legacy = "  signing_mode predates customer_only; this proof names a customer-classified authority, and stage 8 resolved its key in the key list below, so the signer is the customer authority named above.\n"
	at := strings.Index(stdout, legacy)
	list := strings.Index(stdout, "  Key list: issued ")
	if at < 0 || list < 0 || at > list {
		t.Errorf("the legacy line must come before the key-list line it points to:\n%s", stdout)
	}
}

// An authority id holding a right-to-left override and a control character is
// shown escaped in the Signer line, the stage-7 advice and the mismatch line,
// with the same text the Rust CLI and the browser page show.
func TestAuthorityIDControlsAreEscapedAsInRustAndTheBrowser(t *testing.T) {
	covered := true
	r := auditproof.AuditProofVerificationResult{Valid: true, StageReached: 7}
	r.Metadata.AuthoritySigned = &covered
	var out bytes.Buffer
	printSigner(&out, r, []byte(`{"cdp_version":"2.1","signing_mode":"customer_only","authority_id":"us-customer-kms-\u202eacme\u0007-v1","signing_key_version":"1"}`), nil)
	for _, want := range []string{
		`  Signer: authority us-customer-kms-\u{202e}acme\u{7}-v1, key version 1 (covered by the signature)` + "\n",
		`  This proof's signed labels name a customer authority (us-customer-kms-\u{202e}acme\u{7}-v1). To anchor its key, supply the key list and identity fingerprint published for that authority.` + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	claimed := "us-kms-\u202enanorix\u0007-v1"
	got := failureLine(&auditproof.FailureReason{Type: auditproof.ReasonSigningModeAuthorityMismatch, ClaimedAuthorityID: &claimed})
	if want := `signing_mode_authority_mismatch (signing_mode: customer_only, claimed_authority_id: us-kms-\u{202e}nanorix\u{7}-v1)`; got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}
