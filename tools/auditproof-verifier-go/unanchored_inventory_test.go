// Row tests for tools/nanorix-verify/UNANCHORED_SURFACES.md (Go rows).
//
// Each test hands a surface an object correctly signed by a key nothing
// anchors: no key list, a key list given without a pin, or only the key the
// object carries. The most a surface may return is not_anchored. A test for an
// open row asserts the wanted behaviour and is skipped with the item id.

package auditproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const inventoryCustomerPin = "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f"

func inventoryFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", "nanorix-verify", "fixtures"}, parts...)...))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func TestInventoryVerifyWithoutKeyListIsNotAnchored(t *testing.T) {
	proof := inventoryFixture(t, "trust_chain", "proofs", "customer_v1.json")
	for name, r := range map[string]AuditProofVerificationResult{
		"Verify":                    Verify(proof, VerifierPolicy{}),
		"VerifyFullAuditProofWaveN": VerifyFullAuditProofWaveN(proof, VerifierPolicy{}),
		"VerifyValue":               VerifyValue(inventoryProofValue(t, proof), VerifierPolicy{}),
	} {
		if r.Status() != "not_anchored" || r.OK() {
			t.Fatalf("%s: status %q ok %v, want not_anchored and not ok", name, r.Status(), r.OK())
		}
	}
}

func TestInventoryLoadTrustChainRefusesAnEmptyPin(t *testing.T) {
	if _, err := LoadTrustChain(inventoryFixture(t, "trust_chain", "key_lists", "customer_v1.json"), ""); err == nil {
		t.Fatal("a key list loaded without a pin")
	}
}

// A caller outside this package can build a TrustChain only through
// LoadTrustChain; the zero value it could write holds no keys, so a proof
// under it is refused rather than verified.
func TestInventoryZeroTrustChainNeverVerifies(t *testing.T) {
	r := Verify(inventoryFixture(t, "trust_chain", "proofs", "customer_v1.json"), VerifierPolicy{TrustChain: &TrustChain{}})
	if r.OK() || r.Status() == "verified" {
		t.Fatalf("status %q under an unloaded trust chain", r.Status())
	}
}

// inventoryCLI builds the verifier command once per test; `go run` would turn
// every non-zero exit into 1.
func inventoryCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "auditproof-verifier-go")
	if out, err := exec.Command("go", "build", "-o", bin, "./cmd/auditproof-verifier-go").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func inventoryBundle(t *testing.T) *PortableReceiptBundle {
	t.Helper()
	var bundle PortableReceiptBundle
	dec := json.NewDecoder(strings.NewReader(string(inventoryFixture(t, "bundles", "a_legacy_n1_idx0.prb.json"))))
	dec.UseNumber()
	if err := dec.Decode(&bundle); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	return &bundle
}

func TestInventoryReceiptBundleDetailedIsAtMostNotAnchored(t *testing.T) {
	r, err := VerifyReceiptBundleDetailed(inventoryBundle(t))
	if err != nil || !r.Valid() {
		t.Fatalf("integrity checks: %v %+v", err, r)
	}
	if r.Status() != "not_anchored" {
		t.Fatalf("status %q, want not_anchored", r.Status())
	}
}

func TestInventoryReceiptBundleNilErrorIsAtMostNotAnchored(t *testing.T) {
	bundle := inventoryBundle(t)
	if err := VerifyReceiptBundle(bundle); err != nil {
		t.Fatalf("integrity checks: %v", err)
	}
	r, _ := VerifyReceiptBundleDetailed(bundle)
	if r.Status() != "not_anchored" {
		t.Fatalf("status %q, want not_anchored", r.Status())
	}
}

// A result whose integrity checks do not all hold says not_verified, as one
// for a bundle signed over a document it does not carry does.
func TestInventoryReceiptBundleStatusIsNotVerifiedWhenIntegrityFails(t *testing.T) {
	held, err := VerifyReceiptBundleDetailed(inventoryBundle(t))
	if err != nil || !held.Valid() {
		t.Fatalf("integrity checks: %v %+v", err, held)
	}
	for _, v := range []BundleVerification{
		{SignatureAuthentic: held.SignatureAuthentic, ReceiptBound: false, SignatureTarget: held.SignatureTarget},
		{SignatureAuthentic: false, ReceiptBound: held.ReceiptBound, SignatureTarget: held.SignatureTarget},
	} {
		if v.Valid() || v.Status() != "not_verified" {
			t.Fatalf("%+v: Valid() %v, Status() %q, want false and not_verified", v, v.Valid(), v.Status())
		}
	}
}

// The CLI refuses a key list without a pin before reading any proof.
func TestInventoryCLIKeyListWithoutPinExits2(t *testing.T) {
	proof := filepath.Join("..", "nanorix-verify", "fixtures", "trust_chain", "proofs", "customer_v1.json")
	list := filepath.Join("..", "nanorix-verify", "fixtures", "trust_chain", "key_lists", "customer_v1.json")
	cmd := exec.Command(inventoryCLI(t), "--trust-chain", list, proof)
	out, err := cmd.Output()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("exit %v, want 2; stdout %s", err, out)
	}
}

func TestInventoryOpenBundleVerifyCLIExitsZeroOnCarriedKey(t *testing.T) {
	t.Skip("open: bundle verify exits 0 with valid true on the carried key")
	bundle := filepath.Join("..", "nanorix-verify", "fixtures", "bundles", "a_legacy_n1_idx0.prb.json")
	err := exec.Command(inventoryCLI(t), "bundle", "verify", bundle).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 4 {
		t.Fatalf("exit %v, want 4", err)
	}
}

func inventoryProofValue(t *testing.T, proof []byte) map[string]interface{} {
	t.Helper()
	var v map[string]interface{}
	if err := json.Unmarshal(proof, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// VerifySignature checks a proof against the key it carries and answers
// SignatureVerified. Wanted: an answer that does not read as a verified proof
// on its own.
func TestInventoryOpenVerifySignatureOnCarriedKeyIsNotVerified(t *testing.T) {
	t.Skip("open: VerifySignature answers SignatureVerified on the key the proof carries")
	proof := inventoryProofValue(t, inventoryFixture(t, "trust_chain", "proofs", "customer_v1.json"))
	version, _ := proof["cdp_version"].(string)
	if VerifySignature(proof, version).Kind == SignatureVerified {
		t.Fatal("SignatureVerified on the carried key")
	}
}

// VerifySignatureAgainst and VerifyAttestationSignature check only the key
// their caller names: a signature by another key is refused, so the key a
// proof carries never stands in for it.
func TestInventorySignatureChecksAgainstAnotherKeyAreRefused(t *testing.T) {
	proof := inventoryProofValue(t, inventoryFixture(t, "trust_chain", "proofs", "customer_v1.json"))
	version, _ := proof["cdp_version"].(string)
	attestation, _ := proof["attestation"].(map[string]interface{})
	signerKey, _ := attestation["public_key"].(string)
	if got := VerifySignatureAgainst(proof, version, signerKey); got.Kind != SignatureVerified {
		t.Fatalf("the signing key no longer verifies (%+v), so this case proves nothing", got)
	}
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	otherB64 := base64.StdEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
	if VerifySignatureAgainst(proof, version, otherB64).Kind == SignatureVerified {
		t.Fatal("VerifySignatureAgainst verified under a key that did not sign")
	}

	signer := ed25519.NewKeyFromSeed(append(make([]byte, ed25519.SeedSize-1), 1))
	chainHash := strings.Repeat("ab", 64)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(signer, []byte(chainHash)))
	signerB64 := base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey))
	if _, ok := VerifyAttestationSignature(signerB64, sig, chainHash); !ok {
		t.Fatal("the signer's own key no longer verifies, so this case proves nothing")
	}
	if _, ok := VerifyAttestationSignature(otherB64, sig, chainHash); ok {
		t.Fatal("VerifyAttestationSignature verified under a key that did not sign")
	}
}

// pubkey-bundle verify checks the bundle only against the publisher key its
// caller names: the right key exits 0, any other key exits 1.
func TestInventoryPubkeyBundleCLIChecksOnlyTheCallersKey(t *testing.T) {
	signer := ed25519.NewKeyFromSeed(append(make([]byte, ed25519.SeedSize-1), 3))
	pub := signer.Public().(ed25519.PublicKey)
	entry := PubKeyEntry{KeyID: "key-1", Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub), ValidFrom: "2026-01-01T00:00:00Z", IssuedByOrg: "vendor:test"}
	bundle, err := BuildPubkeyBundle([]PubKeyEntry{entry}, signer, "nrx-bundle-publisher-test-v1", "issuer:test")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.ppb.json")
	rightKey := filepath.Join(dir, "right.bin")
	wrongKey := filepath.Join(dir, "wrong.bin")
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	for path, data := range map[string][]byte{bundlePath: raw, rightKey: pub, wrongKey: other} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := inventoryCLI(t)
	out, err := exec.Command(bin, "pubkey-bundle", "verify", "--publisher-pubkey", rightKey, "--json", bundlePath).Output()
	if err != nil || !strings.Contains(string(out), `"valid":true`) {
		t.Fatalf("the publisher's own key: %v %s, want exit 0 and valid true", err, out)
	}
	out, err = exec.Command(bin, "pubkey-bundle", "verify", "--publisher-pubkey", wrongKey, "--json", bundlePath).Output()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 || !strings.Contains(string(out), `"valid":false`) {
		t.Fatalf("another key: %v %s, want exit 1 and valid false", err, out)
	}
}
