package auditproof

// `signing_mode: "customer_only"` (section 4): the mode
// names the authority the proof claims, not which bytes are signed, so on 2.1 and 2.2 it signs
// the canonical-view hash as nanorix_only does; a signed customer_only beside
// a Nanorix-classified authority_id is refused at stage 4.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

const customerOnlyBaseFixture = "../nanorix-verify/fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json"

// resignedFixture loads a genuine 2.1 corpus proof, applies edit to it and
// signs the result with a fixed test key, so the labels edit is covered by a
// signature that verifies.
func resignedFixture(t *testing.T, edit func(map[string]interface{})) []byte {
	t.Helper()
	raw, err := os.ReadFile(customerOnlyBaseFixture)
	if err != nil {
		t.Fatalf("read base fixture: %v", err)
	}
	var proof map[string]interface{}
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatalf("parse base fixture: %v", err)
	}
	edit(proof)
	unsigned, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tree, ok := canonicalProofTree(unsigned)
	if !ok {
		t.Fatal("canonicalProofTree failed")
	}
	canonical := RecomputeCanonicalHash(tree)
	if len(canonical) != 128 {
		t.Fatalf("canonical hash length %d (the mode was not recomputed)", len(canonical))
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 42
	}
	signer := ed25519.NewKeyFromSeed(seed)
	att, _ := proof["attestation"].(map[string]interface{})
	if att == nil {
		att = map[string]interface{}{}
	}
	att["public_key"] = "base64:" + base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey))
	att["signature"] = "base64:" + base64.StdEncoding.EncodeToString(ed25519.Sign(signer, []byte(canonical)))
	delete(att, "verification_key")
	proof["attestation"] = att
	out, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func labels(mode string, authority interface{}) func(map[string]interface{}) {
	return func(p map[string]interface{}) {
		p["signing_mode"] = mode
		if authority == nil {
			delete(p, "authority_id")
		} else {
			p["authority_id"] = authority
		}
	}
}

func TestCustomerAuthorityClassifierIsTheIssuersTest(t *testing.T) {
	for _, id := range []string{
		"customer-hsm-acme-v1", "customer-kms-acme-v1", "customer-tee-acme-v1",
		"customer-byo-acme-v1", "us-customer-kms-acme-v1", "eu-west-customer-byo-x",
	} {
		if !IsCustomerAuthority(id) {
			t.Errorf("IsCustomerAuthority(%q) = false, want true", id)
		}
	}
	for _, id := range []string{
		"us-kms-nanorix-v1", "us-Customer-kms-acme-v1", "CUSTOMER-KMS-acme",
		"customer-kms", "customerkms-acme", "customer_kms-acme", "customer-", "",
	} {
		if IsCustomerAuthority(id) {
			t.Errorf("IsCustomerAuthority(%q) = true, want false", id)
		}
	}
}

func TestCustomerOnlyRecomputesTheCanonicalHash(t *testing.T) {
	for _, version := range []string{"2.1", "2.2"} {
		raw := resignedFixture(t, func(p map[string]interface{}) {
			labels(SigningModeCustomerOnly, "us-customer-kms-acme-v1")(p)
			p["cdp_version"] = version
		})
		r := Verify(raw, VerifierPolicy{})
		if !r.Valid || r.StageReached != 7 || r.FailureReason != nil {
			t.Fatalf("%s: valid=%v stage=%d reason=%+v, want valid at stage 7", version, r.Valid, r.StageReached, r.FailureReason)
		}
	}
}

func TestCustomerOnlyModeEditBreaksTheSignature(t *testing.T) {
	raw := resignedFixture(t, labels(SigningModeCustomerOnly, "us-customer-kms-acme-v1"))
	var proof map[string]interface{}
	_ = json.Unmarshal(raw, &proof)
	proof["signing_mode"] = "nanorix_only"
	edited, _ := json.Marshal(proof)
	r := Verify(edited, VerifierPolicy{})
	if r.Valid || r.StageReached != 7 || r.FailureReason == nil || r.FailureReason.Type != ReasonSignatureMismatch {
		t.Fatalf("valid=%v stage=%d reason=%+v, want signature_mismatch at stage 7", r.Valid, r.StageReached, r.FailureReason)
	}
}

func TestCustomerOnlyUnderANanorixAuthorityIsRefusedAtStage4(t *testing.T) {
	for _, authority := range []interface{}{"us-kms-nanorix-v1", "us-Customer-kms-acme-v1", nil, 7.0} {
		raw := resignedFixture(t, labels(SigningModeCustomerOnly, authority))
		r := Verify(raw, VerifierPolicy{})
		if r.Valid || r.StageReached != 4 || r.FailureReason == nil ||
			r.FailureReason.Type != ReasonSigningModeAuthorityMismatch {
			t.Fatalf("%v: valid=%v stage=%d reason=%+v, want signing_mode_authority_mismatch at stage 4", authority, r.Valid, r.StageReached, r.FailureReason)
		}
		wire, _ := json.Marshal(r.FailureReason)
		want := `{"type":"signing_mode_authority_mismatch","claimed_authority_id":null}`
		if s, ok := authority.(string); ok {
			want = `{"type":"signing_mode_authority_mismatch","claimed_authority_id":"` + s + `"}`
		}
		if string(wire) != want {
			t.Errorf("%v: wire %s, want %s", authority, wire, want)
		}
	}
}

func TestAnUnsupportedAlgorithmIsRefusedBeforeTheGate(t *testing.T) {
	raw := resignedFixture(t, labels(SigningModeCustomerOnly, "us-kms-nanorix-v1"))
	var proof map[string]interface{}
	_ = json.Unmarshal(raw, &proof)
	proof["attestation"].(map[string]interface{})["algorithm"] = "Ed448"
	edited, _ := json.Marshal(proof)
	r := Verify(edited, VerifierPolicy{})
	if r.StageReached != 4 || r.FailureReason == nil || r.FailureReason.Type != ReasonAlgorithmUnsupported {
		t.Fatalf("stage=%d reason=%+v, want algorithm_unsupported at stage 4", r.StageReached, r.FailureReason)
	}
}

func TestEveryOtherModeIsStillRefused(t *testing.T) {
	for _, mode := range []string{"customer-only", "Customer_Only", "customer_only ", "customer", "dual_signature"} {
		raw := resignedFixture(t, labels(SigningModeCustomerOnly, "us-customer-kms-acme-v1"))
		var proof map[string]interface{}
		_ = json.Unmarshal(raw, &proof)
		proof["signing_mode"] = mode
		edited, _ := json.Marshal(proof)
		r := Verify(edited, VerifierPolicy{})
		if r.Valid || r.StageReached != 4 || r.FailureReason == nil ||
			r.FailureReason.Type != ReasonAlgorithmUnsupported || r.FailureReason.Found != "signing_mode="+mode {
			t.Fatalf("%q: valid=%v stage=%d reason=%+v, want algorithm_unsupported signing_mode=%s", mode, r.Valid, r.StageReached, r.FailureReason, mode)
		}
	}
}

func TestTheLegacyPairStillVerifies(t *testing.T) {
	raw := resignedFixture(t, labels("nanorix_only", "us-customer-kms-acme-v1"))
	r := Verify(raw, VerifierPolicy{})
	if !r.Valid || r.StageReached != 7 {
		t.Fatalf("valid=%v stage=%d reason=%+v, want valid at stage 7", r.Valid, r.StageReached, r.FailureReason)
	}
}
