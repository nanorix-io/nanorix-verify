package auditproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// The RejectDiagnostic gate. Mirrors the reject_diagnostic tests
// in tools/nanorix-verify/src/lib.rs.

func assertDiagnosticRefused(t *testing.T, label string, r AuditProofVerificationResult) {
	t.Helper()
	if r.Valid || r.StageReached != 2 || r.FailureReason == nil || r.FailureReason.Type != ReasonDiagnosticProofRefused {
		t.Errorf("%s: want diagnostic_proof_refused at stage 2; got valid=%v stage=%d reason=%+v",
			label, r.Valid, r.StageReached, r.FailureReason)
	}
}

func diagnosticProof(version string, trail []interface{}) map[string]interface{} {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["cdp_version"] = version
	if trail != nil {
		proof["activity"] = trail
	}
	return proof
}

// signTrailProof signs a 2.1 or 2.2 proof over its canonical view with an
// embedded key, so a policy that reads the trail reads one the signature
// covers. The proof then verifies at stage 7 with no policy.
func signTrailProof(t *testing.T, proof map[string]interface{}) map[string]interface{} {
	t.Helper()
	delete(proof, "attestation")
	unsigned, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tree, ok := canonicalProofTree(unsigned)
	if !ok {
		t.Fatal("canonicalProofTree failed")
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 23
	}
	signer := ed25519.NewKeyFromSeed(seed)
	proof["attestation"] = map[string]interface{}{
		"algorithm":  "Ed25519",
		"public_key": base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)),
		"signature":  base64.StdEncoding.EncodeToString(ed25519.Sign(signer, []byte(RecomputeCanonicalHash(tree)))),
	}
	return proof
}

func signedDiagnosticProof(t *testing.T, version string, trail []interface{}) map[string]interface{} {
	t.Helper()
	return signTrailProof(t, diagnosticProof(version, trail))
}

func startedEvent() map[string]interface{} {
	return map[string]interface{}{"event": "capsule_started", "region": "us-central1"}
}

func diagnosticEvent() map[string]interface{} {
	return map[string]interface{}{"event": "diagnostic_mode_enabled", "at": "2026-05-06T12:00:00Z"}
}

// With the setting on, a signed proof whose trail holds the event, wherever it
// sits, is refused at stage 2; without it the proof is accepted.
func TestRejectDiagnosticRefusesAProofRecordingDiagnosticMode(t *testing.T) {
	for _, version := range []string{"2.1", "2.2"} {
		for i, trail := range [][]interface{}{
			{startedEvent(), diagnosticEvent()},
			{diagnosticEvent(), startedEvent()},
			{diagnosticEvent()},
		} {
			label := fmt.Sprintf("%s trail %d", version, i)
			proof := signedDiagnosticProof(t, version, trail)
			assertDiagnosticRefused(t, label, VerifyValue(proof, VerifierPolicy{RejectDiagnostic: true}))
			if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid || r.StageReached != 7 {
				t.Errorf("%s: without the setting want valid at stage 7; got %+v", label, r)
			}
		}
	}
}

// The setting refuses only what it names: a signed proof without the event
// continues to the chain and signature checks.
func TestRejectDiagnosticAcceptsAProofWithoutTheEvent(t *testing.T) {
	for _, version := range []string{"2.1", "2.2"} {
		for i, trail := range [][]interface{}{
			nil,
			{},
			{startedEvent()},
			{map[string]interface{}{"event": "Diagnostic_Mode_Enabled"}},
			{map[string]interface{}{"event": "diagnostic_mode"}},
			{map[string]interface{}{"diagnostic_mode_enabled": true}},
		} {
			r := VerifyValue(signedDiagnosticProof(t, version, trail), VerifierPolicy{RejectDiagnostic: true})
			if !r.Valid || r.StageReached != 7 {
				t.Errorf("%s trail %d: want valid at stage 7; got %+v", version, i, r)
			}
		}
	}
}

// cdp_version 1.0 signs only final_hash, so its activity is unsigned and the
// setting refuses every 1.0 proof.
func TestRejectDiagnosticRefusesEveryV1Proof(t *testing.T) {
	for i, trail := range [][]interface{}{nil, {}, {startedEvent()}, {diagnosticEvent()}} {
		label := fmt.Sprintf("1.0 trail %d", i)
		proof := diagnosticProof("1.0", trail)
		assertDiagnosticRefused(t, label, VerifyValue(proof, VerifierPolicy{RejectDiagnostic: true}))
		if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid {
			t.Errorf("%s: without the setting want valid; got %+v", label, r)
		}
	}
}

// The gate sits after the authority and residency pins and before the chain
// walk.
func TestRejectDiagnosticRunsAfterThePinsAndBeforeTheChainWalk(t *testing.T) {
	proof := signedDiagnosticProof(t, "2.2", []interface{}{startedEvent(), diagnosticEvent()})
	r := VerifyValue(proof, VerifierPolicy{RejectDiagnostic: true, RequiredRegion: "europe-west1"})
	if r.FailureReason == nil || r.FailureReason.Type != ReasonRegionMismatch {
		t.Errorf("region pin first: got %+v", r.FailureReason)
	}
	r = VerifyValue(proof, VerifierPolicy{RejectDiagnostic: true, RequiredAuthorityID: "customer-hsm-example-org-v1"})
	if r.FailureReason == nil || r.FailureReason.Type != ReasonAuthorityIDMismatch {
		t.Errorf("authority pin first: got %+v", r.FailureReason)
	}
	assertDiagnosticRefused(t, "pins match", VerifyValue(proof, VerifierPolicy{
		RejectDiagnostic:    true,
		RequiredRegion:      "us-central1",
		RequiredAuthorityID: DefaultAuthorityID,
	}))

	proof["chain"] = []interface{}{}
	assertDiagnosticRefused(t, "empty chain", VerifyValue(proof, VerifierPolicy{RejectDiagnostic: true}))
	v1 := diagnosticProof("1.0", nil)
	v1["chain"] = []interface{}{}
	assertDiagnosticRefused(t, "1.0 empty chain", VerifyValue(v1, VerifierPolicy{RejectDiagnostic: true}))
}

// A 2.1 or 2.2 proof whose signature step ends as SignatureAbsent has an
// unsigned trail, like a 1.0 proof: both policies refuse it at stage 2. Each
// input is asserted Absent here, so the gate and stage 4 cannot disagree. An
// empty public_key beside a valid verification_key falls back to the
// verification_key in this engine, so its signature is checked and its trail
// counts as signed.
func TestTrailPoliciesRefuseAProofWhoseSignatureStepEndsAbsent(t *testing.T) {
	setting := VerifierPolicy{RejectDiagnostic: true}
	pin := VerifierPolicy{RequiredRegion: "europe-west1"}
	wantRegion := FailureReason{Type: ReasonRegionMismatch, Required: "europe-west1", Actual: ""}
	trail := []interface{}{map[string]interface{}{"event": "capsule_started", "region": "europe-west1"}}
	for _, version := range []string{"2.1", "2.2"} {
		signed := func() map[string]interface{} { return signedDiagnosticProof(t, version, trail) }
		attestation := func(p map[string]interface{}) map[string]interface{} {
			return p["attestation"].(map[string]interface{})
		}
		for _, policy := range []VerifierPolicy{setting, pin} {
			if r := VerifyValue(signed(), policy); !r.Valid || r.StageReached != 7 {
				t.Errorf("%s signed under %+v: want valid at stage 7; got %+v", version, policy, r)
			}
		}

		noSignature := signed()
		delete(attestation(noSignature), "signature")
		emptySignature := signed()
		attestation(emptySignature)["signature"] = ""
		noKey := signed()
		delete(attestation(noKey), "public_key")
		for name, proof := range map[string]map[string]interface{}{
			"no signature": noSignature, "empty signature": emptySignature, "no key": noKey,
		} {
			label := version + " " + name
			if check := VerifySignature(proof, version); check.Kind != SignatureAbsent {
				t.Errorf("%s: VerifySignature = %+v, want SignatureAbsent", label, check)
			}
			assertDiagnosticRefused(t, label, VerifyValue(proof, setting))
			if r := VerifyValue(proof, pin); r.Valid || r.StageReached != 2 || !r.FailureReason.Equal(&wantRegion) {
				t.Errorf("%s: want %+v at stage 2; got %+v", label, wantRegion, r)
			}
			if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid || r.StageReached != 4 {
				t.Errorf("%s: without a policy want valid at stage 4; got %+v", label, r)
			}
		}

		fallback := signed()
		attestation(fallback)["verification_key"] = attestation(fallback)["public_key"]
		attestation(fallback)["public_key"] = ""
		if check := VerifySignature(fallback, version); check.Kind != SignatureVerified {
			t.Errorf("%s empty public_key: VerifySignature = %+v, want SignatureVerified", version, check)
		}
		for _, policy := range []VerifierPolicy{setting, pin} {
			if r := VerifyValue(fallback, policy); !r.Valid || r.StageReached != 7 {
				t.Errorf("%s empty public_key under %+v: want valid at stage 7; got %+v", version, policy, r)
			}
		}
	}
}

// Only the no-signature case is refused at stage 2: a signature that is
// present but no longer covers the trail fails at stage 7.
func TestRejectDiagnosticLeavesAPresentSignatureToTheSignatureStep(t *testing.T) {
	for _, version := range []string{"2.1", "2.2"} {
		proof := signedDiagnosticProof(t, version, []interface{}{startedEvent(), diagnosticEvent()})
		proof["activity"] = []interface{}{startedEvent()}
		r := VerifyValue(proof, VerifierPolicy{RejectDiagnostic: true})
		if r.Valid || r.StageReached != 7 || r.FailureReason == nil || r.FailureReason.Type != ReasonSignatureMismatch {
			t.Errorf("%s stripped: want signature_mismatch at stage 7; got %+v", version, r)
		}
	}
}
