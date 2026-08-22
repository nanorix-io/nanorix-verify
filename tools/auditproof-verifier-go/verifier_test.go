// Test suite for the Go reference verifier.
//
// **Cross-impl byte-equivalence (binding contract):** every fixture in
// `tools/nanorix-verify/fixtures/corpus/` must produce a Go-side verification
// output that is byte-identical to the Rust verifier output. Divergence on
// even one fixture is a P0 finding per ADR-006 I0 + ADR-033 release framing
// + `feedback_canonical_hash_under_fault.md`.
//
// Property-test fault injection (per `feedback_canonical_hash_under_fault.md`):
// 10k iterations of random AuditProof bytes — malformed JSON, wrong field
// types, off-by-one chain values, tampered signatures — every fault path must
// produce a deterministic FailureReason from the closed-set enum.

package auditproof

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// FixtureCorpusRelative is the corpus path relative to this Go module.
	// The corpus is shipped at `tools/nanorix-verify/fixtures/corpus/` from
	// commit ba1d51a (Wave 6 verification-surface scaffolds).
	FixtureCorpusRelative = "../nanorix-verify/fixtures/corpus"

	// MinFixturesExpected is the corpus-size invariant. New fixtures may be
	// added (additive); this floor catches accidental corpus deletion.
	MinFixturesExpected = 100
)

// TestGenesisHashIsSHA512OfEmpty pins the genesis-hash constant against the
// canonical SHA-512(empty) computation. Mirror of Rust test
// `genesis_hash_constant_matches_sha512_of_empty`.
func TestGenesisHashIsSHA512OfEmpty(t *testing.T) {
	h := sha512.Sum512([]byte(""))
	got := hex.EncodeToString(h[:])
	if got != NanorixGenesisHash {
		t.Fatalf("genesis hash drift: got %s, want %s", got, NanorixGenesisHash)
	}
}

// TestLookupMethodCoversAll8Subsystems pins the subsystem→method canonical
// mapping. Mirror of Rust test `lookup_method_covers_all_8_subsystems`.
func TestLookupMethodCoversAll8Subsystems(t *testing.T) {
	subsystems := []string{
		"eee_namespace", "eee_tmpfs", "eee_memory", "dire_keys",
		"dire_identity", "fgx_forensic", "rzl_audit", "capsule_destroy",
	}
	for _, s := range subsystems {
		if LookupMethod(s) == "" {
			t.Errorf("no method for subsystem %s", s)
		}
	}
	if LookupMethod("unknown_subsystem") != "" {
		t.Error("unknown subsystem should map to empty string")
	}
}

// TestStripPrefixHelpers pins the prefix-strip behavior. Mirror of Rust test
// `strip_prefix_helpers_handle_present_and_absent_prefix`.
func TestStripPrefixHelpers(t *testing.T) {
	cases := []struct{ in, want string }{
		{"sha512:abc", "abc"},
		{"abc", "abc"},
		{"sha512:", ""},
	}
	for _, c := range cases {
		if got := StripHashPrefix(c.in); got != c.want {
			t.Errorf("StripHashPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if StripBase64Prefix("base64:xyz") != "xyz" {
		t.Error("StripBase64Prefix failed")
	}
	if StripBase64Prefix("xyz") != "xyz" {
		t.Error("StripBase64Prefix idempotent failed")
	}
}

// makeMinimalV1Proof builds a v1.0 AuditProof valid through stage 4. Mirror
// of Rust test helper `make_minimal_v1_proof`.
func makeMinimalV1Proof(timestamp string) map[string]interface{} {
	subsystems := []string{
		"eee_namespace", "eee_tmpfs", "eee_memory", "dire_keys",
		"dire_identity", "fgx_forensic", "rzl_audit", "capsule_destroy",
	}
	prevHash := NanorixGenesisHash
	chain := make([]interface{}, 0, 8)
	for _, s := range subsystems {
		method := LookupMethod(s)
		ch := ComputeStepHash(prevHash, s, "destroy", method, timestamp)
		chain = append(chain, map[string]interface{}{
			"subsystem":  s,
			"method":     method,
			"chain_hash": ch,
		})
		prevHash = ch
	}
	return map[string]interface{}{
		"cdp_version":  "1.0",
		"capsule_id":   "cap_test",
		"destroyed_at": timestamp,
		"chain":        chain,
		"final_hash":   prevHash,
	}
}

// TestVerifyMinimalV1ProofSucceeds — the basic happy-path test.
func TestVerifyMinimalV1ProofSucceeds(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	r := VerifyValue(proof, VerifierPolicy{})
	if !r.Valid {
		t.Fatalf("expected valid; got %+v", r)
	}
	if r.Metadata.CdpVersion == nil || *r.Metadata.CdpVersion != "1.0" {
		t.Errorf("metadata.cdp_version not 1.0")
	}
	if r.Metadata.StepCount == nil || *r.Metadata.StepCount != 8 {
		t.Errorf("step_count not 8")
	}
}

// TestVerifyMissingCdpVersionFailsAtStage1 mirrors Rust
// `verify_missing_cdp_version_fails_at_stage_1`.
func TestVerifyMissingCdpVersionFailsAtStage1(t *testing.T) {
	proof := map[string]interface{}{"foo": "bar"}
	r := VerifyValue(proof, VerifierPolicy{})
	if r.Valid {
		t.Fatal("expected invalid")
	}
	if r.StageReached != 1 {
		t.Errorf("stage_reached = %d, want 1", r.StageReached)
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonRequiredFieldMissing {
		t.Errorf("failure_reason = %+v, want required_field_missing", r.FailureReason)
	}
	if r.FailureReason.Field != "cdp_version" {
		t.Errorf("field = %q, want cdp_version", r.FailureReason.Field)
	}
}

// TestVerifyUnsupportedCdpVersionFailsAtStage2 mirrors Rust
// `verify_unsupported_cdp_version_fails_at_stage_2`.
func TestVerifyUnsupportedCdpVersionFailsAtStage2(t *testing.T) {
	proof := map[string]interface{}{"cdp_version": "99.0"}
	r := VerifyValue(proof, VerifierPolicy{})
	if r.Valid {
		t.Fatal("expected invalid")
	}
	if r.StageReached != 2 {
		t.Errorf("stage_reached = %d, want 2", r.StageReached)
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonCdpVersionUnsupported {
		t.Errorf("failure_reason = %+v", r.FailureReason)
	}
	if r.FailureReason.Found != "99.0" {
		t.Errorf("found = %q, want 99.0", r.FailureReason.Found)
	}
}

// TestVerifyTamperedStepHashFailsAtStage3 mirrors Rust
// `verify_tampered_step_hash_fails_at_stage_3`.
func TestVerifyTamperedStepHashFailsAtStage3(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	chain := proof["chain"].([]interface{})
	step4 := chain[4].(map[string]interface{})
	step4["chain_hash"] = strings.Repeat("0", 128)
	r := VerifyValue(proof, VerifierPolicy{})
	if r.Valid {
		t.Fatal("expected invalid")
	}
	if r.StageReached != 3 {
		t.Errorf("stage_reached = %d, want 3", r.StageReached)
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonStepHashMismatch {
		t.Errorf("failure_reason = %+v", r.FailureReason)
	}
	if r.FailureReason.StepIdx != 4 {
		t.Errorf("step_idx = %d, want 4", r.FailureReason.StepIdx)
	}
}

// TestCanonicalChainIdentityIsEnforced mirrors the Rust B1.4 tests. Eight
// entries is a count, not an identity: before the canonical-identity walk, a
// self-consistent chain over any eight subsystem names verified clean.
func TestCanonicalChainIdentityIsEnforced(t *testing.T) {
	ts := "2026-05-06T12:00:00Z"

	// Positive control — the canonical eight still verify.
	if r := VerifyValue(makeMinimalV1Proof(ts), VerifierPolicy{}); !r.Valid {
		t.Fatalf("canonical chain must verify; got %+v", r.FailureReason)
	}

	// A self-consistent chain over non-canonical subsystems: the hashes were
	// computed over the forger's own names, so the canonical recompute
	// disagrees at step 0.
	forged := makeMinimalV1Proof(ts)
	chain := forged["chain"].([]interface{})
	prev := NanorixGenesisHash
	for idx := range chain {
		step := chain[idx].(map[string]interface{})
		name := fmt.Sprintf("subsystem_%d", idx)
		step["subsystem"] = name
		h := ComputeStepHash(prev, name, "destroy", LookupMethod(name), ts)
		step["chain_hash"] = h
		prev = h
	}
	forged["final_hash"] = prev
	r := VerifyValue(forged, VerifierPolicy{})
	if r.Valid {
		t.Fatal("a self-consistent non-canonical chain must not verify")
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonStepHashMismatch || r.FailureReason.StepIdx != 0 {
		t.Errorf("failure_reason = %+v; want step_hash_mismatch at 0", r.FailureReason)
	}

	// Genuine hashes, forged label — only the explicit identity check sees it.
	mislabelled := makeMinimalV1Proof(ts)
	mislabelled["chain"].([]interface{})[3].(map[string]interface{})["subsystem"] = "dire_identity"
	r = VerifyValue(mislabelled, VerifierPolicy{})
	if r.Valid {
		t.Fatal("a forged step label must not verify")
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonChainStepIdentity {
		t.Fatalf("failure_reason = %+v; want chain_step_identity_mismatch", r.FailureReason)
	}
	if r.FailureReason.StepIdx != 3 ||
		r.FailureReason.ExpectedSubsystem != "dire_keys" ||
		r.FailureReason.FoundSubsystem != "dire_identity" {
		t.Errorf("payload = %+v", r.FailureReason)
	}
}

// TestVerifyMismatchedFinalHashFailsAtStage4 mirrors Rust
// `verify_mismatched_final_hash_fails_at_stage_4`.
func TestVerifyMismatchedFinalHashFailsAtStage4(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["final_hash"] = strings.Repeat("0", 128)
	r := VerifyValue(proof, VerifierPolicy{})
	if r.Valid {
		t.Fatal("expected invalid")
	}
	if r.StageReached != 4 {
		t.Errorf("stage_reached = %d, want 4", r.StageReached)
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonFinalHashMismatch {
		t.Errorf("failure_reason = %+v", r.FailureReason)
	}
}

// TestPolicyPinCustomerHsmAuditProofNoneRejected mirrors Rust
// `policy_pin_customer_hsm_audit_proof_none_rejected`.
func TestPolicyPinCustomerHsmAuditProofNoneRejected(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	policy := VerifierPolicy{RequiredAuthorityID: "customer-hsm-example-org-v1"}
	r := VerifyValue(proof, policy)
	if r.Valid {
		t.Fatalf("expected reject; got %+v", r)
	}
	if r.StageReached != 2 {
		t.Errorf("stage_reached = %d, want 2", r.StageReached)
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonAuthorityIDMismatch {
		t.Errorf("failure_reason = %+v", r.FailureReason)
	}
	if r.FailureReason.ClaimedAuthorityID != nil {
		t.Errorf("expected nil claimed; got %v", r.FailureReason.ClaimedAuthorityID)
	}
	if r.FailureReason.ExpectedAuthorityID != "customer-hsm-example-org-v1" {
		t.Errorf("expected_authority_id = %q", r.FailureReason.ExpectedAuthorityID)
	}
	if r.FailureReason.AuthIDReason != AuthIDPolicyDemandsCustomerHSMHasNone {
		t.Errorf("reason = %q", r.FailureReason.AuthIDReason)
	}
}

// TestPolicyPinCustomerHsmAuditProofWrongAuthorityRejected mirrors Rust
// `policy_pin_customer_hsm_audit_proof_wrong_authority_rejected`.
func TestPolicyPinCustomerHsmAuditProofWrongAuthorityRejected(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["signing_authority"] = map[string]interface{}{
		"authority_id": "customer-hsm-other-v1",
	}
	policy := VerifierPolicy{RequiredAuthorityID: "customer-hsm-example-org-v1"}
	r := VerifyValue(proof, policy)
	if r.Valid {
		t.Fatalf("expected reject; got %+v", r)
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonAuthorityIDMismatch {
		t.Errorf("failure_reason = %+v", r.FailureReason)
	}
	if r.FailureReason.AuthIDReason != AuthIDPolicyAuthorityIDMismatch {
		t.Errorf("reason = %q", r.FailureReason.AuthIDReason)
	}
}

// TestPolicyPinCustomerHsmAuditProofMatchesAuthorityAccepted mirrors Rust
// `policy_pin_customer_hsm_audit_proof_matches_authority_accepted`.
func TestPolicyPinCustomerHsmAuditProofMatchesAuthorityAccepted(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["signing_authority"] = map[string]interface{}{
		"authority_id": "customer-hsm-example-org-v1",
	}
	policy := VerifierPolicy{RequiredAuthorityID: "customer-hsm-example-org-v1"}
	r := VerifyValue(proof, policy)
	if !r.Valid {
		t.Fatalf("expected valid; got %+v", r)
	}
}

// TestFixtureCorpusByteEquivalentWithRust walks the reference corpus shipped
// at `tools/nanorix-verify/fixtures/corpus/`, runs the Go verifier on each
// proof JSON, runs the Rust verifier (via the binary at
// `target/debug/nanorix-verify` if present), and asserts byte-identical JSON
// output.
//
// **This is the primary cross-impl byte-equivalence assertion.** Per
// ADR-006 I0 + ADR-033 release framing + `feedback_canonical_hash_under_fault.md`,
// divergence on even ONE fixture is a P0 finding.
//
// If the Rust binary is unavailable (`go test` running in an environment
// without the Cargo workspace), the test runs Go-only verification and
// asserts every fixture produces a deterministic non-empty result; the
// cross-impl byte-equivalence check is skipped with a NOTICE.
func TestFixtureCorpusByteEquivalentWithRust(t *testing.T) {
	corpusRoot, err := filepath.Abs(FixtureCorpusRelative)
	if err != nil {
		t.Fatalf("resolve corpus path: %v", err)
	}
	if _, err := os.Stat(corpusRoot); err != nil {
		t.Skipf("fixture corpus not available at %s: %v", corpusRoot, err)
	}

	rustBin, rustAvailable := findRustVerifier()

	var fixtures []string
	walkErr := filepath.Walk(corpusRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		base := filepath.Base(p)
		if strings.HasSuffix(p, ".expected.json") || base == "index.json" {
			return nil
		}
		if strings.HasSuffix(p, ".json") {
			fixtures = append(fixtures, p)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk corpus: %v", walkErr)
	}

	if len(fixtures) < MinFixturesExpected {
		t.Fatalf("corpus shrank below floor: %d < %d", len(fixtures), MinFixturesExpected)
	}

	verifiedCount := 0
	failedCount := 0
	divergent := []string{}

	for _, fx := range fixtures {
		bytes, err := os.ReadFile(fx)
		if err != nil {
			t.Fatalf("read %s: %v", fx, err)
		}
		goResult := Verify(bytes, VerifierPolicy{})
		if goResult.Valid {
			verifiedCount++
		} else {
			failedCount++
		}

		if !rustAvailable {
			continue
		}

		// Run the Rust verifier on the same fixture and compare JSON output.
		rustOut, err := runRustVerifier(rustBin, fx)
		if err != nil {
			// Once the Rust binary is available, a fixture it cannot produce a
			// verdict for is a finding, not something to log past. A skip here
			// is indistinguishable from agreement.
			t.Errorf("rust verifier produced no verdict for %s: %v", fx, err)
			continue
		}
		goJSON, err := json.MarshalIndent(goResult, "", "  ")
		if err != nil {
			t.Fatalf("marshal go result: %v", err)
		}
		// Rust uses serde_json::to_string_pretty which uses 2-space indent
		// and emits one final newline. main.go prints with println which adds
		// one newline. Strip trailing whitespace from both before compare.
		rustNorm := strings.TrimRight(string(rustOut), "\n")
		goNorm := strings.TrimRight(string(goJSON), "\n")
		if rustNorm != goNorm {
			divergent = append(divergent, fx)
			if len(divergent) <= 3 {
				t.Errorf("DIVERGENT: %s\n--- Rust ---\n%s\n--- Go ---\n%s", fx, rustNorm, goNorm)
			}
		}
	}

	t.Logf("Fixture corpus: %d total · %d verified · %d failed · %d divergent",
		len(fixtures), verifiedCount, failedCount, len(divergent))

	if rustAvailable && len(divergent) > 0 {
		t.Fatalf("Cross-impl byte-equivalence FAILED: %d/%d fixtures diverge between Rust and Go verifiers",
			len(divergent), len(fixtures))
	}

	if !rustAvailable {
		t.Logf("NOTICE: Rust verifier binary not found; cross-impl byte-equivalence check skipped. " +
			"Build the Rust verifier with `cargo build -p nanorix-verify` to enable cross-impl assertion.")
	}
}

// TestPropertyFault10kIterations runs the 10k-iteration property-test fault
// injection mandated by `feedback_canonical_hash_under_fault.md`. Random
// AuditProof bytes — malformed JSON, wrong field types, off-by-one chain
// values, tampered signatures — every fault path must produce a
// deterministic FailureReason from the closed-set enum (or `valid: true`
// when the random mutation happens to be benign).
//
// **Forever-Standard discipline:** verifier MUST NOT panic, MUST NOT return
// a FailureReason outside the closed-set enum, MUST NOT hang, MUST NOT leak
// resources, regardless of input.
func TestPropertyFault10kIterations(t *testing.T) {
	const iterations = 10_000
	// Deterministic seed; cast to int64 — top bit chosen so the literal fits.
	rng := rand.New(rand.NewSource(int64(0x40DE_5117_FACE_FEED)))

	closedSet := map[FailureReasonType]bool{
		ReasonAlgorithmUnsupported:                 true,
		ReasonAuthorityIDMismatch:                  true,
		ReasonAuthorityModeMismatch:                true,
		ReasonAuthorityRevoked:                     true,
		ReasonCdpVersionUnsupported:                true,
		ReasonChainStepIdentity:                    true,
		ReasonCustomerDeclaredActivityRootMismatch: true,
		ReasonDiagnosticProofRefused:               true,
		ReasonFieldMalformed:                       true,
		ReasonFinalHashMismatch:                    true,
		ReasonGenesisHashMismatch:                  true,
		ReasonRegionMismatch:                       true,
		ReasonRequiredFieldMissing:                 true,
		ReasonReserved:                             true,
		ReasonSignatureMismatch:                    true,
		ReasonSigningKeyVersionUnknown:             true,
		ReasonStepCountInvalid:                     true,
		ReasonStepHashMismatch:                     true,
	}

	// 8 fault families. Each iteration picks one and applies a random mutation.
	for i := 0; i < iterations; i++ {
		family := rng.Intn(8)
		var proof map[string]interface{}
		ts := "2026-05-06T12:00:00Z"
		switch family {
		case 0:
			// Family 0: completely random bytes. Most will fail parse.
			randomBytes := make([]byte, rng.Intn(256))
			_, _ = rng.Read(randomBytes)
			r := Verify(randomBytes, VerifierPolicy{})
			if r.Valid {
				continue // benign — random bytes happened to be valid JSON+chain (vanishingly rare)
			}
			if r.FailureReason == nil {
				t.Fatalf("iter %d (family 0): nil failure reason on invalid input", i)
			}
			if !closedSet[r.FailureReason.Type] {
				t.Fatalf("iter %d (family 0): out-of-set failure reason %q", i, r.FailureReason.Type)
			}
			continue

		case 1:
			// Family 1: syntactically valid JSON but missing cdp_version.
			proof = map[string]interface{}{
				"random_field": rng.Intn(1000),
			}
		case 2:
			// Family 2: cdp_version is wrong type (number instead of string).
			proof = map[string]interface{}{
				"cdp_version": rng.Intn(100),
			}
		case 3:
			// Family 3: unsupported version.
			versions := []string{"0.5", "3.0", "99.0", "v1", "1.0.0", "", "null"}
			proof = map[string]interface{}{
				"cdp_version": versions[rng.Intn(len(versions))],
			}
		case 4:
			// Family 4: chain wrong type / missing.
			proof = makeMinimalV1Proof(ts)
			delete(proof, "chain")
		case 5:
			// Family 5: chain truncated to N steps where N != 8.
			proof = makeMinimalV1Proof(ts)
			chain := proof["chain"].([]interface{})
			n := rng.Intn(15)
			if n > 8 {
				// extend
				for len(chain) < n {
					chain = append(chain, chain[len(chain)-1])
				}
			} else {
				// truncate
				if n < len(chain) {
					chain = chain[:n]
				}
			}
			proof["chain"] = chain
		case 6:
			// Family 6: tamper one step's chain_hash.
			proof = makeMinimalV1Proof(ts)
			chain := proof["chain"].([]interface{})
			tamperIdx := rng.Intn(len(chain))
			step := chain[tamperIdx].(map[string]interface{})
			tamper := make([]byte, 64)
			_, _ = rng.Read(tamper)
			step["chain_hash"] = hex.EncodeToString(tamper)
		case 7:
			// Family 7: tamper final_hash.
			proof = makeMinimalV1Proof(ts)
			tamper := make([]byte, 64)
			_, _ = rng.Read(tamper)
			proof["final_hash"] = hex.EncodeToString(tamper)
		}

		if proof == nil {
			continue
		}
		bytes, err := json.Marshal(proof)
		if err != nil {
			t.Fatalf("iter %d: marshal: %v", i, err)
		}
		// Run with random policy too.
		policy := VerifierPolicy{}
		if rng.Intn(4) == 0 {
			policy.RequiredAuthorityID = "customer-hsm-example-org-v1"
		}

		r := Verify(bytes, policy)
		// MUST NOT panic. If we got here, no panic. Now invariants:
		if !r.Valid {
			if r.FailureReason == nil {
				t.Fatalf("iter %d (family %d): valid=false but failure_reason=nil", i, family)
			}
			if !closedSet[r.FailureReason.Type] {
				t.Fatalf("iter %d (family %d): out-of-set failure reason %q",
					i, family, r.FailureReason.Type)
			}
		}
		if r.StageReached < 1 || r.StageReached > 8 {
			t.Fatalf("iter %d (family %d): stage_reached %d out of range",
				i, family, r.StageReached)
		}
		// Round-trip the failure reason if present.
		if r.FailureReason != nil {
			fb, err := r.FailureReason.MarshalJSON()
			if err != nil {
				t.Fatalf("iter %d: marshal failure reason: %v", i, err)
			}
			var rt FailureReason
			if err := rt.UnmarshalJSON(fb); err != nil {
				t.Fatalf("iter %d: roundtrip unmarshal: %v (bytes %s)", i, err, fb)
			}
			if rt.Type != r.FailureReason.Type {
				t.Fatalf("iter %d: roundtrip type drift %q -> %q",
					i, r.FailureReason.Type, rt.Type)
			}
		}
	}
	t.Logf("Property-test fault injection: 10000 iterations · 0 panics · 0 out-of-set failure reasons · 0 round-trip drift")
}

// TestComputeStepHashCrossImplAnchor pins the byte-output of ComputeStepHash
// against a hand-computed anchor. If this drifts, the chain algorithm has
// been tampered with — Forever-Standard ADR-006 I0 violation.
func TestComputeStepHashCrossImplAnchor(t *testing.T) {
	// Compute step 1 from genesis: subsystem=eee_namespace, action=destroy,
	// method=procfs_verification, timestamp=2026-05-08T00:00:00Z.
	// Fixture 0000_v2_1_signed.json step 1 chain_hash should be
	//   dd8b771ee228b936131127f029c2f937380f2053cb6e70b4ee36a30faf1dd31116b501b3a700e2c798b31e036c137ccc93d74b87ec94c10661a70cf5a03e872e
	const expected = "dd8b771ee228b936131127f029c2f937380f2053cb6e70b4ee36a30faf1dd31116b501b3a700e2c798b31e036c137ccc93d74b87ec94c10661a70cf5a03e872e"
	got := ComputeStepHash(NanorixGenesisHash, "eee_namespace", "destroy", "procfs_verification", "2026-05-08T00:00:00Z")
	if got != expected {
		t.Fatalf("chain step-1 anchor drift: got %s, want %s", got, expected)
	}
}

// TestFailureReasonWireFormIsLocked pins every variant's wire-form tag.
// Mirror of Rust test `failure_reason_wire_form_is_locked`.
func TestFailureReasonWireFormIsLocked(t *testing.T) {
	cases := []struct {
		r       FailureReason
		wireTag string
	}{
		{FailureReason{Type: ReasonCdpVersionUnsupported, Found: "99.0"}, "cdp_version_unsupported"},
		{FailureReason{Type: ReasonRequiredFieldMissing, Field: "x"}, "required_field_missing"},
		{FailureReason{Type: ReasonStepCountInvalid, Expected: 8, FoundCount: 7}, "step_count_invalid"},
		{FailureReason{Type: ReasonStepHashMismatch, StepIdx: 0, Subsystem: "x"}, "step_hash_mismatch"},
		{FailureReason{Type: ReasonChainStepIdentity, StepIdx: 3, ExpectedSubsystem: "dire_keys", FoundSubsystem: "rzl_audit"}, "chain_step_identity_mismatch"},
		{FailureReason{Type: ReasonGenesisHashMismatch}, "genesis_hash_mismatch"},
		{FailureReason{Type: ReasonFinalHashMismatch, Claimed: "x", Computed: "y"}, "final_hash_mismatch"},
		{FailureReason{Type: ReasonSignatureMismatch, SigReason: SigDoesNotVerify}, "signature_mismatch"},
		{FailureReason{Type: ReasonSigningKeyVersionUnknown, Version: "v7"}, "signing_key_version_unknown"},
		{FailureReason{Type: ReasonAuthorityRevoked}, "authority_revoked"},
		{FailureReason{Type: ReasonRegionMismatch, Required: "europe-west1", Actual: "us-central1"}, "region_mismatch"},
		{FailureReason{Type: ReasonDiagnosticProofRefused}, "diagnostic_proof_refused"},
		{FailureReason{Type: ReasonAlgorithmUnsupported, Found: "RSA-PSS"}, "algorithm_unsupported"},
		{FailureReason{Type: ReasonReserved}, "reserved"},
	}
	for _, c := range cases {
		out, err := c.r.MarshalJSON()
		if err != nil {
			t.Errorf("marshal %v: %v", c.r, err)
			continue
		}
		want := fmt.Sprintf(`"type":"%s"`, c.wireTag)
		if !strings.Contains(string(out), want) {
			t.Errorf("variant %q wire form drifted: got %s, want substring %s",
				c.wireTag, out, want)
		}
	}
}

// TestSignatureFailureReasonWireForm pins the sub-enum wire form. Mirror of
// Rust test `signature_failure_reason_wire_form_is_locked`.
func TestSignatureFailureReasonWireForm(t *testing.T) {
	cases := []struct {
		r    SignatureFailureReason
		want string
	}{
		{SigMalformed, "malformed"},
		{SigDoesNotVerify, "does_not_verify"},
		{SigPublicKeyMalformed, "public_key_malformed"},
		{SigMessageFormatMismatch, "message_format_mismatch"},
	}
	for _, c := range cases {
		if string(c.r) != c.want {
			t.Errorf("SignatureFailureReason wire-form drift: %q != %q", c.r, c.want)
		}
	}
}

// TestJCSCanonicalizeBasic exercises the JCS canonicalization path. The
// reference corpus is currently V1 (chain-only verification) so JCS is not
// on the critical path for fixture byte-equivalence, but the implementation
// must hold under simple inputs as a foundation for V2.
func TestJCSCanonicalizeBasic(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`{"b":2,"a":1}`, `{"a":1,"b":2}`},
		{`{"a":  1,  "b":[3,1,2]}`, `{"a":1,"b":[3,1,2]}`},
		{`{"key":"value"}`, `{"key":"value"}`},
		{`{"escape":"\""}`, `{"escape":"\""}`},
		{`{"unicode":"abc"}`, `{"unicode":"abc"}`},
	}
	for _, c := range cases {
		got, err := JCSCanonicalize([]byte(c.in))
		if err != nil {
			t.Errorf("JCSCanonicalize(%q): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("JCSCanonicalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestVerifyEd25519SignatureRoundTrip exercises the Ed25519 verify path.
// V1 verifier doesn't fail on signature-mismatch fixtures (stages 5-8 not
// wired), so this is unit-level coverage for the helper itself.
func TestVerifyEd25519SignatureRoundTrip(t *testing.T) {
	// Fixture 0000_v2_1_signed.json public key + signature + chain-tail.
	pk := "base64:GVHak/xHE0xBsS1K/zXf3f5XTSdINLQ568meFsvQvCw="
	sig := "base64:HEK4ohrgZ/kD+R1UZVe0Vf58TRdg4z4mxagsWp+xU5EVaauC8yFyw4dIAk/pscUSAGWJFY8RDnWNQcFDD6gLAw=="
	hash := "sha512:d21930f23d04006db2b5e35d7964891c0de43c4a43e8a757a43ecf4a4068514c389a9435ac83623e7c0929ef74bf89d228b231eae044108c7ffd416121d0fe4e"

	reason, ok := VerifyAttestationSignature(pk, sig, hash)
	if !ok {
		t.Fatalf("expected verify ok; got reason %q", reason)
	}

	// Tamper the signature.
	badSig := "base64:" + strings.Repeat("A", 86) + "=="
	reason, ok = VerifyAttestationSignature(pk, badSig, hash)
	if ok {
		t.Fatalf("expected verify reject on tampered signature; got ok")
	}
	if reason != SigDoesNotVerify {
		t.Errorf("reason = %q, want does_not_verify", reason)
	}

	// Malformed signature.
	reason, ok = VerifyAttestationSignature(pk, "base64:short", hash)
	if ok {
		t.Fatal("expected reject on short signature")
	}
	if reason != SigMalformed {
		t.Errorf("reason = %q, want malformed", reason)
	}

	// Malformed public key.
	reason, ok = VerifyAttestationSignature("base64:tooShort", sig, hash)
	if ok {
		t.Fatal("expected reject on malformed public key")
	}
	if reason != SigPublicKeyMalformed {
		t.Errorf("reason = %q, want public_key_malformed", reason)
	}
}

// ── Cross-impl helpers ───────────────────────────────────────────────

// findRustVerifier locates the Rust verifier binary on disk. Returns the path
// and `true` if found, "" and `false` otherwise.
func findRustVerifier() (string, bool) {
	candidates := []string{
		"../../target/debug/nanorix-verify",
		"../../target/release/nanorix-verify",
		"/home/dr/nanorix/target/debug/nanorix-verify",
		"/home/dr/nanorix/target/release/nanorix-verify",
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs, true
		}
	}
	return "", false
}

// runRustVerifier invokes the Rust verifier binary on a fixture path and
// returns its --json output bytes.
func runRustVerifier(bin, fixture string) ([]byte, error) {
	cmd := exec.Command(bin, "--json", fixture)
	stdout, err := cmd.Output()
	if err != nil {
		// Every exit code in the verdict-producing set still writes the full
		// JSON result to stdout; only exit 2 (malformed input) has no verdict
		// to compare. Tolerating exit 1 alone is what silently disabled this
		// entire cross-impl check: the first `dual_signature` fixture exits 3
		// ("chain verified, signature NOT checked"), which read as a harness
		// error and skipped the comparison for the rest of the corpus.
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 1, 3:
				return stdout, nil
			}
		}
		return nil, err
	}
	return stdout, nil
}

// ── ADR-051 C.1-2 — algorithm dispatch + additive-evolution tolerance ──

// TestNonEd25519AlgorithmFailsTypedAtStage4: a declared non-Ed25519 algorithm
// must fail typed as algorithm_unsupported, never fall through to the byte
// gates and report as "malformed".
func TestNonEd25519AlgorithmFailsTypedAtStage4(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["attestation"] = map[string]interface{}{"algorithm": "ML-DSA-65"}
	r := VerifyValue(proof, VerifierPolicy{})
	if r.Valid {
		t.Fatalf("expected invalid; got %+v", r)
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonAlgorithmUnsupported {
		t.Fatalf("expected algorithm_unsupported, got %+v", r.FailureReason)
	}
	if r.FailureReason.Found != "ML-DSA-65" {
		t.Errorf("found = %q, want ML-DSA-65", r.FailureReason.Found)
	}
	if r.StageReached != 4 {
		t.Errorf("stage_reached = %d, want 4", r.StageReached)
	}
}

func TestNonEd25519TopLevelSignatureAlgorithmFailsTyped(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["signature_algorithm"] = "ECDSA-P256"
	r := VerifyValue(proof, VerifierPolicy{})
	if r.Valid || r.FailureReason == nil || r.FailureReason.Type != ReasonAlgorithmUnsupported {
		t.Fatalf("expected algorithm_unsupported, got %+v", r)
	}
}

// TestUnknownFieldsDoNotDisturbVerification: additive-evolution insurance
// (ADR-051 C.2) — unknown fields must be ignored by the ladder.
func TestUnknownFieldsDoNotDisturbVerification(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["future_sibling_artifact"] = map[string]interface{}{"anything": []int{1, 2, 3}}
	proof["pqc_signature_hint"] = "reserved"
	r := VerifyValue(proof, VerifierPolicy{})
	if !r.Valid {
		t.Fatalf("unknown fields must be ignored; got %+v", r)
	}
}
