// Test suite for the Go reference verifier.
//
// **Cross-impl byte-equivalence (binding contract):** every fixture in
// `tools/nanorix-verify/fixtures/corpus/` must produce a Go-side verification
// output that is byte-identical to the Rust verifier output. Divergence on
// even one fixture is a P0 finding release framing
// + an internal design rule.
//
// Property-test fault injection:
// 10k iterations of random AuditProof bytes — malformed JSON, wrong field
// types, off-by-one chain values, tampered signatures — every fault path must
// produce a deterministic FailureReason from the closed-set enum.

package auditproof

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
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
	// the published corpus (an earlier release verification-surface scaffolds).
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

// TestVerifyRefusesCdpVersion2_0AtStage2 mirrors the Rust library test of the
// same refusal: a 2.0-labelled document is refused at the version gate with
// the found value, with or without a declared activity root.
func TestVerifyRefusesCdpVersion2_0AtStage2(t *testing.T) {
	cases := []map[string]interface{}{
		{"cdp_version": "2.0"},
		{"cdp_version": "2.0", "document_hash": "sha512:" + strings.Repeat("ab", 64)},
		{"cdp_version": "2.0", CustomerDeclaredActivityRootField: "sha512:" + strings.Repeat("ab", 64)},
	}
	for _, proof := range cases {
		r := VerifyValue(proof, VerifierPolicy{})
		if r.Valid {
			t.Fatalf("expected invalid for %v", proof)
		}
		if r.StageReached != 2 {
			t.Errorf("stage_reached = %d, want 2", r.StageReached)
		}
		if r.FailureReason == nil || r.FailureReason.Type != ReasonCdpVersionUnsupported || r.FailureReason.Found != "2.0" {
			t.Errorf("failure_reason = %+v", r.FailureReason)
		}
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

const (
	testPin     = "customer-hsm-example-org-v1"
	testNanorix = "us-kms-nanorix-v1"
)

// assertAuthorityReject checks a stage-2 pin rejection down to the wire
// fields. claimed == nil means the claimed authority must be null.
func assertAuthorityReject(t *testing.T, label string, r AuditProofVerificationResult, claimed *string, reason AuthorityIDMismatchReason) {
	t.Helper()
	if r.Valid {
		t.Fatalf("%s: expected reject; got %+v", label, r)
	}
	if r.StageReached != 2 {
		t.Errorf("%s: stage_reached = %d, want 2", label, r.StageReached)
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonAuthorityIDMismatch {
		t.Fatalf("%s: failure_reason = %+v", label, r.FailureReason)
	}
	got := r.FailureReason.ClaimedAuthorityID
	switch {
	case claimed == nil && got != nil:
		t.Errorf("%s: claimed = %q, want null", label, *got)
	case claimed != nil && (got == nil || *got != *claimed):
		t.Errorf("%s: claimed = %v, want %q", label, got, *claimed)
	}
	if r.FailureReason.ExpectedAuthorityID != testPin {
		t.Errorf("%s: expected_authority_id = %q", label, r.FailureReason.ExpectedAuthorityID)
	}
	if r.FailureReason.AuthIDReason != reason {
		t.Errorf("%s: reason = %q, want %q", label, r.FailureReason.AuthIDReason, reason)
	}
}

// pinProof builds an unsigned minimal proof on cdp_version 2.1, a version that
// signs the top-level authority_id. pinProofVersion picks the version.
func pinProof(top string, signingAuthority interface{}, withSA bool) map[string]interface{} {
	return pinProofVersion("2.1", top, signingAuthority, withSA)
}

func pinProofVersion(version, top string, signingAuthority interface{}, withSA bool) map[string]interface{} {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["cdp_version"] = version
	if top != "" {
		proof["authority_id"] = top
	}
	if withSA {
		proof["signing_authority"] = signingAuthority
	}
	return proof
}

// TestPolicyPinBindsTopLevelAuthority mirrors the Rust pin tests: the
// pin compares the signed top-level authority_id, absent means the default.
func TestPolicyPinBindsTopLevelAuthority(t *testing.T) {
	policy := VerifierPolicy{RequiredAuthorityID: testPin}

	// pin equals top-level, no signing_authority: gate passes.
	if r := VerifyValue(pinProof(testPin, nil, false), policy); !r.Valid || r.StageReached != 4 {
		t.Errorf("equal pin: expected valid at stage 4; got %+v", r)
	}
	// pin differs from top-level: mismatch, claimed = top-level.
	nanorix := testNanorix
	assertAuthorityReject(t, "differs", VerifyValue(pinProof(testNanorix, nil, false), policy),
		&nanorix, AuthIDPolicyAuthorityIDMismatch)
	// top-level absent: pin on the default passes, any other pin is has_none.
	if r := VerifyValue(pinProof("", nil, false), VerifierPolicy{RequiredAuthorityID: testNanorix}); !r.Valid {
		t.Errorf("default pin: expected valid; got %+v", r)
	}
	assertAuthorityReject(t, "absent", VerifyValue(pinProof("", nil, false), policy),
		nil, AuthIDPolicyDemandsCustomerHSMHasNone)
	// non-string top-level resolves to the default too.
	p := pinProof("", nil, false)
	p["authority_id"] = float64(7)
	if r := VerifyValue(p, VerifierPolicy{RequiredAuthorityID: testNanorix}); !r.Valid {
		t.Errorf("non-string default pin: expected valid; got %+v", r)
	}
	assertAuthorityReject(t, "non-string", VerifyValue(p, policy), nil, AuthIDPolicyDemandsCustomerHSMHasNone)
}

// TestPolicyPinUnsignedSigningAuthorityCannotMatch is the attack: a genuine
// proof under the Nanorix authority plus an unsigned signing_authority naming
// the pin is refused, whether or not the top-level field is present.
func TestPolicyPinUnsignedSigningAuthorityCannotMatch(t *testing.T) {
	policy := VerifierPolicy{RequiredAuthorityID: testPin}
	pin := testPin
	for _, top := range []string{testNanorix, ""} {
		proof := pinProof(top, map[string]interface{}{"authority_id": testPin}, true)
		assertAuthorityReject(t, "attack top="+top, VerifyValue(proof, policy), &pin, AuthIDPolicyAuthorityIDMismatch)
	}
}

// TestPolicyPinUnsignedAuthorityOnV1RefusesV2_0First covers cdp_version 1.0,
// whose signature covers no authority_id: an added top-level string other than
// the default is refused at stage 2 whatever the pin, and a pin accepts only
// the default there. The same cases relabelled 2.0 are refused at the version
// gate before the pin is read, so no pin or label can reopen 2.0.
func TestPolicyPinUnsignedAuthorityOnV1RefusesV2_0First(t *testing.T) {
	pin := testPin
	empty := ""
	type pinCase struct {
		name   string
		top    string
		empty  bool
		policy VerifierPolicy
	}
	cases := []pinCase{
		{"relabel", testPin, false, VerifierPolicy{RequiredAuthorityID: testPin}},
		{"empty", "", true, VerifierPolicy{RequiredAuthorityID: testPin}},
		{"default pin", "", false, VerifierPolicy{RequiredAuthorityID: testNanorix}},
		{"default label and pin", testNanorix, false, VerifierPolicy{RequiredAuthorityID: testNanorix}},
		{"absent", "", false, VerifierPolicy{RequiredAuthorityID: testPin}},
		{"no pin", testPin, false, VerifierPolicy{}},
	}
	build := func(version string, c pinCase) map[string]interface{} {
		p := pinProofVersion(version, c.top, nil, false)
		if c.empty {
			p["authority_id"] = ""
		}
		return p
	}
	for _, c := range cases {
		r := VerifyValue(build("1.0", c), c.policy)
		label := "1.0 " + c.name
		switch c.name {
		case "relabel":
			// top-level equal to the pin is still refused.
			assertAuthorityReject(t, label, r, &pin, AuthIDPolicyAuthorityIDMismatch)
		case "empty":
			// the empty string is a string other than the default.
			assertAuthorityReject(t, label, r, &empty, AuthIDPolicyAuthorityIDMismatch)
		case "absent":
			// any other pin on an unlabelled proof is has_none.
			assertAuthorityReject(t, label, r, nil, AuthIDPolicyDemandsCustomerHSMHasNone)
		default:
			// default pin, default label, and no pin are accepted.
			if !r.Valid || r.StageReached != 4 {
				t.Errorf("%s: expected valid at stage 4; got %+v", label, r)
			}
		}
	}
	for _, c := range cases {
		r := VerifyValue(build("2.0", c), c.policy)
		if r.Valid || r.StageReached != 2 || r.FailureReason == nil ||
			r.FailureReason.Type != ReasonCdpVersionUnsupported || r.FailureReason.Found != "2.0" {
			t.Errorf("2.0 %s: expected cdp_version_unsupported at stage 2; got %+v", c.name, r)
		}
	}
}

// TestPolicyPinDecisionTable runs every (top-level, signing_authority) row.
func TestPolicyPinDecisionTable(t *testing.T) {
	const other = "customer-hsm-other-v1"
	const diff = "customer-hsm-forged-v1"
	policy := VerifierPolicy{RequiredAuthorityID: testPin}
	for _, top := range []string{"", testPin, other} {
		effective := top
		if effective == "" {
			effective = testNanorix
		}
		shapes := map[string]struct {
			sa   interface{}
			with bool
		}{
			"absent":    {nil, false},
			"null":      {nil, true},
			"no_id":     {map[string]interface{}{"x": float64(1)}, true},
			"equal_top": {map[string]interface{}{"authority_id": effective}, true},
			"different": {map[string]interface{}{"authority_id": diff}, true},
		}
		for name, sh := range shapes {
			label := "top=" + top + " sa=" + name
			r := VerifyValue(pinProof(top, sh.sa, sh.with), policy)
			d, tp := diff, top
			switch {
			case name == "different":
				assertAuthorityReject(t, label, r, &d, AuthIDPolicyAuthorityIDMismatch)
			case effective == testPin:
				if !r.Valid || r.StageReached != 4 {
					t.Errorf("%s: expected valid at stage 4; got %+v", label, r)
				}
			case top == "":
				assertAuthorityReject(t, label, r, nil, AuthIDPolicyDemandsCustomerHSMHasNone)
			default:
				assertAuthorityReject(t, label, r, &tp, AuthIDPolicyAuthorityIDMismatch)
			}
		}
	}
}

// TestPolicyNoPinAcceptsAnySigningAuthority keeps the no-pin behaviour.
func TestPolicyNoPinAcceptsAnySigningAuthority(t *testing.T) {
	for _, sa := range []interface{}{
		nil,
		map[string]interface{}{"authority_id": testPin},
		map[string]interface{}{"x": float64(1)},
	} {
		r := VerifyValue(pinProof("", sa, true), VerifierPolicy{})
		if !r.Valid {
			t.Errorf("no pin, sa=%v: expected valid; got %+v", sa, r)
		}
	}
}

// TestFixtureCorpusByteEquivalentWithRust walks the reference corpus shipped
// at `tools/nanorix-verify/fixtures/corpus/`, runs the Go verifier on each
// proof JSON, runs the Rust verifier (via the binary at
// `target/debug/nanorix-verify` if present), and asserts byte-identical JSON
// output.
//
// **This is the primary cross-impl byte-equivalence assertion.**
// Release framing +
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
	notAnchoredCount := 0
	notVerifiedCount := 0
	divergent := []string{}

	for _, fx := range fixtures {
		bytes, err := os.ReadFile(fx)
		if err != nil {
			t.Fatalf("read %s: %v", fx, err)
		}
		goResult := Verify(bytes, VerifierPolicy{})
		switch goResult.Status() {
		case "verified":
			verifiedCount++
		case "not_anchored":
			notAnchoredCount++
		default:
			notVerifiedCount++
		}

		if !rustAvailable {
			continue
		}

		// Run the Rust verifier on the same fixture and compare JSON output.
		rustOut, rustExit, err := runRustVerifier(rustBin, fx)
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
		rustRaw := strings.TrimRight(string(rustOut), "\n")
		goNorm := strings.TrimRight(string(goJSON), "\n")
		if rustRaw == "" {
			// Nothing on stdout: the Rust CLI refused bytes its JSON parser
			// cannot read, before verification, so there is no verdict and no
			// status to pair with the exit. That refusal is exit 1, and Go must
			// refuse the bytes too, in the form the corpus pins for them.
			r := goResult.FailureReason
			if rustExit != 1 || goResult.Valid || goResult.StageReached != 1 || r == nil ||
				r.Type != ReasonRequiredFieldMissing || r.Field != "json_root" {
				divergent = append(divergent, fx)
				t.Errorf("DIVERGENT: %s\n--- Rust ---\nno verdict, exit %d (a refusal exits 1)\n--- Go ---\n%s", fx, rustExit, goNorm)
			}
			continue
		}
		rustNorm, rustStatus, ok := splitRustStatus(rustRaw)
		if !ok {
			t.Errorf("rust --json output for %s ends without its status member:\n%s", fx, rustOut)
			continue
		}
		if want := goResult.Status(); rustStatus != want {
			t.Errorf("rust status for %s is %q; the Go result gives %q", fx, rustStatus, want)
		}
		if !rustExitMatchesStatus(rustExit, rustStatus) {
			t.Errorf("rust exit for %s is %d with status %q; verified exits 0, not_anchored 4, not_verified 1 or 3", fx, rustExit, rustStatus)
		}
		if rustNorm != goNorm {
			divergent = append(divergent, fx)
			if len(divergent) <= 3 {
				t.Errorf("DIVERGENT: %s\n--- Rust ---\n%s\n--- Go ---\n%s", fx, rustNorm, goNorm)
			}
		}
	}

	t.Logf("Fixture corpus under the empty policy: %d total · %d verified · %d not_anchored · %d not_verified · %d divergent",
		len(fixtures), verifiedCount, notAnchoredCount, notVerifiedCount, len(divergent))

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
// injection. Random
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
// been tampered with — Forever-Standard violation.
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

// TestJCSCanonicalizeNumbers pins the ECMAScript Number::toString behaviour
// RFC 8785 §3.2.2.3 requires, and which must stay byte-equivalent to Rust
// serde_jcs. Each `want` below is what String(x) / serde_jcs produce.
func TestJCSCanonicalizeNumbers(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// exponential form: '+' is mandatory on positive exponents...
		{`{"n":1e21}`, `{"n":1e+21}`},
		{`{"n":1e30}`, `{"n":1e+30}`},
		// ...and no leading zero on negative exponents.
		{`{"n":1e-7}`, `{"n":1e-7}`},
		{`{"n":5e-324}`, `{"n":5e-324}`},
		// positional form up to (but not including) 1e21 and down to 1e-6.
		{`{"n":1e20}`, `{"n":100000000000000000000}`},
		{`{"n":1.5e19}`, `{"n":15000000000000000000}`},
		{`{"n":1e-5}`, `{"n":0.00001}`},
		{`{"n":1e-6}`, `{"n":0.000001}`},
		// shortest round-trip: the canonical text must parse back to the
		// same double (0.1 + 0.2 is the classic 17-significant-digit case).
		{`{"n":0.30000000000000004}`, `{"n":0.30000000000000004}`},
		{`{"n":123456789012345680.0}`, `{"n":123456789012345680}`},
		{`{"n":-0.0001}`, `{"n":-0.0001}`},
		// a mantissa with several digits in exponential form, both signs.
		{`{"n":1.5e300}`, `{"n":1.5e+300}`},
		{`{"n":-1.25e-7}`, `{"n":-1.25e-7}`},
		{`{"n":1.5}`, `{"n":1.5}`},
		// the largest double, and the last positional value below 1e21.
		{`{"n":1.7976931348623157e308}`, `{"n":1.7976931348623157e+308}`},
		{`{"n":999999999999999900000}`, `{"n":999999999999999900000}`},
		// integers: exact up to 2^53, rounded to the nearest double beyond it,
		// as serde_jcs writes every integer through f64.
		{`{"n":9007199254740992}`, `{"n":9007199254740992}`},
		{`{"n":9007199254740993}`, `{"n":9007199254740992}`},
		{`{"n":-9007199254740993}`, `{"n":-9007199254740992}`},
		{`{"n":9223372036854775807}`, `{"n":9223372036854776000}`},
		{`{"n":-9223372036854775808}`, `{"n":-9223372036854776000}`},
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

// TestJCSRefusesNonFiniteNumbers covers the float64 branch of jcsEmit, which
// JCSCanonicalize never reaches (it decodes with UseNumber), and number text
// too large for a double.
func TestJCSRefusesNonFiniteNumbers(t *testing.T) {
	for _, f := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		var buf bytes.Buffer
		if err := jcsEmit(&buf, f); err == nil {
			t.Errorf("jcsEmit(%v) wrote %q, want an error", f, buf.String())
		}
	}
	if got, err := JCSCanonicalize([]byte(`{"n":1e999}`)); err == nil {
		t.Errorf("JCSCanonicalize(1e999) = %q, want an error", got)
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
// returns its --json output bytes and exit code.
func runRustVerifier(bin, fixture string) ([]byte, int, error) {
	cmd := exec.Command(bin, "--json", fixture)
	stdout, err := cmd.Output()
	if err != nil {
		// Every exit code in the verdict-producing set still writes the full
		// JSON result to stdout, except exit 1 for a file that is not JSON,
		// which writes nothing; exit 2 (a usage or setup error) has no verdict to
		// compare. Tolerating exit 1 alone is what silently disabled this
		// entire cross-impl check: the first `dual_signature` fixture exits 3
		// ("chain verified, signature NOT checked"), which read as a harness
		// error and skipped the comparison for the rest of the corpus.
		// Exit 4 is a stage 7 result: valid against the embedded key only.
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 1, 3, 4:
				return stdout, exitErr.ExitCode(), nil
			}
		}
		return nil, 0, err
	}
	return stdout, 0, nil
}

// rustExitMatchesStatus reports whether a Rust single-file exit code is the
// one its status carries: 0 for verified, 4 for not_anchored, 1 or 3 for
// not_verified.
func rustExitMatchesStatus(code int, status string) bool {
	switch status {
	case "verified":
		return code == 0
	case "not_anchored":
		return code == 4
	case "not_verified":
		return code == 1 || code == 3
	}
	return false
}

// splitRustStatus removes the `status` member the Rust single-file --json
// output appends after the verification result, and returns both. The rest
// is the result itself, compared byte for byte with the Go output.
func splitRustStatus(out string) (string, string, bool) {
	const prefix = ",\n  \"status\": \""
	const suffix = "\"\n}"
	i := strings.LastIndex(out, prefix)
	if i < 0 || !strings.HasSuffix(out, suffix) {
		return "", "", false
	}
	status := out[i+len(prefix) : len(out)-len(suffix)]
	if strings.ContainsAny(status, "\"\n") {
		return "", "", false
	}
	return out[:i] + "\n}", status, true
}

// ── the EU signing profile — algorithm dispatch + additive-evolution tolerance ──

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
// — unknown fields must be ignored by the ladder.
func TestUnknownFieldsDoNotDisturbVerification(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["future_sibling_artifact"] = map[string]interface{}{"anything": []int{1, 2, 3}}
	proof["pqc_signature_hint"] = "reserved"
	r := VerifyValue(proof, VerifierPolicy{})
	if !r.Valid {
		t.Fatalf("unknown fields must be ignored; got %+v", r)
	}
}
