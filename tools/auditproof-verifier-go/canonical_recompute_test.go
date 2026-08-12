// Tests for the canonical-hash recompute, the signature stage, and the chain-timestamp recovery rule
// chain-timestamp recovery — the Go peers of the test module in
// the Rust verifiersrc/canonical_recompute.rs` and the chain-timestamp recovery rule block in
// the Rust verifiersrc/lib.rs`.
//
// The corpus sweep covers the signature stage end-to-end on 100 fixtures, but
// no corpus fixture omits `destroyed_at`, so the recovery path needs its own
// coverage here.

package auditproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// goldenInput is the wire form of the AuditProof document builder::test_cdp()`
// — the fixed input behind the server's `golden_canonical_hash` test. Only the
// fields the canonical view actually reads are present.
func goldenInput() map[string]interface{} {
	return map[string]interface{}{
		"cdp_version":         "2.1",
		"capsule_id":          "cap_test_0001",
		"signing_key_version": "1",
		"activity":            []interface{}{},
		"chain":               []interface{}{},
		"signing_mode":        "nanorix_only",
		"jurisdiction":        "us",
		"authority_id":        "us-kms-nanorix-v1",
		"org_id":              "00000000-0000-0000-0000-000000000001",
		"destruction_state":   "complete",
		"hash_algorithm":      "SHA-512",
		"signature_algorithm": "Ed25519",
	}
}

// TestCanonicalRecomputeMatchesServerGolden is the BYTE-EXACTNESS LOCK against
// the signer. The Go recompute must equal the server's golden `402f533e…`
// (`cdp_document.rs::golden_canonical_hash`, also asserted by the Rust
// verifier) for the same input. This is what keeps the independent Go verifier
// from silently drifting away from how proofs are actually signed — a drift
// that would make every v2.1 signature check meaningless.
func TestCanonicalRecomputeMatchesServerGolden(t *testing.T) {
	const golden = "402f533e81d78a05f386bee62a919436b8eacdea2c49397d54547bbd19dabce4" +
		"7bc95143635ee6d487e35eee037fec31ebd1f8f88b2f3f36ae2908324c74aabe"
	got := RecomputeCanonicalHash(goldenInput())
	if got != golden {
		t.Fatalf("Go canonical recompute drifted from the server golden\n  want %s\n  got  %s", golden, got)
	}
}

// TestRoundtripVerifyAndCatchCanonicalDrift proves (1) a correctly signed proof
// verifies, (2) flipping a canonical-bound field — jurisdiction, the exact
// corpus `08` drift case — is caught even though it does NOT touch the 8-step
// chain or final_hash, which is precisely what a chain-only verifier misses,
// and (3) an unsigned proof reports Absent, never a false pass.
func TestRoundtripVerifyAndCatchCanonicalDrift(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	priv := ed25519.NewKeyFromSeed(seed)

	canonical := RecomputeCanonicalHash(goldenInput())
	sig := ed25519.Sign(priv, []byte(canonical))

	signed := goldenInput()
	signed["attestation"] = map[string]interface{}{
		"algorithm":  "Ed25519",
		"public_key": base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		"signature":  base64.StdEncoding.EncodeToString(sig),
	}
	if check := VerifySignature(signed, "2.1"); check.Kind != SignatureVerified {
		t.Fatalf("correctly signed proof must verify; got kind=%v reason=%q", check.Kind, check.Reason)
	}

	drifted := goldenInput()
	for k, v := range signed {
		drifted[k] = v
	}
	drifted["jurisdiction"] = "eu"
	if check := VerifySignature(drifted, "2.1"); check.Kind != SignatureFailed {
		t.Fatalf("canonical-view drift must fail the signature; got kind=%v", check.Kind)
	}

	if check := VerifySignature(goldenInput(), "2.1"); check.Kind != SignatureAbsent {
		t.Fatalf("unsigned proof must report Absent, never a pass; got kind=%v", check.Kind)
	}
}

// ── the chain-timestamp recovery rule — chain-timestamp recovery from attestation key_id ──────────────

func TestRecoverTimestampFromKeyID(t *testing.T) {
	// The exact shape the chain specification emits for a production
	// `to_rfc3339_opts(SecondsFormat::Millis, true)` timestamp.
	if got, ok := RecoverTimestampFromKeyID("nrx-verify-2026-03-01T00-05-00.000Z-550e8400"); !ok ||
		got != "2026-03-01T00:05:00.000Z" {
		t.Errorf("millis+Z key_id: got %q ok=%v", got, ok)
	}

	// The fixture generator writes key_id without the ':' → '-' pass, so
	// restoring ':' is a no-op there; the same parser handles both encodings.
	if got, ok := RecoverTimestampFromKeyID("nrx-verify-2026-05-08T00:00:00Z-cap12345"); !ok ||
		got != "2026-05-08T00:00:00Z" {
		t.Errorf("unreplaced-colon key_id: got %q ok=%v", got, ok)
	}
}

// TestRecoveryRefusesOffShapeKeyIDs — every rejection here means "fall back to
// the pre-recovery behaviour", i.e. reject the proof. The parser never guesses.
func TestRecoveryRefusesOffShapeKeyIDs(t *testing.T) {
	bad := []string{
		"",
		"nrx-verify-",
		"some-other-prefix-2026-03-01T00-05-00Z-550e8400",
		// No 'T' separator — cannot tell date from time.
		"nrx-verify-2026-03-01-00-05-00Z-550e8400",
		// No trailing capsule fragment.
		"nrx-verify-2026-03-01T00:05:00Z",
		// Trailing delimiter with an empty fragment.
		"nrx-verify-2026-03-01T00:05:00Z-",
		// Date portion not YYYY-MM-DD.
		"nrx-verify-26-3-1T00-05-00Z-550e8400",
		// Time portion not HH:MM:SS.
		"nrx-verify-2026-03-01Tnoon-550e8400",
		// Non-digit smuggled into the time portion.
		"nrx-verify-2026-03-01T0a-05-00Z-550e8400",
	}
	for _, k := range bad {
		if got, ok := RecoverTimestampFromKeyID(k); ok {
			t.Errorf("must refuse to recover from %q, got %q", k, got)
		}
	}
}

// makePreRestorationV1Proof builds a v1.0 proof exactly as production issued it
// before the chain-timestamp recovery rule: authentic 8-step chain and NO `destroyed_at` key at all.
func makePreRestorationV1Proof() map[string]interface{} {
	const timestamp = "2026-05-06T12:00:00Z"
	proof := makeMinimalV1Proof(timestamp)
	delete(proof, "destroyed_at")
	proof["attestation"] = map[string]interface{}{
		"algorithm": "Ed25519",
		"key_id":    "nrx-verify-" + strings.ReplaceAll(timestamp, ":", "-") + "-cap_test",
	}
	return proof
}

func TestPreRestorationProofVerifiesViaKeyIDRecovery(t *testing.T) {
	r := VerifyValue(makePreRestorationV1Proof(), VerifierPolicy{})
	if !r.Valid {
		t.Fatalf("authentic pre-restoration proof must verify; got %+v", r.FailureReason)
	}
	if r.Metadata.RecoveredChainTimestamp == nil ||
		*r.Metadata.RecoveredChainTimestamp != "2026-05-06T12:00:00Z" {
		t.Fatalf("the recovered route must be visible in the verdict, not silent; got %v",
			r.Metadata.RecoveredChainTimestamp)
	}
}

// TestNativePathDoesNotReportRecoveredTimestamp — a proof carrying its own
// `destroyed_at` must be indistinguishable from pre-change behaviour and must
// NOT claim recovery. The field is omitted from the wire form entirely.
func TestNativePathDoesNotReportRecoveredTimestamp(t *testing.T) {
	r := VerifyValue(makeMinimalV1Proof("2026-05-06T12:00:00Z"), VerifierPolicy{})
	if !r.Valid {
		t.Fatalf("expected valid; got %+v", r.FailureReason)
	}
	if r.Metadata.RecoveredChainTimestamp != nil {
		t.Fatalf("must not claim recovery; got %q", *r.Metadata.RecoveredChainTimestamp)
	}
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal verdict: %v", err)
	}
	if strings.Contains(string(wire), "recovered_chain_timestamp") {
		t.Errorf("recovered_chain_timestamp must be omitted when unset, wire form was %s", wire)
	}
}

// TestRecoveryWithoutAKeyIDStillRejects is the control proving the recovery
// path — not some weakened chain check — is what accepts the fixture above.
func TestRecoveryWithoutAKeyIDStillRejects(t *testing.T) {
	proof := makePreRestorationV1Proof()
	delete(proof, "attestation")
	r := VerifyValue(proof, VerifierPolicy{})
	if r.Valid {
		t.Fatalf("no timestamp anywhere must reject; got valid=true")
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonStepHashMismatch || r.FailureReason.StepIdx != 0 {
		t.Fatalf("expected step_hash_mismatch at step 0; got %+v", r.FailureReason)
	}
}

// TestMutatedKeyIDCannotBeWeaponised is SECURITY-CRITICAL. `key_id` is covered
// by neither signed message, so an attacker can rewrite it freely. Recovery
// must therefore be unable to launder a mutated key_id into a passing verdict:
// the recovered value is an INPUT to the chain walk, and the chain hashes it
// must reproduce are signature-bound. Any key_id but the true one mismatches.
func TestMutatedKeyIDCannotBeWeaponised(t *testing.T) {
	if r := VerifyValue(makePreRestorationV1Proof(), VerifierPolicy{}); !r.Valid {
		t.Fatalf("baseline authentic proof must verify; got %+v", r.FailureReason)
	}

	for _, forged := range []string{
		"2026-05-06T12:00:01Z", // one second later
		"2020-01-01T00:00:00Z", // backdated years
		"2099-12-31T23:59:59Z", // postdated
	} {
		proof := makePreRestorationV1Proof()
		proof["attestation"] = map[string]interface{}{
			"algorithm": "Ed25519",
			"key_id":    "nrx-verify-" + strings.ReplaceAll(forged, ":", "-") + "-cap_test",
		}
		r := VerifyValue(proof, VerifierPolicy{})
		if r.Valid {
			t.Errorf("key_id rewritten to %s must NOT verify", forged)
			continue
		}
		if r.FailureReason == nil || r.FailureReason.Type != ReasonStepHashMismatch || r.FailureReason.StepIdx != 0 {
			t.Errorf("key_id %s: expected step_hash_mismatch at step 0; got %+v", forged, r.FailureReason)
		}
	}
}

// TestRegionPinFailsClosedWhenProofDeclaresNoRegion — a proof that carries no
// region cannot satisfy a residency pin. Accepting it would make the pin
// bypassable by simply omitting the field.
func TestRegionPinFailsClosedWhenProofDeclaresNoRegion(t *testing.T) {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	r := VerifyValue(proof, VerifierPolicy{RequiredRegion: "europe-west1"})
	if r.Valid {
		t.Fatalf("region pin must fail closed on a proof with no region; got valid=true")
	}
	if r.FailureReason == nil || r.FailureReason.Type != ReasonRegionMismatch {
		t.Fatalf("expected region_mismatch; got %+v", r.FailureReason)
	}
	if r.FailureReason.Required != "europe-west1" || r.FailureReason.Actual != "" {
		t.Errorf("expected required=europe-west1 actual=\"\"; got required=%q actual=%q",
			r.FailureReason.Required, r.FailureReason.Actual)
	}
	if r.StageReached != 2 {
		t.Errorf("region pin fires at stage 2; got %d", r.StageReached)
	}
}
