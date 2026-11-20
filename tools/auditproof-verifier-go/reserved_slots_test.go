// Reserved attestation slots: a populated one is refused at stage 2, after
// the version gate and before every other stage-2 gate, as the Rust verifier
// does (`tools/nanorix-verify/src/lib.rs`: UNSIGNED_RESERVED_SLOTS, its call
// site in verify_auditproof, and the tests from
// `every_populated_reserved_slot_is_rejected` on).

package auditproof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

// rustReservedSlots is written out here rather than read from
// unsignedReservedSlots, so a slot dropped from or reordered in the
// verifier's list fails these tests.
var rustReservedSlots = []string{
	"customer_attestation",
	"policy_attestation",
	"third_party_attestation",
	"retention_policy_attestation",
	"witness_signatures",
	"pqc_attestation",
	"customer_pqc_attestation",
}

// signedGenuineFixtures are signed corpus proofs, each valid at stage 7.
var signedGenuineFixtures = []struct{ version, path string }{
	{"2.1", "01_single_capsule_success/0001_v2_1_signed.json"},
	{"2.2", "10_v2_2/0000_v2_2_plain.json"},
}

type genuineDocument struct {
	name  string
	stage uint8 // stage a clean copy reaches, valid
	fresh func() map[string]interface{}
}

// genuineDocuments returns the minimal 1.0 proof (valid at stage 4) and,
// when the corpus is present, the signed 2.1 and 2.2 corpus proofs (valid at
// stage 7). Each call of fresh returns an unshared copy.
func genuineDocuments(t *testing.T) []genuineDocument {
	t.Helper()
	docs := []genuineDocument{{
		name:  "minimal 1.0",
		stage: 4,
		fresh: func() map[string]interface{} { return makeMinimalV1Proof("2026-05-06T12:00:00Z") },
	}}
	for _, f := range signedGenuineFixtures {
		signed := filepath.Join(corpusRoot, f.path)
		if _, err := os.Stat(signed); err != nil {
			t.Logf("signed corpus proof not available at %s: %v", signed, err)
			continue
		}
		docs = append(docs, genuineDocument{
			name:  "signed " + f.version + " " + f.path,
			stage: 7,
			fresh: func() map[string]interface{} { return readCorpusJSON(t, signed) },
		})
	}
	for _, d := range docs {
		r := VerifyValue(d.fresh(), VerifierPolicy{})
		if !r.Valid || r.StageReached != d.stage {
			t.Fatalf("%s: clean document must be valid at stage %d, got %+v", d.name, d.stage, r)
		}
	}
	return docs
}

func assertSlotRefused(t *testing.T, label string, r AuditProofVerificationResult, slot string) {
	t.Helper()
	want := &FailureReason{Type: ReasonUnsignedFieldPopulated, Field: slot}
	if r.Valid || !r.FailureReason.Equal(want) || r.StageReached != 2 {
		t.Fatalf("%s: want invalid, unsigned_field_populated %q at stage 2; got valid=%v stage=%d reason=%+v",
			label, slot, r.Valid, r.StageReached, r.FailureReason)
	}
	// Rust refuses before metadata beyond cdp_version is read.
	if r.Metadata.CdpVersion == nil || r.Metadata.CapsuleID != nil {
		t.Fatalf("%s: metadata must carry cdp_version only, got %+v", label, r.Metadata)
	}
}

func TestReservedSlotListMatchesRust(t *testing.T) {
	if !reflect.DeepEqual(unsignedReservedSlots[:], rustReservedSlots) {
		t.Fatalf("Go list %v, want %v", unsignedReservedSlots, rustReservedSlots)
	}
	src, err := os.ReadFile("../nanorix-verify/src/lib.rs")
	if err != nil {
		t.Skipf("Rust verifier source not available: %v", err)
	}
	block := regexp.MustCompile(`(?s)pub const UNSIGNED_RESERVED_SLOTS: \[&str; \d+\] = \[(.*?)\];`).FindSubmatch(src)
	if block == nil {
		t.Fatal("UNSIGNED_RESERVED_SLOTS not found in ../nanorix-verify/src/lib.rs")
	}
	// Only live entries count: a line commented out in Rust is not a slot.
	var fromRust []string
	for _, m := range regexp.MustCompile(`(?m)^\s*"([^"]+)",`).FindAllSubmatch(block[1], -1) {
		fromRust = append(fromRust, string(m[1]))
	}
	if !reflect.DeepEqual(unsignedReservedSlots[:], fromRust) {
		t.Fatalf("Go list %v differs from Rust UNSIGNED_RESERVED_SLOTS %v", unsignedReservedSlots, fromRust)
	}
}

func TestEveryPopulatedReservedSlotIsRefused(t *testing.T) {
	shapes := map[string]interface{}{
		"array":        []interface{}{map[string]interface{}{"signature": "base64:AAAA"}},
		"object":       map[string]interface{}{"fabricated": true},
		"empty object": map[string]interface{}{},
		"string":       "",
		"false":        false,
		"zero":         float64(0),
	}
	for _, doc := range genuineDocuments(t) {
		for _, slot := range rustReservedSlots {
			for shapeName, value := range shapes {
				proof := doc.fresh()
				proof[slot] = value
				assertSlotRefused(t, doc.name+" "+slot+" "+shapeName, VerifyValue(proof, VerifierPolicy{}), slot)
			}
		}
	}
}

func TestPopulatedReservedSlotIsRefusedOnTheWaveNEntryPoint(t *testing.T) {
	for _, doc := range genuineDocuments(t) {
		proof := doc.fresh()
		proof["witness_signatures"] = []interface{}{map[string]interface{}{"signature": "base64:ZZZZ"}}
		raw, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		assertSlotRefused(t, doc.name, VerifyFullAuditProofWaveN(raw, VerifierPolicy{}), "witness_signatures")
	}
}

func TestReservedSlotsNullOrAbsentStillVerify(t *testing.T) {
	for _, doc := range genuineDocuments(t) {
		proof := doc.fresh()
		for _, slot := range rustReservedSlots {
			if _, present := proof[slot]; present {
				t.Fatalf("%s: fixture already carries %s; absent case not exercised", doc.name, slot)
			}
		}
		if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid || r.StageReached != doc.stage {
			t.Fatalf("%s: slots absent must verify at stage %d, got %+v", doc.name, doc.stage, r)
		}
		for _, slot := range rustReservedSlots {
			proof[slot] = nil
		}
		proof["per_event_attestations"] = nil
		if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid || r.StageReached != doc.stage {
			t.Fatalf("%s: every slot null must verify at stage %d, got %+v", doc.name, doc.stage, r)
		}
	}
}

func TestEmptyArrayInAReservedSlotIsRefused(t *testing.T) {
	for _, doc := range genuineDocuments(t) {
		for _, slot := range rustReservedSlots {
			proof := doc.fresh()
			proof[slot] = []interface{}{}
			assertSlotRefused(t, doc.name+" "+slot+" []", VerifyValue(proof, VerifierPolicy{}), slot)
		}
	}
}

func TestSeveralPopulatedSlotsNameTheFirstInListOrder(t *testing.T) {
	for _, doc := range genuineDocuments(t) {
		for i := range rustReservedSlots {
			proof := doc.fresh()
			for _, slot := range rustReservedSlots[i:] {
				proof[slot] = []interface{}{"x"}
			}
			assertSlotRefused(t, doc.name+" from "+rustReservedSlots[i], VerifyValue(proof, VerifierPolicy{}), rustReservedSlots[i])
		}
		proof := doc.fresh()
		proof[rustReservedSlots[len(rustReservedSlots)-1]] = []interface{}{"x"}
		proof[rustReservedSlots[0]] = []interface{}{"x"}
		assertSlotRefused(t, doc.name+" first and last", VerifyValue(proof, VerifierPolicy{}), rustReservedSlots[0])
	}
}

// Rust matches the slot names exactly, so a key that differs in case or by a
// trailing space is an unknown field, ignored like any other.
func TestNearMissSlotKeysStayValid(t *testing.T) {
	for _, doc := range genuineDocuments(t) {
		for _, key := range []string{"Witness_Signatures", "witness_signatures "} {
			proof := doc.fresh()
			proof[key] = []interface{}{map[string]interface{}{"signature": "base64:AAAA"}}
			if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid || r.StageReached != doc.stage {
				t.Fatalf("%s: key %q must stay valid at stage %d, got %+v", doc.name, key, doc.stage, r)
			}
		}
	}
}

func TestPerEventAttestationsPopulatedIsStillAccepted(t *testing.T) {
	for _, doc := range genuineDocuments(t) {
		proof := doc.fresh()
		proof["per_event_attestations"] = []interface{}{map[string]interface{}{
			"algorithm":  "Ed25519",
			"public_key": "base64:AAAA",
			"signature":  "base64:BBBB",
			"event_id":   "evt_1",
		}}
		if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid || r.StageReached != doc.stage {
			t.Fatalf("%s: per_event_attestations must stay accepted at stage %d, got %+v", doc.name, doc.stage, r)
		}
	}
}

// Rust's ladder: version gate, then the reserved-slot gate, then the
// declared-activity-root gate and the two policy pins. Each case below fails
// a different gate on its own; with a slot populated as well, the earlier
// gate's verdict is the one returned.
func TestReservedSlotGatePositionInTheStage2Ladder(t *testing.T) {
	const slot = "witness_signatures"
	populated := []interface{}{map[string]interface{}{"signature": "base64:AAAA"}}

	t.Run("after the version gates", func(t *testing.T) {
		missing := makeMinimalV1Proof("2026-05-06T12:00:00Z")
		delete(missing, "cdp_version")
		missing[slot] = populated
		r := VerifyValue(missing, VerifierPolicy{})
		if !r.FailureReason.Equal(&FailureReason{Type: ReasonRequiredFieldMissing, Field: "cdp_version"}) || r.StageReached != 1 {
			t.Fatalf("missing cdp_version must win, got %+v", r)
		}
		unknown := makeMinimalV1Proof("2026-05-06T12:00:00Z")
		unknown["cdp_version"] = "9.9"
		unknown[slot] = populated
		r = VerifyValue(unknown, VerifierPolicy{})
		if !r.FailureReason.Equal(&FailureReason{Type: ReasonCdpVersionUnsupported, Found: "9.9"}) || r.StageReached != 2 {
			t.Fatalf("unsupported version must win, got %+v", r)
		}
	})

	t.Run("before the declared activity root gate", func(t *testing.T) {
		proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
		proof[CustomerDeclaredActivityRootField] = "sha512:" + NanorixGenesisHash
		alone := VerifyValue(proof, VerifierPolicy{})
		if !alone.FailureReason.Equal(&FailureReason{Type: ReasonUnsignedFieldPopulated, Field: CustomerDeclaredActivityRootField}) {
			t.Fatalf("control: a root on 1.0 alone must be refused for the root, got %+v", alone)
		}
		proof[slot] = populated
		assertSlotRefused(t, "slot and root", VerifyValue(proof, VerifierPolicy{}), slot)
	})

	t.Run("before the policy pins", func(t *testing.T) {
		for _, doc := range genuineDocuments(t) {
			for name, policy := range map[string]VerifierPolicy{
				"authority pin": {RequiredAuthorityID: "cust-authority-not-this-one"},
				"region pin":    {RequiredRegion: "region-not-this-one"},
			} {
				control := VerifyValue(doc.fresh(), policy)
				if control.Valid || control.StageReached != 2 {
					t.Fatalf("%s %s control: pin alone must refuse at stage 2, got %+v", doc.name, name, control)
				}
				proof := doc.fresh()
				proof[slot] = populated
				assertSlotRefused(t, doc.name+" "+name, VerifyValue(proof, policy), slot)
			}
		}
	})
}
