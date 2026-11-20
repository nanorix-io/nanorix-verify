package auditproof

import (
	"fmt"
	"testing"
)

// RequiredRegion reads only a signed region. Mirrors the residency_pin tests
// in tools/nanorix-verify/src/lib.rs.

func regionProof(version string, region string) map[string]interface{} {
	proof := makeMinimalV1Proof("2026-05-06T12:00:00Z")
	proof["cdp_version"] = version
	if region != "" {
		proof["activity"] = []interface{}{
			map[string]interface{}{"event": "capsule_started", "region": region},
		}
	}
	return proof
}

// On a signed 2.1 or 2.2 proof the activity trail is inside the signed
// canonical view, so the pin compares the region on the capsule_started event.
func TestRegionPinComparesTheSignedRegion(t *testing.T) {
	for _, version := range []string{"2.1", "2.2"} {
		proof := signTrailProof(t, regionProof(version, "europe-west1"))
		if r := VerifyValue(proof, VerifierPolicy{RequiredRegion: "europe-west1"}); !r.Valid || r.StageReached != 7 {
			t.Errorf("%s: matching pin want valid at stage 7; got %+v", version, r)
		}
		r := VerifyValue(proof, VerifierPolicy{RequiredRegion: "us-central1"})
		want := FailureReason{Type: ReasonRegionMismatch, Required: "us-central1", Actual: "europe-west1"}
		if r.Valid || r.StageReached != 2 || !r.FailureReason.Equal(&want) {
			t.Errorf("%s: disagreeing pin want %+v at stage 2; got %+v", version, want, r)
		}
	}
}

// cdp_version 1.0 signs only final_hash, so its activity trail, and the region
// in it, is unsigned: anyone could add a capsule_started region equal to the
// pin to a genuine 1.0 proof. Under a pin every 1.0 proof is refused with an
// empty actual, whatever region it states; without a pin it verifies.
func TestRegionPinRefusesEveryV1Proof(t *testing.T) {
	want := FailureReason{Type: ReasonRegionMismatch, Required: "europe-west1", Actual: ""}
	for _, stated := range []string{"europe-west1", "us-central1", ""} {
		label := fmt.Sprintf("1.0 stating %q", stated)
		proof := regionProof("1.0", stated)
		r := VerifyValue(proof, VerifierPolicy{RequiredRegion: "europe-west1"})
		if r.Valid || r.StageReached != 2 || !r.FailureReason.Equal(&want) {
			t.Errorf("%s: want %+v at stage 2; got %+v", label, want, r)
		}
		if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid {
			t.Errorf("%s: without a pin want valid; got %+v", label, r)
		}
	}
}

// A 2.1 or 2.2 proof without a signature has an unsigned trail, like a 1.0
// proof: under a pin it is refused with an empty actual, whatever region it
// states; without a pin it verifies at stage 4.
func TestRegionPinRefusesAnUnsignedProof(t *testing.T) {
	want := FailureReason{Type: ReasonRegionMismatch, Required: "europe-west1", Actual: ""}
	for _, version := range []string{"2.1", "2.2"} {
		for _, stated := range []string{"europe-west1", "us-central1", ""} {
			label := fmt.Sprintf("unsigned %s stating %q", version, stated)
			proof := regionProof(version, stated)
			r := VerifyValue(proof, VerifierPolicy{RequiredRegion: "europe-west1"})
			if r.Valid || r.StageReached != 2 || !r.FailureReason.Equal(&want) {
				t.Errorf("%s: want %+v at stage 2; got %+v", label, want, r)
			}
			// No return of an unsigned trail names the region it states.
			if r.Metadata.Region != nil {
				t.Errorf("%s: the refusal names the unsigned region %q", label, *r.Metadata.Region)
			}
			if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid || r.StageReached != 4 {
				t.Errorf("%s: without a pin want valid at stage 4; got %+v", label, r)
			}
		}
	}
}
