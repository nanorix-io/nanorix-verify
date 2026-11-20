package auditproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

type strictVector struct {
	Name         string   `json:"name"`
	PublicKeyHex string   `json:"public_key_hex"`
	SignatureHex string   `json:"signature_hex"`
	Messages     []string `json:"messages"`
	MustReject   bool     `json:"must_reject"`
	Permissive   struct {
		Go bool `json:"go"`
	} `json:"permissive_accepts"`
}

type registrationVector struct {
	PublicKeyHex   string   `json:"public_key_hex"`
	SignatureHex   string   `json:"signature_hex"`
	Messages       []string `json:"messages"`
	VerifiesStrict bool     `json:"verifies_under_strict_verify"`
}

type strictFixture struct {
	Vectors      []strictVector       `json:"vectors"`
	Registration []registrationVector `json:"registration_negative_vectors"`
	SmallOrder   []string             `json:"small_order_point_encodings_hex"`
	NonCanonical []string             `json:"non_canonical_point_encodings_hex"`
}

func loadStrictFixture(t *testing.T) strictFixture {
	t.Helper()
	raw, err := os.ReadFile("../../tests/vectors/ed25519_strict_negative.json")
	if err != nil {
		t.Fatal(err)
	}
	var f strictFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestStrictFixtureMatchesStdlibVerdict(t *testing.T) {
	accepted := 0
	for _, v := range loadStrictFixture(t).Vectors {
		pk, _ := hex.DecodeString(v.PublicKeyHex)
		sig, _ := hex.DecodeString(v.SignatureHex)
		for _, m := range v.Messages {
			if got := ed25519.Verify(pk, []byte(m), sig); got != v.Permissive.Go {
				t.Fatalf("%s: stdlib Verify = %v, fixture permissive_accepts.go = %v", v.Name, got, v.Permissive.Go)
			}
			if v.Permissive.Go {
				accepted++
			}
		}
	}
	if accepted == 0 {
		t.Fatal("fixture has no vector the stdlib verifier accepts")
	}
}

func TestMixedOrderKeyStillVerifiesAtProofTime(t *testing.T) {
	fx := loadStrictFixture(t)
	if len(fx.Registration) == 0 {
		t.Fatal("fixture has no registration vectors")
	}
	for _, v := range fx.Registration {
		pk, _ := hex.DecodeString(v.PublicKeyHex)
		sig, _ := hex.DecodeString(v.SignatureHex)
		for _, m := range v.Messages {
			if got := verifyEd25519Strict(pk, []byte(m), sig); got != v.VerifiesStrict {
				t.Fatalf("mixed-order vector: strict verify = %v, fixture says %v", got, v.VerifiesStrict)
			}
		}
	}
}

func TestVerifyEd25519StrictRejectsFixture(t *testing.T) {
	for _, v := range loadStrictFixture(t).Vectors {
		if !v.MustReject {
			t.Fatalf("%s: shared vectors must all be must_reject", v.Name)
		}
		pk, _ := hex.DecodeString(v.PublicKeyHex)
		sig, _ := hex.DecodeString(v.SignatureHex)
		for _, m := range v.Messages {
			if verifyEd25519Strict(pk, []byte(m), sig) {
				t.Fatalf("%s: strict verify accepted a must_reject vector", v.Name)
			}
		}
	}
}

func TestSmallOrderListMatchesFixture(t *testing.T) {
	want := loadStrictFixture(t).SmallOrder
	var got []string
	for _, e := range smallOrderEncodings {
		got = append(got, hex.EncodeToString(e[:]))
	}
	sort.Strings(want)
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("list length %d != fixture %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("entry %d: %s != %s", i, got[i], want[i])
		}
	}
}

func TestVerifyEd25519StrictAcceptsHonestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := ed25519.Sign(priv, []byte("honest"))
	if !verifyEd25519Strict(pub, []byte("honest"), sig) {
		t.Fatal("honest signature rejected")
	}
}

// Refusal only: the honest S does not complete a signature the stdlib verifier
// would accept under these keys or R values. The permissive-valid cases are the
// shared fixture vectors.
func TestSmallOrderEncodingsRefusedAsKeyAndAsRRefusalOnly(t *testing.T) {
	fx := loadStrictFixture(t)
	if len(fx.SmallOrder) != 14 {
		t.Fatalf("fixture has %d small-order encodings, want 14", len(fx.SmallOrder))
	}
	honestPub, honestPriv, _ := ed25519.GenerateKey(nil)
	honestSig := ed25519.Sign(honestPriv, []byte("m"))
	for _, h := range fx.SmallOrder {
		enc, _ := hex.DecodeString(h)
		asKey := append(append([]byte{}, enc...), honestSig[32:]...)
		if verifyEd25519Strict(enc, []byte("m"), asKey) {
			t.Fatalf("%s: accepted as public key", h)
		}
		asR := append(append([]byte{}, enc...), honestSig[32:]...)
		if verifyEd25519Strict(honestPub, []byte("m"), asR) {
			t.Fatalf("%s: accepted as R", h)
		}
	}
}

func TestEntryPointsRejectFixture(t *testing.T) {
	b64 := base64.StdEncoding
	for _, v := range loadStrictFixture(t).Vectors {
		pk, _ := hex.DecodeString(v.PublicKeyHex)
		sig, _ := hex.DecodeString(v.SignatureHex)
		for _, m := range v.Messages {
			if _, ok := VerifyAttestationSignature(b64.EncodeToString(pk), b64.EncodeToString(sig), m); ok {
				t.Fatalf("%s: VerifyAttestationSignature accepted a must_reject vector", v.Name)
			}
			if c := verifyMessageWithKey(m, b64.EncodeToString(sig), b64.EncodeToString(pk)); c.Kind != SignatureFailed {
				t.Fatalf("%s: verifyMessageWithKey accepted a must_reject vector", v.Name)
			}
		}
	}
}

func TestNonCanonicalEncodingsRejectedAsKeyAndAsR(t *testing.T) {
	fx := loadStrictFixture(t)
	if len(fx.NonCanonical) != 20 {
		t.Fatalf("fixture has %d non-canonical encodings, want 20", len(fx.NonCanonical))
	}
	honestPub, honestPriv, _ := ed25519.GenerateKey(nil)
	base, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
	one := make([]byte, 32)
	one[0] = 1
	msg := []byte("m")
	for _, h := range fx.NonCanonical {
		enc, _ := hex.DecodeString(h)
		if !isNonCanonicalEncoding(enc) || !hasSmallOrderEncoding(enc) {
			t.Fatalf("%s: predicate did not flag a non-canonical encoding", h)
		}
		asKey := append(append([]byte{}, base...), one...)
		if verifyEd25519Strict(enc, msg, asKey) {
			t.Fatalf("%s: accepted as public key", h)
		}
		asR := append(append([]byte{}, enc...), one...)
		if verifyEd25519Strict(honestPub, msg, asR) {
			t.Fatalf("%s: accepted as R", h)
		}
	}
	if !verifyEd25519Strict(honestPub, msg, ed25519.Sign(honestPriv, msg)) {
		t.Fatal("honest signature rejected")
	}
}

type positiveVector struct {
	PublicKeyHex string `json:"public_key_hex"`
	MessageHex   string `json:"message_hex"`
	SignatureHex string `json:"signature_hex"`
}

func TestStrictAcceptsEveryGenuinePositiveVector(t *testing.T) {
	raw, err := os.ReadFile("../../tests/vectors/ed25519_strict_positive.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []positiveVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) != 64 {
		t.Fatalf("fixture has %d vectors, want 64", len(doc.Vectors))
	}
	b64 := base64.StdEncoding
	for i, v := range doc.Vectors {
		pk, _ := hex.DecodeString(v.PublicKeyHex)
		msg, _ := hex.DecodeString(v.MessageHex)
		sig, _ := hex.DecodeString(v.SignatureHex)
		if !verifyEd25519Strict(pk, msg, sig) {
			t.Fatalf("vector %d: strict verify refused a genuine signature", i)
		}
		if _, ok := VerifyAttestationSignature(b64.EncodeToString(pk), b64.EncodeToString(sig), string(msg)); !ok {
			t.Fatalf("vector %d: VerifyAttestationSignature refused a genuine signature", i)
		}
		if c := verifyMessageWithKey(string(msg), b64.EncodeToString(sig), b64.EncodeToString(pk)); c.Kind == SignatureFailed {
			t.Fatalf("vector %d: verifyMessageWithKey refused a genuine signature", i)
		}
	}
}
