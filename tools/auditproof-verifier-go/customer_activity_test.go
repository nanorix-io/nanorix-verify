// Tests for the ADR-056 customer-declared activity root — the Go peer of the
// test module in `tools/nanorix-verify/src/customer_activity.rs`. Every vector
// in the shared JSON file is exercised; the file is read, not copied, so Go
// cannot drift from what Rust, Python and TypeScript test against.

package auditproof

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const activityRootVectorsPath = "../nanorix-verify/fixtures/customer_declared_activity_root_vectors.json"

type activityRootVector struct {
	Name       string   `json:"name"`
	InputUTF8  string   `json:"input_utf8"`
	LineCount  int      `json:"line_count"`
	LeafHashes []string `json:"leaf_hashes"`
	Root       string   `json:"root"`
}

func loadActivityRootVectors(t *testing.T) []activityRootVector {
	t.Helper()
	raw, err := os.ReadFile(activityRootVectorsPath)
	if err != nil {
		t.Fatalf("read vectors %s: %v", activityRootVectorsPath, err)
	}
	var doc struct {
		Vectors []activityRootVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(doc.Vectors) != 5 {
		t.Fatalf("every pinned vector must be exercised: want 5, got %d", len(doc.Vectors))
	}
	return doc.Vectors
}

func activityRootVector3(t *testing.T) activityRootVector {
	t.Helper()
	for _, v := range loadActivityRootVectors(t) {
		if v.Name == "three" {
			return v
		}
	}
	t.Fatal("vector `three` missing")
	return activityRootVector{}
}

func TestCustomerActivityEveryPinnedVectorReproduces(t *testing.T) {
	for _, v := range loadActivityRootVectors(t) {
		input := []byte(v.InputUTF8)

		if got := len(SplitActivityLines(input)); got != v.LineCount {
			t.Errorf("%s: line_count: got %d, want %d", v.Name, got, v.LineCount)
		}

		leaves := CustomerDeclaredActivityLeafHashes(input)
		if len(leaves) != len(v.LeafHashes) {
			t.Fatalf("%s: leaf count: got %d, want %d", v.Name, len(leaves), len(v.LeafHashes))
		}
		for i := range leaves {
			if leaves[i] != v.LeafHashes[i] {
				t.Errorf("%s: leaf[%d]: got %s, want %s", v.Name, i, leaves[i], v.LeafHashes[i])
			}
		}

		if got := ComputeCustomerDeclaredActivityRoot(input); got != v.Root {
			t.Errorf("%s: root: got %s, want %s", v.Name, got, v.Root)
		}
	}
}

func TestCustomerActivityEmptyRecordIsGenesis(t *testing.T) {
	if got := ComputeCustomerDeclaredActivityRoot(nil); got != "sha512:"+NanorixGenesisHash {
		t.Fatalf("empty record root: got %s", got)
	}
}

// A lone newline is one empty line, not zero lines — only the trailing empty
// segment is dropped. Its root nevertheless equals the genesis root: a single
// leaf is its own root, and the leaf of an empty line is SHA-512 of nothing.
// The pinned algorithm makes "declared nothing" and "declared one empty line"
// the same commitment; stated here so nobody reads the coincidence as a bug.
func TestCustomerActivityLoneNewlineIsOneEmptyLeaf(t *testing.T) {
	if got := SplitActivityLines([]byte("\n")); len(got) != 1 || len(got[0]) != 0 {
		t.Fatalf("lone newline: got %v", got)
	}
	got := SplitActivityLines([]byte("a\n\nb\n"))
	if len(got) != 3 || string(got[0]) != "a" || len(got[1]) != 0 || string(got[2]) != "b" {
		t.Fatalf("a\\n\\nb\\n: got %v", got)
	}
	if ComputeCustomerDeclaredActivityRoot([]byte("\n")) != ComputeCustomerDeclaredActivityRoot(nil) {
		t.Fatal("one empty leaf must equal the genesis root (single leaf = leaf hash = SHA-512(\"\"))")
	}
	if ComputeCustomerDeclaredActivityRoot([]byte("\n\n")) == ComputeCustomerDeclaredActivityRoot(nil) {
		t.Fatal("two empty leaves must differ from genesis")
	}
}

func TestCustomerActivityAnyByteFlipMovesTheRoot(t *testing.T) {
	v := activityRootVector3(t)
	input := []byte(v.InputUTF8)
	root := ComputeCustomerDeclaredActivityRoot(input)
	for i := range input {
		if input[i] == '\n' {
			continue
		}
		flipped := append([]byte(nil), input...)
		flipped[i] ^= 0x01
		if ComputeCustomerDeclaredActivityRoot(flipped) == root {
			t.Fatalf("flip at byte %d left the root unchanged", i)
		}
	}
}

func TestCustomerActivityReorderingLinesMovesTheRoot(t *testing.T) {
	a := ComputeCustomerDeclaredActivityRoot([]byte("{\"a\":1}\n{\"b\":2}\n"))
	b := ComputeCustomerDeclaredActivityRoot([]byte("{\"b\":2}\n{\"a\":1}\n"))
	if a == b {
		t.Fatal("reordered lines must not share a root")
	}
}

// signedProof is a minimal proof on a version whose signed message covers
// the root.
func signedProof(root interface{}) map[string]interface{} {
	return map[string]interface{}{"cdp_version": "2.2", CustomerDeclaredActivityRootField: root}
}

func TestCustomerActivityRecordAndMatchingRootVerify(t *testing.T) {
	v := activityRootVector3(t)
	proof := signedProof(v.Root)
	if failure := VerifyCustomerDeclaredActivity(proof, []byte(v.InputUTF8)); failure != nil {
		t.Fatalf("matching record must verify, got %+v", failure)
	}
}

func TestCustomerActivityRecordAndDifferentRootIsAMismatchNamingBothSides(t *testing.T) {
	v := activityRootVector3(t)
	genesis := "sha512:" + NanorixGenesisHash
	proof := signedProof(genesis)
	failure := VerifyCustomerDeclaredActivity(proof, []byte(v.InputUTF8))
	want := &FailureReason{
		Type:     ReasonCustomerDeclaredActivityRootMismatch,
		Claimed:  genesis,
		Computed: v.Root,
	}
	if !failure.Equal(want) {
		t.Fatalf("got %+v, want %+v", failure, want)
	}
	// Wire form pinned byte-for-byte against the Rust test in
	// governance/verify-types/tests/customer_declared_activity_root_mismatch_wire_form.rs.
	wire, err := json.Marshal(failure)
	if err != nil {
		t.Fatal(err)
	}
	wantWire := `{"type":"customer_declared_activity_root_mismatch","claimed":"` + genesis + `","computed":"` + v.Root + `"}`
	if string(wire) != wantWire {
		t.Fatalf("wire form drift:\n got %s\nwant %s", wire, wantWire)
	}
	var back FailureReason
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Equal(want) {
		t.Fatalf("roundtrip drift: %+v", back)
	}
}

func TestCustomerActivityRecordAgainstAProofWithoutARootFailsClosed(t *testing.T) {
	v := activityRootVector3(t)
	want := &FailureReason{Type: ReasonRequiredFieldMissing, Field: CustomerDeclaredActivityRootField}
	if f := VerifyCustomerDeclaredActivity(map[string]interface{}{}, []byte(v.InputUTF8)); !f.Equal(want) {
		t.Fatalf("absent root: got %+v", f)
	}
	nullRoot := signedProof(nil)
	if f := VerifyCustomerDeclaredActivity(nullRoot, []byte(v.InputUTF8)); !f.Equal(want) {
		t.Fatalf("null root: got %+v", f)
	}
	// No root is no version gate either: the verdict is the same on a
	// version that would not sign one.
	unsignedVersion := map[string]interface{}{"cdp_version": "1.0"}
	if f := VerifyCustomerDeclaredActivity(unsignedVersion, []byte(v.InputUTF8)); !f.Equal(want) {
		t.Fatalf("no root on 1.0: got %+v", f)
	}
}

// The claimed value is compared after prefix stripping, like every other
// root, and reported exactly as written.
func TestCustomerActivityBareHexRootComparesEqualAndIsReportedVerbatim(t *testing.T) {
	v := activityRootVector3(t)
	bare := signedProof(StripHashPrefix(v.Root))
	if f := VerifyCustomerDeclaredActivity(bare, []byte(v.InputUTF8)); f != nil {
		t.Fatalf("bare hex must compare equal, got %+v", f)
	}
	bareGenesis := signedProof(NanorixGenesisHash)
	f := VerifyCustomerDeclaredActivity(bareGenesis, []byte(v.InputUTF8))
	want := &FailureReason{Type: ReasonCustomerDeclaredActivityRootMismatch, Claimed: NanorixGenesisHash, Computed: v.Root}
	if !f.Equal(want) {
		t.Fatalf("got %+v, want %+v", f, want)
	}
}

func malformedRoot(reason string) *FailureReason {
	return &FailureReason{Type: ReasonFieldMalformed, Field: CustomerDeclaredActivityRootField, Reason: reason}
}

// Every shape no signer emits is named as malformed, with the reason string
// the other implementations reproduce byte-for-byte.
func TestCustomerActivityMalformedRootIsFieldMalformedWithThePinnedReason(t *testing.T) {
	v := activityRootVector3(t)
	hexPart := StripHashPrefix(v.Root)
	cases := []struct {
		value  interface{}
		reason string
	}{
		{float64(7), RootMalformedNotAString},
		{true, RootMalformedNotAString},
		{map[string]interface{}{}, RootMalformedNotAString},
		{[]interface{}{}, RootMalformedNotAString},
		{"", RootMalformedEmpty},
		{"abc", RootMalformedShape},
		{"sha512:", RootMalformedShape},
		{v.Root[:len(v.Root)-1], RootMalformedShape},
		{v.Root + "0", RootMalformedShape},
		{"sha512:" + strings.ToUpper(hexPart), RootMalformedShape},
		{"sha256:" + hexPart, RootMalformedShape},
	}
	for _, c := range cases {
		_, f := CheckDeclaredActivityRootShape(c.value)
		if !f.Equal(malformedRoot(c.reason)) {
			t.Fatalf("value %v: got %+v, want reason %q", c.value, f, c.reason)
		}
	}
	if got, f := CheckDeclaredActivityRootShape(v.Root); f != nil || got != v.Root {
		t.Fatalf("prefixed root must be accepted verbatim, got %q %+v", got, f)
	}
	if got, f := CheckDeclaredActivityRootShape(hexPart); f != nil || got != hexPart {
		t.Fatalf("bare hex root must be accepted verbatim, got %q %+v", got, f)
	}

	// Wire form pinned byte-for-byte against the Rust test in
	// governance/verify-types/tests/field_malformed_wire_form.rs.
	wire, err := json.Marshal(malformedRoot(RootMalformedEmpty))
	if err != nil {
		t.Fatal(err)
	}
	wantWire := `{"type":"field_malformed","field":"customer_declared_activity_root","reason":"empty string"}`
	if string(wire) != wantWire {
		t.Fatalf("wire form drift:\n got %s\nwant %s", wire, wantWire)
	}
	var back FailureReason
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Equal(malformedRoot(RootMalformedEmpty)) {
		t.Fatalf("roundtrip drift: %+v", back)
	}
}

// A malformed root is named before any recompute — never reported as a
// mismatch against the record, which would blame the record.
func TestCustomerActivityMalformedRootWithARecordIsNotAMismatch(t *testing.T) {
	v := activityRootVector3(t)
	empty := signedProof("")
	if f := VerifyCustomerDeclaredActivity(empty, []byte(v.InputUTF8)); !f.Equal(malformedRoot(RootMalformedEmpty)) {
		t.Fatalf("empty root: got %+v", f)
	}
	numeric := signedProof(float64(42))
	if f := VerifyCustomerDeclaredActivity(numeric, []byte(v.InputUTF8)); !f.Equal(malformedRoot(RootMalformedNotAString)) {
		t.Fatalf("numeric root: got %+v", f)
	}
}

// The standalone check applies the stage-2 version gate too: a 1.0 proof
// with an attacker-added root and a record that reproduces it must not come
// back as a match — the signature never covered that root. A missing or
// non-string cdp_version counts as a version that does not sign it, and the
// version gate precedes the shape gate.
func TestCustomerActivityRootTheVersionDoesNotSignIsUnsignedNotVerified(t *testing.T) {
	v := activityRootVector3(t)
	unsigned := &FailureReason{Type: ReasonUnsignedFieldPopulated, Field: CustomerDeclaredActivityRootField}
	versions := []interface{}{"1.0", "2.0", "2.3", "", nil, float64(2.2)}
	roots := []interface{}{v.Root, "", float64(42), "not a hash"}
	for _, version := range versions {
		for _, root := range roots {
			proof := map[string]interface{}{"cdp_version": version, CustomerDeclaredActivityRootField: root}
			if f := VerifyCustomerDeclaredActivity(proof, []byte(v.InputUTF8)); !f.Equal(unsigned) {
				t.Fatalf("version %v root %v: got %+v", version, root, f)
			}
			if f := VerifyCustomerDeclaredActivity(proof, []byte{}); !f.Equal(unsigned) {
				t.Fatalf("version %v root %v, empty record: got %+v", version, root, f)
			}
		}
	}
	for _, root := range roots {
		missing := map[string]interface{}{CustomerDeclaredActivityRootField: root}
		if f := VerifyCustomerDeclaredActivity(missing, []byte(v.InputUTF8)); !f.Equal(unsigned) {
			t.Fatalf("no cdp_version, root %v: got %+v", root, f)
		}
	}
	for _, version := range []string{"2.1", "2.2"} {
		proof := map[string]interface{}{"cdp_version": version, CustomerDeclaredActivityRootField: v.Root}
		if f := VerifyCustomerDeclaredActivity(proof, []byte(v.InputUTF8)); f != nil {
			t.Fatalf("%s signs the root, got %+v", version, f)
		}
	}
}

// The pre-chain-walk gate: a root on a version that does not sign the
// canonical view is unsigned whatever its shape; on 2.1/2.2 it is
// shape-checked; no root is no gate.
func TestCustomerActivityGateRejectsUnsignedVersionsThenMalformedShapes(t *testing.T) {
	v := activityRootVector3(t)
	unsigned := &FailureReason{Type: ReasonUnsignedFieldPopulated, Field: CustomerDeclaredActivityRootField}
	for _, version := range []string{"1.0", "2.0", "3.0"} {
		wellFormed := map[string]interface{}{CustomerDeclaredActivityRootField: v.Root}
		if f := GateDeclaredActivityRoot(wellFormed, version); !f.Equal(unsigned) {
			t.Fatalf("%s well-formed root: got %+v", version, f)
		}
		numeric := map[string]interface{}{CustomerDeclaredActivityRootField: float64(7)}
		if f := GateDeclaredActivityRoot(numeric, version); !f.Equal(unsigned) {
			t.Fatalf("%s: the version gate precedes the shape gate, got %+v", version, f)
		}
		nullRoot := map[string]interface{}{CustomerDeclaredActivityRootField: nil}
		if f := GateDeclaredActivityRoot(nullRoot, version); f != nil {
			t.Fatalf("%s: null is absent, got %+v", version, f)
		}
	}
	for _, version := range []string{"2.1", "2.2"} {
		wellFormed := map[string]interface{}{CustomerDeclaredActivityRootField: v.Root}
		if f := GateDeclaredActivityRoot(wellFormed, version); f != nil {
			t.Fatalf("%s well-formed root: got %+v", version, f)
		}
		empty := map[string]interface{}{CustomerDeclaredActivityRootField: ""}
		if f := GateDeclaredActivityRoot(empty, version); !f.Equal(malformedRoot(RootMalformedEmpty)) {
			t.Fatalf("%s empty root: got %+v", version, f)
		}
		if f := GateDeclaredActivityRoot(map[string]interface{}{}, version); f != nil {
			t.Fatalf("%s no root: got %+v", version, f)
		}
	}
}

// The ladder on the three corpus fixtures that pin the gate, read from the
// same files every other port reads. The corpus sweep covers them too; this
// test states the attack they exist for and checks what the sweep does not:
// that checked is never true.
func TestCustomerActivityGateLadderOnCorpusFixtures(t *testing.T) {
	v := activityRootVector3(t)
	cases := []struct {
		fixture string
		want    *FailureReason
	}{
		{"0007_v1_0_customer_declared_activity_root_unsigned", &FailureReason{Type: ReasonUnsignedFieldPopulated, Field: CustomerDeclaredActivityRootField}},
		{"0008_v2_2_customer_declared_activity_root_empty_string", malformedRoot(RootMalformedEmpty)},
		{"0009_v2_2_customer_declared_activity_root_numeric", malformedRoot(RootMalformedNotAString)},
	}
	for _, c := range cases {
		raw, err := os.ReadFile(corpusRoot + "/10_v2_2/" + c.fixture + ".json")
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		for _, policy := range []VerifierPolicy{{}, {CustomerActivity: []byte(v.InputUTF8)}} {
			r := Verify(raw, policy)
			if r.Valid || r.StageReached != 2 || !r.FailureReason.Equal(c.want) {
				t.Fatalf("%s: got %+v, want %+v at stage 2", c.fixture, r, c.want)
			}
			if r.Metadata.CustomerDeclaredActivityChecked != nil && *r.Metadata.CustomerDeclaredActivityChecked {
				t.Fatalf("%s: a rejected root must never be reported as checked", c.fixture)
			}
		}
	}

	// The attack the 1.0 fixture pins: strip the root and the document is a
	// genuine 1.0 proof that verifies; with a root the attacker computed over
	// their own record, and that record supplied, the verdict used to be
	// "matched". Now it is unsigned_field_populated, whatever the record says.
	raw, err := os.ReadFile(corpusRoot + "/10_v2_2/0007_v1_0_customer_declared_activity_root_unsigned.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var proof map[string]interface{}
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	delete(proof, CustomerDeclaredActivityRootField)
	if r := VerifyValue(proof, VerifierPolicy{}); !r.Valid || r.StageReached != 7 {
		t.Fatalf("the 1.0 fixture without its root must be a genuine proof, got %+v", r)
	}
	attackerRecord := []byte("{\"event\":\"anything the attacker wants\"}\n")
	proof[CustomerDeclaredActivityRootField] = ComputeCustomerDeclaredActivityRoot(attackerRecord)
	r := VerifyValue(proof, VerifierPolicy{CustomerActivity: attackerRecord})
	unsigned := &FailureReason{Type: ReasonUnsignedFieldPopulated, Field: CustomerDeclaredActivityRootField}
	if r.Valid || r.StageReached != 2 || !r.FailureReason.Equal(unsigned) {
		t.Fatalf("injected root on a genuine 1.0 proof must be unsigned at stage 2, got %+v", r)
	}
}

// The ladder: a signed 2.2 fixture declaring the `three` root, verified with
// and without the record, and a 2.1 fixture (no root) offered a record.
func TestCustomerActivityLadderSemantics(t *testing.T) {
	v := activityRootVector3(t)
	withRoot, err := os.ReadFile(corpusRoot + "/10_v2_2/0005_v2_2_customer_declared_activity_root.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	noRoot, err := os.ReadFile(corpusRoot + "/01_single_capsule_success/0000_v2_1_signed.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// root + no record → declared, not checked; not a failure.
	r := Verify(withRoot, VerifierPolicy{})
	if !r.Valid || r.StageReached != 7 {
		t.Fatalf("root without record must verify at stage 7, got %+v", r)
	}
	if r.Metadata.CustomerDeclaredActivityRoot == nil || *r.Metadata.CustomerDeclaredActivityRoot != v.Root {
		t.Fatalf("declared root must be disclosed, got %+v", r.Metadata)
	}
	if r.Metadata.CustomerDeclaredActivityChecked == nil || *r.Metadata.CustomerDeclaredActivityChecked {
		t.Fatalf("declared root without record must report checked=false, got %+v", r.Metadata)
	}

	// root + matching record → checked.
	r = Verify(withRoot, VerifierPolicy{CustomerActivity: []byte(v.InputUTF8)})
	if !r.Valid || r.StageReached != 7 {
		t.Fatalf("matching record must verify, got %+v", r)
	}
	if r.Metadata.CustomerDeclaredActivityChecked == nil || !*r.Metadata.CustomerDeclaredActivityChecked {
		t.Fatalf("matching record must report checked=true, got %+v", r.Metadata)
	}

	// root + different record → mismatch at stage 3.
	r = Verify(withRoot, VerifierPolicy{CustomerActivity: []byte("{\"a\":1}\n")})
	if r.Valid || r.StageReached != 3 || r.FailureReason == nil ||
		r.FailureReason.Type != ReasonCustomerDeclaredActivityRootMismatch ||
		r.FailureReason.Claimed != v.Root {
		t.Fatalf("different record must fail with the mismatch at stage 3, got %+v", r)
	}

	// no root + record → required_field_missing at stage 3.
	r = Verify(noRoot, VerifierPolicy{CustomerActivity: []byte(v.InputUTF8)})
	want := &FailureReason{Type: ReasonRequiredFieldMissing, Field: CustomerDeclaredActivityRootField}
	if r.Valid || r.StageReached != 3 || !r.FailureReason.Equal(want) {
		t.Fatalf("record against a proof without a root must fail closed, got %+v", r)
	}
	if r.Metadata.CustomerDeclaredActivityRoot != nil || r.Metadata.CustomerDeclaredActivityChecked != nil {
		t.Fatalf("a proof without a root must report nothing about one, got %+v", r.Metadata)
	}

	// no root + no record → nothing reported about a root.
	r = Verify(noRoot, VerifierPolicy{})
	if r.Metadata.CustomerDeclaredActivityRoot != nil || r.Metadata.CustomerDeclaredActivityChecked != nil {
		t.Fatalf("a proof without a root must report nothing about one, got %+v", r.Metadata)
	}
}
