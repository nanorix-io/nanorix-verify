//go:build go1.27 && !fips140v1.0

// Runs every case under tools/nanorix-verify/fixtures/mldsa/ through
// VerifyMLDSA, read where the files are, as tools/nanorix-verify/tests/
// mldsa_vectors.rs does for the Rust check. Expected-valid cases must verify;
// expected-invalid cases must be refused with the error their flags name.
//
// What this file checks:
//   - the folder holds exactly the listed vector files, the README and the
//     licence;
//   - case ids are unique across all files;
//   - every key at file, group and case level is one the README's Format
//     section documents, matched exactly (case included), and no key appears
//     twice in one object;
//   - each file's format, parameter set, key and signature lengths and
//     case_count, and that it holds at least one case;
//   - every case's verdict, the total of 488 cases, and per parameter set a
//     valid case, an invalid case of the right lengths, and the four counts in
//     the README's per-set table;
//   - the repeated-hint cases, the chosen-rho keys and cross-set refusals.
//
// The Rust test alone checks where provenance fields sit (built, changes, a
// group source, base_source), that each strict-decoding class has a built case
// for both sets, and the z-coefficient properties of the signed cases.

package auditproof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var mldsaVectorDir = filepath.Join("..", "nanorix-verify", "fixtures", "mldsa")

var mldsaVectorFiles = []struct {
	name string
	set  MLDSAParameterSet
}{
	{"acvp_ml_dsa_65.json", MLDSA65},
	{"acvp_ml_dsa_87.json", MLDSA87},
	{"acvp_siggen_ml_dsa_65.json", MLDSA65},
	{"acvp_siggen_ml_dsa_87.json", MLDSA87},
	{"wycheproof_ml_dsa_65.json", MLDSA65},
	{"wycheproof_ml_dsa_87.json", MLDSA87},
	{"mutations_ml_dsa_65.json", MLDSA65},
	{"mutations_ml_dsa_87.json", MLDSA87},
	{"signed_ml_dsa_65.json", MLDSA65},
	{"signed_ml_dsa_87.json", MLDSA87},
}

// The folder's two entries that are not vector files.
var mldsaOtherEntries = []string{"README.md", "LICENSE-wycheproof.txt"}

// The keys README.md's Format section documents at file, group and case level.
var (
	mldsaTopKeys   = []string{"format", "parameter_set", "public_key_bytes", "signature_bytes", "source", "changes", "case_count", "groups"}
	mldsaGroupKeys = []string{"public_key", "source", "cases"}
	mldsaCaseKeys  = []string{"id", "comment", "message", "signature", "expected", "flags", "built"}
)

// The same documented fields, for decoding once the key sets have been checked.
type mldsaVectorFile struct {
	Format         string             `json:"format"`
	ParameterSet   string             `json:"parameter_set"`
	PublicKeyBytes int                `json:"public_key_bytes"`
	SignatureBytes int                `json:"signature_bytes"`
	Source         json.RawMessage    `json:"source"`
	Changes        string             `json:"changes"`
	CaseCount      int                `json:"case_count"`
	Groups         []mldsaVectorGroup `json:"groups"`
}

type mldsaVectorGroup struct {
	PublicKey string            `json:"public_key"`
	Source    json.RawMessage   `json:"source"`
	Cases     []mldsaVectorCase `json:"cases"`
}

type mldsaVectorCase struct {
	ID        string   `json:"id"`
	Comment   string   `json:"comment"`
	Message   string   `json:"message"`
	Signature string   `json:"signature"`
	Expected  string   `json:"expected"`
	Flags     []string `json:"flags"`
	Built     string   `json:"built"`
}

type mldsaCase struct {
	file      string
	id        string
	publicKey []byte
	message   []byte
	signature []byte
	valid     bool
	flags     []string
}

func (c mldsaCase) hasFlag(f string) bool {
	for _, x := range c.flags {
		if x == f {
			return true
		}
	}
	return false
}

// mldsaObjectKeys returns the keys of the JSON object in raw, in order and
// with repeats, as written.
func mldsaObjectKeys(raw []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("not a JSON object")
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// mldsaCheckKeys refuses an object holding a key outside allowed, compared
// exactly, or holding one key twice.
func mldsaCheckKeys(where string, raw []byte, allowed []string) error {
	keys, err := mldsaObjectKeys(raw)
	if err != nil {
		return fmt.Errorf("%s: %v", where, err)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		documented := false
		for _, a := range allowed {
			if k == a {
				documented = true
			}
		}
		if !documented {
			return fmt.Errorf("%s: undocumented key %q", where, k)
		}
		if seen[k] {
			return fmt.Errorf("%s: key %q appears twice", where, k)
		}
		seen[k] = true
	}
	return nil
}

// mldsaCheckAllKeys runs mldsaCheckKeys at file, group and case level.
func mldsaCheckAllKeys(name string, raw []byte) error {
	if err := mldsaCheckKeys(name, raw, mldsaTopKeys); err != nil {
		return err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	var groups []json.RawMessage
	if err := json.Unmarshal(top["groups"], &groups); err != nil {
		return fmt.Errorf("%s groups: %v", name, err)
	}
	for gi, g := range groups {
		where := fmt.Sprintf("%s group %d", name, gi)
		if err := mldsaCheckKeys(where, g, mldsaGroupKeys); err != nil {
			return err
		}
		var group map[string]json.RawMessage
		if err := json.Unmarshal(g, &group); err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		var cases []json.RawMessage
		if err := json.Unmarshal(group["cases"], &cases); err != nil {
			return fmt.Errorf("%s cases: %v", where, err)
		}
		for ci, c := range cases {
			if err := mldsaCheckKeys(fmt.Sprintf("%s case %d", where, ci), c, mldsaCaseKeys); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseMLDSAFile reads one vector file after checking its keys at every level.
func parseMLDSAFile(name string, raw []byte) (mldsaVectorFile, []mldsaCase, error) {
	var doc mldsaVectorFile
	if err := mldsaCheckAllKeys(name, raw); err != nil {
		return doc, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, nil, fmt.Errorf("%s: %v", name, err)
	}
	var out []mldsaCase
	for _, g := range doc.Groups {
		pk, err := hex.DecodeString(g.PublicKey)
		if err != nil {
			return doc, nil, fmt.Errorf("%s public_key: %v", name, err)
		}
		for _, c := range g.Cases {
			var valid bool
			switch c.Expected {
			case "valid":
				valid = true
			case "invalid":
			default:
				return doc, nil, fmt.Errorf("%s %s: unknown expected value %q", name, c.ID, c.Expected)
			}
			msg, err := hex.DecodeString(c.Message)
			if err != nil {
				return doc, nil, fmt.Errorf("%s %s message: %v", name, c.ID, err)
			}
			sig, err := hex.DecodeString(c.Signature)
			if err != nil {
				return doc, nil, fmt.Errorf("%s %s signature: %v", name, c.ID, err)
			}
			out = append(out, mldsaCase{file: name, id: c.ID, publicKey: pk, message: msg, signature: sig, valid: valid, flags: c.Flags})
		}
	}
	return doc, out, nil
}

func loadMLDSAFile(t *testing.T, name string) (mldsaVectorFile, []mldsaCase) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(mldsaVectorDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	doc, cases, err := parseMLDSAFile(name, raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc, cases
}

func mldsaExpectedRefusal(set MLDSAParameterSet, c mldsaCase) MLDSAError {
	switch {
	case c.hasFlag("IncorrectPublicKeyLength") || c.hasFlag("PublicKeyLength"):
		return MLDSAError{Kind: MLDSAPublicKeyLength, ParameterSet: set, Expected: set.PublicKeySize(), Actual: len(c.publicKey)}
	case c.hasFlag("IncorrectSignatureLength") || c.hasFlag("SignatureLength"):
		return MLDSAError{Kind: MLDSASignatureLength, ParameterSet: set, Expected: set.SignatureSize(), Actual: len(c.signature)}
	}
	return MLDSAError{Kind: MLDSASignatureInvalid, ParameterSet: set}
}

// mldsaCheck returns "" when VerifyMLDSA gives c its expected verdict, else
// what it gave instead.
func mldsaCheck(set MLDSAParameterSet, c mldsaCase) string {
	err := VerifyMLDSA(set, c.publicKey, c.message, c.signature)
	if c.valid {
		if err != nil {
			return "want valid, got " + err.Error()
		}
		return ""
	}
	want := mldsaExpectedRefusal(set, c)
	var got *MLDSAError
	if !errors.As(err, &got) || *got != want {
		return "want " + want.Error() + ", got " + strconv.Quote(errString(err))
	}
	return ""
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func TestMLDSAVectorFolderHoldsExactlyTheListedFiles(t *testing.T) {
	entries, err := os.ReadDir(mldsaVectorDir)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk, listed []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		onDisk = append(onDisk, name)
	}
	for _, f := range mldsaVectorFiles {
		listed = append(listed, f.name)
	}
	listed = append(listed, mldsaOtherEntries...)
	sort.Strings(onDisk)
	sort.Strings(listed)
	if strings.Join(onDisk, "\n") != strings.Join(listed, "\n") {
		t.Fatalf("folder holds %v, test lists %v", onDisk, listed)
	}
}

func TestMLDSACaseIDsAreUniqueAcrossAllFiles(t *testing.T) {
	seen := map[string]string{}
	for _, f := range mldsaVectorFiles {
		_, cs := loadMLDSAFile(t, f.name)
		for _, c := range cs {
			if prev, ok := seen[c.id]; ok {
				t.Errorf("%s: id %s already used in %s", f.name, c.id, prev)
			}
			seen[c.id] = f.name
		}
	}
}

// mldsaCounts holds, per parameter set across its files: all cases, valid
// cases, invalid cases whose key and signature have the set's lengths, and
// invalid cases with a key or signature of another length.
type mldsaCounts struct {
	cases, valid, invalidRightLengths, invalidWrongLength int
}

func (n *mldsaCounts) add(set MLDSAParameterSet, c mldsaCase) {
	n.cases++
	switch {
	case c.valid:
		n.valid++
	case len(c.publicKey) == set.PublicKeySize() && len(c.signature) == set.SignatureSize():
		n.invalidRightLengths++
	default:
		n.invalidWrongLength++
	}
}

// mldsaReadmeCounts reads the README's per-set table row that starts with
// "| <set name> |".
func mldsaReadmeCounts(t *testing.T, set MLDSAParameterSet) mldsaCounts {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(mldsaVectorDir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	start := "| " + set.String() + " |"
	var rows []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, start) {
			rows = append(rows, l)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("README rows for %s: %q", set, rows)
	}
	var n []int
	for i, f := range strings.Split(rows[0], "|") {
		f = strings.TrimSpace(f)
		if f == "" || i == 1 {
			continue
		}
		v, err := strconv.Atoi(strings.ReplaceAll(f, ",", ""))
		if err != nil {
			t.Fatalf("README row for %s: %q: %v", set, rows[0], err)
		}
		n = append(n, v)
	}
	if len(n) != 4 {
		t.Fatalf("README row for %s: %q", set, rows[0])
	}
	return mldsaCounts{cases: n[0], valid: n[1], invalidRightLengths: n[2], invalidWrongLength: n[3]}
}

func TestMLDSAEveryVectorCaseGetsItsExpectedVerdict(t *testing.T) {
	perSet := map[MLDSAParameterSet]*mldsaCounts{MLDSA65: {}, MLDSA87: {}}
	total := 0
	for _, f := range mldsaVectorFiles {
		doc, cs := loadMLDSAFile(t, f.name)
		if doc.Format != "nanorix-mldsa-sigver/1" || doc.ParameterSet != f.set.String() ||
			doc.PublicKeyBytes != f.set.PublicKeySize() || doc.SignatureBytes != f.set.SignatureSize() {
			t.Fatalf("%s: header %q %q %d %d", f.name, doc.Format, doc.ParameterSet, doc.PublicKeyBytes, doc.SignatureBytes)
		}
		if len(cs) == 0 {
			t.Fatalf("%s holds no cases", f.name)
		}
		if doc.CaseCount != len(cs) {
			t.Fatalf("%s: case_count %d, %d cases present", f.name, doc.CaseCount, len(cs))
		}
		for _, c := range cs {
			total++
			perSet[f.set].add(f.set, c)
			if msg := mldsaCheck(f.set, c); msg != "" {
				t.Errorf("%s %s: %s", f.name, c.id, msg)
			}
		}
	}
	if total != 488 {
		t.Errorf("ran %d cases, the README states 488", total)
	}
	for _, set := range []MLDSAParameterSet{MLDSA65, MLDSA87} {
		got := *perSet[set]
		if got.valid == 0 {
			t.Errorf("%s: no valid case", set)
		}
		if got.invalidRightLengths == 0 {
			t.Errorf("%s: no invalid case with a key and signature of the right length", set)
		}
		if want := mldsaReadmeCounts(t, set); got != want {
			t.Errorf("%s: counts %+v, README states %+v", set, got, want)
		}
	}
}

func mldsaCasesWithFlag(t *testing.T, name, flag string) []mldsaCase {
	t.Helper()
	_, cs := loadMLDSAFile(t, name)
	var out []mldsaCase
	for _, c := range cs {
		if len(c.flags) == 1 && c.flags[0] == flag {
			out = append(out, c)
		}
	}
	return out
}

// The CVE-2026-24850 class: one hint index written twice leaves the decoded
// hints as in a valid signature, so only the decoder's index-order check
// refuses it. The built cases and Wycheproof's own case for each set
// (README: tc19 for ML-DSA-65, tc21 for ML-DSA-87) must be refused.
func TestMLDSARepeatedHintIndexIsRefused(t *testing.T) {
	for _, tc := range []struct {
		set        MLDSAParameterSet
		mutations  string
		wycheproof string
		id         string
	}{
		{MLDSA65, "mutations_ml_dsa_65.json", "wycheproof_ml_dsa_65.json", "wycheproof-65-tc19"},
		{MLDSA87, "mutations_ml_dsa_87.json", "wycheproof_ml_dsa_87.json", "wycheproof-87-tc21"},
	} {
		built := mldsaCasesWithFlag(t, tc.mutations, "HintRepeatedIndex")
		if len(built) == 0 {
			t.Fatalf("%s has no HintRepeatedIndex case", tc.mutations)
		}
		_, wcs := loadMLDSAFile(t, tc.wycheproof)
		found := false
		for _, c := range wcs {
			if c.id == tc.id {
				built = append(built, c)
				found = true
			}
		}
		if !found {
			t.Fatalf("%s has no %s", tc.wycheproof, tc.id)
		}
		for _, c := range built {
			if c.valid {
				t.Fatalf("%s %s is listed valid", c.file, c.id)
			}
			err := VerifyMLDSA(tc.set, c.publicKey, c.message, c.signature)
			var got *MLDSAError
			if !errors.As(err, &got) || got.Kind != MLDSASignatureInvalid {
				t.Errorf("%s %s: want signature invalid, got %s", c.file, c.id, errString(err))
			}
		}
	}
}

// A key whose rho starts with a smaller set's SubjectPublicKeyInfo header is
// read as the declared set's raw key and verifies.
func TestMLDSAChosenRhoKeyIsReadAsTheDeclaredSet(t *testing.T) {
	smallerHeader := map[MLDSAParameterSet][]byte{
		MLDSA65: {0x30, 0x82, 0x05, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11, 0x03, 0x82, 0x05, 0x21, 0x00},
		MLDSA87: {0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00},
	}
	for name, set := range map[string]MLDSAParameterSet{"signed_ml_dsa_65.json": MLDSA65, "signed_ml_dsa_87.json": MLDSA87} {
		cs := mldsaCasesWithFlag(t, name, "ChosenRho")
		if len(cs) != 1 || !cs[0].valid {
			t.Fatalf("%s: want one valid ChosenRho case, got %d", name, len(cs))
		}
		if !bytes.HasPrefix(cs[0].publicKey, smallerHeader[set]) {
			t.Fatalf("%s: key does not start with the smaller set's header", name)
		}
		if err := VerifyMLDSA(set, cs[0].publicKey, cs[0].message, cs[0].signature); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func mldsaBase(t *testing.T, name string) mldsaCase {
	t.Helper()
	cs := mldsaCasesWithFlag(t, name, "Base")
	if len(cs) != 1 {
		t.Fatalf("%s: %d Base cases", name, len(cs))
	}
	return cs[0]
}

func TestMLDSAKeyAndSignatureOfOneSetAreRefusedByTheOther(t *testing.T) {
	b65 := mldsaBase(t, "mutations_ml_dsa_65.json")
	b87 := mldsaBase(t, "mutations_ml_dsa_87.json")
	for _, tc := range []struct {
		what          string
		set           MLDSAParameterSet
		key, msg, sig []byte
		want          *MLDSAError
	}{
		{"65 base", MLDSA65, b65.publicKey, b65.message, b65.signature, nil},
		{"87 base", MLDSA87, b87.publicKey, b87.message, b87.signature, nil},
		{"65 under 87", MLDSA87, b65.publicKey, b65.message, b65.signature, &MLDSAError{Kind: MLDSAPublicKeyLength, ParameterSet: MLDSA87, Expected: 2592, Actual: 1952}},
		{"87 under 65", MLDSA65, b87.publicKey, b87.message, b87.signature, &MLDSAError{Kind: MLDSAPublicKeyLength, ParameterSet: MLDSA65, Expected: 1952, Actual: 2592}},
		{"87 key, 65 signature", MLDSA87, b87.publicKey, b65.message, b65.signature, &MLDSAError{Kind: MLDSASignatureLength, ParameterSet: MLDSA87, Expected: 4627, Actual: 3309}},
		{"65 key, 87 signature", MLDSA65, b65.publicKey, b87.message, b87.signature, &MLDSAError{Kind: MLDSASignatureLength, ParameterSet: MLDSA65, Expected: 3309, Actual: 4627}},
	} {
		err := VerifyMLDSA(tc.set, tc.key, tc.msg, tc.sig)
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: %v", tc.what, err)
			}
			continue
		}
		var got *MLDSAError
		if !errors.As(err, &got) || *got != *tc.want {
			t.Errorf("%s: want %v, got %s", tc.what, tc.want, errString(err))
		}
	}
}

func TestMLDSAUnknownParameterSetIsRefused(t *testing.T) {
	b65 := mldsaBase(t, "mutations_ml_dsa_65.json")
	for _, set := range []MLDSAParameterSet{0, 3, -1} {
		err := VerifyMLDSA(set, b65.publicKey, b65.message, b65.signature)
		var got *MLDSAError
		if !errors.As(err, &got) || got.Kind != MLDSAUnknownParameterSet {
			t.Errorf("%v: want unknown parameter set, got %s", set, errString(err))
		}
	}
}

// The library call is reached only after the length checks, so the library's
// own refusals cannot be reached through VerifyMLDSA. Called directly with a
// key or signature of another length, each must be an error of its kind,
// never a success.
func TestMLDSALibraryRefusalsAreNeverASuccess(t *testing.T) {
	b65 := mldsaBase(t, "mutations_ml_dsa_65.json")
	for _, tc := range []struct {
		what     string
		key, sig []byte
		want     MLDSAErrorKind
	}{
		{"short key", b65.publicKey[1:], b65.signature, MLDSAPublicKeyRejected},
		{"short signature", b65.publicKey, b65.signature[1:], MLDSASignatureInvalid},
	} {
		err := verifyMLDSAWithLibrary(MLDSA65, tc.key, b65.message, tc.sig)
		var got *MLDSAError
		if !errors.As(err, &got) || *got != (MLDSAError{Kind: tc.want, ParameterSet: MLDSA65}) {
			t.Errorf("%s: want kind %d, got %s", tc.what, tc.want, errString(err))
		}
	}
}

// A key outside the documented set, one that differs from a documented key only
// in case, or one written twice fails the reader at each level, while the same
// document without it is read.
func TestMLDSAVectorReaderRefusesUndocumentedOrRepeatedKeys(t *testing.T) {
	build := func(top, group, kase string) []byte {
		return []byte(`{"format":"nanorix-mldsa-sigver/1","parameter_set":"ML-DSA-65","public_key_bytes":1952,` +
			`"signature_bytes":3309,"source":{"name":"x"},"case_count":1` + top + `,"groups":[{"public_key":"00"` + group +
			`,"cases":[{"id":"x-1","comment":"","message":"","signature":"00","expected":"invalid","flags":[]` + kase + `}]}]}`)
	}
	if _, cases, err := parseMLDSAFile("control", build("", "", "")); err != nil || len(cases) != 1 || cases[0].valid {
		t.Fatalf("control document: cases %v, err %v", cases, err)
	}
	for name, doc := range map[string][]byte{
		"case-variant case key":  build("", "", `,"Expected":"valid"`),
		"repeated case key":      build("", "", `,"expected":"valid"`),
		"unknown case key":       build("", "", `,"note":"x"`),
		"case-variant group key": build("", `,"Public_Key":"00"`, ""),
		"repeated group key":     build("", `,"public_key":"00"`, ""),
		"case-variant file key":  build(`,"Case_Count":1`, "", ""),
		"repeated file key":      build(`,"case_count":1`, "", ""),
		"unknown file key":       build(`,"note":"x"`, "", ""),
	} {
		if _, _, err := parseMLDSAFile(name, doc); err == nil {
			t.Errorf("%s: read without error", name)
		}
	}
}

// The library step picks the library's parameter set by an explicit case for
// each set, so a value that is neither, even with a valid ML-DSA-65 key and
// signature, is refused as an unknown set rather than read as ML-DSA-65.
func TestMLDSALibraryStepRefusesAnUnknownSet(t *testing.T) {
	b65 := mldsaBase(t, "mutations_ml_dsa_65.json")
	for _, set := range []MLDSAParameterSet{0, 3, -1} {
		err := verifyMLDSAWithLibrary(set, b65.publicKey, b65.message, b65.signature)
		var got *MLDSAError
		if !errors.As(err, &got) || *got != (MLDSAError{Kind: MLDSAUnknownParameterSet, ParameterSet: set}) {
			t.Errorf("%v: want unknown parameter set, got %s", set, errString(err))
		}
	}
}
