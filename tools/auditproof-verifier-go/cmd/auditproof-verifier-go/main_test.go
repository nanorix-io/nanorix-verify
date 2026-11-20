package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	auditproof "github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go"
)

// runMainEnv makes this test binary run main() instead of the tests, so a test
// can run the real command, flag parsing and exit code included.
const runMainEnv = "AUDITPROOF_VERIFIER_GO_TEST_RUN_MAIN"

const corpusRoot = "../../../nanorix-verify/fixtures/corpus"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestFailureLineNamesTheFieldAsRustDoes(t *testing.T) {
	cases := []struct {
		reason auditproof.FailureReason
		want   string
	}{
		{auditproof.FailureReason{Type: auditproof.ReasonUnsignedFieldPopulated, Field: "witness_signatures"},
			"unsigned_field_populated (field: witness_signatures)"},
		{auditproof.FailureReason{Type: auditproof.ReasonRequiredFieldMissing, Field: "chain"},
			"required_field_missing (field: chain)"},
		{auditproof.FailureReason{Type: auditproof.ReasonFieldMalformed, Field: "customer_declared_activity_root", Reason: "not_a_string"},
			"field_malformed (field: customer_declared_activity_root, reason: not_a_string)"},
		{auditproof.FailureReason{Type: auditproof.ReasonGenesisHashMismatch},
			"genesis_hash_mismatch"},
	}
	for _, c := range cases {
		if got := failureLine(&c.reason); got != c.want {
			t.Errorf("failureLine(%+v) = %q, want %q", c.reason, got, c.want)
		}
	}
}

// printHuman on a refused document prints the populated slot by name.
func TestHumanOutputNamesThePopulatedSlot(t *testing.T) {
	r := auditproof.Verify([]byte(`{"cdp_version":"1.0","witness_signatures":[{"signature":"base64:AAAA"}]}`),
		auditproof.VerifierPolicy{})
	out := captureStdout(t, func() { printHuman(r, nil) })
	for _, want := range []string{
		"  Failure: unsigned_field_populated (field: witness_signatures)\n",
		"  Stage reached: 2 / 8\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = wr
	defer func() { os.Stdout = saved }()
	f()
	wr.Close()
	out, err := io.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// runCLI runs the command with args and returns its exit code, stdout and
// stderr.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, to, string(raw))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The committed corpus, each fixture under its own pins, agrees with every
// .expected.json, so the run exits 0.
func TestFixtureDirExitsZeroWhenEveryVerdictMatchesItsExpectedFile(t *testing.T) {
	n := 0
	counts := map[string]int{}
	err := filepath.Walk(corpusRoot, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(path, ".expected.json") {
			n++
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			var doc struct {
				Status string `json:"status"`
			}
			if jsonErr := json.Unmarshal(raw, &doc); jsonErr != nil {
				return jsonErr
			}
			counts[doc.Status]++
		}
		return err
	})
	if err != nil || n == 0 {
		t.Fatalf("no .expected.json under %s: %v", corpusRoot, err)
	}

	code, stdout, stderr := runCLI(t, "--fixture-dir", corpusRoot)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if counts["verified"]+counts["not_anchored"]+counts["not_verified"] != n || counts["not_anchored"] == 0 {
		t.Fatalf("every .expected.json must pin a status, and some must be not_anchored: %v of %d", counts, n)
	}
	want := fmt.Sprintf("%d fixtures · %d verified · %d not_anchored · %d not_verified\n%d of %d match their expected verdict\n",
		n, counts["verified"], counts["not_anchored"], counts["not_verified"], n, n)
	if stdout != want {
		t.Fatalf("stdout is not %q:\n%s", want, stdout)
	}
}

// One fixture whose committed verdict says it is refused, while it verifies,
// makes the run exit 1 and names each differing field. The pinned
// region_mismatch fixture beside it matches only under its own pin.
func TestFixtureDirExitsOneWhenAVerdictDiffersFromItsExpectedFile(t *testing.T) {
	dir := t.TempDir()
	genuine := filepath.Join(corpusRoot, "01_single_capsule_success", "0001_v2_1_signed")
	pinned := filepath.Join(corpusRoot, "05_failure_region_mismatch", "0000_us-central1_to_europe-west1")
	copyFile(t, genuine+".json", filepath.Join(dir, "a", "genuine.json"))
	writeFile(t, filepath.Join(dir, "a", "genuine.expected.json"),
		`{"failure_reason":{"type":"unsigned_field_populated","field":"witness_signatures"},"stage_reached":2,"valid":false}`)
	copyFile(t, pinned+".json", filepath.Join(dir, "b", "pinned.json"))
	copyFile(t, pinned+".expected.json", filepath.Join(dir, "b", "pinned.expected.json"))
	copyFile(t, filepath.Join(corpusRoot, "10_v2_2", "0007_v1_0_customer_declared_activity_root_unsigned.json"),
		filepath.Join(dir, "c", "refused.json"))
	writeFile(t, filepath.Join(dir, "c", "refused.expected.json"),
		`{"failure_reason":null,"stage_reached":7,"valid":true}`)

	code, stdout, stderr := runCLI(t, "--fixture-dir", dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"3 fixtures · 0 verified · 1 not_anchored · 2 not_verified\n",
		"2 of 3 differ from their expected verdict:\n",
		"  " + filepath.Join("c", "refused.json") + ": valid — expected true, got false\n",
		"  " + filepath.Join("c", "refused.json") + ": stage_reached — expected 7, got 2\n",
		"  " + filepath.Join("c", "refused.json") + ": failure_reason — expected null, got {\"field\":\"customer_declared_activity_root\",\"type\":\"unsigned_field_populated\"}\n",
		"  " + filepath.Join("a", "genuine.json") + ": valid — expected false, got true\n",
		"  " + filepath.Join("a", "genuine.json") + ": stage_reached — expected 2, got 7\n",
		"  " + filepath.Join("a", "genuine.json") + ": failure_reason — expected {\"field\":\"witness_signatures\",\"type\":\"unsigned_field_populated\"}, got null\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "pinned.json") {
		t.Fatalf("the pinned fixture matches its expected verdict but is listed:\n%s", stdout)
	}

	code, stdout, _ = runCLI(t, "--json", "--fixture-dir", dir)
	if code != 1 {
		t.Fatalf("--json exit %d, want 1", code)
	}
	var report struct {
		Mismatched int `json:"mismatched"`
		Results    []struct {
			Path       string   `json:"path"`
			Mismatches []string `json:"mismatches"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("--json output: %v\n%s", err, stdout)
	}
	if report.Mismatched != 2 || len(report.Results) != 3 ||
		len(report.Results[0].Mismatches) != 3 || len(report.Results[1].Mismatches) != 0 ||
		len(report.Results[2].Mismatches) != 3 {
		t.Fatalf("--json mismatches wrong: %+v", report)
	}
	if want := filepath.Join(dir, "a", "genuine.json"); report.Results[0].Path != want {
		t.Fatalf("--json results[0].path is %q, want %q", report.Results[0].Path, want)
	}
}

// Any stage_reached written as an unsigned integer is compared, however large,
// and the difference prints it as written.
func TestFixtureDirComparesEveryUnsignedStage(t *testing.T) {
	genuine := filepath.Join(corpusRoot, "01_single_capsule_success", "0001_v2_1_signed")
	for _, stage := range []string{"8", "1000000", "1000000001"} {
		dir := t.TempDir()
		copyFile(t, genuine+".json", filepath.Join(dir, "x.json"))
		writeFile(t, filepath.Join(dir, "x.expected.json"),
			`{"valid":true,"stage_reached":`+stage+`,"failure_reason":null}`)
		code, stdout, stderr := runCLI(t, "--fixture-dir", dir)
		want := "  x.json: stage_reached — expected " + stage + ", got 7\n"
		if code != 1 || !strings.Contains(stdout, want) {
			t.Errorf("stage_reached %s: exit %d, stdout %q, stderr %q; want exit 1 and %q", stage, code, stdout, stderr, want)
		}
	}
}

// The failure_reason difference prints <, > and & as they are, as Rust does.
func TestFixtureDirPrintsFailureReasonWithoutHTMLEscapes(t *testing.T) {
	genuine := filepath.Join(corpusRoot, "01_single_capsule_success", "0001_v2_1_signed")
	raw, err := os.ReadFile(genuine + ".json")
	if err != nil {
		t.Fatal(err)
	}
	proof := strings.Replace(string(raw), `"cdp_version": "2.1"`, `"cdp_version": "<9&9>"`, 1)
	if proof == string(raw) {
		t.Fatal(`the genuine fixture has no "cdp_version": "2.1" line`)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "x.json"), proof)
	writeFile(t, filepath.Join(dir, "x.expected.json"),
		`{"valid":false,"stage_reached":2,"failure_reason":{"type":"cdp_version_unsupported","found":"<1&1>"}}`)
	code, stdout, stderr := runCLI(t, "--fixture-dir", dir)
	want := `  x.json: failure_reason — expected {"found":"<1&1>","type":"cdp_version_unsupported"}, got {"found":"<9&9>","type":"cdp_version_unsupported"}` + "\n"
	if code != 1 || !strings.Contains(stdout, want) {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 1 and %q", code, stdout, stderr, want)
	}
}

// A run that cannot compare every fixture with a recorded verdict exits 2
// instead of reporting a result.
func TestFixtureDirExitsTwoWhenTheCorpusCannotBeCompared(t *testing.T) {
	genuine := filepath.Join(corpusRoot, "01_single_capsule_success", "0001_v2_1_signed")
	noExpected := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(noExpected, "x.json"))
	noValid := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(noValid, "x.json"))
	writeFile(t, filepath.Join(noValid, "x.expected.json"), `{"stage_reached":7,"failure_reason":null}`)

	withStage := func(stage string) string {
		dir := t.TempDir()
		copyFile(t, genuine+".json", filepath.Join(dir, "x.json"))
		writeFile(t, filepath.Join(dir, "x.expected.json"), `{"valid":true,"stage_reached":`+stage+`,"failure_reason":null}`)
		return dir
	}
	noStage := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(noStage, "x.json"))
	writeFile(t, filepath.Join(noStage, "x.expected.json"), `{"valid":true,"failure_reason":null}`)
	trailing := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(trailing, "x.json"))
	writeFile(t, filepath.Join(trailing, "x.expected.json"), `{"valid":true,"stage_reached":7,"failure_reason":null} {}`)
	record := filepath.Join(t.TempDir(), "activity_events.jsonl")
	writeFile(t, record, "{}\n")

	good := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(good, "x.json"))
	copyFile(t, genuine+".expected.json", filepath.Join(good, "x.expected.json"))

	empty := t.TempDir()

	type exitTwoCase struct {
		name string
		args []string
		want string
	}
	notDigits := func(stage string) string {
		return "error: fixture x.json: x.expected.json has \"stage_reached\": " + stage + ", which is not an unsigned integer written as digits alone"
	}
	cases := []exitTwoCase{
		{"expected file without stage_reached", []string{"--fixture-dir", noStage}, "error: fixture x.json: x.expected.json has no numeric \"stage_reached\""},
		{"expected file with data after the object", []string{"--fixture-dir", trailing}, "error: fixture x.json: x.expected.json is not a JSON object: data after the first JSON value"},
		{"fractional stage_reached", []string{"--fixture-dir", withStage("7.5")}, notDigits("7.5")},
		{"negative stage_reached", []string{"--fixture-dir", withStage("-1")}, notDigits("-1")},
		{"stage_reached with a zero fraction", []string{"--fixture-dir", withStage("7.0")}, notDigits("7.0")},
		{"stage_reached past float64", []string{"--fixture-dir", withStage("1e400")}, notDigits("1e400")},
		{"stage_reached past uint64", []string{"--fixture-dir", withStage("18446744073709551616")},
			"error: fixture x.json: x.expected.json has \"stage_reached\": 18446744073709551616, which is above 18446744073709551615"},
		{"customer activity", []string{"--customer-activity", record, "--fixture-dir", good}, "usage: -customer-activity applies to exactly one proof"},
		{"file as the root", []string{"--fixture-dir", genuine + ".json"}, "error: " + genuine + ".json is not a folder"},
		{"file argument", []string{"--fixture-dir", good, genuine + ".json"}, "usage: --fixture-dir takes no file argument"},
		{"empty folder", []string{"--fixture-dir", empty}, "error: no fixture under " + empty + " ("},
		{"missing folder", []string{"--fixture-dir", filepath.Join(t.TempDir(), "absent")}, "error: fixture walk failed: "},
		{"no expected file", []string{"--fixture-dir", noExpected}, "error: fixture x.json: no readable .expected.json sibling"},
		{"expected file without valid", []string{"--fixture-dir", noValid}, "error: fixture x.json: x.expected.json has no boolean \"valid\""},
		{"region pin", []string{"--required-region", "us-central1", "--fixture-dir", corpusRoot}, "usage: --fixture-dir runs each fixture under the policy"},
		{"authority pin", []string{"--required-authority-id", "us-kms-nanorix-v1", "--fixture-dir", corpusRoot}, "usage: --fixture-dir runs each fixture under the policy"},
		{"reject diagnostic", []string{"--reject-diagnostic", "--fixture-dir", corpusRoot}, "usage: --fixture-dir runs each fixture under the policy"},
		{"trust chain", []string{"--trust-chain", "absent.json", "--identity-fingerprint", "sha256:00", "--fixture-dir", corpusRoot}, "usage: --fixture-dir runs each fixture under the policy"},
	}
	symlinked := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(symlinked, "ok.json"))
	copyFile(t, genuine+".expected.json", filepath.Join(symlinked, "ok.expected.json"))
	deep := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(deep, "ok.json"))
	copyFile(t, genuine+".expected.json", filepath.Join(deep, "ok.expected.json"))
	if err := os.MkdirAll(filepath.Join(deep, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	canLink := os.Symlink(good, filepath.Join(symlinked, "link")) == nil
	if canLink {
		if err := os.Symlink(good, filepath.Join(deep, "a", "link")); err != nil {
			t.Fatal(err)
		}
		cases = append(cases,
			exitTwoCase{"symlinked subfolder", []string{"--fixture-dir", symlinked}, "error: fixture walk failed: " + filepath.Join(symlinked, "link") + " is a symlinked folder"},
			exitTwoCase{"symlinked subfolder below the top", []string{"--fixture-dir", deep}, "error: fixture walk failed: " + filepath.Join(deep, "a", "link") + " is a symlinked folder"})
	} else {
		t.Log("symlink cases skipped: os.Symlink is refused on this system")
	}

	switch {
	case runtime.GOOS == "windows":
		t.Log("unreadable cases skipped: a mode-000 file stays readable on Windows")
	case os.Geteuid() == 0:
		t.Log("unreadable cases skipped: running as root, which reads a mode-000 file")
	default:
		unreadableFile := t.TempDir()
		copyFile(t, genuine+".json", filepath.Join(unreadableFile, "x.json"))
		copyFile(t, genuine+".expected.json", filepath.Join(unreadableFile, "x.expected.json"))
		if err := os.Chmod(filepath.Join(unreadableFile, "x.json"), 0); err != nil {
			t.Fatal(err)
		}
		unreadableDir := t.TempDir()
		copyFile(t, genuine+".json", filepath.Join(unreadableDir, "ok.json"))
		copyFile(t, genuine+".expected.json", filepath.Join(unreadableDir, "ok.expected.json"))
		copyFile(t, genuine+".json", filepath.Join(unreadableDir, "sub", "y.json"))
		copyFile(t, genuine+".expected.json", filepath.Join(unreadableDir, "sub", "y.expected.json"))
		if err := os.Chmod(filepath.Join(unreadableDir, "sub"), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(filepath.Join(unreadableDir, "sub"), 0o755) })
		cases = append(cases,
			exitTwoCase{"unreadable fixture", []string{"--fixture-dir", unreadableFile}, "error: cannot read " + filepath.Join(unreadableFile, "x.json")},
			exitTwoCase{"unreadable subfolder", []string{"--fixture-dir", unreadableDir}, "error: fixture walk failed: open " + filepath.Join(unreadableDir, "sub") + ": permission denied"})
		if canLink {
			// The link's target sits in a folder this user cannot search, and
			// holds a fixture whose verdict differs from its expected file.
			hidden := t.TempDir()
			copyFile(t, genuine+".json", filepath.Join(hidden, "ok.json"))
			copyFile(t, genuine+".expected.json", filepath.Join(hidden, "ok.expected.json"))
			locked := filepath.Join(t.TempDir(), "locked")
			copyFile(t, genuine+".json", filepath.Join(locked, "sub", "y.json"))
			writeFile(t, filepath.Join(locked, "sub", "y.expected.json"), `{"valid":false,"stage_reached":2,"failure_reason":null}`)
			if err := os.Symlink(filepath.Join(locked, "sub"), filepath.Join(hidden, "hidden")); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(locked, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(locked, 0o755) })
			cases = append(cases, exitTwoCase{"symlink whose target cannot be read", []string{"--fixture-dir", hidden},
				"error: fixture walk failed: " + filepath.Join(hidden, "hidden") + " is a symlink whose target cannot be read"})
		}
	}
	// Each folder case again through a symlinked root: every path printed
	// stays under the root as given.
	if canLink {
		for _, c := range append([]exitTwoCase(nil), cases...) {
			dir := c.args[len(c.args)-1]
			if len(c.args) != 2 || c.args[0] != "--fixture-dir" || !strings.Contains(c.want, dir) {
				continue
			}
			if info, err := os.Stat(dir); err != nil || !info.IsDir() {
				continue
			}
			link := filepath.Join(t.TempDir(), "root")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			cases = append(cases, exitTwoCase{c.name + " under a symlinked root", []string{"--fixture-dir", link}, strings.Replace(c.want, dir, link, 1)})
		}
	}
	for _, c := range cases {
		code, stdout, stderr := runCLI(t, c.args...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, c.want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 2, no stdout, stderr starting %q",
				c.name, code, stdout, stderr, c.want)
		}
	}
}

// Help and the version exit 0 without reading anything. A gate that reads only
// the exit code would accept a proof written beside them, so beside any flag or
// file they exit 2 with nothing on stdout.
func TestHelpAndVersionExitZeroOnlyAlone(t *testing.T) {
	forged := filepath.Join(corpusRoot, "05_failure_region_mismatch", "0000_us-central1_to_europe-west1") + ".json"

	if code, stdout, stderr := runCLI(t, "-version"); code != 0 || stdout != "auditproof-verifier-go "+cliVersion+"\n" {
		t.Fatalf("-version alone: exit %d, stdout %q, stderr %q; want exit 0 and the version line", code, stdout, stderr)
	}
	if code, stdout, _ := runCLI(t, "--version"); code != 0 || stdout != "auditproof-verifier-go "+cliVersion+"\n" {
		t.Fatalf("--version alone: exit %d, stdout %q; want exit 0 and the version line", code, stdout)
	}
	for _, args := range [][]string{
		{"-help"}, {"--help"}, {"-h"},
		{"bundle", "verify", "-h"}, {"bundle", "extract", "--help"},
		{"pubkey-bundle", "verify", "-help"}, {"pubkey-bundle", "build", "-h"},
	} {
		if code, _, stderr := runCLI(t, args...); code != 0 {
			t.Errorf("%v: exit %d, stderr %q; want exit 0", args, code, stderr)
		}
	}
	if code, _, _ := runCLI(t, "--required-region", "europe-west1", forged); code != 1 {
		t.Fatalf("the pinned proof alone: exit %d, want 1", code)
	}

	const usage = "usage: -help, -h and -version are given alone, after the subcommand words; this run also got "
	for _, tc := range []struct {
		args  []string
		other string
	}{
		{[]string{"-version", forged}, forged},
		{[]string{"--version", forged}, forged},
		{[]string{"-version=true", forged}, forged},
		{[]string{"-version", "--required-region", "europe-west1", forged}, "--required-region"},
		{[]string{"--required-region", "europe-west1", "-version", forged}, "--required-region"},
		{[]string{"-json", "-version"}, "-json"},
		{[]string{"-version", "-json"}, "-json"},
		{[]string{"-version", "--"}, "--"},
		{[]string{"-help", forged}, forged},
		{[]string{"-h", forged}, forged},
		{[]string{"--required-region", "europe-west1", "--help", forged}, "--required-region"},
		{[]string{"bundle", "verify", "-h", "b.prb.json"}, "b.prb.json"},
		{[]string{"bundle", "verify", "-json", "-help"}, "-json"},
		{[]string{"pubkey-bundle", "verify", "-help", "--publisher-pubkey", "k.bin", "b.ppb.json"}, "--publisher-pubkey"},
		{[]string{"bundle", "-version", "verify", "b.prb.json"}, "b.prb.json"},
		{[]string{"verify", "-h"}, "verify"},
	} {
		code, stdout, stderr := runCLI(t, tc.args...)
		want := usage + strconv.Quote(tc.other) + "\n"
		if code != 2 || stdout != "" || stderr != want {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no stdout, stderr %q",
				tc.args, code, stdout, stderr, want)
		}
	}
}

// In single-file mode a flag or a second file after the proof file is refused:
// flag parsing stops at the file, so running would drop what follows it.
func TestSingleFileModeRefusesArgumentsAfterTheProofFile(t *testing.T) {
	pinned := filepath.Join(corpusRoot, "05_failure_region_mismatch", "0000_us-central1_to_europe-west1") + ".json"
	genuine := filepath.Join(corpusRoot, "01_single_capsule_success", "0001_v2_1_signed") + ".json"

	code, stdout, stderr := runCLI(t, "--required-region", "europe-west1", pinned)
	if code != 1 || !strings.Contains(stdout, "region_mismatch") {
		t.Fatalf("pin before the file: exit %d, stdout %q, stderr %q; want exit 1 with region_mismatch", code, stdout, stderr)
	}

	const usage = "usage: auditproof-verifier-go [flags] <auditproof.json>: flags go before the proof file"
	for _, c := range []struct {
		name string
		args []string
	}{
		{"flag after the file", []string{pinned, "--required-region", "europe-west1"}},
		{"second file", []string{genuine, filepath.Join(t.TempDir(), "absent.json")}},
		{"--fixture-dir after the file", []string{genuine, "--fixture-dir", corpusRoot}},
	} {
		code, stdout, stderr := runCLI(t, c.args...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, usage) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 2, no stdout, stderr starting %q",
				c.name, code, stdout, stderr, usage)
		}
	}
}

// A pin, policy or path flag given twice would keep one value and leave the
// other unchecked: a second key list and pin appended to a gate's line would
// replace the official pair. An empty value would apply nothing. Each refuses
// at flag parsing with exit 2 and no verdict, so no proof is read.
func TestARepeatedOrEmptyPinOrPolicyFlagRefusesWithExitTwo(t *testing.T) {
	genuine := filepath.Join(corpusRoot, "01_single_capsule_success", "0001_v2_1_signed") + ".json"
	if code, _, stderr := runCLI(t, genuine); code != 4 {
		t.Fatalf("control: the proof alone exits %d, want 4\nstderr:\n%s", code, stderr)
	}
	check := func(args []string, want string) {
		t.Helper()
		code, stdout, stderr := runCLI(t, args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, want) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no verdict, and %q",
				args, code, stdout, stderr, want)
		}
	}
	for _, name := range []string{"trust-chain", "identity-fingerprint", "required-region",
		"required-authority-id", "customer-activity", "fixture-dir"} {
		check([]string{"-" + name, "first", "-" + name, "second", genuine}, "for flag -"+name+": given twice")
		check([]string{"--" + name + "=first", "--" + name + "=first", genuine}, "for flag -"+name+": given twice")
		check([]string{"-" + name, "", genuine}, "for flag -"+name+": needs a value")
	}
	check([]string{"-reject-diagnostic", "-reject-diagnostic=false", genuine}, "reject-diagnostic: given twice")

	// The line a gate builds: the official key list and pin, then a second
	// pair. Both are refused before either list is read.
	dir := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures", "trust_chain")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name    string `json:"name"`
			KeyList string `json:"key_list"`
			Pin     string `json:"pin"`
			Proof   string `json:"proof"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Cases {
		if c.Name != "active_version_resolves" {
			continue
		}
		list, proof := filepath.Join(dir, c.KeyList), filepath.Join(dir, c.Proof)
		if code, _, stderr := runCLI(t, "-trust-chain", list, "-identity-fingerprint", c.Pin, proof); code != 0 {
			t.Fatalf("control: one pair exits %d, want 0\nstderr:\n%s", code, stderr)
		}
		check([]string{"-trust-chain", list, "-identity-fingerprint", c.Pin,
			"-trust-chain", list, "-identity-fingerprint", c.Pin, proof}, "for flag -trust-chain: given twice")
		check([]string{"-trust-chain", list, "-identity-fingerprint", c.Pin,
			"-identity-fingerprint", c.Pin, proof}, "for flag -identity-fingerprint: given twice")
		return
	}
	t.Fatal("cases.json has no active_version_resolves case")
}

// buildPubkeyBundle writes, in a new folder, a key list, a publisher key and a
// pubkey bundle of the list that the publisher signed. It returns the folder,
// the publisher key, the bundle and the build flags.
func buildPubkeyBundle(t *testing.T) (dir, pubPath, bundlePath string, build []string) {
	t.Helper()
	dir = t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 9
	}
	listed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	seedPath := filepath.Join(dir, "seed.bin")
	pubPath = filepath.Join(dir, "publisher.bin")
	keysPath := filepath.Join(dir, "keys.json")
	bundlePath = filepath.Join(dir, "bundle.ppb.json")
	writeFile(t, seedPath, string(seed))
	writeFile(t, pubPath, string(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)))
	writeFile(t, keysPath, fmt.Sprintf(`{"pubkeys":[{"key_id":"nrx-verify-test-1","algorithm":"Ed25519",`+
		`"public_key":%q,"valid_from":"2026-01-01T00:00:00Z","issued_by_org":"vendor:example"}]}`,
		base64.StdEncoding.EncodeToString(listed)))
	build = []string{"-keys", keysPath, "-output", bundlePath, "-signer-seed", seedPath,
		"-signer-key-id", "nrx-bundle-publisher-test", "-issuer-org", "vendor:example"}
	if code, _, stderr := runCLI(t, append([]string{"pubkey-bundle", "build"}, build...)...); code != 0 {
		t.Fatalf("pubkey-bundle build: exit %d\nstderr:\n%s", code, stderr)
	}
	return dir, pubPath, bundlePath, build
}

// pubkey-bundle verify pins the publisher's key; a second -publisher-pubkey
// would replace the first, so before the bundle file it refuses at flag
// parsing, and after it (where flag parsing has stopped) it refuses as an
// extra argument, though the first key signed the bundle.
func TestPubkeyBundleVerifyRefusesARepeatedPublisherKey(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	code, stdout, stderr := runCLI(t, "pubkey-bundle", "verify", "-publisher-pubkey", missing+".bin",
		"-publisher-pubkey", missing+"-2.bin", missing+".ppb.json")
	if code != 2 || stdout != "" || !strings.Contains(stderr, "for flag -publisher-pubkey: given twice") {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 2, no verdict, and the flag named as given twice", code, stdout, stderr)
	}

	_, pubPath, bundlePath, _ := buildPubkeyBundle(t)
	verify := []string{"pubkey-bundle", "verify", "-publisher-pubkey", pubPath, bundlePath}
	if code, _, stderr := runCLI(t, verify...); code != 0 {
		t.Fatalf("control: the bundle with its publisher key exits %d, want 0\nstderr:\n%s", code, stderr)
	}
	for _, extra := range [][]string{
		{"-publisher-pubkey", missing + ".bin"},
		{"-publisher-pubkey", pubPath},
		{bundlePath},
	} {
		args := append(append([]string{}, verify...), extra...)
		code, stdout, stderr := runCLI(t, args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "flags go before the bundle file") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no verdict, and the argument-count usage line", args, code, stdout, stderr)
		}
	}
}

// pubkey-bundle build takes flags only. An argument stops flag parsing, so a
// flag after it would be ignored (here the second -output); the line refuses
// with exit 2 instead of building.
func TestPubkeyBundleBuildRefusesAnArgumentAmongItsFlags(t *testing.T) {
	dir, _, _, build := buildPubkeyBundle(t)
	other := filepath.Join(dir, "other.ppb.json")
	for _, args := range [][]string{
		append(append([]string{"pubkey-bundle", "build"}, build...), "extra"),
		append(append([]string{"pubkey-bundle", "build"}, build...), "extra", "-output", other),
	} {
		code, stdout, stderr := runCLI(t, args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "pubkey-bundle build takes flags only") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, nothing built, and the flags-only usage line", args, code, stdout, stderr)
		}
	}
}

// bundle extract reads one proof. A flag written after it would be ignored (a
// -record 3 there would extract record 0), so the line refuses with exit 2
// before the proof is read; with the flags after the file only, the usage
// line gives the flags-first order.
func TestBundleExtractRefusesArgumentsAfterTheProofFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "claim.prb.json")
	proof := filepath.Join(dir, "absent.json")
	for _, args := range [][]string{
		{"bundle", "extract", "-output", out, proof, "-record", "3"},
		{"bundle", "extract", "-output", out, proof, proof},
	} {
		code, stdout, stderr := runCLI(t, args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "flags go before the proof file") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no output, and the argument-count usage line", args, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCLI(t, "bundle", "extract", proof, "-record", "0", "-output", out)
	if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: auditproof-verifier-go bundle extract --record N --output <out.prb.json> <auditproof.json>") {
		t.Errorf("flags after the file only: exit %d, stdout %q, stderr %q; want exit 2 and the flags-first usage line", code, stdout, stderr)
	}
}

// A root that is a symlink to a corpus folder is resolved, so the run compares
// the fixtures instead of reporting an empty folder, and names each fixture
// under the root as given.
func TestFixtureDirFollowsASymlinkedRoot(t *testing.T) {
	genuine := filepath.Join(corpusRoot, "01_single_capsule_success", "0001_v2_1_signed")
	real := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(real, "x.json"))
	copyFile(t, genuine+".expected.json", filepath.Join(real, "x.expected.json"))
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("os.Symlink is refused on this system: %v", err)
	}
	code, stdout, stderr := runCLI(t, "--fixture-dir", link)
	if code != 0 || stdout != "1 fixtures · 0 verified · 1 not_anchored · 0 not_verified\n1 of 1 match their expected verdict\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, _ = runCLI(t, "--json", "--fixture-dir", link)
	var report struct {
		Results []struct {
			Path string `json:"path"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || code != 0 || len(report.Results) != 1 {
		t.Fatalf("--json exit %d, %v:\n%s", code, err, stdout)
	}
	if want := filepath.Join(link, "x.json"); report.Results[0].Path != want {
		t.Fatalf("--json results[0].path is %q, want %q", report.Results[0].Path, want)
	}
}

// A symlink to a fixture file is a fixture; only a symlinked folder is refused.
func TestFixtureDirAcceptsASymlinkedFixtureFile(t *testing.T) {
	genuine := filepath.Join(corpusRoot, "01_single_capsule_success", "0001_v2_1_signed")
	dir := t.TempDir()
	copyFile(t, genuine+".json", filepath.Join(dir, "x.json"))
	copyFile(t, genuine+".expected.json", filepath.Join(dir, "x.expected.json"))
	copyFile(t, genuine+".expected.json", filepath.Join(dir, "l.expected.json"))
	if err := os.Symlink(filepath.Join(dir, "x.json"), filepath.Join(dir, "l.json")); err != nil {
		t.Skipf("os.Symlink is refused on this system: %v", err)
	}
	code, stdout, stderr := runCLI(t, "--fixture-dir", dir)
	if code != 0 || stdout != "2 fixtures · 0 verified · 2 not_anchored · 0 not_verified\n2 of 2 match their expected verdict\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// Without a key list a proof whose signature holds under the key it carries
// is not anchored: exit 4, status not_anchored, and no "Verified" line. The
// proof here is signed by a stranger's key, which the key list does not hold.
func TestSingleFileStageSevenExitsFourAsNotAnchored(t *testing.T) {
	proof := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures", "trust_chain", "proofs", "customer_v1_signed_by_stranger_key.json")

	code, stdout, stderr := runCLI(t, "--json", proof)
	if code != 4 {
		t.Fatalf("--json: exit %d, want 4\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, stdout)
	}
	if out["status"] != "not_anchored" || out["valid"] != true || out["stage_reached"] != float64(7) {
		t.Errorf("--json: status %v, valid %v, stage_reached %v; want not_anchored, true, 7", out["status"], out["valid"], out["stage_reached"])
	}
	if !strings.HasPrefix(stderr, "note: exiting 4") {
		t.Errorf("--json: stderr %q, want the exit 4 note", stderr)
	}

	code, stdout, stderr = runCLI(t, proof)
	if code != 4 {
		t.Fatalf("human: exit %d, want 4\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stdout, "Verified") || !strings.HasPrefix(stdout, "Signature valid · key NOT anchored") {
		t.Errorf("human output at stage 7 must not say Verified:\n%s", stdout)
	}
}

// With the key list and its pin, a proof signed by the listed key is
// verified: exit 0, status verified. The same list and pin refuse the
// stranger's proof with exit 1.
func TestSingleFileKeyListWithPinExitsZeroAsVerified(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures", "trust_chain")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name    string `json:"name"`
			KeyList string `json:"key_list"`
			Pin     string `json:"pin"`
			Proof   string `json:"proof"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		code   int
		status string
	}{
		"active_version_resolves":            {0, "verified"},
		"different_key_under_listed_version": {1, "not_verified"},
	}
	seen := 0
	for _, c := range vectors.Cases {
		w, ok := want[c.Name]
		if !ok {
			continue
		}
		seen++
		code, stdout, stderr := runCLI(t, "--json", "-trust-chain", filepath.Join(dir, c.KeyList),
			"-identity-fingerprint", c.Pin, filepath.Join(dir, c.Proof))
		var out map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("%s: --json output is not JSON: %v\n%s\nstderr:\n%s", c.Name, err, stdout, stderr)
		}
		if code != w.code || out["status"] != w.status {
			t.Errorf("%s: exit %d, status %v; want exit %d, status %s\nstderr:\n%s", c.Name, code, out["status"], w.code, w.status, stderr)
		}
	}
	if seen != len(want) {
		t.Fatalf("found %d of the %d named cases in cases.json", seen, len(want))
	}
}

// bundle verify checks a bundle against the key it carries and reads no key
// list, so a key list handed to it refuses with exit 2 wherever it is written:
// before the subcommand, before the file, or after the file.
func TestBundleVerifyRefusesTrustChainWithExitTwo(t *testing.T) {
	fixtures := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures")
	bundle := filepath.Join(fixtures, "bundles", "a_legacy_n1_idx0.prb.json")
	keyList := filepath.Join(fixtures, "trust_chain", "key_lists", "customer_v1.json")
	pin := "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f"

	if code, _, stderr := runCLI(t, "bundle", "verify", bundle); code != 0 {
		t.Fatalf("plain bundle verify: exit %d, want 0\nstderr:\n%s", code, stderr)
	}
	code, stdout, stderr := runCLI(t, "bundle", "verify", "-trust-chain", keyList, bundle)
	if code != 2 || !strings.Contains(stderr, "bundle verify does not read -trust-chain") || stdout != "" {
		t.Errorf("bundle verify -trust-chain: exit %d, stdout %q, stderr %q; want exit 2 and the refusal", code, stdout, stderr)
	}
	if code, stdout, _ := runCLI(t, "-trust-chain", keyList, "-identity-fingerprint", pin, "bundle", "verify", bundle); code != 2 || stdout != "" {
		t.Errorf("-trust-chain before bundle verify: exit %d, stdout %q; want exit 2 and no verdict", code, stdout)
	}
	code, stdout, stderr = runCLI(t, "bundle", "verify", bundle, "-trust-chain", keyList, "-identity-fingerprint", pin)
	if code != 2 || stdout != "" || !strings.Contains(stderr, "flags go before the bundle file") {
		t.Errorf("bundle verify with the key list after the file: exit %d, stdout %q, stderr %q; want exit 2, no verdict and the usage line", code, stdout, stderr)
	}
	if code, stdout, _ := runCLI(t, "bundle", "verify", bundle, bundle); code != 2 || stdout != "" {
		t.Errorf("bundle verify with two files: exit %d, stdout %q; want exit 2 and no verdict", code, stdout)
	}
	// Keeping the last of two values, or treating an empty one as absent, would
	// let an empty last value turn the refusal into exit 0.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"bundle", "verify", "-trust-chain", keyList, "-trust-chain=", bundle}, "for flag -trust-chain: given twice"},
		{[]string{"bundle", "verify", "-trust-chain", keyList, "--trust-chain", keyList, bundle}, "for flag -trust-chain: given twice"},
		{[]string{"bundle", "verify", "-trust-chain=", bundle}, "for flag -trust-chain: needs a value"},
		{[]string{"bundle", "verify", "-trust-chain", "", bundle}, "for flag -trust-chain: needs a value"},
	} {
		code, stdout, stderr := runCLI(t, c.args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no verdict, and %q", c.args, code, stdout, stderr, c.want)
		}
	}
}

// bundle verify checks one record's receipt and never reads the AuditProof's
// activity trail, region, authority or declared activity root, so each proof
// policy flag refuses with exit 2 wherever it is written: after the
// subcommand (its own flag set has no such flag) or before it (the proof flag
// set then sees three file arguments).
func TestBundleVerifyRefusesEveryProofPolicyFlagWithExitTwo(t *testing.T) {
	bundle := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures", "bundles", "a_legacy_n1_idx0.prb.json")
	if code, _, stderr := runCLI(t, "bundle", "verify", bundle); code != 0 {
		t.Fatalf("control: the bundle alone exits %d, want 0\nstderr:\n%s", code, stderr)
	}
	record := filepath.Join(t.TempDir(), "absent.jsonl")
	for _, flag := range [][]string{
		{"-reject-diagnostic"},
		{"-required-region", "europe-west1"},
		{"-required-authority-id", "customer-kms-example-a-v1"},
		{"-customer-activity", record},
	} {
		// After the subcommand the flag is not one bundle verify defines.
		after := append(append([]string{"bundle", "verify"}, flag...), bundle)
		code, stdout, stderr := runCLI(t, after...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "flag provided but not defined: "+flag[0]) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no verdict, and the undefined flag named", after, code, stdout, stderr)
		}
		// Before it, the subcommand words are read as proof files, and more
		// than one is refused before any file is read.
		before := append(append([]string{}, flag...), "bundle", "verify", bundle)
		code, stdout, stderr = runCLI(t, before...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "usage: auditproof-verifier-go [flags] <auditproof.json>") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no verdict, and the argument-count usage line", before, code, stdout, stderr)
		}
	}
}

// pubkey-bundle verify checks a signed bundle of public keys, not an
// AuditProof, so each proof policy flag refuses with exit 2 wherever it is
// written: after the subcommand (its own flag set has no such flag), after the
// bundle file (an extra argument), or before the subcommand (the proof flag set
// then sees the subcommand words as files).
func TestPubkeyBundleVerifyRefusesEveryProofPolicyFlagWithExitTwo(t *testing.T) {
	dir, pubPath, bundlePath, _ := buildPubkeyBundle(t)
	verify := []string{"pubkey-bundle", "verify", "-publisher-pubkey", pubPath, bundlePath}
	if code, _, stderr := runCLI(t, verify...); code != 0 {
		t.Fatalf("control: the bundle alone exits %d, want 0\nstderr:\n%s", code, stderr)
	}
	record := filepath.Join(dir, "absent.jsonl")
	for _, flag := range [][]string{
		{"-reject-diagnostic"},
		{"-required-region", "europe-west1"},
		{"-required-authority-id", "customer-kms-example-a-v1"},
		{"-customer-activity", record},
	} {
		after := append(append([]string{"pubkey-bundle", "verify"}, flag...), verify[2:]...)
		code, stdout, stderr := runCLI(t, after...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "flag provided but not defined: "+flag[0]) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no verdict, and the undefined flag named", after, code, stdout, stderr)
		}
		afterFile := append(append([]string{}, verify...), flag...)
		code, stdout, stderr = runCLI(t, afterFile...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "flags go before the bundle file") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no verdict, and the argument-count usage line", afterFile, code, stdout, stderr)
		}
		before := append(append([]string{}, flag...), verify...)
		code, stdout, stderr = runCLI(t, before...)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "usage: auditproof-verifier-go [flags] <auditproof.json>") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit 2, no verdict, and the argument-count usage line", before, code, stdout, stderr)
		}
	}
}

// The CLI applies -reject-diagnostic to a single AuditProof: a proof whose
// signed trail records diagnostic mode, and a 1.0 proof, each exit 1 with
// diagnostic_proof_refused at stage 2; without the flag each exits 4.
func TestRejectDiagnosticRefusesOnTheCLI(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures", "corpus", "12_failure_diagnostic_refused")
	for _, name := range []string{"0000_v2_2_signed_diagnostic_mode", "0001_v1_0_signed"} {
		proof := filepath.Join(dir, name+".json")
		if code, _, stderr := runCLI(t, proof); code != 4 {
			t.Errorf("%s without the flag: exit %d, want 4\nstderr:\n%s", name, code, stderr)
		}
		code, stdout, stderr := runCLI(t, "-reject-diagnostic", "-json", proof)
		if code != 1 {
			t.Errorf("%s: exit %d, want 1\nstderr:\n%s", name, code, stderr)
		}
		var out struct {
			FailureReason map[string]interface{} `json:"failure_reason"`
			StageReached  int                    `json:"stage_reached"`
			Status        string                 `json:"status"`
		}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("%s: %v\nstdout:\n%s", name, err, stdout)
		}
		if out.FailureReason["type"] != "diagnostic_proof_refused" || len(out.FailureReason) != 1 ||
			out.StageReached != 2 || out.Status != "not_verified" {
			t.Errorf("%s: got %+v; want diagnostic_proof_refused at stage 2, not_verified", name, out)
		}
	}
}
