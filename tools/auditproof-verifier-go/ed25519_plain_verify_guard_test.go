package auditproof

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plainVerifyAllowList names the only non-test Go files that may call the stdlib
// ed25519.Verify directly, each with the reason.
var plainVerifyAllowList = map[string]string{
	"tools/auditproof-verifier-go/ed25519.go": "the strict wrapper itself: it screens small-order keys and R and S >= L before calling Verify",
}

func plainVerifyCalls(src string) []int {
	var lines []int
	for i, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") {
			continue
		}
		if strings.Contains(t, "ed25519.Verify(") {
			lines = append(lines, i+1)
		}
	}
	return lines
}

func TestPlainVerifyScannerFindsACall(t *testing.T) {
	if got := plainVerifyCalls("x := 1\n\tok := ed25519.Verify(k, m, s)\n"); len(got) != 1 || got[0] != 2 {
		t.Fatalf("scanner missed a plain call: %v", got)
	}
	if got := plainVerifyCalls("// ed25519.Verify(k, m, s)\n"); len(got) != 0 {
		t.Fatalf("scanner flagged a comment: %v", got)
	}
}

func TestNoGoFileCallsPlainEd25519VerifyOutsideTheAllowList(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if strings.HasPrefix(name, ".") && path != root || name == "node_modules" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		if _, ok := plainVerifyAllowList[rel]; ok {
			return nil
		}
		for _, n := range plainVerifyCalls(string(body)) {
			offenders = append(offenders, rel+":"+itoa(n))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 10 {
		t.Fatalf("scanned only %d Go files; the walk is not reaching the tree", scanned)
	}
	if len(offenders) > 0 {
		t.Fatalf("plain ed25519.Verify outside the strict wrapper: %v", offenders)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
