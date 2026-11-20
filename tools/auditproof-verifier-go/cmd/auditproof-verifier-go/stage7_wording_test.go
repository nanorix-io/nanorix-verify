package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The stage 7 note must say what the signature covers: the signed view, not
// the whole proof.
func TestStage7NoteNamesTheSignedView(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "apv")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	proof := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures", "corpus", "01_single_capsule_success", "0000_v2_1_signed.json")
	out, err := exec.Command(bin, proof).CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 4 {
		t.Fatalf("verifier on a stage 7 proof: %v, want exit 4 (not anchored)\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "no signed byte has changed since signing") ||
		!strings.Contains(text, "outside the signed view") {
		t.Errorf("stage 7 note does not name the signed view:\n%s", text)
	}
	if strings.Contains(text, "has not been altered since signing") {
		t.Errorf("stage 7 note still claims the whole proof is unaltered:\n%s", text)
	}
}

// The shared 1.0 vector under the key list that holds its key, with that
// list's pin: the command exits 4 and names no key list as the remedy, on
// stderr or stdout, and says the key version is not covered.
func TestV10UnderItsKeyListNamesNoKeyListAsARemedy(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "apv")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	vectors := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures", "trust_chain")
	raw, err := os.ReadFile(filepath.Join(vectors, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Cases []struct {
			Name    string `json:"name"`
			KeyList string `json:"key_list"`
			Proof   string `json:"proof"`
			Pin     string `json:"pin"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cases.Cases {
		if c.Name != "v1_0_proof_never_anchors" {
			continue
		}
		found = true
		cmd := exec.Command(bin, "-trust-chain", filepath.Join(vectors, c.KeyList),
			"-identity-fingerprint", c.Pin, filepath.Join(vectors, c.Proof))
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 4 {
			t.Fatalf("1.0 under its key list: %v, want exit 4\n%s%s", err, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "a 1.0 proof is never anchored; no key list changes this") {
			t.Errorf("stderr does not give the 1.0 note:\n%s", stderr.String())
		}
		for name, text := range map[string]string{"stdout": stdout.String(), "stderr": stderr.String()} {
			if strings.Contains(text, "-trust-chain") || strings.Contains(text, "to anchor the key") {
				t.Errorf("%s names a key list as the remedy:\n%s", name, text)
			}
		}
		if !strings.Contains(stdout.String(), "Signing key version (not covered by a 1.0 signature): ") {
			t.Errorf("stdout does not say the key version is not covered:\n%s", stdout.String())
		}
	}
	if !found {
		t.Fatal("the shared 1.0 case is missing")
	}
}
