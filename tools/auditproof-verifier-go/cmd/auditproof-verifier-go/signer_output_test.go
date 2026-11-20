package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	auditproof "github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go"
)

// printSigner names the signer the proof's own labels claim and says whether
// the signature covers them: on 2.1 and 2.2 it does, on 1.0 it does not.
func TestPrintSignerGoldens(t *testing.T) {
	stage := func(n uint8, signed *bool) auditproof.AuditProofVerificationResult {
		r := auditproof.AuditProofVerificationResult{Valid: true, StageReached: n}
		r.Metadata.AuthoritySigned = signed
		return r
	}
	covered, notCovered := true, false
	cases := []struct {
		name  string
		r     auditproof.AuditProofVerificationResult
		proof string
		want  string
	}{
		{
			"customer_only at stage 7",
			stage(7, &covered),
			`{"cdp_version":"2.1","signing_mode":"customer_only","authority_id":"us-customer-kms-acme-v1","signing_key_version":"3"}`,
			"  Signer: authority us-customer-kms-acme-v1, key version 3 (covered by the signature)\n" +
				"  Signing mode: customer_only (covered by the signature)\n" +
				"  This proof's signed labels name a customer authority (us-customer-kms-acme-v1). To anchor its key, supply the key list and identity fingerprint published for that authority.\n",
		},
		{
			"legacy pair at stage 7",
			stage(7, &covered),
			`{"cdp_version":"2.2","signing_mode":"nanorix_only","authority_id":"us-customer-kms-acme-v1","signing_key_version":"1"}`,
			"  Signer: authority us-customer-kms-acme-v1, key version 1 (covered by the signature)\n" +
				"  Signing mode: nanorix_only (covered by the signature)\n" +
				"  signing_mode predates customer_only; this proof names a customer-classified authority, which only stage 8 (the customer's key list) anchors to the key that signed.\n" +
				"  This proof's signed labels name a customer authority (us-customer-kms-acme-v1). To anchor its key, supply the key list and identity fingerprint published for that authority.\n",
		},
		{
			"a Nanorix proof at stage 7",
			stage(7, &covered),
			`{"cdp_version":"2.1","signing_mode":"nanorix_only","authority_id":"us-kms-nanorix-v1","signing_key_version":"1"}`,
			"  Signer: authority us-kms-nanorix-v1, key version 1 (covered by the signature)\n" +
				"  Signing mode: nanorix_only (covered by the signature)\n",
		},
		{
			"an absent authority is the default, marked as one",
			stage(7, &covered),
			`{"cdp_version":"2.1","signing_mode":"nanorix_only","signing_key_version":"1"}`,
			"  Signer: authority us-kms-nanorix-v1 (default: absent from the proof; the signature covers its absence), key version 1 (covered by the signature)\n" +
				"  Signing mode: nanorix_only (covered by the signature)\n",
		},
		{
			"a non-string authority is the default, marked as one",
			stage(7, &covered),
			`{"cdp_version":"2.1","signing_mode":"nanorix_only","authority_id":7,"signing_key_version":"1"}`,
			"  Signer: authority us-kms-nanorix-v1 (default: not a string in the proof; the signature covers the value 7), key version 1 (covered by the signature)\n" +
				"  Signing mode: nanorix_only (covered by the signature)\n",
		},
		{
			"an absent mode is the default, marked as one",
			stage(7, &covered),
			`{"cdp_version":"2.1","authority_id":"us-kms-nanorix-v1","signing_key_version":"1"}`,
			"  Signer: authority us-kms-nanorix-v1, key version 1 (covered by the signature)\n" +
				"  Signing mode: nanorix_only (default: absent from the proof; the signature covers its absence)\n",
		},
		{
			"a key version that is not a number prints what the signature binds",
			stage(7, &covered),
			`{"cdp_version":"2.1","signing_mode":"nanorix_only","authority_id":"us-kms-nanorix-v1","signing_key_version":"abc"}`,
			"  Signer: authority us-kms-nanorix-v1 (covered by the signature), key version abc (not a number; the signature covers 0)\n" +
				"  Signing mode: nanorix_only (covered by the signature)\n",
		},
		{
			"an absent key version prints what the signature binds",
			stage(7, &covered),
			`{"cdp_version":"2.1","signing_mode":"nanorix_only","authority_id":"us-kms-nanorix-v1"}`,
			"  Signer: authority us-kms-nanorix-v1 (covered by the signature), key version none (absent from the proof; the signature covers 0)\n" +
				"  Signing mode: nanorix_only (covered by the signature)\n",
		},
		{
			"1.0 labels are not covered",
			stage(7, &notCovered),
			`{"cdp_version":"1.0","authority_id":"us-customer-kms-acme-v1","signing_key_version":"1"}`,
			"  Signer: authority us-customer-kms-acme-v1, key version 1 (not covered by the signature)\n",
		},
		{
			"an absent 1.0 authority is the default, not covered",
			stage(7, &notCovered),
			`{"cdp_version":"1.0"}`,
			"  Signer: authority us-kms-nanorix-v1 (default: absent from the proof; not covered by the signature), key version (none) (not covered by the signature)\n",
		},
		{
			"no signature checked",
			stage(4, nil),
			`{"cdp_version":"2.1","signing_mode":"customer_only","authority_id":"customer-kms-acme","signing_key_version":"1"}`,
			"  Signer: authority customer-kms-acme, key version 1 (no signature was checked)\n" +
				"  Signing mode: customer_only (no signature was checked)\n",
		},
		{
			"control and non-ASCII text is escaped",
			stage(4, nil),
			`{"cdp_version":"2.1","signing_mode":"customer_only‮","authority_id":"acme\u001b[2J\nx","signing_key_version":"1\r"}`,
			"  Signer: authority acme\\u{1b}[2J\\u{a}x, key version 1\\u{d} (no signature was checked)\n" +
				"  Signing mode: customer_only\\u{202e} (no signature was checked)\n",
		},
	}
	for _, c := range cases {
		var out bytes.Buffer
		printSigner(&out, c.r, []byte(c.proof), nil)
		if out.String() != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, out.String(), c.want)
		}
		if strings.Contains(out.String(), "does not hold") || strings.Contains(out.String(), "hold this key") {
			t.Errorf("%s: the output claims who holds the key:\n%s", c.name, out.String())
		}
	}
}

// At stage 8 the key list resolved the attestation's key version; when that
// differs from the signed top-level one, the output says which it used.
func TestPrintSignerNamesAResolvedKeyVersionThatDiffersFromTheSignedOne(t *testing.T) {
	root := filepath.Join("..", "..", "..", "nanorix-verify", "fixtures", "trust_chain")
	raw, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Cases []map[string]interface{} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	var keyList, pin string
	for _, c := range parsed.Cases {
		if c["name"] == "active_version_resolves" {
			keyList, pin = c["key_list"].(string), c["pin"].(string)
		}
	}
	listBytes, err := os.ReadFile(filepath.Join(root, keyList))
	if err != nil {
		t.Fatal(err)
	}
	tc, err := auditproof.LoadTrustChain(listBytes, pin)
	if err != nil {
		t.Fatal(err)
	}
	covered := true
	r := auditproof.AuditProofVerificationResult{Valid: true, StageReached: 8}
	r.Metadata.AuthoritySigned = &covered
	const line = "  Key list resolved key version 2 (read from attestation.signing_key_version, which the signature does not cover)\n"
	var differs bytes.Buffer
	printSigner(&differs, r, []byte(`{"cdp_version":"2.1","signing_mode":"customer_only","authority_id":"us-customer-kms-acme-v1","signing_key_version":"1","attestation":{"signing_key_version":"2"}}`), tc)
	if !strings.Contains(differs.String(), line) {
		t.Errorf("the resolved key version is not named:\n%s", differs.String())
	}
	var same bytes.Buffer
	printSigner(&same, r, []byte(`{"cdp_version":"2.1","signing_mode":"customer_only","authority_id":"us-customer-kms-acme-v1","signing_key_version":"1","attestation":{"signing_key_version":"1"}}`), tc)
	if strings.Contains(same.String(), "Key list resolved key version") {
		t.Errorf("a resolved key version equal to the signed one is named:\n%s", same.String())
	}
}

// The mismatch names the claimed authority, or the one shared phrase when the
// proof's authority_id is absent or not a string.
func TestFailureLineNamesTheClaimedAuthorityOnAMismatch(t *testing.T) {
	claimed := "us-kms-nanorix-v1"
	for _, c := range []struct {
		claimed *string
		want    string
	}{
		{&claimed, "signing_mode_authority_mismatch (signing_mode: customer_only, claimed_authority_id: us-kms-nanorix-v1)"},
		{nil, "signing_mode_authority_mismatch (signing_mode: customer_only, claimed_authority_id: absent or not a string, so the Nanorix default applies)"},
	} {
		got := failureLine(&auditproof.FailureReason{Type: auditproof.ReasonSigningModeAuthorityMismatch, ClaimedAuthorityID: c.claimed})
		if got != c.want {
			t.Errorf("got %q\nwant %q", got, c.want)
		}
	}
}
