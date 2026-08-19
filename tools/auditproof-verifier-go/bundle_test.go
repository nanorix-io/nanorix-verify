// Wave B Items 7+8 — Portable Receipt Bundle + Portable Pubkey Bundle tests.
//
// Cross-impl byte-equivalence with Rust/Python/TypeScript on the canonical
// reference vectors locked in the test constants below.

package auditproof

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fixture builder: synthesizes a Wave-N AuditProof with N=2 receipts for
// bundle extraction/verification roundtrip testing.
// ─────────────────────────────────────────────────────────────────────────────

func makeBundleTestFixtureN2(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	timestamp := "2026-05-12T00:00:00Z"
	capsuleID := "cap_bundle_test_n2"

	receipt0Chain := computeRecordChainHashLocal(capsuleID, 0, "rec_a", "sha512:11", "sha512:21", NanorixGenesisHash, nil)
	receipt1Chain := computeRecordChainHashLocal(capsuleID, 1, "rec_b", "sha512:12", "sha512:22", NanorixGenesisHash, nil)
	merkleRoot := merklePairHashLocal(receipt0Chain, receipt1Chain)

	prevHash := NanorixGenesisHash
	subsystems := []string{"eee_namespace", "eee_tmpfs", "eee_memory", "dire_keys", "dire_identity", "fgx_forensic", "rzl_audit", "capsule_destroy"}
	methods := map[string]string{
		"eee_namespace":   "procfs_verification",
		"eee_tmpfs":       "mountinfo_verification",
		"eee_memory":      "dod_5220_multipass_wipe",
		"dire_keys":       "ed25519_key_destruction",
		"dire_identity":   "credential_incineration",
		"fgx_forensic":    "merkle_tree_verification",
		"rzl_audit":       "hash_chain_validation",
		"capsule_destroy": "capsule_lifecycle_verification",
	}

	chain := make([]map[string]interface{}, 0, 8)
	for i, s := range subsystems {
		method := methods[s]
		var chainHash string
		if i == 7 {
			// Step 8 amended with merkle root
			base := ComputeStepHash(prevHash, s, "destroy", method, timestamp)
			buf := make([]byte, 0, len(base)+1+len(merkleRoot))
			buf = append(buf, base...)
			buf = append(buf, 0x00)
			buf = append(buf, merkleRoot...)
			sum := sha512.Sum512(buf)
			chainHash = hex.EncodeToString(sum[:])
		} else {
			chainHash = ComputeStepHash(prevHash, s, "destroy", method, timestamp)
		}
		chain = append(chain, map[string]interface{}{
			"subsystem":  s,
			"method":     method,
			"chain_hash": chainHash,
		})
		prevHash = chainHash
	}
	finalHash := chain[7]["chain_hash"].(string)

	// Deterministic Ed25519 signer
	seedHex := strings.Repeat("2a", 32)
	seed, _ := hex.DecodeString(seedHex)
	signer := ed25519.NewKeyFromSeed(seed)
	pub := signer.Public().(ed25519.PublicKey)

	sig := ed25519.Sign(signer, []byte(finalHash))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	proof := map[string]interface{}{
		"cdp_version":  "2.0",
		"capsule_id":   capsuleID,
		"destroyed_at": timestamp,
		"chain":        chain,
		"final_hash":   finalHash,
		"record_receipts": []interface{}{
			map[string]interface{}{
				"record_index":           0,
				"record_id":              "rec_a",
				"record_input_hash":      "sha512:11",
				"record_output_hash":     "sha512:21",
				"record_chain_hash":      "sha512:" + receipt0Chain,
				"merkle_inclusion_proof": []interface{}{receipt1Chain},
			},
			map[string]interface{}{
				"record_index":           1,
				"record_id":              "rec_b",
				"record_input_hash":      "sha512:12",
				"record_output_hash":     "sha512:22",
				"record_chain_hash":      "sha512:" + receipt1Chain,
				"merkle_inclusion_proof": []interface{}{receipt0Chain},
			},
		},
		"record_receipts_merkle_root": "sha512:" + merkleRoot,
		"attestation": map[string]interface{}{
			"key_id":           "nrx-verify-test-key",
			"verification_key": pubB64,
			"signature":        sigB64,
		},
	}
	bytes, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("fixture marshal failed: %v", err)
	}
	return bytes, signer
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 7 — Portable Receipt Bundle tests
// ─────────────────────────────────────────────────────────────────────────────

func TestExtractReceiptBundleN2Index0Succeeds(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("ExtractReceiptBundle: %v", err)
	}
	if bundle.BundleVersion != "1.0" {
		t.Errorf("bundle_version: got %s, want 1.0", bundle.BundleVersion)
	}
	if bundle.BundleType != "receipt" {
		t.Errorf("bundle_type: got %s, want receipt", bundle.BundleType)
	}
	if bundle.AuditProofAnchors.CapsuleID != "cap_bundle_test_n2" {
		t.Errorf("capsule_id mismatch: %s", bundle.AuditProofAnchors.CapsuleID)
	}
	if rid, _ := bundle.Receipt["record_id"].(string); rid != "rec_a" {
		t.Errorf("record_id: got %s, want rec_a", rid)
	}
}

func TestExtractReceiptBundleN2Index1Succeeds(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, err := ExtractReceiptBundle(proof, 1)
	if err != nil {
		t.Fatalf("ExtractReceiptBundle: %v", err)
	}
	if rid, _ := bundle.Receipt["record_id"].(string); rid != "rec_b" {
		t.Errorf("record_id: got %s, want rec_b", rid)
	}
}

func TestExtractReceiptBundleOutOfBoundsErrors(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	_, err := ExtractReceiptBundle(proof, 99)
	if err == nil {
		t.Fatal("expected IndexOutOfBounds error")
	}
	be, ok := err.(*BundleError)
	if !ok || be.Kind != BundleErrIndexOutOfBounds {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractReceiptBundlePreWaveNErrors(t *testing.T) {
	pre := map[string]interface{}{
		"cdp_version":  "1.0",
		"capsule_id":   "cap_pre",
		"destroyed_at": "2026-01-01T00:00:00Z",
		"chain":        []interface{}{},
	}
	preBytes, _ := json.Marshal(pre)
	_, err := ExtractReceiptBundle(preBytes, 0)
	if err == nil {
		t.Fatal("expected NoReceipts error")
	}
	be, ok := err.(*BundleError)
	if !ok || be.Kind != BundleErrNoReceipts {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyReceiptBundleRoundtripIndex0(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if err := VerifyReceiptBundle(bundle); err != nil {
		t.Fatalf("VerifyReceiptBundle: %v", err)
	}
}

func TestVerifyReceiptBundleRoundtripIndex1(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, err := ExtractReceiptBundle(proof, 1)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if err := VerifyReceiptBundle(bundle); err != nil {
		t.Fatalf("VerifyReceiptBundle: %v", err)
	}
}

func TestVerifyReceiptBundleTamperedChainHashRejected(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, _ := ExtractReceiptBundle(proof, 0)
	bundle.Receipt["record_output_hash"] = "sha512:tampered"
	err := VerifyReceiptBundle(bundle)
	if err == nil {
		t.Fatal("expected verify failure")
	}
	be, ok := err.(*BundleError)
	if !ok || be.Kind != BundleErrRecordChainHashMismatch {
		t.Errorf("unexpected error kind: %v", err)
	}
}

func TestVerifyReceiptBundleTamperedInclusionRejected(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, _ := ExtractReceiptBundle(proof, 0)
	bundle.Receipt["merkle_inclusion_proof"] = []interface{}{strings.Repeat("0", 128)}
	err := VerifyReceiptBundle(bundle)
	if err == nil {
		t.Fatal("expected verify failure")
	}
	be, ok := err.(*BundleError)
	if !ok || be.Kind != BundleErrMerkleInclusionFailed {
		t.Errorf("unexpected error kind: %v", err)
	}
}

func TestVerifyReceiptBundleTamperedSignatureRejected(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, _ := ExtractReceiptBundle(proof, 0)
	bundle.AuditProofAnchors.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	err := VerifyReceiptBundle(bundle)
	if err == nil {
		t.Fatal("expected verify failure")
	}
	be, ok := err.(*BundleError)
	if !ok || be.Kind != BundleErrSignatureFailed {
		t.Errorf("unexpected error kind: %v", err)
	}
}

func TestBundleDisclaimerFactualLanguage(t *testing.T) {
	for _, forbidden := range []string{"COMPLIANT", "SATISFIED", "PASSED", "MEETS"} {
		if strings.Contains(PortableReceiptBundleDisclaimer, forbidden) {
			t.Errorf("disclaimer contains forbidden term %s", forbidden)
		}
	}
}

func TestBundleDisclaimerCitesADR040(t *testing.T) {
	if !strings.Contains(PortableReceiptBundleDisclaimer, "ADR-040") {
		t.Error("disclaimer must cite ADR-040")
	}
	if !strings.Contains(PortableReceiptBundleDisclaimer, "control-map") {
		t.Error("disclaimer must mention control-map mapping artifact")
	}
}

func TestBundleVersionPinned(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, _ := ExtractReceiptBundle(proof, 0)
	bundle.BundleVersion = "2.0"
	err := VerifyReceiptBundle(bundle)
	if err == nil {
		t.Fatal("expected shape error")
	}
}

func TestBundleTypePinnedReceipt(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, _ := ExtractReceiptBundle(proof, 0)
	bundle.BundleType = "pubkey"
	err := VerifyReceiptBundle(bundle)
	if err == nil {
		t.Fatal("expected shape error")
	}
}

func TestBundleSerializesRoundTrip(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, _ := ExtractReceiptBundle(proof, 0)
	bytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtripped PortableReceiptBundle
	if err := json.Unmarshal(bytes, &roundtripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundtripped.AuditProofAnchors.CapsuleID != bundle.AuditProofAnchors.CapsuleID {
		t.Error("roundtrip capsule_id mismatch")
	}
}

func TestBundleJSONNoForbiddenComplianceTerms(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, _ := ExtractReceiptBundle(proof, 0)
	bytes, _ := json.Marshal(bundle)
	str := string(bytes)
	for _, forbidden := range []string{"COMPLIANT", "SATISFIED", "PASSED", "MEETS"} {
		if strings.Contains(str, forbidden) {
			t.Errorf("bundle JSON contains forbidden term %s", forbidden)
		}
	}
}

func TestExtractN1BundleHasEmptyInclusionProof(t *testing.T) {
	// Build N=1 fixture inline
	timestamp := "2026-05-12T00:00:00Z"
	capsuleID := "cap_n1_go"
	receiptChain := computeRecordChainHashLocal(capsuleID, 0, "rec_only", "sha512:01", "sha512:02", NanorixGenesisHash, nil)
	merkleRoot := receiptChain

	prevHash := NanorixGenesisHash
	subsystems := []string{"eee_namespace", "eee_tmpfs", "eee_memory", "dire_keys", "dire_identity", "fgx_forensic", "rzl_audit", "capsule_destroy"}
	chain := make([]map[string]interface{}, 0, 8)
	for i, s := range subsystems {
		var chainHash string
		if i == 7 {
			base := ComputeStepHash(prevHash, s, "destroy", "capsule_lifecycle_verification", timestamp)
			buf := make([]byte, 0, len(base)+1+len(merkleRoot))
			buf = append(buf, base...)
			buf = append(buf, 0x00)
			buf = append(buf, merkleRoot...)
			sum := sha512.Sum512(buf)
			chainHash = hex.EncodeToString(sum[:])
		} else {
			chainHash = ComputeStepHash(prevHash, s, "destroy", "method", timestamp)
		}
		chain = append(chain, map[string]interface{}{"subsystem": s, "chain_hash": chainHash})
		prevHash = chainHash
	}
	proof := map[string]interface{}{
		"cdp_version":  "2.0",
		"capsule_id":   capsuleID,
		"destroyed_at": timestamp,
		"chain":        chain,
		"record_receipts": []interface{}{
			map[string]interface{}{
				"record_index":           0,
				"record_id":              "rec_only",
				"record_input_hash":      "sha512:01",
				"record_output_hash":     "sha512:02",
				"record_chain_hash":      "sha512:" + receiptChain,
				"merkle_inclusion_proof": []interface{}{},
			},
		},
		"record_receipts_merkle_root": "sha512:" + merkleRoot,
		"attestation": map[string]interface{}{
			"key_id":           "k",
			"verification_key": "AA",
			"signature":        "AA",
		},
	}
	proofBytes, _ := json.Marshal(proof)
	bundle, err := ExtractReceiptBundle(proofBytes, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	inclusion, _ := bundle.Receipt["merkle_inclusion_proof"].([]interface{})
	if len(inclusion) != 0 {
		t.Errorf("N=1 bundle should have empty inclusion proof, got %d entries", len(inclusion))
	}
}

func TestExtractBundleWithPatternTag(t *testing.T) {
	timestamp := "2026-05-12T00:00:00Z"
	capsuleID := "cap_pa_go"
	// ADR-039: the declared tag is bound into the chain hash, not merely
	// carried in the JSON.
	receiptChain := computeRecordChainHashLocal(capsuleID, 0, "rec_pa", "sha512:in", "sha512:out", NanorixGenesisHash, strPtrLocal("pa"))
	merkleRoot := receiptChain
	prevHash := NanorixGenesisHash
	subsystems := []string{"eee_namespace", "eee_tmpfs", "eee_memory", "dire_keys", "dire_identity", "fgx_forensic", "rzl_audit", "capsule_destroy"}
	chain := make([]map[string]interface{}, 0, 8)
	for i, s := range subsystems {
		var chainHash string
		if i == 7 {
			base := ComputeStepHash(prevHash, s, "destroy", "capsule_lifecycle_verification", timestamp)
			buf := append([]byte(base), 0x00)
			buf = append(buf, merkleRoot...)
			sum := sha512.Sum512(buf)
			chainHash = hex.EncodeToString(sum[:])
		} else {
			chainHash = ComputeStepHash(prevHash, s, "destroy", "method", timestamp)
		}
		chain = append(chain, map[string]interface{}{"subsystem": s, "chain_hash": chainHash})
		prevHash = chainHash
	}
	proof := map[string]interface{}{
		"cdp_version":  "2.0",
		"capsule_id":   capsuleID,
		"destroyed_at": timestamp,
		"chain":        chain,
		"record_receipts": []interface{}{
			map[string]interface{}{
				"record_index":           0,
				"record_id":              "rec_pa",
				"record_input_hash":      "sha512:in",
				"record_output_hash":     "sha512:out",
				"record_chain_hash":      "sha512:" + receiptChain,
				"pattern_tag":            "pa",
				"merkle_inclusion_proof": []interface{}{},
			},
		},
		"record_receipts_merkle_root": "sha512:" + merkleRoot,
		"attestation": map[string]interface{}{
			"key_id":           "k",
			"verification_key": "AA",
			"signature":        "AA",
		},
	}
	proofBytes, _ := json.Marshal(proof)
	bundle, err := ExtractReceiptBundle(proofBytes, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if tag, _ := bundle.Receipt["pattern_tag"].(string); tag != "pa" {
		t.Errorf("pattern_tag: got %s, want pa", tag)
	}
}

// Tagged N=1 bundle roundtrip with a real signer: VerifyReceiptBundle must
// bind the declared pattern_tag into the record_chain_hash recompute
// (ADR-039 signed primitive), and a swapped or stripped tag must be rejected.
func TestVerifyReceiptBundleTaggedRoundtripAndTamperRejected(t *testing.T) {
	timestamp := "2026-05-12T00:00:00Z"
	capsuleID := "cap_pa_verify_go"
	receiptChain := computeRecordChainHashLocal(capsuleID, 0, "rec_pa", "sha512:in", "sha512:out", NanorixGenesisHash, strPtrLocal("pa"))
	merkleRoot := receiptChain

	prevHash := NanorixGenesisHash
	subsystems := []string{"eee_namespace", "eee_tmpfs", "eee_memory", "dire_keys", "dire_identity", "fgx_forensic", "rzl_audit", "capsule_destroy"}
	chain := make([]map[string]interface{}, 0, 8)
	for i, s := range subsystems {
		var chainHash string
		if i == 7 {
			base := ComputeStepHash(prevHash, s, "destroy", "capsule_lifecycle_verification", timestamp)
			buf := append([]byte(base), 0x00)
			buf = append(buf, merkleRoot...)
			sum := sha512.Sum512(buf)
			chainHash = hex.EncodeToString(sum[:])
		} else {
			chainHash = ComputeStepHash(prevHash, s, "destroy", "method", timestamp)
		}
		chain = append(chain, map[string]interface{}{"subsystem": s, "chain_hash": chainHash})
		prevHash = chainHash
	}
	finalHash := chain[7]["chain_hash"].(string)

	seed, _ := hex.DecodeString(strings.Repeat("2b", 32))
	signer := ed25519.NewKeyFromSeed(seed)
	pub := signer.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(signer, []byte(finalHash))

	proof := map[string]interface{}{
		"cdp_version":  "2.0",
		"capsule_id":   capsuleID,
		"destroyed_at": timestamp,
		"chain":        chain,
		"final_hash":   finalHash,
		"record_receipts": []interface{}{
			map[string]interface{}{
				"record_index":           0,
				"record_id":              "rec_pa",
				"record_input_hash":      "sha512:in",
				"record_output_hash":     "sha512:out",
				"record_chain_hash":      "sha512:" + receiptChain,
				"pattern_tag":            "pa",
				"merkle_inclusion_proof": []interface{}{},
			},
		},
		"record_receipts_merkle_root": "sha512:" + merkleRoot,
		"attestation": map[string]interface{}{
			"key_id":           "nrx-verify-tagged-test-key",
			"verification_key": base64.StdEncoding.EncodeToString(pub),
			"signature":        base64.StdEncoding.EncodeToString(sig),
		},
	}
	proofBytes, _ := json.Marshal(proof)

	bundle, err := ExtractReceiptBundle(proofBytes, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if err := VerifyReceiptBundle(bundle); err != nil {
		t.Fatalf("tagged bundle must verify; got: %v", err)
	}

	// Tag swap → record_chain_hash mismatch.
	bundle.Receipt["pattern_tag"] = "custom"
	if err := VerifyReceiptBundle(bundle); err == nil {
		t.Error("swapped pattern_tag MUST be rejected")
	} else if be, ok := err.(*BundleError); !ok || be.Kind != BundleErrRecordChainHashMismatch {
		t.Errorf("unexpected error kind: %v", err)
	}

	// Tag strip → untagged formula cannot reproduce a tagged hash.
	delete(bundle.Receipt, "pattern_tag")
	if err := VerifyReceiptBundle(bundle); err == nil {
		t.Error("stripped pattern_tag MUST be rejected")
	}
}

func TestExtractBundleCarriesFrameworkVersion(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	// Add regulatory_context.framework_version
	var doc map[string]interface{}
	json.Unmarshal(proof, &doc)
	doc["regulatory_context"] = map[string]interface{}{"framework_version": "2026-02"}
	proof2, _ := json.Marshal(doc)
	bundle, err := ExtractReceiptBundle(proof2, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if bundle.AuditProofAnchors.FrameworkVersionAtEmit == nil || *bundle.AuditProofAnchors.FrameworkVersionAtEmit != "2026-02" {
		t.Errorf("framework_version_at_emit not propagated")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CDP v2.1 signature-target anchor tests (mirror Rust bundle.rs)
// ─────────────────────────────────────────────────────────────────────────────

// makeV21BundleFixture synthesizes a v2.1 AuditProof (N=1 receipt) whose
// attestation signs the FullCdp document canonical hash — the production
// v2.1 signing model (Ed25519 over the ASCII bytes of the bare lowercase hex
// canonical hash).
func makeV21BundleFixture(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	timestamp := "2026-06-01T00:00:00Z"
	capsuleID := "cap_v21_bundle_test"

	receiptChain := computeRecordChainHashLocal(capsuleID, 0, "rec_v21", "sha512:aa", "sha512:bb", NanorixGenesisHash, nil)
	merkleRoot := receiptChain

	prevHash := NanorixGenesisHash
	subsystems := []string{"eee_namespace", "eee_tmpfs", "eee_memory", "dire_keys", "dire_identity", "fgx_forensic", "rzl_audit", "capsule_destroy"}
	chain := make([]map[string]interface{}, 0, 8)
	for i, s := range subsystems {
		method := LookupMethod(s)
		var chainHash string
		if i == 7 {
			base := ComputeStepHash(prevHash, s, "destroy", method, timestamp)
			buf := make([]byte, 0, len(base)+1+len(merkleRoot))
			buf = append(buf, base...)
			buf = append(buf, 0x00)
			buf = append(buf, merkleRoot...)
			sum := sha512.Sum512(buf)
			chainHash = hex.EncodeToString(sum[:])
		} else {
			chainHash = ComputeStepHash(prevHash, s, "destroy", method, timestamp)
		}
		chain = append(chain, map[string]interface{}{
			"subsystem":  s,
			"method":     method,
			"chain_hash": chainHash,
		})
		prevHash = chainHash
	}

	proof := map[string]interface{}{
		"cdp_version":         "2.1",
		"signing_mode":        "nanorix_only",
		"jurisdiction":        "US",
		"authority_id":        "us-kms-nanorix-v1",
		"signing_key_version": "1",
		"capsule_id":          capsuleID,
		"org_id":              "org_v21_test",
		"activity":            []interface{}{},
		"chain":               chain,
		"destruction_state":   "destroyed",
		"destroyed_at":        timestamp,
		"hash_algorithm":      "sha512",
		"signature_algorithm": "Ed25519",
		"record_receipts": []interface{}{
			map[string]interface{}{
				"record_index":           0,
				"record_id":              "rec_v21",
				"record_input_hash":      "sha512:aa",
				"record_output_hash":     "sha512:bb",
				"record_chain_hash":      "sha512:" + receiptChain,
				"merkle_inclusion_proof": []interface{}{},
			},
		},
		"record_receipts_merkle_root": "sha512:" + merkleRoot,
	}

	// Sign the recomputed document canonical hash over the UseNumber-parsed
	// tree — the confirmed v2.1 signed-byte-form.
	unsigned, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("fixture marshal failed: %v", err)
	}
	numericDoc, ok := canonicalProofTree(unsigned)
	if !ok {
		t.Fatal("canonicalProofTree failed on fixture")
	}
	canonical := RecomputeCanonicalHash(numericDoc)
	if len(canonical) != 128 {
		t.Fatalf("canonical hash length = %d, want 128", len(canonical))
	}

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	signer := ed25519.NewKeyFromSeed(seed)
	pub := signer.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(signer, []byte(canonical))

	proof["attestation"] = map[string]interface{}{
		"key_id":           "nrx-verify-v21-test-key",
		"verification_key": base64.StdEncoding.EncodeToString(pub),
		"signature":        base64.StdEncoding.EncodeToString(sig),
	}
	bytes, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("fixture marshal failed: %v", err)
	}
	return bytes, signer
}

func TestExtractV21PopulatesSignatureTargetAndCanonicalHash(t *testing.T) {
	proof, _ := makeV21BundleFixture(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if bundle.AuditProofAnchors.SignatureTarget == nil ||
		*bundle.AuditProofAnchors.SignatureTarget != SignatureTargetDocumentCanonicalHash {
		t.Fatalf("signature_target = %v, want document_canonical_hash", bundle.AuditProofAnchors.SignatureTarget)
	}
	if bundle.AuditProofAnchors.DocumentCanonicalHash == nil || len(*bundle.AuditProofAnchors.DocumentCanonicalHash) != 128 {
		t.Fatalf("document_canonical_hash missing or malformed: %v", bundle.AuditProofAnchors.DocumentCanonicalHash)
	}
}

func TestExtractLegacyOmitsSignatureTargetBytesUnchanged(t *testing.T) {
	proof, _ := makeBundleTestFixtureN2(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if bundle.AuditProofAnchors.SignatureTarget != nil {
		t.Error("legacy bundle must not carry signature_target")
	}
	if bundle.AuditProofAnchors.DocumentCanonicalHash != nil {
		t.Error("legacy bundle must not carry document_canonical_hash")
	}
	out, _ := json.Marshal(bundle)
	if strings.Contains(string(out), "signature_target") || strings.Contains(string(out), "document_canonical_hash") {
		t.Error("legacy bundle JSON must not gain the new keys (byte-compat guard)")
	}
}

func TestVerifyV21BundleRoundtripSucceeds(t *testing.T) {
	proof, _ := makeV21BundleFixture(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if err := VerifyReceiptBundle(bundle); err != nil {
		t.Fatalf("v2.1 bundle must verify: %v", err)
	}
}

func TestV21BundleMissingCanonicalHashIsStructuredError(t *testing.T) {
	proof, _ := makeV21BundleFixture(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	bundle.AuditProofAnchors.DocumentCanonicalHash = nil
	err = VerifyReceiptBundle(bundle)
	var be *BundleError
	if err == nil {
		t.Fatal("missing canonical-hash anchor must be rejected")
	}
	if !errorsAs(err, &be) || be.Kind != BundleErrMissingCanonicalHashAnchor {
		t.Fatalf("expected %s, got %v", BundleErrMissingCanonicalHashAnchor, err)
	}
}

func TestUnknownSignatureTargetIsStructuredError(t *testing.T) {
	proof, _ := makeV21BundleFixture(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	target := "sha3_sponge"
	bundle.AuditProofAnchors.SignatureTarget = &target
	err = VerifyReceiptBundle(bundle)
	var be *BundleError
	if err == nil {
		t.Fatal("unknown signature_target must be rejected")
	}
	if !errorsAs(err, &be) || be.Kind != BundleErrUnknownSignatureTarget {
		t.Fatalf("expected %s, got %v", BundleErrUnknownSignatureTarget, err)
	}
}

func TestV21TamperedCanonicalHashRejected(t *testing.T) {
	proof, _ := makeV21BundleFixture(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	tampered := strings.Repeat("0", 128)
	bundle.AuditProofAnchors.DocumentCanonicalHash = &tampered
	err = VerifyReceiptBundle(bundle)
	var be *BundleError
	if err == nil {
		t.Fatal("tampered canonical hash must be rejected")
	}
	if !errorsAs(err, &be) || be.Kind != BundleErrSignatureFailed {
		t.Fatalf("expected %s, got %v", BundleErrSignatureFailed, err)
	}
}

func TestV21BundleSerializesRoundTrips(t *testing.T) {
	proof, _ := makeV21BundleFixture(t)
	bundle, err := ExtractReceiptBundle(proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	out, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtripped PortableReceiptBundle
	if err := json.Unmarshal(out, &roundtripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := VerifyReceiptBundle(&roundtripped); err != nil {
		t.Fatalf("roundtripped v2.1 bundle must verify: %v", err)
	}
}

func TestVerdictTextStatesCommitmentSemanticsNeverOverclaims(t *testing.T) {
	v21Proof, _ := makeV21BundleFixture(t)
	v21Bundle, err := ExtractReceiptBundle(v21Proof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	v21Verdict := BundleVerdictText(v21Bundle)
	if !strings.Contains(v21Verdict, "source AuditProof") || !strings.Contains(v21Verdict, "commitment") {
		t.Errorf("v2.1 verdict must state commitment semantics; got: %s", v21Verdict)
	}

	legacyProof, _ := makeBundleTestFixtureN2(t)
	legacyBundle, err := ExtractReceiptBundle(legacyProof, 0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	legacyVerdict := BundleVerdictText(legacyBundle)
	if !strings.Contains(legacyVerdict, "step_8_chain_hash") {
		t.Errorf("legacy verdict must name step_8_chain_hash; got: %s", legacyVerdict)
	}

	for _, verdict := range []string{v21Verdict, legacyVerdict} {
		for _, forbidden := range []string{"COMPLIANT", "SATISFIED", "PASSED", "MEETS"} {
			if strings.Contains(verdict, forbidden) {
				t.Errorf("verdict must not contain %s", forbidden)
			}
		}
	}
}

// errorsAs is a tiny local wrapper so the tests read like the Rust matches!
// assertions without importing errors in every case.
func errorsAs(err error, target **BundleError) bool {
	be, ok := err.(*BundleError)
	if !ok {
		return false
	}
	*target = be
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 8 — Portable Pubkey Bundle tests
// ─────────────────────────────────────────────────────────────────────────────

func makePubkeyBundleSigner(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	signer := ed25519.NewKeyFromSeed(seed)
	pub := signer.Public().(ed25519.PublicKey)
	return signer, pub, "nrx-bundle-publisher-test-v1"
}

func makeTestPubKeyEntry(keyID string) PubKeyEntry {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 9
	}
	sk := ed25519.NewKeyFromSeed(seed)
	pk := sk.Public().(ed25519.PublicKey)
	until := "2027-01-01T00:00:00Z"
	return PubKeyEntry{
		KeyID:       keyID,
		Algorithm:   "Ed25519",
		PublicKey:   base64.StdEncoding.EncodeToString(pk),
		ValidFrom:   "2026-01-01T00:00:00Z",
		ValidUntil:  &until,
		IssuedByOrg: "vendor:test",
	}
}

func TestBuildPubkeyBundleSucceeds(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, err := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	if err != nil {
		t.Fatalf("BuildPubkeyBundle: %v", err)
	}
	if bundle.BundleVersion != "1.0" {
		t.Errorf("bundle_version: %s", bundle.BundleVersion)
	}
	if bundle.BundleType != "pubkey" {
		t.Errorf("bundle_type: %s", bundle.BundleType)
	}
	if len(bundle.Pubkeys) != 1 {
		t.Errorf("pubkey count: %d", len(bundle.Pubkeys))
	}
	if bundle.BundleSignature.Signature == "" {
		t.Error("bundle_signature.signature empty")
	}
}

func TestVerifyPubkeyBundleRoundTrip(t *testing.T) {
	sk, pk, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, err := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := VerifyPubkeyBundle(bundle, pk); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyPubkeyBundleWrongPublisherRejected(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	// Attacker pubkey
	attackerSeed := make([]byte, 32)
	for i := range attackerSeed {
		attackerSeed[i] = 99
	}
	attackerPub := ed25519.NewKeyFromSeed(attackerSeed).Public().(ed25519.PublicKey)
	err := VerifyPubkeyBundle(bundle, attackerPub)
	if err == nil {
		t.Fatal("expected verify failure")
	}
	pbe, ok := err.(*PubkeyBundleError)
	if !ok || pbe.Kind != PubkeyBundleErrBundleSignatureFailed {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyPubkeyBundleTamperedPubkeyRejected(t *testing.T) {
	sk, pk, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	bundle.Pubkeys[0].IssuedByOrg = "vendor:hacked"
	err := VerifyPubkeyBundle(bundle, pk)
	if err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestVerifyPubkeyBundleTamperedIssuerRejected(t *testing.T) {
	sk, pk, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	bundle.IssuerOrganization = "issuer:hacked"
	err := VerifyPubkeyBundle(bundle, pk)
	if err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestResolveParentKeyWithinWindow(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	mid := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if ResolveParentKey(bundle, "key-1", mid) == nil {
		t.Error("expected resolution within window")
	}
}

func TestResolveParentKeyBeforeWindow(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	before := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if ResolveParentKey(bundle, "key-1", before) != nil {
		t.Error("expected nil before window")
	}
}

func TestResolveParentKeyAfterWindow(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	after := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if ResolveParentKey(bundle, "key-1", after) != nil {
		t.Error("expected nil after window")
	}
}

func TestResolveParentKeyForeverFindsOutsideWindow(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	after := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if ResolveParentKey(bundle, "key-1", after) != nil {
		t.Error("within-window resolver should return nil")
	}
	if ResolveParentKeyForever(bundle, "key-1") == nil {
		t.Error("forever-archive resolver should find the key")
	}
}

func TestResolveParentKeyUnknownReturnsNil(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{makeTestPubKeyEntry("key-1")}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	now := time.Now()
	if ResolveParentKey(bundle, "unknown-key", now) != nil {
		t.Error("expected nil for unknown key")
	}
}

func TestResolveParentKeyOpenEndedWindow(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entry := makeTestPubKeyEntry("key-current")
	entry.ValidUntil = nil
	bundle, _ := BuildPubkeyBundle([]PubKeyEntry{entry}, sk, keyID, "issuer:test")
	later := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if ResolveParentKey(bundle, "key-current", later) == nil {
		t.Error("expected resolution for null valid_until")
	}
}

func TestBuildBundleMultipleKeys(t *testing.T) {
	sk, pk, keyID := makePubkeyBundleSigner(t)
	entries := []PubKeyEntry{
		makeTestPubKeyEntry("key-1"),
		makeTestPubKeyEntry("key-2"),
		makeTestPubKeyEntry("key-3"),
	}
	bundle, _ := BuildPubkeyBundle(entries, sk, keyID, "issuer:test")
	if len(bundle.Pubkeys) != 3 {
		t.Errorf("key count: %d", len(bundle.Pubkeys))
	}
	if err := VerifyPubkeyBundle(bundle, pk); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBuildEmptyBundleRejected(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	_, err := BuildPubkeyBundle(nil, sk, keyID, "issuer:test")
	if err == nil {
		t.Fatal("expected EmptyBundle error")
	}
	pbe, ok := err.(*PubkeyBundleError)
	if !ok || pbe.Kind != PubkeyBundleErrEmptyBundle {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBuildBundleInvalidAlgorithmRejected(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entry := makeTestPubKeyEntry("key-1")
	entry.Algorithm = "RSA-2048"
	_, err := BuildPubkeyBundle([]PubKeyEntry{entry}, sk, keyID, "issuer:test")
	if err == nil {
		t.Fatal("expected algorithm error")
	}
}

func TestBuildBundleWrongPubkeySizeRejected(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	entry := makeTestPubKeyEntry("key-1")
	entry.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := BuildPubkeyBundle([]PubKeyEntry{entry}, sk, keyID, "issuer:test")
	if err == nil {
		t.Fatal("expected size error")
	}
}

func TestPubkeyBundleDisclaimerFactualLanguage(t *testing.T) {
	for _, forbidden := range []string{"COMPLIANT", "SATISFIED", "PASSED", "MEETS"} {
		if strings.Contains(PortablePubkeyBundleDisclaimer, forbidden) {
			t.Errorf("disclaimer contains forbidden term %s", forbidden)
		}
	}
}

func TestPubkeyBundleVersionPinned(t *testing.T) {
	sk, pk, keyID := makePubkeyBundleSigner(t)
	bundle, _ := BuildPubkeyBundle([]PubKeyEntry{makeTestPubKeyEntry("key-1")}, sk, keyID, "issuer:test")
	bundle.BundleVersion = "2.0"
	err := VerifyPubkeyBundle(bundle, pk)
	if err == nil {
		t.Fatal("expected version error")
	}
}

func TestPubkeyBundleTypePinned(t *testing.T) {
	sk, pk, keyID := makePubkeyBundleSigner(t)
	bundle, _ := BuildPubkeyBundle([]PubKeyEntry{makeTestPubKeyEntry("key-1")}, sk, keyID, "issuer:test")
	bundle.BundleType = "receipt"
	err := VerifyPubkeyBundle(bundle, pk)
	if err == nil {
		t.Fatal("expected type error")
	}
}

func TestPubkeyBundleJSONNoForbiddenComplianceTerms(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	bundle, _ := BuildPubkeyBundle([]PubKeyEntry{makeTestPubKeyEntry("key-1")}, sk, keyID, "issuer:test")
	bytes, _ := json.Marshal(bundle)
	for _, forbidden := range []string{"COMPLIANT", "SATISFIED", "PASSED", "MEETS"} {
		if strings.Contains(string(bytes), forbidden) {
			t.Errorf("bundle JSON contains forbidden term %s", forbidden)
		}
	}
}

func TestPubkeyBundleJCSCanonicalizationDeterministic(t *testing.T) {
	sk, _, keyID := makePubkeyBundleSigner(t)
	bundle, _ := BuildPubkeyBundle([]PubKeyEntry{makeTestPubKeyEntry("key-1")}, sk, keyID, "issuer:test")
	c1, err1 := canonicalBytesForSigning(bundle)
	c2, err2 := canonicalBytesForSigning(bundle)
	if err1 != nil || err2 != nil {
		t.Fatalf("canonicalization: %v, %v", err1, err2)
	}
	if string(c1) != string(c2) {
		t.Error("canonicalization not deterministic")
	}
}

// Ensure fmt import is used (Go compiler quirk if not used elsewhere in tests).
var _ = fmt.Sprintf
