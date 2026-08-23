// the receipt pipeline (the per-record receipt specification + the receipt-batching specification) per-record receipt + parent-proof composition
// math — Go port mirroring the reference chain implementation byte-for-byte.
//
// Forever-Standard discipline (the Forever-Standard wire discipline): every primitive in this file is
// part of the cryptographic-attestation contract. Cross-impl byte-equivalence
// with the canonical Rust implementation is mandatory; any divergence is a
// P0 finding.
//
// Cross-impl reference vectors anchored against the Rust output of
// `governance/rzl/examples/gen_wave_n_vectors`:
//
//   GENESIS_SHA512_HEX = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
//   merkle_pair_hash("aaa", "bbb") =
//     04ed285cc0e9fe4331e8248f8c37601f4a0836fe1b712fd45096ddd9acdcac1f088ce35db15a93bbc9d13bd7683a2483ab0adbda35814d17f1d44942bf9bd264
//   compute_step_8_amended(GENESIS, "2026-05-12T00:00:00Z", None, None) =
//     3b6a0c8fa70b0e1ead6d2c4c44050c3a45bb732dcd24ff71ffa284a034d5bc41ad4408f4c20649b76ce9a2a8885e857b13ad134f38c92abafb4700b2129b3fbf
//
// Locked in cross-impl tests below (TestCrossImplReferenceVector*).

package auditproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// ─────────────────────────────────────────────────────────────────────────────
// the receipt pipeline types — mirror the reference chain implementation{RecordReceipt, ParentProofLink}`.
// ─────────────────────────────────────────────────────────────────────────────

// RecordReceipt mirrors the Rust struct field-for-field. JSON tags use
// snake_case to byte-match Rust serde output (`rename_all = "snake_case"` at
// the wave-N-types level).
//
// Forever-Standard discipline (the Forever-Standard wire discipline): field shape is permanent. New
// fields land as additive optional (`json:",omitempty"`) — existing fields
// NEVER renamed, NEVER removed, NEVER repurposed.
type RecordReceipt struct {
	RecordIndex          uint32   `json:"record_index"`
	RecordID             string   `json:"record_id"`
	RecordInputHash      string   `json:"record_input_hash"`
	RecordOutputHash     string   `json:"record_output_hash"`
	RecordChainHash      string   `json:"record_chain_hash"`
	RecordActivityTrail  []any    `json:"record_activity_trail,omitempty"`
	PatternTag           *string  `json:"pattern_tag,omitempty"`
	MerkleInclusionProof []string `json:"merkle_inclusion_proof"`
}

// ParentProofLink mirrors the Rust struct. Cross-org chain composition primitive
// (the receipt-batching specification).
type ParentProofLink struct {
	ParentChainHash       string  `json:"parent_chain_hash"`
	ParentKeyID           string  `json:"parent_key_id"`
	ParentSignature       string  `json:"parent_signature"`
	ParentRole            *string `json:"parent_role,omitempty"`
	ParentJurisdiction    *string `json:"parent_jurisdiction,omitempty"`
	ParentOrganizationTag *string `json:"parent_organization_tag,omitempty"`
}

// PARENT_PROOF_MAX_DEPTH per the receipt-batching specification § "Depth limit". V1: 32.
const PARENT_PROOF_MAX_DEPTH = 32

// ─────────────────────────────────────────────────────────────────────────────
// Pattern tag closed-enum (the per-record receipt specification + the specification).
//
// Wire form snake_case per Rust serde. The 15 variants are append-only;
// existing variants NEVER renamed or removed.
// ─────────────────────────────────────────────────────────────────────────────

// PatternTagWireForm enumerates the 15 known pattern_tag wire values. The
// verifier doesn't reject unknown values (forward-compatibility) but downstream
// tooling can intersect against this set.
var PatternTagWireForm = map[string]bool{
	"pa":              true,
	"extraction":      true,
	"annotation":      true,
	"agent_step":      true,
	"agent_turn":      true,
	"rcm_claim":       true,
	"rcm_eligibility": true,
	"rcm_remit":       true,
	"ncpdp_script":    true,
	"dicom_study":     true,
	"dicom_sr":        true,
	"screening_hit":   true,
	"fhir_record":     true,
	"ehr_document":    true,
	"custom":          true,
}

// ─────────────────────────────────────────────────────────────────────────────
// Merkle pair-hash + root construction
// ─────────────────────────────────────────────────────────────────────────────

// MerklePairHash computes `SHA-512(left ‖ \x00 ‖ right)` where both inputs are
// interpreted as their hex-string byte values (per the per-record receipt specification §"Sibling pair
// hashing rule"). Either input MAY carry a `sha512:` prefix; stripped before
// hashing.
//
// Output: lowercase 128-char hex (no prefix). Cross-impl byte-equivalent with
// the Rust `merkle_pair_hash` in the reference chain implementation.
func MerklePairHash(left, right string) string {
	l := StripHashPrefix(left)
	r := StripHashPrefix(right)
	buf := make([]byte, 0, len(l)+1+len(r))
	buf = append(buf, l...)
	buf = append(buf, 0x00)
	buf = append(buf, r...)
	sum := sha512.Sum512(buf)
	return hex.EncodeToString(sum[:])
}

// MerkleRootSHA512NullSeparated builds the canonical Merkle root over an
// ordered slice of SHA-512 leaf hashes per the per-record receipt specification §"Merkle tree construction".
//
//   - leaves.len() == 0 → returns ("", false)
//   - leaves.len() == 1 → returns (leaves[0] with prefix stripped, true)
//   - leaves.len() >= 2 → binary tree with odd-level duplication
//
// Output: bare hex (no `sha512:` prefix). Caller prepends `sha512:` for wire form.
func MerkleRootSHA512NullSeparated(leaves []string) (string, bool) {
	if len(leaves) == 0 {
		return "", false
	}
	if len(leaves) == 1 {
		return StripHashPrefix(leaves[0]), true
	}
	level := make([]string, len(leaves))
	for i, h := range leaves {
		level[i] = StripHashPrefix(h)
	}
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); {
			if i+1 < len(level) {
				next = append(next, MerklePairHash(level[i], level[i+1]))
				i += 2
			} else {
				// Odd-level last node: duplicate per the per-record receipt specification.
				next = append(next, MerklePairHash(level[i], level[i]))
				i++
			}
		}
		level = next
	}
	return level[0], true
}

// ComputeRecordReceiptsMerkleRoot — public the per-record receipt specification surface for receipt root.
//
//   - Empty slice → ("", false) — None equivalent.
//   - Otherwise → ("sha512:{hex}", true) per the per-record receipt specification wire form.
//
// Cross-impl byte-equivalent with Rust `compute_record_receipts_merkle_root`.
func ComputeRecordReceiptsMerkleRoot(receipts []RecordReceipt) (string, bool) {
	if len(receipts) == 0 {
		return "", false
	}
	leaves := make([]string, len(receipts))
	for i, r := range receipts {
		leaves[i] = r.RecordChainHash
	}
	root, ok := MerkleRootSHA512NullSeparated(leaves)
	if !ok {
		return "", false
	}
	return "sha512:" + root, true
}

// ComputeParentProofsMerkleRoot — public the receipt-batching specification surface for parent root.
func ComputeParentProofsMerkleRoot(parents []ParentProofLink) (string, bool) {
	if len(parents) == 0 {
		return "", false
	}
	leaves := make([]string, len(parents))
	for i, p := range parents {
		leaves[i] = p.ParentChainHash
	}
	root, ok := MerkleRootSHA512NullSeparated(leaves)
	if !ok {
		return "", false
	}
	return "sha512:" + root, true
}

// BuildMerkleInclusionProof returns the siblings on the path from leaf to root
// in bottom-up order (each as bare hex, no `sha512:` prefix). Empty when
// `len(leaves) == 1`. Returns `(nil, false)` when `leafIndex` out of range
// OR `leaves` empty. Cross-impl byte-equivalent with Rust
// `build_merkle_inclusion_proof`.
func BuildMerkleInclusionProof(leaves []string, leafIndex int) ([]string, bool) {
	if len(leaves) == 0 || leafIndex < 0 || leafIndex >= len(leaves) {
		return nil, false
	}
	if len(leaves) == 1 {
		return []string{}, true
	}
	idx := leafIndex
	level := make([]string, len(leaves))
	for i, h := range leaves {
		level[i] = StripHashPrefix(h)
	}
	proof := make([]string, 0)
	for len(level) > 1 {
		var siblingIdx int
		if idx%2 == 0 {
			if idx+1 < len(level) {
				siblingIdx = idx + 1
			} else {
				// Right-edge odd-level node duplicates itself.
				siblingIdx = idx
			}
		} else {
			siblingIdx = idx - 1
		}
		proof = append(proof, level[siblingIdx])

		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); {
			if i+1 < len(level) {
				next = append(next, MerklePairHash(level[i], level[i+1]))
				i += 2
			} else {
				next = append(next, MerklePairHash(level[i], level[i]))
				i++
			}
		}
		level = next
		idx /= 2
	}
	return proof, true
}

// VerifyMerkleInclusionProof recomputes the root from leaf + proof + leafIndex
// and compares against claimed. Tolerates `sha512:` prefix on leaf and root.
// Cross-impl byte-equivalent with Rust `verify_merkle_inclusion_proof`.
func VerifyMerkleInclusionProof(leaf string, leafIndex int, proof []string, claimedRoot string) bool {
	leafStripped := StripHashPrefix(leaf)
	claimedStripped := StripHashPrefix(claimedRoot)

	// N=1 fast path: leaf IS root.
	if len(proof) == 0 {
		return leafStripped == claimedStripped
	}

	current := leafStripped
	idx := leafIndex
	for _, sibling := range proof {
		if idx%2 == 0 {
			current = MerklePairHash(current, sibling)
		} else {
			current = MerklePairHash(sibling, current)
		}
		idx /= 2
	}
	return current == claimedStripped
}

// ─────────────────────────────────────────────────────────────────────────────
// Activity root (per-record SHA-512 chain over canonical JCS events)
// ─────────────────────────────────────────────────────────────────────────────

// ComputeActivityRoot — SHA-512 chain over canonical-JSON (RFC 8785 JCS) event
// hashes; genesis fallback when trail is nil/empty. Cross-impl byte-equivalent
// with Rust `compute_activity_root`. Output: lowercase 128-char hex, no prefix.
func ComputeActivityRoot(trail []any) string {
	if len(trail) == 0 {
		return NanorixGenesisHash
	}
	prev := NanorixGenesisHash
	for _, event := range trail {
		// Re-encode event to JSON then JCS-canonicalize. The Rust path uses
		// serde_jcs directly on the parsed serde_json::Value; here we round-
		// trip through `json.Marshal` then `JCSCanonicalize` to reach the same
		// canonical bytes.
		jsonBytes, err := json.Marshal(event)
		if err != nil {
			// Defensive fallback — should never fire for well-formed events.
			jsonBytes = []byte("null")
		}
		canonical, err := JCSCanonicalize(jsonBytes)
		if err != nil {
			canonical = jsonBytes
		}
		eventHash := sha512.Sum512(canonical)
		eventHashHex := hex.EncodeToString(eventHash[:])

		buf := make([]byte, 0, len(prev)+1+len(eventHashHex))
		buf = append(buf, prev...)
		buf = append(buf, 0x00)
		buf = append(buf, eventHashHex...)
		next := sha512.Sum512(buf)
		prev = hex.EncodeToString(next[:])
	}
	return prev
}

// ─────────────────────────────────────────────────────────────────────────────
// Record chain hash (the per-record receipt specification per-record chain hash formula)
// ─────────────────────────────────────────────────────────────────────────────

// ComputeRecordChainHash mirrors Rust `compute_record_chain_hash`:
//
//	SHA-512(capsule_id ‖ \x00 ‖ record_index ‖ \x00 ‖ record_id ‖ \x00
//	        ‖ record_input_hash ‖ \x00 ‖ record_output_hash ‖ \x00
//	        ‖ activity_root_or_genesis [‖ \x00 ‖ pattern_tag_wire])
//
// `record_index` is decimal-formatted. Hash inputs MAY carry `sha512:`; stripped.
//
// `patternTagWire` is the snake_case wire string exactly as serialized in the
// receipt JSON `pattern_tag` field. The trailing `\x00 ‖ pattern_tag_wire`
// segment is appended ONLY when the receipt declares a tag (nil = untagged;
// the per-record receipt specification — the tag is a signed primitive, so it must be bound here, not
// merely carried in the JSON). Domain separation is sound because
// `activity_root_or_genesis` is always exactly 128 stripped hex chars: a
// tagged preimage is strictly longer than every untagged preimage, so the
// conditional append cannot collide. Untagged receipts keep the pre-fix byte
// formula (clean-cut; zero external consumers at fix time).
//
// Returns chain hash WITH `sha512:` prefix — assignable directly to
// `RecordReceipt.RecordChainHash`.
func ComputeRecordChainHash(
	capsuleID string,
	recordIndex uint32,
	recordID string,
	recordInputHash string,
	recordOutputHash string,
	activityRootOrGenesis string,
	patternTagWire *string,
) string {
	inputH := StripHashPrefix(recordInputHash)
	outputH := StripHashPrefix(recordOutputHash)
	activityH := StripHashPrefix(activityRootOrGenesis)
	idx := strconv.FormatUint(uint64(recordIndex), 10)

	buf := make([]byte, 0,
		len(capsuleID)+1+len(idx)+1+len(recordID)+1+len(inputH)+1+len(outputH)+1+len(activityH),
	)
	buf = append(buf, capsuleID...)
	buf = append(buf, 0x00)
	buf = append(buf, idx...)
	buf = append(buf, 0x00)
	buf = append(buf, recordID...)
	buf = append(buf, 0x00)
	buf = append(buf, inputH...)
	buf = append(buf, 0x00)
	buf = append(buf, outputH...)
	buf = append(buf, 0x00)
	buf = append(buf, activityH...)
	if patternTagWire != nil {
		buf = append(buf, 0x00)
		buf = append(buf, *patternTagWire...)
	}

	sum := sha512.Sum512(buf)
	return "sha512:" + hex.EncodeToString(sum[:])
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 8 amendment (presence-conditional 4-arm formula)
// ─────────────────────────────────────────────────────────────────────────────

// ComputeStep8Base is the pre-the receipt pipeline legacy Step 8 hash:
//
//	SHA-512(prev_hash ‖ \x00 ‖ "capsule_destroy" ‖ \x00 ‖
//	        "destroy" ‖ \x00 ‖ "capsule_lifecycle_verification" ‖ \x00 ‖ timestamp)
//
// Mirrors Rust `compute_step_8_base` (which delegates to the existing
// `compute_step_hash` legacy formula). Output: bare lowercase hex (no prefix).
func ComputeStep8Base(prevHash, timestamp string) string {
	return ComputeStepHash(
		prevHash,
		"capsule_destroy",
		"destroy",
		"capsule_lifecycle_verification",
		timestamp,
	)
}

// ComputeStep8Amended implements the per-record receipt specification + the receipt-batching specification presence-conditional
// 4-arm Step 8 formula:
//
//	let base = SHA-512(prev_hash ‖ \x00 ‖ "capsule_destroy" ‖ \x00 ‖ "destroy" ‖ \x00 ‖ "capsule_lifecycle_verification" ‖ \x00 ‖ timestamp);
//	match (rrmr, ppmr) {
//	    (None, None)       => base,                                  // pre-the receipt pipeline: byte-identical
//	    (Some(rr), None)   => SHA-512(base ‖ \x00 ‖ rr),             // the per-record receipt specification only
//	    (None, Some(pp))   => SHA-512(base ‖ \x00 ‖ pp),             // the receipt-batching specification only
//	    (Some(rr), Some(pp)) => SHA-512(base ‖ \x00 ‖ rr ‖ \x00 ‖ pp), // both
//	}
//
// `rrmr` and `ppmr` are encoded as nil = None; non-nil = Some. Either input
// MAY carry `sha512:` prefix; stripped before hashing.
//
// Forever-Standard byte-equivalence (the Forever-Standard wire discipline): the (nil, nil) branch
// returns `ComputeStep8Base` unmodified — byte-identical to every pre-the receipt pipeline
// production AuditProof. Pinned by `TestStep8AmendedNoneNoneByteEquivalence`.
func ComputeStep8Amended(prevHash, timestamp string, rrmr, ppmr *string) string {
	base := ComputeStep8Base(prevHash, timestamp)

	switch {
	case rrmr == nil && ppmr == nil:
		return base
	case rrmr != nil && ppmr == nil:
		rr := StripHashPrefix(*rrmr)
		buf := make([]byte, 0, len(base)+1+len(rr))
		buf = append(buf, base...)
		buf = append(buf, 0x00)
		buf = append(buf, rr...)
		sum := sha512.Sum512(buf)
		return hex.EncodeToString(sum[:])
	case rrmr == nil && ppmr != nil:
		pp := StripHashPrefix(*ppmr)
		buf := make([]byte, 0, len(base)+1+len(pp))
		buf = append(buf, base...)
		buf = append(buf, 0x00)
		buf = append(buf, pp...)
		sum := sha512.Sum512(buf)
		return hex.EncodeToString(sum[:])
	default: // both Some
		rr := StripHashPrefix(*rrmr)
		pp := StripHashPrefix(*ppmr)
		buf := make([]byte, 0, len(base)+1+len(rr)+1+len(pp))
		buf = append(buf, base...)
		buf = append(buf, 0x00)
		buf = append(buf, rr...)
		buf = append(buf, 0x00)
		buf = append(buf, pp...)
		sum := sha512.Sum512(buf)
		return hex.EncodeToString(sum[:])
	}
}

// strPtrLocal is a helper used by tests / verifier paths to create a *string
// from a string literal in one line.
func strPtrLocal(s string) *string { return &s }

// ─────────────────────────────────────────────────────────────────────────────
// Cycle prevention + depth-cap-32
// ─────────────────────────────────────────────────────────────────────────────

// DetectParentProofCycle rejects cycles per the receipt-batching specification §"Cycle prevention".
// Returns the index of the cyclic parent if any `parent_chain_hash` equals
// `selfChainHash`; returns -1 if no cycle. Both inputs prefix-tolerant.
func DetectParentProofCycle(parents []ParentProofLink, selfChainHash string) int {
	selfStripped := StripHashPrefix(selfChainHash)
	for i, p := range parents {
		if StripHashPrefix(p.ParentChainHash) == selfStripped {
			return i
		}
	}
	return -1
}

// EnforceDepthCap returns an error if the parent chain depth exceeds the
// `PARENT_PROOF_MAX_DEPTH` of 32.
func EnforceDepthCap(parents []ParentProofLink) error {
	if len(parents) > PARENT_PROOF_MAX_DEPTH {
		return fmt.Errorf("parent chain depth %d exceeds PARENT_PROOF_MAX_DEPTH=%d (the receipt-batching specification)",
			len(parents), PARENT_PROOF_MAX_DEPTH)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Standalone receipt verification (Mode B — the per-record receipt specification)
// ─────────────────────────────────────────────────────────────────────────────

// VerifyRecordReceiptOptions bundles the outer-context inputs needed to verify
// a standalone receipt detached from its AuditProof container.
type VerifyRecordReceiptOptions struct {
	// CapsuleID — the outer AuditProof's capsule_id field.
	CapsuleID string

	// OuterMerkleRoot — the AuditProof's `record_receipts_merkle_root`. May
	// carry `sha512:` prefix; stripped during verification.
	OuterMerkleRoot string

	// OuterChainHash — the AuditProof's Step 8 amended chain_hash. The outer
	// Ed25519 signature is verified over this.
	OuterChainHash string

	// OuterSignatureB64 — `attestation.signature` of the outer AuditProof,
	// base64-encoded. May carry `base64:` prefix.
	OuterSignatureB64 string

	// OuterPublicKey — the trusted signing authority's Ed25519 public key.
	OuterPublicKey ed25519.PublicKey
}

// VerifyRecordReceipt — Mode B (standalone) verification per the per-record receipt specification:
//
//  1. Recompute the receipt's `record_chain_hash` from its fields (capsule_id
//     comes from the outer context).
//  2. Verify the Merkle inclusion proof binds the receipt to
//     `OuterMerkleRoot`.
//  3. Verify the outer Ed25519 signature over `OuterChainHash` (ASCII-hex
//     bytes) using `OuterPublicKey`.
//
// Returns nil on success, error on first failure.
//
// This is the customer-side primitive a recipient organization uses when given
// a single receipt + the bundle that anchors it back to the AuditProof's
// signed outer chain.
func VerifyRecordReceipt(receipt RecordReceipt, opts VerifyRecordReceiptOptions) error {
	// (1) Recompute record_chain_hash.
	activityRoot := ComputeActivityRoot(receipt.RecordActivityTrail)
	recomputed := ComputeRecordChainHash(
		opts.CapsuleID,
		receipt.RecordIndex,
		receipt.RecordID,
		receipt.RecordInputHash,
		receipt.RecordOutputHash,
		activityRoot,
		receipt.PatternTag,
	)
	if StripHashPrefix(recomputed) != StripHashPrefix(receipt.RecordChainHash) {
		return fmt.Errorf("record_chain_hash mismatch: recomputed=%s claimed=%s",
			recomputed, receipt.RecordChainHash)
	}

	// (2) Verify inclusion proof binds to outer Merkle root.
	if !VerifyMerkleInclusionProof(
		receipt.RecordChainHash,
		int(receipt.RecordIndex),
		receipt.MerkleInclusionProof,
		opts.OuterMerkleRoot,
	) {
		return fmt.Errorf("merkle inclusion proof does NOT bind receipt to outer root %s",
			opts.OuterMerkleRoot)
	}

	// (3) Outer Ed25519 signature over outer chain_hash.
	sigRaw := StripBase64Prefix(opts.OuterSignatureB64)
	sigBytes, err := base64.StdEncoding.DecodeString(sigRaw)
	if err != nil {
		return fmt.Errorf("outer signature base64 decode: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("outer signature wrong size: got %d, want %d",
			len(sigBytes), ed25519.SignatureSize)
	}
	if len(opts.OuterPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("outer public key wrong size: got %d, want %d",
			len(opts.OuterPublicKey), ed25519.PublicKeySize)
	}
	chainHashAscii := StripHashPrefix(opts.OuterChainHash)
	if !ed25519.Verify(opts.OuterPublicKey, []byte(chainHashAscii), sigBytes) {
		return fmt.Errorf("outer Ed25519 signature does NOT verify against outer chain_hash")
	}

	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// the receipt pipeline JSON inflation (Mode A — full AuditProof + receipts + parents)
// ─────────────────────────────────────────────────────────────────────────────

// VerifyFullAuditProofWaveN runs the verification pipeline with the receipt-batching specification
// parent-proof depth cap enforced, on top of everything `Verify` does:
// `record_receipts` + Merkle root, `parent_proof_hashes` + Merkle root, the
// `ComputeStep8Amended` chain walk, and the stage 5-7 signature check.
//
// the receipt pipeline handling is no longer exclusive to this entry point — it lives in the
// shared ladder, so `Verify` and this function cannot drift apart on chain
// semantics or on whether the signature gets checked. The only difference is
// the depth cap. Pre-the receipt pipeline proofs (no receipts / no parents) verify
// byte-identically via the (nil, nil) Step 8 branch, preserving
// Forever-Standard.
func VerifyFullAuditProofWaveN(jsonBytes []byte, policy VerifierPolicy) AuditProofVerificationResult {
	return verifyCore(jsonBytes, policy, true)
}

// verifyRecordReceiptsArray recomputes each receipt's chain hash, the Merkle
// root, and compares to the claimed root. Returns nil on success.
func verifyRecordReceiptsArray(receipts []interface{}, capsuleID string, claimedRootPtr *string) *FailureReason {
	if claimedRootPtr == nil {
		return nil
	}
	claimedRoot := *claimedRootPtr
	leafChainHashes := make([]string, 0, len(receipts))

	for i, raw := range receipts {
		receiptMap, ok := raw.(map[string]interface{})
		if !ok {
			return &FailureReason{
				Type:      ReasonStepHashMismatch,
				StepIdx:   i,
				Subsystem: fmt.Sprintf("record_receipt[%d]", i),
			}
		}
		recordIndex := uint32(0)
		if v, ok := receiptMap["record_index"].(float64); ok {
			recordIndex = uint32(v)
		}
		recordID := stringOrEmpty(receiptMap["record_id"])
		inH := stringOrEmpty(receiptMap["record_input_hash"])
		outH := stringOrEmpty(receiptMap["record_output_hash"])
		claimedChain := stringOrEmpty(receiptMap["record_chain_hash"])

		// Activity-root recompute.
		activityRoot := NanorixGenesisHash
		if trail, ok := receiptMap["record_activity_trail"].([]interface{}); ok && len(trail) > 0 {
			activityRoot = ComputeActivityRoot(trail)
		}

		// the per-record receipt specification: a declared pattern_tag is a signed primitive — bind its
		// wire form into the recompute (mirrors nanorix-verify lib.rs).
		var patternTag *string
		if tag, ok := receiptMap["pattern_tag"].(string); ok {
			patternTag = &tag
		}

		recomputed := ComputeRecordChainHash(
			capsuleID, recordIndex, recordID, inH, outH, activityRoot, patternTag,
		)
		if StripHashPrefix(recomputed) != StripHashPrefix(claimedChain) {
			return &FailureReason{
				Type:      ReasonStepHashMismatch,
				StepIdx:   i,
				Subsystem: fmt.Sprintf("record_receipt[%d]", i),
			}
		}
		leafChainHashes = append(leafChainHashes, StripHashPrefix(recomputed))
	}

	recomputedRoot, ok := MerkleRootSHA512NullSeparated(leafChainHashes)
	if !ok {
		recomputedRoot = ""
	}
	if recomputedRoot != StripHashPrefix(claimedRoot) {
		return &FailureReason{
			Type:     ReasonFinalHashMismatch,
			Claimed:  claimedRoot,
			Computed: "sha512:" + recomputedRoot,
		}
	}
	return nil
}

// verifyParentProofsArray recomputes the parent Merkle root over each
// `parent_chain_hash` and compares to the claimed root.
func verifyParentProofsArray(parents []interface{}, claimedRootPtr *string) *FailureReason {
	if claimedRootPtr == nil {
		return nil
	}
	claimedRoot := *claimedRootPtr
	leaves := make([]string, 0, len(parents))
	for _, raw := range parents {
		parentMap, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		leaves = append(leaves, stringOrEmpty(parentMap["parent_chain_hash"]))
	}
	recomputed, ok := MerkleRootSHA512NullSeparated(leaves)
	if !ok {
		recomputed = ""
	}
	if recomputed != StripHashPrefix(claimedRoot) {
		return &FailureReason{
			Type:     ReasonFinalHashMismatch,
			Claimed:  claimedRoot,
			Computed: "sha512:" + recomputed,
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Unused-import suppressors (go vet keeps these honest)
// ─────────────────────────────────────────────────────────────────────────────

// Force-references to satisfy `goimports` when the verifier code happens to
// not exercise every alias. Imports are USED by primary functions above —
// these dummies exist only so a future refactor that splits files keeps the
// linter happy.
//
// (Compile-time-only; no runtime cost.)
var (
	_ = bytes.Buffer{}
	_ = sort.SliceStable
	_ = utf16.Encode
)
