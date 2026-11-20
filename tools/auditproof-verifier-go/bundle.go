// Portable Receipt Bundle (.prb.json) surface, Go port.
//
// Mirrors `tools/nanorix-verify/src/bundle.rs` byte-for-byte. Cross-impl
// byte-equivalence with Rust/Python/TypeScript bundle JSON on the canonical
// reference vectors.
//
// This is
// a JSON convention + JSON Schema + SDK helper — NOT a new file format with
// MIME registration / OS-level associations.
//
// Bundle disclaimer
// cites; never asserts compliance.

package auditproof

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

// PortableReceiptBundleDisclaimer — factual language only. Vocabulary discipline
// per regulatory_context rules: forbidden words include COMPLIANT, SATISFIED,
// PASSED, MEETS.
const PortableReceiptBundleDisclaimer = "This Portable Receipt Bundle carries cryptographic evidence of one record's structural execution. Verifying party uses the audit_proof_anchors to verify the receipt's merkle inclusion + outer Ed25519 signature. Control framework references are NOT included in this bundle; consult the mapping artifact at https://nanorix.io/v1/control-map?framework_version={framework_version} to apply current control mappings at consumption time."

// signature_target values — which anchor the outer Ed25519 signature covers.
// An absent signature_target means SignatureTargetStep8ChainHash (legacy
// CDP v1.0/v2.0 bundles predate the field).
const (
	SignatureTargetStep8ChainHash        = "step8_chain_hash"
	SignatureTargetDocumentCanonicalHash = "document_canonical_hash"
)

// PortableReceiptBundle — wire shape.
//
// Forever-Standard: BundleVersion is append-only; the V1.0 shape
// remains valid forever. Future bundle types land as new wire-format versions,
// NEVER as breaking-shape changes to V1.0.
type PortableReceiptBundle struct {
	BundleVersion     string                 `json:"bundle_version"`
	BundleType        string                 `json:"bundle_type"`
	GeneratedAt       string                 `json:"generated_at"`
	Receipt           map[string]interface{} `json:"receipt"`
	AuditProofAnchors AuditProofAnchors      `json:"audit_proof_anchors"`
	Disclaimer        string                 `json:"disclaimer"`
}

// AuditProofAnchors — minimal outer-AuditProof fields carried in the bundle.
type AuditProofAnchors struct {
	CapsuleID                string  `json:"capsule_id"`
	KeyID                    string  `json:"key_id"`
	VerificationKey          string  `json:"verification_key"`
	Step8ChainHash           string  `json:"step_8_chain_hash"`
	Signature                string  `json:"signature"`
	RecordReceiptsMerkleRoot string  `json:"record_receipts_merkle_root"`
	Timestamp                string  `json:"timestamp"`
	FrameworkVersionAtEmit   *string `json:"framework_version_at_emit,omitempty"`
	// SignatureTarget names the anchor the outer Ed25519 signature covers.
	// nil = legacy SignatureTargetStep8ChainHash. Additive —
	// legacy bundle JSON is byte-unchanged.
	SignatureTarget *string `json:"signature_target,omitempty"`
	// DocumentCanonicalHash is the FullCdp document canonical hash (bare
	// lowercase 128-char hex) — the signed message when SignatureTarget is
	// SignatureTargetDocumentCanonicalHash. nil on legacy bundles.
	DocumentCanonicalHash *string `json:"document_canonical_hash,omitempty"`
	// ParentProofsMerkleRoot is the parent-proofs Merkle root
	// ("sha512:"-prefixed). Present only when the source proof has parent
	// links; the Step 8 amendment commits to it. Omitted when absent, so
	// bundle JSON from proofs without parent links is byte-unchanged.
	ParentProofsMerkleRoot *string `json:"parent_proofs_merkle_root,omitempty"`
}

// BundleVerification is the detailed outcome of VerifyReceiptBundleDetailed.
//
// SignatureAuthentic: the outer Ed25519 signature verifies over the anchor
// named by SignatureTarget. ReceiptBound: the bundle alone ties the receipt to
// the signed value. True for the legacy target; false for
// SignatureTargetDocumentCanonicalHash, whose signed value commits to a
// document the bundle does not carry.
type BundleVerification struct {
	SignatureAuthentic bool
	ReceiptBound       bool
	SignatureTarget    string
}

// Valid reports whether the signature is authentic and the receipt is bound.
//
// Integrity only: the signature is checked against the key the bundle carries,
// so true never says who signed. Status says so.
func (v BundleVerification) Valid() bool { return v.SignatureAuthentic && v.ReceiptBound }

// Status is "not_anchored" when Valid, otherwise "not_verified". Never
// "verified": no key list is read, so the signing key is only the one the
// bundle carries.
func (v BundleVerification) Status() string {
	if v.Valid() {
		return "not_anchored"
	}
	return "not_verified"
}

// BundleError — typed bundle extraction / verification error.
type BundleError struct {
	Kind   string
	Reason string
}

func (e *BundleError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("bundle error: %s", e.Kind)
	}
	return fmt.Sprintf("bundle error [%s]: %s", e.Kind, e.Reason)
}

// Bundle error kinds — match Rust BundleError variants for cross-impl
// log diffability.
const (
	BundleErrNoReceipts              = "no_receipts"
	BundleErrIndexOutOfBounds        = "index_out_of_bounds"
	BundleErrMissingField            = "missing_field"
	BundleErrRecordChainHashMismatch = "record_chain_hash_mismatch"
	BundleErrMerkleInclusionFailed   = "merkle_inclusion_failed"
	BundleErrSignatureFailed         = "signature_failed"
	BundleErrBase64Decode            = "base64_decode"
	BundleErrShape                   = "shape"
	// BundleErrMissingCanonicalHashAnchor — the bundle declares
	// signature_target=document_canonical_hash (CDP v2.1 signing model) but
	// carries no document_canonical_hash value.
	BundleErrMissingCanonicalHashAnchor = "missing_canonical_hash_anchor"
	// BundleErrMalformedCanonicalHashAnchor — document_canonical_hash is not
	// exactly 128 lowercase hex characters after its sha512: prefix.
	BundleErrMalformedCanonicalHashAnchor = "malformed_canonical_hash_anchor"
	// BundleErrUnknownSignatureTarget — signature_target names a target this
	// verifier does not understand.
	BundleErrUnknownSignatureTarget = "unknown_signature_target"
	// BundleErrStep8Mismatch — the Step 8 hash recomputed from the bundle's
	// timestamp and Merkle roots differs from step_8_chain_hash: the bundled
	// root is not the one the signed Step 8 value commits to.
	BundleErrStep8Mismatch = "step_8_mismatch"
	// BundleErrReceiptNotBound — returned by VerifyReceiptBundle when the
	// signature is authentic but the bundle alone cannot bind the receipt to
	// the signed value (signature_target=document_canonical_hash).
	BundleErrReceiptNotBound = "receipt_not_bound"
)

// ExtractReceiptBundle extracts a single receipt + outer anchors into a
// Portable Receipt Bundle.
//
// `auditProof` is the full FullCdp/VerificationCdp JSON; `recordIndex`
// selects the receipt within `record_receipts`. Returns
// `BundleErrNoReceipts` if the AuditProof is pre-the receipt pipeline (no `record_receipts`
// field).
func ExtractReceiptBundle(auditProof []byte, recordIndex uint32) (*PortableReceiptBundle, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(auditProof, &doc); err != nil {
		return nil, &BundleError{Kind: BundleErrShape, Reason: fmt.Sprintf("invalid JSON: %v", err)}
	}

	receiptsRaw, ok := doc["record_receipts"].([]interface{})
	if !ok {
		return nil, &BundleError{Kind: BundleErrNoReceipts}
	}
	if int(recordIndex) >= len(receiptsRaw) {
		return nil, &BundleError{
			Kind:   BundleErrIndexOutOfBounds,
			Reason: fmt.Sprintf("index %d out of bounds; %d receipts", recordIndex, len(receiptsRaw)),
		}
	}
	receipt, ok := receiptsRaw[recordIndex].(map[string]interface{})
	if !ok {
		return nil, &BundleError{Kind: BundleErrShape, Reason: "receipt is not an object"}
	}

	capsuleID, ok := doc["capsule_id"].(string)
	if !ok {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "capsule_id"}
	}
	timestamp, ok := doc["destroyed_at"].(string)
	if !ok {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "destroyed_at"}
	}

	attestation, _ := doc["attestation"].(map[string]interface{})
	keyID, _ := attestation["key_id"].(string)
	if keyID == "" {
		keyID, _ = doc["key_id"].(string)
	}
	if keyID == "" {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "attestation.key_id"}
	}

	verificationKey, _ := attestation["verification_key"].(string)
	if verificationKey == "" {
		verificationKey, _ = attestation["public_key"].(string)
	}
	if verificationKey == "" {
		verificationKey, _ = doc["verification_key"].(string)
	}
	if verificationKey == "" {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "attestation.verification_key"}
	}

	signature, _ := attestation["signature"].(string)
	if signature == "" {
		signature, _ = doc["signature"].(string)
	}
	if signature == "" {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "attestation.signature"}
	}

	merkleRoot, ok := doc["record_receipts_merkle_root"].(string)
	if !ok {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "record_receipts_merkle_root"}
	}

	chainRaw, ok := doc["chain"].([]interface{})
	if !ok || len(chainRaw) == 0 {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "chain"}
	}
	lastStep, ok := chainRaw[len(chainRaw)-1].(map[string]interface{})
	if !ok {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "chain[last]"}
	}
	step8ChainHash, ok := lastStep["chain_hash"].(string)
	if !ok {
		return nil, &BundleError{Kind: BundleErrMissingField, Reason: "chain[last].chain_hash"}
	}

	var parentRoot *string
	if v, ok := doc["parent_proofs_merkle_root"].(string); ok {
		parentRoot = &v
	}

	var fvae *string
	if rc, ok := doc["regulatory_context"].(map[string]interface{}); ok {
		if fv, ok := rc["framework_version"].(string); ok {
			fvae = &fv
		}
	}

	// CDP v2.1 (and v2.2, which shares its signed-message form) signs the
	// FullCdp document canonical hash, NOT the Step 8 chain hash. Populate the
	// signature-target anchor from the source proof version so
	// VerifyReceiptBundle verifies the correct message. Recompute
	// (same convention as the canonical_recompute signed-message path) rather
	// than trusting an embedded field; fall back to the proof's canonical_hash
	// field only on the fail-closed empty recompute.
	var signatureTarget, documentCanonicalHash *string
	if cdpVersion, _ := doc["cdp_version"].(string); cdpVersion == "2.1" || cdpVersion == "2.2" {
		// Recompute over the UseNumber-parsed tree (RecomputeCanonicalHash's
		// documented contract) so numeric literals keep their source form.
		numericDoc := doc
		if numeric, ok := canonicalProofTree(auditProof); ok {
			numericDoc = numeric
		}
		canonical := RecomputeCanonicalHash(numericDoc)
		if canonical == "" {
			embedded, _ := doc["canonical_hash"].(string)
			canonical = StripHashPrefix(embedded)
		}
		if canonical == "" {
			return nil, &BundleError{
				Kind:   BundleErrMissingCanonicalHashAnchor,
				Reason: "v2.1 AuditProof yields no document canonical hash",
			}
		}
		target := SignatureTargetDocumentCanonicalHash
		signatureTarget = &target
		documentCanonicalHash = &canonical
	}

	return &PortableReceiptBundle{
		BundleVersion: "1.0",
		BundleType:    "receipt",
		GeneratedAt:   time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Receipt:       receipt,
		AuditProofAnchors: AuditProofAnchors{
			CapsuleID:                capsuleID,
			KeyID:                    keyID,
			VerificationKey:          verificationKey,
			Step8ChainHash:           step8ChainHash,
			Signature:                signature,
			RecordReceiptsMerkleRoot: merkleRoot,
			Timestamp:                timestamp,
			FrameworkVersionAtEmit:   fvae,
			SignatureTarget:          signatureTarget,
			DocumentCanonicalHash:    documentCanonicalHash,
			ParentProofsMerkleRoot:   parentRoot,
		},
		Disclaimer: PortableReceiptBundleDisclaimer,
	}, nil
}

// recomputeStep8 rebuilds the amended Step 8 hash from genesis: Steps 1-7 over
// the canonical (subsystem, method) table at timestamp, then the Step 8
// amendment with the receipts root and the optional parent-proofs root.
func recomputeStep8(timestamp string, recordReceiptsMerkleRoot string, parentProofsMerkleRoot *string) string {
	prev := NanorixGenesisHash
	for _, step := range CanonicalChain[:NanorixChainSteps-1] {
		prev = ComputeStepHash(prev, step.Subsystem, "destroy", step.Method, timestamp)
	}
	return ComputeStep8Amended(prev, timestamp, &recordReceiptsMerkleRoot, parentProofsMerkleRoot)
}

// parseRecordIndex accepts only a real non-negative integer that fits uint32.
func parseRecordIndex(raw interface{}) (uint32, error) {
	bad := func(reason string) (uint32, error) {
		return 0, &BundleError{Kind: BundleErrShape, Reason: "receipt.record_index " + reason}
	}
	switch v := raw.(type) {
	case float64:
		if v != math.Trunc(v) || v < 0 || v > math.MaxUint32 {
			return bad("is not an integer in range")
		}
		return uint32(v), nil
	case int:
		if v < 0 || int64(v) > math.MaxUint32 {
			return bad("is not an integer in range")
		}
		return uint32(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil || n < 0 || n > math.MaxUint32 {
			return bad("is not an integer in range")
		}
		return uint32(n), nil
	default:
		return bad("wrong type")
	}
}

// VerifyReceiptBundleDetailed verifies a Portable Receipt Bundle (Mode B
// standalone) and reports both whether the signature is authentic and whether
// the receipt is bound.
//
// Steps:
//  1. Recompute the receipt's record_chain_hash from its fields.
//  2. Verify Merkle inclusion proof binds receipt to record_receipts_merkle_root.
//  3. Recompute Steps 1-7 from genesis at the bundle timestamp, then the
//     amended Step 8 with record_receipts_merkle_root (and
//     parent_proofs_merkle_root when present); require equality with
//     step_8_chain_hash.
//  4. Verify the outer Ed25519 signature over the ASCII-hex bytes of the
//     anchor named by signature_target, using verification_key.
//
// For the legacy target ReceiptBound is true (the signed Step 8 hash was
// recomputed from the bundled root). For document_canonical_hash it is false:
// the signed value commits to a document the bundle does not carry.
//
// Returns a BundleError on failure.
func VerifyReceiptBundleDetailed(bundle *PortableReceiptBundle) (*BundleVerification, error) {
	if bundle.BundleVersion != "1.0" {
		return nil, &BundleError{Kind: BundleErrShape, Reason: "unsupported bundle_version: " + bundle.BundleVersion}
	}
	if bundle.BundleType != "receipt" {
		return nil, &BundleError{Kind: BundleErrShape, Reason: "wrong bundle_type for receipt bundle: " + bundle.BundleType}
	}

	anchors := bundle.AuditProofAnchors

	// (1) Recompute record_chain_hash.
	recordIndexRaw, ok := bundle.Receipt["record_index"]
	if !ok {
		return nil, &BundleError{Kind: BundleErrShape, Reason: "receipt.record_index missing"}
	}
	recordIndex, err := parseRecordIndex(recordIndexRaw)
	if err != nil {
		return nil, err
	}

	recordID, _ := bundle.Receipt["record_id"].(string)
	if recordID == "" {
		return nil, &BundleError{Kind: BundleErrShape, Reason: "receipt.record_id missing"}
	}
	inH, _ := bundle.Receipt["record_input_hash"].(string)
	outH, _ := bundle.Receipt["record_output_hash"].(string)
	claimedChainHash, _ := bundle.Receipt["record_chain_hash"].(string)
	if claimedChainHash == "" {
		return nil, &BundleError{Kind: BundleErrShape, Reason: "receipt.record_chain_hash missing"}
	}

	activityRoot := NanorixGenesisHash
	if trail, ok := bundle.Receipt["record_activity_trail"].([]interface{}); ok && len(trail) > 0 {
		activityRoot = computeActivityRootLocal(trail)
	}

	// A declared pattern_tag is a signed primitive — bind its wire
	// form into the recompute.
	var patternTag *string
	if tag, ok := bundle.Receipt["pattern_tag"].(string); ok {
		patternTag = &tag
	}

	recomputed := computeRecordChainHashLocal(anchors.CapsuleID, recordIndex, recordID, inH, outH, activityRoot, patternTag)
	if recomputed != StripHashPrefix(claimedChainHash) {
		return nil, &BundleError{
			Kind:   BundleErrRecordChainHashMismatch,
			Reason: fmt.Sprintf("claimed=%s recomputed=%s", claimedChainHash, recomputed),
		}
	}

	// (2) Merkle inclusion proof.
	inclusionRaw, _ := bundle.Receipt["merkle_inclusion_proof"].([]interface{})
	inclusion := make([]string, 0, len(inclusionRaw))
	for _, s := range inclusionRaw {
		if str, ok := s.(string); ok {
			inclusion = append(inclusion, str)
		}
	}
	if !verifyMerkleInclusionProofLocal(claimedChainHash, int(recordIndex), inclusion, anchors.RecordReceiptsMerkleRoot) {
		return nil, &BundleError{Kind: BundleErrMerkleInclusionFailed, Reason: anchors.RecordReceiptsMerkleRoot}
	}

	// (3) Step 8 recompute. The bundle does not carry the 8-step chain, but
	// every step hashes the same timestamp over the canonical (subsystem,
	// method) table, so Steps 1-7 are derivable. Requiring the amended Step 8
	// to equal step_8_chain_hash ties the bundled Merkle root (and the
	// parent-proofs root, when present) to the Step 8 value. Runs for every
	// signature_target.
	step8 := recomputeStep8(anchors.Timestamp, anchors.RecordReceiptsMerkleRoot, anchors.ParentProofsMerkleRoot)
	if step8 != StripHashPrefix(anchors.Step8ChainHash) {
		return nil, &BundleError{
			Kind:   BundleErrStep8Mismatch,
			Reason: fmt.Sprintf("claimed=%s recomputed=%s", anchors.Step8ChainHash, step8),
		}
	}

	// (4) Outer Ed25519 signature over the ASCII-hex bytes of the anchor named
	// by signature_target.
	var signedMessage, effectiveTarget string
	var receiptBound bool
	switch {
	case anchors.SignatureTarget == nil, *anchors.SignatureTarget == SignatureTargetStep8ChainHash:
		signedMessage = StripHashPrefix(anchors.Step8ChainHash)
		receiptBound = true
		effectiveTarget = SignatureTargetStep8ChainHash
	case *anchors.SignatureTarget == SignatureTargetDocumentCanonicalHash:
		if anchors.DocumentCanonicalHash == nil || *anchors.DocumentCanonicalHash == "" {
			return nil, &BundleError{
				Kind:   BundleErrMissingCanonicalHashAnchor,
				Reason: "signature_target=document_canonical_hash but no document_canonical_hash value; re-extract the bundle from the source AuditProof with a v2.1-aware extractor",
			}
		}
		signedMessage = StripHashPrefix(*anchors.DocumentCanonicalHash)
		// The same key signs other message shapes, such as a population head,
		// so a signature over anything but a bare hash proves nothing here.
		if !isSHA512LowercaseHex(signedMessage) {
			return nil, &BundleError{
				Kind:   BundleErrMalformedCanonicalHashAnchor,
				Reason: "document_canonical_hash is not 128 lowercase hex characters after its sha512: prefix",
			}
		}
		// The canonical hash commits to the whole source document, which the
		// bundle does not carry, so the bundle alone cannot bind the receipt.
		receiptBound = false
		effectiveTarget = SignatureTargetDocumentCanonicalHash
	default:
		return nil, &BundleError{
			Kind:   BundleErrUnknownSignatureTarget,
			Reason: *anchors.SignatureTarget,
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(StripBase64Prefix(anchors.Signature))
	if err != nil {
		return nil, &BundleError{Kind: BundleErrBase64Decode, Reason: "audit_proof_anchors.signature: " + err.Error()}
	}
	if len(sigBytes) != 64 {
		return nil, &BundleError{Kind: BundleErrSignatureFailed, Reason: fmt.Sprintf("signature wrong size: %d", len(sigBytes))}
	}
	pubBytes, err := base64.StdEncoding.DecodeString(StripBase64Prefix(anchors.VerificationKey))
	if err != nil {
		return nil, &BundleError{Kind: BundleErrBase64Decode, Reason: "audit_proof_anchors.verification_key: " + err.Error()}
	}
	if len(pubBytes) != 32 {
		return nil, &BundleError{Kind: BundleErrSignatureFailed, Reason: fmt.Sprintf("verification_key wrong size: %d", len(pubBytes))}
	}

	if !verifyEd25519Strict(pubBytes, []byte(signedMessage), sigBytes) {
		return nil, &BundleError{Kind: BundleErrSignatureFailed}
	}

	return &BundleVerification{
		SignatureAuthentic: true,
		ReceiptBound:       receiptBound,
		SignatureTarget:    effectiveTarget,
	}, nil
}

// VerifyReceiptBundle verifies a Portable Receipt Bundle (Mode B standalone)
// and returns nil only when the receipt is bound.
//
// It runs VerifyReceiptBundleDetailed. A bundle whose signature is authentic
// but whose receipt the bundle alone cannot bind (the document_canonical_hash
// target) returns a BundleError of kind BundleErrReceiptNotBound, so a caller
// that treats a nil error as "verified" is never told so for an unbound
// receipt. Use VerifyReceiptBundleDetailed to read the distinction.
//
// A nil error is integrity only: the signature is checked against the key the
// bundle carries, so it never says who signed (the detailed result for the
// same bundle has Status "not_anchored").
func VerifyReceiptBundle(bundle *PortableReceiptBundle) error {
	result, err := VerifyReceiptBundleDetailed(bundle)
	if err != nil {
		return err
	}
	if !result.ReceiptBound {
		return &BundleError{
			Kind: BundleErrReceiptNotBound,
			Reason: "signature is authentic over the document canonical hash, but the bundle alone " +
				"cannot bind the receipt to that signed document; verify the source AuditProof",
		}
	}
	return nil
}

// BundleVerdictText returns the human-readable verdict for a bundle that
// VerifyReceiptBundleDetailed accepted. Never overclaims: the v2.1 wording
// states the commitment semantics — the signature covers the document
// canonical hash, and binding the bundled Merkle root to that signed document
// requires the source AuditProof, which the bundle does not carry. Mirrors the
// Rust bundle_verdict_text strings verbatim for cross-impl parity.
func BundleVerdictText(bundle *PortableReceiptBundle) string {
	if t := bundle.AuditProofAnchors.SignatureTarget; t != nil && *t == SignatureTargetDocumentCanonicalHash {
		return "Ed25519 signature verified over the document canonical hash (CDP v2.1 signing model). " +
			"The receipt chain hash was recomputed and its Merkle inclusion checked against the " +
			"bundled record_receipts_merkle_root. NOTE: the canonical hash is a commitment over " +
			"the entire source AuditProof document, which this bundle does not carry — so this " +
			"verification establishes (a) the signature is authentic over the carried canonical " +
			"hash and (b) the receipt is consistent with the bundled Merkle root. Binding that " +
			"Merkle root to the SIGNED document requires verifying the source AuditProof; this " +
			"bundle alone therefore reports the receipt as not bound."
	}
	return "Ed25519 signature verified over step_8_chain_hash. The receipt chain hash was " +
		"recomputed and its Merkle inclusion checked against the bundled " +
		"record_receipts_merkle_root, and Step 8 was recomputed from the canonical chain at the " +
		"bundle timestamp with that root and found equal to the signed step_8_chain_hash. " +
		"The signature is checked against the key carried in the bundle; signer identity needs the published trust chain."
}

// ─────────────────────────────────────────────────────────────────────────────
// Local hash primitives (mirror tools/nanorix-verify/src/bundle.rs).
// ─────────────────────────────────────────────────────────────────────────────

// computeRecordChainHashLocal mirrors `ComputeRecordChainHash` (wave_n.go) but
// returns bare hex (no `sha512:` prefix). `patternTagWire` follows the same
// conditional-append rule: the trailing `\x00 ‖ pattern_tag_wire` segment is
// appended ONLY when non-nil (signed-primitive binding).
func computeRecordChainHashLocal(capsuleID string, recordIndex uint32, recordID, inH, outH, activityRoot string, patternTagWire *string) string {
	inHs := StripHashPrefix(inH)
	outHs := StripHashPrefix(outH)
	actHs := StripHashPrefix(activityRoot)
	idx := strconv.FormatUint(uint64(recordIndex), 10)

	buf := make([]byte, 0, len(capsuleID)+1+len(idx)+1+len(recordID)+1+len(inHs)+1+len(outHs)+1+len(actHs))
	buf = append(buf, capsuleID...)
	buf = append(buf, 0x00)
	buf = append(buf, idx...)
	buf = append(buf, 0x00)
	buf = append(buf, recordID...)
	buf = append(buf, 0x00)
	buf = append(buf, inHs...)
	buf = append(buf, 0x00)
	buf = append(buf, outHs...)
	buf = append(buf, 0x00)
	buf = append(buf, actHs...)
	if patternTagWire != nil {
		buf = append(buf, 0x00)
		buf = append(buf, *patternTagWire...)
	}

	sum := sha512.Sum512(buf)
	return hex.EncodeToString(sum[:])
}

func computeActivityRootLocal(trail []interface{}) string {
	prev := NanorixGenesisHash
	for _, event := range trail {
		jsonBytes, err := json.Marshal(event)
		if err != nil {
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

func merklePairHashLocal(left, right string) string {
	l := StripHashPrefix(left)
	r := StripHashPrefix(right)
	buf := make([]byte, 0, len(l)+1+len(r))
	buf = append(buf, l...)
	buf = append(buf, 0x00)
	buf = append(buf, r...)
	sum := sha512.Sum512(buf)
	return hex.EncodeToString(sum[:])
}

func verifyMerkleInclusionProofLocal(leaf string, leafIndex int, proof []string, claimedRoot string) bool {
	leafStripped := StripHashPrefix(leaf)
	claimedStripped := StripHashPrefix(claimedRoot)

	if len(proof) == 0 {
		return leafStripped == claimedStripped
	}

	current := leafStripped
	idx := leafIndex
	for _, sibling := range proof {
		if idx%2 == 0 {
			current = merklePairHashLocal(current, sibling)
		} else {
			current = merklePairHashLocal(sibling, current)
		}
		idx /= 2
	}
	return current == claimedStripped
}

// Static error sentinel — unused but reserved for callers that prefer
// errors.Is over kind-string comparison.
var ErrBundleNoReceipts = errors.New("bundle: AuditProof has no record_receipts")

func isSHA512LowercaseHex(s string) bool {
	if len(s) != 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
