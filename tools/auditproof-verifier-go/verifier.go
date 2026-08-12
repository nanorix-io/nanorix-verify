// AuditProof 8-stage verification pipeline. Mirrors the Rust verifier in
// the Rust verifiersrc/lib.rs::verify_auditproof`.
//
// **Forever-Standard discipline (the Forever-Standard wire discipline):** the stage numbering, the
// failure-reason emission shapes, the policy-pin gate ordering, and the
// genesis-hash anchor are PERMANENT. Any change to this file that would
// produce non-byte-equivalent output to the Rust verifier on the 100-fixture
// corpus is a P0 finding.
//
// **Stage ladder implemented here:**
//
//	1  schema — cdp_version present
//	2  version recognized; the authority-pin and region-pin policy gates
//	3  chain reproducibility (incl. the per-record receipt specification/041 Step-8 amendment, the
//	   receipt set, and the parent-proof set)
//	4  final_hash binding
//	5  canonical-hash recompute (folded into the signature stage: the
//	   recomputed canonical view IS the v2.1 signed message)
//	6  signing-key resolution — embedded-key path only in this build
//	7  Ed25519 signature verification → integrity
//
// Stage 8 (trust-chain anchoring — resolving the signing key from a verified
// manifest instead of trusting the key embedded in the proof) is implemented in
// the Rust verifier via `VerifierPolicy::trust_chain` and is NOT carried here:
// this build's policy struct has no manifest field. A proof that reaches stage
// 7 here has proven integrity, not authenticity. `VerifySignatureAgainst` is
// the hook a future stage-8 wiring would use.
//
// The cross-impl corpus sweep in `corpus_sweep_test.go` is the binding
// backstop: every fixture must match the Rust-authored committed verdict.

package auditproof

import (
	"encoding/json"
	"fmt"
)

// VerifierPolicy is the customer-side policy configuration. Field-additive
// per the Forever-Standard wire discipline + the customer-authority specification G7 — pre-amendment callers passing a zero-value
// policy continue to behave identically.
type VerifierPolicy struct {
	// RejectDiagnostic: refuse AuditProofs with `diagnostic_mode: true` (the specification).
	RejectDiagnostic bool

	// RequiredRegion: if non-empty, require the AuditProof's `region` to match.
	RequiredRegion string

	// RequiredAuthorityID: if non-empty, require the AuditProof's
	// `signing_authority.authority_id` to match. Per the customer-authority specification G7 + VP Security
	// extended-review F4.3.
	RequiredAuthorityID string
}

// supportedCdpVersions enumerates the closed-set of recognized AuditProof
// schema versions. Additive only per the Forever-Standard wire discipline.
var supportedCdpVersions = map[string]bool{
	"1.0": true,
	"2.0": true,
	"2.1": true,
}

// Verify runs the AuditProof verification pipeline against `jsonBytes` under
// `policy`. Returns the structured verification result.
//
// This is the public entry point for consumers. The result matches
// the Rust verifiersrc/lib.rs::verify_auditproof` on the fixture corpus.
func Verify(jsonBytes []byte, policy VerifierPolicy) AuditProofVerificationResult {
	return verifyCore(jsonBytes, policy, false)
}

// verifyCore is the single verification ladder. `enforceParentDepthCap` adds
// the receipt-batching specification depth-limit check used by the receipt pipeline entry point.
//
// One ladder, not two: a second copy of this logic is how the signature stage
// came to be missing from one path while present in the other.
func verifyCore(jsonBytes []byte, policy VerifierPolicy, enforceParentDepthCap bool) AuditProofVerificationResult {
	metadata := VerificationMetadata{}

	// Stage 0: parse JSON.
	var proof map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &proof); err != nil {
		// Pre-stage parse failure → required_field_missing of the document itself.
		// Rust verifier caller (main.rs) handles this above the lib boundary; we
		// mirror that by returning required_field_missing of "json_root".
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:  ReasonRequiredFieldMissing,
				Field: "json_root",
			},
			StageReached: 1,
			Metadata:     metadata,
		}
	}

	// Stage 1: schema validation — cdp_version present.
	cdpVersion, ok := proof["cdp_version"].(string)
	if !ok {
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:  ReasonRequiredFieldMissing,
				Field: "cdp_version",
			},
			StageReached: 1,
			Metadata:     metadata,
		}
	}
	metadata.CdpVersion = strPtr(cdpVersion)

	// Stage 2: cdp_version recognized.
	if !supportedCdpVersions[cdpVersion] {
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:  ReasonCdpVersionUnsupported,
				Found: cdpVersion,
			},
			StageReached: 2,
			Metadata:     metadata,
		}
	}

	// Populate metadata before the policy-pin / chain checks (mirrors Rust).
	if v, ok := proof["capsule_id"].(string); ok {
		metadata.CapsuleID = strPtr(v)
	}
	metadata.Region = lookupStringPath(proof, "environment", "region")
	if metadata.Region == nil {
		if v, ok := proof["region"].(string); ok {
			metadata.Region = strPtr(v)
		}
	}
	metadata.SigningKeyVersion = lookupStringPath(proof, "attestation", "signing_key_version")
	if metadata.SigningKeyVersion == nil {
		if v, ok := proof["signing_key_version"].(string); ok {
			metadata.SigningKeyVersion = strPtr(v)
		}
	}
	metadata.Algorithm = lookupStringPath(proof, "attestation", "algorithm")

	// Policy-pin gate (the customer-authority specification G7 / VP Security F4.3).
	//
	// Rust ordering: policy-pin gate fires BEFORE chain integrity checks.
	// stage_reached = 2.
	if policy.RequiredAuthorityID != "" {
		claimed := lookupStringPath(proof, "signing_authority", "authority_id")
		switch {
		case claimed == nil:
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:                ReasonAuthorityIDMismatch,
					ClaimedAuthorityID:  nil,
					ExpectedAuthorityID: policy.RequiredAuthorityID,
					AuthIDReason:        AuthIDPolicyDemandsCustomerHSMHasNone,
				},
				StageReached: 2,
				Metadata:     metadata,
			}
		case *claimed != policy.RequiredAuthorityID:
			c := *claimed
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:                ReasonAuthorityIDMismatch,
					ClaimedAuthorityID:  &c,
					ExpectedAuthorityID: policy.RequiredAuthorityID,
					AuthIDReason:        AuthIDPolicyAuthorityIDMismatch,
				},
				StageReached: 2,
				Metadata:     metadata,
			}
		}
		// Authority matches policy pin; fall through.
	}

	// Residency-pin gate (the specification G1 / the region policy).
	//
	// Same shape and rationale as the authority pin above: when the auditor
	// pins a region, a proof asserting a different region is rejected before
	// the chain walk. A proof that carries no region at all cannot satisfy a
	// residency pin — it is rejected with an empty `actual` rather than
	// accepted, so the pin fails closed.
	if policy.RequiredRegion != "" {
		actual := ""
		if metadata.Region != nil {
			actual = *metadata.Region
		}
		if actual != policy.RequiredRegion {
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:     ReasonRegionMismatch,
					Required: policy.RequiredRegion,
					Actual:   actual,
				},
				StageReached: 2,
				Metadata:     metadata,
			}
		}
	}

	// Stage 3: chain reproducibility.
	chainRaw, ok := proof["chain"].([]interface{})
	if !ok {
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:  ReasonRequiredFieldMissing,
				Field: "chain",
			},
			StageReached: 3,
			Metadata:     metadata,
		}
	}
	stepCount := len(chainRaw)
	metadata.StepCount = intPtr(stepCount)

	if stepCount != NanorixChainSteps {
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:       ReasonStepCountInvalid,
				Expected:   NanorixChainSteps,
				FoundCount: stepCount,
			},
			StageReached: 3,
			Metadata:     metadata,
		}
	}

	// the chain-timestamp recovery rule — proofs issued before `destroyed_at` was restored to the wire
	// document carry the chain timestamp only in `attestation.key_id`. Recover
	// it there; the recovered value is disclosed in the verdict metadata, never
	// silently substituted.
	timestamp, recovered := resolveChainTimestamp(proof)
	metadata.RecoveredChainTimestamp = recovered

	// the per-record receipt specification + the receipt-batching specification the receipt pipeline — optional Merkle roots for the Step 8
	// amendment. Absent for pre-the receipt pipeline proofs, where both branches collapse to
	// the legacy formula → byte-identical chain walk.
	var rrmrPtr, ppmrPtr *string
	if v, ok := proof["record_receipts_merkle_root"].(string); ok {
		rrmrPtr = strPtr(v)
	}
	if v, ok := proof["parent_proofs_merkle_root"].(string); ok {
		ppmrPtr = strPtr(v)
	}

	prevHash := NanorixGenesisHash
	for idx, stepRaw := range chainRaw {
		step, ok := stepRaw.(map[string]interface{})
		if !ok {
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:      ReasonStepHashMismatch,
					StepIdx:   idx,
					Subsystem: "",
				},
				StageReached: 3,
				Metadata:     metadata,
			}
		}
		subsystem := stringOrEmpty(step["subsystem"])
		claimedChainHash := stringOrEmpty(step["chain_hash"])
		method := LookupMethod(subsystem)

		var recomputed string
		if idx == 7 && subsystem == "capsule_destroy" {
			// the per-record receipt specification + the receipt-batching specification Step 8 amendment — presence-conditional Merkle-
			// root incorporation. The (nil, nil) branch returns the legacy
			// formula bit-for-bit (Forever-Standard).
			recomputed = ComputeStep8Amended(prevHash, timestamp, rrmrPtr, ppmrPtr)
		} else {
			recomputed = ComputeStepHash(prevHash, subsystem, "destroy", method, timestamp)
		}

		if recomputed != StripHashPrefix(claimedChainHash) {
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:      ReasonStepHashMismatch,
					StepIdx:   idx,
					Subsystem: subsystem,
				},
				StageReached: 3,
				Metadata:     metadata,
			}
		}
		prevHash = recomputed
	}

	// ── the per-record receipt specification receipt-set verification (Mode A step 3) ──
	if receipts, ok := proof["record_receipts"].([]interface{}); ok {
		capsuleID := ""
		if metadata.CapsuleID != nil {
			capsuleID = *metadata.CapsuleID
		}
		if failure := verifyRecordReceiptsArray(receipts, capsuleID, rrmrPtr); failure != nil {
			return AuditProofVerificationResult{
				Valid:         false,
				FailureReason: failure,
				StageReached:  3,
				Metadata:      metadata,
			}
		}
	}

	// ── the receipt-batching specification parent-proof set verification ──
	if parents, ok := proof["parent_proof_hashes"].([]interface{}); ok {
		if failure := verifyParentProofsArray(parents, ppmrPtr); failure != nil {
			return AuditProofVerificationResult{
				Valid:         false,
				FailureReason: failure,
				StageReached:  3,
				Metadata:      metadata,
			}
		}
		if enforceParentDepthCap && len(parents) > PARENT_PROOF_MAX_DEPTH {
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:      ReasonStepHashMismatch,
					StepIdx:   7,
					Subsystem: "parent_proof_depth_cap_violation",
				},
				StageReached: 3,
				Metadata:     metadata,
			}
		}
	}

	// Stage 4: final_hash binding.
	claimedFinal := stringOrEmpty(proof["final_hash"])
	lastStep, _ := chainRaw[stepCount-1].(map[string]interface{})
	lastChainHash := ""
	if lastStep != nil {
		lastChainHash = stringOrEmpty(lastStep["chain_hash"])
	}

	if StripHashPrefix(claimedFinal) != StripHashPrefix(lastChainHash) {
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:     ReasonFinalHashMismatch,
				Claimed:  claimedFinal,
				Computed: lastChainHash,
			},
			StageReached: 4,
			Metadata:     metadata,
		}
	}

	// Algorithm dispatch precedes byte-shape checks (the specification C.1): a proof
	// declaring a non-Ed25519 signature algorithm fails typed as
	// algorithm_unsupported here — it must never fall through to the
	// 64/32-byte decode gates and report as "malformed". Absent or "Ed25519"
	// proceeds unchanged (every proof issued to date).
	if found := declaredNonEd25519Algorithm(proof); found != "" {
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:  ReasonAlgorithmUnsupported,
				Found: found,
			},
			StageReached: 4,
			Metadata:     metadata,
		}
	}

	// Stages 5-7: recompute the signed message and check the Ed25519 signature
	// over it against the key embedded in the proof.
	//
	// Everything above proves the chain is internally consistent, which a
	// forged document can also achieve by computing its own chain. Only this
	// stage distinguishes a genuine AuditProof from a fabricated one.
	//
	// The canonical recompute reads a number-preserving parse of the original
	// bytes, because there the serialization IS the cryptographic message.
	sigTree := proof
	if numeric, ok := canonicalProofTree(jsonBytes); ok {
		sigTree = numeric
	}

	switch check := VerifySignature(sigTree, cdpVersion); check.Kind {
	case SignatureVerified:
		// Integrity proven against the embedded key. Stage 8 (anchoring that
		// key to a trust-chain manifest) is not implemented in this build, so
		// this is the terminal success stage — matching the Rust verifier run
		// without a manifest.
		return AuditProofVerificationResult{
			Valid:         true,
			FailureReason: nil,
			StageReached:  7,
			Metadata:      metadata,
		}

	case SignatureUnsupported:
		// The document declares a signing_mode this build cannot verify. NOT the
		// same as "no signature": signing_mode is inside the canonical hash and
		// is attacker-controllable, so treating an unrecognised mode as a partial
		// success turns a rejection into reassurance — a downgrade oracle.
		// algorithm_unsupported is the existing Forever-Standard reason for "this
		// build cannot perform the verification this document requires"; the
		// resolution (upgrade the verifier) is identical. Mirrors the Rust arm.
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:  ReasonAlgorithmUnsupported,
				Found: "signing_mode=" + check.Mode,
			},
			StageReached: 4,
			Metadata:     metadata,
		}

	case SignatureAbsent:
		// Chain reproduced but no signature this build can check (unsigned
		// partial). Honest: this is NOT a full cryptographic verification — it
		// stays at stage 4 and the CLI prints "chain verified, signature NOT
		// checked".
		return AuditProofVerificationResult{
			Valid:         true,
			FailureReason: nil,
			StageReached:  4,
			Metadata:      metadata,
		}

	default:
		// A signature was present and did not verify → reject.
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:      ReasonSignatureMismatch,
				SigReason: check.Reason,
			},
			StageReached: 7,
			Metadata:     metadata,
		}
	}
}

// VerifyValue is a convenience entry point for callers that already have a
// parsed JSON document. Useful for tests that want to mutate the document
// in-memory between verify calls without re-marshalling.
func VerifyValue(proof map[string]interface{}, policy VerifierPolicy) AuditProofVerificationResult {
	bytes, err := json.Marshal(proof)
	if err != nil {
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:  ReasonRequiredFieldMissing,
				Field: "json_root",
			},
			StageReached: 1,
		}
	}
	return Verify(bytes, policy)
}

// ── Internal helpers ────────────────────────────────────────────────

func stringOrEmpty(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func strPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

// lookupStringPath traverses a parsed JSON tree by string path and returns the
// terminal value as *string. Returns nil if any path segment is missing or
// non-traversable. Mirrors the Rust serde_json::Value::pointer convention.
func lookupStringPath(v interface{}, path ...string) *string {
	cur := v
	for _, p := range path {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur, ok = obj[p]
		if !ok || cur == nil {
			return nil
		}
	}
	if s, ok := cur.(string); ok {
		return strPtr(s)
	}
	return nil
}

// formatExitMessage produces a human-readable summary for CLI output. Used by
// main.go; returns a concise single-line description of the result.
func formatExitMessage(r AuditProofVerificationResult) string {
	if r.Valid {
		cap := "(unknown)"
		if r.Metadata.CapsuleID != nil {
			cap = *r.Metadata.CapsuleID
		}
		region := "(unset)"
		if r.Metadata.Region != nil {
			region = *r.Metadata.Region
		}
		return fmt.Sprintf("Verified · capsule %s · region %s", cap, region)
	}
	if r.FailureReason == nil {
		return "FAILED · unknown reason"
	}
	return fmt.Sprintf("FAILED · %s", r.FailureReason.Type)
}

// declaredNonEd25519Algorithm returns the signature algorithm the proof
// declares when it is anything other than the exact canonical "Ed25519".
// Reads attestation.algorithm and the top-level signature_algorithm; both
// absent is the pre-field era, which is Ed25519 by definition.
func declaredNonEd25519Algorithm(proof map[string]interface{}) string {
	if p := lookupStringPath(proof, "attestation", "algorithm"); p != nil && *p != "Ed25519" {
		return *p
	}
	if s, ok := proof["signature_algorithm"].(string); ok && s != "Ed25519" {
		return s
	}
	return ""
}
