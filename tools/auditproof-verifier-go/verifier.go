// AuditProof 8-stage verification pipeline. Mirrors the Rust verifier in
// `tools/nanorix-verify/src/lib.rs::verify_auditproof`.
//
// **Forever-Standard discipline (ADR-006 I0):** the stage numbering, the
// failure-reason emission shapes, the policy-pin gate ordering, and the
// genesis-hash anchor are PERMANENT. Any change to this file that would
// produce non-byte-equivalent output to the Rust verifier on the reference
// corpus is a P0 finding.
//
// **Stage ladder implemented here:**
//
//	1  schema — cdp_version present
//	2  version recognized; the authority-pin and region-pin policy gates
//	3  chain reproducibility (incl. the ADR-039/041 Step-8 amendment, the
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
// per ADR-006 I0 + ADR-031 G7 — pre-amendment callers passing a zero-value
// policy continue to behave identically.
type VerifierPolicy struct {
	// RejectDiagnostic: refuse AuditProofs with `diagnostic_mode: true` (EO-09).
	RejectDiagnostic bool

	// RequiredRegion: if non-empty, require the AuditProof's `region` to match.
	RequiredRegion string

	// RequiredAuthorityID: if non-empty, require the AuditProof's
	// `signing_authority.authority_id` to match. Per ADR-031 G7 + VP Security
	// extended-review F4.3.
	RequiredAuthorityID string

	// CustomerActivity: ADR-056 — the raw bytes of the customer's activity
	// record, when the reader has it. The proof carries only
	// `customer_declared_activity_root`; with the record in hand the verifier
	// recomputes the root and compares (customer_activity.go). Supplying a
	// record to a proof that declares no root is a failure
	// (required_field_missing), not a no-op. Nil → a declared root is
	// disclosed in the verdict as declared, not checked. Mirrors
	// `VerifierPolicy::customer_activity` in the Rust verifier.
	CustomerActivity []byte
}

// supportedCdpVersions enumerates the closed-set of recognized AuditProof
// schema versions. Additive only per ADR-006 I0.
//
// "2.2" (ADR-053 + ADR-056) is verified exactly as "2.1": the canonical view,
// the signed-message form and every stage are unchanged. What 2.2 adds rides
// inside fields the 2.1 recompute already covers — new activity-trail events,
// and `customer_declared_activity_root`, which the recompute includes whenever
// present.
var supportedCdpVersions = map[string]bool{
	"1.0": true,
	"2.0": true,
	"2.1": true,
	"2.2": true,
}

// Verify runs the AuditProof verification pipeline against `jsonBytes` under
// `policy`. Returns the structured verification result.
//
// This is the public entry point for consumers. The result matches
// `tools/nanorix-verify/src/lib.rs::verify_auditproof` on the fixture corpus.
func Verify(jsonBytes []byte, policy VerifierPolicy) AuditProofVerificationResult {
	return verifyCore(jsonBytes, policy, false)
}

// verifyCore is the single verification ladder. `enforceParentDepthCap` adds
// the ADR-041 depth-limit check used by the Wave-N entry point.
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

	// ADR-056 gate on customer_declared_activity_root, stage 2, before the
	// chain walk (mirrors the Rust ladder's position beside its reserved-slot
	// gate). The root is signed only where the signed message is the canonical
	// view (2.1 / 2.2); on 1.0 the message is final_hash and on 2.0 the
	// document_hash field, so a root there is a value anyone can write and the
	// signature cannot tell. On 2.1 / 2.2 a root that is not a sha512: +
	// 128-lowercase-hex string is a shape no signer emits, named here before
	// any recompute consumes it so the verdict blames the field and not the
	// signature or the record.
	if failure := GateDeclaredActivityRoot(proof, cdpVersion); failure != nil {
		return AuditProofVerificationResult{
			Valid:         false,
			FailureReason: failure,
			StageReached:  2,
			Metadata:      metadata,
		}
	}

	// Populate metadata before the policy-pin / chain checks (mirrors Rust).
	if v, ok := proof["capsule_id"].(string); ok {
		metadata.CapsuleID = strPtr(v)
	}
	// Region resolves from the SIGNED capsule_started activity event only.
	//
	// The activity trail is inside CanonicalCdpView, so a region carried there
	// cannot be altered without breaking the signature. The two paths this
	// replaced -- environment.region and top-level region -- are both outside
	// the canonical hash: environment is a derived projection whose struct has
	// no region field at all, and top-level region is emitted by nothing.
	// Reading either let an outsider satisfy the residency pin by appending a
	// region to a genuine signed proof, with no key. Mirrors the Rust change.
	if events, ok := proof["activity"].([]interface{}); ok {
		for _, e := range events {
			ev, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			if tag, _ := ev["event"].(string); tag != "capsule_started" {
				continue
			}
			if v, ok := ev["region"].(string); ok {
				metadata.Region = strPtr(v)
			}
			break
		}
	}
	metadata.SigningKeyVersion = lookupStringPath(proof, "attestation", "signing_key_version")
	if metadata.SigningKeyVersion == nil {
		if v, ok := proof["signing_key_version"].(string); ok {
			metadata.SigningKeyVersion = strPtr(v)
		}
	}
	metadata.Algorithm = lookupStringPath(proof, "attestation", "algorithm")

	// Policy-pin gate (ADR-031 G7 / VP Security F4.3).
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

	// Residency-pin gate (EO-03 G1 / ADR-018 D3).
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

	// ADR-047 — proofs issued before `destroyed_at` was restored to the wire
	// document carry the chain timestamp only in `attestation.key_id`. Recover
	// it there; the recovered value is disclosed in the verdict metadata, never
	// silently substituted.
	timestamp, recovered := resolveChainTimestamp(proof)
	metadata.RecoveredChainTimestamp = recovered

	// ADR-039 + ADR-041 Wave-N — optional Merkle roots for the Step 8
	// amendment. Absent for pre-Wave-N proofs, where both branches collapse to
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
		// Canonical-identity walk: the hash inputs come from CanonicalChain by
		// INDEX, never from the document. A document cannot choose what a step
		// is; it can only fail to match.
		canonical := CanonicalChain[idx]
		declaredSubsystem := stringOrEmpty(step["subsystem"])
		claimedChainHash := stringOrEmpty(step["chain_hash"])

		var recomputed string
		if idx == NanorixChainSteps-1 {
			// ADR-039 + ADR-041 Step 8 amendment — presence-conditional Merkle-
			// root incorporation. The (nil, nil) branch returns the legacy
			// formula bit-for-bit (Forever-Standard).
			recomputed = ComputeStep8Amended(prevHash, timestamp, rrmrPtr, ppmrPtr)
		} else {
			recomputed = ComputeStepHash(prevHash, canonical.Subsystem, "destroy", canonical.Method, timestamp)
		}

		if recomputed != StripHashPrefix(claimedChainHash) {
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:      ReasonStepHashMismatch,
					StepIdx:   idx,
					Subsystem: declaredSubsystem,
				},
				StageReached: 3,
				Metadata:     metadata,
			}
		}

		// Hashes reproduced; the label beside them still has to be the right
		// one. Genuine hashes under a forged subsystem name would otherwise
		// verify clean and read as attesting to a step they do not describe.
		if declaredSubsystem != canonical.Subsystem {
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:              ReasonChainStepIdentity,
					StepIdx:           idx,
					ExpectedSubsystem: canonical.Subsystem,
					FoundSubsystem:    declaredSubsystem,
				},
				StageReached: 3,
				Metadata:     metadata,
			}
		}
		prevHash = recomputed
	}

	// ── ADR-039 receipt-set verification (Mode A step 3) ──
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

	// ── ADR-041 parent-proof set verification ──
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

	// ── ADR-056 customer-declared activity root ──
	// The stage-2 gate above has already rejected a root on a version that
	// does not sign it and a root of any shape no signer emits, so a root
	// read here is a well-formed string on 2.1 / 2.2 and is canonical-bound:
	// the signature stage below binds it to the signer regardless.
	// Recomputing it needs the customer's record, which the reader supplies
	// through the policy. Placed with the other sub-structure Merkle checks,
	// mirroring the Rust ladder.
	if root, ok := DeclaredActivityRoot(proof); ok {
		metadata.CustomerDeclaredActivityRoot = strPtr(root)
	}
	if policy.CustomerActivity != nil {
		if failure := VerifyCustomerDeclaredActivity(proof, policy.CustomerActivity); failure != nil {
			return AuditProofVerificationResult{
				Valid:         false,
				FailureReason: failure,
				StageReached:  3,
				Metadata:      metadata,
			}
		}
		checked := true
		metadata.CustomerDeclaredActivityChecked = &checked
	} else if metadata.CustomerDeclaredActivityRoot != nil {
		checked := false
		metadata.CustomerDeclaredActivityChecked = &checked
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

	// Algorithm dispatch precedes byte-shape checks (ADR-051 C.1): a proof
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
