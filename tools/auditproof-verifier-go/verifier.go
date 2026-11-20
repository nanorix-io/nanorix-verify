// AuditProof 8-stage verification pipeline. Mirrors the Rust verifier in
// `tools/nanorix-verify/src/lib.rs::verify_auditproof`.
//
// **Forever-Standard discipline:** the stage numbering, the
// failure-reason emission shapes, the policy-pin gate ordering, and the
// genesis-hash anchor are PERMANENT. Any change to this file that would
// produce non-byte-equivalent output to the Rust verifier on the reference
// corpus is a P0 finding.
//
// **Stage ladder implemented here:**
//
//	1  schema — cdp_version present
//	2  version recognized; the reserved-slot gate; the declared-activity-root
//	   gate; the authority-pin and region-pin policy gates
//	3  chain reproducibility (incl. the per-record receipt specification/041 Step-8 amendment, the
//	   receipt set, and the parent-proof set)
//	4  final_hash binding
//	5  canonical-hash recompute (folded into the signature stage: the
//	   recomputed canonical view IS the v2.1 signed message)
//	6  signing-key resolution — the embedded key, or the key list's key at stage 8
//	7  Ed25519 signature verification → integrity
//	8  trust-chain anchoring — only when the policy carries a TrustChain
//
// Stage 8 resolves the proof's (authority_id, signing_key_version) in a signed
// key list, checks the signature against the listed key instead of the key the
// proof carries, and refuses a revoked authority. The key list is loaded with
// LoadTrustChain, which refuses any list that is not signed by the identity
// whose fingerprint the caller pinned. Without a TrustChain in the policy the
// ladder ends at stage 7: a proof that reaches it has proven integrity against
// the key it carries, not authenticity. The Rust verifier is the reference for
// stage 8; `trust_chain_vectors_test.go` replays its vectors.
//
// The cross-impl corpus sweep in `corpus_sweep_test.go` is the binding
// backstop: every fixture must match the Rust-authored committed verdict.

package auditproof

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// VerifierPolicy is the customer-side policy configuration. Field-additive
// — pre-amendment callers passing a zero-value
// policy continue to behave identically.
type VerifierPolicy struct {
	// RejectDiagnostic: refuse at stage 2, with ReasonDiagnosticProofRefused,
	// an AuditProof whose signed activity trail records diagnostic mode (a
	// `diagnostic_mode_enabled` event), and every AuditProof that cannot show
	// it does not: one whose trail is unsigned, which is cdp_version 1.0, or
	// 2.1 or 2.2 without a signature, so the event could be removed and the
	// proof would still verify. Only a stage 8 (verified) result ties the
	// trail to a Nanorix key; at stage 7 the key is the one the proof carries.
	// False accepts diagnostic-mode proofs.
	RejectDiagnostic bool

	// RequiredRegion: if non-empty, require the region on the signed
	// capsule_started activity event to match. An AuditProof whose trail is
	// unsigned (cdp_version 1.0, or 2.1 or 2.2 without a signature) is refused
	// with an empty actual. Only a stage 8 (verified) result ties the region
	// to a Nanorix key.
	RequiredRegion string

	// RequiredAuthorityID: if non-empty, require the AuditProof's top-level
	// `authority_id` (absent means DefaultAuthorityID) to equal it. The
	// signature covers that field only on cdp_version 2.1 and 2.2; on 1.0 a
	// string other than DefaultAuthorityID is refused, so a pin accepts only
	// the default there, and 2.0 is refused at the version gate before the pin
	// is read. An unsigned `signing_authority` that disagrees is refused and
	// can never match. Per VP Security extended-review F4.3. A pin
	// is a full authority check only together with TrustChain, which resolves
	// the signing key in a key list instead of trusting the key in the proof.
	RequiredAuthorityID string

	// TrustChain: the signed key list the proof's signing key is resolved
	// against (stage 8). Make it with LoadTrustChain, which checks the list's
	// signature against the identity fingerprint you pin. Nil → the ladder ends
	// at stage 7. Mirrors `VerifierPolicy::trust_chain` in the Rust verifier.
	TrustChain *TrustChain

	// CustomerActivity: the customer-declared activity specification — the raw bytes of the customer's activity
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
// schema versions. A document declaring any other version is refused at stage
// 2. "2.0" is retired and absent on purpose: a 2.0 signature covers a hash that no published rule lets a verifier recompute from the document
// (the wire-format evolution policy requires a verifier to reject a version it does not explicitly
// support). The Forever-Standard wire discipline
// governs the AuditProof structure, not this set.
//
// "2.2" is verified exactly as "2.1": the canonical view,
// the signed-message form and every stage are unchanged. What 2.2 adds rides
// inside fields the 2.1 recompute already covers — new activity-trail events,
// and `customer_declared_activity_root`, which the recompute includes whenever
// present.
var supportedCdpVersions = map[string]bool{
	"1.0": true,
	"2.1": true,
	"2.2": true,
}

// unsignedReservedSlots are the reserved attestation slots that sit outside
// the canonical view AND that no Nanorix signer populates. Same seven names in
// the same order as Rust UNSIGNED_RESERVED_SLOTS: the order decides which slot
// a document with several populated ones is refused for.
//
// The signature never covered these and a genuine document never carries
// them, so a populated one is either a schema this build does not know or an
// outsider edit to an authentic proof. The signature cannot tell the two
// apart, which is why presence alone is the refusal.
//
// per_event_attestations is deliberately absent: genuine proofs carry it, and
// each entry is signed by the customer's own key; this verifier does not check
// those signatures.
var unsignedReservedSlots = [...]string{
	"customer_attestation",
	"policy_attestation",
	"third_party_attestation",
	"retention_policy_attestation",
	"witness_signatures",
	"pqc_attestation",
	"customer_pqc_attestation",
}

// populatedUnsignedSlot returns the first reserved slot, in
// unsignedReservedSlots order, that is present with a value other than JSON
// null, or "" when there is none. Genuine documents emit these keys as an
// explicit null, so absent and null are both normal; anything else, an empty
// array included, is a shape no signer produces.
func populatedUnsignedSlot(proof map[string]interface{}) string {
	for _, slot := range unsignedReservedSlots {
		if v, present := proof[slot]; present && v != nil {
			return slot
		}
	}
	return ""
}

// serdeJSONMaxDepth is how deep serde_json, the parser in front of the Rust
// reference verifier, nests containers: it starts remaining_depth at 128 and
// refuses the `[` or `{` that brings it to zero, so 127 nested containers parse
// and 128 do not. encoding/json allows 10000.
const serdeJSONMaxDepth = 127

// referenceParserRefuses reports whether serde_json refuses bytes that
// encoding/json accepts: invalid UTF-8 and an escape naming half of a
// surrogate pair (both of which encoding/json replaces with U+FFFD), and
// nesting deeper than serdeJSONMaxDepth. It is only consulted for bytes
// encoding/json also parses, so it may assume well-formed JSON.
func referenceParserRefuses(b []byte) bool {
	if !utf8.Valid(b) {
		return true
	}
	depth := 0
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if !inString {
			switch c {
			case '"':
				inString = true
			case '[', '{':
				depth++
				if depth > serdeJSONMaxDepth {
					return true
				}
			case ']', '}':
				depth--
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			i++
			if i >= len(b) || b[i] != 'u' {
				continue
			}
			unit, ok := hexEscapeUnit(b, i+1)
			if !ok {
				return true
			}
			i += 4
			switch {
			case unit >= 0xDC00 && unit <= 0xDFFF:
				return true
			case unit >= 0xD800 && unit <= 0xDBFF:
				if i+2 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
					return true
				}
				low, ok := hexEscapeUnit(b, i+3)
				if !ok || low < 0xDC00 || low > 0xDFFF {
					return true
				}
				i += 6
			}
		}
	}
	return false
}

// hexEscapeUnit reads the four hex digits of a \u escape starting at b[at].
func hexEscapeUnit(b []byte, at int) (rune, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	var unit rune
	for _, c := range b[at : at+4] {
		unit <<= 4
		switch {
		case c >= '0' && c <= '9':
			unit |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			unit |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			unit |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return unit, true
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
// the depth-limit check used by the receipt pipeline entry point.
//
// One ladder, not two: a second copy of this logic is how the signature stage
// came to be missing from one path while present in the other.
func verifyCore(jsonBytes []byte, policy VerifierPolicy, enforceParentDepthCap bool) AuditProofVerificationResult {
	metadata := VerificationMetadata{}

	// Stage 0: parse JSON.
	var document interface{}
	if err := json.Unmarshal(jsonBytes, &document); err != nil || referenceParserRefuses(jsonBytes) {
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

	// A top-level value that is not an object parses, so it is not json_root:
	// like the reference, it has no cdp_version.
	proof, _ := document.(map[string]interface{})

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

	// Reserved-slot gate, stage 2, after the version gate and before every
	// other stage-2 gate (mirrors the Rust ladder). A slot outside the
	// signature carrying a value no signer emits means these bytes are not
	// the bytes that were signed, even when the signature over the covered
	// subset still checks out; that holds whatever a customer policy asks for.
	if slot := populatedUnsignedSlot(proof); slot != "" {
		return AuditProofVerificationResult{
			Valid: false,
			FailureReason: &FailureReason{
				Type:  ReasonUnsignedFieldPopulated,
				Field: slot,
			},
			StageReached: 2,
			Metadata:     metadata,
		}
	}

	// Gate on customer_declared_activity_root, stage 2, before the
	// chain walk (mirrors the Rust ladder's position after its reserved-slot
	// gate). The root is signed only where the signed message is the canonical
	// view (2.1 / 2.2); on 1.0 the message is final_hash, so a root there is
	// a value anyone can write and the signature cannot tell. On 2.1 / 2.2 a root that is not a sha512: +
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
	//
	// The capsule id as the document states it: the record-receipt check below
	// hashes it on every version. The metadata names a capsule and a region only
	// on a version whose signature covers them. A 1.0 signature covers
	// final_hash alone, which binds destroyed_at and the two optional Merkle
	// roots. It does not bind the capsule_id itself (only through record
	// receipts, which a holder can remove), the region or the key id, so on 1.0
	// neither is reported.
	documentCapsuleID, _ := proof["capsule_id"].(string)
	namesSignedFields := canonicalViewSignedVersions[cdpVersion]
	// The region is read from the activity trail, so it is reported only when
	// the signature step below will check a signature over that trail: on a
	// proof without a signature or key, no return names it. Mirrors Rust.
	trailChecked := namesSignedFields &&
		VerifySignature(signatureTree(proof, jsonBytes), cdpVersion).Kind != SignatureAbsent
	if v, ok := proof["capsule_id"].(string); ok && namesSignedFields {
		metadata.CapsuleID = strPtr(v)
	}
	// Region resolves from the capsule_started activity event only, on 2.1 and
	// 2.2 carrying a signature.
	//
	// On 2.1 and 2.2 the activity trail is inside CanonicalCdpView, so a region
	// carried there cannot be altered without breaking the signature. An
	// unsigned 2.1 or 2.2 proof reports no region. The two paths this
	// replaced -- environment.region and top-level region -- are both outside
	// the canonical hash: environment is a derived projection whose struct has
	// no region field at all, and top-level region is emitted by nothing.
	// Reading either let an outsider satisfy the residency pin by appending a
	// region to a genuine signed proof, with no key. Mirrors the Rust change.
	if events, ok := proof["activity"].([]interface{}); ok && trailChecked {
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
	if v, ok := proof["authority_id"].(string); ok {
		metadata.AuthorityID = strPtr(v)
	}
	if v, ok := proof["signing_mode"].(string); ok {
		metadata.SigningMode = strPtr(v)
	}

	// Policy-pin gate (the customer-authority specification / VP Security F4.3).
	//
	// Rust ordering: policy-pin gate fires BEFORE chain integrity checks.
	// stage_reached = 2.
	//
	// The pin is compared with the top-level `authority_id`; absent or
	// non-string means DefaultAuthorityID. Only cdp_version 2.1 and 2.2 sign
	// that field (the canonical view binds it): 1.0 signs final_hash, so on 1.0
	// a top-level string other than DefaultAuthorityID (the empty string
	// included) is refused first, claimed = that value, and the effective
	// authority can only be the default. 2.0 never reaches this gate: the
	// version gate above refuses it first. An unsigned
	// `signing_authority.authority_id` that differs from it is refused
	// (claimed = that value) and can never make a proof match a pin;
	// `signing_authority` absent, null or without `authority_id` is ignored.
	// With the top-level field absent, a non-matching pin reports claimed nil
	// and the has-none reason. A pin is a full authority check only when the
	// policy also carries a TrustChain.
	if policy.RequiredAuthorityID != "" {
		topLevel := lookupStringPath(proof, "authority_id")
		effective := effectiveAuthorityID(proof)
		if !canonicalViewSignedVersions[cdpVersion] && topLevel != nil && *topLevel != DefaultAuthorityID {
			c := *topLevel
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
		unsigned := lookupStringPath(proof, "signing_authority", "authority_id")
		if unsigned != nil && *unsigned != effective {
			c := *unsigned
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
		if effective != policy.RequiredAuthorityID {
			reason := AuthIDPolicyAuthorityIDMismatch
			var claimed *string
			if topLevel == nil {
				reason = AuthIDPolicyDemandsCustomerHSMHasNone
			} else {
				c := *topLevel
				claimed = &c
			}
			return AuditProofVerificationResult{
				Valid: false,
				FailureReason: &FailureReason{
					Type:                ReasonAuthorityIDMismatch,
					ClaimedAuthorityID:  claimed,
					ExpectedAuthorityID: policy.RequiredAuthorityID,
					AuthIDReason:        reason,
				},
				StageReached: 2,
				Metadata:     metadata,
			}
		}
		// Authority matches policy pin; fall through.
	}

	// The residency pin and the diagnostic gate read the activity trail, so
	// each trusts it only when the signature step below will check a signature
	// over it: the version's signed message is the canonical view (2.1 / 2.2)
	// and that step does not end as SignatureAbsent. A 1.0 trail, and the
	// trail of a 2.1 or 2.2 proof without a signature or key, is unsigned:
	// anyone could add a region equal to the pin, or delete a
	// diagnostic_mode_enabled event, and the proof would still verify.
	// Computed only under a policy that reads the trail. Mirrors Rust.
	trailSigned := (policy.RequiredRegion != "" || policy.RejectDiagnostic) && trailChecked

	// Residency-pin gate.
	//
	// Same shape and rationale as the authority pin above: when the auditor
	// pins a region, a proof asserting a different region is rejected before
	// the chain walk. A proof that carries no region at all cannot satisfy a
	// residency pin — it is rejected with an empty `actual` rather than
	// accepted, so the pin fails closed.
	//
	// Only a signed region counts: on an unsigned trail the pin reads no
	// region and refuses with an empty actual.
	if policy.RequiredRegion != "" {
		actual := ""
		if metadata.Region != nil && trailSigned {
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

	// Diagnostic-mode gate, after the residency pin and before
	// the chain walk, like the other policy pins. A proof whose trail is
	// unsigned (1.0, or 2.1 or 2.2 without a signature) cannot show it was not
	// run in diagnostic mode, since the event could be deleted and the proof
	// would still verify: the setting refuses every one. Mirrors Rust.
	if policy.RejectDiagnostic && (!trailSigned || recordsDiagnosticMode(proof)) {
		return AuditProofVerificationResult{
			Valid:         false,
			FailureReason: &FailureReason{Type: ReasonDiagnosticProofRefused},
			StageReached:  2,
			Metadata:      metadata,
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

	// Proofs issued before `destroyed_at` was restored to the wire
	// document carry the chain timestamp only in `attestation.key_id`. Recover
	// it there; the recovered value is disclosed in the verdict metadata, never
	// silently substituted.
	timestamp, recovered := resolveChainTimestamp(proof)
	metadata.RecoveredChainTimestamp = recovered

	// The receipt pipeline — optional Merkle roots for the Step 8
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
		// Canonical-identity walk: the hash inputs come from CanonicalChain by
		// INDEX, never from the document. A document cannot choose what a step
		// is; it can only fail to match.
		canonical := CanonicalChain[idx]
		declaredSubsystem := stringOrEmpty(step["subsystem"])
		claimedChainHash := stringOrEmpty(step["chain_hash"])

		var recomputed string
		if idx == NanorixChainSteps-1 {
			// The per-record receipt specification + the cross-organisation chain specification Step 8 amendment — presence-conditional Merkle-
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

	// ── receipt-set verification (Mode A step 3) ──
	if receipts, ok := proof["record_receipts"].([]interface{}); ok {
		if failure := verifyRecordReceiptsArray(receipts, documentCapsuleID, rrmrPtr); failure != nil {
			return AuditProofVerificationResult{
				Valid:         false,
				FailureReason: failure,
				StageReached:  3,
				Metadata:      metadata,
			}
		}
	}

	// ── parent-proof set verification ──
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

	// ── customer-declared activity root ──
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

	// Algorithm dispatch precedes byte-shape checks: a proof
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

	// The consistency rule of the amendment, section 4: after the
	// algorithm check and before the signature-presence check, so an unsigned
	// customer_only document under a Nanorix-classified authority is refused
	// too. Mirrors signing_mode_authority_mismatch in
	// tools/nanorix-verify/src/lib.rs.
	if reason := signingModeAuthorityMismatch(proof, cdpVersion); reason != nil {
		return AuditProofVerificationResult{
			Valid:         false,
			FailureReason: reason,
			StageReached:  4,
			Metadata:      metadata,
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
	sigTree := signatureTree(proof, jsonBytes)

	switch check := VerifySignature(sigTree, cdpVersion); check.Kind {
	case SignatureVerified:
		// Integrity proven against the embedded key. With a key list in the
		// policy, stage 8 anchors that key; without one this is the terminal
		// success stage, matching the Rust verifier run without a manifest.
		signed := canonicalViewSignedVersions[cdpVersion]
		metadata.AuthoritySigned = &signed
		if policy.TrustChain != nil {
			return anchorToTrustChain(proof, sigTree, cdpVersion, policy.TrustChain, metadata)
		}
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
		// checked". Under a hybrid pin it is refused there instead.
		if underHybridPin(policy.TrustChain) {
			return hybridRecordRefusal(4, metadata)
		}
		// No signature covers the activity trail here, so the region read from
		// it is not reported.
		metadata.Region = nil
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

// canonicalViewSignedVersions are the cdp_versions whose signature covers the
// canonical view, and with it the top-level `authority_id`. Mirrors Rust
// CANONICAL_VIEW_SIGNED_VERSIONS.
var canonicalViewSignedVersions = map[string]bool{"2.1": true, "2.2": true}

// DefaultAuthorityID is the authority a proof anchors under when it carries no
// top-level `authority_id` (the Nanorix-hosted signing path).
const DefaultAuthorityID = "us-kms-nanorix-v1"

// DiagnosticModeEvent is the activity event an issuer writes when a capsule
// ran in diagnostic mode.
const DiagnosticModeEvent = "diagnostic_mode_enabled"

// signatureTree is the tree the signature step reads: a number-preserving
// parse of the original bytes, or the parsed proof when that parse fails.
func signatureTree(proof map[string]interface{}, jsonBytes []byte) map[string]interface{} {
	if numeric, ok := canonicalProofTree(jsonBytes); ok {
		return numeric
	}
	return proof
}

// recordsDiagnosticMode reports whether the activity trail holds an entry
// whose `event` is DiagnosticModeEvent. The trail is signed only on 2.1 and
// 2.2 with a signature, so false proves nothing on 1.0 or on an unsigned 2.1
// or 2.2 proof; the diagnostic gate refuses those outright for that reason.
// Mirrors Rust `records_diagnostic_mode`.
func recordsDiagnosticMode(proof map[string]interface{}) bool {
	events, ok := proof["activity"].([]interface{})
	if !ok {
		return false
	}
	for _, e := range events {
		ev, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		if tag, _ := ev["event"].(string); tag == DiagnosticModeEvent {
			return true
		}
	}
	return false
}

// effectiveAuthorityID returns the top-level `authority_id`, or
// DefaultAuthorityID when it is absent or not a string.
func effectiveAuthorityID(proof interface{}) string {
	if v := lookupStringPath(proof, "authority_id"); v != nil {
		return *v
	}
	return DefaultAuthorityID
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

// SigningModeCustomerOnly is the signing_mode a proof carries when the
// install's customer authority signed it (Part A).
// Compared byte for byte.
const SigningModeCustomerOnly = "customer_only"

// customerAuthoritySegments are the byte strings that make an authority id
// customer-classified: the issuer's test, AuthorityKind::from_authority_id in
// the reference server implementation, a substring match anywhere
// in the id, byte-exact and case-sensitive, with no normalization.
var customerAuthoritySegments = [...]string{
	"customer-hsm-",
	"customer-kms-",
	"customer-tee-",
	"customer-byo-",
}

// IsCustomerAuthority reports whether authorityID is customer-classified.
// Every other id is Nanorix-classified.
func IsCustomerAuthority(authorityID string) bool {
	for _, segment := range customerAuthoritySegments {
		if strings.Contains(authorityID, segment) {
			return true
		}
	}
	return false
}

// signingModeAuthorityMismatch is the consistency rule:
// on 2.1 and 2.2, a signing_mode of exactly customer_only under a
// Nanorix-classified authority_id (an absent, null or non-string one
// included) is refused. Returns nil when the pair is consistent or the
// version signs neither label.
func signingModeAuthorityMismatch(proof map[string]interface{}, cdpVersion string) *FailureReason {
	if cdpVersion != "2.1" && cdpVersion != "2.2" {
		return nil
	}
	if mode, _ := proof["signing_mode"].(string); mode != SigningModeCustomerOnly {
		return nil
	}
	claimed, isString := proof["authority_id"].(string)
	if isString && IsCustomerAuthority(claimed) {
		return nil
	}
	reason := &FailureReason{Type: ReasonSigningModeAuthorityMismatch}
	if isString {
		reason.ClaimedAuthorityID = &claimed
	}
	return reason
}
