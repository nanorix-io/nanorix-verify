// Package auditproof — verification result types mirroring the Rust
// `nanorix-verify-types` crate at `governance/verify-types/src/lib.rs`.
//
// **Forever-Standard discipline (ADR-006 I0):** every variant shipped here is
// permanent. New failure modes ship as ADDITIVE variants. Existing variants
// NEVER renamed, NEVER removed, NEVER repurposed.
//
// Wire form: `{"type": "<snake_case>", ...payload}` — must serialize
// byte-identical to the Rust serde-tag dispatch. The variant catalog is the
// cryptographic-attestation contract auditors rely on.
//
// Variant catalog (alphabetical by snake_case wire tag):
//
//   - algorithm_unsupported            V1 only supports Ed25519
//   - authority_id_mismatch            policy-pin failure (ADR-031 G7)
//   - authority_mode_mismatch          customer-authority Ed25519 verify failure
//   - authority_revoked                trust-chain marks authority revoked
//   - cdp_version_unsupported          version not in {1.0, 2.0, 2.1, 2.2}
//   - customer_declared_activity_root_mismatch  the proof's signed root disagrees with the root recomputed from the supplied record (ADR-056)
//   - diagnostic_proof_refused         policy refuses diagnostic-mode (ADR-019 D2)
//   - final_hash_mismatch              final_hash != last step's chain_hash
//   - genesis_hash_mismatch            first step's prev_hash != SHA-512(empty)
//   - region_mismatch                  region differs from policy-required
//   - required_field_missing           structural field absent
//   - reserved                         V2+ wire-surface reservation
//   - signature_mismatch               Ed25519 signature verification failed
//   - signing_key_version_unknown      key version not in trust-chain manifest
//   - step_count_invalid               chain has != 8 steps
//   - step_hash_mismatch               step's recompute didn't match
//   - chain_step_identity_mismatch     a step names a non-canonical subsystem
package auditproof

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// AuditProofVerificationResult mirrors `tools/nanorix-verify/src/lib.rs::VerificationResult`.
//
// Wire form is JSON; field order is irrelevant in JSON but the field set is
// part of the Forever-Standard contract.
type AuditProofVerificationResult struct {
	// Valid is true if and only if every check stage passed.
	Valid bool `json:"valid"`

	// FailureReason is populated when Valid is false. Closed-set enum.
	FailureReason *FailureReason `json:"failure_reason"`

	// StageReached: 1..=8 highest stage reached (advisory; matches ADR-011 I8).
	StageReached uint8 `json:"stage_reached"`

	// Metadata: structural-only diagnostic data; no payload bytes.
	Metadata VerificationMetadata `json:"metadata"`
}

// VerificationMetadata mirrors `tools/nanorix-verify/src/lib.rs::VerificationMetadata`.
type VerificationMetadata struct {
	CdpVersion         *string `json:"cdp_version"`
	CapsuleID          *string `json:"capsule_id"`
	Region             *string `json:"region"`
	SigningKeyVersion  *string `json:"signing_key_version"`
	Algorithm          *string `json:"algorithm"`
	StepCount          *int    `json:"step_count"`
	ActivityEventCount *int    `json:"activity_event_count"`

	// RecoveredChainTimestamp is set only when the document carried no usable
	// `destroyed_at` and the chain timestamp was recovered from
	// `attestation.key_id` (ADR-047 pre-restoration proofs). Nil means the
	// timestamp came from the document's own field, so an auditor reading a
	// verdict can always tell which route produced it. Omitted from the wire
	// form when nil, mirroring the Rust `skip_serializing_if = "Option::is_none"`.
	RecoveredChainTimestamp *string `json:"recovered_chain_timestamp,omitempty"`

	// UnattestedParentAttribution counts parent links carrying attribution the
	// signature does not cover -- parent_key_id, parent_signature, parent_role,
	// parent_jurisdiction, parent_organization_tag. Only parent_chain_hash feeds
	// the signed Merkle root, so an outsider can rewrite the rest of a genuine
	// proof's declared lineage. The lineage UI renders exactly those fields, so
	// a verdict that stays silent invites them to be read as attested.
	UnattestedParentAttribution *int `json:"unattested_parent_attribution,omitempty"`

	// CustomerDeclaredActivityRoot is the `customer_declared_activity_root`
	// the proof carries (ADR-056), as written. Nil when the proof declares
	// none. Disclosed whether or not the record was supplied: a verdict that
	// stays silent about a declared root invites a reader to assume it was
	// checked.
	CustomerDeclaredActivityRoot *string `json:"customer_declared_activity_root,omitempty"`

	// CustomerDeclaredActivityChecked is true when the customer's activity
	// record was supplied (VerifierPolicy.CustomerActivity) and its recomputed
	// root matched the declared one; false when the proof declares a root but
	// no record was supplied — declared, not checked. Nil when the proof
	// declares no root. A mismatch is a failure, not a false here. Never true
	// outside cdp_version 2.1 / 2.2: on any other version a declared root is
	// unsigned and the proof is rejected before this point.
	CustomerDeclaredActivityChecked *bool `json:"customer_declared_activity_checked,omitempty"`
}

// CdpKind is the ADR-006 Wave 16-A reserved-slot scope discriminator
// (2026-05-10). Forever-stable per ADR-006 I0. Mirrors the Rust enum
// `nanorix_rzl::cdp::CdpKind`.
//
// AuditProof scope. V1 always absent in serialized JSON (workload scope is
// implicit). Future Items 2 (sealed-proxy = "call") and 4 (sealed-middleware
// = "request") populate this; Pattern 4 high-volume per-record AuditProofs
// use "batch".
//
// The Go verifier treats `cdp_kind` as OPAQUE — chain integrity verification
// is independent of cdp_kind. The field lives at the canonical_hash
// outer-document layer (services/api/src/cdp_document.rs), not in the
// 8-step destruction chain that this verifier reproduces.
type CdpKind string

const (
	CdpKindWorkload CdpKind = "workload"
	CdpKindRequest  CdpKind = "request"
	CdpKindCall     CdpKind = "call"
	CdpKindBatch    CdpKind = "batch"
)

// FailureReasonType is the closed-set wire-form discriminator. Forever-stable
// per ADR-006 I0. Additive only — new variants land here without breaking
// existing parsers.
type FailureReasonType string

const (
	ReasonAlgorithmUnsupported                 FailureReasonType = "algorithm_unsupported"
	ReasonAuthorityIDMismatch                  FailureReasonType = "authority_id_mismatch"
	ReasonAuthorityModeMismatch                FailureReasonType = "authority_mode_mismatch"
	ReasonAuthorityRevoked                     FailureReasonType = "authority_revoked"
	ReasonCdpVersionUnsupported                FailureReasonType = "cdp_version_unsupported"
	ReasonChainStepIdentity                    FailureReasonType = "chain_step_identity_mismatch"
	ReasonCustomerDeclaredActivityRootMismatch FailureReasonType = "customer_declared_activity_root_mismatch"
	ReasonDiagnosticProofRefused               FailureReasonType = "diagnostic_proof_refused"
	ReasonFieldMalformed                       FailureReasonType = "field_malformed"
	ReasonFinalHashMismatch                    FailureReasonType = "final_hash_mismatch"
	ReasonGenesisHashMismatch                  FailureReasonType = "genesis_hash_mismatch"
	ReasonRegionMismatch                       FailureReasonType = "region_mismatch"
	ReasonRequiredFieldMissing                 FailureReasonType = "required_field_missing"
	ReasonReserved                             FailureReasonType = "reserved"
	ReasonSignatureMismatch                    FailureReasonType = "signature_mismatch"
	ReasonSigningKeyVersionUnknown             FailureReasonType = "signing_key_version_unknown"
	ReasonStepCountInvalid                     FailureReasonType = "step_count_invalid"
	ReasonStepHashMismatch                     FailureReasonType = "step_hash_mismatch"
	ReasonUnsignedFieldPopulated               FailureReasonType = "unsigned_field_populated"
)

// SignatureFailureReason mirrors the Rust sub-enum
// `governance/verify-types/src/lib.rs::SignatureFailureReason`.
type SignatureFailureReason string

const (
	SigMalformed             SignatureFailureReason = "malformed"
	SigDoesNotVerify         SignatureFailureReason = "does_not_verify"
	SigPublicKeyMalformed    SignatureFailureReason = "public_key_malformed"
	SigMessageFormatMismatch SignatureFailureReason = "message_format_mismatch"
)

// AuthorityIDMismatchReason mirrors the Rust sub-enum
// `governance/verify-types/src/lib.rs::AuthorityIdMismatchReason`.
type AuthorityIDMismatchReason string

const (
	AuthIDPolicyDemandsCustomerHSMHasNone AuthorityIDMismatchReason = "verifier_policy_demands_customer_hsm_audit_proof_has_none"
	AuthIDPolicyAuthorityIDMismatch       AuthorityIDMismatchReason = "verifier_policy_authority_id_mismatch"
)

// FailureReason is the closed-set tagged-union mirror of the Rust enum
// `nanorix_verify_types::FailureReason`. Marshals/unmarshals to/from
// `{"type": "...", ...payload}` matching serde's `tag = "type"` dispatch.
//
// Field semantics per variant:
//
//   - cdp_version_unsupported:    Found
//   - required_field_missing:     Field
//   - step_count_invalid:         Expected, Found
//   - step_hash_mismatch:         StepIdx, Subsystem
//   - chain_step_identity_mismatch: StepIdx, ExpectedSubsystem, FoundSubsystem
//   - genesis_hash_mismatch:      (no fields)
//   - final_hash_mismatch:        Claimed, Computed
//   - customer_declared_activity_root_mismatch: Claimed, Computed
//   - field_malformed:            Field, Reason
//   - signature_mismatch:         SigReason
//   - signing_key_version_unknown: Version
//   - authority_revoked:          (no fields)
//   - region_mismatch:            Required, Actual
//   - diagnostic_proof_refused:   (no fields)
//   - algorithm_unsupported:      Found
//   - authority_mode_mismatch:    ClaimedAuthorityID, ExpectedAlgorithm, ActualAlgorithm
//   - authority_id_mismatch:      ClaimedAuthorityID*, ExpectedAuthorityID, AuthIDReason
//   - unsigned_field_populated:   Field
//   - reserved:                   (no fields)
type FailureReason struct {
	Type FailureReasonType

	// Per-variant payload fields. Nil/zero values when not applicable.
	Found               string                    // cdp_version_unsupported, algorithm_unsupported
	Field               string                    // required_field_missing, unsigned_field_populated, field_malformed
	Reason              string                    // field_malformed — free text naming what was wrong with the field
	Expected            int                       // step_count_invalid
	FoundCount          int                       // step_count_invalid (Found is overloaded; use this for int)
	StepIdx             int                       // step_hash_mismatch, chain_step_identity_mismatch
	Subsystem           string                    // step_hash_mismatch
	ExpectedSubsystem   string                    // chain_step_identity_mismatch
	FoundSubsystem      string                    // chain_step_identity_mismatch
	Claimed             string                    // final_hash_mismatch, customer_declared_activity_root_mismatch
	Computed            string                    // final_hash_mismatch, customer_declared_activity_root_mismatch
	SigReason           SignatureFailureReason    // signature_mismatch
	Version             string                    // signing_key_version_unknown
	Required            string                    // region_mismatch
	Actual              string                    // region_mismatch
	ClaimedAuthorityID  *string                   // authority_id_mismatch (None = nil)
	ExpectedAuthorityID string                    // authority_id_mismatch
	AuthIDReason        AuthorityIDMismatchReason // authority_id_mismatch
	ExpectedAlgorithm   string                    // authority_mode_mismatch
	ActualAlgorithm     *string                   // authority_mode_mismatch (None = nil)
	// ClaimedAuthorityID also used by authority_mode_mismatch; reuse field.
}

// MarshalJSON emits the serde-tag wire form: `{"type": "...", payload-fields...}`.
//
// **Cross-impl byte-equivalence:** the field emission order matches Rust's
// serde-tag dispatch — `"type"` is emitted FIRST as the discriminant, then
// payload fields in their Rust struct-declaration order. Go's default
// `map[string]interface{}` marshalling sorts keys alphabetically and would
// drift from Rust's wire form; therefore we hand-emit the bytes here.
//
// Forever-Standard discipline (ADR-006 I0): the wire form (key ordering, key
// names, value encoding) is the cryptographic-attestation contract. Any
// future change must produce byte-identical output to Rust's `serde_json::
// to_string(&FailureReason)` on the reference corpus.
func (r *FailureReason) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	buf.WriteString(`"type":`)
	tagBytes, err := json.Marshal(string(r.Type))
	if err != nil {
		return nil, err
	}
	buf.Write(tagBytes)

	emit := func(key string, value interface{}) error {
		buf.WriteByte(',')
		kBytes, err := json.Marshal(key)
		if err != nil {
			return err
		}
		buf.Write(kBytes)
		buf.WriteByte(':')
		vBytes, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(vBytes)
		return nil
	}

	switch r.Type {
	case ReasonCdpVersionUnsupported, ReasonAlgorithmUnsupported:
		if err := emit("found", r.Found); err != nil {
			return nil, err
		}
	case ReasonRequiredFieldMissing, ReasonUnsignedFieldPopulated:
		if err := emit("field", r.Field); err != nil {
			return nil, err
		}
	case ReasonFieldMalformed:
		// Rust struct declaration order: field, reason.
		if err := emit("field", r.Field); err != nil {
			return nil, err
		}
		if err := emit("reason", r.Reason); err != nil {
			return nil, err
		}
	case ReasonStepCountInvalid:
		if err := emit("expected", r.Expected); err != nil {
			return nil, err
		}
		if err := emit("found", r.FoundCount); err != nil {
			return nil, err
		}
	case ReasonStepHashMismatch:
		if err := emit("step_idx", r.StepIdx); err != nil {
			return nil, err
		}
		if err := emit("subsystem", r.Subsystem); err != nil {
			return nil, err
		}
	case ReasonChainStepIdentity:
		if err := emit("step_idx", r.StepIdx); err != nil {
			return nil, err
		}
		if err := emit("expected_subsystem", r.ExpectedSubsystem); err != nil {
			return nil, err
		}
		if err := emit("found_subsystem", r.FoundSubsystem); err != nil {
			return nil, err
		}
	case ReasonGenesisHashMismatch, ReasonAuthorityRevoked, ReasonDiagnosticProofRefused, ReasonReserved:
		// no payload fields
	case ReasonFinalHashMismatch, ReasonCustomerDeclaredActivityRootMismatch:
		if err := emit("claimed", r.Claimed); err != nil {
			return nil, err
		}
		if err := emit("computed", r.Computed); err != nil {
			return nil, err
		}
	case ReasonSignatureMismatch:
		if err := emit("reason", string(r.SigReason)); err != nil {
			return nil, err
		}
	case ReasonSigningKeyVersionUnknown:
		if err := emit("version", r.Version); err != nil {
			return nil, err
		}
	case ReasonRegionMismatch:
		if err := emit("required", r.Required); err != nil {
			return nil, err
		}
		if err := emit("actual", r.Actual); err != nil {
			return nil, err
		}
	case ReasonAuthorityModeMismatch:
		// Rust struct declaration order: claimed_authority_id, expected_algorithm,
		// actual_algorithm.
		var claimed interface{} = ""
		if r.ClaimedAuthorityID != nil {
			claimed = *r.ClaimedAuthorityID
		}
		if err := emit("claimed_authority_id", claimed); err != nil {
			return nil, err
		}
		if err := emit("expected_algorithm", r.ExpectedAlgorithm); err != nil {
			return nil, err
		}
		var actual interface{}
		if r.ActualAlgorithm != nil {
			actual = *r.ActualAlgorithm
		}
		if err := emit("actual_algorithm", actual); err != nil {
			return nil, err
		}
	case ReasonAuthorityIDMismatch:
		// Rust struct declaration order: claimed_authority_id, expected_authority_id, reason.
		var claimed interface{}
		if r.ClaimedAuthorityID != nil {
			claimed = *r.ClaimedAuthorityID
		}
		if err := emit("claimed_authority_id", claimed); err != nil {
			return nil, err
		}
		if err := emit("expected_authority_id", r.ExpectedAuthorityID); err != nil {
			return nil, err
		}
		if err := emit("reason", string(r.AuthIDReason)); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown FailureReason type %q (closed-set enum violation; Forever-Standard ADR-006 I0)", r.Type)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON parses the serde-tag wire form back into FailureReason.
// Tolerates field absence (omitted = zero value).
func (r *FailureReason) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	t, ok := raw["type"].(string)
	if !ok {
		return fmt.Errorf("FailureReason missing 'type' tag")
	}
	r.Type = FailureReasonType(t)
	switch r.Type {
	case ReasonCdpVersionUnsupported, ReasonAlgorithmUnsupported:
		if v, ok := raw["found"].(string); ok {
			r.Found = v
		}
	case ReasonRequiredFieldMissing, ReasonUnsignedFieldPopulated:
		if v, ok := raw["field"].(string); ok {
			r.Field = v
		}
	case ReasonFieldMalformed:
		if v, ok := raw["field"].(string); ok {
			r.Field = v
		}
		if v, ok := raw["reason"].(string); ok {
			r.Reason = v
		}
	case ReasonStepCountInvalid:
		if v, ok := raw["expected"].(float64); ok {
			r.Expected = int(v)
		}
		if v, ok := raw["found"].(float64); ok {
			r.FoundCount = int(v)
		}
	case ReasonStepHashMismatch:
		if v, ok := raw["step_idx"].(float64); ok {
			r.StepIdx = int(v)
		}
		if v, ok := raw["subsystem"].(string); ok {
			r.Subsystem = v
		}
	case ReasonChainStepIdentity:
		if v, ok := raw["step_idx"].(float64); ok {
			r.StepIdx = int(v)
		}
		if v, ok := raw["expected_subsystem"].(string); ok {
			r.ExpectedSubsystem = v
		}
		if v, ok := raw["found_subsystem"].(string); ok {
			r.FoundSubsystem = v
		}
	case ReasonFinalHashMismatch, ReasonCustomerDeclaredActivityRootMismatch:
		if v, ok := raw["claimed"].(string); ok {
			r.Claimed = v
		}
		if v, ok := raw["computed"].(string); ok {
			r.Computed = v
		}
	case ReasonSignatureMismatch:
		if v, ok := raw["reason"].(string); ok {
			r.SigReason = SignatureFailureReason(v)
		}
	case ReasonSigningKeyVersionUnknown:
		if v, ok := raw["version"].(string); ok {
			r.Version = v
		}
	case ReasonRegionMismatch:
		if v, ok := raw["required"].(string); ok {
			r.Required = v
		}
		if v, ok := raw["actual"].(string); ok {
			r.Actual = v
		}
	case ReasonAuthorityModeMismatch:
		if v, ok := raw["claimed_authority_id"].(string); ok {
			r.ClaimedAuthorityID = &v
		}
		if v, ok := raw["expected_algorithm"].(string); ok {
			r.ExpectedAlgorithm = v
		}
		if v, ok := raw["actual_algorithm"].(string); ok {
			r.ActualAlgorithm = &v
		}
	case ReasonAuthorityIDMismatch:
		if v, ok := raw["claimed_authority_id"].(string); ok {
			r.ClaimedAuthorityID = &v
		}
		if v, ok := raw["expected_authority_id"].(string); ok {
			r.ExpectedAuthorityID = v
		}
		if v, ok := raw["reason"].(string); ok {
			r.AuthIDReason = AuthorityIDMismatchReason(v)
		}
	}
	return nil
}

// Equal returns true if the two FailureReasons are byte-equivalent in wire form.
// Used by cross-impl tests to assert byte-equivalence against Rust verifier output.
func (r *FailureReason) Equal(other *FailureReason) bool {
	if r == nil && other == nil {
		return true
	}
	if r == nil || other == nil {
		return false
	}
	a, _ := r.MarshalJSON()
	b, _ := other.MarshalJSON()
	return string(a) == string(b)
}
