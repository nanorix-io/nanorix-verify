// Stage 8 trust root: a signed key list (the trust-chain manifest) pinned by the
// fingerprint of the identity key that signed it.
//
// Mirrors `tools/nanorix-verify/src/trust_chain.rs`. The Rust verifier is the
// reference and the vectors under `tools/nanorix-verify/fixtures/trust_chain/`
// are what holds this file to it: `trust_chain_vectors_test.go` replays them.
//
// A list is checked once, when it is loaded, against the pinned fingerprint. A
// list that is not the pinned identity's is refused there, before any proof is
// read, and never becomes a policy that could be applied by mistake.

package auditproof

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

// TrustChainErrorKind names why a key list was refused. The names match the
// Rust `ManifestError` variants, with LoadFailed for a list that does not parse
// as a key list at all.
type TrustChainErrorKind string

const (
	// TrustChainLoadFailed: the bytes are not a key list of the expected shape.
	TrustChainLoadFailed TrustChainErrorKind = "load_failed"
	// TrustChainMalformed: the identity public key is missing or unusable.
	TrustChainMalformed TrustChainErrorKind = "malformed"
	// TrustChainFingerprintMismatch: the identity key does not hash to both the
	// list's own fingerprint and the pinned one.
	TrustChainFingerprintMismatch TrustChainErrorKind = "fingerprint_mismatch"
	// TrustChainSignatureInvalid: the list's signature does not verify under
	// the identity key, strictly.
	TrustChainSignatureInvalid TrustChainErrorKind = "signature_invalid"
)

// The refusals of the hybrid key list, named as the Rust
// `ManifestError::kind` names them (trust_chain_hybrid.go).
const (
	TrustChainPqcIdentityMissing           TrustChainErrorKind = "pqc_identity_missing"
	TrustChainPqcAlgorithmUnsupported      TrustChainErrorKind = "pqc_algorithm_unsupported"
	TrustChainPqcSignatureMissing          TrustChainErrorKind = "pqc_signature_missing"
	TrustChainPqcSignatureInvalid          TrustChainErrorKind = "pqc_signature_invalid"
	TrustChainNonCanonicalEncoding         TrustChainErrorKind = "non_canonical_encoding"
	TrustChainKeyLabelUnknown              TrustChainErrorKind = "key_label_unknown"
	TrustChainRecordKeyLength              TrustChainErrorKind = "record_key_length"
	TrustChainVersionRepeated              TrustChainErrorKind = "version_repeated"
	TrustChainFingerprintNotOfKey          TrustChainErrorKind = "fingerprint_not_of_key"
	TrustChainPartnerMissing               TrustChainErrorKind = "partner_missing"
	TrustChainPartnerInvalid               TrustChainErrorKind = "partner_invalid"
	TrustChainPartnerShared                TrustChainErrorKind = "partner_shared"
	TrustChainKeyInTwoRoles                TrustChainErrorKind = "key_in_two_roles"
	TrustChainPartnerChanged               TrustChainErrorKind = "partner_changed"
	TrustChainPqcIdentityUnderClassicalPin TrustChainErrorKind = "pqc_identity_under_classical_pin"
	TrustChainAuthorityIDMalformed         TrustChainErrorKind = "authority_id_malformed"
	TrustChainByocAuthorityIDMalformed     TrustChainErrorKind = "byoc_authority_id_malformed"
	TrustChainByocAuthorityNeedsHybridPin  TrustChainErrorKind = "byoc_authority_needs_hybrid_pin"
	TrustChainByocAuthorityPinMismatch     TrustChainErrorKind = "byoc_authority_pin_mismatch"
	// TrustChainHybridCheckUnavailable: a hybrid1-sha256: pin was given to a
	// build without an ML-DSA check (Go before 1.27, or built with
	// GOFIPS140=certified or v1.0.0), which refuses every hybrid pin rather
	// than check one half.
	TrustChainHybridCheckUnavailable TrustChainErrorKind = "hybrid_check_unavailable"
)

// TrustChainError is the refusal of a key list. It is a setup error, not a
// verdict on a proof.
type TrustChainError struct {
	Kind TrustChainErrorKind
}

func (e *TrustChainError) Error() string {
	switch e.Kind {
	case TrustChainLoadFailed:
		return "trust-chain key list does not parse as a key list"
	case TrustChainMalformed:
		return "trust-chain key list is malformed (bad identity key)"
	case TrustChainFingerprintMismatch:
		return "trust-chain key list is not signed by the pinned identity (fingerprint mismatch)"
	case TrustChainSignatureInvalid:
		return "trust-chain key list signature is invalid"
	case TrustChainHybridCheckUnavailable:
		return "this build has no ML-DSA check, so it refuses every hybrid1-sha256: pin (build with Go 1.27 or later, without GOFIPS140=certified or v1.0.0)"
	default:
		return "trust-chain key list refused: " + string(e.Kind)
	}
}

type trustChainKey struct {
	version     string
	pubB64      string
	fingerprint string
	algorithm   *string
	partner     *string
}

type trustChainAuthority struct {
	active   []trustChainKey
	archived []trustChainKey
	revoked  bool
}

// TrustChain is a key list whose signature has been verified against a pinned
// identity fingerprint. It can only be made by LoadTrustChain.
type TrustChain struct {
	authorities map[string]trustChainAuthority
	pinned      string
	issuedAt    string
}

// PinnedIdentityFingerprint is the fingerprint the list was verified against.
func (t *TrustChain) PinnedIdentityFingerprint() string { return t.pinned }

// IssuedAt is the list's signed `issued_at`.
func (t *TrustChain) IssuedAt() string { return t.issuedAt }

// findKey looks in the authority's active versions first, then its archived
// ones, so a rotated-away version still resolves.
func (t *TrustChain) findKey(authorityID, version string) (trustChainKey, bool, bool) {
	a, ok := t.authorities[authorityID]
	if !ok {
		return trustChainKey{}, false, false
	}
	for _, k := range a.active {
		if k.version == version {
			return k, a.revoked, true
		}
	}
	for _, k := range a.archived {
		if k.version == version {
			return k, a.revoked, true
		}
	}
	return trustChainKey{}, false, false
}

// LoadTrustChain parses a signed key list and verifies it against
// pinnedFingerprint, obtained apart from the list. Every failure is a
// *TrustChainError.
//
// A `hybrid1-sha256:` pin runs the hybrid check
// (trust_chain_hybrid.go), or is refused with hybrid_check_unavailable by a
// build without ML-DSA. Any other pin runs the classical check: shape, then
// the identity key, then the fingerprint (`sha256:<hex of SHA-256 over the
// identity public key>`) against both the list's own claim and the pin, then
// the signature, as the Rust reference orders them; then the authority id
// rules and the refusal of post-quantum identity members.
func LoadTrustChain(keyList []byte, pinnedFingerprint string) (*TrustChain, error) {
	if isHybridPin(pinnedFingerprint) && !mldsaAvailable {
		return nil, &TrustChainError{Kind: TrustChainHybridCheckUnavailable}
	}
	var root map[string]interface{}
	if err := json.Unmarshal(keyList, &root); err != nil || root == nil {
		return nil, &TrustChainError{Kind: TrustChainLoadFailed}
	}
	parsed, ok := parseKeyList(root)
	if !ok {
		return nil, &TrustChainError{Kind: TrustChainLoadFailed}
	}
	if isHybridPin(pinnedFingerprint) {
		return loadHybrid(keyList, parsed, pinnedFingerprint)
	}

	pub, err := base64.StdEncoding.DecodeString(StripBase64Prefix(parsed.identityPublicKeyB64))
	if err != nil || len(pub) != Ed25519PublicKeySize {
		return nil, &TrustChainError{Kind: TrustChainMalformed}
	}

	digest := sha256.Sum256(pub)
	computed := "sha256:" + hex.EncodeToString(digest[:])
	if computed != parsed.identityFingerprint || computed != pinnedFingerprint {
		return nil, &TrustChainError{Kind: TrustChainFingerprintMismatch}
	}

	sig, err := base64.StdEncoding.DecodeString(StripBase64Prefix(parsed.manifestSignature))
	if err != nil || len(sig) != Ed25519SignatureSize {
		return nil, &TrustChainError{Kind: TrustChainSignatureInvalid}
	}
	payload, err := parsed.signedPayload()
	if err != nil {
		return nil, &TrustChainError{Kind: TrustChainMalformed}
	}
	// A key whose bytes are a second encoding of its point is refused, as is a
	// small-order key or R; verifyEd25519Strict covers both small-order cases.
	if isNonCanonicalEncoding(pub) || !verifyEd25519Strict(pub, payload, sig) {
		return nil, &TrustChainError{Kind: TrustChainSignatureInvalid}
	}
	if parsed.pqcIdentityAlgorithm != nil || parsed.pqcIdentityPublicKeyB64 != nil {
		return nil, &TrustChainError{Kind: TrustChainPqcIdentityUnderClassicalPin}
	}
	if err := checkAuthorityIDs(parsed.authorities, ""); err != nil {
		return nil, err
	}

	issuedAt, _ := parsed.signed["issued_at"].(string)
	return &TrustChain{authorities: parsed.authorities, pinned: pinnedFingerprint, issuedAt: issuedAt}, nil
}

type parsedKeyList struct {
	identityFingerprint     string
	identityPublicKeyB64    string
	manifestSignature       string
	pqcManifestSignature    *string
	pqcIdentityAlgorithm    *string
	pqcIdentityPublicKeyB64 *string
	authorities             map[string]trustChainAuthority
	// raw keeps the signed view: every field the reference reads, with the
	// reference's defaults filled in. Anything else in the document is not part
	// of what the signature covers.
	signed map[string]interface{}
}

// signedPayload is the RFC 8785 form of the list without its signature slots.
func (p *parsedKeyList) signedPayload() ([]byte, error) {
	raw, err := json.Marshal(p.signed)
	if err != nil {
		return nil, err
	}
	return JCSCanonicalize(raw)
}

func reqString(m map[string]interface{}, key string) (string, bool) {
	s, ok := m[key].(string)
	return s, ok
}

// optString reads a string or null; a present value of any other type is a
// parse failure, as it is for the reference's Option<String>.
func optString(m map[string]interface{}, key string) (*string, bool) {
	v, present := m[key]
	if !present || v == nil {
		return nil, true
	}
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	return &s, true
}

func parseKeyRecords(v interface{}) ([]trustChainKey, []interface{}, bool) {
	arr, ok := v.([]interface{})
	if !ok {
		return nil, nil, false
	}
	keys := make([]trustChainKey, 0, len(arr))
	signed := make([]interface{}, 0, len(arr))
	for _, e := range arr {
		rec, ok := e.(map[string]interface{})
		if !ok {
			return nil, nil, false
		}
		version, ok1 := reqString(rec, "signing_key_version")
		pubB64, ok2 := reqString(rec, "public_key_b64")
		fp, ok3 := reqString(rec, "public_key_fingerprint")
		from, ok4 := reqString(rec, "effective_from")
		archivedAt, ok5 := optString(rec, "archived_at")
		algorithm, ok6 := optString(rec, "algorithm")
		partner, ok7 := optString(rec, "pqc_partner_version")
		if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
			return nil, nil, false
		}
		view := map[string]interface{}{
			"signing_key_version":    version,
			"public_key_b64":         pubB64,
			"public_key_fingerprint": fp,
			"effective_from":         from,
		}
		if archivedAt != nil {
			view["archived_at"] = *archivedAt
		}
		if algorithm != nil {
			view["algorithm"] = *algorithm
		}
		if partner != nil {
			view["pqc_partner_version"] = *partner
		}
		keys = append(keys, trustChainKey{version: version, pubB64: pubB64, fingerprint: fp, algorithm: algorithm, partner: partner})
		signed = append(signed, view)
	}
	return keys, signed, true
}

func parseKeyList(root map[string]interface{}) (*parsedKeyList, bool) {
	schema, ok1 := reqString(root, "schema_version")
	issued, ok2 := reqString(root, "issued_at")
	fp, ok3 := reqString(root, "identity_fingerprint")
	sig, ok4 := reqString(root, "manifest_signature")
	if !(ok1 && ok2 && ok3 && ok4) {
		return nil, false
	}
	// The identity key may be absent (it then reads as empty and the list is
	// refused as malformed) but not another type.
	identityKey := ""
	if v, present := root["identity_public_key_b64"]; present {
		s, ok := v.(string)
		if !ok {
			return nil, false
		}
		identityKey = s
	}
	pqcSignature, ok := optString(root, "pqc_manifest_signature")
	if !ok {
		return nil, false
	}
	pqcAlgorithm, ok := optString(root, "pqc_identity_algorithm")
	if !ok {
		return nil, false
	}
	pqcKey, ok := optString(root, "pqc_identity_public_key_b64")
	if !ok {
		return nil, false
	}

	authRaw, ok := root["authorities"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	authorities := make(map[string]trustChainAuthority, len(authRaw))
	signedAuthorities := make(map[string]interface{}, len(authRaw))
	for id, rawRec := range authRaw {
		rec, ok := rawRec.(map[string]interface{})
		if !ok {
			return nil, false
		}
		display, ok := reqString(rec, "display_name")
		if !ok {
			return nil, false
		}
		active, activeView, ok := parseKeyRecords(rec["active_versions"])
		if !ok {
			return nil, false
		}
		archived, archivedView := []trustChainKey{}, []interface{}{}
		if v, present := rec["archived_versions"]; present {
			archived, archivedView, ok = parseKeyRecords(v)
			if !ok {
				return nil, false
			}
		}
		revoked := false
		if v, present := rec["revoked"]; present {
			revoked, ok = v.(bool)
			if !ok {
				return nil, false
			}
		}
		emitsHeads := false
		if v, present := rec["emits_population_heads"]; present {
			emitsHeads, ok = v.(bool)
			if !ok {
				return nil, false
			}
		}
		authorities[id] = trustChainAuthority{active: active, archived: archived, revoked: revoked}
		signedAuthority := map[string]interface{}{
			"display_name":      display,
			"active_versions":   activeView,
			"archived_versions": archivedView,
			"revoked":           revoked,
		}
		if emitsHeads {
			signedAuthority["emits_population_heads"] = true
		}
		signedAuthorities[id] = signedAuthority
	}

	signed := map[string]interface{}{
		"schema_version":          schema,
		"issued_at":               issued,
		"authorities":             signedAuthorities,
		"identity_fingerprint":    fp,
		"identity_public_key_b64": identityKey,
	}
	if pqcAlgorithm != nil {
		signed["pqc_identity_algorithm"] = *pqcAlgorithm
	}
	if pqcKey != nil {
		signed["pqc_identity_public_key_b64"] = *pqcKey
	}
	return &parsedKeyList{
		identityFingerprint:     fp,
		identityPublicKeyB64:    identityKey,
		manifestSignature:       sig,
		pqcManifestSignature:    pqcSignature,
		pqcIdentityAlgorithm:    pqcAlgorithm,
		pqcIdentityPublicKeyB64: pqcKey,
		authorities:             authorities,
		signed:                  signed,
	}, true
}

// anchorToTrustChain is stage 8: resolve the proof's (authority, key version) in
// the verified key list, check the signature against the listed key rather than
// the key the proof carries, and refuse a revoked authority. Mirrors
// `anchor_to_trust_chain` in the Rust library.
func anchorToTrustChain(proof map[string]interface{}, sigTree map[string]interface{}, cdpVersion string, chain *TrustChain, metadata VerificationMetadata) AuditProofVerificationResult {
	authorityID := effectiveAuthorityID(proof)
	version := ""
	if v, present := lookupPointer(proof, "attestation", "signing_key_version"); present {
		version, _ = v.(string)
	} else if v, present := proof["signing_key_version"]; present {
		version, _ = v.(string)
	}

	if pin := chain.PinnedIdentityFingerprint(); pin != "" {
		metadata.TrustChainIdentityFingerprint = strPtr(pin)
	}
	metadata.TrustChainIssuedAt = strPtr(chain.IssuedAt())

	key, revoked, found := chain.findKey(authorityID, version)
	if !found {
		return AuditProofVerificationResult{
			Valid:         false,
			FailureReason: &FailureReason{Type: ReasonSigningKeyVersionUnknown, Version: version},
			StageReached:  6,
			Metadata:      metadata,
		}
	}

	switch check := VerifySignatureAgainst(sigTree, cdpVersion, key.pubB64); check.Kind {
	case SignatureVerified:
	case SignatureFailed:
		return AuditProofVerificationResult{
			Valid:         false,
			FailureReason: &FailureReason{Type: ReasonSignatureMismatch, SigReason: check.Reason},
			StageReached:  7,
			Metadata:      metadata,
		}
	case SignatureUnsupported:
		return AuditProofVerificationResult{
			Valid:         false,
			FailureReason: &FailureReason{Type: ReasonAlgorithmUnsupported, Found: "signing_mode=" + check.Mode},
			StageReached:  7,
			Metadata:      metadata,
		}
	default:
		if underHybridPin(chain) {
			return hybridRecordRefusal(7, metadata)
		}
		return AuditProofVerificationResult{Valid: true, StageReached: 7, Metadata: metadata}
	}

	if revoked {
		return AuditProofVerificationResult{
			Valid:         false,
			FailureReason: &FailureReason{Type: ReasonAuthorityRevoked},
			StageReached:  8,
			Metadata:      metadata,
		}
	}
	// A 1.0 signature covers final_hash alone, which binds destroyed_at and the
	// two optional Merkle roots. It does not bind the capsule_id itself (only
	// through record receipts, which a holder can remove), the region or the
	// key id. So a key list cannot tie it to a capsule: a 1.0 proof runs the
	// lookup, the re-verify and the revocation check above as 2.x does, and
	// where 2.x would reach stage 8 it ends at stage 7, never anchored. Under a
	// hybrid pin it is refused there, as every record is. Mirrors Rust.
	if cdpVersion == "1.0" {
		if underHybridPin(chain) {
			return hybridRecordRefusal(7, metadata)
		}
		return AuditProofVerificationResult{Valid: true, StageReached: 7, Metadata: metadata}
	}
	// The hybrid-pin gate: under a hybrid pin a record is
	// anchored only with its ML-DSA-65 half checked, which this verifier does
	// not do yet.
	if underHybridPin(chain) {
		return hybridRecordRefusal(8, metadata)
	}
	return AuditProofVerificationResult{Valid: true, StageReached: 8, Metadata: metadata}
}

// underHybridPin reports whether a record checked against chain is refused
// for want of its ML-DSA-65 half. A key list always carries its pin here.
func underHybridPin(chain *TrustChain) bool {
	return chain != nil && isHybridPin(chain.PinnedIdentityFingerprint())
}

// hybridRecordRefusal is the refusal a record gets under a hybrid pin, at the
// stage where it would otherwise have ended valid, signed or unsigned.
func hybridRecordRefusal(stage uint8, metadata VerificationMetadata) AuditProofVerificationResult {
	return AuditProofVerificationResult{
		Valid:         false,
		FailureReason: &FailureReason{Type: ReasonAlgorithmUnsupported, Found: HybridRecordCheckMissing},
		StageReached:  stage,
		Metadata:      metadata,
	}
}

// lookupPointer walks a parsed tree and returns the terminal value of any type,
// and whether the path exists. A JSON null counts as present, as it does for
// serde_json::Value::pointer.
func lookupPointer(v interface{}, path ...string) (interface{}, bool) {
	cur := v
	for _, p := range path {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = obj[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
