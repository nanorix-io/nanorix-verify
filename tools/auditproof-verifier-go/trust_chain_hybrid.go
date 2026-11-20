// The hybrid key list: an Ed25519 and an ML-DSA-87 identity, one `hybrid1-sha256:` pin over
// both, both list signatures, and the partner, role and authority id rules.
//
// Mirrors the hybrid branch of `TrustChainManifest::verify_signature` in
// `tools/nanorix-verify/src/trust_chain.rs`; the vectors under
// `tools/nanorix-verify/fixtures/trust_chain_hybrid/` hold this file to it
// (`trust_chain_hybrid_vectors_test.go`).

package auditproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

const (
	// HybridPinPrefix starts a hybrid identity pin.
	HybridPinPrefix = "hybrid1-sha256:"
	// KeyListPqcTag is the domain tag in front of the ML-DSA-87 list
	// signature's message.
	KeyListPqcTag = "nanorix-key-list-pqc-v1"
	// HybridRecordCheckMissing is the `found` text of the refusal every record
	// gets under a hybrid pin until this verifier checks the record's
	// ML-DSA-65 half. The shared vectors fix it.
	HybridRecordCheckMissing = "ML-DSA-65 record check (hybrid pin)"

	pqcIdentityAlgorithm = "ML-DSA-87"
	mlDsa65              = "ML-DSA-65"
	mlDsa65PublicKeySize = 1952
	mlDsa87PublicKeySize = 2592
	maxAuthorityIDLen    = 128
)

func isHybridPin(pin string) bool { return strings.HasPrefix(pin, HybridPinPrefix) }

// HybridPin is the pin of an identity: `hybrid1-sha256:` and the lowercase hex
// SHA-256 of `nanorix-identity-hybrid-v1` 0x00 `Ed25519` 0x00 <32 bytes> 0x00
// `ML-DSA-87` 0x00 <2592 bytes>.
func HybridPin(ed25519Identity, mldsa87Identity []byte) string {
	h := sha256.New()
	h.Write([]byte("nanorix-identity-hybrid-v1\x00Ed25519\x00"))
	h.Write(ed25519Identity)
	h.Write([]byte("\x00ML-DSA-87\x00"))
	h.Write(mldsa87Identity)
	return HybridPinPrefix + hex.EncodeToString(h.Sum(nil))
}

func refuse(kind TrustChainErrorKind) error { return &TrustChainError{Kind: kind} }

// strictDecode reads canonical standard padded base64 after an optional
// `base64:` prefix, refusing set trailing bits.
func strictDecode(text string) ([]byte, bool) {
	b, err := base64.StdEncoding.Strict().DecodeString(StripBase64Prefix(text))
	return b, err == nil
}

func loadHybrid(keyList []byte, parsed *parsedKeyList, pin string) (*TrustChain, error) {
	// encoding/json keeps the last copy of a repeated member, which no
	// signature then covers. The reference refuses a repeated member of any
	// key list object, the authority map's own keys aside.
	if hasRepeatedMember(keyList) {
		return nil, refuse(TrustChainLoadFailed)
	}
	edIdentity, ok := strictDecode(parsed.identityPublicKeyB64)
	if !ok || len(edIdentity) != Ed25519PublicKeySize {
		return nil, refuse(TrustChainMalformed)
	}
	if parsed.pqcIdentityAlgorithm == nil {
		return nil, refuse(TrustChainPqcIdentityMissing)
	}
	if *parsed.pqcIdentityAlgorithm != pqcIdentityAlgorithm {
		return nil, refuse(TrustChainPqcAlgorithmUnsupported)
	}
	if parsed.pqcIdentityPublicKeyB64 == nil {
		return nil, refuse(TrustChainPqcIdentityMissing)
	}
	mlIdentity, ok := strictDecode(*parsed.pqcIdentityPublicKeyB64)
	if !ok {
		return nil, refuse(TrustChainNonCanonicalEncoding)
	}
	if len(mlIdentity) != mlDsa87PublicKeySize {
		return nil, refuse(TrustChainMalformed)
	}
	computed := HybridPin(edIdentity, mlIdentity)
	if computed != parsed.identityFingerprint || computed != pin {
		return nil, refuse(TrustChainFingerprintMismatch)
	}

	sig, ok := strictDecode(parsed.manifestSignature)
	if !ok || len(sig) != Ed25519SignatureSize {
		return nil, refuse(TrustChainSignatureInvalid)
	}
	payload, err := parsed.signedPayload()
	if err != nil {
		return nil, refuse(TrustChainMalformed)
	}
	if isNonCanonicalEncoding(edIdentity) || !verifyEd25519Strict(edIdentity, payload, sig) {
		return nil, refuse(TrustChainSignatureInvalid)
	}
	if parsed.pqcManifestSignature == nil {
		return nil, refuse(TrustChainPqcSignatureMissing)
	}
	pqcSig, ok := strictDecode(*parsed.pqcManifestSignature)
	if !ok {
		return nil, refuse(TrustChainNonCanonicalEncoding)
	}
	message := append([]byte(KeyListPqcTag+"\x00"), payload...)
	if !verifyMLDSA87(mlIdentity, message, pqcSig) {
		return nil, refuse(TrustChainPqcSignatureInvalid)
	}

	if err := checkHybridRecords(parsed.authorities, [][]byte{edIdentity, mlIdentity}); err != nil {
		return nil, err
	}
	if err := checkAuthorityIDs(parsed.authorities, computed[len(HybridPinPrefix):]); err != nil {
		return nil, err
	}
	issuedAt, _ := parsed.signed["issued_at"].(string)
	return &TrustChain{authorities: parsed.authorities, pinned: pin, issuedAt: issuedAt}, nil
}

func sortedIDs(authorities map[string]trustChainAuthority) []string {
	ids := make([]string, 0, len(authorities))
	for id := range authorities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func algorithmOrDefault(k trustChainKey) string {
	if k.algorithm == nil {
		return "Ed25519"
	}
	return *k.algorithm
}

// versionNumber is a decimal version's value as digits without leading zeros,
// so "1" and "01" are one version.
func versionNumber(v string) (string, bool) {
	if v == "" {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return "", false
		}
	}
	return strings.TrimLeft(v, "0"), true
}

// checkHybridRecords applies the record rules under a hybrid pin, as
// `check_hybrid_records` in the Rust reference does, in the same order.
func checkHybridRecords(authorities map[string]trustChainAuthority, identityKeys [][]byte) error {
	seen := map[string]bool{}
	for _, k := range identityKeys {
		seen[string(k)] = true
	}
	for _, id := range sortedIDs(authorities) {
		a := authorities[id]
		records := append(append([]trustChainKey{}, a.active...), a.archived...)
		texts := map[string]bool{}
		numbers := map[string]bool{}
		algorithms := map[string]string{}
		for _, r := range records {
			length := 0
			switch {
			case r.algorithm == nil || *r.algorithm == "Ed25519":
				length = Ed25519PublicKeySize
			case *r.algorithm == mlDsa65:
				length = mlDsa65PublicKeySize
			default:
				return refuse(TrustChainKeyLabelUnknown)
			}
			key, ok := strictDecode(r.pubB64)
			if !ok {
				return refuse(TrustChainNonCanonicalEncoding)
			}
			if len(key) != length {
				return refuse(TrustChainRecordKeyLength)
			}
			digest := sha256.Sum256(key)
			if r.fingerprint != "sha256:"+hex.EncodeToString(digest[:]) {
				return refuse(TrustChainFingerprintNotOfKey)
			}
			repeated := texts[r.version]
			texts[r.version] = true
			if n, ok := versionNumber(r.version); ok {
				repeated = repeated || numbers[n]
				numbers[n] = true
			}
			if repeated {
				return refuse(TrustChainVersionRepeated)
			}
			if seen[string(key)] {
				return refuse(TrustChainKeyInTwoRoles)
			}
			seen[string(key)] = true
			algorithms[r.version] = algorithmOrDefault(r)
		}
		partners := map[string]bool{}
		for _, r := range records {
			if algorithmOrDefault(r) != "Ed25519" {
				if r.partner != nil {
					return refuse(TrustChainPartnerInvalid)
				}
				continue
			}
			if r.partner == nil {
				return refuse(TrustChainPartnerMissing)
			}
			if algorithms[*r.partner] != mlDsa65 {
				return refuse(TrustChainPartnerInvalid)
			}
			if partners[*r.partner] {
				return refuse(TrustChainPartnerShared)
			}
			partners[*r.partner] = true
		}
	}
	return nil
}

func isAuthorityIdentifier(s string) bool {
	if s == "" || len(s) > maxAuthorityIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// byocPinHex is the pin hex an authority id of BYOC form carries, when the id
// is exactly `<base>-hybrid1.<p>-v<n>`.
func byocPinHex(id string) (string, bool) {
	if strings.Count(id, "hybrid1") != 1 {
		return "", false
	}
	at := strings.Index(id, "-hybrid1.")
	if at <= 0 {
		return "", false
	}
	rest := id[at+len("-hybrid1."):]
	if len(rest) < 64+3 {
		return "", false
	}
	hexPart, suffix := rest[:64], rest[64:]
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	if !strings.HasPrefix(suffix, "-v") {
		return "", false
	}
	n := suffix[2:]
	if n == "" || n[0] == '0' {
		return "", false
	}
	for i := 0; i < len(n); i++ {
		if n[i] < '0' || n[i] > '9' {
			return "", false
		}
	}
	return hexPart, true
}

// checkAuthorityIDs applies the key list's authority id rules to each id in
// byte order, as the Rust reference does: the id alphabet under a hybrid pin
// only, then the BYOC form of an id containing hybrid1, then the pin's kind.
// pinHex is the hybrid pin's 64 hex digits, or "" under a classical pin.
func checkAuthorityIDs(authorities map[string]trustChainAuthority, pinHex string) error {
	for _, id := range sortedIDs(authorities) {
		if pinHex != "" && !isAuthorityIdentifier(id) {
			return refuse(TrustChainAuthorityIDMalformed)
		}
		carried, byoc := "", strings.Contains(id, "hybrid1")
		if byoc {
			var ok bool
			if carried, ok = byocPinHex(id); !ok {
				return refuse(TrustChainByocAuthorityIDMalformed)
			}
		}
		switch {
		case pinHex == "" && byoc:
			return refuse(TrustChainByocAuthorityNeedsHybridPin)
		case pinHex != "" && carried != pinHex:
			return refuse(TrustChainByocAuthorityPinMismatch)
		}
	}
	return nil
}

// PartnerRecord is an Ed25519 version's ML-DSA-65 partner.
type PartnerRecord struct {
	// Version is the partner's signing_key_version; a record's ML-DSA-65 key
	// id is "nrx-pqc-v" followed by it.
	Version string
	// PublicKeyB64 is the partner's ML-DSA-65 key as the list writes it.
	PublicKeyB64 string
}

// HybridPartner is the ML-DSA-65 partner the Ed25519 version names in the same
// authority. It means something only for a list loaded under a hybrid pin.
func (t *TrustChain) HybridPartner(authorityID, ed25519Version string) (PartnerRecord, bool) {
	ed, _, found := t.findKey(authorityID, ed25519Version)
	if !found || algorithmOrDefault(ed) != "Ed25519" || ed.partner == nil {
		return PartnerRecord{}, false
	}
	p, _, found := t.findKey(authorityID, *ed.partner)
	if !found || p.algorithm == nil || *p.algorithm != mlDsa65 {
		return PartnerRecord{}, false
	}
	return PartnerRecord{Version: p.version, PublicKeyB64: p.pubB64}, true
}

func decodedKey(b64 string) string {
	b, err := base64.StdEncoding.DecodeString(StripBase64Prefix(b64))
	if err != nil {
		return "\x00undecodable:" + b64
	}
	return string(b)
}

// ComparePartners compares two key lists from one identity, both loaded:
// every record of earlier must be in later
// under the same authority and version, algorithm and decoded key, and every
// partner earlier names must be named again with the same decoded key.
func ComparePartners(earlier, later *TrustChain) error {
	for _, id := range sortedIDs(earlier.authorities) {
		a := earlier.authorities[id]
		for _, r := range append(append([]trustChainKey{}, a.active...), a.archived...) {
			now, _, found := later.findKey(id, r.version)
			if !found || algorithmOrDefault(now) != algorithmOrDefault(r) || decodedKey(now.pubB64) != decodedKey(r.pubB64) {
				return refuse(TrustChainPartnerChanged)
			}
			if r.partner != nil {
				then, ok1 := earlier.HybridPartner(id, r.version)
				nowP, ok2 := later.HybridPartner(id, r.version)
				if !ok1 || !ok2 || decodedKey(then.PublicKeyB64) != decodedKey(nowP.PublicKeyB64) {
					return refuse(TrustChainPartnerChanged)
				}
			}
		}
	}
	return nil
}

// hasRepeatedMember reports whether any JSON object in data holds one member
// name twice, the authority map's own keys aside: the reference reads that
// map last-wins and every other object field by field, refusing a repeat.
func hasRepeatedMember(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	// walk reads one value. top is true for the document's root object;
	// authorityMap is true for the value of its "authorities" member.
	var walk func(top, authorityMap bool) bool
	walk = func(top, authorityMap bool) bool {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch tok {
		case json.Delim('{'):
			names := map[string]bool{}
			for dec.More() {
				t, err := dec.Token()
				if err != nil {
					return false
				}
				name, _ := t.(string)
				if names[name] && !authorityMap {
					return true
				}
				names[name] = true
				if walk(false, top && name == "authorities") {
					return true
				}
			}
			_, _ = dec.Token()
		case json.Delim('['):
			for dec.More() {
				if walk(false, false) {
					return true
				}
			}
			_, _ = dec.Token()
		}
		return false
	}
	return walk(true, false)
}

// mldsaAvailable reports whether this build checks ML-DSA. A build without
// crypto/mldsa (mldsa_fallback.go) refuses every call with
// MLDSAAlgorithmUnsupported, so such a build refuses every hybrid pin with
// hybrid_check_unavailable instead of checking one half of a hybrid key list.
var mldsaAvailable = func() bool {
	err := VerifyMLDSA(MLDSA87, make([]byte, MLDSA87.PublicKeySize()), nil, make([]byte, MLDSA87.SignatureSize()))
	e, ok := err.(*MLDSAError)
	return !(ok && e.Kind == MLDSAAlgorithmUnsupported)
}()

// verifyMLDSA87 checks the key list's ML-DSA-87 signature: pure ML-DSA with an
// empty context.
func verifyMLDSA87(publicKey, message, signature []byte) bool {
	return VerifyMLDSA(MLDSA87, publicKey, message, signature) == nil
}
