// Canonical-hash recompute + Ed25519 signature verification — the Go mirror of
// the Rust verifiersrc/canonical_recompute.rs`.
//
// This is what makes stages 5-7 real. Reproducing the 8-step chain (stages 1-4)
// proves the chain is internally consistent; it says nothing about whether the
// document was signed. A forged proof carrying a chain it computed itself walks
// stages 1-4 perfectly. Only recomputing the signed message and checking the
// Ed25519 signature over it distinguishes a genuine AuditProof from a fabricated
// one.
//
// ## Which message is signed (mirrors the hosted verification endpoint)
//
//   - 1.0                    → final_hash (ASCII hex, prefix-stripped)
//   - 2.0                    → document_hash
//   - 2.1 + nanorix_only     → the recomputed the specification Part-3 canonical hash
//   - 2.1 + dual_signature   → not verifiable by this build → Absent
//   - 2.1 + tee_attested     → not verifiable by this build → Absent
//
// Recomputing the canonical hash from the document (rather than trusting the
// embedded `canonical_hash` field) is what catches canonical-view drift: a
// tampered `jurisdiction` / `org_id` / `capsule_id` never touches the 8-step
// chain, so it is invisible to stages 1-4 and shows up only here.
//
// ## Trust scope
//
// The signature is checked against the public key EMBEDDED in the proof. That
// proves INTEGRITY — the document has not been altered since it was signed — and
// is stage 7. It does NOT prove the key belongs to Nanorix; binding the key to a
// Nanorix-rooted trust anchor is the trust-chain manifest path (stage 8), which
// the Rust verifier implements via `VerifierPolicy::trust_chain` and this Go
// build does not yet carry.
//
// Forever-Standard discipline (the Forever-Standard wire discipline): the canonical view's field set,
// wire-name mapping, and the two server-side transforms (signing_key_version
// String → i64; the attestation subset) are part of the attestation contract.
// Any change here must keep the 100-fixture corpus at 100/100.

package auditproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

// unsupportedModeSentinel marks a signedMessage result as "this build cannot
// verify the declared signing_mode" rather than a message to sign over. The NUL
// prefix can never occur in a hex digest. Mirrors UNSUPPORTED_MODE_SENTINEL in
// the Rust verifier.
const unsupportedModeSentinel = "\x00unsupported-signing-mode:"

// SignatureCheckKind is the outcome of the signature stage (stages 5-7).
type SignatureCheckKind int

const (
	// SignatureVerified — the signature checked out against the embedded key
	// over the correct per-version message.
	SignatureVerified SignatureCheckKind = iota

	// SignatureAbsent — nothing to check: no signature or key present. The
	// caller keeps the honest stage-4 "chain verified, signature NOT checked"
	// verdict rather than claiming a verification it did not perform.
	SignatureAbsent

	// SignatureFailed — a signature was present and did not verify.
	SignatureFailed

	// SignatureUnsupported — the document declares a signing_mode this build
	// cannot verify. Distinct from SignatureAbsent on purpose: signing_mode is
	// inside the canonical hash and is attacker-controllable, so if an
	// unrecognised mode produced the same verdict as a missing signature,
	// flipping the field would convert a rejection into reassurance — a
	// downgrade oracle. Mirrors SignatureCheck::Unsupported in the Rust verifier.
	SignatureUnsupported
)

// SignatureCheck pairs the outcome with the closed-set reason on failure.
type SignatureCheck struct {
	Kind   SignatureCheckKind
	Reason SignatureFailureReason
	// Mode is set only for SignatureUnsupported: the signing_mode this build
	// cannot verify, surfaced as algorithm_unsupported{found:"signing_mode=..."}.
	Mode string
}

// RecomputeCanonicalHash rebuilds the specification Part-3 canonical view from a
// proof's JSON and returns its RFC-8785 JCS SHA-512 hex digest — byte-identical
// to the server's `FullCdp::canonical_hash()` and to the Rust verifier's
// `recompute_canonical_hash`. Lowercase 128-char hex, or empty string on the
// impossible JCS-serialize failure so the signature check fails closed.
//
// `proof` must be a tree parsed with `json.Decoder.UseNumber()` so numeric
// literals keep their source form; see canonicalProofTree.
func RecomputeCanonicalHash(proof map[string]interface{}) string {
	view := map[string]interface{}{}

	// Always-present scalars (FullCdp wire name → canonical-view key). An
	// absent key canonicalizes to null, matching serde's behaviour for a field
	// with no skip attribute.
	view["version"] = proof["cdp_version"]
	view["signing_mode"] = proof["signing_mode"]
	view["jurisdiction"] = proof["jurisdiction"]
	view["authority_id"] = proof["authority_id"]

	// signing_key_version: FullCdp stores a String; the canonical view emits an
	// integer (server parses; unparseable → 0).
	skv := int64(0)
	if s, ok := proof["signing_key_version"].(string); ok {
		if parsed, err := strconv.ParseInt(s, 10, 64); err == nil {
			skv = parsed
		}
	}
	view["signing_key_version"] = json.Number(strconv.FormatInt(skv, 10))

	view["capsule_id"] = proof["capsule_id"]

	// org_id defaults to "" on the server (#[serde(default)] String).
	if v, ok := proof["org_id"]; ok {
		view["org_id"] = v
	} else {
		view["org_id"] = ""
	}

	// skip_serializing_if = Option::is_none → OMIT when absent or null.
	insertIfPresent(view, "parent_audit_proof_id", proof)
	insertIfPresent(view, "cdp_kind", proof)

	// Arrays carried verbatim (canonical-view key differs from wire name).
	if v, ok := proof["activity"]; ok && v != nil {
		view["activity_trail"] = v
	} else {
		view["activity_trail"] = []interface{}{}
	}
	if v, ok := proof["chain"]; ok && v != nil {
		view["destruction_chain"] = v
	} else {
		view["destruction_chain"] = []interface{}{}
	}

	view["destruction_state"] = proof["destruction_state"]

	// No skip attribute → serialized as null when absent (NOT omitted).
	view["destruction_failure_step"] = proof["destruction_failure_step"]

	insertIfPresent(view, "parent_proofs_merkle_root", proof)
	insertIfPresent(view, "record_receipts_merkle_root", proof)

	// No skip attribute → null when absent.
	view["runtime_attestation"] = proof["runtime_attestation"]

	// attestation subset. An empty fingerprint canonicalizes to null, matching
	// the server's `if fingerprint.is_empty() { None }`.
	att := map[string]interface{}{
		"timestamp_attestation": proof["timestamp_attestation"],
	}
	if s, ok := proof["attestation_chain_fingerprint"].(string); ok && s != "" {
		att["attestation_chain_fingerprint"] = s
	} else {
		att["attestation_chain_fingerprint"] = nil
	}
	view["attestation"] = att

	view["hash_algorithm"] = proof["hash_algorithm"]
	view["signature_algorithm"] = proof["signature_algorithm"]

	var buf bytes.Buffer
	if err := jcsEmit(&buf, view); err != nil {
		// A map of JSON-derived values always serializes; on the impossible
		// failure return empty so the comparison fails closed.
		return ""
	}
	sum := sha512.Sum512(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func insertIfPresent(view map[string]interface{}, key string, proof map[string]interface{}) {
	if v, ok := proof[key]; ok && v != nil {
		view[key] = v
	}
}

// canonicalProofTree re-parses the raw document with UseNumber so numeric
// literals keep their exact source form through JCS. The verification ladder
// itself works on a conventional `json.Unmarshal` tree (float64 numbers); only
// the canonical recompute needs the number-preserving view, because there the
// bytes are the cryptographic message.
func canonicalProofTree(jsonBytes []byte) (map[string]interface{}, bool) {
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.UseNumber()
	var v map[string]interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

// signedMessage selects the message a proof's signature covers, by version and
// signing mode. Returns ok=false when this build cannot determine the message,
// which the caller reports as Absent rather than as a failure.
func signedMessage(proof map[string]interface{}, cdpVersion string) (string, bool) {
	signingMode := "nanorix_only"
	if s, ok := proof["signing_mode"].(string); ok {
		signingMode = s
	}

	switch cdpVersion {
	case "1.0":
		s, _ := proof["final_hash"].(string)
		return StripHashPrefix(s), true
	case "2.0":
		s, _ := proof["document_hash"].(string)
		return StripHashPrefix(s), true
	case "2.1":
		if signingMode == "nanorix_only" {
			return RecomputeCanonicalHash(proof), true
		}
		// Any other declared mode is one this build cannot verify. NOT the same
		// as "no signature" — signalled with a sentinel the callers translate
		// into SignatureUnsupported, keeping this function's (string, bool) shape.
		return unsupportedModeSentinel + signingMode, true
	default:
		return "", false
	}
}

// verifyMessageWithKey decodes the base64 Ed25519 signature + public key and
// verifies `message` under them.
//
// Failure-reason ordering mirrors the Rust verifier: the signature is decoded
// and length-checked BEFORE the public key, so a proof with both malformed
// reports `malformed`, not `public_key_malformed`.
//
// One documented boundary: ed25519-dalek rejects a structurally invalid
// 32-byte public key at parse time (→ public_key_malformed), while Go's
// standard library has no exported point-validation and reports the same input
// as `does_not_verify`. Both reject; only the sub-reason can differ, and only
// for a key that is 32 bytes but not a valid curve point. Closing that gap
// would require a third-party curve library, which this module deliberately
// does not carry (see go.mod).
func verifyMessageWithKey(message, sigB64, pubB64 string) SignatureCheck {
	sig, err := base64.StdEncoding.DecodeString(StripBase64Prefix(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return SignatureCheck{Kind: SignatureFailed, Reason: SigMalformed}
	}
	pub, err := base64.StdEncoding.DecodeString(StripBase64Prefix(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return SignatureCheck{Kind: SignatureFailed, Reason: SigPublicKeyMalformed}
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig) {
		return SignatureCheck{Kind: SignatureFailed, Reason: SigDoesNotVerify}
	}
	return SignatureCheck{Kind: SignatureVerified}
}

// embeddedSignature returns the proof's attestation signature, if present and
// non-empty.
func embeddedSignature(proof map[string]interface{}) (string, bool) {
	s := lookupStringPath(proof, "attestation", "signature")
	if s == nil || *s == "" {
		return "", false
	}
	return *s, true
}

// VerifySignature verifies the proof's signature against the public key
// EMBEDDED in its attestation. Proves integrity (not tampered since signing),
// not authenticity. Returns Absent when no signature/key is present or the
// version/mode is not signature-verifiable here.
func VerifySignature(proof map[string]interface{}, cdpVersion string) SignatureCheck {
	pub := lookupStringPath(proof, "attestation", "public_key")
	if pub == nil || *pub == "" {
		pub = lookupStringPath(proof, "attestation", "verification_key")
	}
	if pub == nil || *pub == "" {
		return SignatureCheck{Kind: SignatureAbsent}
	}
	sig, ok := embeddedSignature(proof)
	if !ok {
		return SignatureCheck{Kind: SignatureAbsent}
	}
	message, ok := signedMessage(proof, cdpVersion)
	if !ok {
		return SignatureCheck{Kind: SignatureAbsent}
	}
	if mode, found := strings.CutPrefix(message, unsupportedModeSentinel); found {
		return SignatureCheck{Kind: SignatureUnsupported, Mode: mode}
	}
	return verifyMessageWithKey(message, sig, *pub)
}

// VerifySignatureAgainst verifies the proof's signature against a caller-
// supplied public key rather than the embedded one — the shape the trust-chain
// (stage 8) path uses to reject a forged proof that carries its own key.
func VerifySignatureAgainst(proof map[string]interface{}, cdpVersion, pubB64 string) SignatureCheck {
	sig, ok := embeddedSignature(proof)
	if !ok {
		return SignatureCheck{Kind: SignatureAbsent}
	}
	message, ok := signedMessage(proof, cdpVersion)
	if !ok {
		return SignatureCheck{Kind: SignatureAbsent}
	}
	if mode, found := strings.CutPrefix(message, unsupportedModeSentinel); found {
		return SignatureCheck{Kind: SignatureUnsupported, Mode: mode}
	}
	return verifyMessageWithKey(message, sig, pubB64)
}

// ─────────────────────────────────────────────────────────────────────────────
// the chain-timestamp recovery rule — chain-timestamp recovery from attestation key_id
// ─────────────────────────────────────────────────────────────────────────────

// RecoverTimestampFromKeyID recovers the chain timestamp from an attestation
// `key_id`. Mirrors `nanorix_verify::recover_timestamp_from_key_id`.
//
// AuditProofs issued before the chain-timestamp recovery rule restored the document-level `destroyed_at`
// field carry the chain timestamp in exactly one place: the attestation
// `key_id`, built by the chain specification as
// `nrx-verify-{terminated_at with ':' replaced by '-'}-{capsule_id[..8]}`.
// Only the TIME portion ever held colons — the ISO-8601 date carries its own
// dashes — so restoration splits at `T` and rewrites dashes on the right-hand
// side only. Fractional seconds and the zone suffix pass through untouched.
//
// Returns ok=false unless the reconstruction has the exact ISO-8601
// `YYYY-MM-DDTHH:MM:SS` shape; this function never guesses.
//
// Recovering from an attacker-mutable field is sound because `key_id` is
// covered by NEITHER signed message, so the recovered value is never trusted on
// its own — it is an INPUT to the chain walk, and the chain hashes it must
// reproduce ARE signature-bound. Exactly one timestamp string reproduces a
// signed chain, so a mutated `key_id` yields a mismatch and a rejection, never
// a false accept.
func RecoverTimestampFromKeyID(keyID string) (string, bool) {
	const prefix = "nrx-verify-"
	if len(keyID) < len(prefix) || keyID[:len(prefix)] != prefix {
		return "", false
	}
	rest := keyID[len(prefix):]

	// Strip the trailing `-{capsule_id[..8]}` fragment. Capsule-id fragments
	// are hex, so the LAST dash is the delimiter.
	lastDash := -1
	for i := len(rest) - 1; i >= 0; i-- {
		if rest[i] == '-' {
			lastDash = i
			break
		}
	}
	if lastDash < 0 {
		return "", false
	}
	encoded, fragment := rest[:lastDash], rest[lastDash+1:]
	if fragment == "" {
		return "", false
	}

	tIdx := -1
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == 'T' {
			tIdx = i
			break
		}
	}
	if tIdx < 0 {
		return "", false
	}
	date, encodedTime := encoded[:tIdx], encoded[tIdx+1:]

	timePart := make([]byte, len(encodedTime))
	for i := 0; i < len(encodedTime); i++ {
		if encodedTime[i] == '-' {
			timePart[i] = ':'
		} else {
			timePart[i] = encodedTime[i]
		}
	}
	timeStr := string(timePart)

	if !isISO8601Shaped(date, timeStr) {
		return "", false
	}
	return date + "T" + timeStr, true
}

// isISO8601Shaped checks a `YYYY-MM-DD` date plus an `HH:MM:SS` time prefix.
// Anything after the seconds (fractional part, zone designator) is a free-form
// tail.
func isISO8601Shaped(date, timeStr string) bool {
	d, t := []byte(date), []byte(timeStr)
	if len(d) != 10 || len(t) < 8 {
		return false
	}
	if d[4] != '-' || d[7] != '-' {
		return false
	}
	for _, i := range [...]int{0, 1, 2, 3, 5, 6, 8, 9} {
		if d[i] < '0' || d[i] > '9' {
			return false
		}
	}
	if t[2] != ':' || t[5] != ':' {
		return false
	}
	for _, i := range [...]int{0, 1, 3, 4, 6, 7} {
		if t[i] < '0' || t[i] > '9' {
			return false
		}
	}
	return true
}

// resolveChainTimestamp resolves the timestamp every chain step hashes.
//
// Returns (timestamp, recovered) where `recovered` is non-nil only on the
// `key_id` recovery path — the caller records it in the verdict metadata so an
// auditor can always tell which route produced the result.
func resolveChainTimestamp(proof map[string]interface{}) (string, *string) {
	declared := stringOrEmpty(proof["destroyed_at"])
	if declared != "" {
		return declared, nil
	}
	keyID := lookupStringPath(proof, "attestation", "key_id")
	if keyID == nil {
		return declared, nil
	}
	ts, ok := RecoverTimestampFromKeyID(*keyID)
	if !ok {
		// No usable key_id — keep the pre-recovery behaviour exactly (an empty
		// timestamp, which fails the chain walk for any real proof).
		return declared, nil
	}
	return ts, strPtr(ts)
}
