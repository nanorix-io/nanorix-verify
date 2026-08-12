// Portable Pubkey Bundle (.ppb.json) — Wave B Item 8 surface, Go port.
//
// Mirrors the Rust verifiersrc/pubkey_bundle.rs` byte-for-byte.
// Cross-impl byte-equivalence with Rust/Python/TypeScript bundle JSON on the
// canonical reference vectors.
//
// Per feedback_open_verifier_bounded_manifest.md: the bundle algorithm is
// open + portable; the trust root (publisher pubkey) is bounded out-of-band.

package auditproof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PortablePubkeyBundleDisclaimer — factual language only. Vocabulary
// discipline forbids COMPLIANT, SATISFIED, PASSED, MEETS.
const PortablePubkeyBundleDisclaimer = "This Portable Pubkey Bundle is a key-discovery aid for cross-org chain verification. The bundle_signature confirms publisher integrity. The bundle issuer attests that the listed pubkeys were valid as of generated_at; subsequent key rotation or revocation MUST be verified out-of-band by the consuming party."

// PortablePubkeyBundle — Wave B Item 8 wire shape.
type PortablePubkeyBundle struct {
	BundleVersion      string          `json:"bundle_version"`
	BundleType         string          `json:"bundle_type"`
	GeneratedAt        string          `json:"generated_at"`
	IssuerOrganization string          `json:"issuer_organization"`
	Pubkeys            []PubKeyEntry   `json:"pubkeys"`
	BundleSignature    PubkeyBundleSig `json:"bundle_signature"`
	Disclaimer         string          `json:"disclaimer"`
}

// PubKeyEntry — single pubkey entry within a Portable Pubkey Bundle.
type PubKeyEntry struct {
	KeyID       string  `json:"key_id"`
	Algorithm   string  `json:"algorithm"`
	PublicKey   string  `json:"public_key"`
	ValidFrom   string  `json:"valid_from"`
	ValidUntil  *string `json:"valid_until,omitempty"`
	IssuedByOrg string  `json:"issued_by_org"`
}

// PubkeyBundleSig — bundle self-signature.
type PubkeyBundleSig struct {
	Algorithm     string `json:"algorithm"`
	SignedByKeyID string `json:"signed_by_key_id"`
	Signature     string `json:"signature"`
}

// PubkeyBundleError — typed error for pubkey bundle operations.
type PubkeyBundleError struct {
	Kind   string
	Reason string
}

func (e *PubkeyBundleError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("pubkey bundle error: %s", e.Kind)
	}
	return fmt.Sprintf("pubkey bundle error [%s]: %s", e.Kind, e.Reason)
}

// Pubkey bundle error kinds.
const (
	PubkeyBundleErrUnsupportedVersion    = "unsupported_version"
	PubkeyBundleErrWrongBundleType       = "wrong_bundle_type"
	PubkeyBundleErrBundleSignatureFailed = "bundle_signature_failed"
	PubkeyBundleErrInvalidPublisherKey   = "invalid_publisher_key"
	PubkeyBundleErrBase64Decode          = "base64_decode"
	PubkeyBundleErrCanonicalization      = "canonicalization"
	PubkeyBundleErrInvalidEntry          = "invalid_entry"
	PubkeyBundleErrEmptyBundle           = "empty_bundle"
)

// BuildPubkeyBundle constructs and signs a Portable Pubkey Bundle.
//
// The bundle is self-signed using signerKey. Publishers distribute the bundle
// out-of-band; consumers verify via VerifyPubkeyBundle using the publisher's
// pubkey delivered through trust-chain manifest / direct override.
func BuildPubkeyBundle(keys []PubKeyEntry, signerKey ed25519.PrivateKey, signerKeyID, issuerOrg string) (*PortablePubkeyBundle, error) {
	if len(keys) == 0 {
		return nil, &PubkeyBundleError{Kind: PubkeyBundleErrEmptyBundle}
	}
	for i := range keys {
		if err := validateEntry(&keys[i], i); err != nil {
			return nil, err
		}
	}
	if len(signerKey) != ed25519.PrivateKeySize {
		return nil, &PubkeyBundleError{Kind: PubkeyBundleErrInvalidPublisherKey, Reason: fmt.Sprintf("signer_key wrong size: %d", len(signerKey))}
	}

	bundle := &PortablePubkeyBundle{
		BundleVersion:      "1.0",
		BundleType:         "pubkey",
		GeneratedAt:        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		IssuerOrganization: issuerOrg,
		Pubkeys:            keys,
		BundleSignature: PubkeyBundleSig{
			Algorithm:     "Ed25519",
			SignedByKeyID: signerKeyID,
			Signature:     "",
		},
		Disclaimer: PortablePubkeyBundleDisclaimer,
	}

	canonical, err := canonicalBytesForSigning(bundle)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(signerKey, canonical)
	bundle.BundleSignature.Signature = base64.StdEncoding.EncodeToString(sig)
	return bundle, nil
}

// VerifyPubkeyBundle verifies a Portable Pubkey Bundle's publisher signature.
//
// publisherPubkey is the trust anchor; it MUST be delivered out-of-band.
// The bundle's bundle_signature.signed_by_key_id MUST match the consumer's
// expected publisher identity — verified at the application layer.
func VerifyPubkeyBundle(bundle *PortablePubkeyBundle, publisherPubkey ed25519.PublicKey) error {
	if bundle.BundleVersion != "1.0" {
		return &PubkeyBundleError{Kind: PubkeyBundleErrUnsupportedVersion, Reason: bundle.BundleVersion}
	}
	if bundle.BundleType != "pubkey" {
		return &PubkeyBundleError{Kind: PubkeyBundleErrWrongBundleType, Reason: bundle.BundleType}
	}
	if len(bundle.Pubkeys) == 0 {
		return &PubkeyBundleError{Kind: PubkeyBundleErrEmptyBundle}
	}
	for i := range bundle.Pubkeys {
		if err := validateEntry(&bundle.Pubkeys[i], i); err != nil {
			return err
		}
	}
	if len(publisherPubkey) != ed25519.PublicKeySize {
		return &PubkeyBundleError{Kind: PubkeyBundleErrInvalidPublisherKey, Reason: fmt.Sprintf("size %d", len(publisherPubkey))}
	}

	sig, err := base64.StdEncoding.DecodeString(StripBase64Prefix(bundle.BundleSignature.Signature))
	if err != nil {
		return &PubkeyBundleError{Kind: PubkeyBundleErrBase64Decode, Reason: "bundle_signature.signature: " + err.Error()}
	}
	if len(sig) != ed25519.SignatureSize {
		return &PubkeyBundleError{Kind: PubkeyBundleErrBundleSignatureFailed, Reason: fmt.Sprintf("sig wrong size: %d", len(sig))}
	}

	// Canonicalize with cleared signature.
	clone := *bundle
	clone.BundleSignature.Signature = ""
	canonical, err := canonicalBytesForSigning(&clone)
	if err != nil {
		return err
	}

	if !ed25519.Verify(publisherPubkey, canonical, sig) {
		return &PubkeyBundleError{Kind: PubkeyBundleErrBundleSignatureFailed}
	}
	return nil
}

// ResolveParentKey looks up a pubkey by key_id with validity-window check.
//
// Returns the pubkey entry whose key_id matches AND whose validity window
// contains atTimestamp. Returns nil if no matching entry is found.
//
// Note: "outside validity window" does NOT mean "untrusted for historical
// verification". Use ResolveParentKeyForever for historical AuditProofs.
func ResolveParentKey(bundle *PortablePubkeyBundle, keyID string, atTimestamp time.Time) *PubKeyEntry {
	for i := range bundle.Pubkeys {
		entry := &bundle.Pubkeys[i]
		if entry.KeyID != keyID {
			continue
		}
		validFrom, err := time.Parse(time.RFC3339, entry.ValidFrom)
		if err != nil {
			continue
		}
		if atTimestamp.Before(validFrom) {
			continue
		}
		if entry.ValidUntil != nil {
			validUntil, err := time.Parse(time.RFC3339, *entry.ValidUntil)
			if err != nil {
				continue
			}
			if atTimestamp.After(validUntil) {
				continue
			}
		}
		return entry
	}
	return nil
}

// ResolveParentKeyForever looks up a pubkey by key_id regardless of validity
// window. Used for historical AuditProof verification (forever-archive).
// Returns the first matching key_id.
func ResolveParentKeyForever(bundle *PortablePubkeyBundle, keyID string) *PubKeyEntry {
	for i := range bundle.Pubkeys {
		if bundle.Pubkeys[i].KeyID == keyID {
			return &bundle.Pubkeys[i]
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

func validateEntry(entry *PubKeyEntry, idx int) error {
	if entry.Algorithm != "Ed25519" {
		return &PubkeyBundleError{Kind: PubkeyBundleErrInvalidEntry, Reason: fmt.Sprintf("idx %d: unsupported algorithm %s", idx, entry.Algorithm)}
	}
	pubBytes, err := base64.StdEncoding.DecodeString(StripBase64Prefix(entry.PublicKey))
	if err != nil {
		return &PubkeyBundleError{Kind: PubkeyBundleErrInvalidEntry, Reason: fmt.Sprintf("idx %d: base64 decode: %v", idx, err)}
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return &PubkeyBundleError{Kind: PubkeyBundleErrInvalidEntry, Reason: fmt.Sprintf("idx %d: public_key wrong size %d", idx, len(pubBytes))}
	}
	if strings.TrimSpace(entry.KeyID) == "" {
		return &PubkeyBundleError{Kind: PubkeyBundleErrInvalidEntry, Reason: fmt.Sprintf("idx %d: key_id empty", idx)}
	}
	return nil
}

func canonicalBytesForSigning(bundle *PortablePubkeyBundle) ([]byte, error) {
	// Clear the signature field for deterministic canonicalization.
	clone := *bundle
	clone.BundleSignature.Signature = ""
	jsonBytes, err := json.Marshal(&clone)
	if err != nil {
		return nil, &PubkeyBundleError{Kind: PubkeyBundleErrCanonicalization, Reason: err.Error()}
	}
	canonical, err := JCSCanonicalize(jsonBytes)
	if err != nil {
		return nil, &PubkeyBundleError{Kind: PubkeyBundleErrCanonicalization, Reason: err.Error()}
	}
	return canonical, nil
}

// Static error sentinel.
var ErrPubkeyBundleEmpty = errors.New("pubkey bundle: empty")
