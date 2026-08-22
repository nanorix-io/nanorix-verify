// Ed25519 signature verification for AuditProof attestations.
//
// **Canonical message format (Forever-Standard ADR-006 I0):** the Ed25519
// signature is computed over the **ASCII-hex encoding** of the final
// chain_hash (128 bytes), NOT the raw 64-byte SHA-512 digest. This is
// surprising but is the binding wire-form decision pinned at first ship.
//
// Cross-impl byte-equivalence: this Go implementation must verify every
// AuditProof signature that the Rust verifier accepts and reject every one
// the Rust verifier rejects. The reference corpus exercises both
// success-path and 5 failure-path (signature-mismatch) variants.

package auditproof

import (
	"crypto/ed25519"
	"encoding/base64"
)

// Ed25519PublicKeySize is the canonical Ed25519 public-key length (32 bytes).
const Ed25519PublicKeySize = ed25519.PublicKeySize

// Ed25519SignatureSize is the canonical Ed25519 signature length (64 bytes).
const Ed25519SignatureSize = ed25519.SignatureSize

// VerifyAttestationSignature verifies an Ed25519 signature against the
// AuditProof's chain_hash (in its canonical ASCII-hex form).
//
// Inputs:
//   - publicKeyB64: the AuditProof's `attestation.public_key` field, with the
//     "base64:" prefix already stripped (caller's responsibility) OR present.
//   - signatureB64: the AuditProof's `attestation.signature` field, prefix
//     stripped or present.
//   - chainHashHex: the AuditProof's last-step chain_hash, prefix stripped or
//     present. This is the 128-char ASCII-hex string; we pass its UTF-8 bytes
//     as the message Ed25519 was signed over.
//
// Returns:
//   - reason: the `SignatureFailureReason` if verification fails.
//   - ok: true iff Ed25519 verifies.
//
// Cross-impl byte-equivalent with the Rust verifier's signature-check stage.
func VerifyAttestationSignature(publicKeyB64, signatureB64, chainHashHex string) (SignatureFailureReason, bool) {
	pkRaw := StripBase64Prefix(publicKeyB64)
	sigRaw := StripBase64Prefix(signatureB64)
	hashAscii := StripHashPrefix(chainHashHex)

	pk, err := base64.StdEncoding.DecodeString(pkRaw)
	if err != nil || len(pk) != Ed25519PublicKeySize {
		return SigPublicKeyMalformed, false
	}

	sig, err := base64.StdEncoding.DecodeString(sigRaw)
	if err != nil || len(sig) != Ed25519SignatureSize {
		return SigMalformed, false
	}

	// Ed25519 message = the ASCII-hex bytes of the chain_hash (128 bytes).
	if !ed25519.Verify(ed25519.PublicKey(pk), []byte(hashAscii), sig) {
		return SigDoesNotVerify, false
	}
	return "", true
}
