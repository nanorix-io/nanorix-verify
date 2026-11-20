// ML-DSA (FIPS 204) signature verification, the primitive only.
//
// VerifyMLDSA checks one signature over one message with one public key, for
// ML-DSA-65 or ML-DSA-87. It is pure ML-DSA (not HashML-DSA) with an empty
// context string, the external ML-DSA.Verify of FIPS 204 Algorithm 3: the same
// contract as `verify_ml_dsa` in `tools/nanorix-verify/src/mldsa.rs`.
//
// A success says only that the signature is valid for that key and message. It
// says nothing about a record, a key list, a checkpoint, or whether the key is
// anchored to any authority: the caller decides what the key and the message
// are and what a valid signature means for them. Only the hybrid key list's
// ML-DSA-87 signature check (trust_chain_hybrid.go) calls it; no record or
// checkpoint verdict does.
//
// The check itself is built only by Go 1.27 or later, whose standard library
// has `crypto/mldsa` (mldsa_go127.go). A build by an older toolchain, or one
// using the FIPS 140-3 Go Cryptographic Module v1.0.0 (GOFIPS140=certified or
// GOFIPS140=v1.0.0, both of which add the build tag fips140v1.0 and make
// `crypto/mldsa` a stub that refuses every key), gets mldsa_fallback.go
// instead, which refuses every call with MLDSAAlgorithmUnsupported and never
// returns a success. GOFIPS140=inprocess and GOFIPS140=v1.26.0 build the real
// check, run on the frozen v1.26.0 module (golang.org/fips140@v1.26.0) rather
// than on the toolchain's own crypto/internal/fips140/mldsa.

package auditproof

import "fmt"

// MLDSAParameterSet names an ML-DSA parameter set VerifyMLDSA verifies.
type MLDSAParameterSet int

const (
	// MLDSA65 is ML-DSA-65 (FIPS 204 Table 1, security category 3).
	MLDSA65 MLDSAParameterSet = iota + 1
	// MLDSA87 is ML-DSA-87 (FIPS 204 Table 1, security category 5).
	MLDSA87
)

// PublicKeySize is the length in bytes of an encoded public key (FIPS 204
// Table 2), or 0 for a value that is not a parameter set this module verifies.
func (s MLDSAParameterSet) PublicKeySize() int {
	switch s {
	case MLDSA65:
		return 1952
	case MLDSA87:
		return 2592
	}
	return 0
}

// SignatureSize is the length in bytes of an encoded signature (FIPS 204
// Table 2), or 0 for a value that is not a parameter set this module verifies.
func (s MLDSAParameterSet) SignatureSize() int {
	switch s {
	case MLDSA65:
		return 3309
	case MLDSA87:
		return 4627
	}
	return 0
}

// String is the parameter set's name as FIPS 204 writes it, ML-DSA-65 or
// ML-DSA-87.
func (s MLDSAParameterSet) String() string {
	switch s {
	case MLDSA65:
		return "ML-DSA-65"
	case MLDSA87:
		return "ML-DSA-87"
	}
	return fmt.Sprintf("MLDSAParameterSet(%d)", int(s))
}

// MLDSAErrorKind says why VerifyMLDSA refused a signature.
type MLDSAErrorKind int

const (
	// MLDSAPublicKeyLength: the public key is not exactly the parameter set's
	// raw encoded length.
	MLDSAPublicKeyLength MLDSAErrorKind = iota + 1
	// MLDSASignatureLength: the signature is not exactly the parameter set's
	// encoded length.
	MLDSASignatureLength
	// MLDSAPublicKeyRejected: the library refused a public key of the right
	// length. Go's decoder checks only the length, so this is not expected; it
	// is kept so that an unexpected refusal is reported as a key refusal.
	MLDSAPublicKeyRejected
	// MLDSASignatureInvalid: the signature does not verify for this key and
	// message, or its encoding is not canonical.
	MLDSASignatureInvalid
	// MLDSAAlgorithmUnsupported: this build has no ML-DSA (a toolchain older
	// than Go 1.27, or GOFIPS140=certified or v1.0.0). Nothing was checked. A
	// caller whose verdict requires an ML-DSA signature must treat this as a
	// failure of that verdict, never as leave to skip the ML-DSA check.
	MLDSAAlgorithmUnsupported
	// MLDSAUnknownParameterSet: the parameter set is neither MLDSA65 nor
	// MLDSA87.
	MLDSAUnknownParameterSet
)

// MLDSAError is the error VerifyMLDSA returns, always as *MLDSAError.
type MLDSAError struct {
	Kind MLDSAErrorKind
	// ParameterSet is the parameter set the caller asked for.
	ParameterSet MLDSAParameterSet
	// Expected and Actual are the required and given lengths, set only for
	// MLDSAPublicKeyLength and MLDSASignatureLength.
	Expected, Actual int
}

func (e *MLDSAError) Error() string {
	switch e.Kind {
	case MLDSAPublicKeyLength:
		return fmt.Sprintf("%s public key must be %d bytes, got %d", e.ParameterSet, e.Expected, e.Actual)
	case MLDSASignatureLength:
		return fmt.Sprintf("%s signature must be %d bytes, got %d", e.ParameterSet, e.Expected, e.Actual)
	case MLDSAPublicKeyRejected:
		return fmt.Sprintf("%s public key was refused by the decoder", e.ParameterSet)
	case MLDSASignatureInvalid:
		return fmt.Sprintf("%s signature does not verify", e.ParameterSet)
	case MLDSAAlgorithmUnsupported:
		return fmt.Sprintf("%s is unsupported by this build: crypto/mldsa needs Go 1.27 or later, without GOFIPS140=certified or v1.0.0", e.ParameterSet)
	case MLDSAUnknownParameterSet:
		return fmt.Sprintf("%s is not a parameter set this verifier checks", e.ParameterSet)
	}
	return fmt.Sprintf("%s: ML-DSA error kind %d", e.ParameterSet, int(e.Kind))
}

// VerifyMLDSA verifies an ML-DSA signature over message with publicKey, pure
// ML-DSA with an empty context.
//
// A nil return means the signature is valid for this key and message under
// set, and nothing more: it is a primitive check that says nothing about a
// record, a key list, or whether the key is anchored.
//
// Every refusal is an *MLDSAError. MLDSAUnknownParameterSet comes first, for a
// set that is neither MLDSA65 nor MLDSA87; then MLDSAAlgorithmUnsupported on a
// build without ML-DSA; then MLDSAPublicKeyLength or MLDSASignatureLength when
// an input is not exactly the set's raw FIPS 204 length (key before signature,
// checked before the library is called); then MLDSASignatureInvalid when the
// signature does not verify or is not canonically encoded.
func VerifyMLDSA(set MLDSAParameterSet, publicKey, message, signature []byte) error {
	if set != MLDSA65 && set != MLDSA87 {
		return &MLDSAError{Kind: MLDSAUnknownParameterSet, ParameterSet: set}
	}
	return verifyMLDSA(set, publicKey, message, signature)
}

// checkMLDSALengths refuses a key or signature that is not exactly the set's
// raw encoded length, key first.
func checkMLDSALengths(set MLDSAParameterSet, publicKey, signature []byte) error {
	if len(publicKey) != set.PublicKeySize() {
		return &MLDSAError{Kind: MLDSAPublicKeyLength, ParameterSet: set, Expected: set.PublicKeySize(), Actual: len(publicKey)}
	}
	if len(signature) != set.SignatureSize() {
		return &MLDSAError{Kind: MLDSASignatureLength, ParameterSet: set, Expected: set.SignatureSize(), Actual: len(signature)}
	}
	return nil
}
