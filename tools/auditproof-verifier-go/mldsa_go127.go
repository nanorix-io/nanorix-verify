//go:build go1.27 && !fips140v1.0

// The ML-DSA check on Go 1.27 or later, with the standard library's
// crypto/mldsa. See mldsa.go for the contract.
//
// Strict decoding. The key and the signature must be exactly the parameter
// set's raw FIPS 204 lengths, checked here before the library is called. The
// Rust module wraps each key in its set's own SubjectPublicKeyInfo because its
// library reads a key as DER first; that concern does not apply here.
// crypto/mldsa's NewPublicKey takes the parameter set from the caller and reads
// only a raw key: it checks the length and keeps the bytes, with no DER parse
// (go1.27.0 src/crypto/mldsa/mldsa_fips140v1.26.go:158-180,
// src/crypto/internal/fips140/mldsa/mldsa.go:312-330, pkDecode :279-296). Its
// signature decoder refuses a hint section that is not canonical (a count
// above omega or decreasing, indices repeated or out of order, non-zero
// padding: hintDecode, mldsa.go:762-788) and a z outside the bound (the norm
// loop, mldsa.go:707-711), and reports them the same way as a signature that
// does not verify, so this file does too.
//
// Under GOFIPS140=inprocess or v1.26.0 the same calls run on the frozen
// golang.org/fips140@v1.26.0 module. Its mldsa.go has the same pkDecode,
// sigDecode, hintDecode and norm loop as go1.27.0's; it differs only in
// computing the key's matrix when the key is parsed rather than at Verify.

package auditproof

import "crypto/mldsa"

func verifyMLDSA(set MLDSAParameterSet, publicKey, message, signature []byte) error {
	if err := checkMLDSALengths(set, publicKey, signature); err != nil {
		return err
	}
	return verifyMLDSAWithLibrary(set, publicKey, message, signature)
}

// verifyMLDSAWithLibrary is the library call alone, after the length checks.
// Any refusal by the library is an error here, never a success.
func verifyMLDSAWithLibrary(set MLDSAParameterSet, publicKey, message, signature []byte) error {
	var params mldsa.Parameters
	switch set {
	case MLDSA65:
		params = mldsa.MLDSA65()
	case MLDSA87:
		params = mldsa.MLDSA87()
	default:
		return &MLDSAError{Kind: MLDSAUnknownParameterSet, ParameterSet: set}
	}
	key, err := mldsa.NewPublicKey(params, publicKey)
	if err != nil {
		return &MLDSAError{Kind: MLDSAPublicKeyRejected, ParameterSet: set}
	}
	if err := mldsa.Verify(key, message, signature, nil); err != nil {
		return &MLDSAError{Kind: MLDSASignatureInvalid, ParameterSet: set}
	}
	return nil
}
