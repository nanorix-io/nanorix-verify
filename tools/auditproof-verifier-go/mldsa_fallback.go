//go:build !go1.27 || fips140v1.0

// The ML-DSA check on a build without crypto/mldsa: a toolchain older than
// Go 1.27, or GOFIPS140=certified or GOFIPS140=v1.0.0 (both add the build tag
// fips140v1.0). GOFIPS140=inprocess and GOFIPS140=v1.26.0 do not build this
// file: they build mldsa_go127.go on the frozen v1.26.0 module. See mldsa.go
// for the contract. Every call here is refused with MLDSAAlgorithmUnsupported,
// never accepted; a verdict that requires an ML-DSA signature fails on it
// rather than skipping the ML-DSA check.

package auditproof

func verifyMLDSA(set MLDSAParameterSet, _, _, _ []byte) error {
	return &MLDSAError{Kind: MLDSAAlgorithmUnsupported, ParameterSet: set}
}
