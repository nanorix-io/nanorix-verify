//go:build !go1.27 || fips140v1.0

package auditproof

import (
	"bytes"
	"errors"
	"testing"
)

// On a build without crypto/mldsa every call is refused as unsupported, even
// one whose key and signature have the right lengths.
func TestMLDSAFallbackRefusesAsUnsupported(t *testing.T) {
	for _, set := range []MLDSAParameterSet{MLDSA65, MLDSA87} {
		key := bytes.Repeat([]byte{1}, set.PublicKeySize())
		sig := bytes.Repeat([]byte{1}, set.SignatureSize())
		for _, in := range []struct{ key, sig []byte }{{key, sig}, {nil, nil}, {key[1:], sig}} {
			err := VerifyMLDSA(set, in.key, []byte("message"), in.sig)
			var got *MLDSAError
			if !errors.As(err, &got) || *got != (MLDSAError{Kind: MLDSAAlgorithmUnsupported, ParameterSet: set}) {
				t.Errorf("%s: want algorithm unsupported, got %v", set, err)
			}
		}
	}
	err := VerifyMLDSA(0, nil, nil, nil)
	var got *MLDSAError
	if !errors.As(err, &got) || got.Kind != MLDSAUnknownParameterSet {
		t.Errorf("unknown set: got %v", err)
	}
}
