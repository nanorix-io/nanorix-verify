// ADR-056 — `customer_declared_activity_root`: recompute the customer's
// activity-record commitment from the raw record bytes and compare it with the
// root the proof carries. Go peer of `tools/nanorix-verify/src/customer_activity.rs`.
//
// What the root is: a capsule that opted in has the bytes of its activity
// buffer (`/data/activity_events.jsonl`, written by the customer's own SDK
// integrations) committed to one SHA-512 Merkle root at destroy. The proof
// carries the root only; the record goes back to the customer. Nanorix never
// parses, validates or interprets the record — the commitment is over bytes.
//
// The exact algorithm is pinned by
// `tools/nanorix-verify/fixtures/customer_declared_activity_root_vectors.json`,
// which `customer_activity_test.go` reads and checks vector by vector:
//
//  1. Split the buffer on 0x0A. Drop only a trailing empty segment, so a
//     buffer that ends in a newline and one that does not produce the same
//     lines. Nothing is trimmed: a leading space is content; an empty line in
//     the middle is a leaf.
//  2. Leaf = lowercase SHA-512 hex of the line's raw bytes.
//  3. Root = the ADR-039 null-separated Merkle root over the leaves in order
//     (MerkleRootSHA512NullSeparated — pairs hashed as
//     SHA-512(left_hex || 0x00 || right_hex), odd last node duplicated).
//  4. Zero lines = the genesis hash (SHA-512 of the empty string).
//  5. Wire form `sha512:<hex>`.
//
// The root is bound only where the signed message is the canonical view —
// cdp_version 2.1 and 2.2. A present, non-null root on any other version is
// rejected as unsigned_field_populated before the chain walk and is never
// reported as checked. On 2.1/2.2 the root must be a JSON string of `sha512:`
// + 128 lowercase hex (bare 128-hex accepted); anything else is
// field_malformed, also before the chain walk and before any recompute
// consumes it. The empty string is malformed rather than absent: the
// canonical view binds "" as a value.
//
// Three situations then follow for a verifier:
//   - record supplied, root present → recompute and compare;
//   - record supplied, root absent → required_field_missing (a record nothing
//     anchors is not evidence — the same fail-closed shape as a receipt set
//     without its root);
//   - root present, no record → disclosed as declared, not checked; not a
//     failure.

package auditproof

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
)

// CustomerDeclaredActivityRootField is the proof field that carries the root.
const CustomerDeclaredActivityRootField = "customer_declared_activity_root"

// The field_malformed reasons for the root — present but not a JSON string;
// the empty string; any other string that is not `sha512:` + 128 lowercase
// hex (bare 128-hex accepted). Pinned byte-for-byte with the Rust constants
// of the same names in tools/nanorix-verify/src/customer_activity.rs: the
// corpus compares the full failure_reason object, so a reason that differs by
// a character fails the sweep.
const (
	RootMalformedNotAString = "expected a JSON string"
	RootMalformedEmpty      = "empty string"
	RootMalformedShape      = "expected sha512: followed by 128 lowercase hex characters"
)

// VersionSignsActivityRoot reports whether cdpVersion signs the canonical
// view, which is the only place the root is bound. In 1.0 the signed message
// is final_hash and in 2.0 the document_hash field, so a root on either is a
// value anyone holding the document can write.
func VersionSignsActivityRoot(cdpVersion string) bool {
	return cdpVersion == "2.1" || cdpVersion == "2.2"
}

// DeclaresActivityRoot reports whether proof carries a root that is not JSON
// null. Absence and null are the same thing: no root declared.
func DeclaresActivityRoot(proof map[string]interface{}) bool {
	v, present := proof[CustomerDeclaredActivityRootField]
	return present && v != nil
}

// CheckDeclaredActivityRootShape is the shape check a present, non-null root
// must pass before anything reads it: a JSON string of `sha512:` + 128
// lowercase hex characters, or a bare 128-hex digest. Returns the string as
// written on success so the caller can report it verbatim.
func CheckDeclaredActivityRootShape(value interface{}) (string, *FailureReason) {
	malformed := func(reason string) *FailureReason {
		return &FailureReason{
			Type:   ReasonFieldMalformed,
			Field:  CustomerDeclaredActivityRootField,
			Reason: reason,
		}
	}
	root, ok := value.(string)
	if !ok {
		return "", malformed(RootMalformedNotAString)
	}
	if root == "" {
		return "", malformed(RootMalformedEmpty)
	}
	hexPart := StripHashPrefix(root)
	if len(hexPart) != 128 {
		return "", malformed(RootMalformedShape)
	}
	for i := 0; i < len(hexPart); i++ {
		b := hexPart[i]
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return "", malformed(RootMalformedShape)
		}
	}
	return root, nil
}

// GateDeclaredActivityRoot is the pre-chain-walk gate for a declared root:
// unsigned_field_populated on a version that does not sign it, field_malformed
// on a shape no signer emits, nil when no root is declared or the declared one
// is well-formed on a version that signs it. The version gate precedes the
// shape gate: a root the signature never covered is the more fundamental
// defect, whatever its shape. Shared with VerifyCustomerDeclaredActivity, so
// the two entry points cannot disagree about which roots are readable.
func GateDeclaredActivityRoot(proof map[string]interface{}, cdpVersion string) *FailureReason {
	if !DeclaresActivityRoot(proof) {
		return nil
	}
	if !VersionSignsActivityRoot(cdpVersion) {
		return &FailureReason{
			Type:  ReasonUnsignedFieldPopulated,
			Field: CustomerDeclaredActivityRootField,
		}
	}
	_, failure := CheckDeclaredActivityRootShape(proof[CustomerDeclaredActivityRootField])
	return failure
}

// SplitActivityLines splits an activity record into its lines: on 0x0A,
// dropping only a trailing empty segment. No trimming, no parsing.
func SplitActivityLines(record []byte) [][]byte {
	lines := bytes.Split(record, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// CustomerDeclaredActivityLeafHashes returns the lowercase SHA-512 hex of each
// line's raw bytes, in record order.
func CustomerDeclaredActivityLeafHashes(record []byte) []string {
	lines := SplitActivityLines(record)
	leaves := make([]string, 0, len(lines))
	for _, line := range lines {
		sum := sha512.Sum512(line)
		leaves = append(leaves, hex.EncodeToString(sum[:]))
	}
	return leaves
}

// ComputeCustomerDeclaredActivityRoot returns the root over a record in wire
// form `sha512:<hex>`. Zero lines yield the genesis hash.
func ComputeCustomerDeclaredActivityRoot(record []byte) string {
	leaves := CustomerDeclaredActivityLeafHashes(record)
	root, ok := MerkleRootSHA512NullSeparated(leaves)
	if !ok {
		root = NanorixGenesisHash
	}
	return "sha512:" + root
}

// DeclaredActivityRoot returns the root a proof declares, when it carries one
// as a string. JSON null is absent. A non-string value is also reported as
// absent here; GateDeclaredActivityRoot has already rejected it by the time
// the ladder reads the root, so this helper never sees one on a live path.
func DeclaredActivityRoot(proof map[string]interface{}) (string, bool) {
	root, ok := proof[CustomerDeclaredActivityRootField].(string)
	return root, ok
}

// VerifyCustomerDeclaredActivity recomputes the root from `record` and
// compares it with the one `proof` declares. Nil on agreement.
//
// A proof without the field fails closed when a record is offered: there is
// nothing the record can be checked against, and accepting it would let any
// file be presented as "the record" of a proof that never committed to one.
// A present root on a cdp_version that does not sign it (a missing or
// non-string cdp_version included) is unsigned_field_populated, and a
// malformed one is field_malformed — both before any recompute, never a
// mismatch against the record.
func VerifyCustomerDeclaredActivity(proof map[string]interface{}, record []byte) *FailureReason {
	cdpVersion, _ := proof["cdp_version"].(string)
	if failure := GateDeclaredActivityRoot(proof, cdpVersion); failure != nil {
		return failure
	}
	claimed, declared := DeclaredActivityRoot(proof)
	if !declared {
		return &FailureReason{
			Type:  ReasonRequiredFieldMissing,
			Field: CustomerDeclaredActivityRootField,
		}
	}
	computed := ComputeCustomerDeclaredActivityRoot(record)
	if StripHashPrefix(claimed) != StripHashPrefix(computed) {
		return &FailureReason{
			Type:     ReasonCustomerDeclaredActivityRootMismatch,
			Claimed:  claimed,
			Computed: computed,
		}
	}
	return nil
}
