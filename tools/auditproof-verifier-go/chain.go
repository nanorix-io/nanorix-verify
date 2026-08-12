// 8-step SHA-512 hash chain reproduction. Mirrors the Rust function
// the chain specification::assemble_cdp` algorithm and the verifier-side
// the Rust verifiersrc/lib.rs::compute_step_hash` reproduction.
//
// Forever-Standard discipline (the Forever-Standard wire discipline): the chain shape, the genesis hash,
// the per-subsystem method strings, the action constant ("destroy"), and the
// 0x00 separator are PERMANENT. They CANNOT change in any future Nanorix
// release without invalidating every prior AuditProof. This Go implementation
// is a peer of the Rust implementation and must produce byte-identical chain
// outputs for any input timestamp + subsystem sequence.
//
// Chain formula:
//   step_hash = SHA-512(prev_hash || 0x00 || subsystem || 0x00 ||
//                       "destroy"  || 0x00 || method    || 0x00 || timestamp)
//
// All inputs are interpreted as their UTF-8 byte representation; `prev_hash`
// is the lowercase-hex string of the prior step's SHA-512.
//
// Genesis: prev_hash for step 0 is SHA-512("") =
//   cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
//   47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e

package auditproof

import (
	"crypto/sha512"
	"encoding/hex"
)

// NanorixGenesisHash is SHA-512 of the empty string. Forever-stable cryptographic
// anchor; mirrors the Rust verifiersrc/lib.rs::NANORIX_GENESIS_HASH`.
const NanorixGenesisHash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

// NanorixChainSteps is the canonical chain step count (forever 8). Any
// AuditProof with != 8 steps is structurally invalid.
const NanorixChainSteps = 8

// ComputeStepHash reproduces one chain step's SHA-512 hash. Mirrors
// `nanorix_verify::compute_step_hash` byte-for-byte.
//
// Returns the lowercase-hex string of the SHA-512 digest (128 chars).
func ComputeStepHash(prevHash, subsystem, action, method, timestamp string) string {
	h := sha512.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{0x00})
	h.Write([]byte(subsystem))
	h.Write([]byte{0x00})
	h.Write([]byte(action))
	h.Write([]byte{0x00})
	h.Write([]byte(method))
	h.Write([]byte{0x00})
	h.Write([]byte(timestamp))
	return hex.EncodeToString(h.Sum(nil))
}

// LookupMethod returns the canonical method string for a given subsystem
// (per CLAUDE.md CDP v1.0 chain spec). Forever-stable per the Forever-Standard wire discipline.
//
// Returns the empty string for unknown subsystems — same convention as Rust.
func LookupMethod(subsystem string) string {
	switch subsystem {
	case "eee_namespace":
		return "procfs_verification"
	case "eee_tmpfs":
		return "mountinfo_verification"
	case "eee_memory":
		return "dod_5220_multipass_wipe"
	case "dire_keys":
		return "ed25519_key_destruction"
	case "dire_identity":
		return "credential_incineration"
	case "fgx_forensic":
		return "merkle_tree_verification"
	case "rzl_audit":
		return "hash_chain_validation"
	case "capsule_destroy":
		return "capsule_lifecycle_verification"
	default:
		return ""
	}
}

// StripHashPrefix removes the canonical "sha512:" prefix from hash fields.
// the specification forever-stable.
func StripHashPrefix(s string) string {
	const p = "sha512:"
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

// StripBase64Prefix removes the canonical "base64:" prefix from key/signature
// fields. the specification forever-stable.
func StripBase64Prefix(s string) string {
	const p = "base64:"
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}
