//! Transparency-checkpoint core — the ADR-045/049 anchoring primitive.
//!
//! An append-only SHA-512 Merkle tree over AuditProof leaves, published as
//! periodic signed checkpoints and mirrored externally. Purpose (ADR-049 D3.4):
//! a proof anchored before a cryptographically relevant quantum computer
//! exists stays forgery-evident forever, because detection rests only on hash
//! security and public history — not on any signature key.
//!
//! Spec decisions carried from adversarial review (ADR-049 D3.4, ADR-051 §D.1):
//!
//! - **Leaf** = SHA-512 over `final_hash_raw` + the attestation-envelope
//!   digest — never over full proof JSON (which can embed customer-supplied
//!   metadata; EDPB ledger guidance would make such leaves presumptively
//!   personal data). The envelope digest covers algorithm identifiers, key id,
//!   signature bytes and the `pqc_signature` field, so stripping or swapping
//!   any of them breaks anchor inclusion.
//! - **Domain separation** is RFC 6962-shaped: `H(0x00 ‖ leaf-input)` for
//!   leaves, `H(0x01 ‖ left ‖ right)` for interior nodes, with SHA-512 as the
//!   hash. Odd sizes split at the largest power of two below `n` (no
//!   leaf duplication).
//! - **Checkpoints** carry tree size, epoch, root, previous root, and the
//!   hash algorithm; consecutive checkpoints are linked by consistency
//!   proofs. The publisher signs the checkpoint (Ed25519 today, dual-signed
//!   at ADR-049 Phase 1); signing lives with the publisher — this module is
//!   the deterministic core both publisher and verifiers share.
//!
//! Inclusion and consistency verification follow the RFC 9162 algorithms,
//! instantiated with SHA-512.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// A SHA-512 digest.
pub type Digest64 = [u8; 64];

/// The attestation-envelope fields a leaf binds (ADR-051 §D.1). All values are
/// the wire strings exactly as they appear in the proof document; `None` for
/// `pqc_signature` is the pre-PQC era and digests as the empty string, so
/// filling the field at Phase 1 changes the leaf — stripping it is
/// anchor-detectable.
#[derive(Debug, Clone, Default)]
pub struct AttestationEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
    pub pqc_signature: Option<String>,
}

impl AttestationEnvelope {
    /// SHA-512 over the `\x00`-separated envelope fields, lowercase hex.
    /// Field values are base64/hex/identifier ASCII and never contain NUL —
    /// the same separator contract as the CDP chain itself.
    pub fn digest_hex(&self) -> String {
        let mut h = Sha512::new();
        for (i, part) in [
            self.algorithm.as_str(),
            self.key_id.as_str(),
            self.public_key.as_str(),
            self.signature.as_str(),
            self.pqc_signature.as_deref().unwrap_or(""),
        ]
        .iter()
        .enumerate()
        {
            if i > 0 {
                h.update([0u8]);
            }
            h.update(part.as_bytes());
        }
        hex(&h.finalize().into())
    }
}

/// Leaf hash: `SHA-512(0x00 ‖ final_hash_raw ‖ 0x00 ‖ envelope_digest_hex)`.
///
/// `final_hash_raw` is the proof's final chain hash as the 128-char ASCII-hex
/// string WITHOUT the `sha512:` prefix (the same wire form Ed25519 signs).
pub fn leaf_hash(final_hash_raw: &str, envelope: &AttestationEnvelope) -> Digest64 {
    let mut h = Sha512::new();
    h.update([0u8]);
    h.update(final_hash_raw.as_bytes());
    h.update([0u8]);
    h.update(envelope.digest_hex().as_bytes());
    h.finalize().into()
}

fn node_hash(left: &Digest64, right: &Digest64) -> Digest64 {
    let mut h = Sha512::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (n >= 2).
fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle tree head over leaf hashes. The empty tree is `SHA-512("")` —
/// the same genesis value the CDP chain uses.
pub fn merkle_root(leaves: &[Digest64]) -> Digest64 {
    match leaves.len() {
        0 => Sha512::digest(b"").into(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// RFC 6962 `PATH(m, D[n])` — the inclusion audit path for leaf `index`.
pub fn inclusion_proof(leaves: &[Digest64], index: usize) -> Option<Vec<Digest64>> {
    if index >= leaves.len() {
        return None;
    }
    fn path(leaves: &[Digest64], m: usize) -> Vec<Digest64> {
        let n = leaves.len();
        if n <= 1 {
            return Vec::new();
        }
        let k = split_point(n);
        if m < k {
            let mut p = path(&leaves[..k], m);
            p.push(merkle_root(&leaves[k..]));
            p
        } else {
            let mut p = path(&leaves[k..], m - k);
            p.push(merkle_root(&leaves[..k]));
            p
        }
    }
    Some(path(leaves, index))
}

/// RFC 9162 §2.1.3.2 inclusion verification, SHA-512 instantiation.
pub fn verify_inclusion(
    leaf: &Digest64,
    index: u64,
    tree_size: u64,
    proof: &[Digest64],
    root: &Digest64,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let mut fnode = index;
    let mut snode = tree_size - 1;
    let mut r = *leaf;
    for p in proof {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

/// RFC 6962 `PROOF(m, D[n])` — consistency proof from the `old_size`-leaf tree
/// to the current tree.
pub fn consistency_proof(leaves: &[Digest64], old_size: usize) -> Option<Vec<Digest64>> {
    let n = leaves.len();
    if old_size == 0 || old_size > n {
        return None;
    }
    fn subproof(leaves: &[Digest64], m: usize, complete: bool) -> Vec<Digest64> {
        let n = leaves.len();
        if m == n {
            if complete {
                return Vec::new();
            }
            return vec![merkle_root(leaves)];
        }
        let k = split_point(n);
        if m <= k {
            let mut p = subproof(&leaves[..k], m, complete);
            p.push(merkle_root(&leaves[k..]));
            p
        } else {
            let mut p = subproof(&leaves[k..], m - k, false);
            p.push(merkle_root(&leaves[..k]));
            p
        }
    }
    Some(subproof(leaves, old_size, true))
}

/// RFC 9162 §2.1.4.2 consistency verification, SHA-512 instantiation.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &Digest64,
    new_root: &Digest64,
    proof: &[Digest64],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    // old_size < new_size: a non-empty proof is required.
    let mut proof_iter = proof.iter();
    let (mut fr, mut sr) = if old_size.is_power_of_two() {
        (*old_root, *old_root)
    } else {
        match proof_iter.next() {
            Some(first) => (*first, *first),
            None => return false,
        }
    };
    let mut fnode = old_size - 1;
    let mut snode = new_size - 1;
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    for p in proof_iter {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(p, &fr);
            sr = node_hash(p, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && fr == *old_root && sr == *new_root
}

/// One published checkpoint — the signed tree head. The publisher fills
/// `signature` (Ed25519 over `signed_payload()`; dual-signed at ADR-049
/// Phase 1 via the reserved field). This module keeps the payload contract;
/// key custody and signing live with the publisher.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Checkpoint {
    /// Schema version. V1 = `"1"`; additive evolution only.
    pub checkpoint_version: String,
    /// Hash algorithm identifier — always `"sha512"` in V1; explicit so the
    /// format carries algorithm agility from day one (ADR-051 discipline).
    pub hash_algorithm: String,
    /// Number of leaves in the tree at this checkpoint.
    pub tree_size: u64,
    /// Merkle root, `sha512:`-prefixed lowercase hex.
    pub root_hash: String,
    /// Previous checkpoint's root, `sha512:`-prefixed. The empty-tree root
    /// for the first checkpoint.
    pub prev_root_hash: String,
    /// When this checkpoint was issued. RFC 3339 UTC; supplied by the
    /// publisher.
    pub issued_at: String,
    /// Publisher's Ed25519 signature over `signed_payload()`, `base64:`
    /// prefixed. Empty until signed.
    #[serde(default)]
    pub signature: String,
    /// Reserved for the ADR-049 Phase 1 post-quantum dual signature over the
    /// same payload. Absent until then (byte-compat discipline, mirroring the
    /// trust-chain manifest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_signature: Option<String>,
}

impl Checkpoint {
    /// Assemble an unsigned checkpoint for the given tree state.
    pub fn assemble(leaves: &[Digest64], prev_root_hash: &str, issued_at: &str) -> Checkpoint {
        Checkpoint {
            checkpoint_version: "1".to_string(),
            hash_algorithm: "sha512".to_string(),
            tree_size: leaves.len() as u64,
            root_hash: format!("sha512:{}", hex(&merkle_root(leaves))),
            prev_root_hash: prev_root_hash.to_string(),
            issued_at: issued_at.to_string(),
            signature: String::new(),
            pqc_signature: None,
        }
    }

    /// Deterministic signing payload: the `\x00`-separated stable fields.
    /// Both signature fields are excluded, so Ed25519 and the future PQC
    /// signature independently cover the same bytes (no ordering dependency —
    /// the same contract as the trust-chain manifest).
    pub fn signed_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, part) in [
            self.checkpoint_version.as_str(),
            self.hash_algorithm.as_str(),
            &self.tree_size.to_string(),
            self.root_hash.as_str(),
            self.prev_root_hash.as_str(),
            self.issued_at.as_str(),
        ]
        .iter()
        .enumerate()
        {
            if i > 0 {
                out.push(0u8);
            }
            out.extend_from_slice(part.as_bytes());
        }
        out
    }
}

/// Lowercase hex of a SHA-512 digest.
pub fn hex(d: &Digest64) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a `sha512:`-prefixed (or bare) lowercase-hex digest.
pub fn parse_digest(s: &str) -> Option<Digest64> {
    let bare = s.strip_prefix("sha512:").unwrap_or(s);
    if bare.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, chunk) in bare.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_leaves(n: usize) -> Vec<Digest64> {
        (0..n)
            .map(|i| {
                let env = AttestationEnvelope {
                    algorithm: "Ed25519".to_string(),
                    key_id: format!("nrx-verify-2026-08-08T00-00-00Z-{i:08}"),
                    public_key: format!("base64:PK{i}"),
                    signature: format!("base64:SIG{i}"),
                    pqc_signature: None,
                };
                leaf_hash(&format!("{:0128}", i), &env)
            })
            .collect()
    }

    #[test]
    fn empty_tree_root_is_sha512_of_empty_string() {
        assert_eq!(
            hex(&merkle_root(&[])),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaves = test_leaves(1);
        assert_eq!(merkle_root(&leaves), leaves[0]);
    }

    #[test]
    fn leaf_and_node_domains_are_separated() {
        // A two-leaf root must differ from hashing the concatenation without
        // the 0x01 node prefix — the CT malleability defense.
        let leaves = test_leaves(2);
        let root = merkle_root(&leaves);
        let mut h = Sha512::new();
        h.update(leaves[0]);
        h.update(leaves[1]);
        let undomained: Digest64 = h.finalize().into();
        assert_ne!(root, undomained);
    }

    #[test]
    fn pqc_field_changes_the_leaf() {
        // Stripping-detection (ADR-049 D2): a leaf with pqc_signature set
        // differs from the same leaf without it.
        let mut env = AttestationEnvelope {
            algorithm: "Ed25519".to_string(),
            key_id: "k".to_string(),
            public_key: "p".to_string(),
            signature: "s".to_string(),
            pqc_signature: None,
        };
        let final_hash = "a".repeat(128);
        let without = leaf_hash(&final_hash, &env);
        env.pqc_signature = Some("base64:mldsa".to_string());
        let with = leaf_hash(&final_hash, &env);
        assert_ne!(without, with);
    }

    #[test]
    fn inclusion_roundtrip_across_sizes() {
        for n in 1..=33usize {
            let leaves = test_leaves(n);
            let root = merkle_root(&leaves);
            for m in 0..n {
                let proof = inclusion_proof(&leaves, m).unwrap();
                assert!(
                    verify_inclusion(&leaves[m], m as u64, n as u64, &proof, &root),
                    "inclusion must verify: n={n} m={m}"
                );
                // Wrong leaf must fail.
                let wrong = test_leaves(n + 1)[n];
                assert!(
                    !verify_inclusion(&wrong, m as u64, n as u64, &proof, &root),
                    "foreign leaf must not verify: n={n} m={m}"
                );
            }
        }
    }

    #[test]
    fn inclusion_rejects_out_of_range_index() {
        let leaves = test_leaves(4);
        let root = merkle_root(&leaves);
        let proof = inclusion_proof(&leaves, 0).unwrap();
        assert!(!verify_inclusion(&leaves[0], 4, 4, &proof, &root));
        assert!(inclusion_proof(&leaves, 4).is_none());
    }

    #[test]
    fn consistency_roundtrip_across_sizes() {
        for n in 1..=25usize {
            let leaves = test_leaves(n);
            let new_root = merkle_root(&leaves);
            for m in 1..=n {
                let old_root = merkle_root(&leaves[..m]);
                let proof = consistency_proof(&leaves, m).unwrap();
                assert!(
                    verify_consistency(m as u64, n as u64, &old_root, &new_root, &proof),
                    "consistency must verify: m={m} n={n}"
                );
            }
        }
    }

    #[test]
    fn consistency_detects_rewritten_history() {
        // The split-view / rewrite defense: a "new" tree whose first m leaves
        // are NOT the old tree's leaves must fail against the old root.
        let honest = test_leaves(8);
        let old_root = merkle_root(&honest[..5]);
        let mut rewritten = honest.clone();
        rewritten[2] = test_leaves(9)[8];
        let new_root = merkle_root(&rewritten);
        let proof = consistency_proof(&rewritten, 5).unwrap();
        assert!(!verify_consistency(5, 8, &old_root, &new_root, &proof));
    }

    #[test]
    fn checkpoint_assemble_links_and_serializes_byte_compat() {
        let leaves = test_leaves(3);
        let genesis = format!("sha512:{}", hex(&merkle_root(&[])));
        let cp = Checkpoint::assemble(&leaves, &genesis, "2026-08-09T00:00:00Z");
        assert_eq!(cp.tree_size, 3);
        assert_eq!(cp.prev_root_hash, genesis);
        assert_eq!(parse_digest(&cp.root_hash), Some(merkle_root(&leaves)));

        // pqc_signature: None must not serialize (byte-compat discipline).
        let json = serde_json::to_value(&cp).unwrap();
        assert!(json.get("pqc_signature").is_none());

        // Round-trips, including through a document carrying unknown fields.
        let mut with_unknown = serde_json::to_value(&cp).unwrap();
        with_unknown["future_field"] = serde_json::json!(true);
        let parsed: Checkpoint = serde_json::from_value(with_unknown).unwrap();
        assert_eq!(parsed, cp);
    }

    #[test]
    fn signed_payload_excludes_both_signature_fields() {
        let leaves = test_leaves(2);
        let mut cp = Checkpoint::assemble(&leaves, "sha512:prev", "2026-08-09T00:00:00Z");
        let unsigned = cp.signed_payload();
        cp.signature = "base64:ed25519sig".to_string();
        cp.pqc_signature = Some("base64:futuresig".to_string());
        assert_eq!(cp.signed_payload(), unsigned);
    }
}
