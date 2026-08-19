//! Streaming-egress Merkle root verification.
//!
//! A capsule that streams a response records one `streaming_egress_chunk`
//! activity event per chunk and closes the stream with a
//! `streaming_egress_completed` event carrying `streaming_merkle_root` — an
//! RFC 6962 SHA-512 commitment over exactly those chunk hashes, emitted by
//! `runtime/eee/src/daemon/streaming.rs::merkle_root_from_leaves` and wrapped
//! in the `sha512:` prefix at `runtime/eee/src/daemon/relay.rs:819`.
//!
//! Until this module, no verifier in any of the four implementations read that
//! root. It was signed and carried past. The activity trail is inside
//! `CanonicalCdpView`, so the root and its leaves are both signature-bound —
//! but a proof can reach a verdict without a signature check at all (the
//! `SignatureCheck::Absent` path reports chain-verified at stage 4), and the
//! whole point of the commitment is that it stays checkable once the leaves
//! are truncated away above a size threshold. A commitment nothing recomputes
//! is not evidence.
//!
//! ## What is checked, and what deliberately is not
//!
//! The root is recomputed only when the leaves are **present and complete** —
//! the number of `streaming_egress_chunk` events collected for a stream equals
//! that stream's `total_chunks`. A document that discloses the root with fewer
//! leaves (or none) is the future truncation shape, not a defect: recomputing
//! from a partial set would fail every truncated proof. Those are carried past
//! unchecked, exactly as today.
//!
//! Leaves are ordered by their `seq` field rather than by document order,
//! matching the contract stated at `streaming.rs:150` ("verifiers replay the
//! tree by collecting `chunk_hash` values in `seq` order").

use nanorix_verify_types::FailureReason;
use serde_json::Value;
use sha2::{Digest, Sha512};

/// RFC 6962 leaf-domain prefix. Mirrors `MERKLE_LEAF_PREFIX`.
const MERKLE_LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 inner-node domain prefix. Mirrors `MERKLE_INNER_PREFIX`.
const MERKLE_INNER_PREFIX: u8 = 0x01;

/// SHA-512 of the empty input — the root of a zero-leaf tree.
const EMPTY_SHA512_HEX: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/// Byte-for-byte mirror of
/// `runtime/eee/src/daemon/streaming.rs::merkle_root_from_leaves`.
///
/// Empty → SHA-512 of empty. Single leaf → `SHA-512(0x00 || leaf)`. Inner →
/// `SHA-512(0x01 || left || right)`. An odd tail node is promoted unchanged.
/// Returns 128 lowercase hex characters, unprefixed.
///
/// **Forever-Standard (ADR-006 I0).** Changing any of the three rules above
/// invalidates every streaming Merkle root ever emitted.
pub fn merkle_root_from_leaves(leaves: &[[u8; 64]]) -> String {
    if leaves.is_empty() {
        return EMPTY_SHA512_HEX.to_string();
    }

    let mut level: Vec<[u8; 64]> = leaves
        .iter()
        .map(|leaf| {
            let mut hasher = Sha512::new();
            hasher.update([MERKLE_LEAF_PREFIX]);
            hasher.update(leaf);
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&hasher.finalize());
            arr
        })
        .collect();

    while level.len() > 1 {
        let mut next: Vec<[u8; 64]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            let mut hasher = Sha512::new();
            hasher.update([MERKLE_INNER_PREFIX]);
            hasher.update(level[i]);
            hasher.update(level[i + 1]);
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&hasher.finalize());
            next.push(arr);
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        level = next;
    }

    hex::encode(level[0])
}

/// One `chunk_hash` as a 64-byte Merkle leaf, or `None` when the value is not
/// a `sha512:`-prefixed (or bare) 128-hex string.
fn leaf_bytes(chunk_hash: &str) -> Option<[u8; 64]> {
    let hex_str = crate::strip_hash_prefix(chunk_hash);
    let raw = hex::decode(hex_str).ok()?;
    let arr: [u8; 64] = raw.try_into().ok()?;
    Some(arr)
}

/// A stream's chunk leaves, accumulated between `streaming_egress_started`
/// and `streaming_egress_completed`.
#[derive(Default)]
struct StreamAccumulator {
    /// `(seq, chunk_hash)` in document order; sorted by `seq` at close.
    chunks: Vec<(u64, String)>,
    /// Set when any chunk event carried a malformed or absent `chunk_hash`.
    malformed: bool,
}

impl StreamAccumulator {
    /// Evaluate one closed stream. `None` means "nothing to say": the leaves
    /// were absent or incomplete, or the event carried no root.
    fn close(&self, completed: &Value) -> Option<FailureReason> {
        let claimed = completed.get("streaming_merkle_root")?.as_str()?;

        // A disclosed chunk event with no usable `chunk_hash` is a structural
        // defect in the trail, not a root disagreement — and it is reported as
        // one. Checked before the completeness gate below so a single unusable
        // leaf cannot be used to shrink the set into the "truncated, do not
        // check" shape.
        if self.malformed {
            return Some(FailureReason::RequiredFieldMissing {
                field: "activity_trail.streaming_egress_chunk.chunk_hash".to_string(),
            });
        }

        // Absent `total_chunks` is treated as "as many as were disclosed", so a
        // document that omits the count still gets checked when its leaves are
        // all there.
        let total = completed
            .get("total_chunks")
            .and_then(Value::as_u64)
            .unwrap_or(self.chunks.len() as u64);

        // Partial disclosure — the truncated shape. Not a defect; not
        // checkable. A zero-chunk stream lands here with an empty leaf set and
        // total 0, which IS checkable: its root is SHA-512 of empty.
        if self.chunks.len() as u64 != total {
            return None;
        }

        let mut ordered = self.chunks.clone();
        ordered.sort_by_key(|(seq, _)| *seq);
        let leaves: Vec<[u8; 64]> = ordered.iter().filter_map(|(_, h)| leaf_bytes(h)).collect();
        // filter_map cannot shorten the list here — `malformed` already
        // rejected every unparseable hash above.
        debug_assert_eq!(leaves.len(), ordered.len());

        let computed = merkle_root_from_leaves(&leaves);
        if crate::strip_hash_prefix(claimed) != computed {
            return Some(FailureReason::StreamingMerkleRootMismatch {
                claimed: claimed.to_string(),
                computed: format!("sha512:{computed}"),
            });
        }
        None
    }
}

/// Walk the activity trail and verify every streaming Merkle root whose leaves
/// are fully disclosed. Returns the first mismatch, or `None`.
///
/// Streams are delimited by their events: `streaming_egress_started` opens a
/// fresh accumulator, `streaming_egress_chunk` adds a leaf,
/// `streaming_egress_completed` closes and checks. Events of any other kind
/// are ignored, so an interleaved trail is walked correctly as long as each
/// stream's own events stay in order — which is how the API emits them
/// (`services/api/src/routes/capsules.rs:1866`).
pub fn verify_streaming_merkle_roots(activity: &[Value]) -> Option<FailureReason> {
    let mut acc = StreamAccumulator::default();

    for event in activity {
        match event.get("event").and_then(Value::as_str) {
            Some("streaming_egress_started") => {
                acc = StreamAccumulator::default();
            }
            Some("streaming_egress_chunk") => {
                let seq = event.get("seq").and_then(Value::as_u64);
                let hash = event.get("chunk_hash").and_then(Value::as_str);
                match (seq, hash) {
                    (Some(seq), Some(hash)) if leaf_bytes(hash).is_some() => {
                        acc.chunks.push((seq, hash.to_string()));
                    }
                    // Missing seq, missing hash, or a hash that is not 128 hex
                    // characters. Flagged rather than dropped: dropping it
                    // would let a malformed leaf shrink the set into a
                    // different tree, or into the "truncated" shape.
                    _ => acc.malformed = true,
                }
            }
            Some("streaming_egress_completed") => {
                if let Some(failure) = acc.close(event) {
                    return Some(failure);
                }
                acc = StreamAccumulator::default();
            }
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Independently computed (outside this crate, in Python) over the same
    /// three leaves the EEE-side anchor test uses at
    /// `runtime/eee/src/daemon/streaming.rs::merkle_root_for_streaming_chunk_hashes_pinned_anchor`.
    /// Exercises leaf prefix, inner prefix and odd-tail promotion in one value.
    /// Drift here means the verifier stopped agreeing with the emitter.
    const PINNED_3LEAF_ROOT: &str = "28f59b1c8b9304b9a2d5c23d85aeee777b74655ee1104f0ec497c771ba85a9658b04969e7d1ab4c4793fb2eca3d62ad94020d29a79f0486bbf3ae828042a4e82";

    fn leaf(byte: u8) -> [u8; 64] {
        [byte; 64]
    }

    fn chunk_event(seq: u64, leaf_byte: u8) -> serde_json::Value {
        json!({
            "event": "streaming_egress_chunk",
            "seq": seq,
            "chunk_hash": format!("sha512:{}", hex::encode(leaf(leaf_byte))),
            "at": "2026-08-18T00:00:00Z",
        })
    }

    fn completed_event(total: u64, root_hex: &str) -> serde_json::Value {
        json!({
            "event": "streaming_egress_completed",
            "total_chunks": total,
            "streaming_merkle_root": format!("sha512:{root_hex}"),
            "duration_ms": 12,
            "at": "2026-08-18T00:00:00Z",
        })
    }

    fn started_event() -> serde_json::Value {
        json!({
            "event": "streaming_egress_started",
            "destination": "api.example.com",
            "protocol": "chunked",
            "request_hash": "sha512:00",
            "at": "2026-08-18T00:00:00Z",
        })
    }

    // ── the tree itself ────────────────────────────────────────────────

    #[test]
    fn empty_leaf_set_is_sha512_of_empty() {
        assert_eq!(merkle_root_from_leaves(&[]), EMPTY_SHA512_HEX);
    }

    #[test]
    fn single_leaf_is_leaf_domain_hashed() {
        let mut h = Sha512::new();
        h.update([MERKLE_LEAF_PREFIX]);
        h.update(leaf(0xaa));
        assert_eq!(
            merkle_root_from_leaves(&[leaf(0xaa)]),
            hex::encode(h.finalize())
        );
    }

    #[test]
    fn three_leaves_match_the_pinned_cross_impl_anchor() {
        assert_eq!(
            merkle_root_from_leaves(&[leaf(0xaa), leaf(0xbb), leaf(0xcc)]),
            PINNED_3LEAF_ROOT
        );
    }

    #[test]
    fn root_is_order_sensitive() {
        assert_ne!(
            merkle_root_from_leaves(&[leaf(0xaa), leaf(0xbb)]),
            merkle_root_from_leaves(&[leaf(0xbb), leaf(0xaa)])
        );
    }

    // ── the trail walk ─────────────────────────────────────────────────

    #[test]
    fn genuine_stream_passes() {
        let trail = vec![
            started_event(),
            chunk_event(0, 0xaa),
            chunk_event(1, 0xbb),
            chunk_event(2, 0xcc),
            completed_event(3, PINNED_3LEAF_ROOT),
        ];
        assert_eq!(verify_streaming_merkle_roots(&trail), None);
    }

    #[test]
    fn altered_chunk_hash_is_caught() {
        let trail = vec![
            started_event(),
            chunk_event(0, 0xaa),
            chunk_event(1, 0xbb),
            // 0xdd where the root commits to 0xcc.
            chunk_event(2, 0xdd),
            completed_event(3, PINNED_3LEAF_ROOT),
        ];
        match verify_streaming_merkle_roots(&trail) {
            Some(FailureReason::StreamingMerkleRootMismatch { claimed, computed }) => {
                assert_eq!(claimed, format!("sha512:{PINNED_3LEAF_ROOT}"));
                assert!(computed.starts_with("sha512:"));
                assert_ne!(claimed, computed);
            }
            other => panic!("expected StreamingMerkleRootMismatch, got {other:?}"),
        }
    }

    #[test]
    fn reordered_chunk_events_are_replayed_in_seq_order() {
        // Document order scrambled; `seq` still says which leaf goes where.
        let trail = vec![
            started_event(),
            chunk_event(2, 0xcc),
            chunk_event(0, 0xaa),
            chunk_event(1, 0xbb),
            completed_event(3, PINNED_3LEAF_ROOT),
        ];
        assert_eq!(verify_streaming_merkle_roots(&trail), None);
    }

    #[test]
    fn swapped_seq_numbers_are_caught() {
        // Same three hashes, two of them re-labelled — a different tree.
        let trail = vec![
            started_event(),
            chunk_event(1, 0xaa),
            chunk_event(0, 0xbb),
            chunk_event(2, 0xcc),
            completed_event(3, PINNED_3LEAF_ROOT),
        ];
        assert!(matches!(
            verify_streaming_merkle_roots(&trail),
            Some(FailureReason::StreamingMerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn zero_chunk_stream_checks_against_the_empty_root() {
        let ok = vec![started_event(), completed_event(0, EMPTY_SHA512_HEX)];
        assert_eq!(verify_streaming_merkle_roots(&ok), None);

        let bad = vec![started_event(), completed_event(0, PINNED_3LEAF_ROOT)];
        assert!(matches!(
            verify_streaming_merkle_roots(&bad),
            Some(FailureReason::StreamingMerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn root_without_leaves_is_carried_past_unchecked() {
        // The future truncation shape (B6.2): the commitment stands alone.
        // Recomputing from an empty set would reject every truncated proof.
        let trail = vec![started_event(), completed_event(3, PINNED_3LEAF_ROOT)];
        assert_eq!(verify_streaming_merkle_roots(&trail), None);
    }

    #[test]
    fn partially_disclosed_leaves_are_carried_past_unchecked() {
        let trail = vec![
            started_event(),
            chunk_event(0, 0xaa),
            completed_event(3, PINNED_3LEAF_ROOT),
        ];
        assert_eq!(verify_streaming_merkle_roots(&trail), None);
    }

    #[test]
    fn malformed_chunk_hash_reports_the_missing_field() {
        let trail = vec![
            started_event(),
            json!({"event": "streaming_egress_chunk", "seq": 0, "chunk_hash": "sha512:zz"}),
            chunk_event(1, 0xbb),
            chunk_event(2, 0xcc),
            completed_event(3, PINNED_3LEAF_ROOT),
        ];
        match verify_streaming_merkle_roots(&trail) {
            Some(FailureReason::RequiredFieldMissing { field }) => {
                assert_eq!(field, "activity_trail.streaming_egress_chunk.chunk_hash");
            }
            other => panic!("expected RequiredFieldMissing, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_leaf_cannot_masquerade_as_truncation() {
        // Dropping the bad leaf instead of flagging it would leave 2 of 3 and
        // land in the "partially disclosed, do not check" branch — turning a
        // corrupt trail into a silent pass.
        let trail = vec![
            started_event(),
            json!({"event": "streaming_egress_chunk", "seq": 0}),
            chunk_event(1, 0xbb),
            chunk_event(2, 0xcc),
            completed_event(3, PINNED_3LEAF_ROOT),
        ];
        assert!(matches!(
            verify_streaming_merkle_roots(&trail),
            Some(FailureReason::RequiredFieldMissing { .. })
        ));
    }

    #[test]
    fn second_stream_is_checked_independently_of_the_first() {
        let trail = vec![
            started_event(),
            chunk_event(0, 0xaa),
            chunk_event(1, 0xbb),
            chunk_event(2, 0xcc),
            completed_event(3, PINNED_3LEAF_ROOT),
            started_event(),
            chunk_event(0, 0xaa),
            chunk_event(1, 0xbb),
            // Second stream claims the three-leaf root over two leaves.
            completed_event(2, PINNED_3LEAF_ROOT),
        ];
        assert!(matches!(
            verify_streaming_merkle_roots(&trail),
            Some(FailureReason::StreamingMerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn leaves_do_not_leak_across_a_stream_boundary() {
        // Without the reset on `started`, the second stream would replay five
        // leaves and reject a genuine pair of streams.
        let trail = vec![
            started_event(),
            chunk_event(0, 0xaa),
            chunk_event(1, 0xbb),
            chunk_event(2, 0xcc),
            completed_event(3, PINNED_3LEAF_ROOT),
            started_event(),
            chunk_event(0, 0xaa),
            chunk_event(1, 0xbb),
            chunk_event(2, 0xcc),
            completed_event(3, PINNED_3LEAF_ROOT),
        ];
        assert_eq!(verify_streaming_merkle_roots(&trail), None);
    }

    #[test]
    fn a_trail_with_no_streaming_events_is_untouched() {
        let trail = vec![
            json!({"event": "capsule_created", "at": "2026-08-18T00:00:00Z"}),
            json!({"event": "command_executed", "at": "2026-08-18T00:00:00Z"}),
        ];
        assert_eq!(verify_streaming_merkle_roots(&trail), None);
    }

    #[test]
    fn bare_hex_root_without_the_prefix_still_compares() {
        let trail = vec![
            started_event(),
            chunk_event(0, 0xaa),
            chunk_event(1, 0xbb),
            chunk_event(2, 0xcc),
            json!({
                "event": "streaming_egress_completed",
                "total_chunks": 3,
                "streaming_merkle_root": PINNED_3LEAF_ROOT,
            }),
        ];
        assert_eq!(verify_streaming_merkle_roots(&trail), None);
    }
}
