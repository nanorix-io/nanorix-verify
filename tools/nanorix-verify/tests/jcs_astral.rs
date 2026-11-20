//! Cross-implementation JCS astral-plane vector — byte-equivalence lock.
//!
//! The same vector, with the same expected canonical bytes, is pinned in the Rust and Go
//! verifiers:
//!   - Rust:       this file (serde_jcs — the reference)
//!   - Go:         tools/auditproof-verifier-go/canonical_astral_test.go
//!
//! Two RFC 8785 properties that only astral-plane characters (U+10000+)
//! exercise, and where Go, TypeScript and the Python wave-N emitter diverged
//! from serde_jcs:
//!   - §3.2.2.2: characters outside the escape set are emitted literally as
//!     UTF-8 — an astral character is 4 literal bytes, never a
//!     `\uXXXX\uXXXX` surrogate-pair escape.
//!   - §3.2.3: object keys sort by UTF-16 code unit, not code point — so the
//!     astral key U+1F600 (D83D DE00) sorts BEFORE the BMP key U+FB33, the
//!     opposite of code-point order.

/// Canonical bytes of the vector, hex-encoded:
/// `{"a":"x😀y𝄞","controls":"\"\\","é":"latin","😀":"astral-key","דּ":"bmp-key-after-astral"}`
const EXPECTED_HEX: &str = "7b2261223a2278f09f988079f09d849e222c22636f6e74726f6c73223a225c75303030315c225c5c222c22c3a9223a226c6174696e222c22f09f9880223a2261737472616c2d6b6579222c22efacb3223a22626d702d6b65792d61667465722d61737472616c227d";

#[test]
fn astral_plane_characters_serialize_as_literal_utf8_and_sort_by_utf16() {
    let value = serde_json::json!({
        "a": "x\u{1F600}y\u{1D11E}",
        "controls": "\u{0001}\"\\",
        "é": "latin",
        "\u{1F600}": "astral-key",
        "\u{FB33}": "bmp-key-after-astral",
    });
    let bytes = serde_jcs::to_vec(&value).expect("JCS serialization");
    assert_eq!(
        hex::encode(&bytes),
        EXPECTED_HEX,
        "canonical form was: {}",
        String::from_utf8_lossy(&bytes)
    );
}
