//! Every signed-message type tag.
//!
//! Each primitive that signs a tagged message registers its tag here. A proof
//! signature covers exactly 128 lowercase hex characters, so a tag holding a
//! non-hex character can never produce a proof's signature target, and no tag
//! may be a prefix of another, or one primitive's message could be read as
//! another's.

use crate::population_head::{
    POPULATION_HEAD_PQC_TAG_V2, POPULATION_HEAD_TYPE_V1, POPULATION_HEAD_TYPE_V2,
};
use crate::population_tick::{POPULATION_TICK_PQC_TAG_V1, POPULATION_TICK_TYPE_V1};

/// The prefix of an authority ownership proof, signed under the authority's
/// key. `OWNERSHIP_PROOF_PREFIX_V1` in the reference chain implementation
/// fixes these bytes.
pub const AUTHORITY_OWNERSHIP_TAG: &str = "NANORIX-AUTHORITY-OWNERSHIP-V1\x00";

/// The signed-message type tags in use.
pub const SIGNED_MESSAGE_TAGS: &[&str] = &[
    POPULATION_HEAD_TYPE_V1,
    AUTHORITY_OWNERSHIP_TAG,
    POPULATION_TICK_TYPE_V1,
    POPULATION_TICK_PQC_TAG_V1,
    POPULATION_HEAD_TYPE_V2,
    POPULATION_HEAD_PQC_TAG_V2,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_distinct_and_none_prefixes_another() {
        for (i, a) in SIGNED_MESSAGE_TAGS.iter().enumerate() {
            for (j, b) in SIGNED_MESSAGE_TAGS.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "{a} prefixes {b}");
                }
            }
        }
    }

    #[test]
    fn every_tag_holds_a_character_outside_lowercase_hex() {
        for tag in SIGNED_MESSAGE_TAGS {
            assert!(
                tag.bytes().any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "{tag}"
            );
        }
    }

    #[test]
    fn the_population_head_tag_is_registered() {
        assert!(SIGNED_MESSAGE_TAGS.contains(&POPULATION_HEAD_TYPE_V1));
    }

    #[test]
    fn both_tick_tags_are_registered() {
        assert!(SIGNED_MESSAGE_TAGS.contains(&POPULATION_TICK_TYPE_V1));
        assert!(SIGNED_MESSAGE_TAGS.contains(&POPULATION_TICK_PQC_TAG_V1));
    }

    #[test]
    fn both_version_2_head_tags_are_registered() {
        assert!(SIGNED_MESSAGE_TAGS.contains(&POPULATION_HEAD_TYPE_V2));
        assert!(SIGNED_MESSAGE_TAGS.contains(&POPULATION_HEAD_PQC_TAG_V2));
    }
}
