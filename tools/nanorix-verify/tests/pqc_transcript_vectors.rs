//! The shared record transcript vectors (`fixtures/pqc_transcript/record_transcript.json`) run
//! through `nanorix_verify::pqc_transcript::record_transcript`: every valid case builds exactly
//! its expected bytes, every refusal case returns exactly its named refusal, and a floor keeps the
//! file from losing a version and mode pair or a rule.

use nanorix_verify::pqc_transcript::{
    record_transcript, RecordTranscriptInputs, TranscriptError, TranscriptField,
};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/pqc_transcript/record_transcript.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("the vector file is JSON")
}

fn text<'a>(case: &'a Map<String, Value>, key: &str) -> &'a str {
    case.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case field {key} is a string"))
}

/// Builds from one case's fields; `key` holds the decoded ML-DSA public key bytes.
fn build(case: &Map<String, Value>, key: &[u8]) -> Result<Vec<u8>, TranscriptError> {
    let inputs = RecordTranscriptInputs {
        cdp_version: text(case, "cdp_version"),
        signing_mode: text(case, "signing_mode"),
        capsule_id: text(case, "capsule_id"),
        key_id: text(case, "key_id"),
        signature_algorithm: text(case, "signature_algorithm"),
        pqc_algorithm: text(case, "pqc_algorithm"),
        ed25519_public_key: text(case, "ed25519_public_key"),
        pqc_public_key: key,
        canonical_hash_raw: text(case, "canonical_hash_raw"),
    };
    record_transcript(&inputs).map(|t| t.as_bytes().to_vec())
}

/// The refusal's name and field as the vector file writes them.
fn refusal_name(e: &TranscriptError) -> (&'static str, Option<&'static str>) {
    match e {
        TranscriptError::NulByte(f) => ("NulByte", Some(f.name())),
        TranscriptError::NonAsciiByte(f) => ("NonAsciiByte", Some(f.name())),
        TranscriptError::CdpVersionUnsupported => ("CdpVersionUnsupported", None),
        TranscriptError::SigningModeUnsupported => ("SigningModeUnsupported", None),
        TranscriptError::CapsuleIdEmpty => ("CapsuleIdEmpty", None),
        TranscriptError::KeyIdEmpty => ("KeyIdEmpty", None),
        TranscriptError::SignatureAlgorithmUnsupported => ("SignatureAlgorithmUnsupported", None),
        TranscriptError::PqcAlgorithmUnsupported => ("PqcAlgorithmUnsupported", None),
        TranscriptError::Ed25519PublicKeyMalformed => ("Ed25519PublicKeyMalformed", None),
        TranscriptError::PqcPublicKeyLength(_) => ("PqcPublicKeyLength", None),
        TranscriptError::CanonicalHashMalformed => ("CanonicalHashMalformed", None),
    }
}

fn cases<'a>(doc: &'a Value, list: &str) -> Vec<&'a Map<String, Value>> {
    doc[list]
        .as_array()
        .unwrap_or_else(|| panic!("{list} is a list"))
        .iter()
        .map(|c| c.as_object().expect("each case is an object"))
        .collect()
}

#[test]
fn every_valid_case_builds_exactly_its_expected_bytes() {
    let doc = vectors();
    for case in cases(&doc, "valid") {
        let name = text(case, "name");
        let key = hex::decode(text(case, "pqc_public_key_hex")).expect("key hex");
        let got = build(case, &key).unwrap_or_else(|e| panic!("{name}: refused: {e}"));
        assert_eq!(
            hex::encode(&got),
            text(case, "expected_transcript_hex"),
            "{name}: transcript bytes"
        );
        assert_eq!(
            Some(got.len() as u64),
            case["expected_length"].as_u64(),
            "{name}: length"
        );
        let fields: Vec<&[u8]> = got.split(|b| *b == 0).collect();
        assert_eq!(fields.len(), 9, "{name}: nine fields");
        assert_eq!(
            fields[7],
            text(case, "expected_fingerprint").as_bytes(),
            "{name}: the fingerprint field"
        );
    }
}

#[test]
fn every_refusal_case_returns_its_named_refusal_and_nothing_else() {
    let doc = vectors();
    let valid = cases(&doc, "valid");
    for case in cases(&doc, "refusals") {
        let name = text(case, "name");
        let base = valid
            .iter()
            .find(|v| text(v, "name") == text(case, "base"))
            .unwrap_or_else(|| panic!("{name}: base case"));
        let mut inputs = (*base).clone();
        for (k, v) in case["set"].as_object().expect("set is an object") {
            assert!(inputs.contains_key(k), "{name}: sets an unknown field {k}");
            inputs.insert(k.clone(), v.clone());
        }
        let key = hex::decode(text(&inputs, "pqc_public_key_hex")).expect("key hex");
        let got = build(&inputs, &key).map_err(|e| refusal_name(&e));
        let want = (
            text(case, "expected_error"),
            case["expected_field"].as_str(),
        );
        match got {
            Ok(bytes) => panic!("{name}: built {} bytes, wanted {want:?}", bytes.len()),
            Err(found) => assert_eq!(found, want, "{name}"),
        }
    }
}

#[test]
fn the_vector_file_keeps_every_pair_and_every_rule() {
    let doc = vectors();
    let pairs: BTreeSet<(String, String)> = cases(&doc, "valid")
        .iter()
        .map(|c| {
            (
                text(c, "cdp_version").into(),
                text(c, "signing_mode").into(),
            )
        })
        .collect();
    for version in ["2.1", "2.2"] {
        for mode in ["nanorix_only", "customer_only"] {
            assert!(
                pairs.contains(&(version.into(), mode.into())),
                "no valid case for {version} {mode}"
            );
        }
    }
    // Two partner keys, so a builder that fingerprints a fixed key fails a valid case.
    let fingerprints: BTreeSet<&str> = cases(&doc, "valid")
        .iter()
        .map(|c| text(c, "expected_fingerprint"))
        .collect();
    assert!(
        fingerprints.len() >= 2,
        "the valid cases carry one fingerprint"
    );

    let refusals = cases(&doc, "refusals");
    let seen: BTreeSet<(String, Option<String>)> = refusals
        .iter()
        .map(|c| {
            (
                text(c, "expected_error").into(),
                c["expected_field"].as_str().map(String::from),
            )
        })
        .collect();
    let fields = [
        TranscriptField::CdpVersion,
        TranscriptField::SigningMode,
        TranscriptField::CapsuleId,
        TranscriptField::KeyId,
        TranscriptField::SignatureAlgorithm,
        TranscriptField::PqcAlgorithm,
        TranscriptField::Ed25519PublicKey,
        TranscriptField::CanonicalHashRaw,
    ];
    for field in fields {
        for rule in ["NulByte", "NonAsciiByte"] {
            assert!(
                seen.contains(&(rule.into(), Some(field.name().into()))),
                "no {rule} case on {field}"
            );
        }
    }
    for rule in [
        "CdpVersionUnsupported",
        "SigningModeUnsupported",
        "CapsuleIdEmpty",
        "KeyIdEmpty",
        "SignatureAlgorithmUnsupported",
        "PqcAlgorithmUnsupported",
        "Ed25519PublicKeyMalformed",
        "PqcPublicKeyLength",
        "CanonicalHashMalformed",
    ] {
        assert!(seen.contains(&(rule.into(), None)), "no {rule} case");
    }

    // The values the ruling names one by one each keep a case.
    let named = |field: &str, value: &str| {
        refusals
            .iter()
            .any(|c| c["set"].get(field).and_then(Value::as_str) == Some(value))
    };
    for v in ["1.0", "2.0", ""] {
        assert!(
            named("cdp_version", v),
            "no refusal case for cdp_version {v:?}"
        );
    }
    for m in ["dual_signature", "tee_attested", ""] {
        assert!(
            named("signing_mode", m),
            "no refusal case for signing_mode {m:?}"
        );
    }
    for case in [
        "ed25519_public_key_missing_prefix",
        "ed25519_public_key_unpadded",
        "ed25519_public_key_url_safe",
        "ed25519_public_key_non_zero_padding_bits",
        "ed25519_public_key_31_bytes",
        "ed25519_public_key_33_bytes",
        "ed25519_public_key_newline_inside",
        "ed25519_public_key_crlf_inside",
        "ed25519_public_key_trailing_newline",
        "ed25519_public_key_leading_space",
        "two_faults_cdp_version_1_0_and_capsule_id_holds_nul",
        "two_faults_key_id_holds_non_ascii_then_nul",
        "canonical_hash_raw_uppercase",
        "canonical_hash_raw_one_uppercase",
        "canonical_hash_raw_127_chars",
        "canonical_hash_raw_129_chars",
        "pqc_public_key_1951_bytes",
        "pqc_public_key_1953_bytes",
    ] {
        assert!(
            refusals.iter().any(|c| text(c, "name") == case),
            "the vector file lost {case}"
        );
    }
}
