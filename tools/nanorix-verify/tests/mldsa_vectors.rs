//! Runs every case under `fixtures/mldsa/` through `mldsa::verify_ml_dsa`.
//!
//! Expected-valid cases must verify; expected-invalid cases must be refused
//! with the error their flags name. A file with no cases, a case count that
//! does not match the file's own `case_count`, a key the README does not
//! document at file, group or case level, a case id used twice, or any entry
//! in the folder that this test does not list fails the run. So does a
//! parameter set whose files hold no valid case or no invalid case with a key
//! and signature of the right length, or whose counts differ from the table
//! in `fixtures/mldsa/README.md`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use nanorix_verify::mldsa::{verify_ml_dsa, MlDsaError, MlDsaParameterSet};
use serde_json::Value;

const FILES: [(&str, MlDsaParameterSet); 10] = [
    ("acvp_ml_dsa_65.json", MlDsaParameterSet::MlDsa65),
    ("acvp_ml_dsa_87.json", MlDsaParameterSet::MlDsa87),
    ("acvp_siggen_ml_dsa_65.json", MlDsaParameterSet::MlDsa65),
    ("acvp_siggen_ml_dsa_87.json", MlDsaParameterSet::MlDsa87),
    ("wycheproof_ml_dsa_65.json", MlDsaParameterSet::MlDsa65),
    ("wycheproof_ml_dsa_87.json", MlDsaParameterSet::MlDsa87),
    ("mutations_ml_dsa_65.json", MlDsaParameterSet::MlDsa65),
    ("mutations_ml_dsa_87.json", MlDsaParameterSet::MlDsa87),
    ("signed_ml_dsa_65.json", MlDsaParameterSet::MlDsa65),
    ("signed_ml_dsa_87.json", MlDsaParameterSet::MlDsa87),
];

const SETS: [MlDsaParameterSet; 2] = [MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87];

/// The folder's two entries that are not vector files: the README and the
/// Wycheproof licence.
const OTHER_ENTRIES: [&str; 2] = ["README.md", "LICENSE-wycheproof.txt"];

/// The Wycheproof files, which alone carry `changes` and a `source` per group.
const WYCHEPROOF: [&str; 2] = ["wycheproof_ml_dsa_65.json", "wycheproof_ml_dsa_87.json"];

/// The files built from a Wycheproof case, which alone carry `base_source`.
const MUTATIONS: [&str; 2] = ["mutations_ml_dsa_65.json", "mutations_ml_dsa_87.json"];

/// The files signed here, with a key and signature of their own.
const SIGNED: [&str; 2] = ["signed_ml_dsa_65.json", "signed_ml_dsa_87.json"];

/// The built files, whose cases alone carry `built`.
const BUILT: [&str; 4] = [MUTATIONS[0], MUTATIONS[1], SIGNED[0], SIGNED[1]];

const TOP_KEYS: [&str; 8] = [
    "format",
    "parameter_set",
    "public_key_bytes",
    "signature_bytes",
    "source",
    "changes",
    "case_count",
    "groups",
];
const GROUP_KEYS: [&str; 3] = ["public_key", "source", "cases"];
const CASE_KEYS: [&str; 7] = [
    "id",
    "comment",
    "message",
    "signature",
    "expected",
    "flags",
    "built",
];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/mldsa")
}

fn load(name: &str) -> Value {
    let text = std::fs::read_to_string(dir().join(name)).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

struct Case {
    id: String,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    valid: bool,
    flags: Vec<String>,
}

fn cases(doc: &Value) -> Vec<Case> {
    let mut out = Vec::new();
    for group in doc["groups"].as_array().unwrap() {
        let public_key = unhex(&group["public_key"]);
        for c in group["cases"].as_array().unwrap() {
            let valid = match c["expected"].as_str().unwrap() {
                "valid" => true,
                "invalid" => false,
                other => panic!("{}: unknown expected value {other}", c["id"]),
            };
            out.push(Case {
                id: c["id"].as_str().unwrap().to_owned(),
                public_key: public_key.clone(),
                message: unhex(&c["message"]),
                signature: unhex(&c["signature"]),
                valid,
                flags: c["flags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| f.as_str().unwrap().to_owned())
                    .collect(),
            });
        }
    }
    out
}

fn expected_refusal(set: MlDsaParameterSet, case: &Case) -> MlDsaError {
    let has = |f: &str| case.flags.iter().any(|x| x == f);
    if has("IncorrectPublicKeyLength") || has("PublicKeyLength") {
        MlDsaError::PublicKeyLength {
            parameter_set: set,
            expected: set.public_key_len(),
            actual: case.public_key.len(),
        }
    } else if has("IncorrectSignatureLength") || has("SignatureLength") {
        MlDsaError::SignatureLength {
            parameter_set: set,
            expected: set.signature_len(),
            actual: case.signature.len(),
        }
    } else {
        MlDsaError::SignatureInvalid { parameter_set: set }
    }
}

fn entries(root: &Path, at: &Path, out: &mut BTreeSet<String>) {
    for e in std::fs::read_dir(at).unwrap() {
        let path = e.unwrap().path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if path.is_dir() {
            entries(root, &path, out);
            out.insert(format!("{rel}/"));
        } else {
            out.insert(rel);
        }
    }
}

#[test]
fn the_folder_holds_exactly_the_listed_files() {
    let mut on_disk = BTreeSet::new();
    entries(&dir(), &dir(), &mut on_disk);
    let listed: BTreeSet<String> = FILES
        .iter()
        .map(|(n, _)| *n)
        .chain(OTHER_ENTRIES)
        .map(str::to_owned)
        .collect();
    assert_eq!(on_disk, listed);
}

#[test]
fn case_ids_are_unique_across_all_files() {
    let mut seen = BTreeSet::new();
    let mut repeats = Vec::new();
    for (name, _) in FILES {
        for case in cases(&load(name)) {
            if !seen.insert(case.id.clone()) {
                repeats.push(format!("{name} {}", case.id));
            }
        }
    }
    assert!(repeats.is_empty(), "repeated ids: {}", repeats.join(", "));
}

fn keys(v: &Value) -> BTreeSet<&str> {
    v.as_object().unwrap().keys().map(String::as_str).collect()
}

#[test]
fn every_field_is_a_documented_one_and_provenance_sits_where_the_readme_says() {
    for (name, _) in FILES {
        let doc = load(name);
        let wycheproof = WYCHEPROOF.contains(&name);
        let top = keys(&doc);
        assert!(top.is_subset(&TOP_KEYS.into()), "{name}: {top:?}");
        assert_eq!(top.contains("changes"), wycheproof, "{name}: changes");
        if wycheproof {
            assert!(!doc["changes"].as_str().unwrap().is_empty(), "{name}");
        }
        assert!(doc["source"]["name"].is_string(), "{name}: source");
        let mutations = MUTATIONS.contains(&name);
        assert_eq!(
            doc["source"].get("base_source").is_some(),
            mutations,
            "{name}: base_source"
        );
        if mutations {
            assert!(
                doc["source"]["base_source"]["name"].is_string(),
                "{name}: base_source"
            );
        }
        for group in doc["groups"].as_array().unwrap() {
            let g = keys(group);
            assert!(g.is_subset(&GROUP_KEYS.into()), "{name}: {g:?}");
            assert_eq!(g.contains("source"), wycheproof, "{name}: group source");
            if wycheproof {
                assert!(group["source"]["name"].is_string(), "{name}: group source");
            }
            for c in group["cases"].as_array().unwrap() {
                let k = keys(c);
                assert!(k.is_subset(&CASE_KEYS.into()), "{name}: {k:?}");
                assert_eq!(
                    k.contains("built"),
                    BUILT.contains(&name),
                    "{name} {}: built",
                    c["id"]
                );
            }
        }
    }
}

/// Per parameter set, across its files: all cases, valid cases, invalid
/// cases whose key and signature have the set's lengths, and invalid cases
/// with a key or signature of another length.
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    cases: usize,
    valid: usize,
    invalid_right_lengths: usize,
    invalid_wrong_length: usize,
}

impl Counts {
    fn add(&mut self, set: MlDsaParameterSet, case: &Case) {
        self.cases += 1;
        if case.valid {
            self.valid += 1;
        } else if case.public_key.len() == set.public_key_len()
            && case.signature.len() == set.signature_len()
        {
            self.invalid_right_lengths += 1;
        } else {
            self.invalid_wrong_length += 1;
        }
    }
}

/// The counts the README's per-set table states, from its row that starts
/// with `| <set name> |`.
fn readme_counts(set: MlDsaParameterSet) -> Counts {
    let readme = std::fs::read_to_string(dir().join("README.md")).unwrap();
    let start = format!("| {} |", set.name());
    let rows: Vec<&str> = readme.lines().filter(|l| l.starts_with(&start)).collect();
    assert_eq!(rows.len(), 1, "README rows for {set}: {rows:?}");
    let n: Vec<usize> = rows[0]
        .split('|')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .skip(1)
        .map(|f| f.replace(',', "").parse().unwrap())
        .collect();
    assert_eq!(n.len(), 4, "README row for {set}: {}", rows[0]);
    Counts {
        cases: n[0],
        valid: n[1],
        invalid_right_lengths: n[2],
        invalid_wrong_length: n[3],
    }
}

#[test]
fn every_vector_case_gets_its_expected_verdict() {
    let mut failures = Vec::new();
    let mut total = 0;
    let mut per_set = [Counts::default(), Counts::default()];
    for (name, set) in FILES {
        let doc = load(name);
        assert_eq!(doc["format"], "nanorix-mldsa-sigver/1", "{name}");
        assert_eq!(doc["parameter_set"], set.name(), "{name}");
        assert_eq!(doc["public_key_bytes"], set.public_key_len(), "{name}");
        assert_eq!(doc["signature_bytes"], set.signature_len(), "{name}");
        let cs = cases(&doc);
        assert!(!cs.is_empty(), "{name} holds no cases");
        assert_eq!(
            doc["case_count"].as_u64().unwrap() as usize,
            cs.len(),
            "{name}: case_count does not match the cases present"
        );
        for case in &cs {
            total += 1;
            per_set[SETS.iter().position(|s| *s == set).unwrap()].add(set, case);
            let got = verify_ml_dsa(set, &case.public_key, &case.message, &case.signature);
            let want = if case.valid {
                Ok(())
            } else {
                Err(expected_refusal(set, case))
            };
            if got != want {
                failures.push(format!("{name} {}: want {want:?}, got {got:?}", case.id));
            }
        }
    }
    assert!(total > 0);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    for (set, counts) in SETS.iter().zip(&per_set) {
        assert!(counts.valid > 0, "{set}: no valid case");
        assert!(
            counts.invalid_right_lengths > 0,
            "{set}: no invalid case with a key and signature of the right length"
        );
        assert_eq!(*counts, readme_counts(*set), "{set}: counts against README");
    }
}

#[test]
fn every_strict_decoding_class_has_a_built_case_for_both_parameter_sets() {
    let required = [
        "Base",
        "HintRepeatedIndex",
        "HintOutOfOrder",
        "HintNonZeroPadding",
        "HintCountOverOmega",
        "HintCountDecreasing",
        "ZOutOfRange",
        "BitFlipCTilde",
        "BitFlipZ",
        "BitFlipHint",
        "SignatureLength",
        "PublicKeyLength",
    ];
    for name in ["mutations_ml_dsa_65.json", "mutations_ml_dsa_87.json"] {
        let doc = load(name);
        let present: BTreeSet<String> = cases(&doc).into_iter().flat_map(|c| c.flags).collect();
        for class in required {
            assert!(present.contains(class), "{name} has no {class} case");
        }
        for group in doc["groups"].as_array().unwrap() {
            for c in group["cases"].as_array().unwrap() {
                assert!(
                    !c["built"].as_str().unwrap_or("").is_empty(),
                    "{}: no line saying how it was built",
                    c["id"]
                );
            }
        }
    }
}

fn base(name: &str) -> Case {
    cases(&load(name))
        .into_iter()
        .find(|c| c.flags == ["Base"])
        .unwrap()
}

#[test]
fn a_key_and_signature_of_one_parameter_set_are_refused_by_the_other() {
    let b65 = base("mutations_ml_dsa_65.json");
    let b87 = base("mutations_ml_dsa_87.json");
    let p65 = MlDsaParameterSet::MlDsa65;
    let p87 = MlDsaParameterSet::MlDsa87;
    assert_eq!(
        verify_ml_dsa(p65, &b65.public_key, &b65.message, &b65.signature),
        Ok(())
    );
    assert_eq!(
        verify_ml_dsa(p87, &b87.public_key, &b87.message, &b87.signature),
        Ok(())
    );
    assert_eq!(
        verify_ml_dsa(p87, &b65.public_key, &b65.message, &b65.signature),
        Err(MlDsaError::PublicKeyLength {
            parameter_set: p87,
            expected: 2592,
            actual: 1952
        })
    );
    assert_eq!(
        verify_ml_dsa(p65, &b87.public_key, &b87.message, &b87.signature),
        Err(MlDsaError::PublicKeyLength {
            parameter_set: p65,
            expected: 1952,
            actual: 2592
        })
    );
    // With a key of the right length, the other set's signature is still refused.
    assert_eq!(
        verify_ml_dsa(p87, &b87.public_key, &b65.message, &b65.signature),
        Err(MlDsaError::SignatureLength {
            parameter_set: p87,
            expected: 4627,
            actual: 3309
        })
    );
    assert_eq!(
        verify_ml_dsa(p65, &b65.public_key, &b87.message, &b87.signature),
        Err(MlDsaError::SignatureLength {
            parameter_set: p65,
            expected: 3309,
            actual: 4627
        })
    );
}

/// The 22-byte DER `SubjectPublicKeyInfo` header of a smaller parameter set:
/// ML-DSA-44 for an ML-DSA-65 key, ML-DSA-65 for an ML-DSA-87 key.
fn smaller_set_spki_header(set: MlDsaParameterSet) -> [u8; 22] {
    match set {
        MlDsaParameterSet::MlDsa65 => [
            0x30, 0x82, 0x05, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x03, 0x11, 0x03, 0x82, 0x05, 0x21, 0x00,
        ],
        MlDsaParameterSet::MlDsa87 => [
            0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
        ],
    }
}

/// The centred `z` coefficients a signature of the set's length encodes:
/// after `c~`, l polynomials of 256 coefficients packed at 20 bits, each
/// stored as gamma1 - z (FIPS 204 Algorithm 26).
fn z_coefficients(set: MlDsaParameterSet, signature: &[u8]) -> Vec<i64> {
    let (ctilde, l) = match set {
        MlDsaParameterSet::MlDsa65 => (48, 5),
        MlDsaParameterSet::MlDsa87 => (64, 7),
    };
    let packed = &signature[ctilde..ctilde + 640 * l];
    (0..256 * l)
        .map(|i| {
            let bit = 20 * i;
            let mut v = 0u32;
            for b in 0..3 {
                v |= u32::from(packed[bit / 8 + b]) << (8 * b);
            }
            let stored = (v >> (bit % 8)) & 0xF_FFFF;
            (1i64 << 19) - i64::from(stored)
        })
        .collect()
}

#[test]
fn the_signed_cases_hold_what_their_class_names() {
    for (name, set) in [
        ("signed_ml_dsa_65.json", MlDsaParameterSet::MlDsa65),
        ("signed_ml_dsa_87.json", MlDsaParameterSet::MlDsa87),
    ] {
        let bound: i64 = (1 << 19)
            - match set {
                MlDsaParameterSet::MlDsa65 => 196,
                MlDsaParameterSet::MlDsa87 => 120,
            };
        let cs = cases(&load(name));
        let one = |class: &str| {
            let found: Vec<&Case> = cs.iter().filter(|c| c.flags == [class]).collect();
            assert_eq!(found.len(), 1, "{name}: {class} cases");
            found[0]
        };

        let rho = one("ChosenRho");
        assert!(rho.valid, "{name}: ChosenRho must be valid");
        assert_eq!(rho.public_key.len(), set.public_key_len(), "{name}");
        assert_eq!(
            rho.public_key[..22],
            smaller_set_spki_header(set),
            "{name}: rho does not start with the smaller set's header"
        );

        let at = one("ZOutOfRange");
        assert!(!at.valid, "{name}: ZOutOfRange must be invalid");
        let z = z_coefficients(set, &at.signature);
        assert_eq!(z.iter().filter(|c| **c == bound).count(), 1, "{name}");
        assert!(z.iter().all(|c| *c == bound || c.abs() < bound), "{name}");

        let below = one("ZAtBoundMinusOne");
        assert!(below.valid, "{name}: ZAtBoundMinusOne must be valid");
        let z = z_coefficients(set, &below.signature);
        assert!(z.contains(&(bound - 1)), "{name}");
        assert!(z.iter().all(|c| c.abs() < bound), "{name}");
    }
}
