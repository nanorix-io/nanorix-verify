//! Embedded-key verification — independent canonical-hash recompute + Ed25519 signature
//! verification for the single-proof path (`verify_auditproof`).
//!
//! ## Why this lives here (and not in a shared product crate)
//!
//! The offline verifier is deliberately INDEPENDENT of the product crates so
//! an auditor can compile and read it without pulling the reference server implementation /
//! the reference chain implementation and their transitive deps. `nanorix-verify-types` is a
//! pure-types crate (serde only) and cannot host the JCS + SHA-512 + Ed25519
//! runtime code. So — consistent with how this crate already mirrors
//! `compute_step_hash` in the reference chain implementation and the receipt pipeline primitives — we mirror the
//! server's canonical view here and lock byte-identity with the cross-impl
//! corpus (`fixtures/corpus/01_single_capsule_success` must verify; the
//! `04_failure_signature_invalid` and `08_failure_canonical_hash_drift`
//! categories must fail).
//!
//! ## What is mirrored
//!
//! `canonical_view` in `the AuditProof document builder()` builds a
//! `CanonicalCdpView` and hashes it via
//! `canonical_hash` in the reference chain implementation = `hex(sha512(serde_jcs(view)))`.
//! Because the AuditProof JSON already contains every value in its exact
//! serialized shape, we rebuild only the *view* — mapping `FullCdp` wire field
//! names to the canonical-view keys and applying the two transforms the server
//! applies (`signing_key_version` String -> i64; the `attestation` subset) —
//! then re-canonicalize with the same RFC-8785 JCS. Under JCS the physical key
//! order is irrelevant (keys are sorted), so a byte-flip / key-reorder tamper
//! either changes a hashed value (signature fails) or is semantically identical
//! (correctly still verifies).
//!
//! ## Trust scope (sub-A vs sub-B)
//!
//! This verifies the signature against the public key EMBEDDED in the proof —
//! identical to what the hosted verification endpoint does today. That
//! detects a change to any signed byte of a proof; fields outside the signed
//! view (such as `metadata`) are not checked. It does NOT establish that the key
//! belongs to Nanorix; binding the key to a Nanorix-rooted trust anchor is
//! Trust-chain anchoring (the trust-chain manifest in `trust_chain.rs`).

use crate::ed25519_strict::VerifyCanonicalStrict;
use crate::{strip_base64_prefix, strip_hash_prefix};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use nanorix_verify_types::SignatureFailureReason;
use serde_json::{Map, Value};
use sha2::{Digest, Sha512};

/// Marks a `signed_message` result as "this build cannot verify the declared
/// signing_mode" rather than an actual message to sign over. Never a valid hash.
const UNSUPPORTED_MODE_SENTINEL: &str = "\u{0}unsupported-signing-mode:";

/// Outcome of the signature stage (stages 5-8).
#[derive(Debug, PartialEq)]
pub enum SignatureCheck {
    /// Signature verified against the embedded key over the correct message.
    Verified,
    /// No signature present at all (unsigned partial). Nothing to check — the
    /// caller keeps the honest stage-4 "chain verified, signature NOT checked"
    /// verdict.
    Absent,
    /// The document declares a `signing_mode` this build cannot verify.
    ///
    /// Distinct from `Absent` on purpose. `signing_mode` is inside the canonical
    /// hash and is attacker-controllable, so if an unrecognised mode produced the
    /// same "signature not checked" outcome as a missing signature, flipping the
    /// mode would convert a rejection into a reassuring partial result — a
    /// downgrade oracle. "I have no signature to check" and "I cannot perform the
    /// verification this document requires" are different conditions and must
    /// produce different verdicts. Carries the offending mode.
    Unsupported(String),
    /// A signature was present but did not verify.
    Failed(SignatureFailureReason),
}

/// Rebuild the canonical view from a proof's JSON and return its
/// RFC-8785 JCS SHA-512 hex digest — byte-identical to the server's
/// `FullCdp::canonical_hash()`. Lowercase 128-char hex (or empty on the
/// impossible JCS-serialize failure, which fails the signature check closed).
pub fn recompute_canonical_hash(proof: &Value) -> String {
    let str_field = |k: &str| proof.get(k).cloned().unwrap_or(Value::Null);
    let mut v: Map<String, Value> = Map::new();

    // Always-present scalars (FullCdp wire name -> canonical-view key).
    v.insert("version".into(), str_field("cdp_version"));
    v.insert("signing_mode".into(), str_field("signing_mode"));
    v.insert("jurisdiction".into(), str_field("jurisdiction"));
    v.insert("authority_id".into(), str_field("authority_id"));
    // signing_key_version: FullCdp stores a String; the canonical view emits an
    // integer (server parses, unparseable -> 0).
    let skv = proof
        .get("signing_key_version")
        .and_then(|x| x.as_str())
        .and_then(|x| x.parse::<i64>().ok())
        .unwrap_or(0);
    v.insert("signing_key_version".into(), Value::from(skv));
    v.insert("capsule_id".into(), str_field("capsule_id"));
    // org_id defaults to "" on the server (#[serde(default)] String).
    v.insert(
        "org_id".into(),
        proof
            .get("org_id")
            .cloned()
            .unwrap_or_else(|| Value::String(String::new())),
    );

    // skip_serializing_if = Option::is_none -> OMIT when absent/null.
    insert_if_present(&mut v, "parent_audit_proof_id", proof);
    insert_if_present(&mut v, "cdp_kind", proof);

    // Arrays carried verbatim (canonical-view key differs from wire name).
    v.insert(
        "activity_trail".into(),
        proof
            .get("activity")
            .cloned()
            .unwrap_or(Value::Array(vec![])),
    );
    v.insert(
        "destruction_chain".into(),
        proof.get("chain").cloned().unwrap_or(Value::Array(vec![])),
    );
    v.insert("destruction_state".into(), str_field("destruction_state"));

    // No skip attribute -> serialized as null when absent (NOT omitted).
    v.insert(
        "destruction_failure_step".into(),
        str_field("destruction_failure_step"),
    );

    insert_if_present(&mut v, "parent_proofs_merkle_root", proof);
    insert_if_present(&mut v, "record_receipts_merkle_root", proof);
    // The one signed root over the customer's own activity record.
    // Same skip_serializing_if mechanic as the two Merkle roots above, so a
    // document without it hashes byte-identically to a earlier document.
    insert_if_present(&mut v, "customer_declared_activity_root", proof);

    // No skip attribute -> null when absent.
    v.insert(
        "runtime_attestation".into(),
        str_field("runtime_attestation"),
    );

    // attestation subset: { timestamp_attestation (null|obj),
    // attestation_chain_fingerprint (null|str — empty string canonicalizes to
    // null, matching the server's `if fingerprint.is_empty() { None }`). }
    let mut att: Map<String, Value> = Map::new();
    att.insert(
        "timestamp_attestation".into(),
        str_field("timestamp_attestation"),
    );
    let fingerprint = proof
        .get("attestation_chain_fingerprint")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty());
    att.insert(
        "attestation_chain_fingerprint".into(),
        fingerprint.map(Value::from).unwrap_or(Value::Null),
    );
    v.insert("attestation".into(), Value::Object(att));

    v.insert("hash_algorithm".into(), str_field("hash_algorithm"));
    v.insert(
        "signature_algorithm".into(),
        str_field("signature_algorithm"),
    );

    match serde_jcs::to_vec(&Value::Object(v)) {
        Ok(bytes) => {
            let digest = Sha512::digest(&bytes);
            digest.iter().map(|b| format!("{:02x}", b)).collect()
        }
        // An object of parsed JSON always serializes, which `population_head`
        // relies on when it keeps this value as a document identity. On the
        // impossible failure return empty so the signature comparison fails
        // closed rather than panicking.
        Err(_) => String::new(),
    }
}

fn insert_if_present(view: &mut Map<String, Value>, key: &str, proof: &Value) {
    if let Some(x) = proof.get(key) {
        if !x.is_null() {
            view.insert(key.to_string(), x.clone());
        }
    }
}

/// Select the signed message for a proof by version/mode — mirrors
/// the hosted verification endpoint:
/// - `1.0` -> `final_hash` (ASCII hex, prefix-stripped)
/// - `2.1` / `2.2` + `nanorix_only` or `customer_only` -> recomputed
///   `canonical_hash`; the two modes differ only in the mode string the view
///   carries, which the recompute already binds
/// - `2.1` / `2.2` + any other mode (`dual_signature`, `tee_attested`, a
///   value with different case or extra characters) -> the unsupported-mode
///   sentinel (not verifiable here)
///
/// `2.2` shares the `2.1` arm deliberately: changed what the
/// canonical view may carry, not how it is hashed or signed.
fn signed_message(proof: &Value, cdp_version: &str) -> Option<String> {
    let signing_mode = proof
        .get("signing_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("nanorix_only");
    let msg = match cdp_version {
        "1.0" => strip_hash_prefix(
            proof
                .get("final_hash")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )
        .to_string(),
        "2.1" | "2.2" => match signing_mode {
            "nanorix_only" | "customer_only" => recompute_canonical_hash(proof),
            // Any other declared mode is one this build cannot verify. It is NOT
            // "no signature" — see SignatureCheck::Unsupported. Signalled with a
            // sentinel the callers translate, so this fn keeps its Option shape.
            other => return Some(format!("{UNSUPPORTED_MODE_SENTINEL}{other}")),
        },
        _ => return None,
    };
    Some(msg)
}

/// Decode base64 Ed25519 signature + public key and verify `message` under
/// them. Shared by the embedded-key (sub-A) and manifest-key (sub-B) paths,
/// and by the BoundaryAttestation sibling pipeline (`boundary.rs`).
pub(crate) fn verify_message_with_key(
    message: &str,
    sig_b64: &str,
    pub_b64: &str,
) -> SignatureCheck {
    let sig_bytes =
        match base64::engine::general_purpose::STANDARD.decode(strip_base64_prefix(sig_b64)) {
            Ok(b) if b.len() == 64 => b,
            _ => return SignatureCheck::Failed(SignatureFailureReason::Malformed),
        };
    let pub_bytes =
        match base64::engine::general_purpose::STANDARD.decode(strip_base64_prefix(pub_b64)) {
            Ok(b) if b.len() == 32 => b,
            _ => return SignatureCheck::Failed(SignatureFailureReason::PublicKeyMalformed),
        };
    let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return SignatureCheck::Failed(SignatureFailureReason::Malformed),
    };
    let pub_array: [u8; 32] = match pub_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return SignatureCheck::Failed(SignatureFailureReason::PublicKeyMalformed),
    };
    let signature = Signature::from_bytes(&sig_array);
    let verifying_key = match VerifyingKey::from_bytes(&pub_array) {
        Ok(k) => k,
        Err(_) => return SignatureCheck::Failed(SignatureFailureReason::PublicKeyMalformed),
    };
    match verifying_key.verify_canonical_strict(message.as_bytes(), &signature) {
        Ok(()) => SignatureCheck::Verified,
        Err(_) => SignatureCheck::Failed(SignatureFailureReason::DoesNotVerify),
    }
}

/// The proof's embedded attestation signature (base64), if present + non-empty.
fn embedded_signature(proof: &Value) -> Option<&str> {
    proof
        .pointer("/attestation/signature")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// sub-A — verify the proof's signature against the public key EMBEDDED in the
/// proof's attestation. Proves integrity of the signed view (no signed byte
/// changed since signing), NOT authenticity. Returns `Absent` when no signature/key is present or the
/// version/mode is not signature-verifiable here.
pub fn verify_signature(proof: &Value, cdp_version: &str) -> SignatureCheck {
    let pub_b64 = proof
        .pointer("/attestation/public_key")
        .or_else(|| proof.pointer("/attestation/verification_key"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let (sig_b64, pub_b64) = match (embedded_signature(proof), pub_b64) {
        (Some(s), Some(p)) => (s, p),
        _ => return SignatureCheck::Absent,
    };
    let message = match signed_message(proof, cdp_version) {
        Some(m) => match m.strip_prefix(UNSUPPORTED_MODE_SENTINEL) {
            Some(mode) => return SignatureCheck::Unsupported(mode.to_string()),
            None => m,
        },
        None => return SignatureCheck::Absent,
    };
    verify_message_with_key(&message, sig_b64, pub_b64)
}

/// sub-B — verify the proof's signature against a trust-chain-RESOLVED public
/// key (from the signed manifest), NOT the embedded one. This is what
/// establishes authenticity: a forged proof carrying its own embedded key
/// passes sub-A but fails here, because its key is not the manifest key.
/// Returns `Absent` when the proof has no signature or is not verifiable here.
pub fn verify_signature_against(proof: &Value, cdp_version: &str, pub_b64: &str) -> SignatureCheck {
    let sig_b64 = match embedded_signature(proof) {
        Some(s) => s,
        None => return SignatureCheck::Absent,
    };
    let message = match signed_message(proof, cdp_version) {
        Some(m) => match m.strip_prefix(UNSUPPORTED_MODE_SENTINEL) {
            Some(mode) => return SignatureCheck::Unsupported(mode.to_string()),
            None => m,
        },
        None => return SignatureCheck::Absent,
    };
    verify_message_with_key(&message, sig_b64, pub_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    /// The wire form of `test_cdp` in `the AuditProof document builder()` — the
    /// fixed input behind the server's `golden_canonical_hash` test. Only the
    /// fields the canonical view actually reads are present; excluded fields
    /// (residency, final_hash, destruction_trigger, the main attestation, the
    /// reserved slots) are omitted because the view never reads them.
    fn golden_input() -> serde_json::Value {
        json!({
            "cdp_version": "2.1",
            "capsule_id": "cap_test_0001",
            "signing_key_version": "1",
            "activity": [],
            "chain": [],
            "signing_mode": "nanorix_only",
            "jurisdiction": "us",
            "authority_id": "us-kms-nanorix-v1",
            "org_id": "00000000-0000-0000-0000-000000000001",
            "destruction_state": "complete",
            "hash_algorithm": "SHA-512",
            "signature_algorithm": "Ed25519"
        })
    }

    /// BYTE-EXACTNESS LOCK against the signer. The offline recompute must equal
    /// the server's golden `402f533e…` (`golden_canonical_hash` in the reference implementation)
    /// for the same input. If the server's canonical view ever changes this
    /// digest changes too and BOTH goldens must be updated in lockstep — this
    /// is the cross-crate guard that keeps the independent offline verifier from
    /// silently drifting away from how proofs are actually signed.
    #[test]
    fn canonical_recompute_matches_server_golden() {
        assert_eq!(
            recompute_canonical_hash(&golden_input()),
            "402f533e81d78a05f386bee62a919436b8eacdea2c49397d54547bbd19dabce47bc95143635ee6d487e35eee037fec31ebd1f8f88b2f3f36ae2908324c74aabe",
            "offline canonical recompute drifted from the server golden"
        );
    }

    /// `customer_declared_activity_root` is canonical-bound when
    /// present and invisible when absent. Three facts pinned: (1) the golden
    /// input, which carries no root, still hashes to `402f533e…`; (2) a
    /// document carrying the root hashes differently — so a signature made
    /// without it does not cover a later-injected root, and a signature made
    /// with it breaks if the root is altered; (3) `null` is treated as absent,
    /// exactly like the two Merkle roots beside it.
    #[test]
    fn customer_declared_activity_root_is_canonical_bound_only_when_present() {
        const GOLDEN: &str = "402f533e81d78a05f386bee62a919436b8eacdea2c49397d54547bbd19dabce47bc95143635ee6d487e35eee037fec31ebd1f8f88b2f3f36ae2908324c74aabe";
        let without = golden_input();
        assert_eq!(recompute_canonical_hash(&without), GOLDEN);

        let mut with_root = golden_input();
        with_root["customer_declared_activity_root"] = json!(
            "sha512:eeaf4d8e1236e12b43441daafff96d0cd178e2785664eea2ff261574522204a9f908540a12eac5a2292b487c49f2c24f008e8e6e07ea9b9508fb07dcec90f87b"
        );
        let with_hash = recompute_canonical_hash(&with_root);
        assert_ne!(with_hash, GOLDEN, "a carried root must move the hash");

        let mut other_root = with_root.clone();
        other_root["customer_declared_activity_root"] = json!(
            "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_ne!(
            recompute_canonical_hash(&other_root),
            with_hash,
            "a different root must produce a different hash"
        );

        let mut null_root = golden_input();
        null_root["customer_declared_activity_root"] = Value::Null;
        assert_eq!(
            recompute_canonical_hash(&null_root),
            GOLDEN,
            "an explicit null is absent, not a value"
        );
    }

    /// Sign-then-verify roundtrip over the recomputed canonical hash (the
    /// production v2.1 `nanorix_only` message). Proves (1) a correctly signed
    /// proof verifies, (2) flipping a canonical-bound field (jurisdiction — the
    /// exact corpus `08` drift case) is caught even though it does NOT touch the
    /// 8-step chain / `final_hash` (the property a final_hash-only verifier
    /// would MISS), and (3) an unsigned proof reports `Absent`, never a false
    /// pass.
    #[test]
    fn roundtrip_verify_and_catch_canonical_drift() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let canonical = recompute_canonical_hash(&golden_input());
        let sig = key.sign(canonical.as_bytes());

        let mut signed = golden_input();
        signed["attestation"] = json!({
            "algorithm": "Ed25519",
            "public_key": base64::engine::general_purpose::STANDARD
                .encode(key.verifying_key().to_bytes()),
            "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        });
        assert_eq!(verify_signature(&signed, "2.1"), SignatureCheck::Verified);

        let mut drifted = signed.clone();
        drifted["jurisdiction"] = json!("eu");
        assert!(matches!(
            verify_signature(&drifted, "2.1"),
            SignatureCheck::Failed(_)
        ));

        assert_eq!(
            verify_signature(&golden_input(), "2.1"),
            SignatureCheck::Absent
        );
    }

    /// The golden input relabelled as a customer-signed proof. The digest was
    /// computed independently by the Python verifier's recompute, which also
    /// reproduces `402f533e…` for the unrelabelled input.
    const CUSTOMER_ONLY_GOLDEN: &str = "7c44dbde61de1b8aed00683c4cd116ef93a08a93340302ddccc8e8c1c90697d64f2c22014537de74759c9f7ce7cf7960337c50d7bdcd9c84a0156ebe6b9ab44d";

    fn customer_only_input() -> serde_json::Value {
        let mut input = golden_input();
        input["signing_mode"] = json!("customer_only");
        input["authority_id"] = json!("us-customer-kms-acme-v1");
        // A final_hash distinct from every canonical digest, so a message
        // built from it can never pass for the canonical view.
        input["final_hash"] = json!(format!("sha512:{}", "ab".repeat(64)));
        input
    }

    #[test]
    fn customer_only_signs_the_canonical_view_on_2_1_and_2_2() {
        let input = customer_only_input();
        assert_eq!(recompute_canonical_hash(&input), CUSTOMER_ONLY_GOLDEN);
        for version in ["2.1", "2.2"] {
            let message = signed_message(&input, version).expect("a message");
            assert_eq!(message, CUSTOMER_ONLY_GOLDEN, "{version}");
            assert_ne!(message, "ab".repeat(64), "{version}");
        }
        // The mode string is bound: the same view under nanorix_only hashes
        // differently, so a mode edit after signing breaks the signature.
        let mut relabelled = input.clone();
        relabelled["signing_mode"] = json!("nanorix_only");
        assert_ne!(recompute_canonical_hash(&relabelled), CUSTOMER_ONLY_GOLDEN);
    }

    #[test]
    fn customer_only_roundtrip_and_mode_edit() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut signed = customer_only_input();
        let sig = key.sign(CUSTOMER_ONLY_GOLDEN.as_bytes());
        signed["attestation"] = json!({
            "algorithm": "Ed25519",
            "public_key": base64::engine::general_purpose::STANDARD
                .encode(key.verifying_key().to_bytes()),
            "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        });
        let pub_b64 =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        for version in ["2.1", "2.2"] {
            assert_eq!(verify_signature(&signed, version), SignatureCheck::Verified);
            assert_eq!(
                verify_signature_against(&signed, version, &pub_b64),
                SignatureCheck::Verified
            );
        }
        let mut edited = signed.clone();
        edited["signing_mode"] = json!("nanorix_only");
        assert_eq!(
            verify_signature(&edited, "2.1"),
            SignatureCheck::Failed(SignatureFailureReason::DoesNotVerify)
        );
    }

    #[test]
    fn only_the_two_exact_modes_are_verifiable() {
        for mode in [
            "Customer_Only",
            "CUSTOMER_ONLY",
            "customer_onlyx",
            "customer",
            "customer-only",
            " customer_only",
            "dual_signature",
            "tee_attested",
        ] {
            let mut input = customer_only_input();
            input["signing_mode"] = json!(mode);
            let message = signed_message(&input, "2.1").expect("a sentinel");
            assert_eq!(
                message,
                format!("{UNSUPPORTED_MODE_SENTINEL}{mode}"),
                "{mode:?}"
            );
        }
    }
}

#[cfg(test)]
mod strict_tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    struct Vector {
        name: String,
        pk: [u8; 32],
        sig: [u8; 64],
        msgs: Vec<String>,
        dalek_permissive: bool,
    }

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/ed25519_strict_negative.json"
        )))
        .unwrap()
    }

    fn parse_vector(v: &serde_json::Value) -> Vector {
        Vector {
            name: v["name"].as_str().unwrap().to_string(),
            pk: unhex(v["public_key_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            sig: unhex(v["signature_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            msgs: v["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap().to_string())
                .collect(),
            dalek_permissive: v["permissive_accepts"]["dalek"].as_bool().unwrap_or(false),
        }
    }

    /// Vectors every verifier must refuse (`must_reject`).
    fn strict_vectors() -> Vec<Vector> {
        let doc = fixture();
        let all = doc["vectors"].as_array().unwrap();
        let out: Vec<Vector> = all
            .iter()
            .filter(|v| v["must_reject"].as_bool() == Some(true))
            .map(parse_vector)
            .collect();
        assert_eq!(out.len(), all.len(), "every vector must set must_reject");
        out
    }

    fn encodings(key: &str) -> Vec<[u8; 32]> {
        fixture()[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| unhex(h.as_str().unwrap()).try_into().unwrap())
            .collect()
    }

    #[test]
    fn verify_message_with_key_refuses_every_vector() {
        let b64 = base64::engine::general_purpose::STANDARD;
        for v in strict_vectors() {
            for m in &v.msgs {
                let r = verify_message_with_key(m, &b64.encode(v.sig), &b64.encode(v.pk));
                assert!(matches!(r, SignatureCheck::Failed(_)), "{}", v.name);
            }
        }
    }

    #[test]
    fn verify_message_with_key_refuses_weak_encodings_refusal_only() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut base = [0x66u8; 32];
        base[0] = 0x58;
        let mut all = encodings("small_order_point_encodings_hex");
        all.extend(encodings("non_canonical_point_encodings_hex"));
        assert_eq!(all.len(), 34);
        for enc in all {
            let as_key = [base, one].concat();
            let r = verify_message_with_key("m", &b64.encode(as_key), &b64.encode(enc));
            assert!(matches!(r, SignatureCheck::Failed(_)));
            let as_r = [enc, one].concat();
            let r = verify_message_with_key("m", &b64.encode(as_r), &b64.encode(base));
            assert!(matches!(r, SignatureCheck::Failed(_)));
        }
    }

    #[test]
    fn dalek_permissive_verify_matches_the_fixture_verdict() {
        use ed25519_dalek::Verifier as _;
        let mut accepted = 0;
        for v in strict_vectors() {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&v.pk).unwrap();
            let sig = ed25519_dalek::Signature::from_bytes(&v.sig);
            for m in &v.msgs {
                assert_eq!(
                    vk.verify(m.as_bytes(), &sig).is_ok(),
                    v.dalek_permissive,
                    "{}",
                    v.name
                );
                accepted += usize::from(v.dalek_permissive);
            }
        }
        assert!(
            accepted >= 12,
            "expected permissive-accepted vectors, got {accepted}"
        );
    }
}
