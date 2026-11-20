//! `nanorix-verify population` end to end.
//!
//! Each test runs the real binary over the head vectors, so the exit code an
//! auditor's script reads and the check lines an auditor reads are pinned
//! against the library's results. There is no exit 0: without checks (d) and
//! (e) nothing shows that the handed heads are every head.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN_PATH: &str = env!("CARGO_BIN_EXE_nanorix-verify");
const VECTORS: &str = include_str!("../fixtures/population_head/population_head_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn case<'a>(doc: &'a Value, name: &str) -> &'a Value {
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("case {name}"))
}

fn write(path: &Path, value: &Value) -> PathBuf {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).expect("write");
    path.to_path_buf()
}

/// The case's proofs in `dir/proofs`, its heads in `dir/heads.json` and the
/// key list in `dir/key_list.json`.
fn lay_out(doc: &Value, name: &str, dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let case = case(doc, name);
    let proofs = dir.join("proofs");
    std::fs::create_dir(&proofs).unwrap();
    for (i, id) in case["proofs"].as_array().unwrap().iter().enumerate() {
        let proof = &doc["proof_pool"][id.as_str().unwrap()];
        write(&proofs.join(format!("{i:03}.json")), proof);
    }
    let heads = write(&dir.join("heads.json"), &case["heads"]);
    let key_list = write(&dir.join("key_list.json"), &doc["key_list"]);
    (proofs, heads, key_list)
}

fn pin(doc: &Value) -> &str {
    doc["key_list_identity_fingerprint"].as_str().unwrap()
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN_PATH).args(args).output().expect("spawn")
}

fn population(key_list: &Path, pin: &str, proofs: &Path, heads: &Path, json: bool) -> Output {
    let mut args = vec![
        "--trust-chain",
        key_list.to_str().unwrap(),
        "--identity-fingerprint",
        pin,
    ];
    if json {
        args.push("--json");
    }
    args.extend([
        "population",
        proofs.to_str().unwrap(),
        "--heads",
        heads.to_str().unwrap(),
    ]);
    run(&args)
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_clean_population_exits_3_and_prints_every_check() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    let text = stdout(&out);
    for line in [
        "(a) chain links: ok",
        "(b) sequence contiguous: ok",
        "(c) tips match proofs: ok",
        "(d) log inclusion: not checked, needs a transparency log",
        "(e) log population: not checked, needs a transparency log",
        "(f) head signatures: ok",
        "population not externally witnessed",
        "does not show that they are every proof or every head",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    assert!(stderr(&out).contains("exiting 3"));
}

#[test]
fn json_output_is_the_library_result() {
    let doc = vectors();
    for name in ["good_chain", "relabelled_authority"] {
        let dir = tempfile::tempdir().unwrap();
        let (proofs, heads, key_list) = lay_out(&doc, name, dir.path());
        let out = population(&key_list, pin(&doc), &proofs, &heads, true);
        let got: Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
        assert_eq!(got, case(&doc, name)["expected"], "{name}");
    }
}

#[test]
fn a_failed_check_exits_1_and_names_it() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "relabelled_authority", dir.path());
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).contains("(f) head signatures: failed, head 1 signature does not verify"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_proof_no_head_names_is_listed() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(
        &doc,
        "proof_under_authority_not_in_the_key_list",
        dir.path(),
    );
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stdout(&out).contains("proof 0: NoHandedHead, sha512:"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn files_and_directories_are_read_in_the_order_given() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());
    let first = proofs.join("000.json");
    let rest = dir.path().join("rest");
    std::fs::create_dir(&rest).unwrap();
    std::fs::rename(proofs.join("001.json"), rest.join("001.json")).unwrap();
    std::fs::rename(proofs.join("002.json"), rest.join("002.json")).unwrap();
    let out = run(&[
        "--trust-chain",
        key_list.to_str().unwrap(),
        "--identity-fingerprint",
        pin(&doc),
        "--json",
        "population",
        first.to_str().unwrap(),
        rest.to_str().unwrap(),
        "--heads",
        heads.to_str().unwrap(),
    ]);
    let got: Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert_eq!(got, case(&doc, "good_chain")["expected"]);
}

#[test]
fn no_key_list_is_refused_before_anything_is_read() {
    let out = run(&[
        "population",
        "/nonexistent/proof.json",
        "--heads",
        "/nonexistent/heads.json",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("needs --trust-chain"));
}

#[test]
fn a_key_list_under_another_pin_is_refused() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());
    let other = format!("sha256:{}", "0".repeat(64));
    let out = population(&key_list, &other, &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("verification FAILED"));
}

#[test]
fn a_key_list_that_cannot_be_loaded_or_pinned_is_a_setup_error() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());

    let out = population(
        &dir.path().join("absent.json"),
        pin(&doc),
        &proofs,
        &heads,
        false,
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("failed to load trust-chain manifest"));

    let out = run(&[
        "--trust-chain",
        key_list.to_str().unwrap(),
        "population",
        proofs.to_str().unwrap(),
        "--heads",
        heads.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("no pinned identity fingerprint"));
}

#[test]
fn a_key_list_holding_bytes_its_signature_does_not_cover_is_a_setup_error() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, _) = lay_out(&doc, "good_chain", dir.path());
    for text in doc["key_list_texts"].as_array().unwrap() {
        let name = text["name"].as_str().unwrap();
        let key_list = dir.path().join(format!("{name}.json"));
        std::fs::write(&key_list, text["text"].as_str().unwrap()).unwrap();
        let out = population(&key_list, pin(&doc), &proofs, &heads, false);
        if text["member"].is_null() {
            assert_eq!(out.status.code(), Some(3), "{name}: {}", stderr(&out));
            continue;
        }
        assert_eq!(out.status.code(), Some(2), "{name}");
        assert!(out.stdout.is_empty(), "{name}");
        let wording = match text["member"]["kind"].as_str().unwrap() {
            "repeated" => "is written twice",
            _ => "is not covered by the signature",
        };
        let pointer = text["member"]["pointer"].as_str().unwrap();
        let err = stderr(&out);
        assert!(
            err.contains("its signature does not cover"),
            "{name}: {err}"
        );
        assert!(
            err.contains(&format!("{pointer:?} {wording}")),
            "{name}: {err}"
        );
    }
}

#[test]
fn the_key_list_read_is_printed() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert!(stdout(&out).contains(&format!(
        "Key list: issued {}, identity {}",
        doc["key_list"]["issued_at"].as_str().unwrap(),
        pin(&doc)
    )));
}

#[test]
fn the_key_list_line_cannot_write_to_the_terminal() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, _) = lay_out(&doc, "good_chain", dir.path());
    let key_list = write(
        &dir.path().join("forged.json"),
        &doc["key_list_issued_at_writes_a_line"],
    );
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(!text.contains('\u{1b}'), "{text}");
    let lines = text
        .lines()
        .filter(|l| l.trim_start().starts_with("\u{2713} (f)"));
    assert_eq!(lines.count(), 1, "{text}");
    assert!(text.contains(r"\u{1b}[2K"), "{text}");
}

#[test]
fn a_file_name_in_a_setup_error_cannot_write_to_the_terminal() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());
    std::fs::write(proofs.join("x\u{1b}[2K\n.json"), b"not json").unwrap();
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(2));
    let text = stderr(&out);
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_eq!(text.trim_end().lines().count(), 1, "{text}");
}

#[test]
fn a_key_list_path_in_a_setup_error_cannot_write_to_the_terminal() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, _) = lay_out(&doc, "good_chain", dir.path());
    let missing = dir.path().join("x\u{1b}[2K\n.json");
    let out = population(&missing, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(2));
    let text = stderr(&out);
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_eq!(text.trim_end().lines().count(), 1, "{text}");
}

#[test]
fn a_reason_quoting_a_proof_cannot_write_to_the_terminal() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "proof_authority_writes_a_line", dir.path());
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(!text.contains('\u{1b}'), "{text}");
    let forged = text
        .lines()
        .filter(|l| l.trim_start().starts_with("\u{2713} (f)"));
    assert_eq!(forged.count(), 0, "{text}");
    assert!(text.contains(r"\u{1b}[2K"), "{text}");
}

#[test]
fn a_member_name_in_a_heads_refusal_cannot_write_to_the_terminal() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());
    let genuine = std::fs::read_to_string(&heads).unwrap();
    let name = "\"x\\u001b[2K\u{202e}\": 0";
    let forged = genuine.replacen('{', &format!("{{{name}, {name}, "), 1);
    assert_ne!(forged, genuine);
    std::fs::write(&heads, forged).unwrap();
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(2));
    let text = stderr(&out);
    assert!(text.contains("writes member"), "{text}");
    assert!(text.contains(r"\u{1b}[2K"), "{text}");
    let message = text.strip_prefix("\u{2717} ").expect("a setup error line");
    let outside = message
        .bytes()
        .find(|b| !(b.is_ascii_graphic() || *b == b' ' || *b == b'\n'));
    assert_eq!(outside, None, "{text}");
    assert_eq!(text.trim_end().lines().count(), 1, "{text}");
}

#[test]
fn a_file_that_cannot_be_read_is_a_setup_error() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());

    let not_array = write(&dir.path().join("object.json"), &serde_json::json!({}));
    let out = population(&key_list, pin(&doc), &proofs, &not_array, false);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("not a JSON array"),
        "{}",
        stderr(&out)
    );

    let object_writing_twice = dir.path().join("object_writing_twice.json");
    std::fs::write(&object_writing_twice, r#"{"a": 1, "a": 2}"#).unwrap();
    let out = population(&key_list, pin(&doc), &proofs, &object_writing_twice, false);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("not a JSON array"),
        "{}",
        stderr(&out)
    );

    let missing = dir.path().join("missing.json");
    let out = population(&key_list, pin(&doc), &proofs, &missing, false);
    assert_eq!(out.status.code(), Some(2));

    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let out = population(&key_list, pin(&doc), &empty, &heads, false);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("no proofs found"), "{}", stderr(&out));

    std::fs::copy(&heads, proofs.join("heads.json")).unwrap();
    let out = population(&key_list, pin(&doc), &proofs, &heads, false);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("not an AuditProof object"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_proof_policy_flag_is_refused_rather_than_ignored() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "good_chain", dir.path());
    for flag in [
        vec!["--reject-diagnostic"],
        vec!["--required-region", "europe-west1"],
        vec!["--required-authority-id", "customer-kms-example-a-v1"],
        vec!["--customer-activity", "/nonexistent/activity.jsonl"],
    ] {
        let mut args = vec![
            "--trust-chain",
            key_list.to_str().unwrap(),
            "--identity-fingerprint",
            pin(&doc),
        ];
        args.extend(&flag);
        args.extend([
            "population",
            proofs.to_str().unwrap(),
            "--heads",
            heads.to_str().unwrap(),
        ]);
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{flag:?}");
        assert!(out.stdout.is_empty(), "{flag:?}");
    }
}

#[test]
fn json_output_holds_only_printable_ascii() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, heads, key_list) = lay_out(&doc, "proof_authority_writes_a_line", dir.path());
    let out = population(&key_list, pin(&doc), &proofs, &heads, true);
    assert_eq!(out.status.code(), Some(1));
    let outside = out
        .stdout
        .iter()
        .find(|b| !(b.is_ascii_graphic() || **b == b' ' || **b == b'\n'));
    assert_eq!(outside, None, "{}", stdout(&out));
    let got: Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert_eq!(got, case(&doc, "proof_authority_writes_a_line")["expected"]);
}

#[test]
fn a_heads_file_writing_a_member_twice_is_a_setup_error() {
    let doc = vectors();
    let dir = tempfile::tempdir().unwrap();
    let (proofs, _, key_list) = lay_out(&doc, "good_chain", dir.path());
    for text in doc["head_texts"].as_array().unwrap() {
        let name = text["name"].as_str().unwrap();
        let heads = dir.path().join(format!("{name}.json"));
        std::fs::write(&heads, text["text"].as_str().unwrap()).unwrap();
        let out = population(&key_list, pin(&doc), &proofs, &heads, false);
        if text["member"].is_null() {
            assert_eq!(out.status.code(), Some(3), "{name}: {}", stderr(&out));
            continue;
        }
        assert_eq!(out.status.code(), Some(2), "{name}");
        assert!(out.stdout.is_empty(), "{name}");
        let pointer = text["member"]["pointer"].as_str().unwrap();
        let err = stderr(&out);
        assert!(
            err.contains(&format!("writes member {pointer:?} twice")),
            "{name}: {err}"
        );
    }
}
