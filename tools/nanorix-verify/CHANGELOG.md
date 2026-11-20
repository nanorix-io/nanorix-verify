# Changelog

Notable changes to the `nanorix-verify` command. The crate takes the workspace
version, so a change here is not marked by a version of its own.

## Unreleased

### Population checks (amended 2026-11-16)

- Every time a population check compares is read under one grammar: `YYYY-MM-DDTHH:MM:SS`, an optional `.` and 1 to
  9 digits, then an upper case `Z`, from year 0001, with seconds from 00 to 59. A key version's `effective_from` or
  `archived_at` written with an offset (`+00:00` included), in lower case, with a space for `T`, with second `60`, in
  year 0000 or with a fraction of more than 9 digits was read before and now fails (f) with
  `head_outside_key_window`; a named document's destruction time written so fails (c) with
  `head_issued_before_proof`. A head whose own `issued_at` is in year 0000 was read before and now fails (a) with
  `head_malformed`. Proof verification reads its times as before.
- The library reads the population tick of the specification (`population_tick`): its members, its signed messages, its
  seal and salt, and its log key pin, with shared vectors in `fixtures/population_tick/`. It refuses a tick whose
  bytes are not their own RFC 8785 form and a member written `null`. No command reads ticks yet, so (d) and (e) still
  report `not_checked`.
- Population check (f) reads version 2 heads, signed with Ed25519 and the key version's ML-DSA-65
  partner. Under a hybrid pin it checks both halves: a `pqc_signing_key_version` that is not the partner fails with
  `head_signing_key_unknown`, and an ML-DSA-65 half that does not verify with the new reason
  `head_pqc_signature_invalid`. A version 2 head missing either half fails (a) with `head_malformed`, and so does a
  version 1 head carrying `pqc_signing_key_version` or `pqc_signature`, `null` included. Without a key list a version
  2 head failed (a) with `head_malformed` at `head.type` before; now it is read, and (f) reports `not_checked`
  ("needs a registered key list"), as for a version 1 head. Under a `sha256:` pin a version 2 head fails (f) with
  `head_algorithm_unsupported` (`nanorix-population-head-v2 (classical pin)`). A head naming a BYOC document still fails (c) with
  `tip_matches_no_proof`, because a document carrying `pqc_attestation` has no leaf yet.

### BYOC hybrid key lists

- `--identity-fingerprint` takes a `hybrid1-sha256:` pin, a BYOC install's, beside the `sha256:` pin of the hosted
  service. Under it a key list must carry both identity keys (Ed25519 and ML-DSA-87). The pin is recomputed from both
  keys, and both list signatures must verify. Every Ed25519 key version must name its ML-DSA-65 partner, and every
  authority id must carry the install's pin. Each refusal is typed and exits `2` before any proof is read.
- Under a hybrid pin no record, version 1 population head or boundary attestation is reported verified yet, because
  none of them carries an ML-DSA half this release checks:
  - a record whose key resolves fails at stage 8 (stage 7 for a 1.0 record) with `algorithm_unsupported`
    (`ML-DSA-65 record check (hybrid pin)`);
  - an unsigned record, which ends valid at stage 4 otherwise, fails there with the same reason;
  - in the library, a record checked with a hybrid pin and no key list, which ended valid at stage 7 before, fails
    there with the same reason;
  - population check (f) fails with `head_algorithm_unsupported` at the first version 1 head;
  - `boundary verify` exits `2`.
- The library treats a key list given with no pin as under a hybrid pin when the list's own `identity_fingerprint`
  is one, as boundary verification already did.
- Under a `sha256:` pin, key lists change as follows:
  - a list with post-quantum identity members added after signing loaded before and is now refused
    (`signature_invalid`); a list whose signature covers those members was already refused (`signature_invalid`),
    and is now refused as `pqc_identity_under_classical_pin`;
  - a list whose authority id contains `hybrid1` loaded before and is now refused (`byoc_authority_needs_hybrid_pin`,
    or `byoc_authority_id_malformed`);
  - a list whose signature covers a record's `pqc_partner_version` was refused before (`signature_invalid`, since the
    member was left out of the signed payload) and now loads. The member means nothing under a `sha256:` pin, and no
    list the hosted service has published carries it.

  Under a hybrid pin an authority id outside 1 to 128 bytes of `a`-`z`, `0`-`9`, `.`, `_` and `-` is refused
  (`authority_id_malformed`).

  The hosted list keeps its signed bytes and still loads.

### Breaking: exit 0 now means verified

A CI gate that runs `nanorix-verify proof.json` with no key list starts failing
with exit 4 after this change. That is the intended result: before, it exited 0
on a signature checked only against the key the proof carries, which a proof
signed with a freshly made key also passes.

- `nanorix-verify <file>` and `verify <file>` exit `4` (not anchored) at stage 7:
  the signature is valid against the key the proof carries, and no key list
  anchored that key: none was given, or the proof is `cdp_version` `1.0`. They
  exited `0` before. Exit `0` now needs stage 8.
- `batch <directory>` exits `1` when any file is `not_verified`, otherwise `4`
  when any file is `not_anchored`, otherwise `0`. Before, a batch whose files
  were all valid exited `0` even when none was anchored.
- `batch` on a directory with no matching file exits `2`. It exited `0` with a
  total of `0`, so a CI glob that matched nothing looked like a batch whose
  every file was verified.
- `--identity-fingerprint` without `--trust-chain` is refused with exit `2`
  before any proof is read, as the Go and Python verifiers refuse it. It was
  dropped before, and the proof ended at stage 7.
- A `cdp_version` `1.0` proof never reaches `0`: its signature covers `final_hash`
  alone, which binds `destroyed_at` and the two optional Merkle roots. It does not
  bind the capsule_id itself (only through record receipts, which a holder can
  remove), the region or the key id. Under a key list it is checked as a `2.1`
  proof is (key lookup, signature against the listed key, revocation), so the list
  can still refuse it, and where a `2.1` proof would reach `0` it exits `4`; its
  result names no capsule and no region. In `batch`, a `1.0` file is never
  `verified`.
- Single-file `--json` output gains `status`: `verified`, `not_anchored` or
  `not_verified`, as each `batch` entry already carried. `valid` keeps its
  meaning and is true at stage 7 and at stage 4; read `status` or the exit code.
- To reach exit `0`, pass the signed key list and the fingerprint pinned for it:
  `nanorix-verify --trust-chain trust-chain.json --identity-fingerprint sha256:... proof.json`,
  with the list from https://verify.nanorix.io/.well-known/trust-chain.json and
  the fingerprint from https://verify.nanorix.io/.well-known/identity.txt,
  confirmed through a channel you trust.
- `verify_auditproof` in the library ends at stage 7 (`not_anchored`) when
  `VerifierPolicy::trust_chain` is set and `pinned_identity_fingerprint` is
  not. It reached stage 8 (`verified`) before, on a key list whose own
  signature nothing checked, so a list made by whoever made the proof
  anchored it. A manifest from `TrustChainManifest::into_verified` is treated
  the same way: its signature was checked when it was built, but the policy
  carries no pin, so the library cannot tell which pin. The command line was
  not affected: `--trust-chain` without `--identity-fingerprint` exits `1`.
  Migration: set `pinned_identity_fingerprint` beside `trust_chain`.

### Breaking: browser verifier (verify page, homepage demo, auditor portal)

The verify page, the homepage demo and the auditor portal keep no changelog of
their own, so their entry sits here under its own heading.

- 2026-11-13: the engine inlined in the verify page, which the homepage demo
  loads as `engine.<hash>.js` and the auditor portal as `verify-engine.js`,
  takes a `pin` option beside `trustChain`. A manifest given without a pin now
  ends at stage 7 (`not_anchored`); it reached stage 8 (`verified`) before. A
  manifest whose signature does not check against the pin ends at stage 6 with
  `signing_key_version_unknown`. With a pin, keys are read from the copy of the
  manifest whose signature was checked. The verify page and the auditor portal
  pass the pin they hold. Migration: code that loads `engine.<hash>.js` itself
  passes `pin` with `trustChain`.

### Deprecated

- `VerificationResult::valid` in the library is deprecated as a verdict, with
  a `#[deprecated]` attribute, so code outside the crate that reads it gets a
  warning. New `VerificationResult::status()` and `VerificationResult::ok()`
  give the verdict that the exit code and the `--json` `status` already use:
  `verified` only at stage 8. The field keeps its value and its JSON meaning;
  the crate allows its own uses, since it builds the field on every
  verification path.
- Each `.expected.json` in `fixtures/corpus/` now carries `status`, and the
  corpus test asserts it. `index.json` describes the new key and no longer
  calls `valid` the accept or reject decision.

### Changed

- `boundary verify` and `bundle verify` keep exit `0` when the signature holds
  against the key the document carries, which a proof exits `4` for. Their
  success lines now say the key was not anchored, `boundary verify` prints a
  note on stderr when no key list anchored every attestation, and the README
  exit table names both as exceptions.
- The exit-4 hint says both `curl`s reach the same host and asks you to compare
  the fingerprint with one you got another way; the README prints the published
  fingerprint beside them. The help text names `verify.nanorix.io` where it
  named the old host.
- `bundle verify` refuses `--trust-chain` with exit `2`. It checks a bundle
  against the key the bundle carries and does not read a key list yet, so a key
  list given to it was ignored before.
- `--reject-diagnostic` refuses, at stage 2 with `diagnostic_proof_refused` and
  exit `1`, an AuditProof whose signed activity trail records diagnostic mode
  (a `diagnostic_mode_enabled` event), and every AuditProof whose activity is
  unsigned, so that it cannot show it was not run in diagnostic mode:
  `cdp_version` 1.0, or 2.1 or 2.2 without a signature. The flag, and
  `VerifierPolicy::reject_diagnostic` in the library, were accepted and refused
  nothing before. Only a `verified` result (stage 8, with `--trust-chain`) ties
  the trail to a Nanorix key. `bundle verify` refuses the flag with exit `2`.
- `--required-region`, and `VerifierPolicy::required_region` in the library,
  refuse every AuditProof whose region is unsigned (`cdp_version` 1.0, or 2.1
  or 2.2 without a signature) at stage 2 with `region_mismatch` and an empty
  `actual`. 1.0 signs only `final_hash`, and no signature covers the trail of a
  2.1 or 2.2 proof without one, so anyone could add a `capsule_started` region
  equal to the pin; before, the pin accepted it. Signed 2.1 and 2.2 AuditProofs
  are compared as before. Only a `verified` result (stage 8, with
  `--trust-chain`) ties the region to a Nanorix key. The metadata still reports
  the region a document states.
- `bundle verify`, `boundary verify` and `pubkey-bundle verify` refuse each
  proof policy flag (`--reject-diagnostic`, `--required-region`,
  `--required-authority-id`, `--customer-activity`) with exit `2`, before any
  file is read, as `population` refuses them. None of them reads an AuditProof:
  a bundle carries one record's receipt, a boundary attestation is its own
  document, and a pubkey bundle carries public keys, so a region, authority or
  activity record given to them was ignored before.
- `pubkey-bundle verify` refuses `--trust-chain` with exit `2`, before any
  file is read. It checks the publisher signature against the key file given
  with `--publisher-pubkey` and reads no key list, so a list given to it was
  ignored and the command exited `0`. Its help says exit `0` anchors no key in
  the bundle. `--identity-fingerprint` alone was already refused with exit `2`.
- `BundleVerification::status()` in the library gives `not_anchored` when
  `is_valid()` holds and `not_verified` otherwise, never `verified`: a bundle
  is checked against the key it carries. `is_valid()` and an `Ok(())` from
  `verify_receipt_bundle` keep their meaning and are now documented as
  integrity only. The Go verifier's `BundleVerification.Status()` gives the
  same answer, and a nil error from its `VerifyReceiptBundle` is documented
  the same way.
- The library re-checks a trust-chain manifest against
  `VerifierPolicy.pinned_identity_fingerprint` when both are set. A manifest the
  pin did not sign resolves no key: stage 6, `signing_key_version_unknown`.

### Fixed

- `--help`, `-h`, `--version` and `-V` now print and exit `0` only alone or
  after subcommand words (`nanorix-verify bundle extract --help`). Beside any
  other flag or a file they exit `2` with a usage line on stderr and nothing on
  stdout. Before, each printed and exited `0` without reading the rest of the
  line, so `nanorix-verify --version forged.json`, `-Vforged.json` and
  `forged.json help` exited `0` for a proof that alone exits non-zero. The Go
  verifier's `-help`, `-h` and `-version` (one dash or two) and the `nanorix`
  CLI's `--help`, `-h`, `--version` and `-V` follow the same rule, and so does
  the Python SDK's `python -m nanorix --version`, `-v` and `version`. The
  TypeScript script has no version or help flag and refuses a second argument.
