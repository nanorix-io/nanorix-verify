# ML-DSA signature verification vectors

Shared test vectors for the ML-DSA (FIPS 204) primitive check: verify one signature over one message
with one public key, for ML-DSA-65 and ML-DSA-87, pure ML-DSA (not HashML-DSA) with an empty context.
Every verifier that checks ML-DSA is held to the same verdict on every case here. The Rust check is
`src/mldsa.rs`; `tests/mldsa_vectors.rs` runs every case in this folder through it.

These vectors test a primitive only. They say nothing about records, key lists or any other format.

## Files

| File | Source | Parameter set | Cases | Valid | Invalid | Bytes |
|---|---|---|---:|---:|---:|---:|
| `acvp_ml_dsa_65.json` | NIST ACVP | ML-DSA-65 | 1 | 0 | 1 | 18,548 |
| `acvp_ml_dsa_87.json` | NIST ACVP | ML-DSA-87 | 1 | 0 | 1 | 31,119 |
| `acvp_siggen_ml_dsa_65.json` | NIST ACVP sigGen | ML-DSA-65 | 2 | 2 | 0 | 52,330 |
| `acvp_siggen_ml_dsa_87.json` | NIST ACVP sigGen | ML-DSA-87 | 3 | 3 | 0 | 76,350 |
| `wycheproof_ml_dsa_65.json` | Wycheproof | ML-DSA-65 | 203 | 77 | 126 | 1,501,918 |
| `wycheproof_ml_dsa_87.json` | Wycheproof | ML-DSA-87 | 234 | 69 | 165 | 2,369,834 |
| `mutations_ml_dsa_65.json` | built here | ML-DSA-65 | 19 | 1 | 18 | 145,230 |
| `mutations_ml_dsa_87.json` | built here | ML-DSA-87 | 19 | 1 | 18 | 199,078 |
| `signed_ml_dsa_65.json` | signed for these vectors | ML-DSA-65 | 3 | 2 | 1 | 30,628 |
| `signed_ml_dsa_87.json` | signed for these vectors | ML-DSA-87 | 3 | 2 | 1 | 41,095 |

488 cases and 4,466,130 bytes of JSON in all. `LICENSE-wycheproof.txt` is the Wycheproof licence.

## Counts per parameter set

Counted across each parameter set's five files. "Right lengths" means the key and the signature
both have the set's lengths, so the case reaches the signature check; "wrong length" means the key or
the signature has another length.

| Parameter set | Cases | Valid | Invalid, right lengths | Invalid, wrong length |
|---|---:|---:|---:|---:|
| ML-DSA-65 | 228 | 82 | 134 | 12 |
| ML-DSA-87 | 260 | 75 | 173 | 12 |

The floor: `every_vector_case_gets_its_expected_verdict` (`tests/mldsa_vectors.rs:282`) counts the
four numbers per set while it runs every case, fails if a set has no valid case or no invalid case
of the right lengths (`:316-320`), and fails unless the four numbers equal this table's row for the
set (`:321`, read by `readme_counts` at `:260`). A regeneration that drops valid cases therefore
fails unless this table is changed with it. Any other verifier held to these vectors must carry the
same floor.

## Format

Each file is one JSON object. All byte strings are lowercase hex, and an empty string is zero bytes.

```json
{
  "format": "nanorix-mldsa-sigver/1",
  "parameter_set": "ML-DSA-65",
  "public_key_bytes": 1952,
  "signature_bytes": 3309,
  "source": { "name": "...", "url": "...", "commit": "...", "files": ["..."] },
  "changes": "only in wycheproof_*.json: how the file differs from its source",
  "case_count": 203,
  "groups": [
    {
      "public_key": "<hex>",
      "source": { "name": "github/gendx", "version": "0.1" },
      "cases": [
        {
          "id": "wycheproof-65-tc1",
          "comment": "...",
          "message": "<hex>",
          "signature": "<hex>",
          "expected": "valid",
          "flags": ["ValidSignature"],
          "built": "only in mutations_*.json: how the case was made"
        }
      ]
    }
  ]
}
```

- `expected` is `valid` (the signature must verify) or `invalid` (it must be refused).
- `case_count` is the number of cases in the file. A reader must fail if it reads a different number,
  or if a file has no cases.
- `public_key_bytes` and `signature_bytes` are the parameter set's exact lengths (FIPS 204 Table 2).
  A key or signature of any other length must be refused before the signature is checked.
- `source` (top level) in the two `signed_*.json` files holds only `name` and `url`: those cases
  come from no source file.
- `changes` (top level) and `source` (in each group) appear only in the two Wycheproof files. The
  group `source` is the Wycheproof group's own `source` object, copied unchanged, naming who
  contributed those cases; `changes` states how the file was changed from the Wycheproof file, as
  Apache-2.0 section 4(b) asks. Both are attribution and say nothing about any verdict: a reader must
  accept them and must not use them to decide a case. The fields shown above are the only ones a
  file may hold at file, group or case level: `tests/mldsa_vectors.rs` fails on any other key at
  those levels, on a `built` field in a case outside the `mutations_*.json` and `signed_*.json`
  files, and on a case in those files without one (`tests/mldsa_vectors.rs:188-230`). It does not check the keys inside a `source` object other than `base_source`.
- `base_source` (inside the top-level `source`) appears only in the two mutation files: the
  Wycheproof group `source` of the base case, copied unchanged. It is attribution too, and a reader
  must accept it and must not use it to decide a case.
- `flags` are Wycheproof's flags as the source wrote them, empty for ACVP cases, and one class name
  for each built or signed case. A case flagged `IncorrectPublicKeyLength` or `PublicKeyLength` is refused for
  its key length, and one flagged `IncorrectSignatureLength` or `SignatureLength` for its signature
  length; every other invalid case is refused as a signature that does not verify.

## Sources

### NIST ACVP

- Repository: https://github.com/usnistgov/ACVP-Server
- Commit: `a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324` (the last commit to the folder below, 2026-07-31)
- Files: `gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json` (inputs), `expectedResults.json`
  (verdicts) and `internalProjection.json` (the `reason` text, kept here as `comment`).
- ACVP marks a case's verdict with a boolean field whose name is its own; it is written here as
  `expected: valid` or `expected: invalid`.
- Selection: the source holds 180 cases in 12 groups of 15. Kept: the 2 cases that are ML-DSA-65 or
  ML-DSA-87, external interface, pure, with an empty context. Dropped: 60 ML-DSA-44; 30 pre-hash
  (HashML-DSA); 30 internal interface with external mu; 30 internal interface without external mu;
  28 external pure ML-DSA-65 or ML-DSA-87 with a non-empty context.
- Notice, as the ACVP-Server README requires it be kept intact:

  > NIST-developed software is provided by NIST as a public service. You may use, copy, and
  > distribute copies of the software in any medium, provided that you keep intact this entire
  > notice. You may improve, modify, and create derivative works of the software or any portion of
  > the software, and you may copy and distribute such modifications or works. Modified works should
  > carry a notice stating that you changed the software and should note the date and nature of any
  > such change. Please explicitly acknowledge the National Institute of Standards and Technology as
  > the source of the software.
  >
  > NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND,
  > EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE
  > IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA
  > ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE
  > UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE
  > ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT
  > LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
  >
  > You are solely responsible for determining the appropriateness of using and distributing the
  > software and you assume all risks associated with its use, including but not limited to the
  > risks and costs of program errors, compliance with applicable laws, damage to or loss of data,
  > programs or equipment, and the unavailability or interruption of operation. This software is not
  > intended to be used in any situation where a failure could cause risk of injury or damage to
  > property. The software developed by NIST employees is not subject to copyright protection within
  > the United States.

  Changes, 2026-11-13: the cases were selected by the rule above, converted to this format (hex
  lowercased, the verdict renamed, inputs, verdict and reason joined by group and case id), and
  nothing else changed. Source: the National Institute of Standards and Technology.

### NIST ACVP sigGen

- Repository: https://github.com/usnistgov/ACVP-Server
- Commit: `2972def23bf9f3680c2c531561ed9bdd0f1086ad` (the last commit to the folder below, 2026-07-20)
- Files: `gen-val/json-files/ML-DSA-sigGen-FIPS204/prompt.json` (secret key, message, context and
  `rnd`), `expectedResults.json` (signature) and `internalProjection.json` (public key).
- The public key is only in `internalProjection.json`: `prompt.json` gives each case's `sk` and no
  `pk`, and `expectedResults.json` gives only the signature. For each kept case the builder checked
  that the projection's `sk`, message and signature equal the prompt's and the expected result's,
  that the key's `rho` equals the first 32 bytes of `sk`, and that `tr` in `sk` is SHAKE256 of the
  key (FIPS 204 Algorithm 6).
- Every sigGen case is a signature NIST's generator made, so every kept case is expected valid.
  Its `comment` says whether it was signed deterministically or with the `rnd` NIST gives; `rnd` is
  not carried over, since verification does not use it.
- Selection: the source holds 360 cases in 24 groups of 15. Kept: the 5 cases that are ML-DSA-65 or
  ML-DSA-87, external interface, pure, with an empty context (ML-DSA-65 `tg3-tc44` and `tg15-tc216`;
  ML-DSA-87 `tg5-tc63`, `tg5-tc70` and `tg17-tc252`; ids are written `acvp-siggen-tg<N>-tc<N>`).
  Dropped: 120 ML-DSA-44; 60 pre-hash (HashML-DSA); 60 internal interface with external mu; 60
  internal interface without external mu; 55 external pure ML-DSA-65 or ML-DSA-87 with a non-empty
  context.
- The ACVP-Server notice above applies. Changes, 2026-11-14: the cases were selected by the rule
  above, converted to this format (hex lowercased, the public key taken from
  `internalProjection.json`, `sk`, `rnd`, `context`, `hashAlg` and `deferred` not carried over,
  every case given `expected: valid`), and nothing else changed. Source: the National Institute of Standards
  and Technology.

### Wycheproof

- Repository: https://github.com/C2SP/wycheproof
- Commit: `65ca494727a52944c204441c860b039e6786b99b` (2026-11-11)
- Files: `testvectors_v1/mldsa_65_verify_test.json` (210 cases) and
  `testvectors_v1/mldsa_87_verify_test.json` (241 cases).
- Selection: every case with an empty context is kept, with its `result` as `expected`, its `flags`
  and its `comment`. Dropped: the 7 cases in each file that carry a context (2 valid with 14- and
  510-hex-digit contexts, 5 invalid with an over-long context). Neither file has a pre-hash, an
  external-mu or an internal-interface case, and neither has an `acceptable` result.
- Each Wycheproof group's raw `publicKey` is used; its `publicKeyDer` is not. Each kept group's
  `source` object, which names the contributor of its cases, is kept unchanged in the group.
- Licence: Apache License 2.0, in `LICENSE-wycheproof.txt` (copied from the repository's `LICENSE`
  at the commit above). The cases were converted to this format and selected by the rule above;
  each converted file's `changes` field says exactly what changed, and nothing else did.

### Built cases (`mutations_*.json`)

Each file starts from one Wycheproof case: the first case whose flags are exactly `ValidSignature`,
whose context is empty, whose key has the right length, and whose signature has a hint row with two
or more indices and fewer than omega hints in all (`wycheproof-65-tc1` and `wycheproof-87-tc1`).
That case is repeated first, as `Base`, expected valid; every other case changes one thing in it and
is expected invalid. Each case's `built` field says exactly what changed. Both base cases come from
Wycheproof groups whose `source` is `{"name": "github/gendx", "version": "0.1"}`, kept in each
mutation file as `source.base_source`; the built files are changed from those cases as each `built`
field says, under the Apache License 2.0 in `LICENSE-wycheproof.txt`.

The signature is `c~ || z || h` (FIPS 204 Algorithm 26, `sigEncode`): `c~` is 48 bytes (ML-DSA-65)
or 64 (ML-DSA-87); `z` is l polynomials of 256 coefficients packed at 20 bits, each stored as
gamma1 - z; `h` is omega index bytes followed by k cumulative count bytes (ML-DSA-65: l = 5, k = 6,
omega = 55; ML-DSA-87: l = 7, k = 8, omega = 75).

| Class | What it changes | Why |
|---|---|---|
| `HintRepeatedIndex` | One hint index written twice, later indices and counts moved up by one | The CVE-2026-24850 class: the decoded hints are unchanged, so a decoder that allows a repeat accepts a second encoding of a valid signature |
| `HintOutOfOrder` | Two indices in one row swapped | Same decoded hints, non-canonical order (FIPS 204 Algorithm 21, `HintBitUnpack`) |
| `HintNonZeroPadding` | An unused index slot set to 1 | Same decoded hints, non-zero padding |
| `HintCountOverOmega` | The last count set to omega + 1 | Count out of range |
| `HintCountDecreasing` | A count set below the one before it | Counts must not decrease |
| `ZOutOfRange` | First `z` coefficient set to +(gamma1 - beta), then -(gamma1 - beta) | `z` must have infinity norm below gamma1 - beta |
| `BitFlipCTilde`, `BitFlipZ`, `BitFlipHint` | One bit flipped in `c~`, in `z`, in a hint count and in a hint index | Each part of the signature is bound |
| `SignatureLength` | Signature one byte short, one byte long, empty | Exact length |
| `PublicKeyLength` | Key one byte short, one byte long | Exact length |
| `PublicKeyBitFlip`, `MessageBitFlip` | One bit flipped in the key's `t1`, or in the message | Key and message are bound |

Which built cases isolate their check. A verifier that lacks a check refuses a built case only if
the change also breaks the signature some other way. `hint-repeated-index`, `hint-out-of-order` and
`hint-nonzero-padding` leave the decoded hints exactly as in the base, so a decoder without the check
reads a valid signature: these three refuse only through the check they name. `mutation-*-z-at-bound`,
`mutation-*-z-at-negative-bound`, `hint-count-over-omega` and `hint-count-decreasing` do not isolate their
check: changing `z` or a count also changes what a lax verifier computes, so it still refuses them
through the `c~` comparison: the two `z` cases without the norm check, the two count cases with
every hint check removed. With only the count check
removed, the two count cases are refused by the index-order check.

The Wycheproof files already carry every hint and `z` class above. Each id below was checked against
the source file: the case is expected invalid, its signature holds the named defect, and its source
comment names it. A case isolates its check when a verifier that lacks only that check accepts it.
Each id was run through a separate FIPS 204 verifier, outside this repository, with that one check
removed; the table says which ids isolate their check and which do not.

| Class | `wycheproof_ml_dsa_65.json` | `wycheproof_ml_dsa_87.json` |
|---|---|---|
| Hint indices out of order (reverse order) | `tc16` isolates | `tc18` isolates |
| Repeated hint index | `tc19` isolates | `tc21` isolates |
| Non-zero hint padding | `tc18` isolates | `tc20` isolates |
| Hint count above omega | `tc160` isolates; `tc17`, `tc20`, `tc151`, `tc152` do not | `tc173` isolates; `tc19`, `tc22`, `tc164`, `tc165` do not |
| Decreasing hint count | `tc150` isolates | `tc163` isolates |
| `z` exactly at +(gamma1 - beta) | `tc138` does not | `tc151` isolates |
| `z` exactly at -(gamma1 - beta) | `tc139` isolates | `tc152` isolates |
| `z` beyond the bound | `tc84` to `tc133`: all isolate except `tc89`, `tc96`, `tc100`, `tc101`, `tc105`, `tc107`, `tc108`, `tc119`, `tc123`, `tc133` | `tc77` to `tc146`: all isolate except `tc77`, `tc78`, `tc97`, `tc100`, `tc103`, `tc104`, `tc107`, `tc111` to `tc116`, `tc120`, `tc122`, `tc124`, `tc128`, `tc129`, `tc133`, `tc135` to `tc137`, `tc139` |

The ids that do not isolate their check are refused another way. The comments on ML-DSA-65 `tc17`,
`tc20`, `tc151`, `tc152` and ML-DSA-87 `tc19`, `tc22`, `tc164`, `tc165` say they were built to
cause a buffer overflow or overread: they test memory safety in a decoder without the count check,
not its verdict. Without that check, `tc17`, `tc20` (ML-DSA-65) and `tc19`, `tc22` (ML-DSA-87) are
still refused by the index-order check, and the other four read past the end of the signature.
ML-DSA-65 `tc138` and the `z` ids listed as exceptions are refused through the `c~` comparison.

A verifier whose norm check wrongly lets `z` = +(gamma1 - beta) through, on the positive side only
(for example a check on the stored value `gamma1 - z` written `< beta` instead of `<= beta`), gets
every case in this folder right except `signed-65-z-at-bound` for ML-DSA-65, and except
`signed-87-z-at-bound` and `wycheproof-87-tc151` for ML-DSA-87. That was run over every case here
with a separate FIPS 204 verifier, outside this repository, with its norm check broken that way.

The same id names different cases in the two files: `tc151` is a count above omega for ML-DSA-65
and a `z` bound case for ML-DSA-87.

### Signed cases (`signed_*.json`)

These cases need a key or a signature that no source file holds, so they were signed for these
vectors by a test-only FIPS 204 signer, written for them in Python 3, standard library only, and
kept outside this repository. Before signing, that signer
reproduced NIST's answers for every ML-DSA-65 and ML-DSA-87 case of the ACVP keyGen files (50
cases: `pk` and `sk` from the seed) and of the ACVP sigGen files except pre-hash (180 cases: the
signature byte for byte), at the sigGen commit above, where both folders were last changed. Each
key's `xi` is SHAKE256 of an ASCII label, 32 bytes, and each message is ASCII; each case's `built`
field gives the label, the `rnd` and every change from FIPS 204.

| Class | Expected | What it is | Why |
|---|---|---|---|
| `ChosenRho` | valid | A key made by FIPS 204 KeyGen_internal (Algorithm 6) with `rho` chosen instead of derived: the 22-byte `SubjectPublicKeyInfo` header of a smaller set (ML-DSA-44 for the ML-DSA-65 key, ML-DSA-65 for the ML-DSA-87 key), then the last 10 bytes of the derived `rho`; signed deterministically | Verification never checks how `rho` was made, so this is a valid key. A verifier that decides the parameter set, or DER against raw, from a key's first bytes reads it as the smaller set's key and refuses the signature; one that goes by the key's length and the declared set accepts it, as `src/mldsa.rs:165-183` does (length checks, then the key wrapped in the declared set's own `SubjectPublicKeyInfo`) |
| `ZOutOfRange` | invalid | A signature from Sign_internal (Algorithm 7) with only the `z` check widened by one (refuse only infinity norm above gamma1 - beta), at the smallest `rnd` whose output has exactly one `z` coefficient at +(gamma1 - beta) and none at -(gamma1 - beta) | FIPS 204 Algorithm 8 refuses infinity norm at or above gamma1 - beta. Every other part of the signature is right, so only the norm check can refuse it: a verifier without that check, or with the off-by-one above, accepts it (checked outside this repository with a separate FIPS 204 verifier whose norm check was widened by one) |
| `ZAtBoundMinusOne` | valid | A signature from the standard Sign_internal, with the same key and message, at the smallest `rnd` whose output has a `z` coefficient at gamma1 - beta - 1 | The neighbouring value is inside the bound, so a verifier whose norm check is off by one the other way refuses it |

`the_signed_cases_hold_what_their_class_names` (`tests/mldsa_vectors.rs:453`) checks the property
each class names: the `ChosenRho` key starts with the smaller set's header (`:473-477`), the
`ZOutOfRange` signature has exactly one `z` coefficient at +(gamma1 - beta) and none at or beyond
the bound otherwise (`:482-483`), and the `ZAtBoundMinusOne` signature has one at gamma1 - beta - 1
and none at or beyond the bound (`:488-489`).

Two builders wrote the JSON files here, and neither is part of this folder. Slice 1a's read only the
sigVer and Wycheproof files above and wrote the `acvp_ml_dsa_*`, `wycheproof_*` and `mutations_*`
files. Slice 1b's read only the sigGen files above, for `acvp_siggen_*`, and signed the
`signed_*` cases itself.
