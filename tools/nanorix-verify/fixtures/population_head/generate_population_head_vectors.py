#!/usr/bin/env python3
"""Deterministic population head vectors shared by every verifier.

Writes ``population_head_vectors.json`` into this directory: a key list signed
by a test-only identity, a pool of signed AuditProofs, encoding vectors for the head format, and
one case per check outcome with the exact result a verifier must report.

The head encoding, the signed message and the transparency-log leaf are computed
here with hashlib and ``cryptography`` only, independently of the Rust code the
vectors pin. Every key is derived from a public, test-only seed and has no
relation to any production or ceremony key.

Usage:
    python3 -I generate_population_head_vectors.py           # (re)write
    python3 -I generate_population_head_vectors.py --check   # exit 1 if stale
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
OUT = HERE / "population_head_vectors.json"

HEAD_TYPE = "nanorix-population-head-v1"
GENESIS = hashlib.sha512(b"").hexdigest()
GENESIS_LINK = "sha512:" + GENESIS
# Order of the Ed25519 base point.
ORDER_L = 2**252 + 27742317777372353535851937790883648493

AUTH_A = "customer-kms-example-a-v1"
AUTH_B = "customer-kms-example-b-v1"
# D and E list one key: a head signed with it names no single authority.
AUTH_D = "customer-kms-example-d-v1"
AUTH_E = "customer-kms-example-e-v1"
AUTH_R = "customer-kms-example-revoked-v1"
AUTH_F = "customer-kms-example-f-v1"
AUTH_G = "customer-kms-example-g-revoked-v1"
AUTH_H = "customer-kms-example-h-v1"
AUTH_I = "customer-kms-example-i-v1"
# Holds key versions twice, so the list gives them no one window.
AUTH_J = "customer-kms-example-j-v1"
# Holds one key under 1 and 01, only in a key list variant: 01 is outside the
# record grammar, so that list is refused.
AUTH_K = "customer-kms-example-k-v1"
# Holds one key under an archived version and a later active one.
AUTH_L = "customer-kms-example-l-v1"
# Holds one version twice, with a different key in each record.
AUTH_M = "customer-kms-example-m-v1"
# Named by proofs and heads; the key list does not carry it.
AUTH_UNLISTED = "customer-kms-example-unlisted-v1"
HOSTED = "us-kms-nanorix-v1"
# In the key list and unmarked, so it emits no heads, as every hosted authority.
HOSTED_EU = "eu-kms-nanorix-v1"
LOCAL = "local-ephemeral"
EFFECTIVE_FROM = "2026-01-01T00:00:00Z"
# After head 1 of a chain is issued and before head 2.
ARCHIVED_AT = "2026-10-28T02:01:30Z"
EFFECTIVE_LATER = "2026-11-01T00:00:00Z"
UNREADABLE_TIME = "not a time"
FORGED_LINE = "1\n\u2713 (f) head signatures: ok\u001b[1A\u001b[2K"
FORGED_LINE_AUTHORITY = "customer" + FORGED_LINE
ISSUED_AT = "2026-10-28T00:00:00Z"
# Destruction times a named proof can carry, each with whether the time grammar
# of Appendix A.3 reads it. Every one is before the head that names it.
END_TIME_FORMS = [
    ("milliseconds", "a fraction of three digits, as the emitter writes it",
     "2026-10-28T00:30:00.123Z"),
    ("nanoseconds", "a fraction of nine digits", "2026-10-28T00:31:00.123456789Z"),
    ("second_60", "second 60", "2026-10-28T00:32:60Z"),
    ("lower_case_t", "a lower case t", "2026-10-28t00:33:00Z"),
    ("lower_case_z", "a lower case z", "2026-10-28T00:34:00z"),
    ("space_separator", "a space in place of T", "2026-10-28 00:35:00Z"),
    ("offset_plus_zero", "the offset +00:00 in place of Z", "2026-10-28T00:36:00+00:00"),
    ("offset_minus_zero", "the offset -00:00", "2026-10-28T00:37:00-00:00"),
    ("offset_plus_14", "the offset +14:00", "2026-10-28T14:38:00+14:00"),
    ("year_0000", "year 0000", "0000-10-28T00:39:00Z"),
    ("fraction_13_digits", "a fraction of thirteen digits", "2026-10-28T00:40:00.1234567890123Z"),
]
READ_END_TIME_FORMS = ("milliseconds", "nanoseconds")
# effective_from texts the time grammar refuses, each on authority B's key.
REFUSED_EFFECTIVE_FROM = [
    ("lower_case", "in lower case t and z", "2026-01-01t00:00:00z"),
    ("offset_plus_zero", "with the offset +00:00", "2026-01-01T00:00:00+00:00"),
    ("second_60", "at second 60", "2025-12-31T23:59:60Z"),
]
NOT_LOG = {"outcome": "not_checked", "reason": "needs a transparency log"}
OK = {"outcome": "ok"}
SIGNATURE_DOES_NOT_VERIFY = {"type": "signature_mismatch", "reason": "does_not_verify"}
PQC_SLOTS = ("pqc_signature", "pqc_attestation", "customer_pqc_attestation")

CANONICAL_CHAIN = [
    ("eee_namespace", "procfs_verification"),
    ("eee_tmpfs", "mountinfo_verification"),
    ("eee_memory", "dod_5220_multipass_wipe"),
    ("dire_keys", "ed25519_key_destruction"),
    ("dire_identity", "credential_incineration"),
    ("fgx_forensic", "merkle_tree_verification"),
    ("rzl_audit", "hash_chain_validation"),
    ("capsule_destroy", "capsule_lifecycle_verification"),
]


def test_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"nanorix-test-only-population-head-{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def ml_dsa_test_key(label: str, length: int = 1952) -> bytes:
    # Bytes of an ML-DSA public key's length, not a key: no case verifies an
    # ML-DSA signature, and a record needs only its label's length.
    return hashlib.shake_256(f"nanorix-test-only-population-head-ml-dsa-{label}".encode()).digest(
        length
    )


KEY_A1 = test_key("authority-a-v1")
KEY_A0 = test_key("authority-a-v0")
KEY_A3 = test_key("authority-a-v3")
KEY_A4 = test_key("authority-a-v4")
KEY_A5 = test_key("authority-a-v5")
KEY_A6 = test_key("authority-a-v6")
KEY_A7 = test_key("authority-a-v7")
KEY_B1 = test_key("authority-b-v1")
# Another key, which B holds only in key list variants.
KEY_B8 = test_key("authority-b-v8")
KEY_D1 = test_key("authority-d-v1")
KEY_R1 = test_key("authority-revoked-v1")
KEY_F1 = test_key("authority-f-v1")
KEY_H1 = test_key("authority-h-v1")
KEY_J1 = test_key("authority-j-v1")
KEY_J2 = test_key("authority-j-v2")
KEY_K1 = test_key("authority-k-v1")
KEY_L1 = test_key("authority-l-v1")
KEY_M1 = test_key("authority-m-v1")
KEY_M2 = test_key("authority-m-v2")
# Registered under no authority.
KEY_UNREGISTERED = test_key("unregistered")
KEY_HOSTED = test_key("hosted")
KEY_HOSTED_EU = test_key("hosted-eu")
KEY_IDENTITY = test_key("key-list-identity")
ML_DSA_65_A3 = ml_dsa_test_key("65-authority-a-v3")
ML_DSA_87_B8 = ml_dsa_test_key("87-authority-b-v8", 2592)
ML_DSA_65_B8 = ml_dsa_test_key("65-authority-b-v8")
# DER of an ML-DSA-65 SubjectPublicKeyInfo up to the key: the algorithm
# identifier (OID 2.16.840.1.101.3.4.3.18) and the bit string header.
ML_DSA_65_SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
KEY_LOCAL = test_key("local-ephemeral")
# The identity point: canonical, small order. R = identity, S = 0 makes a
# signature that a non-strict verifier accepts for every message.
IDENTITY_KEY = bytes([1]) + bytes(31)
SMALL_ORDER_SIGNATURE = bytes([1]) + bytes(63)


def jcs(obj: Any) -> bytes:
    # Every key and string here is ASCII and every number is an integer below
    # 2^53, so compact sort_keys json.dumps is the RFC 8785 byte form.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def step_hash(prev: str, subsystem: str, method: str, timestamp: str) -> str:
    parts = [prev, subsystem, "destroy", method, timestamp]
    return sha512_hex(b"\x00".join(p.encode() for p in parts))


def make_proof(
    n: int,
    authority: str,
    key_version: str,
    key: Ed25519PrivateKey,
    destroyed_at: Optional[str] = None,
    version: str = "2.1",
) -> Dict[str, Any]:
    """An AuditProof of `version`, signed nanorix_only over its canonical hash."""
    destroyed_at = destroyed_at or f"2026-10-28T{n // 60:02d}:{n % 60:02d}:00Z"
    capsule_id = f"cap_{n:032x}"
    chain = []
    prev = GENESIS
    for i, (subsystem, method) in enumerate(CANONICAL_CHAIN):
        prev = step_hash(prev, subsystem, method, destroyed_at)
        chain.append(
            {
                "chain_hash": "sha512:" + prev,
                "evidence_hash": "sha512:" + "0" * 128,
                "operation": f"{subsystem}_op",
                "step": i + 1,
                "subsystem": subsystem,
            }
        )
    activity = [
        {
            "encryption": "aes-256-gcm",
            "event": "capsule_started",
            "network": "sealed",
            "region": "us-central1",
        }
    ]
    org_id = "00000000-0000-0000-0000-0000000000a1"
    try:
        view_key_version = int(key_version)
    except ValueError:
        view_key_version = 0
    view = {
        "version": version,
        "signing_mode": "nanorix_only",
        "jurisdiction": "us",
        "authority_id": authority,
        "signing_key_version": view_key_version,
        "capsule_id": capsule_id,
        "org_id": org_id,
        "activity_trail": activity,
        "destruction_chain": chain,
        "destruction_state": "complete",
        "destruction_failure_step": None,
        "runtime_attestation": None,
        "attestation": {"timestamp_attestation": None, "attestation_chain_fingerprint": None},
        "hash_algorithm": "SHA-512",
        "signature_algorithm": "Ed25519",
    }
    canonical_hash = sha512_hex(jcs(view))
    return {
        "activity": activity,
        "attestation": {
            "algorithm": "Ed25519",
            "key_id": f"nrx-verify-{destroyed_at}-{capsule_id[4:12]}",
            "public_key": "base64:" + b64(raw_public(key)),
            "signature": "base64:" + b64(key.sign(canonical_hash.encode("ascii"))),
        },
        "authority_id": authority,
        "capsule_id": capsule_id,
        "cdp_version": version,
        "chain": chain,
        "destroyed_at": destroyed_at,
        "destruction_state": "complete",
        "final_hash": "sha512:" + prev,
        "hash_algorithm": "SHA-512",
        "jurisdiction": "us",
        "org_id": org_id,
        "signature_algorithm": "Ed25519",
        "signing_key_version": key_version,
        "signing_mode": "nanorix_only",
    }


def as_v1_0(proof: Dict[str, Any], key: Ed25519PrivateKey) -> Dict[str, Any]:
    """The proof as cdp_version 1.0, whose signature covers final_hash alone."""
    v1 = copy.deepcopy(proof)
    v1["cdp_version"] = "1.0"
    final_raw = v1["final_hash"][len("sha512:") :]
    v1["attestation"]["signature"] = "base64:" + b64(key.sign(final_raw.encode("ascii")))
    return v1


def leaf(proof: Dict[str, Any]) -> Optional[str]:
    """Transparency-log leaf: SHA-512(0x00 ‖ final_hash_raw ‖ 0x00 ‖ envelope_digest_hex).

    None for a proof a transparency log holds no leaf for (Appendix A.1).
    """
    final = proof.get("final_hash")
    if not isinstance(final, str):
        return None
    final_raw = final[len("sha512:") :] if final.startswith("sha512:") else final
    if len(final_raw) != 128 or any(c not in "0123456789abcdef" for c in final_raw):
        return None
    if any(proof.get(slot) is not None for slot in PQC_SLOTS):
        return None
    att = proof.get("attestation")
    if not isinstance(att, dict):
        return None
    fields = [att.get(name) for name in ("algorithm", "key_id", "public_key", "signature")]
    if not all(isinstance(f, str) and "\x00" not in f for f in fields):
        return None
    envelope = sha512_hex(b"\x00".join(p.encode() for p in fields + [""]))
    return "sha512:" + sha512_hex(b"\x00" + final_raw.encode() + b"\x00" + envelope.encode())


def head(sequence: int, prev: str, tip: str, authority: str = AUTH_A) -> Dict[str, Any]:
    return {
        "type": HEAD_TYPE,
        "authority_id": authority,
        "proof_sequence": sequence,
        "prev_head_hash": prev,
        "tip_proof_hash": tip,
        "issued_at": f"2026-10-28T02:{sequence % 60:02d}:00Z",
    }


def head_hash(h: Dict[str, Any]) -> str:
    return "sha512:" + sha512_hex(jcs(h))


def signed_message(h: Dict[str, Any]) -> str:
    return f"{HEAD_TYPE}:{sha512_hex(jcs(h))}"


def sign_head(h: Dict[str, Any], key_version: str = "1", key=KEY_A1) -> Dict[str, Any]:
    return {
        "head": h,
        "signing_key_version": key_version,
        "signature": "base64:" + b64(key.sign(signed_message(h).encode("ascii"))),
    }


def chain_of(tips: List[str], authority: str = AUTH_A) -> List[Dict[str, Any]]:
    """Unsigned heads 1..n naming `tips` in order, each linked to the last."""
    heads = []
    prev = GENESIS_LINK
    for i, tip in enumerate(tips):
        h = head(i + 1, prev, tip, authority)
        heads.append(h)
        prev = head_hash(h)
    return heads


def fingerprint(public: bytes) -> str:
    return "sha256:" + hashlib.sha256(public).hexdigest()


def version_record(
    version: str,
    public: bytes,
    algorithm: str = "Ed25519",
    effective_from: str = EFFECTIVE_FROM,
    archived_at: Optional[str] = None,
) -> Dict[str, Any]:
    record = {
        "signing_key_version": version,
        "public_key_b64": b64(public),
        "public_key_fingerprint": fingerprint(public),
        "effective_from": effective_from,
        "algorithm": algorithm,
    }
    if archived_at is not None:
        record["archived_at"] = archived_at
    return record


def authority(
    name: str,
    versions: List[Dict[str, Any]],
    revoked: bool = False,
    archived: Optional[List[Dict[str, Any]]] = None,
    emits_heads: bool = True,
) -> Dict[str, Any]:
    record = {
        "display_name": f"{name} (test only)",
        "active_versions": versions,
        "archived_versions": archived or [],
        "revoked": revoked,
    }
    if emits_heads:
        record["emits_population_heads"] = True
    return record


def prefixed(record: Dict[str, Any]) -> Dict[str, Any]:
    return {**record, "public_key_b64": "base64:" + record["public_key_b64"]}


def key_list(
    issued_at: str = ISSUED_AT,
    edit: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    identity = raw_public(KEY_IDENTITY)
    document = {
        "schema_version": "1.0",
        "issued_at": issued_at,
        "authorities": {
            AUTH_A: authority(
                "Example customer authority A",
                [
                    version_record("1", raw_public(KEY_A1)),
                    version_record("2", IDENTITY_KEY),
                    # An ML-DSA-65 record; a head under it fails on its algorithm.
                    version_record("3", ML_DSA_65_A3, "ML-DSA-65"),
                    version_record("4", raw_public(KEY_A4), effective_from=EFFECTIVE_LATER),
                    version_record("5", raw_public(KEY_A5), effective_from=UNREADABLE_TIME),
                ],
                archived=[
                    version_record("8", raw_public(KEY_A0), archived_at=ARCHIVED_AT),
                    version_record("6", raw_public(KEY_A6), archived_at=UNREADABLE_TIME),
                    version_record("7", raw_public(KEY_A7)),
                ],
            ),
            AUTH_B: authority(
                "Example customer authority B", [version_record("1", raw_public(KEY_B1))]
            ),
            AUTH_D: authority(
                "Example customer authority D", [version_record("1", raw_public(KEY_D1))]
            ),
            AUTH_E: authority(
                "Example customer authority E, listing D's key",
                [version_record("1", raw_public(KEY_D1))],
            ),
            AUTH_R: authority(
                "Example revoked customer authority",
                [version_record("1", raw_public(KEY_R1))],
                revoked=True,
            ),
            AUTH_F: authority(
                "Example customer authority F", [version_record("1", raw_public(KEY_F1))]
            ),
            AUTH_G: authority(
                "Example revoked customer authority G, with F's key archived",
                [],
                revoked=True,
                archived=[version_record("1", raw_public(KEY_F1))],
            ),
            AUTH_H: authority(
                "Example customer authority H", [version_record("1", raw_public(KEY_H1))]
            ),
            AUTH_I: authority(
                "Example customer authority I, listing H's key with a base64: prefix",
                [prefixed(version_record("1", raw_public(KEY_H1)))],
            ),
            AUTH_J: authority(
                "Example customer authority J, holding two key versions twice",
                [
                    version_record("1", raw_public(KEY_J1)),
                    version_record("2", raw_public(KEY_J2)),
                    version_record("2", raw_public(KEY_J2)),
                ],
                archived=[version_record("1", raw_public(KEY_J1), archived_at=ARCHIVED_AT)],
            ),
            AUTH_L: authority(
                "Example customer authority L, holding one key under 1 and 9",
                [version_record("9", raw_public(KEY_L1))],
                archived=[version_record("1", raw_public(KEY_L1), archived_at=ARCHIVED_AT)],
            ),
            AUTH_M: authority(
                "Example customer authority M, holding version 1 with two keys",
                [version_record("1", raw_public(KEY_M1))],
                archived=[version_record("1", raw_public(KEY_M2), archived_at=ARCHIVED_AT)],
            ),
            HOSTED: authority(
                "Example hosted authority",
                [version_record("1", raw_public(KEY_HOSTED))],
                emits_heads=False,
            ),
            HOSTED_EU: authority(
                "Example second hosted authority",
                [version_record("1", raw_public(KEY_HOSTED_EU))],
                emits_heads=False,
            ),
        },
        "identity_fingerprint": fingerprint(identity),
        "identity_public_key_b64": b64(identity),
    }
    if edit is not None:
        edit(document["authorities"])
    document["manifest_signature"] = "base64:" + b64(KEY_IDENTITY.sign(jcs(document)))
    return document


def key_list_texts() -> List[Dict[str, Any]]:
    """The signed key list as texts, each with the first member it holds that
    the signature does not cover. None of them is signed again."""
    texts: List[Dict[str, Any]] = []

    def add_text(name: str, description: str, text: str, member: Optional[Dict[str, str]]) -> None:
        texts.append({"name": name, "description": description, "text": text, "member": member})

    def edited(edit: Callable[[Dict[str, Any]], None]) -> str:
        document = key_list()
        edit(document["authorities"])
        return render(document)

    add_text(
        "genuine",
        "The signed list as written: every member is covered by the signature.",
        render(key_list()),
        None,
    )

    def leave_out_defaults(authorities: Dict[str, Any]) -> None:
        del authorities[AUTH_B]["revoked"]
        del authorities[AUTH_B]["archived_versions"]

    add_text(
        "defaults_left_out",
        "B's revoked and archived_versions are left out. The signature covers them at their "
        "defaults, false and empty, so nothing is outside it.",
        edited(leave_out_defaults),
        None,
    )

    def add_retirement(authorities: Dict[str, Any]) -> None:
        authorities[AUTH_B]["active_versions"][0]["superseded_by_hex"] = raw_public(KEY_B8).hex()
        authorities[AUTH_B]["active_versions"][0]["retired_at"] = ARCHIVED_AT
        authorities[AUTH_D]["active_versions"][0]["public_key_hex"] = raw_public(KEY_B1).hex()

    b_record = f"/authorities/{AUTH_B}/active_versions/0"
    add_text(
        "members_outside_the_signature",
        "B's record gains superseded_by_hex and retired_at, and D's a public_key_hex holding "
        "B's key. The signature does not cover them, so they would show B's key retired.",
        edited(add_retirement),
        {"kind": "not_carried", "pointer": f"{b_record}/superseded_by_hex"},
    )

    def add_escaped_name(authorities: Dict[str, Any]) -> None:
        authorities[AUTH_B]["active_versions"][0]["retired/at~"] = ARCHIVED_AT

    add_text(
        "member_name_escaped_in_the_pointer",
        "B's record gains a member named retired/at~. The pointer writes / as ~1 and ~ as ~0.",
        edited(add_escaped_name),
        {"kind": "not_carried", "pointer": f"{b_record}/retired~1at~0"},
    )

    def write_null_end(authorities: Dict[str, Any]) -> None:
        authorities[AUTH_B]["active_versions"][0]["archived_at"] = None

    add_text(
        "archived_at_written_null",
        "B's active record gains archived_at written as null. The signature covers the record "
        "without it, so the member written is not covered.",
        edited(write_null_end),
        {"kind": "not_carried", "pointer": f"{b_record}/archived_at"},
    )

    def write_false_marker(authorities: Dict[str, Any]) -> None:
        authorities[HOSTED]["emits_population_heads"] = False

    add_text(
        "marker_written_false",
        "The hosted authority's marker is written as false. The signature covers the list "
        "without a false marker, so the member written is not covered.",
        edited(write_false_marker),
        {"kind": "not_carried", "pointer": f"/authorities/{HOSTED}/emits_population_heads"},
    )

    genuine = render(key_list())
    anchor = f"    {json.dumps(AUTH_B)}: {{\n"
    assert genuine.count(anchor) == 1
    revoked_at = genuine.index('"revoked"', genuine.index(anchor))
    add_text(
        "member_name_written_with_an_escape",
        "B's revoked is written with its first letter as the escape \\u0072. A parser reads "
        "the same name, so the signature covers it and nothing is outside it.",
        genuine[:revoked_at] + '"\\u0072evoked"' + genuine[revoked_at + len('"revoked"'):],
        None,
    )
    retired = version_record("8", raw_public(KEY_B1), archived_at=ARCHIVED_AT)
    retired["public_key_b64"] = raw_public(KEY_B1).hex()
    first_copy = authority(
        "Example customer authority B",
        [version_record("1", raw_public(KEY_B1))],
        archived=[retired],
    )
    add_text(
        "authority_written_twice",
        "A second copy of B, holding B's key archived in hex, is written before the real one. "
        "A parser keeps the last copy, so the signature verifies and no check reads the first.",
        genuine.replace(anchor, f"    {json.dumps(AUTH_B)}: {json.dumps(first_copy)},\n" + anchor),
        {"kind": "repeated", "pointer": f"/authorities/{AUTH_B}"},
    )
    null_pqc = key_list()
    null_pqc["pqc_manifest_signature"] = None
    add_text(
        "pqc_signature_written_null",
        "The reserved pqc_manifest_signature is written as null. No signature covers either "
        "signature member, so their values are not compared and nothing is outside it.",
        render(null_pqc),
        None,
    )
    return texts


def head_texts(heads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The good chain's signed heads as texts, each with the first member name
    it writes twice in one object. A parser keeps one copy, so the checks read
    one head while a reader keeping the other copy sees another."""

    def rendered(items: List[str]) -> str:
        return "[\n" + ",\n".join(items) + "\n]\n"

    items = ["\n".join("  " + line for line in render(h).splitlines()) for h in heads]
    genuine = rendered(items)
    assert genuine == render(heads)
    texts: List[Dict[str, Any]] = []

    def add_text(name: str, description: str, text: str, pointer: Optional[str]) -> None:
        member = None if pointer is None else {"kind": "repeated", "pointer": pointer}
        texts.append({"name": name, "description": description, "text": text, "member": member})

    def written_twice(index: int, name: str, first: Any, in_head: bool = False,
                      written_name: Optional[str] = None) -> str:
        """The heads with head `index` writing `name` once more, holding
        `first`, before its own copy: inside the head or beside it."""
        indent = " " * (6 if in_head else 4)
        own = f"{indent}{json.dumps(name)}: "
        assert items[index].count(own) == 1
        copy_line = f"{indent}{written_name or json.dumps(name)}: {json.dumps(first)},\n"
        edited = list(items)
        edited[index] = items[index].replace(own, copy_line + own)
        return rendered(edited)

    add_text("genuine", "The good chain's heads as written: no member is written twice.",
             genuine, None)
    add_text(
        "issued_at_written_twice",
        "Head 1 writes issued_at twice, the earlier copy dated an hour later. The checks would "
        "read the last copy, which the signature covers.",
        written_twice(0, "issued_at", "2026-10-28T03:01:00Z", in_head=True),
        "/0/head/issued_at",
    )
    relabelled = dict(heads[1]["head"], authority_id=AUTH_B)
    add_text(
        "head_written_twice",
        "Head 2 writes its head twice, the earlier copy under authority B.",
        written_twice(1, "head", relabelled),
        "/1/head",
    )
    add_text(
        "signature_written_twice",
        "Head 3 writes its signature twice, the earlier copy head 1's signature.",
        written_twice(2, "signature", heads[0]["signature"]),
        "/2/signature",
    )
    add_text(
        "key_version_written_twice",
        "Head 1 writes signing_key_version twice, the earlier copy 8.",
        written_twice(0, "signing_key_version", "8"),
        "/0/signing_key_version",
    )
    add_text(
        "signature_written_twice_once_escaped",
        "Head 2 writes its signature twice, the earlier copy's name with the escape \\u0073. "
        "A parser reads the same name, so it is one member written twice.",
        written_twice(1, "signature", "base64:AAAA", written_name='"\\u0073ignature"'),
        "/1/signature",
    )
    return texts


NO_CDP_VERSION = {"type": "required_field_missing", "field": "cdp_version"}
KEY_LIST_READ = {
    "issued_at": ISSUED_AT,
    "identity_fingerprint": fingerprint(raw_public(KEY_IDENTITY)),
}


def failed(reason_type: str, **fields: Any) -> Dict[str, Any]:
    return {"outcome": "failed", "reason": {"type": reason_type, **fields}}


def head_malformed(head_index: int, field: str) -> Dict[str, Any]:
    # `detail` is free text for a human reader and is not compared.
    return failed("head_malformed", head_index=head_index, field=field)


def not_checked(reason: str) -> Dict[str, Any]:
    return {"outcome": "not_checked", "reason": reason}


def build() -> Dict[str, Any]:
    pool = {f"a{n}": make_proof(n, AUTH_A, "1", KEY_A1) for n in range(1, 5)}
    pool["a2_fork"] = make_proof(22, AUTH_A, "1", KEY_A1)
    pool["b2"] = make_proof(52, AUTH_B, "1", KEY_B1)
    pool["local"] = make_proof(40, LOCAL, LOCAL, KEY_LOCAL)
    pool["hosted"] = make_proof(41, HOSTED, "1", KEY_HOSTED)
    pool["hosted_eu"] = make_proof(42, HOSTED_EU, "1", KEY_HOSTED_EU)
    pool["unlisted1"] = make_proof(95, AUTH_UNLISTED, "1", KEY_UNREGISTERED)
    pool["a6_fractional_end"] = make_proof(
        6, AUTH_A, "1", KEY_A1, destroyed_at="2026-10-28T00:06:00.750Z"
    )
    pool["a7_unreadable_end"] = make_proof(
        7, AUTH_A, "1", KEY_A1, destroyed_at="2026-10-28 00:07:00 UTC"
    )
    for n, (name, _, end) in enumerate(END_TIME_FORMS, start=140):
        pool[f"end_{name}"] = make_proof(n, AUTH_A, "1", KEY_A1, destroyed_at=end)
    pool["d1"] = make_proof(71, AUTH_D, "1", KEY_D1)
    pool["revoked1"] = make_proof(61, AUTH_R, "1", KEY_R1)
    pool["f1"] = make_proof(81, AUTH_F, "1", KEY_F1)
    pool["h1"] = make_proof(91, AUTH_H, "1", KEY_H1)
    pool["a5_unregistered_key"] = make_proof(5, AUTH_A, "1", KEY_UNREGISTERED)
    # Same final_hash and attestation as a2, so the same leaf; the edited
    # field is in the canonical view, so the signature no longer verifies.
    pool["a2_forged"] = copy.deepcopy(pool["a2"])
    pool["a2_forged"]["destruction_state"] = "partial"
    # key_id is in the leaf but not under the signature: a new leaf, the
    # same signed document.
    pool["a1_key_id_rewritten"] = copy.deepcopy(pool["a1"])
    pool["a1_key_id_rewritten"]["attestation"]["key_id"] = "nrx-verify-rewritten"
    # The same key under verification_key instead of public_key: the proof
    # verifier still reads it, but the leaf reads public_key only.
    pool["a1_verification_key_only"] = copy.deepcopy(pool["a1"])
    attestation = pool["a1_verification_key_only"]["attestation"]
    attestation["verification_key"] = attestation.pop("public_key")
    # A top-level pqc_signature is outside the signature, so this copy verifies;
    # it must not gain a second leaf. PQC has no leaf until verifiers check it.
    pool["a1_pqc_signature_added"] = copy.deepcopy(pool["a1"])
    pool["a1_pqc_signature_added"]["pqc_signature"] = "base64:CCCC"
    # A populated reserved slot fails verification and has no leaf.
    pool["a1_customer_pqc_populated"] = copy.deepcopy(pool["a1"])
    pool["a1_customer_pqc_populated"]["customer_pqc_attestation"] = {
        "algorithm": "ML-DSA-65",
        "key_id": "k",
        "public_key": "base64:CCCC",
        "signature": "base64:DDDD",
    }
    # key_id is not under the signature. NUL would make the digest's join
    # ambiguous, so a field holding it has no leaf.
    pool["a1_nul_in_key_id"] = copy.deepcopy(pool["a1"])
    pool["a1_nul_in_key_id"]["attestation"]["key_id"] += "\x00x"
    # No signature at all: the proof stops at stage 4 and is still valid there,
    # with a leaf, so only the stage it reached can keep it out of a population.
    pool["a1_no_signature"] = copy.deepcopy(pool["a1"])
    pool["a1_no_signature"]["attestation"]["signature"] = ""
    pool["a8_v2_2"] = make_proof(8, AUTH_A, "1", KEY_A1, version="2.2")
    pool["a9_v1_0"] = as_v1_0(make_proof(9, AUTH_A, "1", KEY_A1), KEY_A1)
    # Each of these claims a signer with an edit that takes no key. The leaf
    # stays that of the proof it was edited from.
    pool["a2_attestation_claims_local"] = copy.deepcopy(pool["a2"])
    pool["a2_attestation_claims_local"]["attestation"]["signing_key_version"] = LOCAL
    pool["a2_authority_set_hosted"] = copy.deepcopy(pool["a2"])
    pool["a2_authority_set_hosted"]["authority_id"] = HOSTED
    pool["a2_authority_set_local"] = copy.deepcopy(pool["a2"])
    pool["a2_authority_set_local"]["authority_id"] = LOCAL
    pool["a2_authority_deleted"] = copy.deepcopy(pool["a2"])
    del pool["a2_authority_deleted"]["authority_id"]
    # The canonical view reads an unparseable key version as 0, so this edit
    # leaves the signature verifying.
    pool["a0_relabelled_local"] = make_proof(10, AUTH_A, "0", KEY_A0)
    pool["a0_relabelled_local"]["signing_key_version"] = LOCAL
    pool["hosted_unlisted_key"] = make_proof(43, HOSTED, "1", KEY_UNREGISTERED)
    pool["unlisted_v0_relabelled_local"] = make_proof(96, AUTH_UNLISTED, "0", KEY_UNREGISTERED)
    pool["unlisted_v0_relabelled_local"]["signing_key_version"] = LOCAL
    # Anyone can mint this key and keep the marked authority's name.
    pool["throwaway_key_keeps_a"] = make_proof(97, AUTH_A, LOCAL, KEY_UNREGISTERED)
    pool["local_version_on_hosted_authority"] = make_proof(98, HOSTED, LOCAL, KEY_LOCAL)
    pool["local_v1_0"] = as_v1_0(make_proof(99, LOCAL, LOCAL, KEY_LOCAL), KEY_LOCAL)
    # The authority and the key would both read as the local signer's, so only
    # the top-level key version keeps this proof from reporting it.
    pool["local_name_pointer_claims_local"] = make_proof(100, LOCAL, "1", KEY_UNREGISTERED)
    pool["local_name_pointer_claims_local"]["attestation"]["signing_key_version"] = LOCAL
    # A key holder can sign these words, so they do not make the proof the
    # local signer's when the list holds the key.
    pool["local_name_listed_key"] = make_proof(103, LOCAL, LOCAL, KEY_A1)
    pool["j1"] = make_proof(101, AUTH_J, "1", KEY_J1)
    pool["j2"] = make_proof(102, AUTH_J, "2", KEY_J2)
    pool["k1"] = make_proof(104, AUTH_K, "1", KEY_K1)
    pool["l1"] = make_proof(105, AUTH_L, "1", KEY_L1)
    pool["m1"] = make_proof(106, AUTH_M, "1", KEY_M1)
    pool["not_a_proof_empty"] = {}
    pool["not_a_proof_authority_only"] = {"authority_id": HOSTED}
    pool["e1_key_shared_with_d"] = make_proof(72, AUTH_E, "1", KEY_D1)
    pool["a11_authority_writes_a_line"] = make_proof(11, FORGED_LINE_AUTHORITY, "1", KEY_A1)
    leaves = {name: leaf(p) for name, p in pool.items()}
    assert [name for name, value in leaves.items() if value is None] == [
        "a1_verification_key_only",
        "a1_pqc_signature_added",
        "a1_customer_pqc_populated",
        "a1_nul_in_key_id",
        "not_a_proof_empty",
        "not_a_proof_authority_only",
    ]
    assert leaves["a2_forged"] == leaves["a2"]
    assert leaves["a1_key_id_rewritten"] != leaves["a1"]
    failures = {
        "a2_forged": {"stage_reached": 7, "failure_reason": SIGNATURE_DOES_NOT_VERIFY},
        "a1_customer_pqc_populated": {
            "stage_reached": 2,
            "failure_reason": {
                "type": "unsigned_field_populated",
                "field": "customer_pqc_attestation",
            },
        },
        "a2_authority_set_hosted": {"stage_reached": 7, "failure_reason": SIGNATURE_DOES_NOT_VERIFY},
        "a2_authority_set_local": {"stage_reached": 7, "failure_reason": SIGNATURE_DOES_NOT_VERIFY},
        "a2_authority_deleted": {"stage_reached": 7, "failure_reason": SIGNATURE_DOES_NOT_VERIFY},
        "not_a_proof_empty": {"stage_reached": 1, "failure_reason": NO_CDP_VERSION},
        "not_a_proof_authority_only": {"stage_reached": 1, "failure_reason": NO_CDP_VERSION},
    }
    stages = {name: 8 for name in pool if name not in failures}
    for name in (
        "local",
        "revoked1",
        "a5_unregistered_key",
        "unlisted1",
        "a2_attestation_claims_local",
        "a0_relabelled_local",
        "hosted_unlisted_key",
        "unlisted_v0_relabelled_local",
        "throwaway_key_keeps_a",
        "local_version_on_hosted_authority",
        "local_name_listed_key",
        "local_v1_0",
        # A 1.0 signature covers final_hash alone, so no key list anchors it.
        "a9_v1_0",
        "local_name_pointer_claims_local",
        "a11_authority_writes_a_line",
        "k1",
    ):
        stages[name] = 7
    stages["a1_no_signature"] = 4

    def tips(*names: str) -> List[str]:
        return [leaves[n] for n in names]

    cases: List[Dict[str, Any]] = []

    def add(
        name: str,
        description: str,
        proofs: List[str],
        heads: List[Dict[str, Any]],
        checks: Dict[str, Any],
        unwitnessed: Optional[List[Dict[str, Any]]] = None,
        key_list_supplied: bool = True,
        heads_parse: bool = True,
        key_list_variant: Optional[str] = None,
    ) -> None:
        parsed = [h["head"] for h in heads] if heads_parse else []
        sequences = sorted(h["proof_sequence"] for h in parsed)
        first = min(parsed, key=lambda h: h["proof_sequence"], default=None)
        full_checks = {
            "a_chain_links": checks.get("a", OK),
            "b_sequence_contiguous": checks.get("b", OK),
            "c_tips_match_proofs": checks.get("c", OK),
            "d_log_inclusion": NOT_LOG,
            "e_log_population": NOT_LOG,
            "f_head_signatures": checks.get("f", OK),
        }
        any_failed = any(c["outcome"] == "failed" for c in full_checks.values())
        cases.append(
            {
                "name": name,
                "description": description,
                "proofs": proofs,
                "heads": heads,
                "key_list_supplied": key_list_supplied,
                "list_variant": key_list_variant,
                "expected": {
                    "verdict": "failed" if any_failed else "not_externally_witnessed",
                    "honesty_label": "population not externally witnessed",
                    "checks": full_checks,
                    "authority_id": first["authority_id"] if first else None,
                    "head_count": len(heads),
                    "proof_count": len(proofs),
                    "first_sequence": sequences[0] if sequences else None,
                    "last_sequence": sequences[-1] if sequences else None,
                    "unwitnessed_proofs": unwitnessed or [],
                    "key_list": KEY_LIST_READ if key_list_supplied else None,
                },
            }
        )

    def unwitnessed(proofs: List[str], name: str, reason: str) -> Dict[str, Any]:
        return {"proof_index": proofs.index(name), "tip_proof_hash": leaves[name], "reason": reason}

    good = chain_of(tips("a1", "a2", "a3"))
    add(
        "good_chain",
        "Three proofs, three heads under the proofs' authority: (a), (b), (c), (f) ok; "
        "(d), (e) need a transparency log, so the population carries the label.",
        ["a1", "a2", "a3"],
        [sign_head(h) for h in good],
        {},
    )

    add(
        "withheld_proof",
        "Head 2 names a proof that was not handed: (c) fails; (f) cannot compare head 2 "
        "with its proof.",
        ["a1", "a3"],
        [sign_head(h) for h in good],
        {
            "c": failed("tip_matches_no_proof", proof_sequence=2, tip_proof_hash=leaves["a2"]),
            "f": not_checked("a named proof was not handed"),
        },
    )

    four = chain_of(tips("a1", "a2", "a3", "a4"))
    proofs = ["a1", "a2", "a3", "a4"]
    add(
        "withheld_head",
        "Head 3 of four was withheld: head 4 links to a head that was not handed (a) and "
        "the sequence skips 3 (b); proof 3 is listed as unwitnessed.",
        proofs,
        [sign_head(four[i]) for i in (0, 1, 3)],
        {
            "a": failed(
                "prev_head_hash_mismatch",
                proof_sequence=4,
                expected=head_hash(four[1]),
                found=head_hash(four[2]),
            ),
            "b": failed("sequence_gap", expected=3, found=4),
        },
        [unwitnessed(proofs, "a3", "no_handed_head")],
    )

    three = chain_of(tips("a1", "a2", "a3"))
    past = head(3, head_hash(three[0]), leaves["a3"])
    add(
        "head_links_past_the_head_below_it",
        "Head 3 carries the hash of head 1, a lower handed head but not the one at the "
        "greatest lower sequence: (a) fails.",
        ["a1", "a2", "a3"],
        [sign_head(h) for h in three[:2] + [past]],
        {
            "a": failed(
                "prev_head_hash_mismatch",
                proof_sequence=3,
                expected=head_hash(three[1]),
                found=head_hash(three[0]),
            ),
        },
    )

    gap = chain_of(tips("a1", "a2"))
    skipped = head(4, head_hash(gap[1]), leaves["a3"])
    add(
        "sequence_gap",
        "The signer linked its third head correctly but numbered it 4: (b) fails, (a) holds.",
        ["a1", "a2", "a3"],
        [sign_head(h) for h in gap + [skipped]],
        {"b": failed("sequence_gap", expected=3, found=4)},
    )

    shuffled = chain_of(tips("a1", "a2", "a3"))
    add(
        "heads_handed_out_of_order",
        "The same three heads handed as 3, 1, 2. A verifier reads them by sequence: nothing "
        "fails.",
        ["a1", "a2", "a3"],
        [sign_head(shuffled[i]) for i in (2, 0, 1)],
        {},
    )
    add(
        "chain_without_head_1",
        "Heads 2 and 3 alone: they link to each other, so (a) holds, and a chain starts at "
        "sequence 1, so (b) fails. Proof 1 is unwitnessed.",
        ["a1", "a2", "a3"],
        [sign_head(h) for h in shuffled[1:]],
        {"b": failed("sequence_gap", expected=1, found=2)},
        [unwitnessed(["a1", "a2", "a3"], "a1", "no_handed_head")],
    )

    fork_a = chain_of(tips("a1", "a2", "a3"))
    fork_b = head(2, head_hash(fork_a[0]), leaves["a2_fork"])
    add(
        "fork",
        "Two heads at sequence 2, both linked to head 1, naming different proofs: (b) fails.",
        ["a1", "a2", "a2_fork", "a3"],
        [sign_head(h) for h in (fork_a[0], fork_a[1], fork_b, fork_a[2])],
        {"b": failed("duplicate_sequence", proof_sequence=2)},
    )

    two = chain_of(tips("a1", "a2"))
    add(
        "wrong_authority",
        "Heads signed by another registered authority (B) over authority A's proofs: (f) "
        "fails at the proofs' authority, before any signature is read, so it would fail "
        "whoever signed.",
        ["a1", "a2"],
        [sign_head(h, "1", KEY_B1) for h in chain_of(tips("a1", "a2"), AUTH_B)],
        {
            "f": failed(
                "named_proof_authority_mismatch",
                proof_sequence=1,
                head_authority=AUTH_B,
                proof_authority=AUTH_A,
            )
        },
    )

    tampered = [sign_head(h) for h in two]
    sig = bytearray(base64.b64decode(tampered[1]["signature"][len("base64:") :]))
    s = int.from_bytes(sig[32:], "little") + ORDER_L
    sig[32:] = s.to_bytes(32, "little")
    tampered[1]["signature"] = "base64:" + b64(bytes(sig))
    add(
        "non_canonical_signature",
        "Head 2's genuine signature with S replaced by S + L: (f) fails. Plain verification "
        "refuses this as well, so small_order_key is the case that proves strictness.",
        ["a1", "a2"],
        tampered,
        {"f": failed("head_signature_mismatch", proof_sequence=2, reason="does_not_verify")},
    )

    small = [sign_head(two[0])]
    small.append(
        {
            "head": two[1],
            "signing_key_version": "2",
            "signature": "base64:" + b64(SMALL_ORDER_SIGNATURE),
        }
    )
    add(
        "small_order_key",
        "Head 2 names key version 2, registered as the identity point, with R = identity and "
        "S = 0. A non-strict verifier accepts that signature for any message; strict "
        "verification refuses the small-order key, so (f) fails.",
        ["a1", "a2"],
        small,
        {"f": failed("head_signature_mismatch", proof_sequence=2, reason="does_not_verify")},
    )

    forged = [sign_head(two[0]), sign_head(two[1], "1", KEY_B1)]
    add(
        "forged_authority_claim",
        "Head 2 claims authority A's key but was signed with authority B's: (f) fails.",
        ["a1", "a2"],
        forged,
        {"f": failed("head_signature_mismatch", proof_sequence=2, reason="does_not_verify")},
    )

    relabelled = sign_head(head(1, GENESIS_LINK, leaves["b2"]))
    relabelled["head"] = {**relabelled["head"], "authority_id": AUTH_B}
    add(
        "relabelled_authority",
        "A head authority A signed, with its authority_id changed to B, naming B's own proof. "
        "The authority is inside the signed bytes, so the signature covers another head and "
        "(f) fails.",
        ["b2"],
        [relabelled],
        {"f": failed("head_signature_mismatch", proof_sequence=1, reason="does_not_verify")},
    )

    switch = [head(1, GENESIS_LINK, leaves["a1"])]
    switch.append(head(2, head_hash(switch[0]), leaves["b2"], AUTH_B))
    add(
        "authority_switch_mid_chain",
        "Head 1 is under authority A; head 2, correctly linked, is under authority B and "
        "names B's own proof. Every signature verifies, and (f) fails because a chain "
        "belongs to one authority.",
        ["a1", "b2"],
        [sign_head(switch[0]), sign_head(switch[1], "1", KEY_B1)],
        {
            "f": failed(
                "chain_authority_mismatch",
                proof_sequence=2,
                chain_authority=AUTH_A,
                head_authority=AUTH_B,
            )
        },
    )

    add(
        "two_authorities_at_sequence_one",
        "Two heads at sequence 1 under two authorities. The result names the first handed, "
        "and (b) and (f) both fail.",
        ["a1", "b2"],
        [
            sign_head(head(1, GENESIS_LINK, leaves["a1"])),
            sign_head(head(1, GENESIS_LINK, leaves["b2"], AUTH_B), "1", KEY_B1),
        ],
        {
            "b": failed("duplicate_sequence", proof_sequence=1),
            "f": failed(
                "chain_authority_mismatch",
                proof_sequence=1,
                chain_authority=AUTH_A,
                head_authority=AUTH_B,
            ),
        },
    )

    proofs = ["local", "hosted", "hosted_eu"]
    add(
        "local_signer_and_hosted_proofs_carry_the_label",
        "A local-signer proof and proofs under two authorities the key list does not mark "
        "as emitting heads, with no heads: nothing fails, all three are listed as unwitnessed, "
        "and the population carries the label.",
        proofs,
        [],
        {
            "a": not_checked("no heads handed"),
            "b": not_checked("no heads handed"),
            "c": not_checked("no heads handed"),
            "f": not_checked("no heads handed"),
        },
        [
            unwitnessed(proofs, "local", "local_signer"),
            unwitnessed(proofs, "hosted", "unmarked_authority"),
            unwitnessed(proofs, "hosted_eu", "unmarked_authority"),
        ],
    )

    add(
        "head_names_local_signer_proof",
        "A customer head names a local-signer proof, which emits no heads: (f) fails.",
        ["local"],
        [sign_head(h) for h in chain_of(tips("local"))],
        {"f": failed("signer_not_marked_for_heads", proof_sequence=1, signer="local_signer")},
    )

    add(
        "head_names_hosted_proof",
        "A customer head names a hosted proof, which emits no heads: (f) fails.",
        ["hosted"],
        [sign_head(h) for h in chain_of(tips("hosted"))],
        {"f": failed("signer_not_marked_for_heads", proof_sequence=1, signer="unmarked_authority")},
    )

    add(
        "head_under_hosted_authority_names_customer_proof",
        "A head under a hosted authority names a customer's proof. The proof is listed and "
        "anchored, so (c) holds; the head's authority emits no heads, so (f) fails before any "
        "key is read.",
        ["a1"],
        [sign_head(h, "1", KEY_HOSTED) for h in chain_of(tips("a1"), HOSTED)],
        {"f": failed("signer_not_marked_for_heads", proof_sequence=1, signer="unmarked_authority")},
    )

    add(
        "head_under_unmarked_authority",
        "A head under an authority the key list carries without the marker, naming that "
        "authority's own proof: it emits no heads, so (f) fails.",
        ["hosted_eu"],
        [sign_head(h, "1", KEY_HOSTED_EU) for h in chain_of(tips("hosted_eu"), HOSTED_EU)],
        {"f": failed("signer_not_marked_for_heads", proof_sequence=1, signer="unmarked_authority")},
    )

    add(
        "head_under_authority_not_in_the_key_list",
        "A head under an authority the key list does not carry: it is not known to emit no "
        "heads, and it has no registered key, so (f) fails.",
        ["unlisted1"],
        [sign_head(h, "1", KEY_UNREGISTERED) for h in chain_of(tips("unlisted1"), AUTH_UNLISTED)],
        {
            "f": failed(
                "head_signing_key_unknown",
                proof_sequence=1,
                authority_id=AUTH_UNLISTED,
                signing_key_version="1",
            )
        },
    )

    proofs = ["unlisted1"]
    add(
        "proof_under_authority_not_in_the_key_list",
        "A proof under an authority the key list does not carry, with no head: listed as "
        "having no handed head.",
        proofs,
        [],
        {
            "a": not_checked("no heads handed"),
            "b": not_checked("no heads handed"),
            "c": not_checked("no heads handed"),
            "f": not_checked("no heads handed"),
        },
        [unwitnessed(proofs, "unlisted1", "no_handed_head")],
    )

    proofs = ["local", "hosted"]
    add(
        "no_key_list_knows_only_the_local_signer",
        "No key list, so only the local signer is known to emit no heads: the hosted proof "
        "is listed as having no handed head.",
        proofs,
        [],
        {
            "a": not_checked("no heads handed"),
            "b": not_checked("no heads handed"),
            "c": not_checked("no heads handed"),
            "f": not_checked("no heads handed"),
        },
        [
            unwitnessed(proofs, "local", "local_signer"),
            unwitnessed(proofs, "hosted", "no_handed_head"),
        ],
        key_list_supplied=False,
    )

    add(
        "no_key_list",
        "The good chain with no key list: (f) cannot resolve head keys and is not checked; "
        "nothing fails.",
        ["a1", "a2", "a3"],
        [sign_head(h) for h in good],
        {"f": not_checked("needs a registered key list")},
        key_list_supplied=False,
    )

    proofs = ["a1", "a2", "a3"]
    add(
        "proof_without_a_head",
        "Two heads and a third proof of the same authority with no head: listed as "
        "unwitnessed, not a failure. A cut tail is found only by (e).",
        proofs,
        [sign_head(h) for h in two],
        {},
        [unwitnessed(proofs, "a3", "no_handed_head")],
    )

    unlinked = head(1, head_hash(two[0]), leaves["a1"])
    add(
        "first_head_without_genesis_link",
        "The head at sequence 1 does not carry the genesis link: (a) fails.",
        ["a1"],
        [sign_head(unlinked)],
        {
            "a": failed(
                "prev_head_hash_mismatch",
                proof_sequence=1,
                expected=GENESIS_LINK,
                found=head_hash(two[0]),
            )
        },
    )

    twice = chain_of(tips("a1", "a1"))
    add(
        "tip_named_twice",
        "Heads 1 and 2 both name proof 1: (c) fails.",
        ["a1"],
        [sign_head(h) for h in twice],
        {
            "c": failed(
                "tip_named_twice",
                tip_proof_hash=leaves["a1"],
                first_sequence=1,
                second_sequence=2,
            )
        },
    )

    for order, proofs in (
        ("before", ["a1", "a2_forged", "a2", "a3"]),
        ("after", ["a1", "a2", "a2_forged", "a3"]),
    ):
        index = proofs.index("a2_forged")
        add(
            f"forged_copy_{order}_genuine",
            f"A copy of proof 2 with destruction_state edited, handed {order} the genuine "
            "proof 2. It keeps the leaf, because the leaf does not cover the canonical view, "
            "but its signature no longer verifies. Every handed proof with the named leaf "
            "must verify, so (c) and (f) both fail on the forged copy whatever the order.",
            proofs,
            [sign_head(h) for h in good],
            {
                "c": failed(
                    "named_proof_not_verified",
                    proof_sequence=2,
                    proof_index=index,
                    stage_reached=7,
                    failure_reason=SIGNATURE_DOES_NOT_VERIFY,
                ),
                "f": failed(
                    "named_proof_not_anchored",
                    proof_sequence=2,
                    proof_index=index,
                    stage_reached=7,
                    failure_reason=SIGNATURE_DOES_NOT_VERIFY,
                ),
            },
        )

    add(
        "one_proof_named_twice_through_an_unsigned_field",
        "Proof 1 and a copy with attestation.key_id rewritten. The key_id is in the leaf "
        "but not under the signature, so the leaves differ and both copies verify. Head 1 "
        "names proof 1 and head 2 names the copy; both signatures cover one message under "
        "one authority, so (c) fails: one document is named twice.",
        ["a1", "a1_key_id_rewritten"],
        [sign_head(h) for h in chain_of(tips("a1", "a1_key_id_rewritten"))],
        {
            "c": failed(
                "tip_named_twice",
                tip_proof_hash=leaves["a1_key_id_rewritten"],
                first_sequence=1,
                second_sequence=2,
            )
        },
    )

    add(
        "head_key_under_two_authorities",
        "Authority D's key is also listed under authority E. A head signed with it cannot "
        "be tied to one authority, so (f) fails.",
        ["d1"],
        [sign_head(h, "1", KEY_D1) for h in chain_of(tips("d1"), AUTH_D)],
        {
            "f": failed(
                "head_key_under_several_authorities",
                proof_sequence=1,
                authority_ids=sorted([AUTH_D, AUTH_E]),
            )
        },
    )
    proofs = ["a1_verification_key_only"]
    add(
        "copy_without_public_key_has_no_leaf",
        "The head names proof 1's leaf, but the only copy handed carries its key under "
        "verification_key instead of public_key. The leaf reads public_key only, so the copy "
        "has no leaf: (c) fails, and the copy is listed as unwitnessed with no tip.",
        proofs,
        [sign_head(h) for h in chain_of(tips("a1"))],
        {
            "c": failed("tip_matches_no_proof", proof_sequence=1, tip_proof_hash=leaves["a1"]),
            "f": not_checked("a named proof was not handed"),
        },
        [unwitnessed(proofs, "a1_verification_key_only", "no_handed_head")],
    )
    add(
        "head_key_archived_under_a_revoked_authority",
        "Authority F's key is also among the archived versions of authority G, which the "
        "key list marks revoked. A revoked authority and an archived version still list the "
        "key, so a head signed with it cannot be tied to one authority, and (f) fails.",
        ["f1"],
        [sign_head(h, "1", KEY_F1) for h in chain_of(tips("f1"), AUTH_F)],
        {
            "f": failed(
                "head_key_under_several_authorities",
                proof_sequence=1,
                authority_ids=sorted([AUTH_F, AUTH_G]),
            )
        },
    )
    add(
        "head_key_listed_again_with_a_base64_prefix",
        "Authority I lists authority H's key with a base64: prefix. Keys are compared as "
        "decoded bytes, so the prefixed listing is the same key, and (f) fails.",
        ["h1"],
        [sign_head(h, "1", KEY_H1) for h in chain_of(tips("h1"), AUTH_H)],
        {
            "f": failed(
                "head_key_under_several_authorities",
                proof_sequence=1,
                authority_ids=sorted([AUTH_H, AUTH_I]),
            )
        },
    )

    first = head(1, GENESIS_LINK, leaves["a1"])
    misplaced = head(2, GENESIS_LINK, leaves["a2"])
    add(
        "genesis_misplaced",
        "Head 2 carries the genesis link, which only the head at sequence 1 may carry: "
        "(a) fails.",
        ["a1", "a2"],
        [sign_head(first), sign_head(misplaced)],
        {"a": failed("genesis_misplaced", proof_sequence=2)},
    )

    add(
        "named_proof_not_verified",
        "Head 2 names a proof whose only handed copy has destruction_state edited: its "
        "signature does not verify, so (c) fails, and it is not anchored, so (f) fails.",
        ["a1", "a2_forged"],
        [sign_head(h) for h in two],
        {
            "c": failed(
                "named_proof_not_verified",
                proof_sequence=2,
                proof_index=1,
                stage_reached=7,
                failure_reason=SIGNATURE_DOES_NOT_VERIFY,
            ),
            "f": failed(
                "named_proof_not_anchored",
                proof_sequence=2,
                proof_index=1,
                stage_reached=7,
                failure_reason=SIGNATURE_DOES_NOT_VERIFY,
            ),
        },
    )

    add(
        "head_signing_key_unknown",
        "Head 2 names key version 9 of authority A, which the key list does not hold: "
        "(f) fails.",
        ["a1", "a2"],
        [sign_head(two[0]), sign_head(two[1], "9", KEY_A1)],
        {
            "f": failed(
                "head_signing_key_unknown",
                proof_sequence=2,
                authority_id=AUTH_A,
                signing_key_version="9",
            )
        },
    )

    add(
        "head_authority_revoked",
        "Heads under an authority the key list marks revoked, naming that authority's own "
        "proof: (f) fails.",
        ["revoked1"],
        [sign_head(h, "1", KEY_R1) for h in chain_of(tips("revoked1"), AUTH_R)],
        {"f": failed("head_authority_revoked", proof_sequence=1, authority_id=AUTH_R)},
    )

    add(
        "head_algorithm_unsupported",
        "Head 2 names key version 3 of authority A, which the key list records as an "
        "ML-DSA-65 key; this verifier checks head signatures only as Ed25519, so (f) fails.",
        ["a1", "a2"],
        [sign_head(two[0]), sign_head(two[1], "3", KEY_A3)],
        {"f": failed("head_algorithm_unsupported", proof_sequence=2, found="ML-DSA-65")},
    )

    add(
        "named_proof_not_anchored",
        "Head 2 names a proof that claims authority A's key version 1 but was signed with a "
        "key no authority lists. It verifies under its embedded key, so (c) holds; it does "
        "not verify under the key list, so (f) fails.",
        ["a1", "a5_unregistered_key"],
        [sign_head(h) for h in chain_of(tips("a1", "a5_unregistered_key"))],
        {
            "f": failed(
                "named_proof_not_anchored",
                proof_sequence=2,
                proof_index=1,
                stage_reached=7,
                failure_reason=SIGNATURE_DOES_NOT_VERIFY,
            )
        },
    )

    add(
        "identical_head_handed_twice",
        "Head 2 is handed twice, the same bytes under the same key version. A copy is not a "
        "fork, so (a), (b) and (c) read it once, and each copy's signature verifies.",
        ["a1", "a2", "a3"],
        [sign_head(good[0]), sign_head(good[1]), sign_head(good[1]), sign_head(good[2])],
        {},
    )

    add(
        "identical_copy_with_a_bad_signature",
        "Head 2 is handed twice under the same key version, the second copy signed with "
        "another key. (a), (b) and (c) read one head, and (f) checks every copy, so (f) fails.",
        ["a1", "a2", "a3"],
        [
            sign_head(good[0]),
            sign_head(good[1]),
            sign_head(good[1], "1", KEY_B1),
            sign_head(good[2]),
        ],
        {"f": failed("head_signature_mismatch", proof_sequence=2, reason="does_not_verify")},
    )

    add(
        "same_head_under_two_key_versions",
        "One head body signed under key versions 1 and 8, both in window. The signer used two "
        "keys at one sequence, so they stay two heads: (b) and (c) fail, and (f) holds.",
        ["a1", "a2"],
        [sign_head(two[0]), sign_head(two[0], "8", KEY_A0), sign_head(two[1])],
        {
            "b": failed("duplicate_sequence", proof_sequence=1),
            "c": failed(
                "tip_named_twice",
                tip_proof_hash=leaves["a1"],
                first_sequence=1,
                second_sequence=1,
            ),
        },
    )

    add(
        "named_proof_has_no_signature",
        "The named proof has an empty signature. It is valid as far as stage 4, and that is "
        "short of both bars: (c) needs stage 7 and (f) needs stage 8.",
        ["a1_no_signature"],
        [sign_head(h) for h in chain_of(tips("a1_no_signature"))],
        {
            "c": failed(
                "named_proof_not_verified",
                proof_sequence=1,
                proof_index=0,
                stage_reached=4,
                failure_reason=None,
            ),
            "f": failed(
                "named_proof_not_anchored",
                proof_sequence=1,
                proof_index=0,
                stage_reached=4,
                failure_reason=None,
            ),
        },
    )

    add(
        "chain_continues_across_key_rotation",
        "Head 1 is under key version 8, issued before that version was archived; head 2 is "
        "under version 1. Nothing fails. Registration does not produce this shape today: "
        "the registration design gates marking on the rotation model.",
        ["a1", "a2"],
        [sign_head(two[0], "8", KEY_A0), sign_head(two[1])],
        {},
    )

    window_cases = [
        ("head_after_its_key_was_archived", "Head 2 is issued after key version 8 was archived.",
         "8", KEY_A0, EFFECTIVE_FROM, ARCHIVED_AT),
        ("head_before_its_key_took_effect", "Head 2 is issued before key version 4 took effect.",
         "4", KEY_A4, EFFECTIVE_LATER, None),
        ("key_list_effective_from_unreadable", "Key version 5's effective_from cannot be read.",
         "5", KEY_A5, UNREADABLE_TIME, None),
        ("key_list_archived_at_unreadable", "Key version 6's archived_at cannot be read.",
         "6", KEY_A6, EFFECTIVE_FROM, UNREADABLE_TIME),
        ("archived_key_with_no_end", "Key version 7 is archived with no archived_at.",
         "7", KEY_A7, EFFECTIVE_FROM, None),
    ]
    for name, why, version, key, effective_from, archived_at in window_cases:
        add(
            name,
            f"{why} The head is not shown to be inside the key's window, so (f) fails.",
            ["a1", "a2"],
            [sign_head(two[0]), sign_head(two[1], version, key)],
            {
                "f": failed(
                    "head_outside_key_window",
                    proof_sequence=2,
                    signing_key_version=version,
                    issued_at=two[1]["issued_at"],
                    effective_from=effective_from,
                    archived_at=archived_at,
                )
            },
        )

    def issued(name: str, issued_at: str) -> Dict[str, Any]:
        return {**head(1, GENESIS_LINK, leaves[name]), "issued_at": issued_at}

    def issued_pair(first_at: str, second_at: str) -> List[Dict[str, Any]]:
        first = issued("a1", first_at)
        second = {
            **head(2, head_hash(first), leaves["a2"]),
            "issued_at": second_at,
        }
        return [first, second]

    backward = issued_pair("2026-10-28T02:05:01Z", "2026-10-28T02:05:00Z")
    add(
        "head_issued_before_the_head_below_it",
        "Head 2 was issued a second before head 1: (b) fails, because a chain runs forward "
        "in time.",
        ["a1", "a2"],
        [sign_head(h) for h in backward],
        {
            "b": failed(
                "head_issued_before_previous",
                proof_sequence=2,
                issued_at=backward[1]["issued_at"],
                previous_issued_at=backward[0]["issued_at"],
            )
        },
    )

    same_second = issued_pair("2026-10-28T02:05:00Z", "2026-10-28T02:05:00Z")
    add(
        "heads_share_a_second",
        "Two heads in one second: time stands still between them, it does not go back.",
        ["a1", "a2"],
        [sign_head(h) for h in same_second],
        {},
    )

    backdated = issued_pair("2026-10-28T02:02:00Z", ARCHIVED_AT)
    add(
        "retired_key_backdates_a_head",
        "Key version 8 was archived, and it extends the chain with a head dated inside its "
        "window. Its signature and window hold; (b) fails, because the head is older than "
        "the head below it.",
        ["a1", "a2"],
        [sign_head(backdated[0]), sign_head(backdated[1], "8", KEY_A0)],
        {
            "b": failed(
                "head_issued_before_previous",
                proof_sequence=2,
                issued_at=ARCHIVED_AT,
                previous_issued_at=backdated[0]["issued_at"],
            )
        },
    )

    add(
        "v1_0_proof_named",
        "A cdp_version 1.0 signature covers final_hash alone, so the proof does not show "
        "which authority it is under: (f) fails, whatever authority it names.",
        ["a9_v1_0"],
        [sign_head(h) for h in chain_of(tips("a9_v1_0"))],
        {
            "f": failed(
                "named_proof_version_unsupported",
                proof_sequence=1,
                proof_index=0,
                cdp_version="1.0",
            )
        },
    )

    add(
        "v1_0_proof_named_no_key_list",
        "The same head with no key list: (f) needs no key list to refuse it.",
        ["a9_v1_0"],
        [sign_head(h) for h in chain_of(tips("a9_v1_0"))],
        {
            "f": failed(
                "named_proof_version_unsupported",
                proof_sequence=1,
                proof_index=0,
                cdp_version="1.0",
            )
        },
        key_list_supplied=False,
    )

    add(
        "v2_2_proof_named",
        "A cdp_version 2.2 signature covers the proof's authority, so a head may name it.",
        ["a8_v2_2"],
        [sign_head(h) for h in chain_of(tips("a8_v2_2"))],
        {},
    )

    add(
        "proof_under_a_shared_key_named_by_the_other_authority",
        "Authority E lists authority D's key. A proof signed under E is not D's, and a head "
        "under D that names it fails (f), though the key is D's too.",
        ["e1_key_shared_with_d"],
        [
            sign_head(h, key=KEY_D1)
            for h in chain_of(tips("e1_key_shared_with_d"), AUTH_D)
        ],
        {
            "f": failed(
                "named_proof_authority_mismatch",
                proof_sequence=1,
                head_authority=AUTH_D,
                proof_authority=AUTH_E,
            )
        },
    )

    add(
        "proof_authority_writes_a_line",
        "A proof's authority holds a newline, a forged check line and a terminal erase "
        "sequence. Whoever holds the key can sign that: (f) fails. The population CLI tests "
        "prove a reader's output escapes it.",
        ["a11_authority_writes_a_line"],
        [sign_head(h) for h in chain_of(tips("a11_authority_writes_a_line"))],
        {
            "f": failed(
                "named_proof_authority_mismatch",
                proof_sequence=1,
                head_authority=AUTH_A,
                proof_authority=FORGED_LINE_AUTHORITY,
            )
        },
    )

    one_head = [sign_head(h) for h in chain_of(tips("a1"))]
    relabelled = [
        ("attestation_pointer_claims_local", "a2_attestation_claims_local", "no_handed_head", True,
         "The proof verifies, and a copy of the key version inside the attestation says the "
         "local signer, but the key list holds its key."),
        ("attestation_pointer_claims_local_unlisted_key", "local_name_pointer_claims_local",
         "no_handed_head", True,
         "The proof names the local signer's authority under a key the list does not hold, with "
         "a numeric key version. A copy of the key version inside the attestation says the local "
         "signer. No signature covers that copy, so it is not read."),
        ("authority_set_to_local", "a2_authority_set_local", "proof_not_verified", True,
         "The proof's authority was changed to the local signer's name, so its signature no "
         "longer verifies and nothing it says about its signer can be read."),
        ("authority_set_to_hosted", "a2_authority_set_hosted", "proof_not_verified", True,
         "The proof's authority was changed to a hosted one, so its signature no longer "
         "verifies and nothing it says about its signer can be read."),
        ("authority_deleted", "a2_authority_deleted", "proof_not_verified", True,
         "The proof's authority was deleted, which reads as the hosted default; its signature "
         "no longer verifies."),
        ("empty_document", "not_a_proof_empty", "proof_not_verified", True,
         "An empty document is not a proof of any signer."),
        ("authority_only_document", "not_a_proof_authority_only", "proof_not_verified", True,
         "A document holding only a hosted authority is not a hosted proof."),
        ("version_0_relabelled_local", "a0_relabelled_local", "no_handed_head", True,
         "A key version 0 proof relabelled local verifies, but the key list holds its key "
         "under version 8, so "
         "it is not the local signer's."),
        ("version_0_relabelled_local_no_key_list", "a0_relabelled_local", "no_handed_head", False,
         "The same proof with no key list: its signature covers authority A, so it does not "
         "name the local signer."),
        ("version_0_relabelled_local_unlisted_authority", "unlisted_v0_relabelled_local",
         "no_handed_head", True,
         "A key version 0 proof under an authority the list does not carry, relabelled local. "
         "The list does not hold its key, but its signature covers that authority, so it does "
         "not name the local signer."),
        ("throwaway_key_keeps_a_marked_authority", "throwaway_key_keeps_a", "no_handed_head", True,
         "A proof signed with a key anyone can mint, carrying the local signer's key version and "
         "keeping an authority that emits heads. Its signature covers that authority, so it does "
         "not name the local signer."),
        ("local_version_on_a_hosted_authority", "local_version_on_hosted_authority",
         "no_handed_head", True,
         "The local signer's key version under a hosted authority's name, which the local signer "
         "no longer writes. Its signature covers the hosted name."),
        ("local_name_under_a_listed_key", "local_name_listed_key", "no_handed_head", True,
         "The signature covers the local signer's name and the proof carries its key version, "
         "but the key list holds the key, so a key holder wrote those words."),
        ("local_name_on_version_1_0", "local_v1_0", "no_handed_head", True,
         "A version 1.0 proof names the local signer in fields its signature does not cover."),
        ("hosted_name_on_an_unlisted_key", "hosted_unlisted_key", "no_handed_head", True,
         "The proof names a hosted authority and verifies alone, but not under that authority's "
         "listed key, so it is not shown to be hosted."),
    ]
    for name, proof, reason, supplied, why in relabelled:
        add(
            f"unwitnessed_{name}",
            f"{why} The reason is {reason}.",
            ["a1", proof],
            one_head,
            {} if supplied else {"f": not_checked("needs a registered key list")},
            [unwitnessed(["a1", proof], proof, reason)],
            key_list_supplied=supplied,
        )

    late = "2026-10-28T03:00:00Z"
    add(
        "key_version_in_both_lists",
        "Key version 1 of authority J is active and also archived, and the head is dated after "
        "the archived record's end. The list gives that version no one window: (f) fails.",
        ["j1"],
        [
            sign_head({**h, "issued_at": late}, "1", KEY_J1)
            for h in chain_of(tips("j1"), AUTH_J)
        ],
        {
            "f": failed(
                "head_key_record_not_unique",
                proof_sequence=1,
                authority_id=AUTH_J,
                signing_key_version="1",
            )
        },
    )
    add(
        "key_version_twice_in_one_list",
        "Key version 2 of authority J is held twice among the active versions: (f) fails.",
        ["j2"],
        [sign_head({**h, "issued_at": late}, "2", KEY_J2) for h in chain_of(tips("j2"), AUTH_J)],
        {
            "f": failed(
                "head_key_record_not_unique",
                proof_sequence=1,
                authority_id=AUTH_J,
                signing_key_version="2",
            )
        },
    )

    add(
        "key_reused_under_a_later_version",
        "Authority L holds one key under version 1, archived, and under version 9, active. A "
        "head dated past the archive end under 9 would reopen the retired key: (f) fails.",
        ["l1"],
        [sign_head({**h, "issued_at": late}, "9", KEY_L1) for h in chain_of(tips("l1"), AUTH_L)],
        {
            "f": failed(
                "head_key_record_not_unique",
                proof_sequence=1,
                authority_id=AUTH_L,
                signing_key_version="9",
            )
        },
    )
    add(
        "key_version_with_two_keys",
        "Authority M holds version 1 twice, with a different key in each record, so the list "
        "does not say which key version 1 is: (f) fails.",
        ["m1"],
        [sign_head({**h, "issued_at": late}, "1", KEY_M1) for h in chain_of(tips("m1"), AUTH_M)],
        {
            "f": failed(
                "head_key_record_not_unique",
                proof_sequence=1,
                authority_id=AUTH_M,
                signing_key_version="1",
            )
        },
    )

    variants: Dict[str, Dict[str, Any]] = {}

    def add_variant(
        name: str,
        description: str,
        edit: Callable[[Dict[str, Any]], None],
        proofs: List[str],
        heads: List[Dict[str, Any]],
        expected: Dict[str, Any],
        unwitnessed_proofs: Optional[List[Dict[str, Any]]] = None,
        heads_parse: bool = True,
    ) -> None:
        variants[name] = key_list(edit=edit)
        add(
            name,
            description,
            proofs,
            heads,
            expected,
            unwitnessed_proofs,
            heads_parse=heads_parse,
            key_list_variant=name,
        )

    late_b_heads = [
        sign_head({**h, "issued_at": late}, "1", KEY_B1) for h in chain_of(tips("b2"), AUTH_B)
    ]

    def holding(*records: Tuple[str, str, Dict[str, Any]]) -> Callable[[Dict[str, Any]], None]:
        """An edit appending each (holder, list, record) to the key list."""

        def edit(authorities: Dict[str, Any]) -> None:
            for holder, versions, record in records:
                authorities[holder][versions].append(record)

        return edit

    def add_listed_key_record(
        name: str,
        description: str,
        holder: str,
        record: Dict[str, Any],
        expected: Dict[str, Any],
    ) -> None:
        add_variant(
            name,
            description,
            holding((holder, "archived_versions", record)),
            ["b2"],
            late_b_heads,
            expected,
        )

    def b_effective_from(text: str) -> Callable[[Dict[str, Any]], None]:
        def edit(authorities: Dict[str, Any]) -> None:
            authorities[AUTH_B]["active_versions"][0]["effective_from"] = text

        return edit

    for name, why, text in REFUSED_EFFECTIVE_FROM:
        add_variant(
            f"key_list_effective_from_{name}",
            f"Authority B's key version 1 takes effect {why}, which the time grammar does not "
            "read, so the head is not shown to be inside the key's window: (f) fails.",
            b_effective_from(text),
            ["b2"],
            late_b_heads,
            {
                "f": failed(
                    "head_outside_key_window",
                    proof_sequence=1,
                    signing_key_version="1",
                    issued_at=late,
                    effective_from=text,
                    archived_at=None,
                )
            },
        )

    def retired_b_key(text: str) -> Dict[str, Any]:
        record = version_record("8", raw_public(KEY_B1), archived_at=ARCHIVED_AT)
        return {**record, "public_key_b64": text}

    def b_record(**fields: Any) -> Dict[str, Any]:
        record = version_record("8", raw_public(KEY_B1), archived_at=ARCHIVED_AT)
        return {**record, **fields}

    def other_key_record(version: str) -> Dict[str, Any]:
        return version_record(version, raw_public(KEY_B8), archived_at=ARCHIVED_AT)

    def ml_dsa_record(text: Optional[str] = None, version: str = "8") -> Dict[str, Any]:
        record = version_record(version, ML_DSA_65_B8, "ML-DSA-65", archived_at=ARCHIVED_AT)
        return record if text is None else {**record, "public_key_b64": text}

    def refused(holder: str, field: str, version: str = "8") -> Dict[str, Any]:
        return {
            "f": failed(
                "key_list_record_refused",
                authority_id=holder,
                signing_key_version=version,
                field=field,
            )
        }

    standard = b64(raw_public(KEY_B1))
    spki = "MCowBQYDK2VwAyEA" + standard
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    trailing_bit = alphabet[alphabet.index(standard[-2]) + 1]

    # A key in a text the record grammar does not read.
    add_listed_key_record(
        "key_retired_in_unpadded_base64",
        "Authority B also holds its key retired under version 8, without padding. The record "
        "would read as a second key, so the retirement would not count: (f) fails.",
        AUTH_B,
        retired_b_key(standard.rstrip("=")),
        refused(AUTH_B, "public_key_b64"),
    )
    add_listed_key_record(
        "key_retired_in_hex",
        "The same record in hex, which decodes as base64 to 48 bytes: (f) fails on the length.",
        AUTH_B,
        retired_b_key(raw_public(KEY_B1).hex()),
        refused(AUTH_B, "public_key_b64"),
    )
    add_listed_key_record(
        "key_retired_with_trailing_bits",
        "The same record in standard base64 with a trailing bit set: (f) fails.",
        AUTH_B,
        retired_b_key(standard[:-2] + trailing_bit + "="),
        refused(AUTH_B, "public_key_b64"),
    )
    add_listed_key_record(
        "key_retired_as_spki",
        "The same record as an SPKI text, which is 16 characters and then the key's own "
        "standard text, so a reader searching the list finds the key: 44 bytes, (f) fails.",
        AUTH_B,
        retired_b_key(spki),
        refused(AUTH_B, "public_key_b64"),
    )
    add_listed_key_record(
        "key_retired_after_a_zero_byte",
        "The same record with a zero byte before the key: 33 bytes, (f) fails.",
        AUTH_B,
        retired_b_key(b64(bytes(1) + raw_public(KEY_B1))),
        refused(AUTH_B, "public_key_b64"),
    )
    add_listed_key_record(
        "key_retired_one_byte_short",
        "The same record with the key's last byte cut: 31 bytes, (f) fails.",
        AUTH_B,
        retired_b_key(b64(raw_public(KEY_B1)[:-1])),
        refused(AUTH_B, "public_key_b64"),
    )
    add_listed_key_record(
        "key_retired_empty",
        "A record of B with an empty key: (f) fails.",
        AUTH_B,
        retired_b_key(""),
        refused(AUTH_B, "public_key_b64"),
    )
    add_listed_key_record(
        "ml_dsa_65_record_with_an_ed25519_key",
        "Authority B holds its 32-byte key under the label ML-DSA-65, whose keys are 1952 "
        "bytes: (f) fails on the length.",
        AUTH_B,
        b_record(algorithm="ML-DSA-65"),
        refused(AUTH_B, "public_key_b64"),
    )
    for name, description, text in [
        (
            "ml_dsa_65_key_in_unpadded_base64",
            "Authority B holds an ML-DSA-65 key without its padding: (f) fails.",
            None,
        ),
        (
            "ml_dsa_65_key_in_hex",
            "Authority B holds an ML-DSA-65 key in hex, which decodes as base64 to 2928 bytes: "
            "(f) fails on the length.",
            ML_DSA_65_B8.hex(),
        ),
        (
            "ml_dsa_65_key_as_spki",
            "Authority B holds an ML-DSA-65 key as the base64 of its SPKI, 1974 bytes: (f) "
            "fails on the length.",
            b64(ML_DSA_65_SPKI_PREFIX + ML_DSA_65_B8),
        ),
        (
            "ml_dsa_65_key_after_a_zero_byte",
            "Authority B holds an ML-DSA-65 key with a zero byte before it, 1953 bytes: (f) "
            "fails on the length.",
            b64(bytes(1) + ML_DSA_65_B8),
        ),
        (
            "ml_dsa_65_key_one_byte_short",
            "Authority B holds an ML-DSA-65 key with its last byte cut, 1951 bytes: (f) fails "
            "on the length.",
            b64(ML_DSA_65_B8[:-1]),
        ),
    ]:
        if text is None:
            text = b64(ML_DSA_65_B8).rstrip("=")
        add_listed_key_record(
            name,
            description,
            AUTH_B,
            ml_dsa_record(text),
            refused(AUTH_B, "public_key_b64"),
        )
    add_listed_key_record(
        "key_under_another_authority_in_unpadded_base64",
        "Authority D lists B's key without padding, which would hide that two authorities "
        "hold it: (f) fails.",
        AUTH_D,
        retired_b_key(standard.rstrip("=")),
        refused(AUTH_D, "public_key_b64"),
    )
    add_listed_key_record(
        "key_under_another_authority_in_hex",
        "Authority D lists B's key in hex: (f) fails on the length.",
        AUTH_D,
        retired_b_key(raw_public(KEY_B1).hex()),
        refused(AUTH_D, "public_key_b64"),
    )
    add_listed_key_record(
        "key_under_another_authority_as_spki_under_eddsa",
        "Authority D lists B's key as SPKI under the label EdDSA. The label is read first, "
        "so (f) fails on it.",
        AUTH_D,
        b_record(public_key_b64=spki, algorithm="EdDSA"),
        refused(AUTH_D, "algorithm"),
    )

    # A label the record grammar does not know.
    for name, label, what in [
        ("key_retired_under_a_lower_case_label", "ed25519", "in lower case"),
        ("key_retired_under_the_label_eddsa", "EdDSA", "EdDSA, the JOSE name for Ed25519"),
        ("key_retired_under_a_label_with_a_trailing_space", "Ed25519 ", "with a trailing space"),
        ("key_retired_under_an_empty_label", "", "empty"),
    ]:
        add_listed_key_record(
            name,
            f"Authority B also holds its key retired under version 8, labelled {what}. Only "
            "Ed25519 and ML-DSA-65 are known labels: (f) fails.",
            AUTH_B,
            b_record(algorithm=label),
            refused(AUTH_B, "algorithm"),
        )
    add_listed_key_record(
        "record_under_an_unknown_algorithm",
        "Authority B holds an ML-DSA-87 record with a key of that algorithm's length. "
        "ML-DSA-87 is not a known label: (f) fails.",
        AUTH_B,
        version_record("8", ML_DSA_87_B8, "ML-DSA-87", archived_at=ARCHIVED_AT),
        refused(AUTH_B, "algorithm"),
    )

    # A fingerprint that is not the SHA-256 of the record's key.
    add_listed_key_record(
        "fingerprint_of_another_key",
        "Authority B holds another key under version 8, with B's own fingerprint, so the list "
        "would show B's fingerprint retired: (f) fails.",
        AUTH_B,
        {**other_key_record("8"), "public_key_fingerprint": fingerprint(raw_public(KEY_B1))},
        refused(AUTH_B, "public_key_fingerprint"),
    )
    add_listed_key_record(
        "fingerprint_under_another_authority",
        "Authority D holds another key with B's fingerprint, so the list would show B's "
        "fingerprint under D: (f) fails.",
        AUTH_D,
        {**other_key_record("8"), "public_key_fingerprint": fingerprint(raw_public(KEY_B1))},
        refused(AUTH_D, "public_key_fingerprint"),
    )
    add_listed_key_record(
        "ml_dsa_65_record_with_another_keys_fingerprint",
        "Authority B holds an ML-DSA-65 record of that algorithm's length with B's Ed25519 "
        "fingerprint. The fingerprint is read under every label: (f) fails.",
        AUTH_B,
        {**ml_dsa_record(), "public_key_fingerprint": fingerprint(raw_public(KEY_B1))},
        refused(AUTH_B, "public_key_fingerprint"),
    )
    upper_case = "sha256:" + hashlib.sha256(raw_public(KEY_B1)).hexdigest().upper()
    add_listed_key_record(
        "fingerprint_in_upper_case_hex",
        "Authority B holds its key with the fingerprint in upper-case hex: (f) fails.",
        AUTH_B,
        b_record(public_key_fingerprint=upper_case),
        refused(AUTH_B, "public_key_fingerprint"),
    )

    # A version that is not the decimal text of an integer from 1 to 2^63 - 1. A
    # document's signature covers its version only as an integer, so 01 and +1
    # are 1 to it, and the other texts are 0.
    for name, version in [
        ("version_with_a_leading_zero", "01"),
        ("version_with_a_plus_sign", "+1"),
        ("version_with_a_leading_space", " 1"),
        ("version_with_an_underscore", "1_0"),
        ("version_as_a_decimal_fraction", "1.0"),
        ("version_with_a_letter", "v8"),
        ("version_minus_zero", "-0"),
        ("version_past_the_largest_integer", "9223372036854775808"),
    ]:
        add_listed_key_record(
            name,
            f"Authority B holds another key archived under version {json.dumps(version)}, "
            "which is not the decimal text of an integer: (f) fails.",
            AUTH_B,
            other_key_record(version),
            refused(AUTH_B, "signing_key_version", version),
        )
    for name, version in [("version_zero", "0"), ("version_minus_one", "-1")]:
        add_listed_key_record(
            name,
            f"Authority B holds another key archived under version {json.dumps(version)}. "
            "Versions run from 1: the registry writes none lower, and a document whose version "
            "cannot be read is under version 0 to its signature. (f) fails.",
            AUTH_B,
            other_key_record(version),
            refused(AUTH_B, "signing_key_version", version),
        )
    add_listed_key_record(
        "ml_dsa_65_record_under_a_leading_zero_version",
        "Authority B holds an ML-DSA-65 key of that length under version \"01\": the version "
        "is read under every label, so (f) fails.",
        AUTH_B,
        ml_dsa_record(version="01"),
        refused(AUTH_B, "signing_key_version", "01"),
    )
    add_variant(
        "key_under_two_spellings_of_a_version",
        "Authority K holds one key under version 1, archived, and under 01, active. A "
        "signature reads 01 as 1, so the list would give the retired key a second window: "
        "(f) fails.",
        lambda authorities: authorities.update(
            {
                AUTH_K: authority(
                    "Example customer authority K, holding one key under 1 and 01",
                    [version_record("01", raw_public(KEY_K1))],
                    archived=[
                        version_record("1", raw_public(KEY_K1), archived_at=ARCHIVED_AT)
                    ],
                )
            }
        ),
        ["k1"],
        [sign_head({**h, "issued_at": late}, "01", KEY_K1) for h in chain_of(tips("k1"), AUTH_K)],
        refused(AUTH_K, "signing_key_version", "01"),
    )

    # Records the grammar reads.
    add_listed_key_record(
        "record_of_another_algorithm_and_length",
        "Authority B also holds an ML-DSA-65 record with a key of that algorithm's length, "
        "1952 bytes, in standard base64. The record is inside the grammar and names another "
        "key, so nothing fails.",
        AUTH_B,
        ml_dsa_record(),
        {},
    )
    no_label = retired_b_key(standard)
    del no_label["algorithm"]
    add_listed_key_record(
        "key_retired_under_no_label",
        "Authority B also holds its key retired under version 8 with no label, which reads "
        "as Ed25519. The record is read, so B holds its key twice: (f) fails.",
        AUTH_B,
        no_label,
        {
            "f": failed(
                "head_key_record_not_unique",
                proof_sequence=1,
                authority_id=AUTH_B,
                signing_key_version="1",
            )
        },
    )
    add_listed_key_record(
        "largest_version",
        "Authority B holds another key under version 9223372036854775807, the largest signed "
        "64-bit integer: inside the grammar, so nothing fails.",
        AUTH_B,
        other_key_record("9223372036854775807"),
        {},
    )

    # Which record is named, and that the refusal comes before every other
    # finding of (f) and stands with any heads.
    add_variant(
        "refused_record_among_the_active_versions",
        "Authority B holds an active record without padding: active records are read too, "
        "so (f) fails.",
        holding(
            (
                AUTH_B,
                "active_versions",
                {**other_key_record("8"), "public_key_b64": b64(raw_public(KEY_B8)).rstrip("=")},
            )
        ),
        ["b2"],
        late_b_heads,
        refused(AUTH_B, "public_key_b64"),
    )
    add_variant(
        "two_refused_records_under_two_authorities",
        "Authority B holds a refused record under version 8 and authority D one under version "
        "7. Authorities are read in byte order of authority_id, so (f) names B's.",
        holding(
            (AUTH_B, "archived_versions", retired_b_key(standard.rstrip("="))),
            (
                AUTH_D,
                "archived_versions",
                {**retired_b_key(raw_public(KEY_B1).hex()), "signing_key_version": "7"},
            ),
        ),
        ["b2"],
        late_b_heads,
        refused(AUTH_B, "public_key_b64"),
    )
    add_variant(
        "two_refused_records_under_one_authority",
        "Authority B holds a refused archived record under version 8 and a refused active one "
        "under version 9. Active records are read before archived ones, so (f) names 9.",
        holding(
            (AUTH_B, "archived_versions", retired_b_key(standard.rstrip("="))),
            (
                AUTH_B,
                "active_versions",
                {**other_key_record("9"), "public_key_b64": raw_public(KEY_B8).hex()},
            ),
        ),
        ["b2"],
        late_b_heads,
        refused(AUTH_B, "public_key_b64", "9"),
    )
    add_variant(
        "two_refused_records_in_one_list",
        "Authority B holds two refused archived records, version 9 before version 8. Each "
        "list is read in its order, not by version, so (f) names 9.",
        holding(
            (
                AUTH_B,
                "archived_versions",
                {**other_key_record("9"), "public_key_b64": raw_public(KEY_B8).hex()},
            ),
            (AUTH_B, "archived_versions", retired_b_key(standard.rstrip("="))),
        ),
        ["b2"],
        late_b_heads,
        refused(AUTH_B, "public_key_b64", "9"),
    )
    lookalike_ids = [
        ("authority_id_with_a_cyrillic_letter",
         "with the e of example written as the Cyrillic letter U+0435",
         AUTH_B.replace("example", "\u0435xample")),
        ("authority_id_with_a_zero_width_space", "followed by a zero-width space",
         AUTH_B + "\u200b"),
        ("authority_id_with_a_trailing_space", "followed by a space", AUTH_B + " "),
        ("authority_id_in_upper_case", "in upper case", AUTH_B.upper()),
    ]
    long_id = "customer-kms-example-" + "b" * (129 - len("customer-kms-example--v1")) + "-v1"
    assert len(long_id.encode()) == 129
    lookalike_ids += [
        ("authority_id_empty", "emptied", ""),
        ("authority_id_of_129_bytes", "lengthened to 129 bytes", long_id),
    ]
    for name, spelled, lookalike in lookalike_ids:
        add_variant(
            name,
            f"The list adds an authority whose id is B's {spelled}, holding version 1 with "
            "another key, archived before the head. It would read as B's version 1 retired "
            "beside B's own. A list authority id has the head alphabet, read before its "
            "records: (f) fails.",
            lambda authorities, lookalike=lookalike: authorities.update(
                {
                    lookalike: authority(
                        "Example lookalike of authority B",
                        [],
                        archived=[
                            version_record("1", raw_public(KEY_B8), archived_at=ARCHIVED_AT)
                        ],
                    )
                }
            ),
            ["b2"],
            late_b_heads,
            refused(lookalike, "authority_id", ""),
        )
    add_variant(
        "authority_id_in_upper_case_with_no_records",
        "The list adds a revoked authority whose id is B's in upper case and which holds no "
        "record. It would show a revoked authority that reads as B. Its id is read although "
        "it holds no key: (f) fails.",
        lambda authorities: authorities.update(
            {AUTH_B.upper(): authority("Example lookalike of authority B", [], revoked=True)}
        ),
        ["b2"],
        late_b_heads,
        refused(AUTH_B.upper(), "authority_id", ""),
    )
    dotted_id = "customer-kms-example.b_" + "x" * (128 - len("customer-kms-example.b_-v1")) + "-v1"
    assert len(dotted_id.encode()) == 128
    add_variant(
        "authority_id_of_128_bytes_with_a_dot_and_an_underscore",
        "The list adds an authority whose id is 128 bytes long and holds a dot and an "
        "underscore, holding version 1 with a key no other authority lists. The id is inside "
        "the alphabet, so nothing fails.",
        lambda authorities: authorities.update(
            {
                dotted_id: authority(
                    "Example authority with a long id",
                    [],
                    archived=[version_record("1", raw_public(KEY_B8), archived_at=ARCHIVED_AT)],
                    emits_heads=False,
                )
            }
        ),
        ["b2"],
        late_b_heads,
        {},
    )
    add_listed_key_record(
        "refused_record_at_its_fingerprint_before_its_version",
        "Authority B holds a record whose fingerprint and version are both outside the "
        "grammar. The fingerprint is read first, so (f) names it.",
        AUTH_B,
        {**other_key_record("v8"), "public_key_fingerprint": fingerprint(raw_public(KEY_B1))},
        refused(AUTH_B, "public_key_fingerprint", "v8"),
    )
    add_variant(
        "refused_record_beside_a_head_under_an_unlisted_authority",
        "A head under an authority the key list does not carry, which alone fails with "
        "head_signing_key_unknown, under a list holding a refused record: the refusal comes "
        "first.",
        holding((AUTH_B, "archived_versions", retired_b_key(standard.rstrip("=")))),
        ["unlisted1"],
        [sign_head(h, "1", KEY_UNREGISTERED) for h in chain_of(tips("unlisted1"), AUTH_UNLISTED)],
        refused(AUTH_B, "public_key_b64"),
    )
    proofs = ["a1"]
    add_variant(
        "refused_record_with_no_heads",
        "No heads, under a list holding a refused record: (f) still fails, and the proof is "
        "listed as having no handed head.",
        holding((AUTH_B, "archived_versions", retired_b_key(standard.rstrip("=")))),
        proofs,
        [],
        {
            "a": not_checked("no heads handed"),
            "b": not_checked("no heads handed"),
            "c": not_checked("no heads handed"),
            **refused(AUTH_B, "public_key_b64"),
        },
        [unwitnessed(proofs, "a1", "no_handed_head")],
    )
    malformed_head = sign_head(head(1, GENESIS_LINK, leaves["a1"]))
    malformed_head["head"]["issued_at"] = UNREADABLE_TIME
    add_variant(
        "refused_record_with_a_malformed_head",
        "A malformed head, under a list holding a refused record: (a) fails on the head and "
        "(f) on the list.",
        holding((AUTH_B, "archived_versions", retired_b_key(standard.rstrip("=")))),
        proofs,
        [malformed_head],
        {
            "a": head_malformed(0, "head.issued_at"),
            "b": not_checked("a handed head is malformed"),
            "c": not_checked("a handed head is malformed"),
            **refused(AUTH_B, "public_key_b64"),
        },
        [unwitnessed(proofs, "a1", "no_handed_head")],
        heads_parse=False,
    )
    proofs = ["local", "hosted"]
    add_variant(
        "refused_record_gives_no_signer_reason",
        "A local-signer proof and a hosted proof with no heads, under a list in which "
        "authority D holds the local signer's key in hex. A refused list says nothing a "
        "reason could rest on, so both are listed as having no handed head, not as "
        "local_signer and unmarked_authority.",
        holding(
            (
                AUTH_D,
                "archived_versions",
                {
                    **retired_b_key(raw_public(KEY_LOCAL).hex()),
                    "public_key_fingerprint": fingerprint(raw_public(KEY_LOCAL)),
                },
            ),
        ),
        proofs,
        [],
        {
            "a": not_checked("no heads handed"),
            "b": not_checked("no heads handed"),
            "c": not_checked("no heads handed"),
            **refused(AUTH_D, "public_key_b64"),
        },
        [
            unwitnessed(proofs, "local", "no_handed_head"),
            unwitnessed(proofs, "hosted", "no_handed_head"),
        ],
    )

    add(
        "head_issued_before_proof",
        "The head was issued a second before the proof it names ended: (c) fails.",
        ["a1"],
        [sign_head(issued("a1", "2026-10-28T00:00:59Z"))],
        {
            "c": failed(
                "head_issued_before_proof",
                proof_sequence=1,
                proof_index=0,
                issued_at="2026-10-28T00:00:59Z",
                destroyed_at=pool["a1"]["destroyed_at"],
            )
        },
    )

    add(
        "head_issued_in_the_second_the_proof_ended",
        "The proof ended at 00:06:00.750 and the head was issued at 00:06:00. Times are "
        "compared to the second, so nothing fails.",
        ["a6_fractional_end"],
        [sign_head(issued("a6_fractional_end", "2026-10-28T00:06:00Z"))],
        {},
    )

    add(
        "proof_end_time_unreadable",
        "The named proof's destroyed_at cannot be read as a time, so the head is not shown "
        "to come after it: (c) fails.",
        ["a7_unreadable_end"],
        [sign_head(head(1, GENESIS_LINK, leaves["a7_unreadable_end"]))],
        {
            "c": failed(
                "head_issued_before_proof",
                proof_sequence=1,
                proof_index=0,
                issued_at=head(1, GENESIS_LINK, "")["issued_at"],
                destroyed_at=pool["a7_unreadable_end"]["destroyed_at"],
            )
        },
    )

    after_every_end = "2026-10-28T15:00:00Z"
    for name, why, end in END_TIME_FORMS:
        proof = f"end_{name}"
        named = sign_head(issued(proof, after_every_end))
        if name in READ_END_TIME_FORMS:
            add(
                f"proof_end_time_{name}",
                f"The named proof ended at {end}, {why}. The time grammar reads it, and the "
                "head is issued after it, so nothing fails.",
                [proof],
                [named],
                {},
            )
            continue
        add(
            f"proof_end_time_{name}",
            f"The named proof's destroyed_at {end!r} has {why}, which the time grammar does "
            "not read, so the head is not shown to come after it: (c) fails.",
            [proof],
            [named],
            {
                "c": failed(
                    "head_issued_before_proof",
                    proof_sequence=1,
                    proof_index=0,
                    issued_at=after_every_end,
                    destroyed_at=end,
                )
            },
        )

    # One fault each in a single head that names proof 1. A head that does not
    # fit the shape (a missing or unknown field, or a value of the wrong JSON
    # type) reports field ""; a value of the right type outside the format
    # reports its dotted path.
    def with_head_field(field: str, value: Any) -> Dict[str, Any]:
        signed = sign_head(head(1, GENESIS_LINK, leaves["a1"]))
        signed["head"][field] = value
        return signed

    def with_top_field(field: str, value: Any) -> Dict[str, Any]:
        signed = sign_head(head(1, GENESIS_LINK, leaves["a1"]))
        signed[field] = value
        return signed

    no_authority = sign_head(head(1, GENESIS_LINK, leaves["a1"]))
    del no_authority["head"]["authority_id"]
    unprefixed = sign_head(head(1, GENESIS_LINK, leaves["a1"]))
    unprefixed["signature"] = unprefixed["signature"][len("base64:") :]
    malformed_heads = [
        ("type_of_a_later_version", "A later head type, which this verifier does not know.",
         with_head_field("type", "nanorix-population-head-v3"), "head.type"),
        ("proof_sequence_zero", "proof_sequence 0: sequences start at 1.",
         with_head_field("proof_sequence", 0), "head.proof_sequence"),
        ("proof_sequence_float", "proof_sequence 1.0: a JSON number with a fraction part is "
         "not an integer.", with_head_field("proof_sequence", 1.0), ""),
        ("proof_sequence_string", 'proof_sequence "1": a string is not an integer.',
         with_head_field("proof_sequence", "1"), ""),
        ("proof_sequence_2_pow_53", "proof_sequence 2^53: above 2^53 - 1, the largest "
         "integer RFC 8785 writes exactly.", with_head_field("proof_sequence", 2**53),
         "head.proof_sequence"),
        ("proof_sequence_negative", "proof_sequence -1: not a non-negative integer.",
         with_head_field("proof_sequence", -1), ""),
        ("unknown_field_in_head", "An extra field inside the signed head body.",
         with_head_field("capsule_id", "cap_1"), ""),
        ("unknown_field_beside_head", "An extra top-level field beside the head, outside "
         "the signed bytes.", with_top_field("note", "unsigned"), ""),
        ("authority_id_empty", 'authority_id "": an authority has a name.',
         with_head_field("authority_id", ""), "head.authority_id"),
        ("authority_id_uppercase", "authority_id with an upper case letter: its characters "
         "are a-z, 0-9, ., _ and -.", with_head_field("authority_id", "Customer-kms-v1"),
         "head.authority_id"),
        ("authority_id_129_bytes", "authority_id of 129 bytes: at most 128.",
         with_head_field("authority_id", "a" * 129), "head.authority_id"),
        ("authority_id_non_ascii", "authority_id with a non-ASCII character.",
         with_head_field("authority_id", "caf\u00e9-v1"), "head.authority_id"),
        ("authority_id_missing", "A head with no authority_id.", no_authority, ""),
        ("authority_id_beside_head", "authority_id beside the head, outside the signed bytes.",
         with_top_field("authority_id", AUTH_A), ""),
        ("signature_without_base64_prefix", "The signature without its base64: prefix.",
         unprefixed, "signature"),
        ("issued_at_second_60", "issued_at 2026-10-28T23:59:60Z: seconds run from 00 to 59 "
         "on every date.", with_head_field("issued_at", "2026-10-28T23:59:60Z"),
         "head.issued_at"),
        ("signing_key_version_empty", "An empty signing_key_version: a key version has a name.",
         with_top_field("signing_key_version", ""), "signing_key_version"),
        ("signing_key_version_writes_a_line", "A signing_key_version holding a newline, a forged "
         "check line and a terminal erase sequence: it has the alphabet of authority_id.",
         with_top_field("signing_key_version", FORGED_LINE), "signing_key_version"),
    ]
    for name, why, bad, field in malformed_heads:
        add(
            f"malformed_{name}",
            f"{why} (a) fails with head_malformed at {field or 'the head as a whole'}; "
            "(b), (c) and (f) are not checked, and proof 1 is unwitnessed.",
            ["a1"],
            [bad],
            {
                "a": head_malformed(0, field),
                "b": not_checked("a handed head is malformed"),
                "c": not_checked("a handed head is malformed"),
                "f": not_checked("a handed head is malformed"),
            },
            [unwitnessed(["a1"], "a1", "no_handed_head")],
            heads_parse=False,
        )

    encoding = []
    for h in (good[0], good[2]):
        encoding.append(
            {
                "head": copy.deepcopy(h),
                "canonical_bytes": jcs(h).decode(),
                "head_hash": head_hash(h),
                "signed_message": signed_message(h),
            }
        )

    return {
        "description": (
            "Population head vectors. Each case hands a verifier the named pool "
            "proofs and the heads, with or without the key list, and gives the exact "
            "result it must report. Test-only keys; never a production or ceremony key."
        ),
        "head_type": HEAD_TYPE,
        "genesis_link": GENESIS_LINK,
        "key_list": key_list(),
        "key_list_identity_fingerprint": fingerprint(raw_public(KEY_IDENTITY)),
        "key_list_issued_at_writes_a_line": key_list(FORGED_LINE),
        "key_list_variants": variants,
        "key_list_texts": key_list_texts(),
        "head_texts": head_texts([sign_head(h) for h in good]),
        "proof_pool": pool,
        "proof_stages": stages,
        "proof_failures": failures,
        "leaves": leaves,
        "encoding": encoding,
        "cases": cases,
    }


def render(obj: Any) -> str:
    return json.dumps(obj, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = render(build())
    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"stale: {OUT.name}", file=sys.stderr)
            return 1
        print(f"{OUT.name} up to date")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
