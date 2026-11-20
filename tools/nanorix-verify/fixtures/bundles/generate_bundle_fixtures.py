#!/usr/bin/env python3
"""Deterministic Portable Receipt Bundle fixtures shared by every verifier.

Writes ``<name>.prb.json`` plus ``<name>.expected.json`` for each case into
this directory. The Rust, Go, Python and TypeScript bundle test suites read
the same files and must report the same outcome kind for each one.

Everything is derived from the fixed constants below, so regeneration is
byte-stable. The Ed25519 key is derived from a public, test-only seed and has
no relation to any production or ceremony key.

Usage:
    python3 generate_bundle_fixtures.py            # (re)write the fixtures
    python3 generate_bundle_fixtures.py --check    # exit 1 if files differ

``expected.json`` fields:
    outcome              "valid", "receipt_not_bound", or the error kind that
                         the strict verifier must report.
    signature_authentic  What the detailed verifier reports (outcome "valid" or
                         "receipt_not_bound" only).
    receipt_bound        Same.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent

# Test-only key material. Never a production or ceremony key.
TEST_SEED = hashlib.sha256(b"nanorix-test-only-bundle-fixture-key-v1").digest()
TIMESTAMP = "2026-10-01T00:00:00Z"
GENERATED_AT = "2026-10-01T00:00:01Z"
KEY_ID = "nrx-verify-fixture-test-only"
DISCLAIMER = (
    "This Portable Receipt Bundle carries cryptographic evidence of one "
    "record's structural execution. Verifying party uses the audit_proof_anchors "
    "to verify the receipt's merkle inclusion + outer Ed25519 signature. "
    "Control framework references are NOT included in this bundle; consult "
    "the mapping artifact at "
    "https://nanorix.io/v1/control-map?framework_version={framework_version} to apply current "
    "control mappings at consumption time."
)

GENESIS = hashlib.sha512(b"").hexdigest()
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

_KEY = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
PUBKEY_B64 = base64.b64encode(
    _KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
).decode()


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def label_hash(label: str) -> str:
    return sha512_hex(label.encode())


def sign(message_hex: str) -> str:
    """Ed25519 over the ASCII bytes of a hex string (the signed-message form)."""
    return base64.b64encode(_KEY.sign(message_hex.encode("ascii"))).decode()


def step_hash(prev: str, subsystem: str, method: str, timestamp: str) -> str:
    parts = [prev, subsystem, "destroy", method, timestamp]
    return sha512_hex(b"\x00".join(p.encode() for p in parts))


def step_7(timestamp: str) -> str:
    prev = GENESIS
    for subsystem, method in CANONICAL_CHAIN[:7]:
        prev = step_hash(prev, subsystem, method, timestamp)
    return prev


def step_8_amended(timestamp: str, rrmr: str, ppmr: Optional[str]) -> str:
    base = step_hash(step_7(timestamp), *CANONICAL_CHAIN[7], timestamp)
    data = base.encode() + b"\x00" + rrmr.encode()
    if ppmr is not None:
        data += b"\x00" + ppmr.encode()
    return sha512_hex(data)


def strip_prefix(h: str) -> str:
    return h[len("sha512:"):] if h.startswith("sha512:") else h


def record_chain_hash(
    capsule_id: str, index: int, record_id: str, in_h: str, out_h: str
) -> str:
    # No activity trail: the activity root is the genesis hash; no pattern_tag.
    parts = [capsule_id, str(index), record_id, strip_prefix(in_h), strip_prefix(out_h), GENESIS]
    return sha512_hex(b"\x00".join(p.encode() for p in parts))


def pair_hash(left: str, right: str) -> str:
    return sha512_hex(left.encode() + b"\x00" + right.encode())


def merkle_root_and_proofs(leaves: List[str]):
    """Binary tree with odd-level duplication; returns (root, proofs per leaf)."""
    if len(leaves) == 1:
        return leaves[0], [[]]
    proofs: List[List[str]] = [[] for _ in leaves]
    level = list(leaves)
    positions = list(range(len(leaves)))
    while len(level) > 1:
        for leaf, pos in enumerate(positions):
            sibling = pos + 1 if pos % 2 == 0 else pos - 1
            if sibling >= len(level):
                sibling = pos
            proofs[leaf].append(level[sibling])
        nxt = []
        for i in range(0, len(level), 2):
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(pair_hash(level[i], right))
        level = nxt
        positions = [p // 2 for p in positions]
    return level[0], proofs


class Source:
    """A synthetic source AuditProof's bundle-relevant values."""

    def __init__(
        self,
        n: int,
        *,
        with_parent_root: bool = False,
        timestamp: str = TIMESTAMP,
        tag: str = "",
    ) -> None:
        self.n = n
        self.timestamp = timestamp
        self.capsule_id = f"cap_fixture_bundle_n{n}{tag}"
        self.receipts: List[Dict[str, Any]] = []
        leaves = []
        for i in range(n):
            rid = f"rec_{i}"
            in_h = "sha512:" + label_hash(f"{self.capsule_id}:in:{i}")
            out_h = "sha512:" + label_hash(f"{self.capsule_id}:out:{i}")
            chain = record_chain_hash(self.capsule_id, i, rid, in_h, out_h)
            leaves.append(chain)
            self.receipts.append(
                {
                    "record_index": i,
                    "record_id": rid,
                    "record_input_hash": in_h,
                    "record_output_hash": out_h,
                    "record_chain_hash": "sha512:" + chain,
                }
            )
        self.root, proofs = merkle_root_and_proofs(leaves)
        for r, p in zip(self.receipts, proofs):
            r["merkle_inclusion_proof"] = p
        self.parent_root: Optional[str] = (
            label_hash(f"{self.capsule_id}:parent-leaf") if with_parent_root else None
        )
        self.step8 = step_8_amended(timestamp, self.root, self.parent_root)

    def bundle(self, index: int, *, signed: str = "legacy") -> Dict[str, Any]:
        anchors: Dict[str, Any] = {
            "capsule_id": self.capsule_id,
            "key_id": KEY_ID,
            "verification_key": PUBKEY_B64,
            "step_8_chain_hash": self.step8,
            "signature": sign(self.step8),
            "record_receipts_merkle_root": "sha512:" + self.root,
            "timestamp": self.timestamp,
        }
        if signed == "document":
            doc_hash = label_hash(f"{self.capsule_id}:document-canonical")
            anchors["signature"] = sign(doc_hash)
            anchors["signature_target"] = "document_canonical_hash"
            anchors["document_canonical_hash"] = doc_hash
        if self.parent_root is not None:
            anchors["parent_proofs_merkle_root"] = "sha512:" + self.parent_root
        return {
            "bundle_version": "1.0",
            "bundle_type": "receipt",
            "generated_at": GENERATED_AT,
            "receipt": copy.deepcopy(self.receipts[index]),
            "audit_proof_anchors": anchors,
            "disclaimer": DISCLAIMER,
        }


def valid(description: str) -> Dict[str, Any]:
    return {
        "description": description,
        "outcome": "valid",
        "signature_authentic": True,
        "receipt_bound": True,
    }


def rejected(kind: str, description: str) -> Dict[str, Any]:
    return {"description": description, "outcome": kind}


def build_cases() -> Dict[str, Any]:
    cases: Dict[str, Any] = {}

    def add(name: str, bundle: Dict[str, Any], expected: Dict[str, Any]) -> None:
        cases[name] = (bundle, expected)

    # (a) genuine legacy, N=1
    s1 = Source(1)
    add("a_legacy_n1_idx0", s1.bundle(0), valid("Genuine legacy bundle, N=1 (empty inclusion proof)."))

    # (b) genuine legacy, N=2 and N=3, every index
    for n in (2, 3):
        s = Source(n)
        for i in range(n):
            add(
                f"b_legacy_n{n}_idx{i}",
                s.bundle(i),
                valid(f"Genuine legacy bundle, N={n}, record index {i}."),
            )

    # (c) genuine legacy with both roots
    sp = Source(2, with_parent_root=True)
    for i in range(2):
        add(
            f"c_legacy_both_roots_n2_idx{i}",
            sp.bundle(i),
            valid(f"Genuine legacy bundle carrying receipts and parent-proofs roots, record index {i}."),
        )

    # (d) bundled Merkle root differs from the root Step 8 committed; the
    # signature over that Step 8 value is genuine.
    other = Source(2)
    alt = Source(1, tag="_forged")
    b = alt.bundle(0)
    b["audit_proof_anchors"]["step_8_chain_hash"] = other.step8
    b["audit_proof_anchors"]["signature"] = sign(other.step8)
    add(
        "d_root_not_committed",
        b,
        rejected(
            "step_8_mismatch",
            "(d) bundled Merkle root differs from the root Step 8 committed; the signature "
            "over that Step 8 value is genuine.",
        ),
    )

    # (e) case (c) with parent_proofs_merkle_root removed
    b = sp.bundle(0)
    del b["audit_proof_anchors"]["parent_proofs_merkle_root"]
    add(
        "e_parent_root_removed",
        b,
        rejected("step_8_mismatch", "Bundle from a proof with parent links, parent_proofs_merkle_root omitted."),
    )

    # (f) altered timestamp
    b = Source(2).bundle(0)
    b["audit_proof_anchors"]["timestamp"] = "2026-10-01T00:00:01Z"
    add("f_altered_timestamp", b, rejected("step_8_mismatch", "Timestamp differs from the one the chain was built at."))

    # (g) signature over a document canonical hash carried under the legacy
    # step8_chain_hash label, next to different receipt content
    v2 = Source(2, tag="_v2")
    b_doc = v2.bundle(0, signed="document")
    doc_hash = b_doc["audit_proof_anchors"]["document_canonical_hash"]
    plain = Source(1, tag="_victim")
    b = plain.bundle(0)
    b["audit_proof_anchors"]["step_8_chain_hash"] = doc_hash
    b["audit_proof_anchors"]["signature"] = b_doc["audit_proof_anchors"]["signature"]
    add(
        "g_v2_signature_under_legacy_label",
        b,
        rejected(
            "step_8_mismatch",
            "(g) signature over a document canonical hash carried as step_8_chain_hash, "
            "with receipt content that does not match.",
        ),
    )

    # (h) genuine v2.x bundle: signature authentic, receipt not bound
    for i in range(2):
        add(
            f"h_v2_not_bound_idx{i}",
            v2.bundle(i, signed="document"),
            {
                "description": "Genuine document_canonical_hash bundle; the bundle alone cannot bind the receipt.",
                "outcome": "receipt_not_bound",
                "signature_authentic": True,
                "receipt_bound": False,
            },
        )

    # Further single-fault rejections, one kind each.
    s = Source(2)
    b = s.bundle(0)
    b["receipt"]["record_output_hash"] = "sha512:" + label_hash("tampered-output")
    add("i_receipt_field_tampered", b, rejected("record_chain_hash_mismatch", "Receipt output hash altered."))

    b = s.bundle(0)
    b["receipt"]["merkle_inclusion_proof"] = [label_hash("wrong-sibling")]
    add("j_inclusion_proof_tampered", b, rejected("merkle_inclusion_failed", "Inclusion proof sibling replaced."))

    b = s.bundle(0)
    b["audit_proof_anchors"]["signature"] = sign(label_hash("some-other-message"))
    add("k_signature_over_other_message", b, rejected("signature_failed", "Signature over a different message."))

    b = v2.bundle(0, signed="document")
    b["audit_proof_anchors"]["document_canonical_hash"] = label_hash("different-document")
    add("l_v2_canonical_hash_altered", b, rejected("signature_failed", "Carried canonical hash differs from the signed one."))

    b = v2.bundle(0, signed="document")
    del b["audit_proof_anchors"]["document_canonical_hash"]
    add("m_v2_canonical_hash_missing", b, rejected("missing_canonical_hash_anchor", "Document target declared without the hash."))

    b = s.bundle(0)
    b["audit_proof_anchors"]["signature_target"] = "sha3_sponge"
    add("n_unknown_signature_target", b, rejected("unknown_signature_target", "Unrecognised signature_target value."))

    b = s.bundle(1)
    b["receipt"]["record_index"] = 1.5
    add("o_record_index_not_integer", b, rejected("shape", "receipt.record_index is not an integer."))

    # Each carried value below is signed by the fixture key, so only the shape
    # check can refuse it.
    good = label_hash("signed-document")
    for name, anchor, description in (
        (
            "p_population_head_message_as_canonical_hash",
            "nanorix-population-head-v1:" + good,
            "A population head's signed message carried as the canonical hash.",
        ),
        ("q_canonical_hash_uppercase", good.upper(), "Canonical hash in uppercase hex."),
        ("r_canonical_hash_too_short", good[:-1], "Canonical hash one character short."),
        ("s_canonical_hash_trailing_newline", good + "\n", "Canonical hash with a trailing newline."),
        ("t_canonical_hash_prefix_only", "sha512:", "Canonical hash that is only its prefix."),
    ):
        b = v2.bundle(0, signed="document")
        b["audit_proof_anchors"]["document_canonical_hash"] = anchor
        b["audit_proof_anchors"]["signature"] = sign(strip_prefix(anchor))
        add(name, b, rejected("malformed_canonical_hash_anchor", description))

    return cases


def render(obj: Any) -> str:
    return json.dumps(obj, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    cases = build_cases()
    wanted: Dict[Path, str] = {}
    for name, (bundle, expected) in cases.items():
        wanted[HERE / f"{name}.prb.json"] = render(bundle)
        wanted[HERE / f"{name}.expected.json"] = render(expected)

    if args.check:
        stale = sorted(
            p.name for p, text in wanted.items() if not p.exists() or p.read_text() != text
        )
        extra = sorted(
            p.name
            for p in HERE.glob("*.json")
            if p not in wanted
        )
        if stale or extra:
            print("stale:", stale, "unexpected:", extra, file=sys.stderr)
            return 1
        print(f"{len(cases)} fixtures up to date")
        return 0

    for p in HERE.glob("*.prb.json"):
        p.unlink()
    for p in HERE.glob("*.expected.json"):
        p.unlink()
    for p, text in wanted.items():
        p.write_text(text)
    print(f"wrote {len(cases)} fixtures to {HERE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
