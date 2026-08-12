"""
Canonical-view recompute + Ed25519 signature verification.

Python mirror of the Rust verifiersrc/canonical_recompute.rs`, which is
the reference implementation. Byte-identity with the signer is locked by
`test_canonical_recompute_matches_server_golden` — the same fixed input the
server's `cdp_document.rs::golden_canonical_hash` test pins.

## The signed message is version-dependent

A v2.1 `nanorix_only` AuditProof is **not** signed over `final_hash` — that is
the v1.0 message. It is signed over the the specification Part-3 canonical-view hash,
`hex(sha512(jcs(canonical_view)))`.

| `cdp_version` | Signed message |
|---|---|
| `1.0` | `final_hash` (hex, prefix stripped) |
| `2.0` | `document_hash` |
| `2.1` + `nanorix_only` | recomputed canonical-view hash |
| `2.1` + `dual_signature` / `tee_attested` | not verifiable by this build |

The signature covers the ASCII hex characters of that hash (128 bytes), not
its 64 raw digest bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nanorix._jcs import canonicalize

# ─────────────────────────────────────────────────────────────────────────────
# Wire-form signature failure sub-reasons (`SignatureFailureReason` in
# governance/verify-types). Forever-Standard per the Forever-Standard wire discipline.
# ─────────────────────────────────────────────────────────────────────────────

SIG_MALFORMED = "malformed"
SIG_DOES_NOT_VERIFY = "does_not_verify"
SIG_PUBLIC_KEY_MALFORMED = "public_key_malformed"
SIG_MESSAGE_FORMAT_MISMATCH = "message_format_mismatch"

_ED25519_SIGNATURE_LEN = 64
_ED25519_PUBLIC_KEY_LEN = 32

SUPPORTED_CDP_VERSIONS = frozenset({"1.0", "2.0", "2.1"})


class SignatureOutcome(Enum):
    """Which of the three signature-stage verdicts was reached."""

    VERIFIED = "verified"
    """Signature verified against the supplied key over the correct message."""

    ABSENT = "absent"
    """Nothing to check — no signature or key present.

    The caller keeps the honest "chain verified, signature NOT checked" verdict
    rather than reporting either a pass or a failure of the signature.
    """

    UNSUPPORTED = "unsupported"
    """The document declares a signing_mode this build cannot verify.

    Distinct from ABSENT on purpose: signing_mode is inside the canonical hash
    and is attacker-controllable, so if an unrecognised mode produced the same
    verdict as a missing signature, flipping the field would convert a rejection
    into reassurance — a downgrade oracle. Mirrors SignatureCheck::Unsupported
    in the Rust verifier and SignatureUnsupported in Go.
    """

    FAILED = "failed"
    """A signature was present and did not verify."""


@dataclass(frozen=True)
class SignatureCheck:
    """Outcome of the signature stage. `reason` is set only when FAILED."""

    outcome: SignatureOutcome
    reason: Optional[str] = None
    #: Set only for UNSUPPORTED — the signing_mode this build cannot verify.
    mode: Optional[str] = None

    @property
    def verified(self) -> bool:
        return self.outcome is SignatureOutcome.VERIFIED

    @property
    def absent(self) -> bool:
        return self.outcome is SignatureOutcome.ABSENT


_VERIFIED = SignatureCheck(SignatureOutcome.VERIFIED)
_ABSENT = SignatureCheck(SignatureOutcome.ABSENT)


def _failed(reason: str) -> SignatureCheck:
    return SignatureCheck(SignatureOutcome.FAILED, reason)


def strip_hash_prefix(value: str) -> str:
    """Strip the `sha512:` wire prefix. the specification forever-stable."""
    return value[len("sha512:") :] if value.startswith("sha512:") else value


def strip_base64_prefix(value: str) -> str:
    """Strip the `base64:` wire prefix. the specification forever-stable."""
    return value[len("base64:") :] if value.startswith("base64:") else value


def _get(proof: Mapping[str, Any], key: str) -> Any:
    """The canonical view reads absent fields as JSON null, not as omitted."""
    return proof.get(key, None)


def _insert_if_present(view: Dict[str, Any], key: str, proof: Mapping[str, Any]) -> None:
    """Mirror `skip_serializing_if = Option::is_none` — omit when absent/null."""
    value = proof.get(key)
    if value is not None:
        view[key] = value


def recompute_canonical_hash(proof: Mapping[str, Any]) -> str:
    """Rebuild the the specification Part-3 canonical view and return its JCS SHA-512 hex.

    Byte-identical to the server's `FullCdp::canonical_hash()`. The AuditProof
    JSON already carries every value in its exact serialized shape, so only the
    *view* is rebuilt: wire field names are mapped to canonical-view keys and
    the two server-side transforms are applied (`signing_key_version` String ->
    integer; the `attestation` subset). Under JCS the physical key order is
    irrelevant, so a key-reorder tamper is either semantically identical or
    changes a hashed value.

    Returns lowercase 128-char hex.
    """
    view: Dict[str, Any] = {}

    view["version"] = _get(proof, "cdp_version")
    view["signing_mode"] = _get(proof, "signing_mode")
    view["jurisdiction"] = _get(proof, "jurisdiction")
    view["authority_id"] = _get(proof, "authority_id")

    # FullCdp stores a String; the canonical view emits an integer, and the
    # server parses with an unparseable-value fallback of 0.
    raw_skv = proof.get("signing_key_version")
    if isinstance(raw_skv, str):
        try:
            view["signing_key_version"] = int(raw_skv)
        except ValueError:
            view["signing_key_version"] = 0
    else:
        view["signing_key_version"] = 0

    view["capsule_id"] = _get(proof, "capsule_id")
    org_id = proof.get("org_id")
    view["org_id"] = org_id if org_id is not None else ""

    _insert_if_present(view, "parent_audit_proof_id", proof)
    _insert_if_present(view, "cdp_kind", proof)

    activity = proof.get("activity")
    view["activity_trail"] = activity if activity is not None else []
    chain = proof.get("chain")
    view["destruction_chain"] = chain if chain is not None else []
    view["destruction_state"] = _get(proof, "destruction_state")

    # No skip attribute server-side -> serialized as null when absent.
    view["destruction_failure_step"] = _get(proof, "destruction_failure_step")

    _insert_if_present(view, "parent_proofs_merkle_root", proof)
    _insert_if_present(view, "record_receipts_merkle_root", proof)

    view["runtime_attestation"] = _get(proof, "runtime_attestation")

    # An empty fingerprint canonicalizes to null, matching the server's
    # `if fingerprint.is_empty() { None }`.
    fingerprint = proof.get("attestation_chain_fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        fingerprint = None
    view["attestation"] = {
        "timestamp_attestation": _get(proof, "timestamp_attestation"),
        "attestation_chain_fingerprint": fingerprint,
    }

    view["hash_algorithm"] = _get(proof, "hash_algorithm")
    view["signature_algorithm"] = _get(proof, "signature_algorithm")

    return hashlib.sha512(canonicalize(view)).hexdigest()


# Marks a signed_message result as "this build cannot verify the declared
# signing_mode" rather than a message to sign over. The NUL prefix can never
# occur in a hex digest. Mirrors UNSUPPORTED_MODE_SENTINEL in the Rust verifier.
UNSUPPORTED_MODE_SENTINEL = "\x00unsupported-signing-mode:"


def signed_message(proof: Mapping[str, Any], cdp_version: str) -> Optional[str]:
    """The message this proof's signature covers, or None if unverifiable here.

    None means "this build cannot check it" (unrecognised version, or a v2.1
    signing mode whose second signature this build has no key for) — never
    "the signature is bad".
    """
    signing_mode = proof.get("signing_mode")
    if not isinstance(signing_mode, str):
        signing_mode = "nanorix_only"

    if cdp_version == "1.0":
        raw = proof.get("final_hash")
        return strip_hash_prefix(raw if isinstance(raw, str) else "")
    if cdp_version == "2.0":
        raw = proof.get("document_hash")
        return strip_hash_prefix(raw if isinstance(raw, str) else "")
    if cdp_version == "2.1":
        if signing_mode == "nanorix_only":
            return recompute_canonical_hash(proof)
        # Any other declared mode is one this build cannot verify. NOT the same
        # as "no signature": signing_mode is inside the canonical hash and is
        # attacker-controllable, so an unrecognised mode yielding a partial
        # success would be a downgrade oracle. Signalled with a sentinel the
        # callers translate. Mirrors the Rust and Go verifiers.
        return UNSUPPORTED_MODE_SENTINEL + signing_mode
    return None


def _decode_exact(value: str, expected_len: int) -> Optional[bytes]:
    """Strict base64 decode requiring an exact byte length, else None.

    `validate=True` matches the Rust `STANDARD` engine: non-alphabet characters
    and non-canonical padding are rejected rather than silently discarded.
    """
    try:
        raw = base64.b64decode(strip_base64_prefix(value), validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == expected_len else None


def verify_message_with_key(message: str, sig_b64: str, pub_b64: str) -> SignatureCheck:
    """Decode a base64 Ed25519 signature + public key and verify `message`.

    Shared by the embedded-key (sub-A) and manifest-key (sub-B) paths. The
    signature is checked first so a proof with both fields malformed reports
    `malformed`, matching the reference verifier.
    """
    sig_bytes = _decode_exact(sig_b64, _ED25519_SIGNATURE_LEN)
    if sig_bytes is None:
        return _failed(SIG_MALFORMED)
    pub_bytes = _decode_exact(pub_b64, _ED25519_PUBLIC_KEY_LEN)
    if pub_bytes is None:
        return _failed(SIG_PUBLIC_KEY_MALFORMED)

    try:
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except (ValueError, TypeError):
        return _failed(SIG_PUBLIC_KEY_MALFORMED)

    try:
        public_key.verify(sig_bytes, message.encode("ascii"))
    except InvalidSignature:
        return _failed(SIG_DOES_NOT_VERIFY)
    return _VERIFIED


def _nonempty_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _embedded_signature(proof: Mapping[str, Any]) -> Optional[str]:
    attestation = proof.get("attestation")
    if not isinstance(attestation, Mapping):
        return None
    return _nonempty_str(attestation.get("signature"))


def _embedded_public_key(proof: Mapping[str, Any]) -> Optional[str]:
    attestation = proof.get("attestation")
    if not isinstance(attestation, Mapping):
        return None
    return _nonempty_str(attestation.get("public_key")) or _nonempty_str(
        attestation.get("verification_key")
    )


def verify_signature(proof: Mapping[str, Any], cdp_version: str) -> SignatureCheck:
    """sub-A — verify against the public key EMBEDDED in the proof.

    Proves integrity (not tampered since signing), NOT authenticity: a forger
    who signs their own document with their own key passes this. Binding the
    key to a Nanorix-rooted trust anchor is `verify_signature_against`.
    """
    sig_b64 = _embedded_signature(proof)
    pub_b64 = _embedded_public_key(proof)
    if sig_b64 is None or pub_b64 is None:
        return _ABSENT
    message = signed_message(proof, cdp_version)
    if message is None:
        return _ABSENT
    if message.startswith(UNSUPPORTED_MODE_SENTINEL):
        return SignatureCheck(
            SignatureOutcome.UNSUPPORTED,
            mode=message[len(UNSUPPORTED_MODE_SENTINEL) :],
        )
    return verify_message_with_key(message, sig_b64, pub_b64)


def verify_signature_against(
    proof: Mapping[str, Any], cdp_version: str, pub_b64: str
) -> SignatureCheck:
    """sub-B — verify against a trust-chain-RESOLVED key, not the embedded one.

    This is what establishes authenticity: a forged proof carrying its own
    embedded key passes sub-A but fails here.
    """
    sig_b64 = _embedded_signature(proof)
    if sig_b64 is None:
        return _ABSENT
    message = signed_message(proof, cdp_version)
    if message is None:
        return _ABSENT
    if message.startswith(UNSUPPORTED_MODE_SENTINEL):
        return SignatureCheck(
            SignatureOutcome.UNSUPPORTED,
            mode=message[len(UNSUPPORTED_MODE_SENTINEL) :],
        )
    return verify_message_with_key(message, sig_b64, pub_b64)


# ─────────────────────────────────────────────────────────────────────────────
# the chain-timestamp recovery rule — chain-timestamp recovery from the attestation key_id
# ─────────────────────────────────────────────────────────────────────────────


def _is_iso8601_shaped(date: str, time: str) -> bool:
    """`YYYY-MM-DD` + `HH:MM:SS` prefix; anything after the seconds is free-form."""
    if not date.isascii() or not time.isascii():
        return False
    if len(date) != 10 or len(time) < 8:
        return False
    if date[4] != "-" or date[7] != "-":
        return False
    if not all(date[i].isdigit() for i in (0, 1, 2, 3, 5, 6, 8, 9)):
        return False
    if time[2] != ":" or time[5] != ":":
        return False
    return all(time[i].isdigit() for i in (0, 1, 3, 4, 6, 7))


def recover_timestamp_from_key_id(key_id: str) -> Optional[str]:
    """Recover the chain timestamp from an attestation `key_id`.

    AuditProofs issued before the chain-timestamp recovery rule restored the document-level
    `destroyed_at` field carry the chain timestamp in exactly one place: the
    attestation `key_id`, built as
    `nrx-verify-{terminated_at with ':' replaced by '-'}-{capsule_id[..8]}`.
    Only the TIME portion ever held colons, so restoration splits at `T` and
    rewrites dashes on the right-hand side only.

    Returns None unless the reconstruction has the exact ISO-8601
    `YYYY-MM-DDTHH:MM:SS` shape — this never guesses.

    Recovering from an attacker-mutable field is sound because the recovered
    value is never trusted on its own: it is an INPUT to the chain walk, and
    the chain hashes it must reproduce are themselves signature-bound. Exactly
    one timestamp string reproduces a signed chain, so a mutated `key_id`
    yields a mismatch and a rejection, never a false accept.
    """
    if not key_id.startswith("nrx-verify-"):
        return None
    rest = key_id[len("nrx-verify-") :]
    encoded, sep, fragment = rest.rpartition("-")
    if not sep or not fragment:
        return None
    date, sep_t, encoded_time = encoded.partition("T")
    if not sep_t:
        return None
    time = encoded_time.replace("-", ":")
    if not _is_iso8601_shaped(date, time):
        return None
    return f"{date}T{time}"


def resolve_chain_timestamp(proof: Mapping[str, Any]) -> Tuple[str, Optional[str]]:
    """Resolve the timestamp every chain step hashes.

    Returns `(timestamp, recovered)` where `recovered` is set only on the
    `key_id` recovery path, so a verdict always discloses which route produced
    it. Falls back to the pre-recovery behaviour (an empty timestamp, which
    fails the chain walk for any real proof) when neither source is usable.
    """
    declared = proof.get("destroyed_at")
    declared = declared if isinstance(declared, str) else ""
    if declared:
        return declared, None

    attestation = proof.get("attestation")
    key_id = attestation.get("key_id") if isinstance(attestation, Mapping) else None
    if isinstance(key_id, str):
        recovered = recover_timestamp_from_key_id(key_id)
        if recovered is not None:
            return recovered, recovered
    return declared, None
