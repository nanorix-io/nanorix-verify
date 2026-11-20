"""Stage 8 trust root: a signed key list pinned by its identity fingerprint.

Python mirror of `tools/nanorix-verify/src/trust_chain.rs`, which is the
reference. The vectors under `tools/nanorix-verify/fixtures/trust_chain/` hold
this file to it.

A list is checked once, when it is loaded, against the pinned fingerprint. A
list that is not the pinned identity's is refused there, before any proof is
read, and never becomes a policy that could be applied by mistake.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nanorix._jcs import canonicalize
from nanorix.verifier._ed25519_strict import verify_strict
from nanorix.verifier._mldsa import ALGORITHM_UNSUPPORTED, MLDSAError, MLDSAParameterSet, verify_ml_dsa

LOAD_FAILED = "load_failed"
MALFORMED = "malformed"
FINGERPRINT_MISMATCH = "fingerprint_mismatch"
SIGNATURE_INVALID = "signature_invalid"

# The refusals of the hybrid key list, named as the Rust
# ``ManifestError::kind`` names them.
PQC_IDENTITY_MISSING = "pqc_identity_missing"
PQC_ALGORITHM_UNSUPPORTED = "pqc_algorithm_unsupported"
PQC_SIGNATURE_MISSING = "pqc_signature_missing"
PQC_SIGNATURE_INVALID = "pqc_signature_invalid"
NON_CANONICAL_ENCODING = "non_canonical_encoding"
KEY_LABEL_UNKNOWN = "key_label_unknown"
RECORD_KEY_LENGTH = "record_key_length"
VERSION_REPEATED = "version_repeated"
FINGERPRINT_NOT_OF_KEY = "fingerprint_not_of_key"
PARTNER_MISSING = "partner_missing"
PARTNER_INVALID = "partner_invalid"
PARTNER_SHARED = "partner_shared"
KEY_IN_TWO_ROLES = "key_in_two_roles"
PARTNER_CHANGED = "partner_changed"
PQC_IDENTITY_UNDER_CLASSICAL_PIN = "pqc_identity_under_classical_pin"
AUTHORITY_ID_MALFORMED = "authority_id_malformed"
BYOC_AUTHORITY_ID_MALFORMED = "byoc_authority_id_malformed"
BYOC_AUTHORITY_NEEDS_HYBRID_PIN = "byoc_authority_needs_hybrid_pin"
BYOC_AUTHORITY_PIN_MISMATCH = "byoc_authority_pin_mismatch"
#: A hybrid pin given where this installation's ``cryptography`` has no ML-DSA:
#: every hybrid pin is refused rather than one half checked.
HYBRID_CHECK_UNAVAILABLE = "hybrid_check_unavailable"

#: The prefix of a hybrid identity pin.
HYBRID_PIN_PREFIX = "hybrid1-sha256:"
#: The domain tag in front of the ML-DSA-87 list signature's message.
KEY_LIST_PQC_TAG = b"nanorix-key-list-pqc-v1"
#: The ``found`` text of the refusal every record gets under a hybrid pin until
#: this verifier checks the record's ML-DSA-65 half (the hybrid-pin gate).
HYBRID_RECORD_CHECK_MISSING = "ML-DSA-65 record check (hybrid pin)"

_PQC_IDENTITY_ALGORITHM = "ML-DSA-87"
_ML_DSA_65 = "ML-DSA-65"
_KEY_LENGTHS = {"Ed25519": 32, _ML_DSA_65: 1952}
_ML_DSA_87_PUBLIC_KEY_LEN = 2592
_AUTHORITY_ID_ALPHABET = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789._-")


def is_hybrid_pin(pin: str) -> bool:
    """True when ``pin`` is of the hybrid kind, read from the pin string alone."""
    return isinstance(pin, str) and pin.startswith(HYBRID_PIN_PREFIX)


def hybrid_pin(ed25519_identity: bytes, mldsa87_identity: bytes) -> str:
    """The hybrid pin of an identity."""
    digest = hashlib.sha256(
        b"nanorix-identity-hybrid-v1\x00Ed25519\x00"
        + ed25519_identity
        + b"\x00ML-DSA-87\x00"
        + mldsa87_identity
    ).hexdigest()
    return HYBRID_PIN_PREFIX + digest


def _mldsa87_verify(public_key: bytes, message: bytes, signature: bytes) -> Optional[bool]:
    """The key list's ML-DSA-87 check; ``None`` when this install has no ML-DSA."""
    try:
        verify_ml_dsa(MLDSAParameterSet.ML_DSA_87, public_key, message, signature)
    except MLDSAError as refused:
        return None if refused.kind == ALGORITHM_UNSUPPORTED else False
    return True


def mldsa_available() -> bool:
    """Whether this installation's ``cryptography`` checks ML-DSA-87."""
    return _mldsa87_verify(b"\x00" * _ML_DSA_87_PUBLIC_KEY_LEN, b"", b"") is not None


class TrustChainError(Exception):
    """A key list was refused. A setup error, not a verdict on a proof.

    ``kind`` is one of ``load_failed`` (the bytes are not a key list of the
    expected shape), ``malformed`` (the identity public key is missing or
    unusable), ``fingerprint_mismatch`` (the identity key does not hash to both
    the list's own fingerprint and the pinned one) or ``signature_invalid`` (the
    list's signature does not verify under the identity key, strictly). The
    names match the Rust ``ManifestError`` variants.
    """

    def __init__(self, kind: str) -> None:
        super().__init__(_MESSAGES.get(kind, f"trust-chain key list refused: {kind}"))
        self.kind = kind


_MESSAGES = {
    LOAD_FAILED: "trust-chain key list does not parse as a key list",
    MALFORMED: "trust-chain key list is malformed (bad identity key)",
    FINGERPRINT_MISMATCH: (
        "trust-chain key list is not signed by the pinned identity (fingerprint mismatch)"
    ),
    SIGNATURE_INVALID: "trust-chain key list signature is invalid",
    HYBRID_CHECK_UNAVAILABLE: (
        "this installation's cryptography has no ML-DSA, so every hybrid1-sha256: pin is refused"
    ),
}


@dataclass(frozen=True)
class _KeyRecord:
    version: str
    public_key_b64: str
    fingerprint: str = ""
    algorithm: Optional[str] = None
    partner: Optional[str] = None

    @property
    def label(self) -> str:
        return "Ed25519" if self.algorithm is None else self.algorithm


@dataclass(frozen=True)
class _Authority:
    active: Tuple[_KeyRecord, ...]
    archived: Tuple[_KeyRecord, ...]
    revoked: bool


@dataclass(frozen=True)
class TrustChain:
    """A key list whose signature has been verified against a pinned identity.

    Make one with :meth:`from_key_list`; pass it as
    ``VerifierPolicy(trust_chain=...)``. A chain built any other way, a
    ``dataclasses.replace`` copy included, was not checked against its pin,
    so a proof it resolves ends at stage 7 (``not_anchored``), never stage 8.
    Its authorities are read-only. Only a chain whose type is exactly
    ``TrustChain`` reaches stage 8, so a subclass never does, even one
    that sets the mark itself. Code in the caller's own process is outside
    what the mark defends when it writes the chain's private fields by any
    means, assigns to ``TrustChain`` itself, patches built-ins, or passes
    the pin or the key list's values as objects of its own types (for
    example a ``str`` subclass, or ``unittest.mock.ANY`` as the pin).
    """

    pinned_identity_fingerprint: str
    _authorities: Mapping[str, _Authority] = field(repr=False)
    # Not a constructor argument, so neither a direct build nor
    # dataclasses.replace can carry it; only from_key_list sets it.
    _pin_checked: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # A read-only copy: the keys the pin vouched for cannot change after.
        object.__setattr__(self, "_authorities", MappingProxyType(dict(self._authorities)))

    @classmethod
    def from_key_list(
        cls,
        key_list: Union[bytes, str, Mapping[str, Any]],
        pinned_identity_fingerprint: str,
    ) -> "TrustChain":
        """Parse a signed key list and verify it against the pinned fingerprint.

        ``pinned_identity_fingerprint`` is ``sha256:<hex of SHA-256 over the
        identity public key>``. Raises :class:`TrustChainError` on every
        refusal. Order matches the Rust reference: shape, then the identity
        key, then the fingerprint against both the list's own claim and the pin,
        then the signature.
        A ``hybrid1-sha256:`` pin runs the hybrid check
        (both identity keys, the recomputed pin, both list signatures, the
        partner, role and authority id rules), or is refused with
        ``hybrid_check_unavailable`` where ML-DSA is not available. Under such
        a pin the list must be bytes or text: a parsed mapping is refused with
        ``load_failed``, because parsing has already dropped any repeated
        member's other copies. Any other
        pin runs the classical check, then the authority id rules and the
        refusal of post-quantum identity members.
        """
        hybrid = is_hybrid_pin(pinned_identity_fingerprint)
        if hybrid and not mldsa_available():
            raise TrustChainError(HYBRID_CHECK_UNAVAILABLE)
        root = _load(key_list, refuse_repeated=hybrid)
        parsed = _parse(root)
        if parsed is None:
            raise TrustChainError(LOAD_FAILED)
        if hybrid:
            authorities = _verify_hybrid(parsed, pinned_identity_fingerprint)
            chain = TrustChain(pinned_identity_fingerprint, authorities)
            object.__setattr__(chain, "_pin_checked", True)
            return chain
        authorities, signed_view, identity_fp, identity_key_b64, signature = parsed[:5]

        pub = _b64(identity_key_b64, 32)
        if pub is None:
            raise TrustChainError(MALFORMED)
        try:
            Ed25519PublicKey.from_public_bytes(pub)
        except (ValueError, TypeError):
            raise TrustChainError(MALFORMED) from None

        computed = "sha256:" + hashlib.sha256(pub).hexdigest()
        if computed != identity_fp or computed != pinned_identity_fingerprint:
            raise TrustChainError(FINGERPRINT_MISMATCH)

        sig = _b64(signature, 64)
        if sig is None:
            raise TrustChainError(SIGNATURE_INVALID)
        payload = canonicalize(signed_view)
        public_key = Ed25519PublicKey.from_public_bytes(pub)
        try:
            # verify_strict refuses a small-order key or R and a key whose bytes
            # are a second encoding of its point.
            verify_strict(public_key, sig, payload)
        except InvalidSignature:
            raise TrustChainError(SIGNATURE_INVALID) from None
        pqc = parsed[5]
        if pqc.algorithm is not None or pqc.public_key_b64 is not None:
            raise TrustChainError(PQC_IDENTITY_UNDER_CLASSICAL_PIN)
        _check_authority_ids(authorities, None)

        # Built as TrustChain even when called on a subclass, so a subclass's
        # own find_key never carries the mark.
        chain = TrustChain(pinned_identity_fingerprint, authorities)
        object.__setattr__(chain, "_pin_checked", True)
        return chain

    def find_key(self, authority_id: str, signing_key_version: str) -> Optional[Tuple[str, bool]]:
        """The listed ``(public_key_b64, authority_revoked)`` for a version.

        Active versions are searched before archived ones, so a rotated-away
        version still resolves. ``None`` when the authority or the version is
        not in the list.
        """
        authority = self._authorities.get(authority_id)
        if authority is None:
            return None
        for record in authority.active:
            if record.version == signing_key_version:
                return record.public_key_b64, authority.revoked
        for record in authority.archived:
            if record.version == signing_key_version:
                return record.public_key_b64, authority.revoked
        return None

    def _record(self, authority_id: str, version: str) -> Optional[_KeyRecord]:
        authority = self._authorities.get(authority_id)
        if authority is None:
            return None
        for record in authority.active + authority.archived:
            if record.version == version:
                return record
        return None

    def hybrid_partner(self, authority_id: str, ed25519_version: str) -> Optional[Tuple[str, str]]:
        """The ``(version, public_key_b64)`` of an Ed25519 version's ML-DSA-65 partner.

        The partner is the record of the same authority that the version's
        ``pqc_partner_version`` names; a record's
        ML-DSA-65 key id is ``nrx-pqc-v`` followed by its version. ``None``
        when there is none. Meaningful only for a chain loaded under a hybrid
        pin, where the partner rules were applied.
        """
        ed = self._record(authority_id, ed25519_version)
        if ed is None or ed.label != "Ed25519" or ed.partner is None:
            return None
        partner = self._record(authority_id, ed.partner)
        if partner is None or partner.algorithm != _ML_DSA_65:
            return None
        return partner.version, partner.public_key_b64


def compare_partners(earlier: TrustChain, later: TrustChain) -> None:
    """Refuse two lists from one identity that disagree.

    Every record of ``earlier`` must be in ``later`` under the same authority
    and version, algorithm and decoded key, and every partner ``earlier`` names
    must be named again with the same decoded key. Raises
    :class:`TrustChainError` (``partner_changed``) on a difference.
    """
    for authority_id in sorted(earlier._authorities):
        authority = earlier._authorities[authority_id]
        for record in authority.active + authority.archived:
            now = later._record(authority_id, record.version)
            if (
                now is None
                or now.label != record.label
                or _decoded(now.public_key_b64) != _decoded(record.public_key_b64)
            ):
                raise TrustChainError(PARTNER_CHANGED)
            if record.partner is not None:
                then_partner = earlier.hybrid_partner(authority_id, record.version)
                now_partner = later.hybrid_partner(authority_id, record.version)
                if (
                    then_partner is None
                    or now_partner is None
                    or _decoded(then_partner[1]) != _decoded(now_partner[1])
                ):
                    raise TrustChainError(PARTNER_CHANGED)


def _decoded(text: str) -> Optional[bytes]:
    stripped = text[len("base64:") :] if text.startswith("base64:") else text
    try:
        return base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None


def _strict(text: str) -> Optional[bytes]:
    """Canonical standard padded base64 after an optional ``base64:`` prefix.

    ``b64decode`` ignores set trailing bits, so the text must also be what
    encoding the decoded bytes gives back.
    """
    stripped = text[len("base64:") :] if text.startswith("base64:") else text
    try:
        raw = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if base64.b64encode(raw).decode("ascii") == stripped else None


@dataclass(frozen=True)
class _PqcMembers:
    algorithm: Optional[str]
    public_key_b64: Optional[str]
    signature: Optional[str]


def _verify_hybrid(parsed: Tuple[Any, ...], pin: str) -> Dict[str, _Authority]:
    """The hybrid check, in the Rust reference's order."""
    authorities, signed_view, identity_fp, identity_key_b64, signature, pqc = parsed
    ed_identity = _strict(identity_key_b64)
    if ed_identity is None or len(ed_identity) != 32:
        raise TrustChainError(MALFORMED)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(ed_identity)
    except (ValueError, TypeError):
        raise TrustChainError(MALFORMED) from None
    if pqc.algorithm is None:
        raise TrustChainError(PQC_IDENTITY_MISSING)
    if pqc.algorithm != _PQC_IDENTITY_ALGORITHM:
        raise TrustChainError(PQC_ALGORITHM_UNSUPPORTED)
    if pqc.public_key_b64 is None:
        raise TrustChainError(PQC_IDENTITY_MISSING)
    ml_identity = _strict(pqc.public_key_b64)
    if ml_identity is None:
        raise TrustChainError(NON_CANONICAL_ENCODING)
    if len(ml_identity) != _ML_DSA_87_PUBLIC_KEY_LEN:
        raise TrustChainError(MALFORMED)

    computed = hybrid_pin(ed_identity, ml_identity)
    if computed != identity_fp or computed != pin:
        raise TrustChainError(FINGERPRINT_MISMATCH)

    sig = _strict(signature)
    if sig is None or len(sig) != 64:
        raise TrustChainError(SIGNATURE_INVALID)
    payload = canonicalize(signed_view)
    try:
        verify_strict(public_key, sig, payload)
    except InvalidSignature:
        raise TrustChainError(SIGNATURE_INVALID) from None
    if pqc.signature is None:
        raise TrustChainError(PQC_SIGNATURE_MISSING)
    pqc_sig = _strict(pqc.signature)
    if pqc_sig is None:
        raise TrustChainError(NON_CANONICAL_ENCODING)
    if _mldsa87_verify(ml_identity, KEY_LIST_PQC_TAG + b"\x00" + payload, pqc_sig) is not True:
        raise TrustChainError(PQC_SIGNATURE_INVALID)

    _check_hybrid_records(authorities, [ed_identity, ml_identity])
    _check_authority_ids(authorities, computed[len(HYBRID_PIN_PREFIX) :])
    return authorities  # type: ignore[no-any-return]


def _version_number(version: str) -> Optional[str]:
    if not version or not all("0" <= c <= "9" for c in version):
        return None
    return version.lstrip("0")


def _check_hybrid_records(authorities: Mapping[str, _Authority], identity_keys: List[bytes]) -> None:
    """The record rules under a hybrid pin, in the Rust reference's order."""
    seen = set(identity_keys)
    for authority_id in sorted(authorities):
        authority = authorities[authority_id]
        records = authority.active + authority.archived
        texts: Set[str] = set()
        numbers: Set[str] = set()
        algorithms: Dict[str, str] = {}
        for record in records:
            if record.label not in _KEY_LENGTHS:
                raise TrustChainError(KEY_LABEL_UNKNOWN)
            key = _strict(record.public_key_b64)
            if key is None:
                raise TrustChainError(NON_CANONICAL_ENCODING)
            if len(key) != _KEY_LENGTHS[record.label]:
                raise TrustChainError(RECORD_KEY_LENGTH)
            if record.fingerprint != "sha256:" + hashlib.sha256(key).hexdigest():
                raise TrustChainError(FINGERPRINT_NOT_OF_KEY)
            number = _version_number(record.version)
            if record.version in texts or (number is not None and number in numbers):
                raise TrustChainError(VERSION_REPEATED)
            texts.add(record.version)
            if number is not None:
                numbers.add(number)
            if key in seen:
                raise TrustChainError(KEY_IN_TWO_ROLES)
            seen.add(key)
            algorithms[record.version] = record.label
        partners: Set[str] = set()
        for record in records:
            if record.label != "Ed25519":
                if record.partner is not None:
                    raise TrustChainError(PARTNER_INVALID)
                continue
            if record.partner is None:
                raise TrustChainError(PARTNER_MISSING)
            if algorithms.get(record.partner) != _ML_DSA_65:
                raise TrustChainError(PARTNER_INVALID)
            if record.partner in partners:
                raise TrustChainError(PARTNER_SHARED)
            partners.add(record.partner)


def _byoc_pin_hex(authority_id: str) -> Optional[str]:
    """The pin hex of an id that is exactly ``<base>-hybrid1.<p>-v<n>``."""
    if authority_id.count("hybrid1") != 1:
        return None
    base, sep, rest = authority_id.partition("-hybrid1.")
    if not sep or not base or len(rest) < 64 + 3:
        return None
    hex_part, suffix = rest[:64], rest[64:]
    if not all(c in "0123456789abcdef" for c in hex_part) or not suffix.startswith("-v"):
        return None
    number = suffix[2:]
    if not number or number[0] == "0" or not all("0" <= c <= "9" for c in number):
        return None
    return hex_part


def _check_authority_ids(authorities: Mapping[str, _Authority], pin_hex: Optional[str]) -> None:
    """The key list's authority id rules, each id in byte order."""
    for authority_id in sorted(authorities, key=lambda i: i.encode("utf-8")):
        raw = authority_id.encode("utf-8")
        # The alphabet is checked under a hybrid pin only, as in the reference.
        if pin_hex is not None and (not raw or len(raw) > 128 or not set(raw) <= _AUTHORITY_ID_ALPHABET):
            raise TrustChainError(AUTHORITY_ID_MALFORMED)
        byoc = "hybrid1" in authority_id
        carried = _byoc_pin_hex(authority_id) if byoc else None
        if byoc and carried is None:
            raise TrustChainError(BYOC_AUTHORITY_ID_MALFORMED)
        if pin_hex is None and byoc:
            raise TrustChainError(BYOC_AUTHORITY_NEEDS_HYBRID_PIN)
        if pin_hex is not None and carried != pin_hex:
            raise TrustChainError(BYOC_AUTHORITY_PIN_MISMATCH)


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


class _Object(dict):  # type: ignore[type-arg]
    """A parsed JSON object that remembers whether a member name was repeated,
    and whether any member value held a repeat, the copies a repeat drops
    included."""

    repeated = False
    inner_repeat = False


def _object(pairs: List[Tuple[str, Any]]) -> "_Object":
    obj = _Object(pairs)
    obj.repeated = len(obj) != len(pairs)
    obj.inner_repeat = any(_has_repeat(v) for _, v in pairs)
    return obj


def _has_repeat(value: Any, authority_map: bool = False) -> bool:
    if isinstance(value, _Object):
        return (value.repeated and not authority_map) or value.inner_repeat
    if isinstance(value, list):
        return any(_has_repeat(v) for v in value)
    return False


def _load(key_list: Union[bytes, str, Mapping[str, Any]], refuse_repeated: bool = False) -> Any:
    # The reference parses the list with serde_json::from_slice, which refuses a
    # byte order mark, UTF-16 and UTF-32 text, NaN and Infinity. json.loads takes
    # all of them from bytes, and NaN and Infinity from text as well.
    #
    # json.loads keeps the last copy of a repeated member, which no signature
    # then covers. The reference refuses a repeated member in every key list
    # object but the authority map, which it reads last-wins; under a hybrid
    # pin so does this loader, and it takes the list only as text: a parsed
    # object has already lost the copies a repeat dropped.
    if refuse_repeated and not isinstance(key_list, (bytes, str)):
        return None
    if isinstance(key_list, (bytes, str)):
        try:
            text = key_list.decode("utf-8") if isinstance(key_list, bytes) else key_list
            if not refuse_repeated:
                return json.loads(text, parse_constant=_refuse_constant)
            root = json.loads(text, parse_constant=_refuse_constant, object_pairs_hook=_object)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None
        if isinstance(root, _Object):
            if root.repeated or any(
                _has_repeat(v, authority_map=(k == "authorities")) for k, v in root.items()
            ):
                return None
        return root
    return key_list


def _b64(value: str, expected_len: int) -> Optional[bytes]:
    """Strict base64 with an optional ``base64:`` prefix, of an exact length."""
    stripped = value[len("base64:") :] if value.startswith("base64:") else value
    try:
        raw = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == expected_len else None


def _opt_str(rec: Mapping[str, Any], key: str) -> Tuple[bool, Optional[str]]:
    """A string or null; any other present value fails, as serde's Option<String>."""
    value = rec.get(key)
    if value is None:
        return True, None
    if isinstance(value, str):
        return True, value
    return False, None


def _parse_records(raw: Any) -> Optional[Tuple[List[_KeyRecord], List[Dict[str, Any]]]]:
    if not isinstance(raw, list):
        return None
    records: List[_KeyRecord] = []
    views: List[Dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            return None
        version = entry.get("signing_key_version")
        pub = entry.get("public_key_b64")
        fingerprint = entry.get("public_key_fingerprint")
        effective_from = entry.get("effective_from")
        if not all(isinstance(v, str) for v in (version, pub, fingerprint, effective_from)):
            return None
        ok_a, archived_at = _opt_str(entry, "archived_at")
        ok_b, algorithm = _opt_str(entry, "algorithm")
        ok_c, partner = _opt_str(entry, "pqc_partner_version")
        if not (ok_a and ok_b and ok_c):
            return None
        view: Dict[str, Any] = {
            "signing_key_version": version,
            "public_key_b64": pub,
            "public_key_fingerprint": fingerprint,
            "effective_from": effective_from,
        }
        if archived_at is not None:
            view["archived_at"] = archived_at
        if algorithm is not None:
            view["algorithm"] = algorithm
        if partner is not None:
            view["pqc_partner_version"] = partner
        records.append(_KeyRecord(version, pub, fingerprint, algorithm, partner))  # type: ignore[arg-type]
        views.append(view)
    return records, views


def _parse(
    root: Any,
) -> Optional[Tuple[Dict[str, _Authority], Dict[str, Any], str, str, str, _PqcMembers]]:
    """The authorities, the signed view, and the identity fields, or None.

    The signed view holds every field the reference reads with its defaults
    filled in (`archived_versions`, `revoked`, the identity key). Anything else
    in the document is outside the signature, as in the reference.
    """
    if not isinstance(root, dict):
        return None
    schema = root.get("schema_version")
    issued = root.get("issued_at")
    fingerprint = root.get("identity_fingerprint")
    signature = root.get("manifest_signature")
    if not all(isinstance(v, str) for v in (schema, issued, fingerprint, signature)):
        return None
    identity_key = root.get("identity_public_key_b64", "")
    if not isinstance(identity_key, str):
        return None
    ok_sig, pqc_signature = _opt_str(root, "pqc_manifest_signature")
    ok_alg, pqc_algorithm = _opt_str(root, "pqc_identity_algorithm")
    ok_key, pqc_key = _opt_str(root, "pqc_identity_public_key_b64")
    if not (ok_sig and ok_alg and ok_key):
        return None

    raw_authorities = root.get("authorities")
    if not isinstance(raw_authorities, dict):
        return None
    authorities: Dict[str, _Authority] = {}
    signed_authorities: Dict[str, Any] = {}
    for authority_id, rec in raw_authorities.items():
        if not isinstance(rec, dict):
            return None
        display_name = rec.get("display_name")
        if not isinstance(display_name, str):
            return None
        active = _parse_records(rec.get("active_versions"))
        if active is None:
            return None
        archived: Tuple[List[_KeyRecord], List[Dict[str, Any]]] = ([], [])
        if "archived_versions" in rec:
            parsed_archived = _parse_records(rec["archived_versions"])
            if parsed_archived is None:
                return None
            archived = parsed_archived
        revoked = False
        if "revoked" in rec:
            if not isinstance(rec["revoked"], bool):
                return None
            revoked = rec["revoked"]
        emits_heads = False
        if "emits_population_heads" in rec:
            if not isinstance(rec["emits_population_heads"], bool):
                return None
            emits_heads = rec["emits_population_heads"]
        authorities[authority_id] = _Authority(tuple(active[0]), tuple(archived[0]), revoked)
        signed_authorities[authority_id] = {
            "display_name": display_name,
            "active_versions": active[1],
            "archived_versions": archived[1],
            "revoked": revoked,
        }
        if emits_heads:
            signed_authorities[authority_id]["emits_population_heads"] = True

    signed_view = {
        "schema_version": schema,
        "issued_at": issued,
        "authorities": signed_authorities,
        "identity_fingerprint": fingerprint,
        "identity_public_key_b64": identity_key,
    }
    if pqc_algorithm is not None:
        signed_view["pqc_identity_algorithm"] = pqc_algorithm
    if pqc_key is not None:
        signed_view["pqc_identity_public_key_b64"] = pqc_key
    pqc = _PqcMembers(pqc_algorithm, pqc_key, pqc_signature)
    return authorities, signed_view, fingerprint, identity_key, signature, pqc  # type: ignore[return-value]
