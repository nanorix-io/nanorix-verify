"""ML-DSA (FIPS 204) signature verification, the primitive only.

:func:`verify_ml_dsa` checks one signature over one message with one public
key, for ML-DSA-65 or ML-DSA-87. It is pure ML-DSA (not HashML-DSA) with an
empty context string, the external ``ML-DSA.Verify`` of FIPS 204 Algorithm 3:
the same contract as ``verify_ml_dsa`` in ``tools/nanorix-verify/src/mldsa.rs``.

A success says only that the signature is valid for that key and message. It
says nothing about a record, a key list, a checkpoint, or whether the key is
anchored to any authority: the caller decides what the key and the message are
and what a valid signature means for them. No module under ``src/`` imports
this one; ``tests/test_mldsa_vectors.py`` fails when one does, so wiring it into
a verdict has to change that test too.

Decoding is strict. The public key and the signature must be raw FIPS 204
encodings of exactly the parameter set's length, checked here before the
library is called. On the OpenSSL backend (checked with the 50.0.2 wheels),
``cryptography``'s ``MLDSA65PublicKey.from_public_bytes`` and
``MLDSA87PublicKey.from_public_bytes`` read only a raw key of their own set's
length and refuse anything else, a DER ``SubjectPublicKeyInfo`` included. Every
refusal by the library, of the key or of the signature, is a refusal here.

``cryptography`` has ML-DSA from 48.0.0 when it is built against OpenSSL 3.5.0
or later (from 47.0.0 with AWS-LC or BoringSSL); the wheels on PyPI for the
range this SDK pins bundle OpenSSL 3.5 or later (50.0.2: 4.0.3). A build
without it, such as one compiled from source against an older system OpenSSL,
gets ``algorithm_unsupported`` for every call, never a success.
"""

from __future__ import annotations

import enum
from typing import Any, Dict, Optional, Tuple

__all__ = [
    "ALGORITHM_UNSUPPORTED",
    "MLDSAError",
    "MLDSAParameterSet",
    "PUBLIC_KEY_LENGTH",
    "PUBLIC_KEY_REJECTED",
    "SIGNATURE_INVALID",
    "SIGNATURE_LENGTH",
    "UNKNOWN_PARAMETER_SET",
    "verify_ml_dsa",
]

#: :attr:`MLDSAError.kind` values. Compare a kind against these names, never
#: against a string literal.
UNKNOWN_PARAMETER_SET = "unknown_parameter_set"
ALGORITHM_UNSUPPORTED = "algorithm_unsupported"
PUBLIC_KEY_LENGTH = "public_key_length"
SIGNATURE_LENGTH = "signature_length"
PUBLIC_KEY_REJECTED = "public_key_rejected"
SIGNATURE_INVALID = "signature_invalid"


class MLDSAParameterSet(enum.Enum):
    """An ML-DSA parameter set :func:`verify_ml_dsa` verifies."""

    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"

    @property
    def public_key_len(self) -> int:
        """Length in bytes of an encoded public key (FIPS 204 Table 2)."""
        return _LENGTHS[self][0]

    @property
    def signature_len(self) -> int:
        """Length in bytes of an encoded signature (FIPS 204 Table 2)."""
        return _LENGTHS[self][1]


#: Public key and signature lengths per set (FIPS 204 Table 2). A member with
#: no entry here is refused as an unknown set.
_LENGTHS: Dict[MLDSAParameterSet, Tuple[int, int]] = {
    MLDSAParameterSet.ML_DSA_65: (1952, 3309),
    MLDSAParameterSet.ML_DSA_87: (2592, 4627),
}


class MLDSAError(Exception):
    """Why :func:`verify_ml_dsa` refused a signature.

    ``kind`` is one of these module constants:

    - :data:`UNKNOWN_PARAMETER_SET`: ``parameter_set`` is not an
      :class:`MLDSAParameterSet` this module verifies.
    - :data:`ALGORITHM_UNSUPPORTED`: the installed ``cryptography`` has no
      ML-DSA. Nothing was checked.
    - :data:`PUBLIC_KEY_LENGTH`: the key is not exactly the set's raw length.
    - :data:`SIGNATURE_LENGTH`: the signature is not exactly the set's length.
    - :data:`PUBLIC_KEY_REJECTED`: the library refused a key of the right
      length.
    - :data:`SIGNATURE_INVALID`: the signature does not verify for this key and
      message, or its encoding is not canonical.

    Any ``MLDSAError``, whatever its kind, means the signature was not
    verified. A verdict that requires an ML-DSA signature must treat every
    kind, ``algorithm_unsupported`` included, as a failure of that verdict,
    never as leave to skip the ML-DSA check.

    ``expected`` and ``actual`` are set only for the two length kinds. The text
    is the Rust verifier's for the four kinds it has, and the Go verifier's,
    adapted to ``cryptography``, for the other two.
    """

    def __init__(
        self,
        kind: str,
        parameter_set: object,
        expected: Optional[int] = None,
        actual: Optional[int] = None,
    ) -> None:
        self.kind = kind
        self.parameter_set = parameter_set
        self.expected = expected
        self.actual = actual
        super().__init__(_message(kind, parameter_set, expected, actual))

    def __reduce__(self) -> Tuple[Any, ...]:
        return (MLDSAError, (self.kind, self.parameter_set, self.expected, self.actual))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MLDSAError):
            return NotImplemented
        return (self.kind, self.parameter_set, self.expected, self.actual) == (
            other.kind,
            other.parameter_set,
            other.expected,
            other.actual,
        )

    def __hash__(self) -> int:
        return hash((self.kind, self.parameter_set, self.expected, self.actual))


def _message(
    kind: str, parameter_set: object, expected: Optional[int], actual: Optional[int]
) -> str:
    if isinstance(parameter_set, MLDSAParameterSet):
        name = parameter_set.value
    else:
        name = repr(parameter_set)
    if kind == PUBLIC_KEY_LENGTH:
        return f"{name} public key must be {expected} bytes, got {actual}"
    if kind == SIGNATURE_LENGTH:
        return f"{name} signature must be {expected} bytes, got {actual}"
    if kind == PUBLIC_KEY_REJECTED:
        return f"{name} public key was refused by the decoder"
    if kind == SIGNATURE_INVALID:
        return f"{name} signature does not verify"
    if kind == ALGORITHM_UNSUPPORTED:
        return (
            f"{name} is unsupported by this build: the installed cryptography has no"
            " ML-DSA (it needs OpenSSL 3.5.0 or later, AWS-LC or BoringSSL)"
        )
    if kind == UNKNOWN_PARAMETER_SET:
        return f"{name} is not a parameter set this verifier checks"
    return f"{name}: ML-DSA error kind {kind!r}"


def _key_classes() -> Optional[Dict[MLDSAParameterSet, Any]]:
    """The library's public-key class per set, or None when it has no ML-DSA."""
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        return None
    if not backend.mldsa_supported():
        return None
    return {
        MLDSAParameterSet.ML_DSA_65: mldsa.MLDSA65PublicKey,
        MLDSAParameterSet.ML_DSA_87: mldsa.MLDSA87PublicKey,
    }


def verify_ml_dsa(
    parameter_set: MLDSAParameterSet,
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> None:
    """Verify an ML-DSA ``signature`` over ``message`` with ``public_key``, pure
    ML-DSA with an empty context.

    Returning ``None`` means the signature is valid for this key and message
    under ``parameter_set``, and nothing more: it is a primitive check that says
    nothing about a record, a key list, or whether the key is anchored.

    Every refusal raises :class:`MLDSAError`, checked in this order:
    ``unknown_parameter_set``; ``algorithm_unsupported``; ``public_key_length``
    then ``signature_length``, before the library is called;
    ``unknown_parameter_set`` again for a set the library has no class for;
    ``public_key_rejected``; ``signature_invalid``. A key, message or signature
    that is not a bytes-like object raises ``TypeError``.
    """
    if not isinstance(parameter_set, MLDSAParameterSet) or parameter_set not in _LENGTHS:
        raise MLDSAError(UNKNOWN_PARAMETER_SET, parameter_set)
    key_bytes = memoryview(public_key).tobytes()
    message_bytes = memoryview(message).tobytes()
    signature_bytes = memoryview(signature).tobytes()
    classes = _key_classes()
    if classes is None:
        raise MLDSAError(ALGORITHM_UNSUPPORTED, parameter_set)
    key_len, signature_len = _LENGTHS[parameter_set]
    if len(key_bytes) != key_len:
        raise MLDSAError(PUBLIC_KEY_LENGTH, parameter_set, key_len, len(key_bytes))
    if len(signature_bytes) != signature_len:
        raise MLDSAError(SIGNATURE_LENGTH, parameter_set, signature_len, len(signature_bytes))
    key_class = classes.get(parameter_set)
    if key_class is None:
        raise MLDSAError(UNKNOWN_PARAMETER_SET, parameter_set)
    try:
        key = key_class.from_public_bytes(key_bytes)
    except Exception:
        raise MLDSAError(PUBLIC_KEY_REJECTED, parameter_set) from None
    try:
        key.verify(signature_bytes, message_bytes)
    except Exception:
        raise MLDSAError(SIGNATURE_INVALID, parameter_set) from None
