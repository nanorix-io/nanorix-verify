"""
JCS (RFC 8785) canonical JSON serialization — pure Python, no external deps.

Implements the JSON Canonicalization Scheme as defined in RFC 8785:
  https://www.rfc-editor.org/rfc/rfc8785

The output is UTF-8 encoded bytes where:
  - Object keys are sorted lexicographically by UTF-16 code unit (RFC 8785
    §3.2.3) — NOT by Unicode code point; the two orders differ once a key
    contains an astral-plane character (U+10000+)
  - No insignificant whitespace
  - Numbers serialized as ECMAScript Number::toString writes them (RFC 8785
    §3.2.2.3): every number is read as an IEEE 754 double, so an integer
    beyond 2^53 is written rounded to the nearest double, as serde_jcs does
  - Strings: only the six mandatory escapes (\\b \\f \\n \\r \\t) plus
    \\uXXXX for code points U+0000–U+001F and lone (unpaired) surrogates;
    astral-plane characters (U+10000+) are emitted literally as UTF-8

Used by SDK verifier helpers for AuditProof canonical hash computation.
Cross-impl byte-equivalence with Rust serde_jcs (via test fixture corpus).

Limitations (by design — matches serde_jcs):
  - NaN and Infinity are not valid JSON values; `canonicalize` and
    `canonicalize_signed` raise ValueError on them. `canonicalize_payload`
    writes them as null and turns an int, float, bool or None key into the
    string json.dumps writes for it, so a payload that json.dumps accepted
    still hashes.
  - `canonicalize` rounds an integer outside +-2^53 to the nearest double, as
    serde_jcs does (one beyond the double range raises ValueError);
    `canonicalize_payload` writes it exactly and `canonicalize_signed`
    refuses it (and a lone surrogate).
"""

from __future__ import annotations

import decimal
import math
from typing import Any, Union

__all__ = ["canonicalize", "canonicalize_payload", "canonicalize_signed"]

_MAX_EXACT_INT = 2**53


def _utf16_sort_key(key: str) -> bytes:
    """RFC 8785 §3.2.3 key-ordering projection: UTF-16 code-unit sequence."""
    return key.encode("utf-16-be", "surrogatepass")


def _serialize_string(s: str) -> bytes:
    """Serialize a JSON string per RFC 8785 §3.2.2.2.

    Only the six mandatory escapes + \\uXXXX for U+0000–U+001F.
    No \\/ escaping (RFC 8785 §3.2.2.2 explicitly forbids it).
    No \\uXXXX for code points above U+001F except surrogates.
    """
    out: list[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 0x0000 <= cp <= 0x001F:
            out.append(f"\\u{cp:04x}")
        elif 0xD800 <= cp <= 0xDFFF:
            # A lone surrogate (only reachable via surrogateescape / invalid
            # input) has no UTF-8 form; escape it rather than fail. Well-formed
            # astral-plane characters never land here — Python strs hold them
            # as a single code point, so they fall through and are emitted
            # literally as 4 UTF-8 bytes, matching serde_jcs.
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out).encode("utf-8")


def _serialize_number(v: Union[int, float]) -> bytes:
    """Serialize a JSON number per RFC 8785 §3.2.2.3.

    Every number is read as an IEEE 754 double and written as ECMAScript
    Number::toString writes it. Integers within 2^53 are exact doubles and
    keep their integer form; a larger integer is rounded to the nearest
    double first, as serde_jcs writes every integer through f64.
    NaN / Infinity are not valid JSON — raise ValueError.
    """
    if isinstance(v, bool):
        raise TypeError(f"bool is not a number: {v!r}")
    if isinstance(v, int):
        if -_MAX_EXACT_INT <= v <= _MAX_EXACT_INT:
            # int.__repr__, not str(): an IntEnum's str() is its member name
            # on Python 3.9 and 3.10.
            return int.__repr__(v).encode("ascii")
        try:
            v = float(v)
        except OverflowError:
            raise ValueError(f"JSON number too large for a double: {v!r}") from None
    if math.isnan(v) or math.isinf(v):
        raise ValueError(f"JSON does not support NaN or Infinity: {v!r}")
    return es_number_to_string(v).encode("ascii")


def es_number_to_string(f: float) -> str:
    """Write a finite double exactly as ECMAScript Number::toString does.

    Python's repr gives the shortest digits that round-trip, as ECMAScript
    requires, but not its layout: repr switches to exponential form below
    1e-4 and from 1e16, writes "1e-07" and "1.0", and ECMAScript writes
    "1e-7", "1" and "10000000000000000", with exponential form only below
    1e-6 and from 1e21, always signed ("1e+21").
    """
    if f == 0:
        return "0"
    # Building a Decimal from a string is exact whatever the caller's decimal
    # context; normalize() is not, so trailing zeros are stripped here.
    sign, digit_tuple, exponent = decimal.Decimal(float.__repr__(f)).as_tuple()
    if not isinstance(exponent, int):
        raise ValueError(f"JSON does not support NaN or Infinity: {f!r}")
    digits = "".join(map(str, digit_tuple)).lstrip("0")
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = exponent + k  # the decimal point's place, counted from the first digit
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        out = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return "-" + out if sign else out


_INT_ROUND = "round"
_INT_EXACT = "exact"
_INT_REFUSE = "refuse"


def _is_lone_surrogate_free(s: str) -> bool:
    return not any(0xD800 <= ord(ch) <= 0xDFFF for ch in s)


def _json_dumps_keys(d: dict[Any, Any]) -> dict[Any, Any]:
    """Return `d` with each key as a str, the way json.dumps writes it.

    An int, float, bool or None key becomes ``1``, ``1.5``, ``true`` or
    ``null``; two keys that collide afterwards raise ValueError.
    """
    out: dict[Any, Any] = {}
    for key, value in d.items():
        if isinstance(key, str):
            name = key
        elif key is None:
            name = "null"
        elif isinstance(key, bool):
            name = "true" if key else "false"
        elif isinstance(key, int):
            name = int.__repr__(key)
        elif isinstance(key, float):
            if math.isnan(key):
                name = "NaN"
            elif math.isinf(key):
                name = "Infinity" if key > 0 else "-Infinity"
            else:
                name = float.__repr__(key)
        else:
            raise TypeError(f"JSON object keys must be strings, got {type(key).__name__!r}")
        if name in out:
            raise ValueError(f"two object keys are both {name!r} once written as JSON")
        out[name] = value
    return out


def _serialize_value(
    v: Any, ints: str = _INT_ROUND, strict_text: bool = False, lenient: bool = False
) -> bytes:
    """Recursively serialize a JSON-compatible Python value to JCS bytes.

    ``ints`` decides what happens to an integer outside +-2^53: ``round``
    (the default, which the verifier relies on) writes the nearest double as
    serde_jcs does, ``exact`` writes its decimal digits, ``refuse`` raises
    ValueError. ``strict_text`` raises ValueError on a lone surrogate in a
    string or key, which a JSON parser cannot read. ``lenient`` writes NaN
    and Infinity as null and converts a non-string key as json.dumps does.
    """
    if v is None:
        return b"null"
    if isinstance(v, bool):
        return b"true" if v else b"false"
    if isinstance(v, int):
        if not -_MAX_EXACT_INT <= v <= _MAX_EXACT_INT:
            if ints == _INT_REFUSE:
                raise ValueError(
                    f"integer outside +-2^53 cannot be signed exactly: {v!r}; pass it as a string"
                )
            if ints == _INT_EXACT:
                return int.__repr__(v).encode("ascii")
        return _serialize_number(v)
    if isinstance(v, float):
        if lenient and (math.isnan(v) or math.isinf(v)):
            return b"null"
        return _serialize_number(v)
    if isinstance(v, str):
        if strict_text and not _is_lone_surrogate_free(v):
            raise ValueError("lone surrogate in a string; a JSON parser cannot read it")
        return _serialize_string(v)
    if isinstance(v, (list, tuple)):
        if not v:
            return b"[]"
        parts = [b"["]
        for i, item in enumerate(v):
            if i > 0:
                parts.append(b",")
            parts.append(_serialize_value(item, ints, strict_text, lenient))
        parts.append(b"]")
        return b"".join(parts)
    if isinstance(v, dict):
        if not v:
            return b"{}"
        if lenient:
            v = _json_dumps_keys(v)
        else:
            for key in v:
                if not isinstance(key, str):
                    raise TypeError(
                        f"JSON object keys must be strings, got {type(key).__name__!r}"
                    )
        # RFC 8785 §3.2.3: keys sorted by UTF-16 code unit, not code point.
        # Big-endian UTF-16 bytes compare in code-unit order; surrogatepass
        # keeps a lone surrogate sortable instead of raising.
        sorted_keys = sorted(v.keys(), key=_utf16_sort_key)
        parts = [b"{"]
        for i, key in enumerate(sorted_keys):
            if i > 0:
                parts.append(b",")
            if strict_text and not _is_lone_surrogate_free(key):
                raise ValueError("lone surrogate in a key; a JSON parser cannot read it")
            parts.append(_serialize_string(key))
            parts.append(b":")
            parts.append(_serialize_value(v[key], ints, strict_text, lenient))
        parts.append(b"}")
        return b"".join(parts)
    raise TypeError(f"Object of type {type(v).__name__!r} is not JSON serializable by JCS")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical JSON serialization of `value` as UTF-8 bytes.

    Args:
        value: Any JSON-compatible Python object (dict, list, str, int, float,
               bool, None).

    Returns:
        UTF-8 encoded bytes in JCS canonical form. An integer outside +-2^53
        is rounded to the nearest double, as serde_jcs does.

    Raises:
        TypeError: if `value` contains a non-JSON-serializable type.
        ValueError: if `value` contains NaN or Infinity.
    """
    return _serialize_value(value)


def canonicalize_payload(value: Any) -> bytes:
    """RFC 8785 bytes of a customer payload that is hashed, never re-canonicalized.

    As `canonicalize`, except that an integer outside +-2^53, which I-JSON
    does not allow, is written exactly as its decimal digits instead of being
    rounded, so a 64-bit identifier keeps its own hash. It accepts everything
    json.dumps accepts: NaN and Infinity are written as null, and an int,
    float, bool or None key becomes the string json.dumps writes for it
    (ValueError only when two keys collide afterwards).
    """
    return _serialize_value(value, _INT_EXACT, False, True)


def canonicalize_signed(value: Any) -> bytes:
    """RFC 8785 bytes of a document that is signed and checked again elsewhere.

    As `canonicalize`, except that an integer outside +-2^53 and a lone
    surrogate (which the server cannot parse) raise ValueError. Pass such an
    integer as a string.
    """
    return _serialize_value(value, _INT_REFUSE, True)
