# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Strict RFC 8785 (JSON Canonicalization Scheme / JCS) serializer and SHA-256 helpers."""

from __future__ import annotations

import hashlib
import hmac
import math
from decimal import Decimal
from typing import Any

_SHORT_ESCAPES: dict[int, str] = {
    0x08: r"\b",
    0x09: r"\t",
    0x0A: r"\n",
    0x0C: r"\f",
    0x0D: r"\r",
    0x22: r"\"",
    0x5C: r"\\",
}

MAX_IEEE754_SAFE_INT = (1 << 53) - 1


def _format_ecmascript_number(value: float) -> str:
    """Serialize an IEEE-754 binary64 float per ECMA-262 7.1.12.1 / RFC 8785 Section 3.2.2.3."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError("RFC 8785 forbids NaN and Infinity in JSON numbers.")
    if value == 0.0:
        # Handles both +0.0 and -0.0 per RFC 8785 ("0", never "-0" or "0.0")
        return "0"

    sign = "-" if value < 0.0 else ""
    abs_val = -value if value < 0.0 else value

    # CPython's repr(float) uses David Gay's shortest round-trip dtoa algorithm.
    dec = Decimal(repr(abs_val)).normalize()
    sign_dec, digits_tuple, exp = dec.as_tuple()
    _ = sign_dec
    if not digits_tuple:
        return "0"

    s = "".join(str(d) for d in digits_tuple)
    k = len(s)
    # value == int(s) * 10**exp == 0.<s_digits> * 10**(exp + k)
    n = int(exp) + k

    if k <= n <= 21:
        return f"{sign}{s}{'0' * (n - k)}"
    if 0 < n <= 21:
        return f"{sign}{s[:n]}.{s[n:]}"
    if -5 <= n <= 0:
        return f"{sign}0.{'0' * (-n)}{s}"

    sci_exp = n - 1
    exp_str = f"e+{sci_exp}" if sci_exp >= 0 else f"e{sci_exp}"
    if k == 1:
        return f"{sign}{s}{exp_str}"
    return f"{sign}{s[0]}.{s[1:]}{exp_str}"


def _serialize_string(value: str) -> str:
    """Serialize a JSON string per RFC 8785 Section 3.2.2.2."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("RFC 8785 forbids unpaired UTF-16 surrogates in strings.") from exc

    out: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        if code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_sort_key(item: tuple[str, Any]) -> bytes:
    """Sort object keys by UTF-16 code unit sequence per RFC 8785 Section 3.2.3."""
    key = item[0]
    if not isinstance(key, str):
        raise TypeError(f"JSON object keys must be strings, got {type(key).__name__}.")
    try:
        return key.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise ValueError("RFC 8785 forbids unpaired UTF-16 surrogates in object keys.") from exc


def _serialize_value(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) <= MAX_IEEE754_SAFE_INT:
            return str(value)
        return _format_ecmascript_number(float(value))
    if isinstance(value, float):
        return _format_ecmascript_number(value)
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize_value(elem) for elem in value) + "]"
    if isinstance(value, dict):
        sorted_items = sorted(value.items(), key=_utf16_sort_key)
        members = [
            f"{_serialize_string(k)}:{_serialize_value(v)}"
            for k, v in sorted_items
        ]
        return "{" + ",".join(members) + "}"
    raise TypeError(f"Unsupported type for RFC 8785 canonicalization: {type(value).__name__}")


def canonicalize_jcs_str(value: Any) -> str:
    """Return the RFC 8785 canonical JSON string for `value`."""
    return _serialize_value(value)


def canonicalize_jcs(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 byte sequence for `value`."""
    return _serialize_value(value).encode("utf-8")


def jcs_sha256(value: Any) -> str:
    """Compute `sha256:<64-lowercase-hex>` over the RFC 8785 canonical bytes of `value`."""
    digest_hex = hashlib.sha256(canonicalize_jcs(value)).hexdigest()
    return f"sha256:{digest_hex}"


def compute_request_digest(
    tool_name: str,
    operation: str,
    parameters: dict[str, Any],
) -> str:
    """Compute the deterministic action `request_digest` binding tool, operation, and parameters."""
    canonical_request = {
        "tool_name": tool_name,
        "operation": operation,
        "parameters": parameters,
    }
    return jcs_sha256(canonical_request)


def jcs_salted_commitment(value: Any, salt_b64u: str) -> str:
    """Compute a high-entropy salted RFC 8785 SHA-256 commitment preventing low-entropy brute force.

    Used when anchoring digests of regulated/low-entropy payloads (e.g., HIPAA ePHI parameters)
    into external IETF SCITT transparency logs while keeping `salt_b64u` inside access-controlled storage.
    """
    if len(salt_b64u) < 22:
        raise ValueError("Commitment salt must contain at least 128 bits (>=22 base64url chars).")
    return jcs_sha256({"commitment_salt": salt_b64u, "payload": value})


def jcs_hmac_sha256(value: Any, secret_key: bytes) -> str:
    """Compute `hmac-sha256:<64-hex>` over RFC 8785 canonical bytes using a >=16-byte key."""
    if len(secret_key) < 16:
        raise ValueError("HMAC key must be at least 16 bytes (128 bits).")
    mac = hmac.new(secret_key, canonicalize_jcs(value), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{mac}"

