# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for RFC 8785 (JCS) canonicalization and real Ed25519 cryptography."""

from __future__ import annotations

import math
import pytest

from ciaf_lcm.canonical import (
    canonicalize_jcs,
    canonicalize_jcs_str,
    jcs_hmac_sha256,
    jcs_salted_commitment,
    jcs_sha256,
)
from ciaf_lcm.crypto import Ed25519Keypair, sign_claim_envelope, verify_jcs_signature


def test_rfc8785_ecmascript_number_edge_cases() -> None:
    assert canonicalize_jcs_str(0) == "0"
    assert canonicalize_jcs_str(0.0) == "0"
    assert canonicalize_jcs_str(-0.0) == "0"
    assert canonicalize_jcs_str(500.0) == "500"
    assert canonicalize_jcs_str(4.50) == "4.5"
    assert canonicalize_jcs_str(1e20) == "100000000000000000000"
    assert canonicalize_jcs_str(1e21) == "1e+21"
    assert canonicalize_jcs_str(1e-6) == "0.000001"
    assert canonicalize_jcs_str(1e-7) == "1e-7"
    assert canonicalize_jcs_str(333333333.33333329) == "333333333.3333333"
    assert canonicalize_jcs_str(True) == "true"
    assert canonicalize_jcs_str(False) == "false"
    assert canonicalize_jcs_str(None) == "null"


def test_rfc8785_rejects_nan_and_infinity() -> None:
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonicalize_jcs(math.nan)
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonicalize_jcs(math.inf)
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonicalize_jcs(-math.inf)


def test_rfc8785_utf16_key_sorting_with_supplementary_planes() -> None:
    # RFC 8785 Section 3.2.3: U+1F600 (UTF-16 0xD83D 0xDE00) MUST sort BEFORE U+E000 (0xE000)
    payload = {
        "\uE000": "bmp-private-use",
        "\U0001F600": "supplementary-emoji",
        "b": 2,
        "a": 1,
    }
    result = canonicalize_jcs_str(payload)
    assert result == '{"a":1,"b":2,"😀":"supplementary-emoji","\ue000":"bmp-private-use"}'


def test_rfc8785_control_character_escaping() -> None:
    payload = {"ctrl": "\x00\x08\t\n\x0c\r\x1f\"\\€"}
    assert canonicalize_jcs_str(payload) == r'{"ctrl":"\u0000\b\t\n\f\r\u001f\"\\€"}'


def test_jcs_digest_invariance_under_key_reordering() -> None:
    obj_a = {"z": [1, {"y": 2, "x": 3.0}], "a": "hello"}
    obj_b = {"a": "hello", "z": [1, {"x": 3, "y": 2.0}]}
    assert jcs_sha256(obj_a) == jcs_sha256(obj_b)


def test_ed25519_enveloped_signing_and_tamper_detection() -> None:
    kp = Ed25519Keypair.generate("gw-test-01", "PRE_EXECUTION_GOVERNANCE_GATEWAY")
    unsigned = {"claim_id": "c-1", "amount": 500, "nested": {"b": 1, "a": 2}}
    signed = sign_claim_envelope(unsigned, kp)

    body = {k: v for k, v in signed.items() if k not in ("signature", "claim_digest")}
    ok, msg = verify_jcs_signature(body, signed["signature"], kp.public_key_b64u)
    assert ok is True, msg

    tampered = {**body, "amount": 501}
    ok_bad, _ = verify_jcs_signature(tampered, signed["signature"], kp.public_key_b64u)
    assert ok_bad is False


def test_cross_language_python_to_webcrypto_jcs_and_okp_jwk_parity() -> None:
    import subprocess
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / "apps" / "verifier-sandbox" / "scripts" / "verify_cross_lang.mjs"
    proc = subprocess.run(
        ["node", str(script_path)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"WebCrypto interop failed:\n{proc.stdout}\n{proc.stderr}"
    assert "PASS:" in proc.stdout


def test_salted_and_hmac_jcs_commitments_for_low_entropy_ephi() -> None:
    ephi_a = {"mrn": "00194821", "icd10": "I10", "care_unit": "ICU-WEST"}
    ephi_b = {"care_unit": "ICU-WEST", "icd10": "I10", "mrn": "00194821"}
    salt_1 = "s9fK3mP8xQ2vL7nR4tW1yZ"
    salt_2 = "a1b2c3d4e5f6g7h8i9j0kL"

    c1 = jcs_salted_commitment(ephi_a, salt_1)
    c1_reordered = jcs_salted_commitment(ephi_b, salt_1)
    c2 = jcs_salted_commitment(ephi_a, salt_2)
    assert c1 == c1_reordered
    assert c1 != c2
    assert c1 != jcs_sha256(ephi_a)

    with pytest.raises(ValueError, match="128 bits"):
        jcs_salted_commitment(ephi_a, "short-salt")

    key = bytes(range(16))
    mac_a = jcs_hmac_sha256(ephi_a, key)
    mac_b = jcs_hmac_sha256(ephi_b, key)
    assert mac_a == mac_b
    assert mac_a.startswith("hmac-sha256:")

    with pytest.raises(ValueError, match="16 bytes"):
        jcs_hmac_sha256(ephi_a, b"too-short")



