# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Ed25519 key generation, OKP JWK manifest helpers, and RFC 8785 enveloped signing."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize_jcs, jcs_sha256

KeyRole = Literal[
    "PRE_EXECUTION_GOVERNANCE_GATEWAY",
    "EXECUTION_SERVICE",
    "ASSURANCE_VERIFIER",
    "REGISTRY_AUTHORITY",
    "HUMAN_REVIEWER",
]


def b64u_encode(raw: bytes) -> str:
    """Encode bytes as unpadded RFC 4648 Section 5 base64url."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(encoded: str) -> bytes:
    """Decode unpadded RFC 4648 Section 5 base64url string to bytes."""
    pad_len = (-len(encoded)) % 4
    return base64.urlsafe_b64decode(encoded + ("=" * pad_len))


def extract_okp_public_key_b64u(manifest_entry: dict[str, Any]) -> str:
    """Validate and extract the raw 32-byte base64url `x` coordinate from an OKP JWK entry."""
    jwk = manifest_entry.get("public_key_jwk")
    if not isinstance(jwk, dict):
        raise ValueError("Missing 'public_key_jwk' object in trusted key entry.")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(
            f"Expected OKP Ed25519 JWK, got kty={jwk.get('kty')}, crv={jwk.get('crv')}."
        )
    x_val = jwk.get("x")
    if not isinstance(x_val, str) or len(x_val) != 43:
        raise ValueError("Invalid OKP Ed25519 JWK 'x' coordinate length.")
    return x_val


@dataclass(frozen=True)
class Ed25519Keypair:
    """Independent Ed25519 keypair scoped to a specific trust-boundary role."""

    key_id: str
    role: KeyRole
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    status: Literal["ACTIVE", "REVOKED"] = "ACTIVE"

    @classmethod
    def generate(cls, key_id: str, role: KeyRole) -> Ed25519Keypair:
        priv = Ed25519PrivateKey.generate()
        return cls(
            key_id=key_id,
            role=role,
            private_key=priv,
            public_key=priv.public_key(),
            status="ACTIVE",
        )

    @classmethod
    def from_seed(cls, key_id: str, role: KeyRole, seed_32: bytes) -> Ed25519Keypair:
        if len(seed_32) != 32:
            raise ValueError("Ed25519 private seed must be exactly 32 bytes.")
        priv = Ed25519PrivateKey.from_private_bytes(seed_32)
        return cls(
            key_id=key_id,
            role=role,
            private_key=priv,
            public_key=priv.public_key(),
            status="ACTIVE",
        )

    @property
    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def public_key_b64u(self) -> str:
        return b64u_encode(self.public_key_bytes)

    def to_okp_jwk(self) -> dict[str, str]:
        """Export RFC 8037 OKP JWK (`kty: OKP, crv: Ed25519, x: <base64url-32-bytes>`)."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": self.public_key_b64u,
        }

    def to_manifest_entry(self) -> dict[str, Any]:
        """Export role-pinned OKP JWK public key entry for `trusted_keys` / `public_key_manifest`."""
        return {
            "key_id": self.key_id,
            "role": self.role,
            "status": self.status,
            "public_key_jwk": self.to_okp_jwk(),
        }


def sign_jcs_object(
    unsigned_obj: dict[str, Any],
    keypair: Ed25519Keypair,
) -> dict[str, str]:
    """Compute an Ed25519 signature object over the RFC 8785 canonical form of `unsigned_obj`."""
    canonical_bytes = canonicalize_jcs(unsigned_obj)
    payload_digest = jcs_sha256(unsigned_obj)
    raw_sig = keypair.private_key.sign(canonical_bytes)
    return {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": keypair.key_id,
        "signed_payload_digest": payload_digest,
        "sig_b64u": b64u_encode(raw_sig),
    }


def sign_claim_envelope(
    unsigned_claim: dict[str, Any],
    keypair: Ed25519Keypair,
) -> dict[str, Any]:
    """Enveloped signing: sign unsigned body first, then compute `claim_digest` over body + signature."""
    body = copy.deepcopy(unsigned_claim)
    body.pop("signature", None)
    body.pop("claim_digest", None)

    sig_obj = sign_jcs_object(body, keypair)
    signed_with_sig = {**body, "signature": sig_obj}
    claim_digest = jcs_sha256(signed_with_sig)
    return {**signed_with_sig, "claim_digest": claim_digest}


def verify_jcs_signature(
    unsigned_obj: dict[str, Any],
    signature_obj: dict[str, Any],
    public_key_b64u: str,
) -> tuple[bool, str]:
    """Verify RFC 8785 `signed_payload_digest` and Ed25519 signature against raw 32-byte `x`."""
    if signature_obj.get("algorithm") != "Ed25519":
        return False, f"Unsupported signature algorithm: {signature_obj.get('algorithm')}"
    if signature_obj.get("canonicalization") != "RFC8785-JCS":
        return False, f"Unsupported canonicalization: {signature_obj.get('canonicalization')}"

    expected_digest = jcs_sha256(unsigned_obj)
    if signature_obj.get("signed_payload_digest") != expected_digest:
        return (
            False,
            f"Signed payload digest mismatch: expected {expected_digest}, "
            f"got {signature_obj.get('signed_payload_digest')}",
        )

    try:
        pub_bytes = b64u_decode(public_key_b64u)
        sig_bytes = b64u_decode(signature_obj["sig_b64u"])
        if len(pub_bytes) != 32 or len(sig_bytes) != 64:
            return False, "Invalid Ed25519 public key or signature byte length."
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, canonicalize_jcs(unsigned_obj))
    except (InvalidSignature, ValueError, KeyError) as exc:
        return False, f"Ed25519 cryptographic verification failed: {exc}"

    return True, "OK"
