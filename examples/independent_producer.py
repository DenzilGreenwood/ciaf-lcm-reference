# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Minimalist Cleanroom Independent Producer for CIAF-LCM v0.1 Interoperability Testing.

IMPORTANT: This module intentionally imports ZERO symbols from `ciaf_lcm`.
It uses ONLY the Python standard library and `cryptography` (Ed25519) directly
from the published CIAF-LCM v0.1 JSON Schema and RFC 8785 specifications to prove
vendor-neutral interoperability with `ciaf_lcm.verifier.IndependentVerifier`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cleanroom_jcs(obj: Any) -> str:
    """Minimal cleanroom RFC 8785 serializer for strings, ints, bools, null, lists, dicts."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        # json.dumps with ensure_ascii=False handles standard escapes; normalize control chars
        chars: list[str] = ['"']
        escapes = {
            0x08: r"\b",
            0x09: r"\t",
            0x0A: r"\n",
            0x0C: r"\f",
            0x0D: r"\r",
            0x22: r"\"",
            0x5C: r"\\",
        }
        for ch in obj:
            cp = ord(ch)
            if cp in escapes:
                chars.append(escapes[cp])
            elif cp < 0x20:
                chars.append(f"\\u{cp:04x}")
            else:
                chars.append(ch)
        chars.append('"')
        return "".join(chars)
    if isinstance(obj, list):
        return "[" + ",".join(_cleanroom_jcs(item) for item in obj) + "]"
    if isinstance(obj, dict):
        ordered = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_cleanroom_jcs(k)}:{_cleanroom_jcs(v)}" for k, v in ordered) + "}"
    raise TypeError(f"Unsupported cleanroom JCS type: {type(obj).__name__}")


def _sha256_jcs(obj: Any) -> str:
    canonical_bytes = _cleanroom_jcs(obj).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()


def _sign_jcs(unsigned_payload: dict[str, Any], priv: Ed25519PrivateKey, key_id: str) -> dict[str, str]:
    raw_bytes = _cleanroom_jcs(unsigned_payload).encode("utf-8")
    sig_bytes = priv.sign(raw_bytes)
    return {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": key_id,
        "signed_payload_digest": "sha256:" + hashlib.sha256(raw_bytes).hexdigest(),
        "sig_b64u": _b64u(sig_bytes),
    }


def produce_independent_capsule() -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Emit a conformant CIAF-LCM v0.1 `(AuditCapsule, trusted_key_manifest)` pair."""
    gw_priv = Ed25519PrivateKey.generate()
    ex_priv = Ed25519PrivateKey.generate()

    gw_kid = "ext-adapter-gateway-key-01"
    ex_kid = "ext-adapter-executor-key-01"

    gw_pub_b64u = _b64u(
        gw_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    ex_pub_b64u = _b64u(
        ex_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )

    key_manifest = [
        {
            "key_id": gw_kid,
            "role": "PRE_EXECUTION_GOVERNANCE_GATEWAY",
            "status": "ACTIVE",
            "public_key_jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": gw_pub_b64u,
            },
        },
        {
            "key_id": ex_kid,
            "role": "EXECUTION_SERVICE",
            "status": "ACTIVE",
            "public_key_jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": ex_pub_b64u,
            },
        },
    ]

    policy_doc = {
        "allowed_currencies": ["USD"],
        "allowed_tools": ["payments.create"],
        "autonomous_max_amount_minor_units": 100000,
        "escalation_max_amount_minor_units": 1000000,
        "minor_unit_scale": 2,
    }
    policy_digest = _sha256_jcs(policy_doc)

    params = {
        "amount_minor_units": 32500,
        "beneficiary": "vendor-cleanroom-99",
        "currency": "USD",
        "invoice_id": "INV-EXT-0042",
        "minor_unit_scale": 2,
    }
    req_digest = _sha256_jcs(
        {
            "operation": "CREATE_PAYMENT",
            "parameters": params,
            "tool_name": "payments.create",
        }
    )

    authz_id = "authz-cleanroom-0001"
    nonce = secrets.token_hex(16)
    unsigned_grant = {
        "bound_agent_id": "agent-external-runtime-01",
        "bound_authorization_claim_id": authz_id,
        "bound_policy_digest": policy_digest,
        "bound_request_digest": req_digest,
        "bound_tool_name": "payments.create",
        "expires_at": "2026-11-10T21:00:30Z",
        "grant_id": "grant-cleanroom-0001",
        "issued_at": "2026-11-10T21:00:00Z",
        "nonce": nonce,
        "target_service": "external-payments-executor",
        "ttl_seconds": 30,
    }
    signed_grant = {
        **unsigned_grant,
        "gateway_grant_signature": _sign_jcs(unsigned_grant, gw_priv, gw_kid),
    }

    unsigned_authz = {
        "authority_context": {
            "authority_status": "ACTIVE",
            "delegated_scope_snapshot": {
                "accountable_owner": "treasury-lead@external-org.example",
                "allowed_tools": ["payments.create"],
                "currency": "USD",
                "escalation_max_amount_minor_units": 1000000,
                "max_auto_amount_minor_units": 100000,
                "revoked": False,
            },
            "delegation_id": "del-cleanroom-01",
            "policy_digest": policy_digest,
            "policy_id": "pol-cleanroom-v1",
            "policy_version": "1.0.0",
        },
        "claim_id": authz_id,
        "claim_type": "AUTHORIZATION_CLAIM",
        "decision": {
            "evaluated_controls": ["CIAF-01", "CIAF-02", "CIAF-03", "CIAF-04", "CIAF-05", "CIAF-06"],
            "outcome": "ALLOW",
            "rationale": "Cleanroom external gateway verified autonomous scope (32,500 USD minor units <= 100,000).",
            "reason_code": "WITHIN_DELEGATED_AUTHORITY",
        },
        "execution_grant": signed_grant,
        "gateway_id": "external-gateway-01",
        "human_escalation": {
            "required": False,
            "review_rationale": None,
            "reviewed_at": None,
            "reviewer_id": None,
            "status": "NOT_REQUIRED",
        },
        "previous_receipt_digest": None,
        "proposed_action": {
            "operation": "CREATE_PAYMENT",
            "parameters": params,
            "proposal_id": "prop-cleanroom-01",
            "request_digest": req_digest,
            "tool_name": "payments.create",
        },
        "schema_version": "0.1.0",
        "sequence_number": 0,
        "subject": {
            "accountable_owner": "treasury-lead@external-org.example",
            "agent_id": "agent-external-runtime-01",
            "business_purpose": "Interoperability acceptance test invoice settlement",
            "use_case_id": "uc-cleanroom-interop-01",
        },
        "timestamp": "2026-11-10T21:00:00Z",
    }
    authz_with_sig = {
        **unsigned_authz,
        "signature": _sign_jcs(unsigned_authz, gw_priv, gw_kid),
    }
    authz_claim = {
        **authz_with_sig,
        "claim_digest": _sha256_jcs(authz_with_sig),
    }

    result_summary = {
        "currency": "USD",
        "minor_unit_scale": 2,
        "payment_id": "pay-cleanroom-7788",
        "settled_amount_minor_units": 32500,
        "settlement_status": "SETTLED",
    }
    unsigned_exec = {
        "action_request": {
            "agent_id": "agent-external-runtime-01",
            "observed_request_digest": req_digest,
            "operation": "CREATE_PAYMENT",
            "parameters": params,
            "proposal_id": "prop-cleanroom-01",
            "tool_name": "payments.create",
        },
        "authorization_binding": {
            "authorization_claim_digest": authz_claim["claim_digest"],
            "authorization_claim_id": authz_id,
            "consumed_nonce": nonce,
            "grant_id": "grant-cleanroom-0001",
            "grant_verification_status": "VERIFIED",
            "policy_digest": policy_digest,
        },
        "claim_id": "exec-cleanroom-0002",
        "claim_type": "EXECUTION_CLAIM",
        "execution": {
            "attempted": True,
            "executed": True,
            "result_digest": _sha256_jcs(result_summary),
            "result_summary": result_summary,
            "side_effects_committed": True,
            "status": "SUCCEEDED",
        },
        "executor_id": "external-payments-executor",
        "previous_receipt_digest": authz_claim["claim_digest"],
        "schema_version": "0.1.0",
        "security_exception": None,
        "sequence_number": 1,
        "timestamp": "2026-11-10T21:00:04Z",
    }
    exec_with_sig = {
        **unsigned_exec,
        "signature": _sign_jcs(unsigned_exec, ex_priv, ex_kid),
    }
    exec_claim = {
        **exec_with_sig,
        "claim_digest": _sha256_jcs(exec_with_sig),
    }

    ordered_digests = [authz_claim["claim_digest"], exec_claim["claim_digest"]]
    unsigned_capsule = {
        "authorization_claims": [authz_claim],
        "capsule_id": "caps-cleanroom-interop-0001",
        "capsule_type": "CIAF_LCM_AUDIT_CAPSULE",
        "execution_claims": [exec_claim],
        "hash_chain": {
            "algorithm": "SHA-256",
            "canonicalization": "RFC8785-JCS",
            "genesis_receipt_digest": ordered_digests[0],
            "ordered_receipt_digests": ordered_digests,
            "receipt_count": 2,
            "tip_receipt_digest": ordered_digests[1],
        },
        "materialized_at": "2026-11-10T21:00:05Z",
        "policy_snapshot": {
            "policy_digest": policy_digest,
            "policy_document": policy_doc,
            "policy_id": "pol-cleanroom-v1",
            "policy_version": "1.0.0",
        },
        "public_key_manifest": key_manifest,
        "schema_version": "0.1.0",
        "scitt_transparency": {
            "completeness_guarantee": (
                "Local RFC 8785 SHA-256 hash-chaining detects mid-chain tampering; "
                "log-tail omission proofs and independent wall-clock anchoring require "
                "IETF SCITT (RFC 9943 / RFC 9942 COSE Receipts) registration or RFC 3161 TSA."
            ),
            "cose_sign1_statement_digest": None,
            "inclusion_receipt_b64u": None,
            "status": "NOT_REGISTERED_LOCAL_CHAIN_ONLY",
            "transparency_service_id": None,
        },
        "workflow_trace_id": "trace-cleanroom-interop-01",
    }
    capsule = {
        **unsigned_capsule,
        "capsule_digest": _sha256_jcs(unsigned_capsule),
    }
    return capsule, key_manifest


if __name__ == "__main__":
    cap, manifest = produce_independent_capsule()
    print(json.dumps({"capsule": cap, "trusted_key_manifest": manifest}, indent=2))

