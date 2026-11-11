# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Export a deterministic cross-language RFC 8785 + Ed25519 fixture from Python for TypeScript Web Crypto."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ciaf_lcm.canonical import canonicalize_jcs_str, jcs_sha256
from ciaf_lcm.capsule import LazyCapsuleMaterializer, ProvenanceEventLedger
from ciaf_lcm.crypto import Ed25519Keypair
from ciaf_lcm.executor import ExecutionService
from ciaf_lcm.gateway import PreExecutionGovernanceGateway
from ciaf_lcm.registry import (
    AgentIdentityRecord,
    AuthorityPolicyRegistry,
    DelegationRecord,
    UseCaseRecord,
)
from ciaf_lcm.verifier import IndependentVerifier


def build_cross_language_fixture() -> dict[str, object]:
    # 1. RFC 8785 Torture Vector (astral-plane surrogate order, floats, nested objects, control chars)
    torture_obj = {
        "\uE000": "bmp-private-use-sorts-after-astral",
        "\U0001F600": "astral-emoji-sorts-before-bmp-e000",
        "numbers": {
            "neg_zero": -0.0,
            "int_exact_float": 500.0,
            "half": 4.50,
            "twenty_zeros": 1e20,
            "sci_pos": 1e21,
            "fixed_micro": 1e-6,
            "sci_neg": 1e-7,
            "dtoa_roundtrip": 333333333.33333329,
        },
        "controls": "\x00\x08\t\n\x0c\r\x1f\"\\€",
        "nested": {"z": [True, False, None], "a": "canonical"},
    }
    expected_jcs = canonicalize_jcs_str(torture_obj)
    expected_digest = jcs_sha256(torture_obj)

    # Note: When serialized to JSON on disk, -0.0 becomes 0; TypeScript tests both parsed JSON
    # AND live JS `-0.0` against `expected_jcs` and `expected_digest`.
    json_safe_torture_obj = json.loads(json.dumps(torture_obj))
    assert canonicalize_jcs_str(json_safe_torture_obj) == expected_jcs

    # 2. Deterministic Multi-Role Ed25519 capsule signed in Python
    gw_seed = bytes(range(1, 33))
    ex_seed = bytes(range(33, 65))
    vr_seed = bytes(range(65, 97))
    rg_seed = bytes(range(97, 129))

    gw_key = Ed25519Keypair.from_seed(
        "py-gateway-ed25519-01", "PRE_EXECUTION_GOVERNANCE_GATEWAY", gw_seed
    )
    ex_key = Ed25519Keypair.from_seed(
        "py-executor-ed25519-01", "EXECUTION_SERVICE", ex_seed
    )
    vr_key = Ed25519Keypair.from_seed(
        "py-verifier-ed25519-01", "ASSURANCE_VERIFIER", vr_seed
    )
    rg_key = Ed25519Keypair.from_seed(
        "py-registry-ed25519-01", "REGISTRY_AUTHORITY", rg_seed
    )

    registry = AuthorityPolicyRegistry(registry_key=rg_key)
    registry.register_use_case(
        UseCaseRecord(
            use_case_id="uc-ap-invoice-settlement-01",
            business_purpose="Automated Accounts Payable verified vendor invoice settlement",
            accountable_owner="controller@enterprise-example.org",
            risk_tier="HIGH",
        )
    )
    registry.register_agent(
        AgentIdentityRecord(
            agent_id="agent-finance-01",
            use_case_id="uc-ap-invoice-settlement-01",
            workload_id="spiffe://enterprise-example.org/ns/finance/sa/agent-finance-01",
            model_profile="vendor-neutral-reasoning-agent-v1",
        )
    )
    policy = registry.register_policy(
        policy_id="pol-ap-payments-2026",
        policy_version="1.0.0",
        policy_document={
            "domain": "enterprise-accounts-payable",
            "allowed_tools": ["payments.create"],
            "autonomous_max_amount_minor_units": 500000,
            "escalation_max_amount_minor_units": 2500000,
            "allowed_currencies": ["USD"],
            "minor_unit_scale": 2,
            "grant_max_ttl_seconds": 30,
            "require_single_use_nonce": True,
            "authorized_human_reviewers": ["vp-finance@enterprise-example.org"],
        },
    )
    registry.register_delegation(
        DelegationRecord(
            delegation_id="del-fin-agent-01",
            agent_id="agent-finance-01",
            policy_id=policy.policy_id,
            allowed_tools=("payments.create",),
            autonomous_max_amount=500000,
            escalation_max_amount=2500000,
            allowed_currencies=("USD",),
            allowed_beneficiaries=("vendor-acme-01", "vendor-globex-02"),
            authorized_human_reviewers=("vp-finance@enterprise-example.org",),
        )
    )

    ledger = ProvenanceEventLedger()
    gateway = PreExecutionGovernanceGateway(
        gateway_id="ciaf-gateway-prod-01",
        gateway_key=gw_key,
        registry=registry,
        ledger=ledger,
    )
    executor = ExecutionService(
        executor_id="payments-executor-01",
        executor_key=ex_key,
        trusted_gateway_public_keys={gw_key.key_id: gw_key.public_key_b64u},
        ledger=ledger,
        pinned_policy_digests={policy.policy_digest},
    )
    materializer = LazyCapsuleMaterializer(ledger)
    trusted_keys = [
        rg_key.to_manifest_entry(),
        gw_key.to_manifest_entry(),
        ex_key.to_manifest_entry(),
        vr_key.to_manifest_entry(),
    ]

    t0 = datetime(2026, 11, 10, 21, 30, 0, tzinfo=timezone.utc)
    params = {
        "amount_minor_units": 45000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-PY-WEBCRYPTO-01",
    }
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-py-to-webcrypto-01",
        proposal_id="prop-py-001",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        now=t0,
    )
    executor.execute(
        workflow_trace_id="trace-py-to-webcrypto-01",
        proposal_id="prop-py-001",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
        now=t0 + timedelta(seconds=4),
    )
    capsule = materializer.materialize(
        "trace-py-to-webcrypto-01",
        policy,
        trusted_keys,
        capsule_id="caps-python-signed-interop-01",
        now=t0 + timedelta(seconds=5),
        authority_attestation=registry.sign_authority_attestation(
            "agent-finance-01", now=t0
        ),
    )
    assurance = IndependentVerifier(verifier_key=vr_key).verify_capsule(
        capsule, trusted_keys, now=t0 + timedelta(seconds=6)
    )
    assert assurance["capsule_valid"] is True

    return {
        "jcs_torture_vector": {
            "input": json_safe_torture_obj,
            "expected_canonical_jcs": expected_jcs,
            "expected_sha256": expected_digest,
        },
        "trusted_key_manifest": trusted_keys,
        "python_signed_capsule": capsule,
        "python_assurance_claim": assurance,
    }


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    out_path = (
        repo_root
        / "apps"
        / "verifier-sandbox"
        / "src"
        / "fixtures"
        / "python_cross_lang_fixture.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fixture = build_cross_language_fixture()
    out_path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n", "utf-8")
    print(f"Wrote cross-language fixture to {out_path}")


if __name__ == "__main__":
    main()

