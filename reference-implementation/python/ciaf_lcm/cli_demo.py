# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Runnable CLI demonstrating the 4 core CIAF-LCM v0.1 governance & verification flows."""

from __future__ import annotations

import json
import sys
from typing import Any

from .capsule import LazyCapsuleMaterializer, ProvenanceEventLedger
from .crypto import Ed25519Keypair
from .executor import ExecutionService
from .gateway import HumanReviewDecision, PreExecutionGovernanceGateway
from .registry import (
    AgentIdentityRecord,
    AuthorityPolicyRegistry,
    DelegationRecord,
    UseCaseRecord,
)
from .verifier import IndependentVerifier


def demo_human_reviewer_keypair() -> Ed25519Keypair:
    """Return an isolated demo `HUMAN_REVIEWER` keypair for `vp-finance@enterprise-example.org`."""
    return Ed25519Keypair.from_seed(
        "reviewer-vp-finance-ed25519-01",
        "HUMAN_REVIEWER",
        bytes(range(101, 133)),
    )


def build_reference_environment() -> tuple[
    AuthorityPolicyRegistry,
    ProvenanceEventLedger,
    PreExecutionGovernanceGateway,
    ExecutionService,
    LazyCapsuleMaterializer,
    IndependentVerifier,
    list[dict[str, Any]],
]:
    """Provision an isolated multi-role CIAF-LCM environment with real Ed25519 keys."""
    registry_key = Ed25519Keypair.generate(
        "registry-ed25519-2026-01", "REGISTRY_AUTHORITY"
    )
    gateway_key = Ed25519Keypair.generate(
        "gateway-ed25519-2026-01", "PRE_EXECUTION_GOVERNANCE_GATEWAY"
    )
    executor_key = Ed25519Keypair.generate(
        "executor-ed25519-2026-01", "EXECUTION_SERVICE"
    )
    verifier_key = Ed25519Keypair.generate(
        "verifier-ed25519-2026-01", "ASSURANCE_VERIFIER"
    )
    reviewer_key = demo_human_reviewer_keypair()

    registry = AuthorityPolicyRegistry(registry_key=registry_key)
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
            "rolling_window_max_amount_minor_units": 2000000,
            "rolling_window_seconds": 86400,
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
            rolling_window_max_amount=2000000,
            rolling_window_seconds=86400,
            allowed_currencies=("USD",),
            allowed_beneficiaries=("vendor-acme-01", "vendor-globex-02"),
            authorized_human_reviewers=("vp-finance@enterprise-example.org",),
        )
    )

    ledger = ProvenanceEventLedger()
    gateway = PreExecutionGovernanceGateway(
        gateway_id="ciaf-gateway-prod-01",
        gateway_key=gateway_key,
        registry=registry,
        ledger=ledger,
        max_grant_ttl_seconds=30,
        trusted_reviewer_public_keys={reviewer_key.key_id: reviewer_key.public_key_b64u},
    )
    executor = ExecutionService(
        executor_id="payments-executor-01",
        executor_key=executor_key,
        trusted_gateway_public_keys={gateway_key.key_id: gateway_key.public_key_b64u},
        ledger=ledger,
        pinned_policy_digests={policy.policy_digest},
        max_accepted_ttl_seconds=30,
        is_agent_revoked=registry.is_agent_revoked,
    )
    materializer = LazyCapsuleMaterializer(ledger)
    verifier = IndependentVerifier(
        verifier_id="ciaf-independent-verifier-01",
        verifier_key=verifier_key,
    )
    trusted_manifest = [
        registry_key.to_manifest_entry(),
        gateway_key.to_manifest_entry(),
        executor_key.to_manifest_entry(),
        verifier_key.to_manifest_entry(),
        reviewer_key.to_manifest_entry(),
    ]
    return (
        registry,
        ledger,
        gateway,
        executor,
        materializer,
        verifier,
        trusted_manifest,
    )


def run_demo_scenarios() -> list[dict[str, Any]]:
    """Execute the 4 canonical CIAF-LCM scenarios and return structured reports."""
    (
        registry,
        _ledger,
        gateway,
        executor,
        materializer,
        verifier,
        trusted_manifest,
    ) = build_reference_environment()
    reviewer_key = demo_human_reviewer_keypair()
    policy = registry.get_policy("pol-ap-payments-2026")
    reports: list[dict[str, Any]] = []

    # Scenario 1: ALLOW within autonomous delegated scope ($450.00 = 45,000 minor units <= 500,000)
    trace_1 = "trace-demo-01-allow"
    params_1 = {
        "amount_minor_units": 45000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-1001",
    }
    authz_1 = gateway.evaluate_proposal(
        workflow_trace_id=trace_1,
        proposal_id="prop-001",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params_1,
    )
    exec_1 = executor.execute(
        workflow_trace_id=trace_1,
        proposal_id="prop-001",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params_1,
        execution_grant=authz_1["execution_grant"],
        authorization_claim_id=authz_1["claim_id"],
        authorization_claim_digest=authz_1["claim_digest"],
    )
    cap_1 = materializer.materialize(
        trace_1,
        policy,
        trusted_manifest,
        authority_attestation=registry.sign_authority_attestation("agent-finance-01"),
    )
    assure_1 = verifier.verify_capsule(cap_1, trusted_manifest)
    reports.append(
        {
            "scenario": "1. ALLOW (Within Autonomous Scope: 45,000 USD minor units / $450.00)",
            "gateway_outcome": authz_1["decision"]["outcome"],
            "reason_code": authz_1["decision"]["reason_code"],
            "execution_attempted": exec_1["execution"]["attempted"],
            "execution_status": exec_1["execution"]["status"],
            "receipt_count": cap_1["hash_chain"]["receipt_count"],
            "capsule_valid": assure_1["capsule_valid"],
            "assurance_disposition": assure_1["assurance_disposition"],
            "assurance_claim_digest": assure_1["claim_digest"],
        }
    )

    # Scenario 2: DENY on AUTHORITY_SCOPE_EXCEEDED ($75,000.00 = 7,500,000 > 2,500,000 ceiling)
    # Blocked cleanly at Gateway without requiring a synthetic Executor receipt (`execution_claims: []`)
    trace_2 = "trace-demo-02-deny-scope"
    authz_2 = gateway.evaluate_proposal(
        workflow_trace_id=trace_2,
        proposal_id="prop-002",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={
            "amount_minor_units": 7500000,
            "currency": "USD",
            "minor_unit_scale": 2,
            "beneficiary": "vendor-acme-01",
            "invoice_id": "INV-2026-1002",
        },
    )
    cap_2 = materializer.materialize(
        trace_2,
        policy,
        trusted_manifest,
        authority_attestation=registry.sign_authority_attestation("agent-finance-01"),
    )
    assure_2 = verifier.verify_capsule(cap_2, trusted_manifest)
    reports.append(
        {
            "scenario": "2. DENY (Out-of-Scope Amount: 7,500,000 USD minor units / $75,000.00 — Blocked at Gateway)",
            "gateway_outcome": authz_2["decision"]["outcome"],
            "reason_code": authz_2["decision"]["reason_code"],
            "execution_attempted": False,
            "execution_status": "GATEWAY_BLOCKED_NO_EXECUTOR_INVOCATION",
            "receipt_count": cap_2["hash_chain"]["receipt_count"],
            "capsule_valid": assure_2["capsule_valid"],
            "assurance_disposition": assure_2["assurance_disposition"],
            "assurance_claim_digest": assure_2["claim_digest"],
        }
    )

    # Scenario 3: ESCALATE ($12,500.00 = 1,250,000 > 500,000 autonomous limit) -> Independent Reviewer Signature -> ALLOW
    trace_3 = "trace-demo-03-escalate"
    params_3 = {
        "amount_minor_units": 1250000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-globex-02",
        "invoice_id": "INV-2026-1003",
    }
    authz_3_pending = gateway.evaluate_proposal(
        workflow_trace_id=trace_3,
        proposal_id="prop-003",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params_3,
    )
    signed_review = HumanReviewDecision.sign(
        reviewer_id="vp-finance@enterprise-example.org",
        reviewer_key=reviewer_key,
        proposal_id="prop-003",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params_3,
        policy_digest=policy.policy_digest,
        approved=True,
        rationale="Verified three-way PO match for quarterly Globex settlement.",
    )
    authz_3_approved = gateway.evaluate_proposal(
        workflow_trace_id=trace_3,
        proposal_id="prop-003",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params_3,
        human_review=signed_review,
    )
    exec_3 = executor.execute(
        workflow_trace_id=trace_3,
        proposal_id="prop-003",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params_3,
        execution_grant=authz_3_approved["execution_grant"],
        authorization_claim_id=authz_3_approved["claim_id"],
        authorization_claim_digest=authz_3_approved["claim_digest"],
    )
    cap_3 = materializer.materialize(
        trace_3,
        policy,
        trusted_manifest,
        authority_attestation=registry.sign_authority_attestation("agent-finance-01"),
    )
    assure_3 = verifier.verify_capsule(cap_3, trusted_manifest)
    reports.append(
        {
            "scenario": "3. ESCALATE -> Signed Human Reviewer Approval -> ALLOW (1,250,000 USD minor units / $12,500.00)",
            "initial_gateway_outcome": authz_3_pending["decision"]["outcome"],
            "gateway_outcome": authz_3_approved["decision"]["outcome"],
            "reason_code": authz_3_approved["decision"]["reason_code"],
            "reviewer_id": authz_3_approved["human_escalation"]["reviewer_id"],
            "reviewer_key_id": authz_3_approved["human_escalation"]["reviewer_signature"][
                "key_id"
            ],
            "execution_attempted": exec_3["execution"]["attempted"],
            "execution_status": exec_3["execution"]["status"],
            "receipt_count": cap_3["hash_chain"]["receipt_count"],
            "capsule_valid": assure_3["capsule_valid"],
            "assurance_disposition": assure_3["assurance_disposition"],
            "assurance_claim_digest": assure_3["claim_digest"],
        }
    )

    # Scenario 4: REVOKED agent authority (CIAF-12 kill-switch)
    registry.revoke_agent_authority(
        "agent-finance-01",
        reason="Anomalous vendor settlement velocity alert (SOC ticket #INC-9921)",
    )
    trace_4 = "trace-demo-04-revoked"
    authz_4 = gateway.evaluate_proposal(
        workflow_trace_id=trace_4,
        proposal_id="prop-004",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={
            "amount_minor_units": 20000,
            "currency": "USD",
            "minor_unit_scale": 2,
            "beneficiary": "vendor-acme-01",
            "invoice_id": "INV-2026-1004",
        },
    )
    cap_4 = materializer.materialize(
        trace_4,
        policy,
        trusted_manifest,
        authority_attestation=registry.sign_authority_attestation("agent-finance-01"),
    )
    assure_4 = verifier.verify_capsule(cap_4, trusted_manifest)
    reports.append(
        {
            "scenario": "4. REVOKED Agent Authority (CIAF-12 Kill-Switch on 20,000 USD minor units / $200.00)",
            "gateway_outcome": authz_4["decision"]["outcome"],
            "reason_code": authz_4["decision"]["reason_code"],
            "execution_attempted": False,
            "execution_status": "GATEWAY_BLOCKED_AUTHORITY_REVOKED",
            "receipt_count": cap_4["hash_chain"]["receipt_count"],
            "capsule_valid": assure_4["capsule_valid"],
            "assurance_disposition": assure_4["assurance_disposition"],
            "assurance_claim_digest": assure_4["claim_digest"],
        }
    )

    return reports


def main() -> int:
    print("=" * 78)
    print("CIAF-LCM v0.1 Reference Architecture — End-to-End Governance & Assurance Demo")
    print("Invariant: Capability != Authority != Authorization != Execution != Assurance")
    print("=" * 78)
    reports = run_demo_scenarios()
    for report in reports:
        print(f"\n--- {report['scenario']} ---")
        print(json.dumps(report, indent=2))
        if not report["capsule_valid"]:
            print("ERROR: Verification failed unexpectedly!", file=sys.stderr)
            return 1
    print("\n" + "=" * 78)
    print(f"SUCCESS: All {len(reports)} end-to-end flows passed stateless verification.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
