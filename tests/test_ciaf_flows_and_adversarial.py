# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Comprehensive positive, adversarial security, and cleanroom interoperability tests.

Enforces GEMINI.md Rule 6 (Zero-Shortcut Verification):
Every test uses real Ed25519 cryptography, real RFC 8785 canonicalization, and real
Draft 2020-12 JSON Schema validation with zero mocked cryptographic primitives.
"""

from __future__ import annotations

import ast
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ciaf_lcm.canonical import jcs_sha256
from ciaf_lcm.capsule import LazyCapsuleMaterializer, ProvenanceEventLedger
from ciaf_lcm.cli_demo import (
    build_reference_environment,
    demo_human_reviewer_keypair,
    run_demo_scenarios,
)
from ciaf_lcm.crypto import Ed25519Keypair, sign_claim_envelope, sign_jcs_object
from ciaf_lcm.executor import ExecutionService
from ciaf_lcm.gateway import (
    ComplianceInspectionDecision,
    HumanReviewDecision,
    PreExecutionGovernanceGateway,
)
from ciaf_lcm.registry import (
    AgentIdentityRecord,
    AuthorityPolicyRegistry,
    DelegationRecord,
    UseCaseRecord,
)
from ciaf_lcm.verifier import IndependentVerifier


def _reverse_dict_key_order_recursively(obj: Any) -> Any:
    """Re-order all dictionary keys in reverse order to simulate benign JSON reformatting."""
    if isinstance(obj, dict):
        return {
            k: _reverse_dict_key_order_recursively(v)
            for k, v in reversed(list(obj.items()))
        }
    if isinstance(obj, list):
        return [_reverse_dict_key_order_recursively(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# 1. Positive Flow: Valid ALLOW produces dual-signed receipts & verifies
# ---------------------------------------------------------------------------
def test_01_valid_allow_flow_dual_signed_and_verified() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")
    t0 = datetime(2026, 11, 10, 20, 0, 0, tzinfo=timezone.utc)

    params = {
        "amount_minor_units": 50000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0001",
    }
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-01",
        proposal_id="prop-test-01",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        now=t0,
    )
    assert authz["decision"]["outcome"] == "ALLOW"
    assert authz["execution_grant"] is not None
    assert authz["execution_grant"]["ttl_seconds"] <= 30

    exec_claim = executor.execute(
        workflow_trace_id="trace-test-01",
        proposal_id="prop-test-01",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
        now=t0 + timedelta(seconds=5),
    )
    assert exec_claim["execution"]["attempted"] is True
    assert exec_claim["execution"]["executed"] is True
    assert exec_claim["execution"]["status"] == "SUCCEEDED"
    assert authz["signature"]["key_id"] != exec_claim["signature"]["key_id"]
    assert len(executor.committed_payments) == 1

    capsule = materializer.materialize("trace-test-01", policy, manifest, now=t0)
    assurance = verifier.verify_capsule(capsule, manifest, now=t0)

    assert assurance["capsule_valid"] is True
    assert assurance["assurance_disposition"] == "ASSURED_AUTHORIZED_EXECUTION"
    assert assurance["failed_controls"] == []
    assert all(
        v is True
        for k, v in assurance["checks"].items()
        if k != "scitt_inclusion_verified"
    )


# ---------------------------------------------------------------------------
# 2. Out-of-scope `payments.create` deterministically blocked (CIAF-06)
# ---------------------------------------------------------------------------
def test_02_out_of_scope_payment_blocked_at_gateway_ciaf_06() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")

    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-02",
        proposal_id="prop-test-02",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={
            "amount_minor_units": 9500000,
            "currency": "USD",
            "minor_unit_scale": 2,
            "beneficiary": "vendor-acme-01",
            "invoice_id": "INV-2026-0002",
        },
    )
    assert authz["decision"]["outcome"] == "DENY"
    assert authz["decision"]["reason_code"] == "AUTHORITY_SCOPE_EXCEEDED"
    assert authz["execution_grant"] is None

    exec_claim = executor.attest_gateway_block(
        workflow_trace_id="trace-test-02",
        authorization_claim=authz,
    )
    assert exec_claim["execution"]["attempted"] is False
    assert exec_claim["execution"]["executed"] is False
    assert len(executor.committed_payments) == 0

    capsule = materializer.materialize("trace-test-02", policy, manifest)
    assurance = verifier.verify_capsule(capsule, manifest)

    assert assurance["capsule_valid"] is True
    assert assurance["assurance_disposition"] == "ASSURED_GOVERNANCE_BLOCK"
    assert assurance["failed_controls"] == []


# ---------------------------------------------------------------------------
# 3. Direct Gateway Bypass Attack -> rejected & logged as CIAF-11 exception
# ---------------------------------------------------------------------------
def test_03_direct_gateway_bypass_attack_rejected_ciaf_11() -> None:
    registry, _ledger, _gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")

    # Malicious or misconfigured agent invokes Executor directly without Gateway grant
    exec_claim = executor.execute(
        workflow_trace_id="trace-test-03-bypass",
        proposal_id="prop-bypass-99",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={
            "amount_minor_units": 45000,
            "currency": "USD",
            "minor_unit_scale": 2,
            "beneficiary": "vendor-acme-01",
            "invoice_id": "INV-BYPASS-01",
        },
        execution_grant=None,
        authorization_claim_id=None,
        authorization_claim_digest=None,
    )

    assert exec_claim["execution"]["attempted"] is False
    assert exec_claim["execution"]["executed"] is False
    assert exec_claim["execution"]["status"] == "REJECTED_SECURITY_EXCEPTION"
    assert exec_claim["security_exception"] is not None
    assert exec_claim["security_exception"]["control_id"] == "CIAF-11"
    assert exec_claim["security_exception"]["exception_code"] == "DIRECT_GATEWAY_BYPASS"
    assert len(executor.committed_payments) == 0

    capsule = materializer.materialize("trace-test-03-bypass", policy, manifest)
    assurance = verifier.verify_capsule(capsule, manifest)

    assert assurance["capsule_valid"] is True
    assert assurance["assurance_disposition"] == "ASSURED_SECURITY_EXCEPTION_CONTAINED"


# ---------------------------------------------------------------------------
# 4. Replay Attack -> single-use grant reused for second call rejected
# ---------------------------------------------------------------------------
def test_04_replay_attack_single_use_nonce_rejected() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")
    t0 = datetime(2026, 11, 10, 20, 10, 0, tzinfo=timezone.utc)

    params = {
        "amount_minor_units": 50000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0004",
    }
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-04-replay",
        proposal_id="prop-test-04",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        now=t0,
    )

    # First call succeeds and consumes the single-use nonce
    exec_first = executor.execute(
        workflow_trace_id="trace-test-04-replay",
        proposal_id="prop-test-04",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
        now=t0 + timedelta(seconds=3),
    )
    assert exec_first["execution"]["executed"] is True
    assert len(executor.committed_payments) == 1

    # Replay Attack: attacker replays the exact valid grant 2 seconds later (still inside TTL!)
    exec_replay = executor.execute(
        workflow_trace_id="trace-test-04-replay",
        proposal_id="prop-test-04",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
        now=t0 + timedelta(seconds=5),
    )
    assert exec_replay["execution"]["attempted"] is False
    assert exec_replay["execution"]["executed"] is False
    assert exec_replay["authorization_binding"]["grant_verification_status"] == "NONCE_REPLAYED"
    assert exec_replay["security_exception"]["exception_code"] == "GRANT_NONCE_REPLAY"
    assert len(executor.committed_payments) == 1  # Still only 1 payment settled!

    capsule = materializer.materialize("trace-test-04-replay", policy, manifest)
    assurance = verifier.verify_capsule(capsule, manifest)
    assert assurance["capsule_valid"] is True
    assert assurance["assurance_disposition"] == "ASSURED_SECURITY_EXCEPTION_CONTAINED"


# ---------------------------------------------------------------------------
# 5. TOCTOU / Payload Tampering Attack ($500 grant mutated to $50,000)
# ---------------------------------------------------------------------------
def test_05_toctou_payload_tampering_attack_rejected() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")
    t0 = datetime(2026, 11, 10, 20, 20, 0, tzinfo=timezone.utc)

    approved_params = {
        "amount_minor_units": 50000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0005",
    }
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-05-toctou",
        proposal_id="prop-test-05",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=approved_params,
        now=t0,
    )
    assert authz["decision"]["outcome"] == "ALLOW"

    # TOCTOU Attack: Agent mutates $500.00 (50,000) -> $50,000.00 (5,000,000) after Gateway approval!
    mutated_params = {**approved_params, "amount_minor_units": 5000000}
    exec_tampered = executor.execute(
        workflow_trace_id="trace-test-05-toctou",
        proposal_id="prop-test-05",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=mutated_params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
        now=t0 + timedelta(seconds=4),
    )

    assert exec_tampered["execution"]["attempted"] is False
    assert exec_tampered["execution"]["executed"] is False
    assert (
        exec_tampered["authorization_binding"]["grant_verification_status"]
        == "REQUEST_DIGEST_MISMATCH"
    )
    assert exec_tampered["security_exception"]["exception_code"] == "TOCTOU_PAYLOAD_TAMPER"
    assert len(executor.committed_payments) == 0

    capsule = materializer.materialize("trace-test-05-toctou", policy, manifest)
    assurance = verifier.verify_capsule(capsule, manifest)
    assert assurance["capsule_valid"] is True
    assert assurance["assurance_disposition"] == "ASSURED_SECURITY_EXCEPTION_CONTAINED"


# ---------------------------------------------------------------------------
# 6. Expired Grant Attack -> grant presented after TTL expiration rejected
# ---------------------------------------------------------------------------
def test_06_expired_grant_ttl_attack_rejected() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")
    t0 = datetime(2026, 11, 10, 20, 30, 0, tzinfo=timezone.utc)

    params = {
        "amount_minor_units": 40000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0006",
    }
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-06-expired",
        proposal_id="prop-test-06",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        ttl_seconds=30,
        now=t0,
    )

    # Present grant at t0 + 31 seconds (1 second past 30s TTL expiration)
    exec_expired = executor.execute(
        workflow_trace_id="trace-test-06-expired",
        proposal_id="prop-test-06",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
        now=t0 + timedelta(seconds=31),
    )

    assert exec_expired["execution"]["attempted"] is False
    assert exec_expired["execution"]["executed"] is False
    assert exec_expired["authorization_binding"]["grant_verification_status"] == "EXPIRED_TTL"
    assert exec_expired["security_exception"]["exception_code"] == "GRANT_TTL_EXPIRED"
    assert len(executor.committed_payments) == 0

    capsule = materializer.materialize("trace-test-06-expired", policy, manifest)
    assurance = verifier.verify_capsule(capsule, manifest)
    assert assurance["capsule_valid"] is True
    assert assurance["assurance_disposition"] == "ASSURED_SECURITY_EXCEPTION_CONTAINED"


# ---------------------------------------------------------------------------
# 7. Evidence Mutation Attack vs. Benign Whitespace/Key-Order Reformatting
# ---------------------------------------------------------------------------
def test_07_evidence_mutation_caught_while_whitespace_and_key_reordering_pass() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")

    params = {
        "amount_minor_units": 60000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0007",
    }
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-07",
        proposal_id="prop-test-07",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
    )
    executor.execute(
        workflow_trace_id="trace-test-07",
        proposal_id="prop-test-07",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
    )
    capsule = materializer.materialize("trace-test-07", policy, manifest)

    # Part A: Benign JSON pretty-printing + complete recursive key reversal MUST PASS
    reversed_obj = _reverse_dict_key_order_recursively(capsule)
    reformatted_json = json.dumps(reversed_obj, indent=4)
    reloaded_capsule = json.loads(reformatted_json)
    benign_assurance = verifier.verify_capsule(reloaded_capsule, manifest)
    assert benign_assurance["capsule_valid"] is True

    # Part B: 1-character mutation in ExecutionClaim invoice_id ("INV-2026-0007" -> "INV-2026-0008")
    tampered_capsule = copy.deepcopy(capsule)
    tampered_capsule["execution_claims"][0]["action_request"]["parameters"][
        "invoice_id"
    ] = "INV-2026-0008"
    tampered_assurance = verifier.verify_capsule(tampered_capsule, manifest)

    assert tampered_assurance["capsule_valid"] is False
    assert (
        tampered_assurance["assurance_disposition"]
        == "ASSURANCE_FAILURE_TAMPER_OR_VIOLATION"
    )
    assert tampered_assurance["checks"]["rfc8785_digests_valid"] is False
    assert tampered_assurance["checks"]["ed25519_signatures_valid"] is False
    assert "CIAF-08" in tampered_assurance["failed_controls"]
    assert "CIAF-09" in tampered_assurance["failed_controls"]
    assert "CIAF-10" in tampered_assurance["failed_controls"]


# ---------------------------------------------------------------------------
# 8. Hash-Chain Deletion / Reorder Attack -> broken previous_receipt_digest
# ---------------------------------------------------------------------------
def test_08_hash_chain_deletion_and_reorder_attack_caught() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")
    params = {
        "amount_minor_units": 1500000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-globex-02",
        "invoice_id": "INV-2026-0008",
    }

    # Receipt 0: ESCALATE pending
    gateway.evaluate_proposal(
        workflow_trace_id="trace-test-08",
        proposal_id="prop-test-08",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
    )
    # Receipt 1: ALLOW after cryptographically signed human reviewer approval (intermediate receipt)
    signed_review = HumanReviewDecision.sign(
        reviewer_id="vp-finance@enterprise-example.org",
        reviewer_key=demo_human_reviewer_keypair(),
        proposal_id="prop-test-08",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        policy_digest=policy.policy_digest,
        approved=True,
        rationale="Approved high-value vendor invoice INV-2026-0008.",
    )
    authz_approved = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-08",
        proposal_id="prop-test-08",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        human_review=signed_review,
    )
    # Receipt 2: ExecutionClaim SUCCEEDED
    executor.execute(
        workflow_trace_id="trace-test-08",
        proposal_id="prop-test-08",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz_approved["execution_grant"],
        authorization_claim_id=authz_approved["claim_id"],
        authorization_claim_digest=authz_approved["claim_digest"],
    )

    valid_capsule = materializer.materialize("trace-test-08", policy, manifest)
    assert verifier.verify_capsule(valid_capsule, manifest)["capsule_valid"] is True

    # Attack: Delete Receipt 0 (or intermediate Receipt 1) and even recompute outer capsule_digest!
    deleted_capsule = copy.deepcopy(valid_capsule)
    # Remove intermediate receipt (index 1 of authorization_claims, sequence_number == 1)
    del deleted_capsule["authorization_claims"][1]
    remaining_digests = [
        deleted_capsule["authorization_claims"][0]["claim_digest"],
        deleted_capsule["execution_claims"][0]["claim_digest"],
    ]
    deleted_capsule["hash_chain"]["ordered_receipt_digests"] = remaining_digests
    deleted_capsule["hash_chain"]["receipt_count"] = 2
    deleted_capsule.pop("capsule_digest", None)
    deleted_capsule["capsule_digest"] = jcs_sha256(deleted_capsule)

    assurance = verifier.verify_capsule(deleted_capsule, manifest)
    assert assurance["capsule_valid"] is False
    assert assurance["checks"]["hash_chain_continuity_valid"] is False
    assert "CIAF-09" in assurance["failed_controls"]


# ---------------------------------------------------------------------------
# 9. Forged Issuer / Wrong Key Attack -> signing ExecutionClaim with Gateway key
# ---------------------------------------------------------------------------
def test_09_forged_issuer_wrong_key_role_attack_rejected() -> None:
    gateway_key = Ed25519Keypair.generate(
        "gw-forger-key-01", "PRE_EXECUTION_GOVERNANCE_GATEWAY"
    )
    executor_key = Ed25519Keypair.generate("ex-legit-key-01", "EXECUTION_SERVICE")

    registry, _ledger, _gw, _ex, _mat, verifier, _manifest = build_reference_environment()
    policy = registry.get_policy("pol-ap-payments-2026")
    ledger = ProvenanceEventLedger()
    gateway = PreExecutionGovernanceGateway(
        gateway_id="ciaf-gw-01",
        gateway_key=gateway_key,
        registry=registry,
        ledger=ledger,
    )
    executor = ExecutionService(
        executor_id="payments-executor-01",
        executor_key=executor_key,
        trusted_gateway_public_keys={gateway_key.key_id: gateway_key.public_key_b64u},
        ledger=ledger,
    )
    materializer = LazyCapsuleMaterializer(ledger)
    trusted_manifest = [
        gateway_key.to_manifest_entry(),
        executor_key.to_manifest_entry(),
    ]

    params = {
        "amount_minor_units": 30000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0009",
    }
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-09",
        proposal_id="prop-test-09",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
    )
    executor.execute(
        workflow_trace_id="trace-test-09",
        proposal_id="prop-test-09",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
    )
    forged_capsule = materializer.materialize("trace-test-09", policy, trusted_manifest)

    # Attack Part A: Compromised Gateway attempts to forge ExecutionClaim with `gateway_key`!
    forged_exec = sign_claim_envelope(forged_capsule["execution_claims"][0], gateway_key)
    forged_capsule["execution_claims"][0] = forged_exec
    forged_capsule["hash_chain"]["ordered_receipt_digests"][1] = forged_exec["claim_digest"]
    forged_capsule["hash_chain"]["tip_receipt_digest"] = forged_exec["claim_digest"]
    forged_capsule.pop("capsule_digest", None)
    forged_capsule["capsule_digest"] = jcs_sha256(forged_capsule)

    res_wrong_role = verifier.verify_capsule(forged_capsule, trusted_manifest)
    assert res_wrong_role["capsule_valid"] is False
    assert res_wrong_role["checks"]["dual_key_trust_boundary_valid"] is False
    assert "CIAF-08" in res_wrong_role["failed_controls"]

    # Attack Part B: Untrusted rogue Executor key signs ExecutionClaim
    rogue_key = Ed25519Keypair.generate("rogue-exec-key-99", "EXECUTION_SERVICE")
    rogue_capsule = copy.deepcopy(forged_capsule)
    rogue_exec = sign_claim_envelope(rogue_capsule["execution_claims"][0], rogue_key)
    rogue_capsule["execution_claims"][0] = rogue_exec
    rogue_capsule["hash_chain"]["ordered_receipt_digests"][1] = rogue_exec["claim_digest"]
    rogue_capsule["hash_chain"]["tip_receipt_digest"] = rogue_exec["claim_digest"]
    rogue_capsule.pop("capsule_digest", None)
    rogue_capsule["capsule_digest"] = jcs_sha256(rogue_capsule)

    res_untrusted = verifier.verify_capsule(rogue_capsule, trusted_manifest)
    assert res_untrusted["capsule_valid"] is False
    assert res_untrusted["checks"]["dual_key_trust_boundary_valid"] is False
    assert res_untrusted["checks"]["ed25519_signatures_valid"] is False
    assert "CIAF-10" in res_untrusted["failed_controls"]


# ---------------------------------------------------------------------------
# 10. Interoperability Acceptance Test: Zero-`ciaf_lcm`-import producer
# ---------------------------------------------------------------------------
def test_10_cleanroom_independent_producer_interoperability() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    producer_path = repo_root / "examples" / "independent_producer.py"
    source = producer_path.read_text("utf-8")

    # AST static proof: ZERO imports from `ciaf_lcm`!
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("ciaf_lcm"), (
                    f"Forbidden ciaf_lcm import in independent_producer.py: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert not mod.startswith("ciaf_lcm"), (
                f"Forbidden ciaf_lcm from-import in independent_producer.py: {mod}"
            )

    # Import and run cleanroom producer
    import importlib.util

    spec = importlib.util.spec_from_file_location("independent_producer", producer_path)
    assert spec is not None and spec.loader is not None
    mod_obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod_obj)

    capsule, trusted_key_manifest = mod_obj.produce_independent_capsule()

    verifier = IndependentVerifier()
    assurance = verifier.verify_capsule(capsule, trusted_key_manifest)

    assert assurance["capsule_valid"] is True, assurance["findings"]
    assert assurance["assurance_disposition"] == "ASSURED_AUTHORIZED_EXECUTION"
    assert assurance["failed_controls"] == []


# ---------------------------------------------------------------------------
# Bonus: Verify all 4 CLI Demo flows (`ALLOW`, `DENY`, `ESCALATE`, `REVOKED`)
# ---------------------------------------------------------------------------
def test_cli_demo_all_four_flows_verify_cleanly() -> None:
    reports = run_demo_scenarios()
    assert len(reports) == 4
    assert [r["gateway_outcome"] for r in reports] == ["ALLOW", "DENY", "ALLOW", "DENY"]
    assert reports[2]["initial_gateway_outcome"] == "ESCALATE"
    assert reports[3]["reason_code"] == "AUTHORITY_REVOKED"
    assert all(r["capsule_valid"] is True for r in reports)


# ---------------------------------------------------------------------------
# 11. Compromised Gateway Forging Human Reviewer Approval Rejected (CIAF-07)
# ---------------------------------------------------------------------------
def test_11_compromised_gateway_forged_or_unsigned_human_approval_rejected() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")
    params = {
        "amount_minor_units": 1400000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-globex-02",
        "invoice_id": "INV-2026-0011",
    }

    # Part A: Unsigned HumanReviewDecision submitted to Gateway -> rejected with DENY
    unsigned_review_claim = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-11a",
        proposal_id="prop-test-11a",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        human_review=HumanReviewDecision(
            reviewer_id="vp-finance@enterprise-example.org",
            approved=True,
            rationale="Attempted approval without HUMAN_REVIEWER signature.",
            reviewer_signature=None,
        ),
    )
    assert unsigned_review_claim["decision"]["outcome"] == "DENY"
    assert unsigned_review_claim["decision"]["reason_code"] == "INVALID_HUMAN_REVIEW_SIGNATURE"
    assert unsigned_review_claim["execution_grant"] is None

    # Part B: Compromised Gateway strips/fabricates human signature with its own gateway_key!
    gw_compromised = Ed25519Keypair.generate(
        "gw-compromised-11", "PRE_EXECUTION_GOVERNANCE_GATEWAY"
    )
    ex_key = Ed25519Keypair.generate("ex-legit-11", "EXECUTION_SERVICE")
    rev_legit = demo_human_reviewer_keypair()

    ledger_b = ProvenanceEventLedger()
    # Compromised Gateway omits `trusted_reviewer_public_keys` so it mints an unsigned approval,
    # and then tries to forge `reviewer_signature` with `gw_compromised`!
    bad_gateway = PreExecutionGovernanceGateway(
        gateway_id="ciaf-gw-compromised",
        gateway_key=gw_compromised,
        registry=registry,
        ledger=ledger_b,
    )
    bad_executor = ExecutionService(
        executor_id="payments-executor-01",
        executor_key=ex_key,
        trusted_gateway_public_keys={gw_compromised.key_id: gw_compromised.public_key_b64u},
        ledger=ledger_b,
    )
    forged_rev_sig = sign_jcs_object({"forged": True}, gw_compromised)
    authz_forged = bad_gateway.evaluate_proposal(
        workflow_trace_id="trace-test-11b",
        proposal_id="prop-test-11b",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        human_review=HumanReviewDecision(
            reviewer_id="vp-finance@enterprise-example.org",
            approved=True,
            rationale="Gateway fabricated reviewer sign-off.",
            reviewer_signature=forged_rev_sig,
        ),
    )
    bad_executor.execute(
        workflow_trace_id="trace-test-11b",
        proposal_id="prop-test-11b",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz_forged["execution_grant"],
        authorization_claim_id=authz_forged["claim_id"],
        authorization_claim_digest=authz_forged["claim_digest"],
    )
    manifest_b = [
        gw_compromised.to_manifest_entry(),
        ex_key.to_manifest_entry(),
        rev_legit.to_manifest_entry(),
    ]
    cap_forged = LazyCapsuleMaterializer(ledger_b).materialize(
        "trace-test-11b", policy, manifest_b
    )
    res = verifier.verify_capsule(cap_forged, manifest_b)
    assert res["capsule_valid"] is False
    assert "CIAF-07" in res["failed_controls"]
    assert res["checks"]["ed25519_signatures_valid"] is False


# ---------------------------------------------------------------------------
# 12. Compromised Gateway Conflicting with Signed Registry Attestation Caught
# ---------------------------------------------------------------------------
def test_12_compromised_gateway_conflicting_with_registry_attestation_rejected() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")
    params = {
        "amount_minor_units": 30000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0012",
    }

    # Mint claim while active, then Registry revokes and attests REVOKED state
    # (simulating a compromised Gateway claiming `authority_status="ACTIVE"` despite Registry revocation)
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-12",
        proposal_id="prop-test-12",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
    )
    executor.execute(
        workflow_trace_id="trace-test-12",
        proposal_id="prop-test-12",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
    )
    registry.revoke_agent_authority("agent-finance-01", reason="Compromised workload")
    revoked_attestation = registry.sign_authority_attestation("agent-finance-01")

    capsule = materializer.materialize(
        "trace-test-12",
        policy,
        manifest,
        authority_attestation=revoked_attestation,
    )
    assurance = verifier.verify_capsule(capsule, manifest)
    assert assurance["capsule_valid"] is False
    assert "CIAF-12" in assurance["failed_controls"]
    assert assurance["checks"]["semantic_consistency_valid"] is False


# ---------------------------------------------------------------------------
# 13. Zero-Window In-Flight Revocation Blocks Unexpired Grant (CIAF-12)
# ---------------------------------------------------------------------------
def test_13_zero_window_inflight_revocation_blocks_unexpired_grant_ciaf_12() -> None:
    registry, _ledger, gateway, executor, materializer, verifier, manifest = (
        build_reference_environment()
    )
    policy = registry.get_policy("pol-ap-payments-2026")
    t0 = datetime(2026, 11, 10, 22, 0, 0, tzinfo=timezone.utc)
    params = {
        "amount_minor_units": 40000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0013",
    }

    # t0: Valid 30s grant minted
    authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-test-13-inflight",
        proposal_id="prop-test-13",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        ttl_seconds=30,
        now=t0,
    )
    assert authz["decision"]["outcome"] == "ALLOW"

    # t0 + 2s: Emergency kill-switch revokes agent mid-flight!
    registry.revoke_agent_authority(
        "agent-finance-01",
        reason="Emergency kill-switch during 30s TTL window",
        now=t0 + timedelta(seconds=2),
    )

    # t0 + 4s: Unexpired grant presented to ExecutionService -> synchronously blocked!
    exec_blocked = executor.execute(
        workflow_trace_id="trace-test-13-inflight",
        proposal_id="prop-test-13",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=params,
        execution_grant=authz["execution_grant"],
        authorization_claim_id=authz["claim_id"],
        authorization_claim_digest=authz["claim_digest"],
        now=t0 + timedelta(seconds=4),
    )
    assert exec_blocked["execution"]["attempted"] is False
    assert exec_blocked["execution"]["executed"] is False
    assert (
        exec_blocked["authorization_binding"]["grant_verification_status"]
        == "AUTHORITY_REVOKED_IN_FLIGHT"
    )
    assert exec_blocked["security_exception"]["control_id"] == "CIAF-12"
    assert exec_blocked["security_exception"]["exception_code"] == "AUTHORITY_REVOKED_IN_FLIGHT"
    assert len(executor.committed_payments) == 0

    capsule = materializer.materialize("trace-test-13-inflight", policy, manifest)
    assurance = verifier.verify_capsule(capsule, manifest)
    assert assurance["capsule_valid"] is True
    assert assurance["assurance_disposition"] == "ASSURED_SECURITY_EXCEPTION_CONTAINED"


# ---------------------------------------------------------------------------
# 14. Structuring / Split-Payment Cumulative Velocity Attack Blocked
# ---------------------------------------------------------------------------
def test_14_cumulative_structuring_split_payment_velocity_attack_blocked() -> None:
    registry, _ledger, gateway, executor, _materializer, _verifier, _manifest = (
        build_reference_environment()
    )
    t0 = datetime(2026, 11, 10, 22, 10, 0, tzinfo=timezone.utc)

    # Delegation autonomous limit is $5,000.00 (500,000), rolling 24h velocity cap is $20,000.00 (2,000,000).
    # Agent attempts 5 x $4,800.00 (480,000) = $24,000.00 split payments to evade human escalation!
    for idx in range(4):
        params = {
            "amount_minor_units": 480000,
            "currency": "USD",
            "minor_unit_scale": 2,
            "beneficiary": "vendor-acme-01",
            "invoice_id": f"INV-SPLIT-{idx}",
        }
        authz_ok = gateway.evaluate_proposal(
            workflow_trace_id=f"trace-split-{idx}",
            proposal_id=f"prop-split-{idx}",
            agent_id="agent-finance-01",
            tool_name="payments.create",
            operation="CREATE_PAYMENT",
            parameters=params,
            now=t0 + timedelta(seconds=idx * 10),
        )
        assert authz_ok["decision"]["outcome"] == "ALLOW"
        executor.execute(
            workflow_trace_id=f"trace-split-{idx}",
            proposal_id=f"prop-split-{idx}",
            agent_id="agent-finance-01",
            tool_name="payments.create",
            operation="CREATE_PAYMENT",
            parameters=params,
            execution_grant=authz_ok["execution_grant"],
            authorization_claim_id=authz_ok["claim_id"],
            authorization_claim_digest=authz_ok["claim_digest"],
            now=t0 + timedelta(seconds=idx * 10 + 2),
        )

    # 5th payment ($19,200.00 + $4,800.00 = $24,000.00 > $20,000.00 rolling cap) MUST be denied!
    authz_blocked = gateway.evaluate_proposal(
        workflow_trace_id="trace-split-4",
        proposal_id="prop-split-4",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={
            "amount_minor_units": 480000,
            "currency": "USD",
            "minor_unit_scale": 2,
            "beneficiary": "vendor-acme-01",
            "invoice_id": "INV-SPLIT-4",
        },
        now=t0 + timedelta(seconds=50),
    )
    assert authz_blocked["decision"]["outcome"] == "DENY"
    assert authz_blocked["decision"]["reason_code"] == "CUMULATIVE_VELOCITY_EXCEEDED"
    assert authz_blocked["execution_grant"] is None
    assert len(executor.committed_payments) == 4


# ---------------------------------------------------------------------------
# 15. Float Precision Rejection, INSPECT Resolution & Domain-Neutral Clinical Flow
# ---------------------------------------------------------------------------
def test_15_float_rejection_inspect_resolution_and_domain_neutral_clinical_flow() -> None:
    rg_key = Ed25519Keypair.generate("rg-clin-01", "REGISTRY_AUTHORITY")
    gw_key = Ed25519Keypair.generate("gw-clin-01", "PRE_EXECUTION_GOVERNANCE_GATEWAY")
    ex_key = Ed25519Keypair.generate("ex-clin-01", "EXECUTION_SERVICE")
    md_key = Ed25519Keypair.generate("md-reviewer-01", "HUMAN_REVIEWER")

    registry = AuthorityPolicyRegistry(registry_key=rg_key)
    registry.register_use_case(
        UseCaseRecord(
            use_case_id="uc-clinical-order-assist-01",
            business_purpose="Inpatient clinical order preparation under attending physician oversight",
            accountable_owner="cmo@hospital-example.org",
            risk_tier="CRITICAL",
        )
    )
    registry.register_agent(
        AgentIdentityRecord(
            agent_id="agent-clinical-01",
            use_case_id="uc-clinical-order-assist-01",
            workload_id="spiffe://hospital-example.org/ns/ehr/sa/agent-clinical-01",
            model_profile="clinical-copilot-v1",
        )
    )
    clin_policy = registry.register_policy(
        policy_id="pol-ehr-orders-2026",
        policy_version="1.2.0",
        policy_document={
            "domain": "healthcare-ehr-clinical-orders",
            "allowed_tools": ["ehr.medication_order.submit"],
            "grant_max_ttl_seconds": 60,  # Policy-configured 60s TTL (Inconsistency 1 check)
        },
    )
    registry.register_delegation(
        DelegationRecord(
            delegation_id="del-clin-01",
            agent_id="agent-clinical-01",
            policy_id=clin_policy.policy_id,
            allowed_tools=("ehr.medication_order.submit",),
            autonomous_max_amount=None,  # Domain-neutral non-monetary delegation!
            escalation_max_amount=None,
            escalate_on_tools=("ehr.medication_order.submit",),
            scope_constraints={"care_unit": ("ICU-WEST", "ONCOLOGY")},
            authorized_human_reviewers=("attending-md@hospital-example.org",),
        )
    )

    # Also register a payment agent with inspection watchlist for float & INSPECT tests
    registry.register_agent(
        AgentIdentityRecord(
            agent_id="agent-pay-inspect-01",
            use_case_id="uc-clinical-order-assist-01",
            workload_id="spiffe://hospital-example.org/ns/ap/sa/agent-pay-inspect-01",
            model_profile="ap-agent-v1",
        )
    )
    pay_policy = registry.register_policy(
        policy_id="pol-ap-watchlist-2026",
        policy_version="1.0.0",
        policy_document={"grant_max_ttl_seconds": 30},
    )
    registry.register_delegation(
        DelegationRecord(
            delegation_id="del-pay-inspect-01",
            agent_id="agent-pay-inspect-01",
            policy_id=pay_policy.policy_id,
            allowed_tools=("payments.create",),
            autonomous_max_amount=500000,  # 500,000 minor units ($5,000.00 USD)
            escalation_max_amount=1000000,
            allowed_currencies=("USD",),
            inspection_watchlist_beneficiaries=("vendor-watchlist-01",),
            authorized_compliance_inspectors=("aml-officer@hospital-example.org",),
        )
    )

    ledger = ProvenanceEventLedger()
    gateway = PreExecutionGovernanceGateway(
        gateway_id="gw-hospital-01",
        gateway_key=gw_key,
        registry=registry,
        ledger=ledger,
        max_grant_ttl_seconds=60,
        trusted_reviewer_public_keys={md_key.key_id: md_key.public_key_b64u},
    )
    executor = ExecutionService(
        executor_id="hospital-executor-01",
        executor_key=ex_key,
        trusted_gateway_public_keys={gw_key.key_id: gw_key.public_key_b64u},
        ledger=ledger,
        max_accepted_ttl_seconds=60,
    )
    materializer = LazyCapsuleMaterializer(ledger)
    verifier = IndependentVerifier()
    manifest = [
        rg_key.to_manifest_entry(),
        gw_key.to_manifest_entry(),
        ex_key.to_manifest_entry(),
        md_key.to_manifest_entry(),
    ]

    # Part A: Bare 'amount' or IEEE-754 float monetary amount rejected & Gateway-only DENY capsule verifies!
    float_deny = gateway.evaluate_proposal(
        workflow_trace_id="trace-float-deny",
        proposal_id="prop-float-01",
        agent_id="agent-pay-inspect-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={"amount_minor_units": 45075.5, "currency": "USD", "minor_unit_scale": 2, "beneficiary": "vendor-ok"},
        target_service="hospital-executor-01",
    )
    assert float_deny["decision"]["outcome"] == "DENY"
    assert float_deny["decision"]["reason_code"] == "INVALID_MONETARY_PRECISION"
    bare_amt_deny = gateway.evaluate_proposal(
        workflow_trace_id="trace-bare-amt-deny",
        proposal_id="prop-bare-amt-01",
        agent_id="agent-pay-inspect-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={"amount": 450, "currency": "USD", "beneficiary": "vendor-ok"},
        target_service="hospital-executor-01",
    )
    assert bare_amt_deny["decision"]["outcome"] == "DENY"
    assert bare_amt_deny["decision"]["reason_code"] == "INVALID_MONETARY_PRECISION"
    cap_float = materializer.materialize("trace-float-deny", pay_policy, manifest)
    assert cap_float["execution_claims"] == []
    assure_float = verifier.verify_capsule(cap_float, manifest)
    assert assure_float["capsule_valid"] is True
    assert assure_float["assurance_disposition"] == "ASSURED_GOVERNANCE_BLOCK"

    # Part B: INSPECT hold -> ComplianceInspectionDecision resolution (`INSPECTION_CLEARED`)
    inspect_hold = gateway.evaluate_proposal(
        workflow_trace_id="trace-inspect-flow",
        proposal_id="prop-insp-01",
        agent_id="agent-pay-inspect-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={
            "amount_minor_units": 125000,
            "currency": "USD",
            "minor_unit_scale": 2,
            "beneficiary": "vendor-watchlist-01",
        },
        target_service="hospital-executor-01",
    )
    assert inspect_hold["decision"]["outcome"] == "INSPECT"
    assert inspect_hold["decision"]["reason_code"] == "INSPECTION_REQUIRED"

    inspect_cleared = gateway.evaluate_proposal(
        workflow_trace_id="trace-inspect-flow",
        proposal_id="prop-insp-01",
        agent_id="agent-pay-inspect-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters={
            "amount_minor_units": 125000,
            "currency": "USD",
            "minor_unit_scale": 2,
            "beneficiary": "vendor-watchlist-01",
        },
        target_service="hospital-executor-01",
        compliance_inspection=ComplianceInspectionDecision(
            inspector_id="aml-officer@hospital-example.org",
            cleared=True,
            inspection_ref="OFAC-CLR-8821",
            rationale="Verified false-positive name match against OFAC SDN list.",
        ),
    )
    assert inspect_cleared["decision"]["outcome"] == "ALLOW"
    assert inspect_cleared["decision"]["reason_code"] == "INSPECTION_CLEARED"

    # Part C: Domain-neutral non-monetary clinical order with 45s policy-bounded TTL & physician signature
    clin_params = {
        "care_unit": "ICU-WEST",
        "medication_rxnorm": "197361",
        "ephi_commitment": "sha256:" + ("a" * 64),
    }
    clin_review = HumanReviewDecision.sign(
        reviewer_id="attending-md@hospital-example.org",
        reviewer_key=md_key,
        proposal_id="prop-clin-01",
        tool_name="ehr.medication_order.submit",
        operation="SUBMIT_MEDICATION_ORDER",
        parameters=clin_params,
        policy_digest=clin_policy.policy_digest,
        approved=True,
        rationale="Reviewed ICU renal dosing and approved order.",
    )
    clin_allow = gateway.evaluate_proposal(
        workflow_trace_id="trace-clin-01",
        proposal_id="prop-clin-01",
        agent_id="agent-clinical-01",
        tool_name="ehr.medication_order.submit",
        operation="SUBMIT_MEDICATION_ORDER",
        parameters=clin_params,
        target_service="hospital-executor-01",
        ttl_seconds=45,
        human_review=clin_review,
    )
    assert clin_allow["decision"]["outcome"] == "ALLOW"
    executor.execute(
        workflow_trace_id="trace-clin-01",
        proposal_id="prop-clin-01",
        agent_id="agent-clinical-01",
        tool_name="ehr.medication_order.submit",
        operation="SUBMIT_MEDICATION_ORDER",
        parameters=clin_params,
        execution_grant=clin_allow["execution_grant"],
        authorization_claim_id=clin_allow["claim_id"],
        authorization_claim_digest=clin_allow["claim_digest"],
    )
    cap_clin = materializer.materialize(
        "trace-clin-01",
        clin_policy,
        manifest,
        authority_attestation=registry.sign_authority_attestation("agent-clinical-01"),
    )
    assure_clin = verifier.verify_capsule(cap_clin, manifest)
    assert assure_clin["capsule_valid"] is True, assure_clin["findings"]
    assert assure_clin["assurance_disposition"] == "ASSURED_AUTHORIZED_EXECUTION"


# ---------------------------------------------------------------------------
# 16. Buggy/Rogue Gateway Issuing Unescalated ALLOW Above delegated_scope_snapshot
# ---------------------------------------------------------------------------
def test_16_rogue_gateway_allow_exceeding_delegated_scope_snapshot_caught() -> None:
    """Prove stateless IndependentVerifier catches Gateway scope/escalation bypass via delegated_scope_snapshot."""
    gw_key = Ed25519Keypair.generate("gw-rogue-snap-16", "PRE_EXECUTION_GOVERNANCE_GATEWAY")
    ex_key = Ed25519Keypair.generate("ex-legit-snap-16", "EXECUTION_SERVICE")

    registry, _ledger, _gw, _ex, _mat, verifier, _manifest = build_reference_environment()
    policy = registry.get_policy("pol-ap-payments-2026")
    ledger = ProvenanceEventLedger()
    gateway = PreExecutionGovernanceGateway(
        gateway_id="ciaf-gw-16",
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
    manifest = [gw_key.to_manifest_entry(), ex_key.to_manifest_entry()]
    t0 = datetime(2026, 11, 10, 23, 0, 0, tzinfo=timezone.utc)

    # Mint a valid baseline capsule first, then simulate a buggy/rogue Gateway signing
    # an unescalated ALLOW for $8,500.00 (850,000 minor units) while delegated_scope_snapshot
    # declares max_auto_amount_minor_units == 500,000 ($5,000.00) — WITH NO authority_attestation!
    base_params = {
        "amount_minor_units": 45000,
        "currency": "USD",
        "minor_unit_scale": 2,
        "beneficiary": "vendor-acme-01",
        "invoice_id": "INV-2026-0016",
    }
    base_authz = gateway.evaluate_proposal(
        workflow_trace_id="trace-rogue-snap-16",
        proposal_id="prop-rogue-16",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=base_params,
        now=t0,
    )

    # Rogue Gateway mutates amount_minor_units to 850,000 ($8,500.00 > $5,000.00 auto limit)
    # without human escalation, re-computes request_digest, and validly signs both grant & claim!
    from ciaf_lcm.canonical import compute_request_digest

    rogue_params = {**base_params, "amount_minor_units": 850000}
    rogue_req_digest = compute_request_digest("payments.create", "CREATE_PAYMENT", rogue_params)

    unsigned_rogue_grant = {
        k: v
        for k, v in base_authz["execution_grant"].items()
        if k != "gateway_grant_signature"
    }
    unsigned_rogue_grant["bound_request_digest"] = rogue_req_digest
    rogue_grant = {
        **unsigned_rogue_grant,
        "gateway_grant_signature": sign_jcs_object(unsigned_rogue_grant, gw_key),
    }

    unsigned_rogue_authz = {
        k: v
        for k, v in copy.deepcopy(base_authz).items()
        if k not in ("signature", "claim_digest")
    }
    unsigned_rogue_authz["proposed_action"]["parameters"] = rogue_params
    unsigned_rogue_authz["proposed_action"]["request_digest"] = rogue_req_digest
    unsigned_rogue_authz["execution_grant"] = rogue_grant
    # `delegated_scope_snapshot.max_auto_amount_minor_units` is 500,000 and `human_escalation.required` is False!
    signed_rogue_authz = sign_claim_envelope(unsigned_rogue_authz, gw_key)

    rogue_ledger = ProvenanceEventLedger()
    rogue_ledger.append("trace-rogue-16", signed_rogue_authz)
    rogue_executor = ExecutionService(
        executor_id="payments-executor-01",
        executor_key=ex_key,
        trusted_gateway_public_keys={gw_key.key_id: gw_key.public_key_b64u},
        ledger=rogue_ledger,
        pinned_policy_digests={policy.policy_digest},
    )
    rogue_executor.execute(
        workflow_trace_id="trace-rogue-16",
        proposal_id="prop-rogue-16",
        agent_id="agent-finance-01",
        tool_name="payments.create",
        operation="CREATE_PAYMENT",
        parameters=rogue_params,
        execution_grant=rogue_grant,
        authorization_claim_id=signed_rogue_authz["claim_id"],
        authorization_claim_digest=signed_rogue_authz["claim_digest"],
        now=t0 + timedelta(seconds=3),
    )

    # Notice: authority_attestation is None — Verifier relies purely on delegated_scope_snapshot!
    rogue_capsule = LazyCapsuleMaterializer(rogue_ledger).materialize(
        "trace-rogue-16", policy, manifest, now=t0 + timedelta(seconds=4)
    )
    assert rogue_capsule.get("authority_attestation") is None

    assurance = verifier.verify_capsule(rogue_capsule, manifest, now=t0 + timedelta(seconds=5))
    assert assurance["capsule_valid"] is False
    assert assurance["checks"]["semantic_consistency_valid"] is False
    assert "CIAF-06" in assurance["failed_controls"]
    assert "CIAF-07" in assurance["failed_controls"]
    finding_codes = {f["code"] for f in assurance["findings"]}
    assert "UNESCALATED_ALLOW_ABOVE_AUTONOMOUS_LIMIT" in finding_codes



