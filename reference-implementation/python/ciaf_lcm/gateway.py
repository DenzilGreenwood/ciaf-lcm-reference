# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Pre-Execution Governance Gateway implementing CIAF-06, CIAF-07, and CIAF-12."""

from __future__ import annotations

import copy
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .canonical import compute_request_digest
from .capsule import ProvenanceEventLedger
from .crypto import (
    Ed25519Keypair,
    sign_claim_envelope,
    sign_jcs_object,
    verify_jcs_signature,
)
from .registry import AuthorityPolicyRegistry, utc_now_iso


def build_human_review_payload(
    *,
    proposal_id: str,
    request_digest: str,
    policy_digest: str,
    reviewer_id: str,
    approved: bool,
    review_rationale: str,
    reviewed_at: str,
) -> dict[str, Any]:
    """Canonical payload signed by an independent `HUMAN_REVIEWER` key for CIAF-07."""
    return {
        "proposal_id": proposal_id,
        "request_digest": request_digest,
        "policy_digest": policy_digest,
        "reviewer_id": reviewer_id,
        "approved": approved,
        "review_rationale": review_rationale,
        "reviewed_at": reviewed_at,
    }


@dataclass(frozen=True)
class HumanReviewDecision:
    """Authenticated human adjudication input for CIAF-07 threshold escalations."""

    reviewer_id: str
    approved: bool
    rationale: str
    reviewed_at: datetime | None = None
    reviewer_signature: dict[str, str] | None = None

    @classmethod
    def sign(
        cls,
        *,
        reviewer_id: str,
        reviewer_key: Ed25519Keypair,
        proposal_id: str,
        tool_name: str,
        operation: str,
        parameters: dict[str, Any],
        policy_digest: str,
        approved: bool,
        rationale: str,
        reviewed_at: datetime | None = None,
    ) -> HumanReviewDecision:
        """Create a cryptographically signed human adjudication bound to `request_digest`."""
        if reviewer_key.role != "HUMAN_REVIEWER":
            raise ValueError("reviewer_key MUST have role 'HUMAN_REVIEWER'.")
        ts_dt = (
            reviewed_at if reviewed_at is not None else datetime.now(timezone.utc)
        ).astimezone(timezone.utc)
        reviewed_ts = utc_now_iso(ts_dt)
        req_digest = compute_request_digest(
            tool_name, operation, copy.deepcopy(parameters)
        )
        payload = build_human_review_payload(
            proposal_id=proposal_id,
            request_digest=req_digest,
            policy_digest=policy_digest,
            reviewer_id=reviewer_id,
            approved=approved,
            review_rationale=rationale,
            reviewed_at=reviewed_ts,
        )
        sig = sign_jcs_object(payload, reviewer_key)
        return cls(
            reviewer_id=reviewer_id,
            approved=approved,
            rationale=rationale,
            reviewed_at=ts_dt,
            reviewer_signature=sig,
        )


@dataclass(frozen=True)
class ComplianceInspectionDecision:
    """Pre-execution compliance inspection resolution for `INSPECT` holds (CIAF-06)."""

    inspector_id: str
    cleared: bool
    inspection_ref: str
    rationale: str


class PreExecutionGovernanceGateway:
    """Separately governed Pre-Execution Governance Gateway (CIAF-06, CIAF-07, CIAF-12).

    Architectural Invariants:
    - Model output is never proof of authorization.
    - Fail-closed: any missing authority, velocity breach, float precision ambiguity,
      invalid reviewer signature, or internal evaluation error results in non-ALLOW
      with `execution_grant = None`.
    - Only `ALLOW` mints short-lived, action-bound `ExecutionGrant` tokens.
    """

    def __init__(
        self,
        gateway_id: str,
        gateway_key: Ed25519Keypair,
        registry: AuthorityPolicyRegistry,
        ledger: ProvenanceEventLedger,
        max_grant_ttl_seconds: int = 30,
        trusted_reviewer_public_keys: dict[str, str] | None = None,
    ) -> None:
        if gateway_key.role != "PRE_EXECUTION_GOVERNANCE_GATEWAY":
            raise ValueError(
                "Gateway keypair MUST have role 'PRE_EXECUTION_GOVERNANCE_GATEWAY'."
            )
        if max_grant_ttl_seconds > 300 or max_grant_ttl_seconds < 1:
            raise ValueError("Gateway max_grant_ttl_seconds must be within 1..300 seconds.")
        self.gateway_id = gateway_id
        self._gateway_key = gateway_key
        self._registry = registry
        self._ledger = ledger
        self.max_grant_ttl_seconds = max_grant_ttl_seconds
        self._trusted_reviewer_keys = (
            dict(trusted_reviewer_public_keys)
            if trusted_reviewer_public_keys is not None
            else {}
        )
        self._grant_history_by_agent: dict[str, list[tuple[datetime, int]]] = {}

    @property
    def public_key_manifest_entry(self) -> dict[str, Any]:
        return self._gateway_key.to_manifest_entry()

    def evaluate_proposal(
        self,
        *,
        workflow_trace_id: str,
        proposal_id: str,
        agent_id: str,
        tool_name: str,
        operation: str,
        parameters: dict[str, Any],
        target_service: str = "payments-executor-01",
        ttl_seconds: int = 30,
        expected_policy_digest: str | None = None,
        human_review: HumanReviewDecision | None = None,
        compliance_inspection: ComplianceInspectionDecision | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        eval_dt = (now if now is not None else datetime.now(timezone.utc)).astimezone(
            timezone.utc
        )
        eval_ts = utc_now_iso(eval_dt)

        ctx = self._registry.resolve_agent_context(agent_id)
        policy_ttl_cap = int(
            ctx.policy.policy_document.get(
                "grant_max_ttl_seconds", self.max_grant_ttl_seconds
            )
        )
        effective_ttl_cap = min(self.max_grant_ttl_seconds, policy_ttl_cap)
        if ttl_seconds < 1 or ttl_seconds > effective_ttl_cap:
            raise ValueError(
                f"Requested ttl_seconds ({ttl_seconds}) exceeds effective bound "
                f"({effective_ttl_cap}s)."
            )

        params_copy = copy.deepcopy(parameters)
        req_digest = compute_request_digest(tool_name, operation, params_copy)
        claim_id = f"authz-{uuid.uuid4().hex[:16]}"
        seq_num, prev_digest = self._ledger.next_chain_position(workflow_trace_id)

        escalation_block: dict[str, Any] = {
            "required": False,
            "status": "NOT_REQUIRED",
            "reviewer_id": None,
            "review_rationale": None,
            "reviewed_at": None,
            "reviewer_signature": None,
        }

        effective_status = (
            "REVOKED"
            if (ctx.agent.status == "REVOKED" or ctx.delegation.status == "REVOKED")
            else (
                "SUSPENDED"
                if (
                    ctx.agent.status == "SUSPENDED"
                    or ctx.delegation.status == "SUSPENDED"
                    or ctx.use_case.status != "ACTIVE"
                )
                else "ACTIVE"
            )
        )

        outcome = "DENY"
        reason_code = "DENIED_BY_DEFAULT"
        rationale = "Default fail-closed deny posture."
        evaluated_controls = [
            "CIAF-01",
            "CIAF-02",
            "CIAF-03",
            "CIAF-04",
            "CIAF-05",
            "CIAF-06",
        ]

        try:
            has_monetary_scope = (
                ctx.delegation.autonomous_max_amount is not None
                or ctx.delegation.escalation_max_amount is not None
                or "amount_minor_units" in params_copy
                or "amount" in params_copy
            )
            amount_minor_raw = params_copy.get("amount_minor_units")
            scale_raw = params_copy.get("minor_unit_scale", 2)
            currency = str(params_copy.get("currency", ""))
            beneficiary = str(params_copy.get("beneficiary", ""))

            # Prune rolling velocity window for this agent
            window_cutoff = eval_dt - timedelta(
                seconds=ctx.delegation.rolling_window_seconds
            )
            recent_grants = [
                (ts, amt)
                for ts, amt in self._grant_history_by_agent.get(agent_id, [])
                if ts >= window_cutoff
            ]
            self._grant_history_by_agent[agent_id] = recent_grants
            window_count = len(recent_grants)
            window_amount = sum(amt for _, amt in recent_grants)

            # Check generic domain-neutral scope constraints
            violated_constraint: str | None = None
            for c_key, allowed_values in ctx.delegation.scope_constraints.items():
                actual_val = params_copy.get(c_key)
                if isinstance(allowed_values, (list, tuple, set)):
                    if actual_val not in allowed_values:
                        violated_constraint = (
                            f"Parameter '{c_key}'={actual_val!r} outside allowed scope "
                            f"{list(allowed_values)}."
                        )
                        break
                elif actual_val != allowed_values:
                    violated_constraint = (
                        f"Parameter '{c_key}'={actual_val!r} != required {allowed_values!r}."
                    )
                    break

            # 1. CIAF-12 Revocation / Suspension check
            if effective_status == "REVOKED":
                outcome = "DENY"
                reason_code = "AUTHORITY_REVOKED"
                rationale = (
                    f"Agent '{agent_id}' authority is REVOKED "
                    f"(reason: {ctx.delegation.revocation_reason or 'administrative revocation'})."
                )
                evaluated_controls.append("CIAF-12")
            elif effective_status != "ACTIVE":
                outcome = "DENY"
                reason_code = "AUTHORITY_SUSPENDED"
                rationale = f"Agent '{agent_id}' or use case is currently suspended."
                evaluated_controls.append("CIAF-12")
            # 2. CIAF-05 Policy digest pinning check
            elif (
                expected_policy_digest is not None
                and expected_policy_digest != ctx.policy.policy_digest
            ):
                outcome = "DENY"
                reason_code = "POLICY_DIGEST_MISMATCH"
                rationale = (
                    f"Expected policy digest {expected_policy_digest} does not match "
                    f"active pinned digest {ctx.policy.policy_digest}."
                )
            # 3. CIAF-04 Scoped tool, domain constraints, and integer monetary validation
            elif tool_name not in ctx.delegation.allowed_tools:
                outcome = "DENY"
                reason_code = "TOOL_NOT_ALLOWED"
                rationale = (
                    f"Tool '{tool_name}' is outside delegated tool allowlist "
                    f"{list(ctx.delegation.allowed_tools)}."
                )
            elif violated_constraint is not None:
                outcome = "DENY"
                reason_code = "SCOPE_CONSTRAINT_VIOLATION"
                rationale = violated_constraint
            elif has_monetary_scope and (
                "amount" in params_copy
                or isinstance(amount_minor_raw, float)
                or isinstance(scale_raw, float)
            ):
                outcome = "DENY"
                reason_code = "INVALID_MONETARY_PRECISION"
                rationale = (
                    "Monetary parameters MUST encode exact ISO-4217 integer minor units "
                    "('amount_minor_units', 'currency', 'minor_unit_scale'); bare 'amount' "
                    "or IEEE-754 floating-point values are rejected."
                )
            elif has_monetary_scope and (
                not isinstance(amount_minor_raw, int)
                or isinstance(amount_minor_raw, bool)
                or amount_minor_raw <= 0
                or not isinstance(scale_raw, int)
                or isinstance(scale_raw, bool)
                or scale_raw < 0
                or scale_raw > 18
            ):
                outcome = "DENY"
                reason_code = "INVALID_PARAMETER_AMOUNT"
                rationale = (
                    "Monetary 'amount_minor_units' must be a positive exact integer and "
                    "'minor_unit_scale' an integer in 0..18."
                )
            elif (
                has_monetary_scope
                and ctx.delegation.allowed_currencies
                and currency not in ctx.delegation.allowed_currencies
            ):
                outcome = "DENY"
                reason_code = "CURRENCY_NOT_ALLOWED"
                rationale = (
                    f"Currency '{currency}' is outside delegated currencies "
                    f"{list(ctx.delegation.allowed_currencies)}."
                )
            elif (
                ctx.delegation.allowed_beneficiaries is not None
                and beneficiary not in ctx.delegation.allowed_beneficiaries
            ):
                outcome = "DENY"
                reason_code = "BENEFICIARY_NOT_ALLOWED"
                rationale = f"Beneficiary '{beneficiary}' is not in approved counterparty registry."
            # 4. Pre-execution Compliance Inspection (`INSPECT` hold & resolution)
            elif (
                beneficiary in ctx.delegation.inspection_watchlist_beneficiaries
                and compliance_inspection is None
            ):
                outcome = "INSPECT"
                reason_code = "INSPECTION_REQUIRED"
                rationale = (
                    f"Counterparty '{beneficiary}' requires pre-execution compliance inspection."
                )
            elif (
                beneficiary in ctx.delegation.inspection_watchlist_beneficiaries
                and compliance_inspection is not None
                and ctx.delegation.authorized_compliance_inspectors
                and compliance_inspection.inspector_id
                not in ctx.delegation.authorized_compliance_inspectors
            ):
                outcome = "DENY"
                reason_code = "UNAUTHORIZED_COMPLIANCE_INSPECTOR"
                rationale = (
                    f"Inspector '{compliance_inspection.inspector_id}' is not authorized "
                    f"to clear compliance holds."
                )
            elif (
                beneficiary in ctx.delegation.inspection_watchlist_beneficiaries
                and compliance_inspection is not None
                and not compliance_inspection.cleared
            ):
                outcome = "DENY"
                reason_code = "INSPECTION_BLOCKED"
                rationale = (
                    f"Compliance inspection '{compliance_inspection.inspection_ref}' "
                    f"blocked action: {compliance_inspection.rationale}"
                )
            # 5. Absolute delegation ceiling & rolling cumulative velocity (anti-structuring)
            elif (
                has_monetary_scope
                and ctx.delegation.escalation_max_amount is not None
                and int(amount_minor_raw) > ctx.delegation.escalation_max_amount
            ):
                outcome = "DENY"
                reason_code = "AUTHORITY_SCOPE_EXCEEDED"
                rationale = (
                    f"Proposed amount {amount_minor_raw} minor units ({currency}) exceeds maximum "
                    f"delegated and escalatable ceiling ({ctx.delegation.escalation_max_amount} "
                    f"minor units {currency})."
                )
            elif (
                ctx.delegation.rolling_window_max_count is not None
                and window_count + 1 > ctx.delegation.rolling_window_max_count
            ):
                outcome = "DENY"
                reason_code = "CUMULATIVE_VELOCITY_EXCEEDED"
                rationale = (
                    f"Rolling window grant count ({window_count + 1}) exceeds cap "
                    f"({ctx.delegation.rolling_window_max_count}) over "
                    f"{ctx.delegation.rolling_window_seconds}s."
                )
            elif (
                has_monetary_scope
                and ctx.delegation.rolling_window_max_amount is not None
                and window_amount + int(amount_minor_raw) > ctx.delegation.rolling_window_max_amount
            ):
                outcome = "DENY"
                reason_code = "CUMULATIVE_VELOCITY_EXCEEDED"
                rationale = (
                    f"Cumulative rolling amount ({window_amount + int(amount_minor_raw)} minor "
                    f"units {currency}) exceeds structuring velocity cap "
                    f"({ctx.delegation.rolling_window_max_amount} minor units {currency}) over "
                    f"{ctx.delegation.rolling_window_seconds}s."
                )
            # 6. CIAF-07 Human-in-the-loop escalation threshold (monetary or high-risk tool)
            elif (
                tool_name in ctx.delegation.escalate_on_tools
                or (
                    has_monetary_scope
                    and ctx.delegation.autonomous_max_amount is not None
                    and int(amount_minor_raw) > ctx.delegation.autonomous_max_amount
                )
            ):
                evaluated_controls.append("CIAF-07")
                if human_review is None:
                    outcome = "ESCALATE"
                    reason_code = "ESCALATION_REQUIRED_PENDING_REVIEW"
                    rationale = (
                        f"Proposed action '{tool_name}' exceeds autonomous authority; "
                        f"cryptographically signed human adjudication required."
                    )
                    escalation_block = {
                        "required": True,
                        "status": "PENDING",
                        "reviewer_id": None,
                        "review_rationale": None,
                        "reviewed_at": None,
                        "reviewer_signature": None,
                    }
                else:
                    reviewed_ts = utc_now_iso(human_review.reviewed_at or eval_dt)
                    if (
                        ctx.delegation.authorized_human_reviewers
                        and human_review.reviewer_id
                        not in ctx.delegation.authorized_human_reviewers
                    ):
                        outcome = "DENY"
                        reason_code = "UNAUTHORIZED_HUMAN_REVIEWER"
                        rationale = (
                            f"Reviewer '{human_review.reviewer_id}' is not authorized to "
                            f"approve escalations for policy '{ctx.policy.policy_id}'."
                        )
                        escalation_block = {
                            "required": True,
                            "status": "REJECTED",
                            "reviewer_id": human_review.reviewer_id,
                            "review_rationale": human_review.rationale,
                            "reviewed_at": reviewed_ts,
                            "reviewer_signature": human_review.reviewer_signature,
                        }
                    elif not human_review.approved:
                        outcome = "DENY"
                        reason_code = "ESCALATION_REJECTED_BY_REVIEWER"
                        rationale = (
                            f"Human reviewer '{human_review.reviewer_id}' rejected escalated action."
                        )
                        escalation_block = {
                            "required": True,
                            "status": "REJECTED",
                            "reviewer_id": human_review.reviewer_id,
                            "review_rationale": human_review.rationale,
                            "reviewed_at": reviewed_ts,
                            "reviewer_signature": human_review.reviewer_signature,
                        }
                    else:
                        # Verify independent HUMAN_REVIEWER Ed25519 signature if reviewer keys configured
                        sig_valid = True
                        sig_err = ""
                        if self._trusted_reviewer_keys:
                            rsig = human_review.reviewer_signature
                            rkid = rsig.get("key_id") if isinstance(rsig, dict) else None
                            rpub = (
                                self._trusted_reviewer_keys.get(str(rkid))
                                if rkid
                                else None
                            )
                            if not isinstance(rsig, dict) or rpub is None:
                                sig_valid = False
                                sig_err = (
                                    f"Missing or untrusted HUMAN_REVIEWER key_id '{rkid}'."
                                )
                            else:
                                expected_payload = build_human_review_payload(
                                    proposal_id=proposal_id,
                                    request_digest=req_digest,
                                    policy_digest=ctx.policy.policy_digest,
                                    reviewer_id=human_review.reviewer_id,
                                    approved=True,
                                    review_rationale=human_review.rationale,
                                    reviewed_at=reviewed_ts,
                                )
                                sig_valid, sig_err = verify_jcs_signature(
                                    expected_payload, rsig, rpub
                                )

                        if not sig_valid:
                            outcome = "DENY"
                            reason_code = "INVALID_HUMAN_REVIEW_SIGNATURE"
                            rationale = (
                                f"CIAF-07 human reviewer signature verification failed: {sig_err}"
                            )
                            escalation_block = {
                                "required": True,
                                "status": "REJECTED",
                                "reviewer_id": human_review.reviewer_id,
                                "review_rationale": human_review.rationale,
                                "reviewed_at": reviewed_ts,
                                "reviewer_signature": human_review.reviewer_signature,
                            }
                        else:
                            outcome = "ALLOW"
                            reason_code = "ESCALATED_HUMAN_APPROVED"
                            rationale = (
                                f"Escalated proposal '{proposal_id}' approved and signed by "
                                f"authorized reviewer '{human_review.reviewer_id}'."
                            )
                            escalation_block = {
                                "required": True,
                                "status": "APPROVED",
                                "reviewer_id": human_review.reviewer_id,
                                "review_rationale": human_review.rationale,
                                "reviewed_at": reviewed_ts,
                                "reviewer_signature": copy.deepcopy(
                                    human_review.reviewer_signature
                                ),
                            }
            else:
                outcome = "ALLOW"
                if (
                    beneficiary in ctx.delegation.inspection_watchlist_beneficiaries
                    and compliance_inspection is not None
                    and compliance_inspection.cleared
                ):
                    reason_code = "INSPECTION_CLEARED"
                    rationale = (
                        f"Compliance inspection '{compliance_inspection.inspection_ref}' cleared "
                        f"by '{compliance_inspection.inspector_id}'; within delegated scope."
                    )
                else:
                    reason_code = "WITHIN_DELEGATED_AUTHORITY"
                    rationale = (
                        f"Proposed action '{tool_name}' satisfies delegated scope and "
                        f"pinned policy '{ctx.policy.policy_id}'."
                    )
        except Exception as exc:  # pragma: no cover - defensive fail-closed invariant
            outcome = "DENY"
            reason_code = "GATEWAY_INTERNAL_FAIL_CLOSED"
            rationale = f"Gateway fail-closed on internal evaluation error: {type(exc).__name__}"

        execution_grant: dict[str, Any] | None = None
        if outcome == "ALLOW":
            committed_amt = (
                int(params_copy["amount_minor_units"])
                if isinstance(params_copy.get("amount_minor_units"), int)
                and not isinstance(params_copy.get("amount_minor_units"), bool)
                else 0
            )
            self._grant_history_by_agent.setdefault(agent_id, []).append(
                (eval_dt, committed_amt)
            )
            expires_dt = eval_dt + timedelta(seconds=ttl_seconds)
            unsigned_grant: dict[str, Any] = {
                "grant_id": f"grant-{uuid.uuid4().hex[:16]}",
                "nonce": secrets.token_hex(16),
                "issued_at": eval_ts,
                "expires_at": utc_now_iso(expires_dt),
                "ttl_seconds": ttl_seconds,
                "target_service": target_service,
                "bound_agent_id": agent_id,
                "bound_tool_name": tool_name,
                "bound_request_digest": req_digest,
                "bound_policy_digest": ctx.policy.policy_digest,
                "bound_authorization_claim_id": claim_id,
            }
            grant_sig = sign_jcs_object(unsigned_grant, self._gateway_key)
            execution_grant = {
                **unsigned_grant,
                "gateway_grant_signature": grant_sig,
            }

        req_currency = str(params_copy.get("currency", ""))
        snap_currency = (
            req_currency
            if (req_currency and req_currency in ctx.delegation.allowed_currencies)
            else (
                ctx.delegation.allowed_currencies[0]
                if ctx.delegation.allowed_currencies
                else None
            )
        )

        unsigned_claim: dict[str, Any] = {
            "schema_version": "0.1.0",
            "claim_type": "AUTHORIZATION_CLAIM",
            "claim_id": claim_id,
            "sequence_number": seq_num,
            "previous_receipt_digest": prev_digest,
            "timestamp": eval_ts,
            "gateway_id": self.gateway_id,
            "subject": {
                "agent_id": ctx.agent.agent_id,
                "use_case_id": ctx.use_case.use_case_id,
                "business_purpose": ctx.use_case.business_purpose,
                "accountable_owner": ctx.use_case.accountable_owner,
            },
            "authority_context": {
                "delegation_id": ctx.delegation.delegation_id,
                "authority_status": effective_status,
                "policy_id": ctx.policy.policy_id,
                "policy_version": ctx.policy.policy_version,
                "policy_digest": ctx.policy.policy_digest,
                "delegated_scope_snapshot": {
                    "accountable_owner": ctx.use_case.accountable_owner,
                    "allowed_tools": list(ctx.delegation.allowed_tools),
                    "max_auto_amount_minor_units": ctx.delegation.autonomous_max_amount,
                    "escalation_max_amount_minor_units": ctx.delegation.escalation_max_amount,
                    "currency": snap_currency,
                    "revoked": effective_status == "REVOKED",
                },
            },
            "proposed_action": {
                "proposal_id": proposal_id,
                "tool_name": tool_name,
                "operation": operation,
                "parameters": params_copy,
                "request_digest": req_digest,
            },
            "decision": {
                "outcome": outcome,
                "reason_code": reason_code,
                "rationale": rationale,
                "evaluated_controls": evaluated_controls,
            },
            "human_escalation": escalation_block,
            "execution_grant": execution_grant,
        }

        signed_claim = sign_claim_envelope(unsigned_claim, self._gateway_key)
        return self._ledger.append(workflow_trace_id, signed_claim)
