# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Authority & Policy Registry implementing CIAF-01 through CIAF-05 and CIAF-12."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from .canonical import jcs_sha256
from .crypto import Ed25519Keypair, sign_jcs_object

AuthorityStatus = Literal["ACTIVE", "REVOKED", "SUSPENDED"]


def utc_now_iso(now: datetime | None = None) -> str:
    dt = now if now is not None else datetime.now(timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class UseCaseRecord:
    """CIAF-01 (Use Case & Business Purpose) and CIAF-02 (Accountable Human Owner)."""

    use_case_id: str
    business_purpose: str
    accountable_owner: str
    risk_tier: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    status: Literal["ACTIVE", "SUSPENDED", "RETIRED"] = "ACTIVE"


@dataclass
class AgentIdentityRecord:
    """CIAF-03 (Cryptographic Agent Identity & Workload Binding)."""

    agent_id: str
    use_case_id: str
    workload_id: str
    model_profile: str
    status: AuthorityStatus = "ACTIVE"


@dataclass(frozen=True)
class PolicyRecord:
    """CIAF-05 (Versioned Policy Definition & RFC 8785 Digest Pinning)."""

    policy_id: str
    policy_version: str
    policy_document: dict[str, Any]
    policy_digest: str

    @classmethod
    def create(
        cls,
        policy_id: str,
        policy_version: str,
        policy_document: dict[str, Any],
    ) -> PolicyRecord:
        doc_copy = copy.deepcopy(policy_document)
        return cls(
            policy_id=policy_id,
            policy_version=policy_version,
            policy_document=doc_copy,
            policy_digest=jcs_sha256(doc_copy),
        )


@dataclass
class DelegationRecord:
    """Domain-neutral CIAF-04 Scoped Delegation & CIAF-12 Revocation Record.

    Supports both financial workflows (exact integer minor-unit/unit ceilings + rolling
    cumulative velocity caps against structuring) and non-financial clinical/gaming/ops
    workflows (`escalate_on_tools`, `scope_constraints`).
    """

    delegation_id: str
    agent_id: str
    policy_id: str
    allowed_tools: tuple[str, ...]
    autonomous_max_amount: int | None = None
    escalation_max_amount: int | None = None
    rolling_window_max_amount: int | None = None
    rolling_window_max_count: int | None = None
    rolling_window_seconds: int = 86400
    allowed_currencies: tuple[str, ...] = ()
    allowed_beneficiaries: tuple[str, ...] | None = None
    inspection_watchlist_beneficiaries: tuple[str, ...] = ()
    authorized_human_reviewers: tuple[str, ...] = ()
    authorized_compliance_inspectors: tuple[str, ...] = ()
    escalate_on_tools: tuple[str, ...] = ()
    scope_constraints: dict[str, Any] = field(default_factory=dict)
    status: AuthorityStatus = "ACTIVE"
    revocation_reason: str | None = None
    revoked_at: str | None = None


@dataclass(frozen=True)
class ResolvedAuthorityContext:
    use_case: UseCaseRecord
    agent: AgentIdentityRecord
    delegation: DelegationRecord
    policy: PolicyRecord


class AuthorityPolicyRegistry:
    """Normative Authority & Policy Registry for CIAF-LCM v0.1 (`CIAF-01..05`, `CIAF-12`)."""

    def __init__(
        self,
        registry_id: str = "ciaf-registry-prod-01",
        registry_key: Ed25519Keypair | None = None,
    ) -> None:
        if registry_key is not None and registry_key.role != "REGISTRY_AUTHORITY":
            raise ValueError("registry_key MUST have role 'REGISTRY_AUTHORITY'.")
        self.registry_id = registry_id
        self._registry_key = registry_key
        self._use_cases: dict[str, UseCaseRecord] = {}
        self._agents: dict[str, AgentIdentityRecord] = {}
        self._policies: dict[str, PolicyRecord] = {}
        self._delegations_by_agent: dict[str, DelegationRecord] = {}

    def register_use_case(self, record: UseCaseRecord) -> UseCaseRecord:
        if not record.accountable_owner.strip():
            raise ValueError("CIAF-02 violation: accountable_owner is required.")
        self._use_cases[record.use_case_id] = record
        return record

    def register_agent(self, record: AgentIdentityRecord) -> AgentIdentityRecord:
        if record.use_case_id not in self._use_cases:
            raise KeyError(f"Unknown use_case_id: {record.use_case_id}")
        self._agents[record.agent_id] = record
        return record

    def register_policy(
        self,
        policy_id: str,
        policy_version: str,
        policy_document: dict[str, Any],
    ) -> PolicyRecord:
        record = PolicyRecord.create(policy_id, policy_version, policy_document)
        self._policies[policy_id] = record
        return record

    def register_delegation(self, record: DelegationRecord) -> DelegationRecord:
        if record.agent_id not in self._agents:
            raise KeyError(f"Unknown agent_id: {record.agent_id}")
        if record.policy_id not in self._policies:
            raise KeyError(f"Unknown policy_id: {record.policy_id}")
        if isinstance(record.autonomous_max_amount, float) or isinstance(
            record.escalation_max_amount, float
        ):
            raise ValueError(
                "Monetary delegation ceilings MUST be exact integers (minor units or whole units), never IEEE-754 floats."
            )
        if (
            record.autonomous_max_amount is not None
            and record.escalation_max_amount is not None
            and record.autonomous_max_amount > record.escalation_max_amount
        ):
            raise ValueError("autonomous_max_amount cannot exceed escalation_max_amount.")
        self._delegations_by_agent[record.agent_id] = record
        return record

    def revoke_agent_authority(
        self,
        agent_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> DelegationRecord:
        """CIAF-12 administrative/automated revocation of agent identity and delegation."""
        if agent_id not in self._agents or agent_id not in self._delegations_by_agent:
            raise KeyError(f"Cannot revoke unregistered agent: {agent_id}")
        ts = utc_now_iso(now)
        self._agents[agent_id].status = "REVOKED"
        delegation = self._delegations_by_agent[agent_id]
        delegation.status = "REVOKED"
        delegation.revocation_reason = reason
        delegation.revoked_at = ts
        return delegation

    def is_agent_revoked(self, agent_id: str) -> bool:
        """Synchronous revocation feed queryable by ExecutionService for zero-window enforcement."""
        agent = self._agents.get(agent_id)
        delegation = self._delegations_by_agent.get(agent_id)
        if agent is None or delegation is None:
            return True
        return agent.status != "ACTIVE" or delegation.status != "ACTIVE"

    def sign_authority_attestation(
        self,
        agent_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Export a REGISTRY_AUTHORITY-signed snapshot of use case, owner, agent, and delegation."""
        if self._registry_key is None:
            return None
        ctx = self.resolve_agent_context(agent_id)
        unsigned: dict[str, Any] = {
            "registry_id": self.registry_id,
            "attested_at": utc_now_iso(now),
            "use_case": {
                "use_case_id": ctx.use_case.use_case_id,
                "business_purpose": ctx.use_case.business_purpose,
                "accountable_owner": ctx.use_case.accountable_owner,
                "risk_tier": ctx.use_case.risk_tier,
                "status": ctx.use_case.status,
            },
            "agent": {
                "agent_id": ctx.agent.agent_id,
                "workload_id": ctx.agent.workload_id,
                "model_profile": ctx.agent.model_profile,
                "status": ctx.agent.status,
            },
            "delegation": {
                "delegation_id": ctx.delegation.delegation_id,
                "policy_id": ctx.delegation.policy_id,
                "allowed_tools": list(ctx.delegation.allowed_tools),
                "autonomous_max_amount": ctx.delegation.autonomous_max_amount,
                "escalation_max_amount": ctx.delegation.escalation_max_amount,
                "rolling_window_max_amount": ctx.delegation.rolling_window_max_amount,
                "rolling_window_max_count": ctx.delegation.rolling_window_max_count,
                "rolling_window_seconds": ctx.delegation.rolling_window_seconds,
                "allowed_currencies": list(ctx.delegation.allowed_currencies),
                "scope_constraints": copy.deepcopy(ctx.delegation.scope_constraints),
                "status": ctx.delegation.status,
                "revocation_reason": ctx.delegation.revocation_reason,
                "revoked_at": ctx.delegation.revoked_at,
            },
        }
        sig = sign_jcs_object(unsigned, self._registry_key)
        with_sig = {**unsigned, "signature": sig}
        return {**with_sig, "attestation_digest": jcs_sha256(with_sig)}

    def resolve_agent_context(self, agent_id: str) -> ResolvedAuthorityContext:
        if agent_id not in self._agents:
            raise KeyError(f"Unregistered agent_id: {agent_id}")
        agent = self._agents[agent_id]
        use_case = self._use_cases[agent.use_case_id]
        delegation = self._delegations_by_agent[agent_id]
        policy = self._policies[delegation.policy_id]
        return ResolvedAuthorityContext(
            use_case=use_case,
            agent=agent,
            delegation=delegation,
            policy=policy,
        )

    def get_policy(self, policy_id: str) -> PolicyRecord:
        return self._policies[policy_id]
