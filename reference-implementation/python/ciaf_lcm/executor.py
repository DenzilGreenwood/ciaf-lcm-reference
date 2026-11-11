# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Independently keyed Execution Service enforcing CIAF-08 and CIAF-11."""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .canonical import compute_request_digest, jcs_sha256
from .capsule import ProvenanceEventLedger
from .crypto import Ed25519Keypair, sign_claim_envelope, verify_jcs_signature
from .registry import utc_now_iso


def _parse_iso_utc(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


class ExecutionService:
    """Downstream Execution Service hosting `payments.create` (CIAF-08, CIAF-11).

    Security Invariants:
    - Holds its own independent Ed25519 `executor_key` (`role == EXECUTION_SERVICE`).
    - Never possesses access to the Gateway's private key; accepts ONLY Gateway public keys.
    - Rejects direct/unauthenticated calls, forged grants, expired TTLs, replayed nonces,
      and TOCTOU payload mutations prior to invoking `payments.create`.
    """

    def __init__(
        self,
        executor_id: str,
        executor_key: Ed25519Keypair,
        trusted_gateway_public_keys: dict[str, str],
        ledger: ProvenanceEventLedger,
        pinned_policy_digests: set[str] | None = None,
        max_accepted_ttl_seconds: int = 30,
        is_agent_revoked: Callable[[str], bool] | None = None,
    ) -> None:
        if executor_key.role != "EXECUTION_SERVICE":
            raise ValueError("Executor keypair MUST have role 'EXECUTION_SERVICE'.")
        if max_accepted_ttl_seconds < 1 or max_accepted_ttl_seconds > 300:
            raise ValueError("max_accepted_ttl_seconds must be within 1..300 seconds.")
        for gw_kid, gw_pub in trusted_gateway_public_keys.items():
            if gw_pub == executor_key.public_key_b64u or gw_kid == executor_key.key_id:
                raise ValueError(
                    "Dual-Key Trust Boundary Violation: Executor and Gateway MUST NOT "
                    "share key material or key identifiers."
                )

        self.executor_id = executor_id
        self._executor_key = executor_key
        self._trusted_gateway_keys = dict(trusted_gateway_public_keys)
        self._ledger = ledger
        self._pinned_policy_digests = (
            set(pinned_policy_digests) if pinned_policy_digests is not None else None
        )
        self.max_accepted_ttl_seconds = max_accepted_ttl_seconds
        self._is_agent_revoked = is_agent_revoked
        self._consumed_nonces: set[str] = set()
        self._committed_payments: list[dict[str, Any]] = []

    @property
    def public_key_manifest_entry(self) -> dict[str, Any]:
        return self._executor_key.to_manifest_entry()

    @property
    def committed_payments(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._committed_payments)

    def execute(
        self,
        *,
        workflow_trace_id: str,
        proposal_id: str,
        agent_id: str,
        tool_name: str,
        operation: str,
        parameters: dict[str, Any],
        execution_grant: dict[str, Any] | None = None,
        authorization_claim_id: str | None = None,
        authorization_claim_digest: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Validate Gateway grant and execute `payments.create` only on full CIAF-08 pass."""
        exec_dt = (now if now is not None else datetime.now(timezone.utc)).astimezone(
            timezone.utc
        )
        exec_ts = utc_now_iso(exec_dt)
        params_copy = copy.deepcopy(parameters)
        observed_digest = compute_request_digest(tool_name, operation, params_copy)

        # 1. Direct Gateway Bypass check (CIAF-08, CIAF-11)
        if (
            execution_grant is None
            or authorization_claim_id is None
            or authorization_claim_digest is None
        ):
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=execution_grant.get("grant_id") if execution_grant else None,
                consumed_nonce=None,
                policy_digest=(
                    execution_grant.get("bound_policy_digest") if execution_grant else None
                ),
                grant_status="MISSING_BYPASS_ATTEMPT",
                control_id="CIAF-11",
                exception_code="DIRECT_GATEWAY_BYPASS",
                detail=(
                    "Direct tool invocation rejected: missing Pre-Execution Governance "
                    "Gateway grant or authorization claim binding."
                ),
            )

        grant_id = str(execution_grant.get("grant_id", ""))
        nonce = str(execution_grant.get("nonce", ""))
        bound_policy_digest = str(execution_grant.get("bound_policy_digest", ""))

        # 2. Verify Gateway Ed25519 signature over unsigned grant
        grant_sig = execution_grant.get("gateway_grant_signature")
        unsigned_grant = {
            k: v for k, v in execution_grant.items() if k != "gateway_grant_signature"
        }
        gw_kid = grant_sig.get("key_id") if isinstance(grant_sig, dict) else None
        gw_pub = self._trusted_gateway_keys.get(str(gw_kid)) if gw_kid else None
        if not isinstance(grant_sig, dict) or gw_pub is None:
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id or None,
                consumed_nonce=None,
                policy_digest=bound_policy_digest or None,
                grant_status="INVALID_SIGNATURE",
                control_id="CIAF-08",
                exception_code="GRANT_SIGNATURE_INVALID",
                detail=f"Untrusted or missing Gateway signing key_id '{gw_kid}'.",
            )

        sig_ok, sig_msg = verify_jcs_signature(unsigned_grant, grant_sig, gw_pub)
        if not sig_ok:
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id or None,
                consumed_nonce=None,
                policy_digest=bound_policy_digest or None,
                grant_status="INVALID_SIGNATURE",
                control_id="CIAF-08",
                exception_code="GRANT_SIGNATURE_INVALID",
                detail=f"Gateway grant Ed25519 verification failed: {sig_msg}",
            )

        # 3. Single-use nonce anti-replay check (CIAF-08)
        if nonce in self._consumed_nonces:
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id,
                consumed_nonce=None,
                policy_digest=bound_policy_digest,
                grant_status="NONCE_REPLAYED",
                control_id="CIAF-08",
                exception_code="GRANT_NONCE_REPLAY",
                detail=f"Single-use grant nonce '{nonce}' has already been consumed.",
            )

        # 4. Short-lived TTL & timestamp validity check (CIAF-08)
        issued_dt = _parse_iso_utc(execution_grant["issued_at"])
        expires_dt = _parse_iso_utc(execution_grant["expires_at"])
        ttl_sec = int(execution_grant.get("ttl_seconds", 0))
        if (
            ttl_sec > self.max_accepted_ttl_seconds
            or exec_dt > expires_dt
            or exec_dt < issued_dt
        ):
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id,
                consumed_nonce=None,
                policy_digest=bound_policy_digest,
                grant_status="EXPIRED_TTL",
                control_id="CIAF-08",
                exception_code="GRANT_TTL_EXPIRED",
                detail=(
                    f"Grant '{grant_id}' expired or outside TTL window "
                    f"(now={exec_ts}, expires_at={execution_grant['expires_at']})."
                ),
            )

        # 5. Caller, target service, tool, and claim ID bindings
        if execution_grant.get("bound_agent_id") != agent_id:
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id,
                consumed_nonce=None,
                policy_digest=bound_policy_digest,
                grant_status="AGENT_MISMATCH",
                control_id="CIAF-08",
                exception_code="UNAUTHORIZED_CALLER_OR_TOOL",
                detail="Presenting agent_id does not match grant bound_agent_id.",
            )

        if (
            execution_grant.get("bound_tool_name") != tool_name
            or execution_grant.get("target_service") != self.executor_id
            or execution_grant.get("bound_authorization_claim_id") != authorization_claim_id
        ):
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id,
                consumed_nonce=None,
                policy_digest=bound_policy_digest,
                grant_status="TOOL_MISMATCH",
                control_id="CIAF-08",
                exception_code="UNAUTHORIZED_CALLER_OR_TOOL",
                detail="Grant tool, target_service, or authorization_claim_id mismatch.",
            )

        # 6. Policy digest binding check
        if (
            self._pinned_policy_digests is not None
            and bound_policy_digest not in self._pinned_policy_digests
        ):
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id,
                consumed_nonce=None,
                policy_digest=bound_policy_digest,
                grant_status="POLICY_DIGEST_MISMATCH",
                control_id="CIAF-08",
                exception_code="POLICY_DIGEST_MISMATCH",
                detail=f"Grant bound_policy_digest '{bound_policy_digest}' is not trusted.",
            )

        # 7. TOCTOU / Request Digest equality check (CIAF-08)
        if observed_digest != execution_grant.get("bound_request_digest"):
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id,
                consumed_nonce=None,
                policy_digest=bound_policy_digest,
                grant_status="REQUEST_DIGEST_MISMATCH",
                control_id="CIAF-08",
                exception_code="TOCTOU_PAYLOAD_TAMPER",
                detail=(
                    f"TOCTOU payload mutation detected: observed request_digest "
                    f"{observed_digest} != grant bound_request_digest "
                    f"{execution_grant.get('bound_request_digest')}."
                ),
            )

        # 8. Synchronous zero-window revocation feed check for in-flight grants (CIAF-12)
        if self._is_agent_revoked is not None and self._is_agent_revoked(agent_id):
            return self._emit_security_exception_receipt(
                workflow_trace_id=workflow_trace_id,
                timestamp=exec_ts,
                proposal_id=proposal_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=params_copy,
                observed_digest=observed_digest,
                authorization_claim_id=authorization_claim_id,
                authorization_claim_digest=authorization_claim_digest,
                grant_id=grant_id,
                consumed_nonce=None,
                policy_digest=bound_policy_digest,
                grant_status="AUTHORITY_REVOKED_IN_FLIGHT",
                control_id="CIAF-12",
                exception_code="AUTHORITY_REVOKED_IN_FLIGHT",
                detail=(
                    f"In-flight grant '{grant_id}' rejected prior to side effects: "
                    f"agent '{agent_id}' authority was synchronously revoked during TTL window."
                ),
            )

        # All CIAF-08 & CIAF-12 checks passed: consume single-use nonce and execute side effect
        self._consumed_nonces.add(nonce)
        result_summary = self._invoke_tool_side_effect(
            tool_name, operation, proposal_id, params_copy, exec_ts
        )
        result_digest = jcs_sha256(result_summary)

        seq_num, prev_digest = self._ledger.next_chain_position(workflow_trace_id)
        unsigned_exec: dict[str, Any] = {
            "schema_version": "0.1.0",
            "claim_type": "EXECUTION_CLAIM",
            "claim_id": f"exec-{uuid.uuid4().hex[:16]}",
            "sequence_number": seq_num,
            "previous_receipt_digest": prev_digest,
            "timestamp": exec_ts,
            "executor_id": self.executor_id,
            "authorization_binding": {
                "authorization_claim_id": authorization_claim_id,
                "authorization_claim_digest": authorization_claim_digest,
                "grant_id": grant_id,
                "consumed_nonce": nonce,
                "policy_digest": bound_policy_digest,
                "grant_verification_status": "VERIFIED",
            },
            "action_request": {
                "proposal_id": proposal_id,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "operation": operation,
                "parameters": params_copy,
                "observed_request_digest": observed_digest,
            },
            "execution": {
                "attempted": True,
                "executed": True,
                "status": "SUCCEEDED",
                "side_effects_committed": True,
                "result_digest": result_digest,
                "result_summary": result_summary,
            },
            "security_exception": None,
        }
        signed_exec = sign_claim_envelope(unsigned_exec, self._executor_key)
        return self._ledger.append(workflow_trace_id, signed_exec)

    def attest_gateway_block(
        self,
        *,
        workflow_trace_id: str,
        authorization_claim: dict[str, Any],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Emit an optional signed non-execution receipt confirming zero side effects on Gateway block.

        Note: In CIAF-LCM v0.1, when a request is blocked at the Gateway (`DENY`, `ESCALATE`,
        or `INSPECT`) and never transmitted to the Execution Service, an `AuditCapsule` with
        `execution_claims: []` is normatively valid. This helper is optional for co-monitored pipelines.
        """
        if authorization_claim.get("decision", {}).get("outcome") == "ALLOW":
            raise ValueError("Cannot attest gateway block on an ALLOW AuthorizationClaim.")
        exec_ts = utc_now_iso(now)
        proposed = authorization_claim["proposed_action"]
        params_copy = copy.deepcopy(proposed["parameters"])
        observed_digest = compute_request_digest(
            proposed["tool_name"], proposed["operation"], params_copy
        )
        seq_num, prev_digest = self._ledger.next_chain_position(workflow_trace_id)

        unsigned_exec: dict[str, Any] = {
            "schema_version": "0.1.0",
            "claim_type": "EXECUTION_CLAIM",
            "claim_id": f"exec-{uuid.uuid4().hex[:16]}",
            "sequence_number": seq_num,
            "previous_receipt_digest": prev_digest,
            "timestamp": exec_ts,
            "executor_id": self.executor_id,
            "authorization_binding": {
                "authorization_claim_id": authorization_claim["claim_id"],
                "authorization_claim_digest": authorization_claim["claim_digest"],
                "grant_id": None,
                "consumed_nonce": None,
                "policy_digest": authorization_claim["authority_context"]["policy_digest"],
                "grant_verification_status": "NOT_PRESENTED_PRE_BLOCKED",
            },
            "action_request": {
                "proposal_id": proposed["proposal_id"],
                "agent_id": authorization_claim["subject"]["agent_id"],
                "tool_name": proposed["tool_name"],
                "operation": proposed["operation"],
                "parameters": params_copy,
                "observed_request_digest": observed_digest,
            },
            "execution": {
                "attempted": False,
                "executed": False,
                "status": "NOT_ATTEMPTED_GATEWAY_BLOCKED",
                "side_effects_committed": False,
                "result_digest": None,
                "result_summary": None,
            },
            "security_exception": None,
        }
        signed_exec = sign_claim_envelope(unsigned_exec, self._executor_key)
        return self._ledger.append(workflow_trace_id, signed_exec)

    def _invoke_tool_side_effect(
        self,
        tool_name: str,
        operation: str,
        proposal_id: str,
        parameters: dict[str, Any],
        settled_at: str,
    ) -> dict[str, Any]:
        if tool_name == "payments.create":
            return self._invoke_payments_create(proposal_id, parameters, settled_at)
        return {
            "execution_record_id": f"act-{uuid.uuid4().hex[:12]}",
            "proposal_id": proposal_id,
            "tool_name": tool_name,
            "operation": operation,
            "status": "COMMITTED",
            "committed_at": settled_at,
        }

    def _invoke_payments_create(
        self,
        proposal_id: str,
        parameters: dict[str, Any],
        settled_at: str,
    ) -> dict[str, Any]:
        if (
            "amount_minor_units" not in parameters
            or "currency" not in parameters
            or "minor_unit_scale" not in parameters
        ):
            raise ValueError(
                "payments.create requires 'amount_minor_units', 'currency', and 'minor_unit_scale'."
            )
        amt = parameters["amount_minor_units"]
        scale = parameters["minor_unit_scale"]
        if (
            isinstance(amt, (float, bool))
            or not isinstance(amt, int)
            or isinstance(scale, (float, bool))
            or not isinstance(scale, int)
        ):
            raise ValueError("payments.create requires exact integer minor monetary units.")
        payment_record = {
            "payment_id": f"pay-{uuid.uuid4().hex[:12]}",
            "proposal_id": proposal_id,
            "settled_amount_minor_units": amt,
            "currency": parameters["currency"],
            "minor_unit_scale": scale,
            "beneficiary": parameters.get("beneficiary", "unspecified"),
            "invoice_id": parameters.get("invoice_id", "unspecified"),
            "settlement_status": "SETTLED",
            "settled_at": settled_at,
        }
        self._committed_payments.append(copy.deepcopy(payment_record))
        return payment_record

    def _emit_security_exception_receipt(
        self,
        *,
        workflow_trace_id: str,
        timestamp: str,
        proposal_id: str,
        agent_id: str,
        tool_name: str,
        operation: str,
        parameters: dict[str, Any],
        observed_digest: str,
        authorization_claim_id: str | None,
        authorization_claim_digest: str | None,
        grant_id: str | None,
        consumed_nonce: str | None,
        policy_digest: str | None,
        grant_status: str,
        control_id: str,
        exception_code: str,
        detail: str,
    ) -> dict[str, Any]:
        seq_num, prev_digest = self._ledger.next_chain_position(workflow_trace_id)
        unsigned_exec: dict[str, Any] = {
            "schema_version": "0.1.0",
            "claim_type": "EXECUTION_CLAIM",
            "claim_id": f"exec-{uuid.uuid4().hex[:16]}",
            "sequence_number": seq_num,
            "previous_receipt_digest": prev_digest,
            "timestamp": timestamp,
            "executor_id": self.executor_id,
            "authorization_binding": {
                "authorization_claim_id": authorization_claim_id,
                "authorization_claim_digest": authorization_claim_digest,
                "grant_id": grant_id,
                "consumed_nonce": consumed_nonce,
                "policy_digest": policy_digest,
                "grant_verification_status": grant_status,
            },
            "action_request": {
                "proposal_id": proposal_id,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "operation": operation,
                "parameters": parameters,
                "observed_request_digest": observed_digest,
            },
            "execution": {
                "attempted": False,
                "executed": False,
                "status": "REJECTED_SECURITY_EXCEPTION",
                "side_effects_committed": False,
                "result_digest": None,
                "result_summary": None,
            },
            "security_exception": {
                "detected": True,
                "control_id": control_id,
                "exception_code": exception_code,
                "severity": "CRITICAL",
                "detail": detail,
            },
        }
        signed_exec = sign_claim_envelope(unsigned_exec, self._executor_key)
        return self._ledger.append(workflow_trace_id, signed_exec)

