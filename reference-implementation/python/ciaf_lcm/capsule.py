# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Append-only Provenance Event Ledger and Lazy Capsule Materializer (CIAF-09)."""

from __future__ import annotations

import copy
import uuid
from datetime import datetime
from typing import Any

from .canonical import jcs_sha256
from .registry import PolicyRecord, utc_now_iso


class ProvenanceEventLedger:
    """Append-only hash-linked provenance store partitioned by `workflow_trace_id`.

    Captures low-latency signed claims at runtime and supports lazy on-demand
    materialization of self-contained `AuditCapsule` bundles (CIAF-09).
    """

    def __init__(self) -> None:
        self._streams: dict[str, list[dict[str, Any]]] = {}

    def next_chain_position(self, workflow_trace_id: str) -> tuple[int, str | None]:
        """Return `(sequence_number, previous_receipt_digest)` for the next receipt."""
        chain = self._streams.get(workflow_trace_id, [])
        if not chain:
            return 0, None
        return len(chain), chain[-1]["claim_digest"]

    def append(self, workflow_trace_id: str, signed_claim: dict[str, Any]) -> dict[str, Any]:
        """Append a signed claim after verifying sequence and `previous_receipt_digest`."""
        expected_seq, expected_prev = self.next_chain_position(workflow_trace_id)
        if signed_claim.get("sequence_number") != expected_seq:
            raise ValueError(
                f"Sequence mismatch for {workflow_trace_id}: "
                f"expected {expected_seq}, got {signed_claim.get('sequence_number')}"
            )
        if signed_claim.get("previous_receipt_digest") != expected_prev:
            raise ValueError(
                f"Hash-chain previous_receipt_digest mismatch for {workflow_trace_id}: "
                f"expected {expected_prev}, got {signed_claim.get('previous_receipt_digest')}"
            )
        stored = copy.deepcopy(signed_claim)
        self._streams.setdefault(workflow_trace_id, []).append(stored)
        return copy.deepcopy(stored)

    def get_stream(self, workflow_trace_id: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self._streams.get(workflow_trace_id, []))


class LazyCapsuleMaterializer:
    """On-demand materializer assembling `AuditCapsule` packages from ledger streams."""

    def __init__(self, ledger: ProvenanceEventLedger) -> None:
        self._ledger = ledger

    def materialize(
        self,
        workflow_trace_id: str,
        policy: PolicyRecord,
        public_key_manifest: list[dict[str, Any]],
        capsule_id: str | None = None,
        now: datetime | None = None,
        scitt_receipt: dict[str, str] | None = None,
        authority_attestation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stream = self._ledger.get_stream(workflow_trace_id)
        if not stream:
            raise ValueError(f"No provenance receipts recorded for trace {workflow_trace_id}")

        authz_claims = [
            c for c in stream if c.get("claim_type") == "AUTHORIZATION_CLAIM"
        ]
        exec_claims = [
            c for c in stream if c.get("claim_type") == "EXECUTION_CLAIM"
        ]
        ordered_digests = [c["claim_digest"] for c in stream]

        if scitt_receipt is not None:
            scitt_block: dict[str, Any] = {
                "status": "REGISTERED_INCLUSION_RECEIPT_ATTACHED",
                "transparency_service_id": scitt_receipt["transparency_service_id"],
                "cose_sign1_statement_digest": scitt_receipt["cose_sign1_statement_digest"],
                "inclusion_receipt_b64u": scitt_receipt["inclusion_receipt_b64u"],
                "completeness_guarantee": (
                    "COSE receipt (RFC 9942) from IETF SCITT (RFC 9943) Transparency "
                    "Service provides externally verifiable append-only completeness "
                    "and independent registration timestamping."
                ),
            }
        else:
            scitt_block = {
                "status": "NOT_REGISTERED_LOCAL_CHAIN_ONLY",
                "transparency_service_id": None,
                "cose_sign1_statement_digest": None,
                "inclusion_receipt_b64u": None,
                "completeness_guarantee": (
                    "Local RFC 8785 SHA-256 hash-chaining detects mid-chain tampering, "
                    "deletion, or reordering within a trace; external log-tail omission, "
                    "whole-trace completeness, and independent trusted timestamp anchoring "
                    "require an RFC 3161 TSA token or IETF SCITT (RFC 9943 / RFC 9942) "
                    "Transparency Service receipt."
                ),
            }

        unsigned_capsule: dict[str, Any] = {
            "schema_version": "0.1.0",
            "capsule_type": "CIAF_LCM_AUDIT_CAPSULE",
            "capsule_id": capsule_id or f"caps-{uuid.uuid4().hex[:16]}",
            "materialized_at": utc_now_iso(now),
            "workflow_trace_id": workflow_trace_id,
            "policy_snapshot": {
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "policy_document": copy.deepcopy(policy.policy_document),
                "policy_digest": policy.policy_digest,
            },
            "public_key_manifest": copy.deepcopy(public_key_manifest),
            "hash_chain": {
                "algorithm": "SHA-256",
                "canonicalization": "RFC8785-JCS",
                "genesis_receipt_digest": ordered_digests[0],
                "tip_receipt_digest": ordered_digests[-1],
                "receipt_count": len(ordered_digests),
                "ordered_receipt_digests": ordered_digests,
            },
            "authorization_claims": authz_claims,
            "execution_claims": exec_claims,
            "scitt_transparency": scitt_block,
        }
        if authority_attestation is not None:
            unsigned_capsule["authority_attestation"] = copy.deepcopy(authority_attestation)

        capsule_digest = jcs_sha256(unsigned_capsule)
        return {**unsigned_capsule, "capsule_digest": capsule_digest}
