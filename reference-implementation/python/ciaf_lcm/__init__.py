# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""CIAF-LCM v0.1 Python Reference Implementation (`ciaf_lcm`)."""

from .canonical import (
    canonicalize_jcs,
    canonicalize_jcs_str,
    compute_request_digest,
    jcs_hmac_sha256,
    jcs_salted_commitment,
    jcs_sha256,
)
from .capsule import LazyCapsuleMaterializer, ProvenanceEventLedger
from .crypto import (
    Ed25519Keypair,
    b64u_decode,
    b64u_encode,
    extract_okp_public_key_b64u,
    sign_claim_envelope,
    sign_jcs_object,
    verify_jcs_signature,
)
from .executor import ExecutionService
from .gateway import (
    ComplianceInspectionDecision,
    HumanReviewDecision,
    PreExecutionGovernanceGateway,
    build_human_review_payload,
)
from .registry import (
    AgentIdentityRecord,
    AuthorityPolicyRegistry,
    DelegationRecord,
    PolicyRecord,
    UseCaseRecord,
)
from .verifier import IndependentVerifier

__version__ = "0.1.1"

__all__ = [
    "__version__",
    "AgentIdentityRecord",
    "AuthorityPolicyRegistry",
    "ComplianceInspectionDecision",
    "DelegationRecord",
    "Ed25519Keypair",
    "ExecutionService",
    "HumanReviewDecision",
    "IndependentVerifier",
    "LazyCapsuleMaterializer",
    "PolicyRecord",
    "PreExecutionGovernanceGateway",
    "ProvenanceEventLedger",
    "UseCaseRecord",
    "b64u_decode",
    "b64u_encode",
    "build_human_review_payload",
    "canonicalize_jcs",
    "canonicalize_jcs_str",
    "compute_request_digest",
    "extract_okp_public_key_b64u",
    "jcs_hmac_sha256",
    "jcs_salted_commitment",
    "jcs_sha256",
    "sign_claim_envelope",
    "sign_jcs_object",
    "verify_jcs_signature",
]
