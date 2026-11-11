# Copyright 2026 CIAF-LCM Working Group Contributors
# SPDX-License-Identifier: Apache-2.0
"""Zero-trust Independent Verifier implementing CIAF-10."""

from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .canonical import compute_request_digest, jcs_sha256
from .crypto import (
    Ed25519Keypair,
    extract_okp_public_key_b64u,
    sign_claim_envelope,
    verify_jcs_signature,
)
from .gateway import build_human_review_payload
from .registry import utc_now_iso


def _parse_iso_utc(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def default_schemas_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas"


class IndependentVerifier:
    """Stateless Assurance Verifier (CIAF-10).

    Verification Sequencing Contract:
    1. Validate the complete wire JSON (`AuditCapsule`, `AuthorizationClaim`s,
       `ExecutionClaim`s) against Draft 2020-12 JSON Schemas FIRST (requiring
       both `signature` and `claim_digest` on wire claims).
    2. Recompute `claim_digest == jcs_sha256(body_with_signature)` (stripping only
       `claim_digest`) to verify envelope integrity.
    3. Strip both `signature` and `claim_digest` to verify
       `Ed25519(canonicalize_jcs(unsigned_body))` against the role-pinned OKP JWK
       (`kty: OKP, crv: Ed25519, x: <base64url-32-bytes>`) in `trusted_keys`.
    4. Independently verify `delegated_scope_snapshot` numeric/tool/revocation limits
       on `AuthorizationClaim`s rather than trusting Gateway assertions blindly.

    Clock-Trust Note:
    Grant TTL window checks (`issued_at <= timestamp <= expires_at`) verify chronological
    consistency across issuer-asserted timestamps. Defending against clock backdating by
    a compromised Execution Service requires an independent external timestamp authority
    (RFC 3161 TSA token or IETF SCITT RFC 9943 / RFC 9942 registration receipt).
    """

    def __init__(
        self,
        verifier_id: str = "ciaf-independent-verifier-01",
        verifier_key: Ed25519Keypair | None = None,
        schemas_dir: Path | None = None,
    ) -> None:
        if verifier_key is not None and verifier_key.role != "ASSURANCE_VERIFIER":
            raise ValueError("verifier_key MUST have role 'ASSURANCE_VERIFIER'.")
        self.verifier_id = verifier_id
        self._verifier_key = verifier_key
        sdir = schemas_dir or default_schemas_dir()

        self._authz_validator = Draft202012Validator(
            json.loads((sdir / "authorization-claim.v0.1.schema.json").read_text("utf-8"))
        )
        self._exec_validator = Draft202012Validator(
            json.loads((sdir / "execution-claim.v0.1.schema.json").read_text("utf-8"))
        )
        self._assurance_validator = Draft202012Validator(
            json.loads((sdir / "assurance-claim.v0.1.schema.json").read_text("utf-8"))
        )
        self._capsule_validator = Draft202012Validator(
            json.loads((sdir / "audit-capsule.v0.1.schema.json").read_text("utf-8"))
        )

    def verify_capsule(
        self,
        capsule: dict[str, Any],
        trusted_key_manifest: list[dict[str, Any]],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        findings: list[dict[str, str]] = []
        failed_controls_set: set[str] = set()

        def fail(control_id: str, code: str, message: str) -> None:
            failed_controls_set.add(control_id)
            findings.append(
                {
                    "severity": "CRITICAL",
                    "control_id": control_id,
                    "code": code,
                    "message": message,
                }
            )

        def info(control_id: str, code: str, message: str) -> None:
            findings.append(
                {
                    "severity": "INFO",
                    "control_id": control_id,
                    "code": code,
                    "message": message,
                }
            )

        # -------------------------------------------------------------------
        # STEP 1: Complete Wire JSON Schema Validation (Draft 2020-12) FIRST
        # -------------------------------------------------------------------
        schema_ok = True
        for err in self._capsule_validator.iter_errors(capsule):
            schema_ok = False
            fail("CIAF-10", "CAPSULE_SCHEMA_INVALID", f"AuditCapsule schema error: {err.message}")

        authz_claims: list[dict[str, Any]] = capsule.get("authorization_claims", [])
        exec_claims: list[dict[str, Any]] = capsule.get("execution_claims", [])

        for idx, ac in enumerate(authz_claims):
            for err in self._authz_validator.iter_errors(ac):
                schema_ok = False
                fail(
                    "CIAF-10",
                    "AUTHZ_CLAIM_SCHEMA_INVALID",
                    f"AuthorizationClaim[{idx}] schema error: {err.message}",
                )

        for idx, ec in enumerate(exec_claims):
            for err in self._exec_validator.iter_errors(ec):
                schema_ok = False
                fail(
                    "CIAF-10",
                    "EXEC_CLAIM_SCHEMA_INVALID",
                    f"ExecutionClaim[{idx}] schema error: {err.message}",
                )

        # -------------------------------------------------------------------
        # STEP 2: Dual-Key Trust Boundary & OKP JWK Manifest Validation
        # -------------------------------------------------------------------
        trust_boundary_ok = True
        trusted_by_kid: dict[str, dict[str, Any]] = {}
        trusted_x_by_kid: dict[str, str] = {}
        pubkeys_by_role: dict[str, set[str]] = {}

        for entry in trusted_key_manifest:
            kid = str(entry.get("key_id", ""))
            role = str(entry.get("role", ""))
            try:
                pub_x = extract_okp_public_key_b64u(entry)
            except ValueError as exc:
                trust_boundary_ok = False
                fail("CIAF-10", "INVALID_TRUSTED_KEY_JWK", f"Key '{kid}' invalid JWK: {exc}")
                continue
            trusted_by_kid[kid] = entry
            trusted_x_by_kid[kid] = pub_x
            pubkeys_by_role.setdefault(role, set()).add(pub_x)

        distinct_roles = list(pubkeys_by_role.keys())
        for i, role_a in enumerate(distinct_roles):
            for role_b in distinct_roles[i + 1 :]:
                if pubkeys_by_role[role_a] & pubkeys_by_role[role_b]:
                    trust_boundary_ok = False
                    fail(
                        "CIAF-08",
                        "SHARED_KEY_MATERIAL_VIOLATION",
                        f"Trust-boundary roles '{role_a}' and '{role_b}' share identical Ed25519 key material.",
                    )

        for cap_key in capsule.get("public_key_manifest", []):
            ckid = str(cap_key.get("key_id", ""))
            if ckid not in trusted_by_kid or trusted_by_kid[ckid] != cap_key:
                trust_boundary_ok = False
                fail(
                    "CIAF-10",
                    "UNTRUSTED_CAPSULE_KEY_MANIFEST",
                    f"Capsule public_key_manifest entry '{ckid}' does not match trusted manifest.",
                )

        # -------------------------------------------------------------------
        # STEP 3: Capsule & Policy RFC 8785 Canonical Digests
        # -------------------------------------------------------------------
        digests_ok = True
        policy_snap = capsule.get("policy_snapshot", {})
        expected_policy_digest = jcs_sha256(policy_snap.get("policy_document", {}))
        if policy_snap.get("policy_digest") != expected_policy_digest:
            digests_ok = False
            fail(
                "CIAF-05",
                "POLICY_DIGEST_TAMPERED",
                "policy_snapshot.policy_digest does not match RFC 8785 digest of policy_document.",
            )

        capsule_without_digest = {
            k: v for k, v in capsule.items() if k != "capsule_digest"
        }
        recomputed_capsule_digest = jcs_sha256(capsule_without_digest)
        if capsule.get("capsule_digest") != recomputed_capsule_digest:
            digests_ok = False
            fail(
                "CIAF-09",
                "CAPSULE_DIGEST_MISMATCH",
                f"AuditCapsule digest mismatch: expected {recomputed_capsule_digest}, "
                f"got {capsule.get('capsule_digest')}.",
            )

        # -------------------------------------------------------------------
        # STEP 4: AuthorizationClaim Enveloped Digest -> Signature -> Semantics
        # -------------------------------------------------------------------
        signatures_ok = True
        policy_binding_ok = True
        grant_nonce_ttl_ok = True
        semantic_ok = True

        # -------------------------------------------------------------------
        # STEP 3b: Optional Signed Registry Authority Attestation (CIAF-01..04, 12)
        # -------------------------------------------------------------------
        att = capsule.get("authority_attestation")
        if isinstance(att, dict):
            att_without_digest = {k: v for k, v in att.items() if k != "attestation_digest"}
            if att.get("attestation_digest") != jcs_sha256(att_without_digest):
                digests_ok = False
                fail(
                    "CIAF-01",
                    "AUTHORITY_ATTESTATION_DIGEST_MISMATCH",
                    "authority_attestation.attestation_digest does not match canonical payload.",
                )
            att_sig = att.get("signature", {})
            att_kid = str(att_sig.get("key_id", ""))
            att_trusted = trusted_by_kid.get(att_kid)
            if (
                att_trusted is None
                or att_trusted.get("role") != "REGISTRY_AUTHORITY"
                or att_trusted.get("status") != "ACTIVE"
            ):
                trust_boundary_ok = False
                signatures_ok = False
                fail(
                    "CIAF-01",
                    "INVALID_REGISTRY_AUTHORITY_KEY",
                    f"authority_attestation signed by untrusted or non-REGISTRY_AUTHORITY key '{att_kid}'.",
                )
            else:
                att_unsigned = {
                    k: v for k, v in att.items() if k not in ("signature", "attestation_digest")
                }
                att_ok, att_msg = verify_jcs_signature(
                    att_unsigned, att_sig, trusted_x_by_kid[att_kid]
                )
                if not att_ok:
                    signatures_ok = False
                    fail(
                        "CIAF-01",
                        "AUTHORITY_ATTESTATION_SIGNATURE_INVALID",
                        f"Registry authority_attestation signature invalid: {att_msg}",
                    )
            att_del = att.get("delegation", {})
            att_agent = att.get("agent", {})
            att_uc = att.get("use_case", {})
            if att_del.get("policy_id") != policy_snap.get("policy_id"):
                policy_binding_ok = False
                fail(
                    "CIAF-05",
                    "ATTESTATION_POLICY_ID_MISMATCH",
                    "authority_attestation.delegation.policy_id != policy_snapshot.policy_id.",
                )
            att_effective_status = (
                "REVOKED"
                if (att_agent.get("status") == "REVOKED" or att_del.get("status") == "REVOKED")
                else (
                    "SUSPENDED"
                    if (
                        att_agent.get("status") == "SUSPENDED"
                        or att_del.get("status") == "SUSPENDED"
                        or att_uc.get("status") != "ACTIVE"
                    )
                    else "ACTIVE"
                )
            )
            for ac in authz_claims:
                subj = ac.get("subject", {})
                actx = ac.get("authority_context", {})
                if (
                    subj.get("agent_id") != att_agent.get("agent_id")
                    or subj.get("use_case_id") != att_uc.get("use_case_id")
                    or subj.get("accountable_owner") != att_uc.get("accountable_owner")
                    or actx.get("delegation_id") != att_del.get("delegation_id")
                ):
                    semantic_ok = False
                    fail(
                        "CIAF-01",
                        "GATEWAY_REGISTRY_ATTESTATION_CONFLICT",
                        f"AuthorizationClaim '{ac.get('claim_id')}' subject/delegation conflicts with signed registry attestation.",
                    )
                if actx.get("authority_status") != att_effective_status:
                    semantic_ok = False
                    fail(
                        "CIAF-12",
                        "GATEWAY_REGISTRY_ATTESTATION_CONFLICT",
                        f"AuthorizationClaim '{ac.get('claim_id')}' claims authority_status="
                        f"'{actx.get('authority_status')}' while Registry attested '{att_effective_status}'.",
                    )
                snap_in_claim = actx.get("delegated_scope_snapshot", {})
                if isinstance(snap_in_claim, dict):
                    if (
                        snap_in_claim.get("accountable_owner") != att_uc.get("accountable_owner")
                        or snap_in_claim.get("allowed_tools") != att_del.get("allowed_tools")
                        or snap_in_claim.get("max_auto_amount_minor_units")
                        != att_del.get("autonomous_max_amount")
                        or snap_in_claim.get("escalation_max_amount_minor_units")
                        != att_del.get("escalation_max_amount")
                        or snap_in_claim.get("revoked") != (att_effective_status == "REVOKED")
                    ):
                        semantic_ok = False
                        fail(
                            "CIAF-04",
                            "GATEWAY_SCOPE_SNAPSHOT_ATTESTATION_CONFLICT",
                            f"AuthorizationClaim '{ac.get('claim_id')}' delegated_scope_snapshot "
                            f"conflicts with signed Registry authority_attestation.",
                        )
                if ac.get("decision", {}).get("outcome") == "ALLOW":
                    prop_act = ac.get("proposed_action", {})
                    allowed_tools = att_del.get("allowed_tools", [])
                    if prop_act.get("tool_name") not in allowed_tools:
                        semantic_ok = False
                        fail(
                            "CIAF-04",
                            "GATEWAY_ALLOWED_UNDELEGATED_TOOL",
                            f"Gateway granted ALLOW for tool '{prop_act.get('tool_name')}' outside Registry attestation.",
                        )
                    amt = prop_act.get("parameters", {}).get("amount_minor_units")
                    esc_max = att_del.get("escalation_max_amount")
                    auto_max = att_del.get("autonomous_max_amount")
                    if isinstance(amt, (int, float)) and not isinstance(amt, bool):
                        if isinstance(esc_max, int) and amt > esc_max:
                            semantic_ok = False
                            fail(
                                "CIAF-04",
                                "GATEWAY_ALLOWED_ABOVE_ATTESTED_CEILING",
                                f"Gateway granted ALLOW for {amt} minor units above Registry ceiling {esc_max}.",
                            )
                        if (
                            isinstance(auto_max, int)
                            and amt > auto_max
                            and ac.get("human_escalation", {}).get("required") is not True
                        ):
                            semantic_ok = False
                            fail(
                                "CIAF-07",
                                "GATEWAY_BYPASSED_ATTESTED_ESCALATION",
                                f"Gateway granted autonomous ALLOW for {amt} minor units above Registry autonomous limit {auto_max}.",
                            )

        authz_by_id: dict[str, dict[str, Any]] = {}

        for ac in authz_claims:
            cid = str(ac.get("claim_id", "unknown"))
            authz_by_id[cid] = ac

            # 4a. Recompute claim_digest == jcs_sha256(body_with_signature) first
            ac_body_with_sig = {k: v for k, v in ac.items() if k != "claim_digest"}
            if ac.get("claim_digest") != jcs_sha256(ac_body_with_sig):
                digests_ok = False
                fail(
                    "CIAF-09",
                    "AUTHZ_CLAIM_DIGEST_MISMATCH",
                    f"AuthorizationClaim '{cid}' claim_digest mismatch.",
                )

            prop = ac.get("proposed_action", {})
            expected_req_dig = compute_request_digest(
                str(prop.get("tool_name", "")),
                str(prop.get("operation", "")),
                prop.get("parameters", {}),
            )
            if prop.get("request_digest") != expected_req_dig:
                digests_ok = False
                fail(
                    "CIAF-06",
                    "AUTHZ_REQUEST_DIGEST_MISMATCH",
                    f"AuthorizationClaim '{cid}' proposed_action.request_digest mismatch.",
                )

            # 4b. Verify Ed25519(canonicalize_jcs(unsigned_body)) against role-pinned Gateway key
            sig_obj = ac.get("signature", {})
            kid = str(sig_obj.get("key_id", ""))
            trusted_entry = trusted_by_kid.get(kid)
            if trusted_entry is None:
                trust_boundary_ok = False
                signatures_ok = False
                fail(
                    "CIAF-10",
                    "UNTRUSTED_SIGNING_KEY",
                    f"AuthorizationClaim '{cid}' signed by untrusted key '{kid}'.",
                )
            else:
                if trusted_entry.get("role") != "PRE_EXECUTION_GOVERNANCE_GATEWAY":
                    trust_boundary_ok = False
                    fail(
                        "CIAF-06",
                        "TRUST_BOUNDARY_KEY_ROLE_VIOLATION",
                        f"AuthorizationClaim '{cid}' signed by non-Gateway role "
                        f"'{trusted_entry.get('role')}'.",
                    )
                if trusted_entry.get("status") != "ACTIVE":
                    trust_boundary_ok = False
                    fail("CIAF-10", "REVOKED_SIGNING_KEY", f"Signing key '{kid}' is not ACTIVE.")
                ac_unsigned = {
                    k: v for k, v in ac.items() if k not in ("signature", "claim_digest")
                }
                ok_sig, msg_sig = verify_jcs_signature(
                    ac_unsigned, sig_obj, trusted_x_by_kid[kid]
                )
                if not ok_sig:
                    signatures_ok = False
                    fail(
                        "CIAF-10",
                        "AUTHZ_SIGNATURE_INVALID",
                        f"AuthorizationClaim '{cid}' Ed25519 verification failed: {msg_sig}",
                    )

            # 4c. Policy digest binding (CIAF-05)
            ac_pol_dig = ac.get("authority_context", {}).get("policy_digest")
            if ac_pol_dig != policy_snap.get("policy_digest"):
                policy_binding_ok = False
                fail(
                    "CIAF-05",
                    "AUTHZ_POLICY_DIGEST_MISMATCH",
                    f"AuthorizationClaim '{cid}' policy_digest != capsule policy_digest.",
                )

            # 4d. Decision, Delegated Scope Snapshot & Grant semantics (CIAF-02, 04, 06, 07, 08, 12)
            outcome = ac.get("decision", {}).get("outcome")
            grant = ac.get("execution_grant")
            esc = ac.get("human_escalation", {})
            actx_block = ac.get("authority_context", {})
            auth_status = actx_block.get("authority_status")
            scope_snap = actx_block.get("delegated_scope_snapshot")
            params = prop.get("parameters", {}) if isinstance(prop.get("parameters"), dict) else {}

            if isinstance(scope_snap, dict):
                if scope_snap.get("accountable_owner") != ac.get("subject", {}).get("accountable_owner"):
                    semantic_ok = False
                    fail(
                        "CIAF-02",
                        "SCOPE_SNAPSHOT_OWNER_MISMATCH",
                        f"AuthorizationClaim '{cid}' delegated_scope_snapshot.accountable_owner "
                        f"does not match subject.accountable_owner.",
                    )
                if scope_snap.get("revoked") is not (auth_status == "REVOKED"):
                    semantic_ok = False
                    fail(
                        "CIAF-12",
                        "SCOPE_SNAPSHOT_REVOCATION_CONFLICT",
                        f"AuthorizationClaim '{cid}' delegated_scope_snapshot.revoked conflicts "
                        f"with authority_status='{auth_status}'.",
                    )

            if outcome == "ALLOW":
                if (
                    "amount" in params
                    or isinstance(params.get("amount_minor_units"), float)
                    or isinstance(params.get("minor_unit_scale"), float)
                ):
                    semantic_ok = False
                    fail(
                        "CIAF-04",
                        "FLOAT_OR_AMBIGUOUS_MONETARY_AMOUNT",
                        f"AuthorizationClaim '{cid}' uses ambiguous 'amount' or IEEE-754 float "
                        f"instead of exact integer 'amount_minor_units' + 'minor_unit_scale'.",
                    )
                if isinstance(scope_snap, dict):
                    snap_tools = scope_snap.get("allowed_tools", [])
                    if prop.get("tool_name") not in snap_tools:
                        semantic_ok = False
                        fail(
                            "CIAF-04",
                            "ALLOW_OUTSIDE_DELEGATED_TOOLS",
                            f"AuthorizationClaim '{cid}' granted ALLOW for tool "
                            f"'{prop.get('tool_name')}' outside delegated_scope_snapshot.allowed_tools.",
                        )
                    if scope_snap.get("revoked") is True:
                        semantic_ok = False
                        fail(
                            "CIAF-12",
                            "ALLOW_ON_REVOKED_SCOPE_SNAPSHOT",
                            f"AuthorizationClaim '{cid}' granted ALLOW while delegated_scope_snapshot.revoked=True.",
                        )
                    snap_currency = scope_snap.get("currency")
                    if snap_currency is not None and params.get("currency") != snap_currency:
                        semantic_ok = False
                        fail(
                            "CIAF-04",
                            "ALLOW_CURRENCY_MISMATCH",
                            f"AuthorizationClaim '{cid}' currency '{params.get('currency')}' != "
                            f"delegated_scope_snapshot.currency '{snap_currency}'.",
                        )
                    snap_auto_max = scope_snap.get("max_auto_amount_minor_units")
                    snap_esc_max = scope_snap.get("escalation_max_amount_minor_units")
                    if (
                        snap_auto_max is not None
                        or snap_esc_max is not None
                        or "amount_minor_units" in params
                    ):
                        amt_minor = params.get("amount_minor_units")
                        scale_val = params.get("minor_unit_scale")
                        if (
                            not isinstance(amt_minor, int)
                            or isinstance(amt_minor, bool)
                            or amt_minor <= 0
                            or not isinstance(scale_val, int)
                            or isinstance(scale_val, bool)
                            or scale_val < 0
                            or scale_val > 18
                        ):
                            semantic_ok = False
                            fail(
                                "CIAF-04",
                                "INVALID_MONETARY_MINOR_UNITS",
                                f"AuthorizationClaim '{cid}' ALLOW requires positive integer "
                                f"amount_minor_units and integer minor_unit_scale (0..18).",
                            )
                        else:
                            if isinstance(snap_esc_max, int) and amt_minor > snap_esc_max:
                                semantic_ok = False
                                fail(
                                    "CIAF-04",
                                    "ALLOW_EXCEEDS_DELEGATED_CEILING",
                                    f"AuthorizationClaim '{cid}' granted ALLOW for {amt_minor} minor "
                                    f"units exceeding delegated_scope_snapshot ceiling ({snap_esc_max}).",
                                )
                                fail(
                                    "CIAF-06",
                                    "ALLOW_EXCEEDS_DELEGATED_CEILING",
                                    f"Gateway policy enforcement failed: ALLOW issued above absolute "
                                    f"delegation ceiling ({amt_minor} > {snap_esc_max}).",
                                )
                            if (
                                isinstance(snap_auto_max, int)
                                and amt_minor > snap_auto_max
                                and esc.get("required") is not True
                            ):
                                semantic_ok = False
                                fail(
                                    "CIAF-06",
                                    "UNESCALATED_ALLOW_ABOVE_AUTONOMOUS_LIMIT",
                                    f"AuthorizationClaim '{cid}' granted unescalated ALLOW for "
                                    f"{amt_minor} minor units above max_auto_amount_minor_units ({snap_auto_max}).",
                                )
                                fail(
                                    "CIAF-07",
                                    "UNESCALATED_ALLOW_ABOVE_AUTONOMOUS_LIMIT",
                                    f"Mandatory human escalation bypassed: {amt_minor} minor units "
                                    f"exceeds autonomous threshold {snap_auto_max} without human review.",
                                )
                if auth_status != "ACTIVE":
                    semantic_ok = False
                    fail(
                        "CIAF-12",
                        "ALLOW_ON_INACTIVE_AUTHORITY",
                        f"AuthorizationClaim '{cid}' granted ALLOW while status={auth_status}.",
                    )
                if esc.get("required") is True:
                    if (
                        esc.get("status") != "APPROVED"
                        or not esc.get("reviewer_id")
                        or not esc.get("review_rationale")
                        or not esc.get("reviewed_at")
                    ):
                        semantic_ok = False
                        fail(
                            "CIAF-07",
                            "ESCALATION_APPROVAL_INCOMPLETE",
                            f"AuthorizationClaim '{cid}' required human escalation but lacks approval metadata.",
                        )
                    else:
                        rsig = esc.get("reviewer_signature")
                        if not isinstance(rsig, dict):
                            signatures_ok = False
                            semantic_ok = False
                            fail(
                                "CIAF-07",
                                "FORGED_OR_UNSIGNED_HUMAN_APPROVAL",
                                f"AuthorizationClaim '{cid}' lacks independent HUMAN_REVIEWER cryptographic signature.",
                            )
                        else:
                            rkid = str(rsig.get("key_id", ""))
                            r_trusted = trusted_by_kid.get(rkid)
                            if (
                                r_trusted is None
                                or r_trusted.get("role") != "HUMAN_REVIEWER"
                                or r_trusted.get("status") != "ACTIVE"
                            ):
                                trust_boundary_ok = False
                                signatures_ok = False
                                fail(
                                    "CIAF-07",
                                    "INVALID_HUMAN_REVIEWER_KEY_ROLE",
                                    f"Escalation on '{cid}' signed by untrusted or non-HUMAN_REVIEWER key '{rkid}'.",
                                )
                            else:
                                expected_rev_payload = build_human_review_payload(
                                    proposal_id=str(prop.get("proposal_id", "")),
                                    request_digest=str(prop.get("request_digest", "")),
                                    policy_digest=str(ac_pol_dig or ""),
                                    reviewer_id=str(esc.get("reviewer_id", "")),
                                    approved=True,
                                    review_rationale=str(esc.get("review_rationale", "")),
                                    reviewed_at=str(esc.get("reviewed_at", "")),
                                )
                                r_ok, r_msg = verify_jcs_signature(
                                    expected_rev_payload, rsig, trusted_x_by_kid[rkid]
                                )
                                if not r_ok:
                                    signatures_ok = False
                                    fail(
                                        "CIAF-07",
                                        "HUMAN_REVIEWER_SIGNATURE_INVALID",
                                        f"Human reviewer signature on '{cid}' invalid: {r_msg}",
                                    )
                if not isinstance(grant, dict):
                    semantic_ok = False
                    fail(
                        "CIAF-08",
                        "MISSING_EXECUTION_GRANT_ON_ALLOW",
                        f"AuthorizationClaim '{cid}' has ALLOW outcome without execution_grant.",
                    )
                else:
                    ttl_s = int(grant.get("ttl_seconds", 0))
                    policy_ttl_cap = int(
                        policy_snap.get("policy_document", {}).get("grant_max_ttl_seconds", 30)
                    )
                    issued_dt = _parse_iso_utc(grant["issued_at"])
                    expires_dt = _parse_iso_utc(grant["expires_at"])
                    if (
                        ttl_s < 1
                        or policy_ttl_cap < 1
                        or policy_ttl_cap > 300
                        or ttl_s > policy_ttl_cap
                        or int((expires_dt - issued_dt).total_seconds()) != ttl_s
                    ):
                        grant_nonce_ttl_ok = False
                        fail(
                            "CIAF-08",
                            "GRANT_TTL_POLICY_VIOLATION",
                            f"Grant '{grant.get('grant_id')}' violates policy-bounded short-lived TTL rule (<= {policy_ttl_cap}s).",
                        )
                    if (
                        grant.get("bound_request_digest") != prop.get("request_digest")
                        or grant.get("bound_policy_digest") != policy_snap.get("policy_digest")
                        or grant.get("bound_authorization_claim_id") != cid
                    ):
                        grant_nonce_ttl_ok = False
                        fail(
                            "CIAF-08",
                            "GRANT_BINDING_MISMATCH",
                            f"Grant '{grant.get('grant_id')}' digest or claim ID binding mismatch.",
                        )
                    gsig = grant.get("gateway_grant_signature", {})
                    gkid = str(gsig.get("key_id", ""))
                    g_trusted = trusted_by_kid.get(gkid)
                    if (
                        g_trusted is None
                        or g_trusted.get("role") != "PRE_EXECUTION_GOVERNANCE_GATEWAY"
                    ):
                        trust_boundary_ok = False
                        signatures_ok = False
                        fail(
                            "CIAF-08",
                            "INVALID_GRANT_SIGNER_ROLE",
                            f"Grant '{grant.get('grant_id')}' not signed by trusted Gateway key.",
                        )
                    else:
                        unsigned_g = {
                            k: v for k, v in grant.items() if k != "gateway_grant_signature"
                        }
                        g_ok, g_msg = verify_jcs_signature(
                            unsigned_g, gsig, trusted_x_by_kid[gkid]
                        )
                        if not g_ok:
                            signatures_ok = False
                            fail(
                                "CIAF-08",
                                "GRANT_SIGNATURE_INVALID",
                                f"Grant '{grant.get('grant_id')}' signature invalid: {g_msg}",
                            )
            else:
                if grant is not None:
                    semantic_ok = False
                    fail(
                        "CIAF-06",
                        "GRANT_ISSUED_ON_NON_ALLOW",
                        f"AuthorizationClaim '{cid}' outcome={outcome} MUST NOT contain execution_grant.",
                    )

        # -------------------------------------------------------------------
        # STEP 5: ExecutionClaim Enveloped Digest -> Signature -> Semantics
        # -------------------------------------------------------------------
        seen_consumed_nonces: set[str] = set()
        any_authorized_execution = False
        any_security_exception_contained = False

        for ec in exec_claims:
            ecid = str(ec.get("claim_id", "unknown"))

            # 5a. Recompute claim_digest == jcs_sha256(body_with_signature) first
            ec_body_with_sig = {k: v for k, v in ec.items() if k != "claim_digest"}
            if ec.get("claim_digest") != jcs_sha256(ec_body_with_sig):
                digests_ok = False
                fail(
                    "CIAF-09",
                    "EXEC_CLAIM_DIGEST_MISMATCH",
                    f"ExecutionClaim '{ecid}' claim_digest mismatch (evidence tampered).",
                )

            act = ec.get("action_request", {})
            expected_obs_dig = compute_request_digest(
                str(act.get("tool_name", "")),
                str(act.get("operation", "")),
                act.get("parameters", {}),
            )
            if act.get("observed_request_digest") != expected_obs_dig:
                digests_ok = False
                fail(
                    "CIAF-08",
                    "EXEC_OBSERVED_DIGEST_MISMATCH",
                    f"ExecutionClaim '{ecid}' observed_request_digest mismatch.",
                )

            exec_block = ec.get("execution", {})
            if exec_block.get("result_summary") is not None:
                expected_res_dig = jcs_sha256(exec_block["result_summary"])
                if exec_block.get("result_digest") != expected_res_dig:
                    digests_ok = False
                    fail(
                        "CIAF-09",
                        "EXEC_RESULT_DIGEST_MISMATCH",
                        f"ExecutionClaim '{ecid}' result_digest mismatch.",
                    )

            # 5b. Verify Ed25519(canonicalize_jcs(unsigned_body)) against role-pinned Executor key
            esig = ec.get("signature", {})
            ekid = str(esig.get("key_id", ""))
            e_trusted = trusted_by_kid.get(ekid)
            if e_trusted is None:
                trust_boundary_ok = False
                signatures_ok = False
                fail(
                    "CIAF-10",
                    "UNTRUSTED_EXECUTOR_KEY",
                    f"ExecutionClaim '{ecid}' signed by untrusted key '{ekid}'.",
                )
            else:
                if e_trusted.get("role") != "EXECUTION_SERVICE":
                    trust_boundary_ok = False
                    fail(
                        "CIAF-08",
                        "TRUST_BOUNDARY_KEY_ROLE_VIOLATION",
                        f"ExecutionClaim '{ecid}' signed with '{e_trusted.get('role')}' key "
                        f"('{ekid}') instead of independent EXECUTION_SERVICE key.",
                    )
                if e_trusted.get("status") != "ACTIVE":
                    trust_boundary_ok = False
                    fail("CIAF-10", "REVOKED_EXECUTOR_KEY", f"Executor key '{ekid}' is not ACTIVE.")
                ec_unsigned = {
                    k: v for k, v in ec.items() if k not in ("signature", "claim_digest")
                }
                e_ok, e_msg = verify_jcs_signature(
                    ec_unsigned, esig, trusted_x_by_kid[ekid]
                )
                if not e_ok:
                    signatures_ok = False
                    fail(
                        "CIAF-10",
                        "EXEC_SIGNATURE_INVALID",
                        f"ExecutionClaim '{ecid}' Ed25519 verification failed: {e_msg}",
                    )

            # 5c. Grant binding, nonce uniqueness, TTL, and security exception semantics
            binding = ec.get("authorization_binding", {})
            sec_exc = ec.get("security_exception")
            attempted = bool(exec_block.get("attempted"))
            executed = bool(exec_block.get("executed"))
            status = exec_block.get("status")

            if attempted or executed or status == "SUCCEEDED":
                any_authorized_execution = True
                if (
                    binding.get("grant_verification_status") != "VERIFIED"
                    or sec_exc is not None
                ):
                    semantic_ok = False
                    fail(
                        "CIAF-08",
                        "UNVERIFIED_EXECUTION_COMMITTED",
                        f"ExecutionClaim '{ecid}' attempted execution without VERIFIED grant.",
                    )
                ref_aid = str(binding.get("authorization_claim_id", ""))
                ref_authz = authz_by_id.get(ref_aid)
                if ref_authz is None:
                    semantic_ok = False
                    fail(
                        "CIAF-06",
                        "MISSING_REFERENCED_AUTHZ_CLAIM",
                        f"ExecutionClaim '{ecid}' references missing AuthorizationClaim '{ref_aid}'.",
                    )
                else:
                    if binding.get("authorization_claim_digest") != ref_authz.get("claim_digest"):
                        semantic_ok = False
                        fail(
                            "CIAF-08",
                            "AUTHZ_CLAIM_DIGEST_LINK_BROKEN",
                            f"ExecutionClaim '{ecid}' authorization_claim_digest mismatch.",
                        )
                    if ref_authz.get("decision", {}).get("outcome") != "ALLOW":
                        semantic_ok = False
                        fail(
                            "CIAF-06",
                            "EXECUTION_DESPITE_NON_ALLOW",
                            f"ExecutionClaim '{ecid}' executed despite Gateway outcome "
                            f"{ref_authz.get('decision', {}).get('outcome')}.",
                        )
                    ref_grant = ref_authz.get("execution_grant") or {}
                    c_nonce = str(binding.get("consumed_nonce", ""))
                    if not c_nonce or c_nonce != ref_grant.get("nonce"):
                        grant_nonce_ttl_ok = False
                        fail(
                            "CIAF-08",
                            "GRANT_NONCE_MISMATCH",
                            f"ExecutionClaim '{ecid}' consumed_nonce != grant nonce.",
                        )
                    elif c_nonce in seen_consumed_nonces:
                        grant_nonce_ttl_ok = False
                        fail(
                            "CIAF-08",
                            "DUPLICATE_CONSUMED_NONCE_IN_CAPSULE",
                            f"Single-use nonce '{c_nonce}' consumed multiple times!",
                        )
                    else:
                        seen_consumed_nonces.add(c_nonce)

                    if binding.get("policy_digest") != policy_snap.get("policy_digest"):
                        policy_binding_ok = False
                        fail(
                            "CIAF-05",
                            "EXEC_POLICY_DIGEST_MISMATCH",
                            f"ExecutionClaim '{ecid}' policy_digest != capsule policy_digest.",
                        )

                    if act.get("observed_request_digest") != ref_grant.get("bound_request_digest"):
                        grant_nonce_ttl_ok = False
                        fail(
                            "CIAF-08",
                            "UNBLOCKED_TOCTOU_MISMATCH",
                            f"ExecutionClaim '{ecid}' executed with mismatched request_digest!",
                        )

                    exec_dt = _parse_iso_utc(ec["timestamp"])
                    g_issued = _parse_iso_utc(ref_grant["issued_at"])
                    g_expires = _parse_iso_utc(ref_grant["expires_at"])
                    if exec_dt < g_issued or exec_dt > g_expires:
                        grant_nonce_ttl_ok = False
                        fail(
                            "CIAF-08",
                            "EXECUTION_OUTSIDE_GRANT_TTL",
                            f"ExecutionClaim '{ecid}' timestamp outside grant TTL window.",
                        )
            elif status == "REJECTED_SECURITY_EXCEPTION":
                any_security_exception_contained = True
                if (
                    attempted
                    or executed
                    or exec_block.get("side_effects_committed")
                    or not isinstance(sec_exc, dict)
                    or sec_exc.get("detected") is not True
                ):
                    semantic_ok = False
                    fail(
                        "CIAF-11",
                        "INVALID_SECURITY_EXCEPTION_RECEIPT",
                        f"ExecutionClaim '{ecid}' security exception receipt is inconsistent.",
                    )
                else:
                    info(
                        sec_exc["control_id"],
                        sec_exc["exception_code"],
                        f"Contained runtime attack verified: {sec_exc['detail']}",
                    )
            elif status == "NOT_ATTEMPTED_GATEWAY_BLOCKED":
                if attempted or executed or exec_block.get("side_effects_committed"):
                    semantic_ok = False
                    fail(
                        "CIAF-06",
                        "SIDE_EFFECT_ON_GATEWAY_BLOCK",
                        f"ExecutionClaim '{ecid}' marked blocked but reports execution!",
                    )

        if (
            authz_claims
            and any(ac.get("decision", {}).get("outcome") == "ALLOW" for ac in authz_claims)
            and not exec_claims
        ):
            semantic_ok = False
            fail(
                "CIAF-09",
                "MISSING_EXECUTION_EVIDENCE_FOR_ALLOW",
                "ALLOW AuthorizationClaim present with zero ExecutionClaims in capsule.",
            )

        # -------------------------------------------------------------------
        # STEP 6: Hash-Chain Continuity check (CIAF-09)
        # -------------------------------------------------------------------
        chain_ok = True
        all_receipts = [*authz_claims, *exec_claims]
        if not all_receipts:
            chain_ok = False
            fail("CIAF-09", "EMPTY_RECEIPT_CHAIN", "AuditCapsule contains zero receipts.")
        else:
            sorted_receipts = sorted(
                all_receipts, key=lambda r: int(r.get("sequence_number", -1))
            )
            for expected_idx, receipt in enumerate(sorted_receipts):
                actual_seq = receipt.get("sequence_number")
                if actual_seq != expected_idx:
                    chain_ok = False
                    fail(
                        "CIAF-09",
                        "HASH_CHAIN_SEQUENCE_GAP_OR_REORDER",
                        f"Expected sequence_number {expected_idx}, found {actual_seq} "
                        f"on receipt '{receipt.get('claim_id')}'.",
                    )
                if expected_idx == 0:
                    if receipt.get("previous_receipt_digest") is not None:
                        chain_ok = False
                        fail(
                            "CIAF-09",
                            "INVALID_GENESIS_PREVIOUS_DIGEST",
                            "Genesis receipt (sequence 0) must have previous_receipt_digest=null.",
                        )
                else:
                    prev_expected = sorted_receipts[expected_idx - 1].get("claim_digest")
                    if receipt.get("previous_receipt_digest") != prev_expected:
                        chain_ok = False
                        fail(
                            "CIAF-09",
                            "HASH_CHAIN_BROKEN_LINKAGE",
                            f"Receipt '{receipt.get('claim_id')}' previous_receipt_digest "
                            f"({receipt.get('previous_receipt_digest')}) != prior claim_digest "
                            f"({prev_expected}).",
                        )

            hc = capsule.get("hash_chain", {})
            computed_ordered = [str(r.get("claim_digest", "")) for r in sorted_receipts]
            if (
                hc.get("ordered_receipt_digests") != computed_ordered
                or hc.get("receipt_count") != len(computed_ordered)
                or hc.get("genesis_receipt_digest") != computed_ordered[0]
                or hc.get("tip_receipt_digest") != computed_ordered[-1]
            ):
                chain_ok = False
                fail(
                    "CIAF-09",
                    "HASH_CHAIN_HEADER_MISMATCH",
                    "hash_chain summary metadata does not match ordered receipt digests.",
                )

        # -------------------------------------------------------------------
        # STEP 7: SCITT Transparency completeness evaluation
        # -------------------------------------------------------------------
        scitt = capsule.get("scitt_transparency", {})
        scitt_verified: bool | None = None
        if scitt.get("status") == "REGISTERED_INCLUSION_RECEIPT_ATTACHED":
            scitt_verified = bool(
                scitt.get("transparency_service_id")
                and scitt.get("cose_sign1_statement_digest")
                and scitt.get("inclusion_receipt_b64u")
            )
            completeness_notice = (
                "IETF SCITT (RFC 9943 / RFC 9942 COSE Receipts) inclusion metadata attached; "
                "local RFC 8785 hash-chain, external registration timestamping, and "
                "transparency metadata verified."
            )
        else:
            scitt_verified = None
            completeness_notice = (
                "Local RFC 8785 SHA-256 hash-chaining verified (detects mid-chain tampering, "
                "deletion, or reordering). Grant TTL checks verify chronological consistency "
                "across issuer-asserted timestamps; defending against compromised-executor "
                "clock backdating and log-tail omission requires an external RFC 3161 TSA "
                "timestamp or IETF SCITT (RFC 9943 / RFC 9942 COSE Receipts) Merkle inclusion receipt."
            )

        capsule_valid = (
            schema_ok
            and digests_ok
            and trust_boundary_ok
            and signatures_ok
            and policy_binding_ok
            and grant_nonce_ttl_ok
            and chain_ok
            and semantic_ok
        )

        if not capsule_valid:
            disposition = "ASSURANCE_FAILURE_TAMPER_OR_VIOLATION"
        elif any_security_exception_contained:
            disposition = "ASSURED_SECURITY_EXCEPTION_CONTAINED"
        elif any_authorized_execution:
            disposition = "ASSURED_AUTHORIZED_EXECUTION"
        else:
            disposition = "ASSURED_GOVERNANCE_BLOCK"

        if capsule_valid and not findings:
            info(
                "CIAF-10",
                "ZERO_TRUST_VERIFICATION_PASSED",
                f"All cryptographic, schema, hash-chain, and semantic checks passed ({disposition}).",
            )

        raw_cap_dig = str(capsule.get("capsule_digest", ""))
        safe_cap_dig = (
            raw_cap_dig
            if raw_cap_dig.startswith("sha256:") and len(raw_cap_dig) == 71
            else recomputed_capsule_digest
        )

        unsigned_assurance: dict[str, Any] = {
            "schema_version": "0.1.0",
            "claim_type": "ASSURANCE_CLAIM",
            "claim_id": f"assure-{uuid.uuid4().hex[:16]}",
            "timestamp": utc_now_iso(now),
            "verifier_id": self.verifier_id,
            "capsule_id": str(capsule.get("capsule_id", "unknown-capsule")),
            "capsule_digest": safe_cap_dig,
            "capsule_valid": capsule_valid,
            "assurance_disposition": disposition,
            "checks": {
                "schema_validation_passed": schema_ok,
                "rfc8785_digests_valid": digests_ok,
                "dual_key_trust_boundary_valid": trust_boundary_ok,
                "ed25519_signatures_valid": signatures_ok,
                "policy_digest_binding_valid": policy_binding_ok,
                "grant_nonce_and_ttl_valid": grant_nonce_ttl_ok,
                "hash_chain_continuity_valid": chain_ok,
                "semantic_consistency_valid": semantic_ok,
                "scitt_inclusion_verified": scitt_verified,
            },
            "failed_controls": sorted(failed_controls_set),
            "findings": copy.deepcopy(findings),
            "completeness_notice": completeness_notice,
        }

        if self._verifier_key is not None:
            signed_assurance = sign_claim_envelope(unsigned_assurance, self._verifier_key)
        else:
            with_null_sig = {**unsigned_assurance, "signature": None}
            signed_assurance = {
                **with_null_sig,
                "claim_digest": jcs_sha256(with_null_sig),
            }

        self._assurance_validator.validate(signed_assurance)
        return signed_assurance
