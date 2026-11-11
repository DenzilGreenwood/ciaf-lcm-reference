# CIAF-LCM v0.1 Normative Control Catalog (`CIAF-01` – `CIAF-12`)

**Document ID**: `CIAF-LCM-CTRL-v0.1.1`  
**Status**: Normative Specification (`v0.1.1` — Public Comment Draft through February 10, 2027)  
**License**: Creative Commons Attribution 4.0 International (`CC-BY-4.0` — see [`LICENSE-SPEC`](../LICENSE-SPEC))

---

## 1. Catalog Structure & Normative Usage

This catalog defines the twelve foundational controls (`CIAF-01` through `CIAF-12`) governing consequential AI and agentic systems under CIAF-LCM v0.1. Every control enforces the separation `Capability != Authority != Authorization != Execution != Assurance`. All JSON field paths referenced below map 1-to-1 to the Draft 2020-12 schemas in [`schemas/`](../schemas/).

---

## `CIAF-01` — Use Case Registration & Business Purpose Binding

- **Title**: Use Case Registration & Business Purpose Binding
- **Objective**: Ensure no AI or agentic system proposes consequential operations outside an approved, risk-classified institutional workflow.
- **Requirement**: Every agent runtime invoking consequential tools `MUST` be bound in the Authority & Policy Registry to an `ACTIVE` `use_case_id` with a documented `business_purpose` and risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). Unregistered or `RETIRED`/`SUSPENDED` use cases `MUST` be denied pre-execution.
- **Minimum Testable Evidence**:
  - Registry `UseCaseRecord` (`use_case_id`, `business_purpose`, `risk_tier`, `status`) and optional `REGISTRY_AUTHORITY`-signed `AuditCapsule.authority_attestation`.
  - `AuthorizationClaim.subject.use_case_id` and `AuthorizationClaim.subject.business_purpose`.
- **Audit Test Procedure**:
  1. Sample production `AuthorizationClaim` receipts and trace each `subject.use_case_id` to an approved `UseCaseRecord`.
  2. Submit a proposal from an agent linked to a `SUSPENDED` use case and confirm deterministic `DENY` (`AUTHORITY_SUSPENDED`).
- **Failure Modes**:
  - Shadow/unregistered agent workflows invoking production APIs;
  - Generic placeholder `business_purpose` values preventing proportionality review;
  - Continued execution after a use case is retired.

---

## `CIAF-02` — Accountable Human Ownership Assignment

- **Title**: Accountable Human Ownership Assignment
- **Objective**: Preserve unambiguous human institutional accountability for every automated or agent-assisted workflow.
- **Requirement**: Every `UseCaseRecord` and `AuthorizationClaim` `MUST` identify a named, active human principal or governed institutional office (`accountable_owner`). Automated agents, models, or shared technical accounts `MUST NOT` be recorded as `accountable_owner`.
- **Minimum Testable Evidence**:
  - `UseCaseRecord.accountable_owner` (non-empty human/role identifier).
  - `AuthorizationClaim.subject.accountable_owner` cryptographically bound inside the Gateway signature.
- **Audit Test Procedure**:
  1. Attempt to register a use case with an empty `accountable_owner` and confirm registry rejection.
  2. Cross-reference sampled `AuthorizationClaim.subject.accountable_owner` principals against active enterprise HR/IAM directory records.
- **Failure Modes**:
  - Orphaned agents operating after owner departure without reassignment;
  - Service-account or bot identities listed as `accountable_owner`.

---

## `CIAF-03` — Cryptographic Agent Identity & Workload Binding

- **Title**: Cryptographic Agent Identity & Workload Binding
- **Objective**: Attribute every action proposal to a specific, non-shared agent runtime instance.
- **Requirement**: Each agent instance `MUST` possess a distinct `agent_id` registered with workload identity metadata (`workload_id`, `model_profile`) and bound into both `AuthorizationClaim.subject.agent_id` and `ExecutionGrant.bound_agent_id`. Anonymous or shared-credential callers `MUST` be rejected.
- **Minimum Testable Evidence**:
  - Registry `AgentIdentityRecord` (`agent_id`, `use_case_id`, `workload_id`, `model_profile`, `status`).
  - `AuthorizationClaim.subject.agent_id`, `ExecutionGrant.bound_agent_id`, and `ExecutionClaim.action_request.agent_id`.
- **Audit Test Procedure**:
  1. Attempt Gateway evaluation with an unregistered `agent_id` and verify rejection.
  2. Present a valid `ExecutionGrant` minted for `agent-finance-01` from a different `agent_id` (`agent-ops-02`) at the Execution Service and confirm `AGENT_MISMATCH` (`UNAUTHORIZED_CALLER_OR_TOOL`).
- **Failure Modes**:
  - Multiple distinct agent workflows sharing a single static API key or `agent_id`;
  - Confused-deputy substitution between agent instances.

---

## `CIAF-04` — Scoped Delegation & Least-Privilege Authority

- **Title**: Scoped Delegation & Least-Privilege Authority
- **Objective**: Constrain standing agent authority to explicit tool allowlists, domain parameter bounds, ISO-4217 integer minor currency units, and cumulative velocity caps (`Capability != Authority`).
- **Requirement**: Delegations (`delegation_id`) `MUST` specify explicit `allowed_tools` and applicable domain-neutral `scope_constraints`, `escalate_on_tools`, and counterparty allowlists/watchlists, and `MUST` bind a `delegated_scope_snapshot` (`accountable_owner`, `allowed_tools`, `max_auto_amount_minor_units`, `escalation_max_amount_minor_units`, `currency`, `revoked`) into every `AuthorizationClaim.authority_context`. Where monetary operations are delegated, ceilings and request amounts `MUST` use exact ISO-4217 integers (`amount_minor_units`, `currency`, `minor_unit_scale` `0..18`; bare `"amount"` fields or IEEE-754 floats `MUST` be rejected with `INVALID_MONETARY_PRECISION`) and `SHOULD` enforce rolling cumulative velocity caps (`rolling_window_max_amount`, `rolling_window_max_count`) to prevent split-transaction structuring (`CUMULATIVE_VELOCITY_EXCEEDED`). Any tool or parameter outside delegated scope `MUST` default to `DENY` or `INSPECT`.
- **Minimum Testable Evidence**:
  - Registry `DelegationRecord`, `AuthorizationClaim.authority_context.delegated_scope_snapshot`, optional `AuditCapsule.authority_attestation`, and `AuthorizationClaim.authority_context.delegation_id`.
  - Signed `AuthorizationClaim` receipts demonstrating `DENY` (`TOOL_NOT_ALLOWED`, `SCOPE_CONSTRAINT_VIOLATION`, `INVALID_MONETARY_PRECISION`, `CURRENCY_NOT_ALLOWED`, `BENEFICIARY_NOT_ALLOWED`, `AUTHORITY_SCOPE_EXCEEDED`, `CUMULATIVE_VELOCITY_EXCEEDED`) on out-of-bounds proposals.
- **Audit Test Procedure**:
  1. Inspect `DelegationRecord` entries and `delegated_scope_snapshot` fields for wildcard tool permissions (`*`), bare `"amount"` / floating-point monetary fields, or missing cumulative velocity caps on autonomous payment agents.
  2. Submit a `payments.create` proposal exceeding `escalation_max_amount_minor_units` (and a split-payment sequence exceeding `rolling_window_max_amount`) and confirm `decision.outcome == "DENY"` with `execution_grant == null`.
- **Failure Modes**:
  - Over-privileged agents granted full ERP/EHR/payment API scope despite narrow operational purpose;
  - Per-transaction limits without cumulative velocity controls, enabling structuring attacks (`100 x \$499`);
  - Floating-point rounding discrepancies across runtimes.

---

## `CIAF-05` — Versioned Policy Definition & Digest Pinning

- **Title**: Versioned Policy Definition & Digest Pinning
- **Objective**: Prevent silent policy drift or mid-flight rule substitution between authorization and execution.
- **Requirement**: Governance policies (`policy_id`, `policy_version`, `policy_document`) `MUST` be canonicalized strictly per **RFC 8785 (JCS)** and hashed via SHA-256 (`policy_digest`). `AuthorizationClaim.authority_context.policy_digest`, `ExecutionGrant.bound_policy_digest`, `ExecutionClaim.authorization_binding.policy_digest`, and `AuditCapsule.policy_snapshot.policy_digest` `MUST` match identically.
- **Minimum Testable Evidence**:
  - `AuditCapsule.policy_snapshot` (`policy_id`, `policy_version`, `policy_document`, `policy_digest`).
  - Matching `policy_digest` fields across `AuthorizationClaim`, `ExecutionGrant`, and `ExecutionClaim`.
- **Audit Test Procedure**:
  1. Recompute `sha256(JCS(policy_snapshot.policy_document))` offline and verify equality with `policy_digest`.
  2. Mutate one rule inside `policy_snapshot.policy_document` of a saved `AuditCapsule` and confirm `IndependentVerifier` flags `CIAF-05` (`POLICY_DIGEST_TAMPERED`).
- **Failure Modes**:
  - Hashing raw uncanonicalized JSON strings, causing cross-language verification failures;
  - Unpinned mutable policy lookups where execution occurs under different rules than Gateway evaluation.

---

## `CIAF-06` — Mandatory Pre-Execution Governance Gate

- **Title**: Mandatory Pre-Execution Governance Gate
- **Objective**: Guarantee deterministic, fail-closed pre-execution adjudication before any consequential tool side effect can be attempted.
- **Requirement**: Every consequential action proposed by an AI runtime `MUST` be evaluated fail-closed by a separately governed Pre-Execution Governance Gateway holding `gateway_key` (`role: PRE_EXECUTION_GOVERNANCE_GATEWAY`), yielding `ALLOW`, `DENY`, `ESCALATE`, or `INSPECT` (with `INSPECT` resolving only via authorized compliance clearance `INSPECTION_CLEARED` or denial `INSPECTION_BLOCKED`). Non-`ALLOW` outcomes `MUST` set `execution_grant: null`. When blocked at the Gateway without reaching the Execution Service, capsules `MAY` legitimately contain `execution_claims: []`.
- **Minimum Testable Evidence**:
  - Gateway-signed `AuthorizationClaim` (`decision.outcome`, `decision.reason_code`, `decision.evaluated_controls`, `proposed_action.request_digest`, `signature`).
  - Absence of committed side effects (`execution_claims: []` or optional `NOT_ATTEMPTED_GATEWAY_BLOCKED` receipt with `execution.attempted == false`).
- **Audit Test Procedure**:
  1. Verify across sampled `DENY`, `ESCALATE` (pending), and `INSPECT` claims that `execution_grant` is `null` and no downstream execution occurred.
  2. Inject a synthetic non-`ALLOW` claim containing a forged `execution_grant` into `IndependentVerifier` and verify `CIAF-06` failure (`GRANT_ISSUED_ON_NON_ALLOW`).
- **Failure Modes**:
  - Fail-open error handling or advisory post-execution governance ("log now, alert later") allowing irreversible transactions to settle;
  - Treating LLM self-moderation prompts as a governance gate.

---

## `CIAF-07` — Threshold Escalation & Human-in-the-Loop Authorization

- **Title**: Threshold Escalation & Human-in-the-Loop Authorization
- **Objective**: Enforce independently signed human review and approval for proposals exceeding autonomous risk, tool, or monetary thresholds.
- **Requirement**: Proposals with `max_auto_amount_minor_units < amount_minor_units <= escalation_max_amount_minor_units` or invoking `escalate_on_tools` `MUST` emit `decision.outcome == "ESCALATE"` (`human_escalation.status == "PENDING"`, `execution_grant == null`) until an authorized principal in `authorized_human_reviewers` signs `{proposal_id, request_digest, policy_digest, reviewer_id, approved, review_rationale, reviewed_at}` using an independent `HUMAN_REVIEWER` Ed25519 key (`human_escalation.reviewer_signature`), preventing a compromised Gateway from fabricating human approval or silently bypassing `delegated_scope_snapshot` autonomous limits (`UNESCALATED_ALLOW_ABOVE_AUTONOMOUS_LIMIT`).
- **Minimum Testable Evidence**:
  - Initial `AuthorizationClaim` (`outcome: "ESCALATE"`, `human_escalation.status: "PENDING"`).
  - Subsequent hash-linked `AuthorizationClaim` (`outcome: "ALLOW"`, `reason_code: "ESCALATED_HUMAN_APPROVED"`, `human_escalation.status: "APPROVED"`, `reviewer_id`, `review_rationale`, `reviewed_at`, `reviewer_signature` verifiable against a `HUMAN_REVIEWER` OKP JWK).
- **Audit Test Procedure**:
  1. Submit a threshold-exceeding proposal without `human_review` and confirm `ESCALATE` with `execution_grant == null`.
  2. Submit an unsigned or Gateway-key-signed `human_review` (or inject an unescalated Gateway `ALLOW` above `max_auto_amount_minor_units`) and confirm rejection (`INVALID_HUMAN_REVIEW_SIGNATURE` / `FORGED_OR_UNSIGNED_HUMAN_APPROVAL` / `UNESCALATED_ALLOW_ABOVE_AUTONOMOUS_LIMIT`).
  3. Verify complete 3-receipt lineage (`ESCALATE -> ALLOW -> SUCCEEDED`) in the materialized `AuditCapsule`.
- **Failure Modes**:
  - Gateway-attested reviewer strings lacking an independent `HUMAN_REVIEWER` cryptographic signature over `request_digest`;
  - Rubber-stamp approvals lacking `review_rationale` or segregation of duties.

---

## `CIAF-08` — Dual-Key Execution Enforcement & Anti-Replay Binding

- **Title**: Dual-Key Execution Enforcement & Anti-Replay Binding
- **Objective**: Prevent gateway bypass, cross-role forgery, token replay, expired-token execution, and Time-of-Check to Time-of-Use (TOCTOU) payload tampering at the Execution Service boundary.
- **Requirement**: The Execution Service `MUST` hold an independent Ed25519 keypair (`executor_key`, `role: EXECUTION_SERVICE`, distinct from `gateway_key`, `registry_key`, and `reviewer_key`), verify `gateway_grant_signature` against trusted Gateway public keys, enforce short-lived policy-bounded TTLs (`default <= 30s`, bounded by pinned `policy_document.grant_max_ttl_seconds <= 300s`, `issued_at <= now <= expires_at`), consume single-use `nonce` tokens atomically, and verify `observed_request_digest == bound_request_digest` and `bound_policy_digest` equality prior to setting `execution.attempted = true`. Note that offline TTL checks verify chronological consistency across issuer-asserted clocks; defending against compromised-executor clock backdating requires external `RFC 3161` TSA or `IETF SCITT (RFC 9943 / RFC 9942)` timestamps.
- **Minimum Testable Evidence**:
  - `AuditCapsule.public_key_manifest` containing distinct OKP JWK entries for `PRE_EXECUTION_GOVERNANCE_GATEWAY` and `EXECUTION_SERVICE`.
  - `ExecutionClaim` (`authorization_binding.consumed_nonce`, `grant_verification_status`, `action_request.observed_request_digest`, `execution`, `signature`).
- **Audit Test Procedure**:
  1. Execute replay attack (reusing valid grant nonce), TOCTOU attack (`\$450.00 -> \$45,000.00` / `45000 -> 4500000` minor-unit payload mutation), and expired-grant attack (`t0 + 31s`); confirm `execution.attempted == false` and zero committed side effects in all three cases.
  2. Re-sign an `ExecutionClaim` using `gateway_key` and confirm `IndependentVerifier` flags `CIAF-08` (`TRUST_BOUNDARY_KEY_ROLE_VIOLATION`).
- **Failure Modes**:
  - Shared signing key across Gateway and Execution Service;
  - Long-lived bearer tokens (`> 30s` or reusable without nonce consumption);
  - Validating grant presence without recomputing `observed_request_digest` over actual tool arguments (TOCTOU vulnerability).

---

## `CIAF-09` — Append-Only Provenance & Lazy Capsule Materialization

- **Title**: Append-Only Provenance & Lazy Capsule Materialization
- **Objective**: Capture low-latency tamper-evident provenance on the hot path and assemble complete, self-contained `AuditCapsule` packages on demand.
- **Requirement**: Every `AuthorizationClaim` and `ExecutionClaim` `MUST` compute `claim_digest = sha256(JCS(claim_with_signature))` and chain sequentially via `sequence_number` (`0..N-1`) and `previous_receipt_digest`. On-demand `AuditCapsule` bundles `MUST` package the policy snapshot, OKP JWK manifest, `hash_chain` header, ordered claims, and `scitt_transparency` status (explicitly distinguishing local mid-chain tamper detection from IETF SCITT `RFC 9943` / `RFC 9942` COSE Receipt completeness proofs).
- **Minimum Testable Evidence**:
  - `AuditCapsule.hash_chain` (`genesis_receipt_digest`, `tip_receipt_digest`, `receipt_count`, `ordered_receipt_digests`).
  - `previous_receipt_digest` and `claim_digest` across all receipts, plus `scitt_transparency` block and outer `capsule_digest`.
- **Audit Test Procedure**:
  1. Delete or reorder an intermediate receipt in a 3-receipt `ESCALATE` capsule (even after recomputing `capsule_digest`) and verify `IndependentVerifier` flags `CIAF-09` (`HASH_CHAIN_SEQUENCE_GAP_OR_REORDER` / `HASH_CHAIN_BROKEN_LINKAGE`).
  2. Reformat JSON indentation and reverse all object key orders; confirm RFC 8785 digests remain invariant.
- **Failure Modes**:
  - Mutable relational audit tables without hash-chain commitments;
  - Claiming log-completeness guarantees from local hash-chaining alone without external SCITT anchoring.

---

## `CIAF-10` — Stateless Independent Assurance Verification

- **Title**: Stateless Independent Assurance Verification
- **Objective**: Enable auditors and automated verifiers to validate governance and execution integrity offline with zero reliance on runtime state or operator trust.
- **Requirement**: Conformant capsules `MUST` be verifiable by a stateless verifier (`IndependentVerifier`) accepting **only** the `AuditCapsule` JSON and an out-of-band `trusted_keys` OKP JWK manifest. Verification `MUST` execute in strict envelope order: (1) Draft 2020-12 wire JSON Schema validation, (2) `claim_digest` and `capsule_digest` RFC 8785 recomputation, (3) multi-role OKP JWK Ed25519 signature verification over unsigned canonical bodies, and (4) `delegated_scope_snapshot`, policy, TTL, nonce, hash-chain, and semantic invariant checks, producing a schema-valid `AssuranceClaim`.
- **Minimum Testable Evidence**:
  - `AssuranceClaim` (`capsule_valid`, `assurance_disposition`, `checks`, `failed_controls`, `findings`, `completeness_notice`, `claim_digest`).
  - Cleanroom interoperability acceptance proof (an external zero-coupled producer validating cleanly under `IndependentVerifier`).
- **Audit Test Procedure**:
  1. Run `IndependentVerifier` offline on production capsules using auditor-held `trusted_keys`.
  2. Mutate 1 character in `ExecutionClaim` (or inject a rogue Gateway `ALLOW` exceeding `delegated_scope_snapshot`) and verify `capsule_valid == false`, `assurance_disposition == "ASSURANCE_FAILURE_TAMPER_OR_VIOLATION"`, and specific `failed_controls`.
- **Failure Modes**:
  - Verifiers that query mutable runtime databases or trust self-declared keys inside untrusted capsules without cross-checking `trusted_keys`;
  - Test suites that mock cryptographic signature checks.

---

## `CIAF-11` — Bypass Detection, Security Exception Logging & Alerting

- **Title**: Bypass Detection, Security Exception Logging & Alerting
- **Objective**: Deterministically contain runtime security violations and preserve forensic-grade signed exception evidence.
- **Requirement**: Any direct Execution Service call lacking a Gateway grant (`DIRECT_GATEWAY_BYPASS`), invalid grant signature (`GRANT_SIGNATURE_INVALID`), replayed nonce (`GRANT_NONCE_REPLAY`), expired grant (`GRANT_TTL_EXPIRED`), TOCTOU payload mismatch (`TOCTOU_PAYLOAD_TAMPER`), or caller/tool mismatch (`UNAUTHORIZED_CALLER_OR_TOOL`) `MUST` be blocked (`execution.attempted = false`, `execution.executed = false`) and recorded as an Executor-signed `ExecutionClaim` with `status == "REJECTED_SECURITY_EXCEPTION"` and populated `security_exception` metadata.
- **Minimum Testable Evidence**:
  - `ExecutionClaim` with `execution.status == "REJECTED_SECURITY_EXCEPTION"`, `execution.attempted == false`, and `security_exception` (`detected: true`, `control_id`, `exception_code`, `severity`, `detail`).
  - `AssuranceClaim` disposition `ASSURED_SECURITY_EXCEPTION_CONTAINED`.
- **Audit Test Procedure**:
  1. Invoke `ExecutionService.execute()` directly with `execution_grant=None` and verify `DIRECT_GATEWAY_BYPASS` (`control_id: "CIAF-11"`) is signed, appended to the provenance chain, and verified cleanly.
- **Failure Modes**:
  - Silently dropping rejected requests with HTTP 401/403 responses that leave no signed cryptographic forensic trail in the provenance ledger.

---

## `CIAF-12` — Immediate Authority Revocation & Kill-Switch Enforcement

- **Title**: Immediate Authority Revocation & Kill-Switch Enforcement
- **Objective**: Provide an administrative or automated kill-switch halting compromised, drifting, or anomalous agents without code deployment, while bounding or eliminating in-flight grant exposure.
- **Requirement**: The Authority & Policy Registry and Pre-Execution Governance Gateway `MUST` support immediate transition of an `agent_id` or `delegation_id` to `status: "REVOKED"` (recording `revocation_reason` and `revoked_at`). All subsequent Gateway evaluations `MUST` deterministically yield `DENY` (`AUTHORITY_REVOKED`, `execution_grant: null`). Deployments relying on stateless Executor verification retain a bounded residual window (`<= 30s` default grant TTL) for grants issued immediately prior to revocation; high-assurance deployments requiring **zero-window revocation** `MUST` subscribe the Execution Service to a synchronous revocation check (`is_agent_revoked`) blocking unexpired in-flight grants (`AUTHORITY_REVOKED_IN_FLIGHT`).
- **Minimum Testable Evidence**:
  - Registry `DelegationRecord` (`status: "REVOKED"`, `revocation_reason`, `revoked_at`) and signed `AuditCapsule.authority_attestation`.
  - Post-revocation `AuthorizationClaim` (`decision.reason_code: "AUTHORITY_REVOKED"`) and, for in-flight grants under synchronous enforcement, `ExecutionClaim` (`grant_verification_status: "AUTHORITY_REVOKED_IN_FLIGHT"`, `security_exception.control_id: "CIAF-12"`).
- **Audit Test Procedure**:
  1. Invoke `revoke_agent_authority("agent-finance-01", reason=...)`, submit a new `\$200.00` (`20000` minor units) proposal at the Gateway, and confirm `DENY` (`AUTHORITY_REVOKED`).
  2. Mint a valid 30s grant at `t0`, revoke the agent at `t0 + 2s`, present the unexpired grant to the Execution Service at `t0 + 4s`, and confirm `AUTHORITY_REVOKED_IN_FLIGHT` containment with zero committed side effects.
- **Failure Modes**:
  - Cached long-lived OAuth/JWT agent tokens continuing to authorize tool calls for minutes or hours after administrative revocation;
  - Unacknowledged residual TTL windows on high-value payment or clinical rails lacking synchronous in-flight revocation checks;
  - Kill-switches requiring container restarts or CI/CD pipeline redeployments.

