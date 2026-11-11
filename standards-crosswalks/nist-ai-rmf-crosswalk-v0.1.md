# NIST AI Risk Management Framework (AI RMF 1.0) Crosswalk — CIAF-LCM v0.1

**Document ID**: `CIAF-LCM-XWALK-NIST-v0.1`  
**Target Standard Version**: NIST Artificial Intelligence Risk Management Framework 1.0 (`NIST AI 100-1`, January 2023)  
**Status**: Normative Standards Crosswalk (`v0.1.1` — Public Comment Draft through February 10, 2027)  
**License**: Creative Commons Attribution 4.0 International (`CC-BY-4.0` — see [`LICENSE-SPEC`](../LICENSE-SPEC))

---

## 1. Versioning, Revision Context & Non-Endorsement Notice

1. **Versioned Functional Alignment**: All mappings in this crosswalk represent versioned functional and subcategory alignments to **NIST AI RMF 1.0 (`NIST AI 100-1`)**.
2. **Active Revision Lifecycle**: Practitioners and assessors `MUST` note that **NIST AI RMF 1.0 is undergoing revision** (alongside companion profiles for generative and agentic AI). Future minor releases of CIAF-LCM will publish version-pinned delta crosswalks as revised NIST AI RMF publications reach final status.
3. **Non-Endorsement**: CIAF-LCM is an independent, community-maintained open specification. Nothing in this document claims or implies that any system implementing CIAF-LCM is "NIST-approved," "NIST-certified," or endorsed by the National Institute of Standards and Technology.
4. **Scope Boundary**: NIST AI RMF 1.0 addresses enterprise-wide socio-technical AI risk (including dataset bias, model training lifecycle, workforce diversity, and societal impact), whereas CIAF-LCM specifically governs **consequential runtime authorization, dual-key execution boundaries, and cryptographic audit provenance**.

---

## 2. Four-Function Subcategory Mapping (`GOVERN`, `MAP`, `MEASURE`, `MANAGE`)

### 2.1 `GOVERN` Function

| Requirement / Subcategory (NIST AI RMF 1.0) | CIAF-LCM Control | Minimum Evidence | Relationship [`Direct` / `Partial` / `Supportive`] & Limitations |
| :--- | :--- | :--- | :--- |
| **GOVERN 1.2**: The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices. | `CIAF-05`, `CIAF-06` | `AuditCapsule.policy_snapshot` (`policy_id`, `policy_version`, `policy_document`, RFC 8785 `policy_digest`); Gateway-signed `AuthorizationClaim`. | **Partial** — Directly operationalizes executable tool-governance policies with cryptographic digest pinning; does not cover enterprise-wide HR, procurement, or model-training policies. |
| **GOVERN 1.4**: The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities. | `CIAF-01`, `CIAF-04`, `CIAF-05` | Registry `UseCaseRecord` (`risk_tier`), `DelegationRecord` (`autonomous_max_amount`, `escalation_max_amount`), and pinned `policy_digest`. | **Supportive** — Translates risk tiers into machine-enforced delegation thresholds; broader enterprise risk-appetite charters remain an organizational governance responsibility. |
| **GOVERN 1.5**: Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities are clearly defined. | `CIAF-02`, `CIAF-09`, `CIAF-10` | `UseCaseRecord.accountable_owner`; lazily materialized `AuditCapsule`; offline `AssuranceClaim`. | **Partial** — Provides continuous cryptographic auditability and named owner attribution; periodic board/committee review cadence requires procedural evidence outside runtime receipts. |
| **GOVERN 1.7**: Processes and procedures are in place for decommissioning and phasing out AI systems safely and in a manner that does not increase risks. | `CIAF-01`, `CIAF-12` | `DelegationRecord` (`status: "REVOKED"`, `revocation_reason`, `revoked_at`); `AuthorizationClaim` (`reason_code: "AUTHORITY_REVOKED"`). | **Direct (Runtime Decommissioning)** — Enforces immediate runtime authority kill-switch without redeployment; data archival and contractual retirement procedures remain external. |
| **GOVERN 2.1**: Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization. | `CIAF-02`, `CIAF-07` | `AuthorizationClaim.subject.accountable_owner`; `AuthorizationClaim.human_escalation` (`reviewer_id`, `review_rationale`, `reviewed_at`). | **Partial** — Cryptographically binds accountable owners and authorized human escalation reviewers into runtime decisions; organizational RACI charts and training records are out of scope. |
| **GOVERN 6.2**: Contingency processes are in place to handle failures or incidents in third-party data or AI systems deemed to be high-risk. | `CIAF-06`, `CIAF-11`, `CIAF-12` | `ExecutionClaim` (`status: "REJECTED_SECURITY_EXCEPTION"`, `security_exception`); post-revocation `DENY` receipts (`CIAF-12`). | **Supportive** — Contains compromised third-party models/agents at the Gateway and Executor boundaries before side effects settle; vendor contract SLAs are external. |

---

### 2.2 `MAP` Function

| Requirement / Subcategory (NIST AI RMF 1.0) | CIAF-LCM Control | Minimum Evidence | Relationship [`Direct` / `Partial` / `Supportive`] & Limitations |
| :--- | :--- | :--- | :--- |
| **MAP 1.1**: Intended purposes, potentially beneficial uses, context-specific laws, norms and expectations, and prospective settings in which the AI system will be deployed are understood and documented. | `CIAF-01` | `UseCaseRecord` (`use_case_id`, `business_purpose`, `risk_tier`); `AuthorizationClaim.subject.business_purpose`. | **Partial** — Enforces mandatory machine-readable `business_purpose` binding on every runtime claim; upstream legal/stakeholder impact assessments require documentary review. |
| **MAP 2.1**: The specific tasks and methods used to implement the tasks that the AI system will support are defined. | `CIAF-03`, `CIAF-04` | `AgentIdentityRecord` (`workload_id`, `model_profile`); `DelegationRecord.allowed_tools` and parameter bounds. | **Direct (Tool Surface Scoping)** — Explicitly enumerates permitted tools (e.g., `payments.create`), currencies, and beneficiaries while blocking undeclared capabilities (`TOOL_NOT_ALLOWED`). |
| **MAP 3.4**: Processes for operator and practitioner proficiency with AI system performance and trustworthiness—and relevant technical standards and certifications—are defined, assessed, and documented. | `CIAF-07` | `DelegationRecord.authorized_human_reviewers`; `AuthorizationClaim` (`UNAUTHORIZED_HUMAN_REVIEWER` rejection vs. `ESCALATED_HUMAN_APPROVED`). | **Supportive** — Restricts human escalation adjudication to designated authorized reviewers; reviewer training and competency assessment records reside in HR/LMS systems. |
| **MAP 3.5**: Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function. | `CIAF-06`, `CIAF-07` | Hash-chained `ESCALATE -> ALLOW` `AuthorizationClaim` pair with `human_escalation.status == "APPROVED"` and `review_rationale`. | **Direct (Pre-Execution Oversight)** — Provides non-repudiable cryptographic proof that human-in-the-loop review occurred *prior* to grant issuance on threshold-exceeding actions. |

---

### 2.3 `MEASURE` Function

| Requirement / Subcategory (NIST AI RMF 1.0) | CIAF-LCM Control | Minimum Evidence | Relationship [`Direct` / `Partial` / `Supportive`] & Limitations |
| :--- | :--- | :--- | :--- |
| **MEASURE 2.6**: The AI system is evaluated regularly for safety risks—as identified in the MAP function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not exceed the risk tolerance, and it can fail safely, particularly if made to operate beyond its knowledge limits. | `CIAF-04`, `CIAF-06`, `CIAF-08`, `CIAF-11` | `AuthorizationClaim` (`AUTHORITY_SCOPE_EXCEEDED`); `ExecutionClaim` (`execution.attempted == false`, `REJECTED_SECURITY_EXCEPTION`). | **Partial (Fail-Closed Consequential Safety)** — Proves fail-closed containment when an agent proposes out-of-scope or tampered actions; does not measure model hallucination rates, toxicity, or statistical accuracy. |
| **MEASURE 2.7**: AI system security and resilience—as identified in the MAP function—are evaluated and documented. | `CIAF-08`, `CIAF-10`, `CIAF-11` | Adversarial `pytest` verification suite outputs (`DIRECT_GATEWAY_BYPASS`, `GRANT_NONCE_REPLAY`, `TOCTOU_PAYLOAD_TAMPER`, `GRANT_TTL_EXPIRED`); `AssuranceClaim`. | **Direct (Execution Boundary Security)** — Directly tests and proves cryptographic resistance against bypass, replay, TOCTOU mutation, key forgery, and receipt tampering. |
| **MEASURE 2.8**: Risks associated with transparency and accountability—as identified in the MAP function—are examined and documented. | `CIAF-09`, `CIAF-10` | `AuditCapsule` (`hash_chain`, `scitt_transparency`); `AssuranceClaim` (`checks`, `completeness_notice`). | **Direct (Operational Provenance & Auditability)** — Provides deterministic RFC 8785 + Ed25519 provenance and SCITT completeness profiling; does not address model weight interpretability/explainability. |
| **MEASURE 4.1**: Measurement approaches for identifying AI risks are connected to deployment context(s) and informed by consultations with relevant AI actors, including affected communities. | `CIAF-10` | Regulated readiness scorecards (`Control Maturity` vs. `Evidence Confidence`) across Healthcare, Banking, and Tribal Gaming profiles. | **Supportive** — Connects technical verification metrics to sector-specific audit thresholds; external community consultation processes remain out of scope. |

---

### 2.4 `MANAGE` Function

| Requirement / Subcategory (NIST AI RMF 1.0) | CIAF-LCM Control | Minimum Evidence | Relationship [`Direct` / `Partial` / `Supportive`] & Limitations |
| :--- | :--- | :--- | :--- |
| **MANAGE 1.3**: Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and implemented. Risk response options can include mitigating, transferring, avoiding, or accepting. | `CIAF-06`, `CIAF-07`, `CIAF-08` | Gateway outcomes (`ALLOW`, `DENY`, `ESCALATE`, `INSPECT`); `<= 30s` single-use `ExecutionGrant`. | **Partial** — Implements deterministic technical risk mitigation and avoidance at pre-execution and execution gates; risk transfer (insurance/indemnity) is out of scope. |
| **MANAGE 2.4**: Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use. | `CIAF-11`, `CIAF-12` | `DelegationRecord` (`status: "REVOKED"`); immediate post-revocation `AuthorizationClaim` (`AUTHORITY_REVOKED`); `ExecutionClaim` (`execution.attempted == false`). | **Direct** — Directly implements immediate administrative/SOC disengagement (`CIAF-12`) with cryptographic proof that post-revocation proposals cannot obtain execution grants. |
| **MANAGE 4.1**: Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, and recovery. | `CIAF-09`, `CIAF-10`, `CIAF-11` | Append-only ledger receipts; on-demand incident `AuditCapsule` bundles; `CIAF-11` `security_exception` alerts; `AssuranceClaim`. | **Partial** — Supplies tamper-evident forensic capsules and contained-attack receipts for incident response; end-user appeal workflows and recovery playbooks require complementary operational procedures. |

