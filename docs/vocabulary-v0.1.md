# CIAF-LCM v0.1 Normative Vocabulary

**Document ID**: `CIAF-LCM-VOCAB-v0.1.1`  
**Status**: Normative Specification (`v0.1.1` — Public Comment Draft through February 10, 2027)  
**License**: Creative Commons Attribution 4.0 International (`CC-BY-4.0` — see [`LICENSE-SPEC`](../LICENSE-SPEC))

---

## 1. Normative Conventions

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `MAY`, and `OPTIONAL` in this document are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in all capitals.

---

## 2. Five-Layer Conceptual Separation

Conformant implementations, schemas, audit procedures, and governance policies `MUST` preserve strict conceptual and structural separation across five distinct layers:

```text
Capability  !=  Authority  !=  Authorization  !=  Execution  !=  Assurance
```

1. **Capability (`What Can Be Formulated or Invoked`)**: The technical ability of an AI model, prompt pipeline, orchestrator, or software connector to construct a tool-call payload or reach a network endpoint. Capability is an engineering property; it `MUST NOT` be interpreted as organizational permission.
2. **Authority (`Standing Organizational Permission Scope`)**: The bounded institutional mandate granted by an accountable human owner through a governed registry, specifying which registered agent identity may propose which operations under which standing constraints.
3. **Authorization (`Specific Pre-Execution Adjudication`)**: The point-in-time determination emitted by a separately governed Pre-Execution Governance Gateway (`ALLOW`, `DENY`, `ESCALATE`, or `INSPECT`) for a single canonical action request under a pinned policy digest, optionally incorporating authenticated human escalation approval.
4. **Execution (`Runtime Enforcement & Side-Effect Outcome`)**: The downstream verification of a short-lived Gateway grant by an independently keyed Execution Service, followed either by the deterministic performance of a consequential side effect or by pre-execution containment and security-exception recording.
5. **Assurance (`Independent Zero-Trust Verification`)**: The reproducible, post-event or continuous cryptographic and semantic verification performed by an independent verifier—holding no shared state or private keys with the runtime—confirming that governance, enforcement, provenance linkage, and transparency invariants held.

Conflating any pair of these layers—such as treating model tool-selection output (`Capability`) as `Authorization`, or treating standing role assignment (`Authority`) as proof of valid runtime grant enforcement (`Execution`)—constitutes a normative non-conformity under CIAF-LCM v0.1.

---

## 3. Core Normative Terms (12 Foundational Definitions)

### 3.1 `Business Purpose`
The documented, legitimate institutional objective justifying the deployment of an automated or agent-assisted workflow. Every registered use case `MUST` record a specific `business_purpose` string inside subject metadata (`AuthorizationClaim.subject.business_purpose`) enabling auditors to evaluate proportionality, regulatory permissibility, and scope drift (`CIAF-01`).

### 3.2 `Use Case`
A uniquely identified operational workflow (`use_case_id`) bounded by a defined `Business Purpose`, data classification, risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), allowed tool surface, and lifecycle status (`ACTIVE`, `SUSPENDED`, `RETIRED`). Consequential agent actions `MUST` bind to an active `use_case_id` prior to runtime invocation (`CIAF-01`).

### 3.3 `Accountable Owner`
An identifiable, active human principal or governed institutional office (`accountable_owner`) holding organizational responsibility and escalation accountability for a `Use Case` and its delegated agents (`CIAF-02`). An AI model, service account, or autonomous agent `MUST NOT` be designated as an `Accountable Owner`.

### 3.4 `Agent Identity`
A unique, non-shared workload identifier (`agent_id`) cryptographically or infrastructurally bound to a specific agent runtime configuration, model profile, and `Use Case` (`CIAF-03`). Shared credentials or anonymous agent invocations `MUST` be rejected by the Pre-Execution Governance Gateway.

### 3.5 `Authority`
The bounded institutional power assigned to an `Agent Identity` to propose specific consequential operations within explicit tool allowlists, domain parameter predicates (`scope_constraints`), high-impact escalation triggers (`escalate_on_tools`), and—where financial value is transferred—exact integer minor-unit or whole-unit ceilings and rolling cumulative velocity caps (`CIAF-04`). `Authority` defines outer standing boundaries; it does not self-authorize individual invocations without Gateway evaluation (`CIAF-06`) and remains subject to administrative or automated revocation (`CIAF-12`).

### 3.6 `Delegation`
The formal, versioned registry record (`delegation_id`) linking an `Accountable Owner`, `Use Case`, `Agent Identity`, and `Policy` (`CIAF-04`), optionally exported into an `AuditCapsule` as a `REGISTRY_AUTHORITY`-signed `authority_attestation`. A `Delegation` `MUST` enumerate domain-neutral least-privilege constraints (`allowed_tools`, optional `scope_constraints`, `escalate_on_tools`, counterparty allowlists/watchlists, and—for monetary tools—exact integer `autonomous_max_amount`, `escalation_max_amount`, optional rolling cumulative velocity caps `rolling_window_max_amount` / `rolling_window_max_count`, and `allowed_currencies`) and `MUST` record lifecycle status (`ACTIVE`, `REVOKED`, `SUSPENDED`).

### 3.7 `Policy`
A deterministic, versioned governance rule specification (`policy_id`, `policy_version`, `policy_document`) serialized per RFC 8785 (JSON Canonicalization Scheme) and identified by an immutable SHA-256 `policy_digest` (`sha256:<64-lowercase-hex>`, `CIAF-05`). Both `AuthorizationClaim` and `ExecutionClaim` records `MUST` bind to the active `policy_digest`.

### 3.8 `Governance Gate`
The mandatory, fail-closed architectural interception boundary—implemented by a separately governed **Pre-Execution Governance Gateway** holding an independent Ed25519 keypair (`role: PRE_EXECUTION_GOVERNANCE_GATEWAY`)—positioned between an untrusted AI/Agent Runtime proposal and any consequential downstream Execution Service (`CIAF-06`).

### 3.9 `Authorization Decision`
The deterministic evaluation result (`outcome` in `["ALLOW", "DENY", "ESCALATE", "INSPECT"]`, paired with `reason_code`, `rationale`, `evaluated_controls`, and—where threshold or tool escalation applies under `CIAF-07`—an independent `HUMAN_REVIEWER` cryptographic signature `reviewer_signature` bound to `request_digest` and `policy_digest`) encapsulated in a Gateway-signed `AuthorizationClaim`. When and only when `outcome == "ALLOW"`, the `Authorization Decision` includes a short-lived (`<= 30s` default TTL, bounded by `policy_document.grant_max_ttl_seconds <= 300s`), single-use `nonce`, digest-bound `execution_grant`.

### 3.10 `Execution Evidence`
The signed receipt (`ExecutionClaim`) emitted exclusively by the downstream Execution Service using its independent Ed25519 keypair (`role: EXECUTION_SERVICE`, `CIAF-08`) whenever an action reaches the Execution Service boundary. `Execution Evidence` records the freshly computed `observed_request_digest`, grant verification status (`grant_verification_status`), whether the consequential tool handler was `attempted` and `executed`, committed result digests, or contained security exceptions (`CIAF-11`, `CIAF-12`). Proposals blocked upstream at the Gateway (`DENY`, pending `ESCALATE`, or pending `INSPECT`) that never reach the Execution Service `MAY` materialize with `execution_claims: []`.

### 3.11 `Evidence Provenance`
The cryptographic lineage connecting registry authority attestations, governance policies, `AuthorizationClaim` records, and `ExecutionClaim` records across time via RFC 8785 canonicalization, enveloped Ed25519 signatures, sequential `previous_receipt_digest` SHA-256 hash-chaining, lazy `AuditCapsule` materialization (`CIAF-09`), high-entropy salted or HMAC commitments for regulated payloads, and optional registration in an **IETF SCITT (RFC 9943)** Transparency Service for verifiable non-omission and trusted timestamping.

### 3.12 `Assurance`
The formal, reproducible confidence determination (`AssuranceClaim`) produced by a zero-trust independent verifier (`CIAF-10`) operating solely over a materialized `AuditCapsule` and an out-of-band trusted OKP JWK public key manifest (`PRE_EXECUTION_GOVERNANCE_GATEWAY`, `EXECUTION_SERVICE`, and where applicable `REGISTRY_AUTHORITY`, `HUMAN_REVIEWER`, and `ASSURANCE_VERIFIER`), establishing whether governance design and runtime controls operated without tampering, key-role violation, replay, or unauthorized execution.

