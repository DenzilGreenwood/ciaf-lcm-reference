# CIAF-LCM v0.1 Audit Readiness Methodology & Regulated Industry Profiles

**Document ID**: `CIAF-LCM-AUDIT-v0.1.1`  
**Status**: Normative Methodology (`v0.1.1` — Public Comment Draft through February 10, 2027)  
**License**: Creative Commons Attribution 4.0 International (`CC-BY-4.0` — see [`LICENSE-SPEC`](../LICENSE-SPEC))

---

## 1. Purpose & Assessment Principles

Organizations deploying AI and agentic workflows often accumulate written AI ethics charters and policy binders while lacking cryptographic proof that runtime tool calls actually obeyed those policies. The **CIAF-LCM Audit Readiness Methodology** equips internal audit, external assessors, risk committees, and regulatory examiners to evaluate consequential AI governance without conflating policy prose with runtime enforcement.

Every assessment `MUST` evaluate three distinct evidentiary dimensions for each control (`CIAF-01` through `CIAF-12`):

1. **Control Design Adequacy (`CDA`)**: Are the authority boundaries, policy schemas, cryptographic trust separations, and escalation rules formally specified and architecturally capable of preventing unauthorized side effects before execution?
2. **Operating Effectiveness (`OE`)**: Did the Pre-Execution Governance Gateway and Execution Service consistently enforce those controls across sampled production windows and adversarial fault-injection tests (bypass, replay, TOCTOU mutation, expired TTL, emergency revocation)?
3. **Evidence Reliability (`ER`)**: Is audit evidence generated deterministically at the enforcement boundary using RFC 8785 canonicalization, dual-key Ed25519 signatures, append-only hash-chaining, and stateless independent verification—rather than mutable application logs or self-reported model outputs?

---

## 2. Six-Step Assessment Lifecycle

```mermaid
flowchart LR
    S1["Step 1: Inventory & Boundary Scoping"] --> S2["Step 2: Control Design Adequacy"]
    S2 --> S3["Step 3: Dual-Key Boundary Inspection"]
    S3 --> S4["Step 4: Lazy Capsule Sampling"]
    S4 --> S5["Step 5: Adversarial Fault Testing"]
    S5 --> S6["Step 6: 2-Axis Scoring & Gates"]
```

### Step 1 — Consequential Surface Inventory & Boundary Scoping
Enumerate all AI/agentic workflows capable of invoking state-changing tools, external APIs, financial disbursements, clinical orders, or regulated record mutations. Verify that every consequential workflow maps to a registered `use_case_id`, `business_purpose`, and human `accountable_owner` (`CIAF-01`, `CIAF-02`), and delineate the network/credential boundary separating the untrusted agent runtime from downstream Execution Services.

### Step 2 — Control Design Adequacy (`CDA`) Review
Inspect the Authority & Policy Registry schemas, `policy_document` rules, delegation ceilings (`autonomous_max_amount` / `max_auto_amount_minor_units`, `escalation_max_amount` / `escalation_max_amount_minor_units`), ISO-4217 integer minor-unit rules (`amount_minor_units`, `currency`, `minor_unit_scale`), Gateway-embedded `delegated_scope_snapshot` constraints, human reviewer separation-of-duties rules (`CIAF-04`, `CIAF-05`, `CIAF-07`), and emergency revocation runbooks (`CIAF-12`). Confirm that model outputs are never consumed directly as execution permissions (`CIAF-06`).

### Step 3 — Cryptographic & Dual-Key Trust-Boundary Inspection
Examine HSM/KMS or workload key-management configurations to confirm that `gateway_key` (`role: PRE_EXECUTION_GOVERNANCE_GATEWAY`) and `executor_key` (`role: EXECUTION_SERVICE`) are generated, stored, and used in separate security domains (`CIAF-08`). Export the out-of-band trusted OKP JWK manifest (`kty: "OKP"`, `crv: "Ed25519"`, `x`) directly from governance custody—never from the untrusted runtime.

### Step 4 — Historical Population Sampling & Stateless Capsule Verification (`OE` + `ER`)
Construct the audit sampling frame (`workflow_trace_id` population) from an **independent downstream system-of-record**—such as the core payment settlement ledger, EHR/ERP transaction journal, or **IETF SCITT (`RFC 9943`)** Transparency Service log—rather than relying solely on an operator-supplied trace list, preventing undetected whole-trace suppression. Select a stratified sample across normal `ALLOW`, out-of-scope `DENY`, threshold `ESCALATE`, `INSPECT`, security-exception (`CIAF-11`), and `REVOKED` events. Materialize `AuditCapsule` bundles on demand (`CIAF-09`), reconcile every downstream settled side effect back to a verified `ExecutionClaim`, and run an offline Stateless Independent Verifier (`CIAF-10`) using only the sampled capsules and the Step 3 trusted key manifest. Assess whether IETF SCITT inclusion receipts (`RFC 9943` / `RFC 9942` COSE Receipts) or external `RFC 3161` Time-Stamp Authority (TSA) tokens are present to prove log completeness and independent wall-clock time beyond issuer-asserted clocks.

### Step 5 — Adversarial Boundary & Fault-Injection Testing (`OE`)
Execute active negative security tests in staging or controlled production-equivalent environments:
- Direct Execution Service invocation without a Gateway grant (`CIAF-11`);
- Single-use `nonce` replay within the `<= 30s` TTL window (`CIAF-08`);
- Post-approval TOCTOU parameter mutation (`request_digest` vs. `observed_request_digest`, `CIAF-08`);
- Expired grant presentation after `expires_at` (`CIAF-08`);
- Rogue or misconfigured Gateway `ALLOW` exceeding `delegated_scope_snapshot` ceilings without human escalation (`CIAF-04`, `CIAF-06`, `CIAF-07`);
- Single-byte receipt tampering, intermediate hash-chain deletion, and cross-role key forgery (`CIAF-09`, `CIAF-10`);
- Live `CIAF-12` agent revocation latency verification.

### Step 6 — Two-Axis Rubric Scoring & Critical-Failure Override Determination
Assign integer `0–4` scores to each of the twelve controls (`CIAF-01` through `CIAF-12`), compute both disjoint axis aggregates (`Axis A` over 10 controls and `Axis B` over 2 controls), apply mandatory **Critical-Failure Override Gates**, and issue one of the four normative Readiness Dispositions.

---

## 3. Two-Axis Scoring Rubric, Disjoint Control Partition & Override Rules

CIAF-LCM prohibits single-number maturity averages or blended percentages that mask weak runtime enforcement behind comprehensive policy documentation. Assessors `MUST` score each control (`CIAF-01` through `CIAF-12`) on an integer `0–4` scale and partition the twelve controls strictly across two disjoint axes:

- **Axis A — Control Design & Runtime Maturity (`10` controls: `CIAF-01`, `CIAF-02`, `CIAF-03`, `CIAF-04`, `CIAF-05`, `CIAF-06`, `CIAF-07`, `CIAF-08`, `CIAF-11`, `CIAF-12`)**:
  - `rawAxisAMean = round_2dp((CIAF-01 + CIAF-02 + CIAF-03 + CIAF-04 + CIAF-05 + CIAF-06 + CIAF-07 + CIAF-08 + CIAF-11 + CIAF-12) / 10)`
  - `axisAMin = min(CIAF-01..08, CIAF-11..12)`
  - Axis B controls (`CIAF-09`, `CIAF-10`) `MUST NEVER` be included in Axis A's numerator or denominator.
- **Axis B — Evidence Provenance & Verification Confidence (`2` controls: `CIAF-09`, `CIAF-10`)**:
  - `rawAxisBMean = round_2dp((CIAF-09 + CIAF-10) / 2)`
  - `axisBMin = min(CIAF-09, CIAF-10)`

### 3.1 Axis A: Control Design & Runtime Maturity (`0–4`)

| Score | Level | Normative Criteria |
| :---: | :--- | :--- |
| **0** | **Non-Existent** | Agent invokes consequential tools directly from model output; no registry, policy pinning, or pre-execution gateway exists. |
| **1** | **Ad-Hoc / Prompt-Only** | Guardrails rely on system prompts, LLM self-critique, or advisory application wrappers without hard cryptographic gateway enforcement (`Capability` conflated with `Authorization`). |
| **2** | **Defined & Partially Enforced** | Pre-Execution Governance Gateway mediates primary flows, but lacks single-use `nonce` anti-replay, `request_digest` TOCTOU binding, or independent dual-key separation. |
| **3** | **Deterministically Enforced** | Full `CIAF-01`–`CIAF-08` and `CIAF-11`–`CIAF-12` enforcement active: separate Gateway/Executor/Reviewer/Registry Ed25519 keys, `<= 30s` default policy-bounded grants, signed `delegated_scope_snapshot` bounds, signed human escalation, ISO-4217 integer minor currency units (`amount_minor_units`, `currency`, `minor_unit_scale`), bypass logging, and Gateway revocation. |
| **4** | **Continuously Assured** | Level 3 enforcement augmented with automated CI/CD adversarial fault-injection regression gates, hardware-backed HSM/WebAuthn key isolation, rolling cumulative velocity caps, and synchronous zero-window in-flight revocation (`AUTHORITY_REVOKED_IN_FLIGHT`). |

### 3.2 Axis B: Evidence Provenance & Verification Confidence (`0–4`)

| Score | Level | Normative Criteria |
| :---: | :--- | :--- |
| **0** | **Unverifiable** | Only unstructured text logs or mutable database rows exist; no canonical digests or digital signatures. |
| **1** | **Operator-Asserted or Shared-Key Logs** | Structured JSON telemetry exists (or receipts share signing keys across Gateway and Executor, triggering Critical Gate 2); operator or compromised component can forge or alter records without cross-role detection. |
| **2** | **Role-Separated Unchained Receipts** | Gateway and Executor sign individual receipts with distinct keys, but JSON is hashed without RFC 8785 canonicalization or receipts lack `previous_receipt_digest` hash-chain linkage. |
| **3** | **Stateless Multi-Role Capsules** | Lazily materialized `AuditCapsule` bundles pass offline Draft 2020-12 schema validation, RFC 8785 digest checks, role-pinned OKP JWK signature verification (`Gateway`, `Executor`, `Human Reviewer`, `Registry`), `delegated_scope_snapshot` verification, and local hash-chain checks (`CIAF-09`, `CIAF-10`). |
| **4** | **Externally Complete & Timestamped (SCITT)** | Level 3 capsules registered in an independent **IETF SCITT (`RFC 9943`)** Transparency Service with verifiable **COSE Receipts (`RFC 9942`)** and external trusted timestamps (`RFC 3161` TSA or SCITT registration time) proving non-omission and independent wall-clock ordering. |

### 3.3 Mandatory Critical-Failure Override Gates

High policy documentation scores `MUST NOT` compensate for broken enforcement or unverifiable evidence. Starting from `effectiveAxisAMaturity = rawAxisAMean` and `effectiveAxisBConfidence = rawAxisBMean`, assessors `MUST` evaluate four deterministic override gates:

1. **Critical Gate 1 — Pre-Execution or Executor Bypass Exposure (`CIAF-06 <= 1` OR `CIAF-08 <= 1`)**: If either `CIAF-06` (Mandatory Pre-Execution Governance Gate) or `CIAF-08` (Dual-Key Executor & Anti-Replay Binding) scores `<= 1` (`CIAF-07` is evaluated separately and is not part of Gate 1), `effectiveAxisAMaturity` is capped at **`1.00 / 4`** and the Readiness Disposition is forced to **`NOT_AUDIT_READY`**, even if all governance and policy controls (`CIAF-01`–`CIAF-05`) score `4/4`.
2. **Critical Gate 2 — Unverifiable, Mutable, or Shared-Key Evidence (`CIAF-09 <= 1` OR `CIAF-10 <= 1` OR `sharedSigningKeysDetected`)**: If `CIAF-09 <= 1`, `CIAF-10 <= 1`, or any two trust roles share signing key material (`TRUST_BOUNDARY_KEY_ROLE_VIOLATION`), `effectiveAxisBConfidence` is capped at **`1.00 / 4`** and the Readiness Disposition is forced to **`NOT_AUDIT_READY`**.
3. **Critical Gate 3 — Unowned Risk or Missing Revocation Kill-Switch (`CIAF-02 == 0` OR `CIAF-12 <= 1`)**: If any production agent lacks a named human `accountable_owner` (`CIAF-02 == 0`) or cannot be revoked immediately without code redeployment (`CIAF-12 <= 1`), `effectiveAxisAMaturity` is capped at **`1.00 / 4`** and the Readiness Disposition is forced to **`NOT_AUDIT_READY`**.
4. **Critical Gate 4 — External Completeness & Trusted-Time Cap (`CIAF-09`, `!scittRegistered`)**: Without external anchoring via an **IETF SCITT (`RFC 9943` / `RFC 9942`)** inclusion receipt and independent external timestamping, `effectiveAxisBConfidence` `MUST` be capped at **`3.00 / 4`** (local hash-chaining proves mid-chain integrity, not absence of tail truncation or colluding clock backdating).

### 3.4 Normative Readiness Dispositions

Assessors and automated scoring tools `MUST` emit one of four exact Readiness Dispositions evaluated in strict precedence order (without averaging Axis A and Axis B together):

| Precedence | Normative Disposition | Deterministic Trigger Condition |
| :---: | :--- | :--- |
| **1** | `NOT_AUDIT_READY` | Critical Gate 1, Critical Gate 2, or Critical Gate 3 is triggered. |
| **2** | `CONDITIONAL_REMEDIATION_REQUIRED` | No Critical Gate 1–3 triggered, AND (`min(effectiveAxisAMaturity, effectiveAxisBConfidence) < 3.00` OR any individual control `CIAF-01..12 < 2`). |
| **3** | `AUDIT_READY_LOCAL_PROVENANCE` | Both effective axes `>= 3.00` and all 12 controls `>= 2`, WITHOUT IETF SCITT (`RFC 9943` / `RFC 9942`) registration + external trusted timestamping (Effective Axis B capped at `3.00 / 4` per Gate 4). |
| **4** | `AUDIT_READY_VERIFIABLE_COMPLETENESS` | Both effective axes `>= 3.00`, all 12 controls `>= 2`, AND IETF SCITT (`RFC 9943` / `RFC 9942`) inclusion receipts + independent external timestamps are verified. |

---

## 4. Regulated Industry Readiness Profiles

> **Scope & Legal Counsel Notice**: The industry profiles below map CIAF-LCM v0.1 technical controls to illustrative regulatory and supervisory expectations to support engineering and internal-audit readiness. Regulatory citations do not constitute legal advice or a claim of standalone statutory compliance; adopting organizations `SHOULD` validate specific jurisdictional, compact, and supervisory requirements with qualified legal and compliance counsel.

### 4.1 Profile A: Healthcare Systems (HIPAA ePHI & Clinical Escalation)

#### Regulatory Context
Covered entities and business associates deploying AI agents that access, summarize, route, or mutate electronic Protected Health Information (ePHI) or propose clinical/revenue-cycle actions operate under the **HIPAA Security Rule (`45 CFR Part 164, Subpart C`)** and **HIPAA Privacy Rule (`45 CFR § 164.502(b)` Minimum Necessary)**.

#### Technical Control Alignment
- **Access Control & Minimum Necessary (`45 CFR § 164.312(a)(1)` & `§ 164.502(b)` -> `CIAF-01`, `CIAF-03`, `CIAF-04`, `CIAF-06`)**: Domain-neutral agent delegations (`scope_constraints`, `allowed_tools`) `MUST` restrict clinical or revenue-cycle parameters to the minimum dataset required for the registered `business_purpose` (e.g., prior-authorization packet assembly vs. unrestricted EHR chart export).
- **Clinical & High-Impact Escalation (`CIAF-07`)**: Any agent-proposed action affecting clinical order entry (`escalate_on_tools`), care-plan modification, discharge disposition, or claim denial `MUST` trigger `ESCALATE`, requiring an independent `HUMAN_REVIEWER` cryptographic signature (`reviewer_signature`) from a licensed clinician or compliance reviewer bound to `request_digest` prior to `ExecutionGrant` issuance.
- **Audit Controls, Salted Commitments & Integrity (`45 CFR § 164.312(b)`, `§ 164.312(c)(1)` -> `CIAF-08`, `CIAF-09`, `CIAF-10`)**: Because unsalted SHA-256 hashes over low-entropy clinical identifiers (such as MRNs, dates of birth, or ICD-10 codes) are susceptible to dictionary brute-force, externalized digests registered in SCITT transparency logs `MUST` use `>= 128-bit` salted commitments (`jcs_salted_commitment`) or keyed `HMAC-SHA256` commitments (`jcs_hmac_sha256`), keeping salts/keys and raw ePHI strictly inside HIPAA-access-controlled vaults.
- **Emergency Access & Synchronous Termination (`§ 164.308(a)(3)(ii)(C)` -> `CIAF-12`)**: Compromised or anomalous clinical/billing agents `MUST` be revocable immediately via `CIAF-12`, with synchronous `is_agent_revoked` feeds recommended on EHR Execution Services to eliminate residual TTL windows.

---

### 4.2 Profile B: Regional Banking & Financial Services

#### Regulatory & 2026 Supervisory Scope Notice
> **Important Supervisory Scope Note (April 17, 2026 Interagency Model Risk Guidance & Third-Party Risk Management)**:
> 1. **MRM Scope & Forthcoming AI RFI (`SR 26-2` / `OCC Bulletin 2026-13` / `FDIC FIL-15-2026`)**: On **April 17, 2026**, the Federal Reserve, OCC, and FDIC issued revised interagency model risk management (MRM) guidance (**Federal Reserve SR 26-2**, **OCC Bulletin 2026-13**, and **FDIC FIL-15-2026**), rescinding and superseding `SR 11-7`, `OCC Bulletin 2011-12`, `FDIC FIL-22-2017`, and the 2021 BSA/AML MRM statements (`SR 21-8`, `OCC Bulletin 2021-19`, `FDIC FIL-27-2021`). The April 17, 2026 guidance characterizes generative AI and agentic AI systems as *"novel and rapidly evolving"* and **explicitly excludes generative and agentic AI from direct MRM scope pending forthcoming interagency AI guidance and the Request for Information (RFI)** announced concurrently by the agencies. This exclusion is **not** a supervisory safe harbor: institutions `MUST` govern consequential AI and agentic workflows through broader safety-and-soundness risk programs—specifically operational risk controls, payment authorization boundaries, segregation of duties, IT/cybersecurity safeguards, and BSA/AML compliance.
> 2. **Third-Party Risk Management (`SR 23-4` / `OCC 2023-17` / `FIL-29-2023` & `91 FR 58536`)**: For external foundation models, hosted agent APIs, and third-party guardrails, the **June 2023 Interagency Guidance on Third-Party Relationships** (`SR 23-4` / `OCC Bulletin 2023-17` / `FDIC FIL-29-2023`) **remains in effect** while its proposed replacement—jointly issued by the **OCC, Federal Reserve, FDIC, and NCUA on September 11, 2026** and published in the Federal Register (`91 FR 58536`, Sept. 15, 2026; `OCC Bulletin 2026-46` — pending finalization)—awaits final agency action.

#### Technical Control Alignment
- **ISO-4217 Integer Minor Units, Dual Control & Velocity Caps (`CIAF-04`, `CIAF-06`, `CIAF-07`)**: Treasury, wire/ACH initiation, fee-waiver, and commercial-payables agents (`payments.create`) `MUST` represent monetary values as exact ISO-4217 integers (`amount_minor_units`, `currency`, `minor_unit_scale`—for example `45000`, `"USD"`, `2` for `\$450.00`—rejecting bare `"amount"` fields and IEEE-754 floats), bind Gateway `delegated_scope_snapshot` ceilings (`max_auto_amount_minor_units`, `escalation_max_amount_minor_units`), enforce rolling cumulative velocity caps (`rolling_window_max_amount`, `rolling_window_max_count`) to prevent split-payment structuring (`100 x \$499`), and require `HUMAN_REVIEWER`-signed officer adjudication (`CIAF-07`) where `reviewer_id != accountable_owner` for high-value settlements.
- **BSA/AML & Sanctions Pre-Execution Screening (`CIAF-06` `INSPECT` / `DENY`)**: Proposals involving watchlist or high-risk counterparties (`inspection_watchlist_beneficiaries`) or cumulative velocity anomalies `MUST` deterministically return `INSPECT` (`INSPECTION_REQUIRED`, resolved only via authorized `INSPECTION_CLEARED` / `INSPECTION_BLOCKED`) or `DENY` at the Pre-Execution Governance Gateway (`execution_grant: null`) prior to payment rail submission.
- **Anti-Replay & Wire Mutation Prevention (`CIAF-08`, `CIAF-11`)**: Payment Execution Services `MUST` enforce `<= 30s` default grant TTLs, single-use `nonce` consumption, and `observed_request_digest` verification so a prompt-injected agent cannot obtain approval for a `\$450.00` (`45000` minor units) vendor invoice and mutate beneficiary routing numbers or settlement amounts (`\$45,000.00` / `4500000` minor units) on execution.

---

### 4.3 Profile C: Tribal Gaming Operations (NIGC MICS / TICS & Compact Governance)

#### Regulatory Context
Tribal gaming enterprises operate under a multi-layered sovereign regulatory framework governed by the **Indian Gaming Regulatory Act (IGRA)**, **National Indian Gaming Commission (NIGC) Minimum Internal Control Standards (MICS — `25 CFR Part 543` for Class II gaming)**, Tribal Gaming Regulatory Authority (**TGRA**) **Tribal Internal Control Standards (TICS)**, and—for **Class III gaming** (slot machines, banked table games, sports wagering where compacted)—specific **Tribal-State Gaming Compacts**.

#### Class II vs. Class III Considerations & Technical Alignment
- **Jurisdictional Scope Separation (`CIAF-01`, `CIAF-04`, `CIAF-05`)**: Registry `use_case_id` and `policy_document` records `MUST` explicitly classify whether an AI-assisted workflow touches **Class II** systems (`25 CFR Part 543` MICS + TGRA TICS), **Class III** compacted gaming systems (subject to compact technical standards and state/tribal co-inspection provisions), or uncompacted hospitality marketing—preventing cross-domain privilege bleed.
- **Cage, Vault, Kiosk & Promotional Credit Authority (`25 CFR § 543.18` Cage/Credit, `§ 543.12` Player Tracking/Promotions -> `CIAF-04`, `CIAF-06`, `CIAF-07`)**: Marketing or player-host agents proposing downloadable promotional credits, complimentaries ("comps"), jackpot/dispute adjustments, or patron account transfers `MUST` be gated by `CIAF-06` ceilings; variance or high-tier awards `MUST` escalate (`CIAF-07`) to an authorized pit/cage supervisor independent of the system administrator.
- **Surveillance & TGRA Independent Revenue Audit (`25 CFR § 543.21` Surveillance, `§ 543.23` Audit & Accounting -> `CIAF-09`, `CIAF-10`, `CIAF-11`)**:
  - Any runtime security exception (`DIRECT_GATEWAY_BYPASS`, `TOCTOU_PAYLOAD_TAMPER`, `GRANT_NONCE_REPLAY` under `CIAF-11`) on patron-wallet or promotional-issuance services `MUST` emit an immutable `ExecutionClaim` exception receipt routable to Surveillance and TGRA compliance monitors.
  - Revenue Audit and TGRA inspectors `MUST` maintain independent custody of the trusted OKP JWK verification manifest (`CIAF-10`) so daily/monthly promotional and cage audit capsules can be verified with zero reliance on the gaming vendor or IT operator.

