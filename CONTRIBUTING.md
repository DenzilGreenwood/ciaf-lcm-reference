# Contributing to `ciaf-lcm-reference`

> **CIAF-LCM v0.1.1 • Public Comment Draft (Open through February 10, 2027)** — Public review comments, adapter conformance vectors, and standards crosswalk critiques are open through February 10, 2027.

Thank you for contributing to the **Cognitive Insight Audit Framework – Lazy Capsule Materialization (CIAF-LCM)** open reference repository. All contributions must preserve strict architectural rigor, cryptographic verifiability, and vendor neutrality.

---

## 1. Architectural & Normative Invariants

Every pull request—whether modifying prose specifications, JSON Schemas, reference code, or crosswalks—MUST preserve the workspace invariants:

1. **Pre-Execution Authority Boundary**: Never treat model output, prompt instructions, or agent memory as execution authorization. Execution authority MUST originate from a separately governed Pre-Execution Governance Gateway (`CIAF-06`).
2. **Five-Layer Separation**: Maintain explicit separation across `Capability != Authority != Authorization != Execution != Assurance`.
3. **Dual-Key Separation**: Gateway signing keys (`PRE_EXECUTION_GOVERNANCE_GATEWAY`) and Execution Service signing keys (`EXECUTION_SERVICE`) MUST remain cryptographically independent (`CIAF-08`).
4. **Strict RFC 8785 (JCS) Canonicalization**: Never compute SHA-256 digests or Ed25519 signatures over uncanonicalized JSON strings.
5. **Zero-Shortcut Verification**: Test cases MUST execute real Ed25519 signatures, real RFC 8785 canonicalization, and Draft 2020-12 JSON Schema validation—never mocked signature stubs.
6. **Vendor Neutrality**: Normative files under `docs/`, `controls/`, and `standards-crosswalks/` MUST use third-person specification prose (`MUST`, `MUST NOT`, `SHOULD`, `MAY` per RFC 2119 / RFC 8174) with zero product marketing or proprietary lock-in.

---

## 2. Contributing Independent Runtime Adapters

External runtimes, proxies, and SDKs in Go, Rust, TypeScript, Java, or Python are encouraged to demonstrate interoperability against `ciaf_lcm.verifier.IndependentVerifier`:

1. **Zero Internal Coupling**: Independent producer examples (modeled after [`examples/independent_producer.py`](examples/independent_producer.py)) MUST NOT import internal helper classes from `ciaf_lcm` when constructing claims.
2. **Required Test Vectors**:
   - Emit at least one positive `ALLOW` capsule (`AuthorizationClaim` + `ExecutionClaim`) and one blocked (`DENY` or `REJECTED_SECURITY_EXCEPTION`) capsule.
   - Verify that `ciaf_lcm.verifier.IndependentVerifier` returns `capsule_valid == True` with `failed_controls == []`.
   - Include at least one negative test demonstrating that mutating a single byte of the adapter's emitted `ExecutionClaim` triggers `ASSURANCE_FAILURE_TAMPER_OR_VIOLATION`.
3. **RFC 8785 Edge-Case Conformance**: Non-JavaScript implementations MUST test IEEE-754 number formatting (`-0.0 -> "0"`, `1e20`, `1e21`, `1e-6`, `1e-7`) and UTF-16 code-unit key ordering (supplementary plane surrogate pairs `U+10000..U+10FFFF` vs. BMP `U+E000..U+FFFF`).

---

## 3. Contributing Standards Crosswalk Critiques & Industry Profiles

Standards mappings in `standards-crosswalks/` and regulated sector profiles in `docs/audit-readiness-methodology-v0.1.md` welcome peer review from auditors, risk officers, and legal/compliance practitioners:

1. **Relationship Precision**: Classify every mapping strictly as `Direct`, `Partial`, or `Supportive`, and document what organizational or procedural evidence remains **outside** CIAF-LCM's technical scope.
2. **Non-Endorsement & Revision Tracking**:
   - Never claim a technical control provides "certification" or "regulatory approval."
   - Cite exact framework versions and revision context (for example, noting NIST AI RMF 1.0's active revision lifecycle, ISO/IEC 42001:2023's management-system clauses beyond Annex A technical controls, and the 2026 revised U.S. interagency model risk guidance superseding SR 11-7 and excluding generative/agentic AI from direct scope).
3. **Traceability**: Every cited field name or control identifier (`CIAF-01` through `CIAF-12`) MUST match the schemas in `schemas/` and tests in `tests/` 1-to-1.

---

## 4. Licensing of Contributions

By submitting a contribution to this repository, you agree that:

- Contributions to `docs/`, `controls/`, and `standards-crosswalks/` are licensed under **CC-BY-4.0** ([`LICENSE-SPEC`](LICENSE-SPEC)).
- Contributions to `schemas/`, `reference-implementation/`, `examples/`, `tests/`, and `apps/` are licensed under **Apache-2.0** ([`LICENSE-CODE`](LICENSE-CODE)).

