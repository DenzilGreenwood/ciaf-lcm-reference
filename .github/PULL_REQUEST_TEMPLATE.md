## Summary of Changes

- **Target Area:** `[ ] Normative Spec / Crosswalk (CC-BY-4.0)` • `[ ] JSON Schema / Code / Verifier (Apache-2.0)`
- **Related Issue / RFC Comment:** `#`

---

## CIAF-LCM Architectural & Security Invariant Checklist

Every pull request MUST preserve all six workspace invariants (`CONTRIBUTING.md`):

- [ ] **1. Pre-Execution Authority Boundary:** Model output or prompt state is never treated as authorization; execution authority originates exclusively from the Pre-Execution Governance Gateway (`CIAF-06`).
- [ ] **2. Five-Layer Non-Conflation:** Preserves strict separation across `Capability != Authority != Authorization != Execution != Assurance`.
- [ ] **3. Dual-Key Trust Separation:** `PRE_EXECUTION_GOVERNANCE_GATEWAY` and `EXECUTION_SERVICE` hold isolated Ed25519 keypairs (`CIAF-08`).
- [ ] **4. Strict RFC 8785 (JCS) Canonicalization:** No raw uncanonicalized JSON strings are hashed or signed; monetary amounts use exact ISO-4217 integers (`amount_minor_units`, `minor_unit_scale`).
- [ ] **5. Zero-Shortcut Verification:** All positive and adversarial tests execute real Ed25519 signatures, real RFC 8785 digests, and Draft 2020-12 schema checks (`pytest -v` and `npm --prefix apps/verifier-sandbox run verify:interop && npm --prefix apps/verifier-sandbox run build` exit `0`).
- [ ] **6. Vendor Neutrality & Dual Licensing:** Changes under `docs/`, `controls/`, and `standards-crosswalks/` use third-person normative prose (`CC-BY-4.0`, zero product marketing); changes under `schemas/`, `reference-implementation/`, `examples/`, `tests/`, and `apps/` are licensed under `Apache-2.0`.

