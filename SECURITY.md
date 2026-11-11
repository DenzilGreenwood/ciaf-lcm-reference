# Security Policy & Responsible Disclosure (`ciaf-lcm-reference`)

## Supported Versions

| Release | Wire Schema | Status | Security Updates |
| :--- | :--- | :--- | :--- |
| **`v0.1.x` (`v0.1.1`)** | `"0.1.0"` | Public Comment Draft (through Feb 10, 2027) | Supported |

---

## Scope of Security Vulnerabilities

Please report the following classes of findings **privately** rather than in public GitHub Issues:

1. **Cryptographic or Canonicalization Flaws**: Cross-language digest drift in RFC 8785 (JCS) serialization, Ed25519 `OKP` JWK import/verification flaws, or envelope-stripping bypasses (`signature` / `claim_digest`).
2. **Trust-Boundary & Anti-Replay Bypasses**: Flaws permitting `ExecutionGrant` acceptance without a valid `PRE_EXECUTION_GOVERNANCE_GATEWAY` signature, single-use `nonce` replay evasion, `<= 30s` TTL bypass, TOCTOU `observed_request_digest` mismatch evasion, or `delegated_scope_snapshot` ceiling bypass in `IndependentVerifier` (`ciaf_lcm` or `verifier-sandbox`).
3. **Hash-Chain Forgery**: Undetected mid-chain receipt deletion, reordering, or splice attacks within `LazyCapsuleMaterializer` or `IndependentVerifier`.

*(Note: General architectural critiques, standards crosswalk comments, and feature requests should be submitted publicly using the **Public Comment / Specification Critique** issue form.)*

---

## How to Report Privately

1. **Preferred — GitHub Private Vulnerability Reporting**:
   Open a private advisory at:
   `https://github.com/DenzilGreenwood/ciaf-lcm-reference/security/advisories/new`
2. **Email Fallback**:
   Send a minimal reproducible `AuditCapsule` JSON vector and verifier reproduction steps to `founder@cognitiveinsight.ai` with subject `[SECURITY] ciaf-lcm-reference`.

Maintainers acknowledge receipt within **72 hours** and coordinate remediation tests across both the Python reference library and the TypeScript/Web Crypto stateless verifier prior to public disclosure.

