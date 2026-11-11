// Copyright 2026 CIAF-LCM Working Group Contributors
// SPDX-License-Identifier: Apache-2.0
/**
 * Browser & Node 20+ Web Crypto Ed25519 Engine, Dual-Key Simulator, Attack Injector,
 * Zero-Trust Independent Verifier (CIAF-10), and 2-Axis Readiness Override Engine.
 */

import { canonicalizeJcsBytes, computeRequestDigest, jcsSha256 } from "./jcs";

export type KeyRole =
  | "PRE_EXECUTION_GOVERNANCE_GATEWAY"
  | "EXECUTION_SERVICE"
  | "ASSURANCE_VERIFIER"
  | "REGISTRY_AUTHORITY"
  | "HUMAN_REVIEWER";

export interface OkpEd25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

export interface TrustedKeyEntry {
  key_id: string;
  role: KeyRole;
  status: "ACTIVE" | "REVOKED";
  public_key_jwk: OkpEd25519Jwk;
}

export interface Ed25519SignatureBlock {
  algorithm: "Ed25519";
  canonicalization: "RFC8785-JCS";
  key_id: string;
  signed_payload_digest: string;
  sig_b64u: string;
}

export interface VerificationFinding {
  severity: "INFO" | "WARNING" | "CRITICAL";
  control_id: string;
  code: string;
  message: string;
}

export interface AssuranceClaim {
  schema_version: "0.1.0";
  claim_type: "ASSURANCE_CLAIM";
  claim_id: string;
  timestamp: string;
  verifier_id: string;
  capsule_id: string;
  capsule_digest: string;
  capsule_valid: boolean;
  assurance_disposition:
    | "ASSURED_AUTHORIZED_EXECUTION"
    | "ASSURED_GOVERNANCE_BLOCK"
    | "ASSURED_SECURITY_EXCEPTION_CONTAINED"
    | "ASSURANCE_FAILURE_TAMPER_OR_VIOLATION";
  checks: {
    schema_validation_passed: boolean;
    rfc8785_digests_valid: boolean;
    dual_key_trust_boundary_valid: boolean;
    ed25519_signatures_valid: boolean;
    policy_digest_binding_valid: boolean;
    grant_nonce_and_ttl_valid: boolean;
    hash_chain_continuity_valid: boolean;
    semantic_consistency_valid: boolean;
    scitt_inclusion_verified: boolean | null;
  };
  failed_controls: string[];
  findings: VerificationFinding[];
  completeness_notice: string;
  signature: Ed25519SignatureBlock | null;
  claim_digest: string;
}

export type AuditCapsule = Record<string, any>;

export interface RoleKeypairHandle {
  key_id: string;
  role: KeyRole;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  manifestEntry: TrustedKeyEntry;
}

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const SIG_B64U_RE = /^[A-Za-z0-9_-]{86}$/;
const OKP_X_RE = /^[A-Za-z0-9_-]{43}$/;

export function b64uEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(encoded: string): Uint8Array<ArrayBuffer> {
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((encoded.length + 3) % 4);
  const binary = atob(padded);
  const buf = new ArrayBuffer(binary.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function randomHex(byteLen: number): string {
  const arr = new Uint8Array(byteLen);
  globalThis.crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function generateRoleKeypair(
  keyId: string,
  role: KeyRole
): Promise<RoleKeypairHandle> {
  const kp = (await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
  const exported = await globalThis.crypto.subtle.exportKey("jwk", kp.publicKey);
  if (exported.kty !== "OKP" || exported.crv !== "Ed25519" || !exported.x) {
    throw new Error("Web Crypto did not export a valid OKP Ed25519 JWK.");
  }
  return {
    key_id: keyId,
    role,
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
    manifestEntry: {
      key_id: keyId,
      role,
      status: "ACTIVE",
      public_key_jwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: exported.x,
      },
    },
  };
}

export async function importOkpVerifyKey(entry: TrustedKeyEntry): Promise<CryptoKey> {
  const jwk = entry.public_key_jwk;
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !OKP_X_RE.test(jwk.x || "")) {
    throw new Error(`Invalid OKP Ed25519 JWK on key '${entry.key_id}'.`);
  }
  return globalThis.crypto.subtle.importKey(
    "jwk",
    { kty: "OKP", crv: "Ed25519", x: jwk.x },
    { name: "Ed25519" },
    false,
    ["verify"]
  );
}

export async function signJcsObjectWebCrypto(
  unsignedObj: Record<string, unknown>,
  signer: RoleKeypairHandle
): Promise<Ed25519SignatureBlock> {
  const canonicalBytes = canonicalizeJcsBytes(unsignedObj);
  const payloadDigest = await jcsSha256(unsignedObj);
  const sigBuf = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    signer.privateKey,
    canonicalBytes
  );
  return {
    algorithm: "Ed25519",
    canonicalization: "RFC8785-JCS",
    key_id: signer.key_id,
    signed_payload_digest: payloadDigest,
    sig_b64u: b64uEncode(new Uint8Array(sigBuf)),
  };
}

export async function signClaimEnvelopeWebCrypto(
  unsignedClaim: Record<string, unknown>,
  signer: RoleKeypairHandle
): Promise<Record<string, any>> {
  const copyObj: Record<string, unknown> = structuredClone(unsignedClaim);
  delete copyObj.signature;
  delete copyObj.claim_digest;

  const sig = await signJcsObjectWebCrypto(copyObj, signer);
  const withSig = { ...copyObj, signature: sig };
  const claimDigest = await jcsSha256(withSig);
  return { ...withSig, claim_digest: claimDigest };
}

export async function verifyJcsSignatureWebCrypto(
  unsignedObj: Record<string, unknown>,
  sigObj: Record<string, any>,
  trustedEntry: TrustedKeyEntry
): Promise<{ ok: boolean; reason: string }> {
  if (!sigObj || sigObj.algorithm !== "Ed25519" || sigObj.canonicalization !== "RFC8785-JCS") {
    return { ok: false, reason: "Unsupported signature algorithm or canonicalization." };
  }
  const expectedDigest = await jcsSha256(unsignedObj);
  if (sigObj.signed_payload_digest !== expectedDigest) {
    return {
      ok: false,
      reason: `Signed payload digest mismatch: expected ${expectedDigest}, got ${sigObj.signed_payload_digest}`,
    };
  }
  if (typeof sigObj.sig_b64u !== "string" || !SIG_B64U_RE.test(sigObj.sig_b64u)) {
    return { ok: false, reason: "Malformed base64url Ed25519 signature." };
  }
  try {
    const cryptoKey = await importOkpVerifyKey(trustedEntry);
    const sigBytes = b64uDecode(sigObj.sig_b64u);
    const payloadBytes = canonicalizeJcsBytes(unsignedObj);
    const verified = await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      cryptoKey,
      sigBytes,
      payloadBytes
    );
    return verified
      ? { ok: true, reason: "OK" }
      : { ok: false, reason: "Web Crypto Ed25519 signature verification returned false." };
  } catch (err) {
    return { ok: false, reason: `Web Crypto verification error: ${String(err)}` };
  }
}

function stripKeys(obj: Record<string, any>, keysToRemove: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (!keysToRemove.includes(k)) {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Zero-Trust Independent Verifier (CIAF-10) in Web Crypto.
 * Enforces exact verification sequencing:
 * 1. Wire structure & required envelope fields (`signature`, `claim_digest`) check FIRST.
 * 2. Recompute `claim_digest == jcsSha256(body_with_signature)`.
 * 3. Verify `Ed25519(canonicalizeJcs(unsigned_body))` against role-pinned OKP JWK in `trustedKeys`.
 */
export async function verifyCapsuleZeroTrust(
  capsule: AuditCapsule,
  trustedKeys: TrustedKeyEntry[]
): Promise<AssuranceClaim> {
  const findings: VerificationFinding[] = [];
  const failedControls = new Set<string>();

  const fail = (control_id: string, code: string, message: string) => {
    failedControls.add(control_id);
    findings.push({ severity: "CRITICAL", control_id, code, message });
  };
  const info = (control_id: string, code: string, message: string) => {
    findings.push({ severity: "INFO", control_id, code, message });
  };

  // STEP 1: Wire structure validation (requiring signature & claim_digest on claims)
  let schemaOk = true;
  const reqCapsuleKeys = [
    "schema_version",
    "capsule_type",
    "capsule_id",
    "materialized_at",
    "workflow_trace_id",
    "policy_snapshot",
    "public_key_manifest",
    "hash_chain",
    "authorization_claims",
    "execution_claims",
    "scitt_transparency",
    "capsule_digest",
  ];
  for (const k of reqCapsuleKeys) {
    if (!(k in capsule)) {
      schemaOk = false;
      fail("CIAF-10", "CAPSULE_WIRE_SCHEMA_INVALID", `Missing required AuditCapsule field '${k}'.`);
    }
  }
  if (
    capsule.schema_version !== "0.1.0" ||
    capsule.capsule_type !== "CIAF_LCM_AUDIT_CAPSULE" ||
    !SHA256_RE.test(String(capsule.capsule_digest || ""))
  ) {
    schemaOk = false;
    fail("CIAF-10", "CAPSULE_HEADER_INVALID", "Invalid AuditCapsule version, type, or digest format.");
  }

  const authzClaims: Record<string, any>[] = Array.isArray(capsule.authorization_claims)
    ? capsule.authorization_claims
    : [];
  const execClaims: Record<string, any>[] = Array.isArray(capsule.execution_claims)
    ? capsule.execution_claims
    : [];

  for (let i = 0; i < authzClaims.length; i++) {
    const ac = authzClaims[i];
    if (
      ac?.claim_type !== "AUTHORIZATION_CLAIM" ||
      !ac?.signature ||
      !SHA256_RE.test(String(ac?.claim_digest || "")) ||
      !ac?.authority_context?.delegated_scope_snapshot ||
      typeof ac.authority_context.delegated_scope_snapshot !== "object"
    ) {
      schemaOk = false;
      fail(
        "CIAF-10",
        "AUTHZ_WIRE_SCHEMA_INVALID",
        `AuthorizationClaim[${i}] missing required wire signature, claim_digest, or delegated_scope_snapshot.`
      );
    }
  }
  for (let i = 0; i < execClaims.length; i++) {
    const ec = execClaims[i];
    if (
      ec?.claim_type !== "EXECUTION_CLAIM" ||
      !ec?.signature ||
      !SHA256_RE.test(String(ec?.claim_digest || ""))
    ) {
      schemaOk = false;
      fail(
        "CIAF-10",
        "EXEC_WIRE_SCHEMA_INVALID",
        `ExecutionClaim[${i}] missing required wire signature or claim_digest.`
      );
    }
  }

  // STEP 2: Multi-Role Trust Boundary & OKP JWK validation
  let trustBoundaryOk = true;
  const trustedByKid = new Map<string, TrustedKeyEntry>();
  const pubSetsByRole = new Map<string, Set<string>>();

  for (const entry of trustedKeys) {
    if (
      !entry.public_key_jwk ||
      entry.public_key_jwk.kty !== "OKP" ||
      entry.public_key_jwk.crv !== "Ed25519" ||
      !OKP_X_RE.test(entry.public_key_jwk.x || "")
    ) {
      trustBoundaryOk = false;
      fail("CIAF-10", "INVALID_OKP_JWK", `Trusted key '${entry.key_id}' lacks valid OKP Ed25519 JWK.`);
      continue;
    }
    trustedByKid.set(entry.key_id, entry);
    if (!pubSetsByRole.has(entry.role)) {
      pubSetsByRole.set(entry.role, new Set());
    }
    pubSetsByRole.get(entry.role)!.add(entry.public_key_jwk.x);
  }
  const roleNames = Array.from(pubSetsByRole.keys());
  for (let i = 0; i < roleNames.length; i++) {
    for (let j = i + 1; j < roleNames.length; j++) {
      const setA = pubSetsByRole.get(roleNames[i])!;
      const setB = pubSetsByRole.get(roleNames[j])!;
      for (const x of setA) {
        if (setB.has(x)) {
          trustBoundaryOk = false;
          fail(
            "CIAF-08",
            "SHARED_KEY_MATERIAL_VIOLATION",
            `Trust-boundary roles '${roleNames[i]}' and '${roleNames[j]}' share identical Ed25519 public key material.`
          );
        }
      }
    }
  }

  // STEP 3: Capsule & Policy RFC 8785 Canonical Digests
  let digestsOk = true;
  const policySnap = capsule.policy_snapshot || {};
  const expectedPolicyDigest = await jcsSha256(policySnap.policy_document || {});
  if (policySnap.policy_digest !== expectedPolicyDigest) {
    digestsOk = false;
    fail("CIAF-05", "POLICY_DIGEST_TAMPERED", "policy_snapshot.policy_digest mismatch.");
  }

  const recomputedCapsuleDigest = await jcsSha256(stripKeys(capsule, ["capsule_digest"]));
  if (capsule.capsule_digest !== recomputedCapsuleDigest) {
    digestsOk = false;
    fail(
      "CIAF-09",
      "CAPSULE_DIGEST_MISMATCH",
      `AuditCapsule digest mismatch: expected ${recomputedCapsuleDigest}, got ${capsule.capsule_digest}.`
    );
  }

  // STEP 4: AuthorizationClaims (Enveloped claim_digest -> Ed25519 sig -> Grant -> Semantics)
  let signaturesOk = true;
  let policyBindingOk = true;
  let grantNonceTtlOk = true;
  let semanticOk = true;

  // STEP 3b: Optional REGISTRY_AUTHORITY Attestation check (CIAF-01..04, CIAF-12)
  const att = capsule.authority_attestation;
  if (att && typeof att === "object") {
    const attNoDig = stripKeys(att, ["attestation_digest"]);
    if (att.attestation_digest !== (await jcsSha256(attNoDig))) {
      digestsOk = false;
      fail("CIAF-01", "AUTHORITY_ATTESTATION_DIGEST_MISMATCH", "authority_attestation digest mismatch.");
    }
    const attSigner = trustedByKid.get(String(att.signature?.key_id || ""));
    if (!attSigner || attSigner.role !== "REGISTRY_AUTHORITY" || attSigner.status !== "ACTIVE") {
      trustBoundaryOk = false;
      signaturesOk = false;
      fail("CIAF-01", "INVALID_REGISTRY_AUTHORITY_KEY", "authority_attestation not signed by active REGISTRY_AUTHORITY key.");
    } else {
      const attUnsigned = stripKeys(att, ["signature", "attestation_digest"]);
      const attRes = await verifyJcsSignatureWebCrypto(attUnsigned, att.signature, attSigner);
      if (!attRes.ok) {
        signaturesOk = false;
        fail("CIAF-01", "AUTHORITY_ATTESTATION_SIGNATURE_INVALID", `Registry attestation sig invalid: ${attRes.reason}`);
      }
    }
    const attEffectiveStatus =
      att.agent?.status === "REVOKED" || att.delegation?.status === "REVOKED"
        ? "REVOKED"
        : att.agent?.status === "SUSPENDED" ||
          att.delegation?.status === "SUSPENDED" ||
          att.use_case?.status !== "ACTIVE"
        ? "SUSPENDED"
        : "ACTIVE";
    for (const ac of authzClaims) {
      if (ac.authority_context?.authority_status !== attEffectiveStatus) {
        semanticOk = false;
        fail(
          "CIAF-12",
          "GATEWAY_REGISTRY_ATTESTATION_CONFLICT",
          `AuthorizationClaim '${ac.claim_id}' claims status '${ac.authority_context?.authority_status}' while Registry attested '${attEffectiveStatus}'.`
        );
      }
      const snap = ac.authority_context?.delegated_scope_snapshot;
      if (snap && typeof snap === "object") {
        if (
          snap.accountable_owner !== att.use_case?.accountable_owner ||
          JSON.stringify(snap.allowed_tools) !== JSON.stringify(att.delegation?.allowed_tools) ||
          snap.max_auto_amount_minor_units !== (att.delegation?.autonomous_max_amount ?? null) ||
          snap.escalation_max_amount_minor_units !== (att.delegation?.escalation_max_amount ?? null) ||
          snap.revoked !== (attEffectiveStatus === "REVOKED")
        ) {
          semanticOk = false;
          fail(
            "CIAF-04",
            "GATEWAY_SCOPE_SNAPSHOT_ATTESTATION_CONFLICT",
            `AuthorizationClaim '${ac.claim_id}' delegated_scope_snapshot conflicts with signed Registry authority_attestation.`
          );
        }
      }
    }
  }

  const authzById = new Map<string, Record<string, any>>();

  for (const ac of authzClaims) {
    const cid = String(ac.claim_id || "unknown");
    authzById.set(cid, ac);

    // 4a. Recompute claim_digest over body + signature FIRST
    const acWithSig = stripKeys(ac, ["claim_digest"]);
    if (ac.claim_digest !== (await jcsSha256(acWithSig))) {
      digestsOk = false;
      fail("CIAF-09", "AUTHZ_CLAIM_DIGEST_MISMATCH", `AuthorizationClaim '${cid}' claim_digest mismatch.`);
    }

    const prop = ac.proposed_action || {};
    const expectedReqDig = await computeRequestDigest(
      String(prop.tool_name || ""),
      String(prop.operation || ""),
      prop.parameters || {}
    );
    if (prop.request_digest !== expectedReqDig) {
      digestsOk = false;
      fail("CIAF-06", "AUTHZ_REQUEST_DIGEST_MISMATCH", `AuthorizationClaim '${cid}' request_digest mismatch.`);
    }

    // 4b. Verify Ed25519 over unsigned body against role-pinned Gateway key
    const kid = String(ac.signature?.key_id || "");
    const trustedSigner = trustedByKid.get(kid);
    if (!trustedSigner) {
      trustBoundaryOk = false;
      signaturesOk = false;
      fail("CIAF-10", "UNTRUSTED_SIGNING_KEY", `AuthorizationClaim '${cid}' signed by untrusted key '${kid}'.`);
    } else {
      if (trustedSigner.role !== "PRE_EXECUTION_GOVERNANCE_GATEWAY") {
        trustBoundaryOk = false;
        fail(
          "CIAF-06",
          "TRUST_BOUNDARY_KEY_ROLE_VIOLATION",
          `AuthorizationClaim '${cid}' signed by '${trustedSigner.role}' instead of Gateway key.`
        );
      }
      const acUnsigned = stripKeys(ac, ["signature", "claim_digest"]);
      const sigRes = await verifyJcsSignatureWebCrypto(acUnsigned, ac.signature, trustedSigner);
      if (!sigRes.ok) {
        signaturesOk = false;
        fail("CIAF-10", "AUTHZ_SIGNATURE_INVALID", `AuthorizationClaim '${cid}' failed Ed25519 check: ${sigRes.reason}`);
      }
    }

    if (ac.authority_context?.policy_digest !== policySnap.policy_digest) {
      policyBindingOk = false;
      fail("CIAF-05", "AUTHZ_POLICY_DIGEST_MISMATCH", `AuthorizationClaim '${cid}' policy_digest mismatch.`);
    }

    const outcome = ac.decision?.outcome;
    const grant = ac.execution_grant;
    const esc = ac.human_escalation || {};
    const authStatus = ac.authority_context?.authority_status;
    const scopeSnap = ac.authority_context?.delegated_scope_snapshot;
    const params = prop.parameters && typeof prop.parameters === "object" ? prop.parameters : {};

    if (scopeSnap && typeof scopeSnap === "object") {
      if (scopeSnap.accountable_owner !== ac.subject?.accountable_owner) {
        semanticOk = false;
        fail(
          "CIAF-02",
          "SCOPE_SNAPSHOT_OWNER_MISMATCH",
          `AuthorizationClaim '${cid}' delegated_scope_snapshot.accountable_owner != subject.accountable_owner.`
        );
      }
      if (Boolean(scopeSnap.revoked) !== (authStatus === "REVOKED")) {
        semanticOk = false;
        fail(
          "CIAF-12",
          "SCOPE_SNAPSHOT_REVOCATION_CONFLICT",
          `AuthorizationClaim '${cid}' delegated_scope_snapshot.revoked conflicts with authority_status='${authStatus}'.`
        );
      }
    }

    if (outcome === "ALLOW") {
      if (
        "amount" in params ||
        (typeof params.amount_minor_units === "number" && !Number.isInteger(params.amount_minor_units)) ||
        (typeof params.minor_unit_scale === "number" && !Number.isInteger(params.minor_unit_scale))
      ) {
        semanticOk = false;
        fail(
          "CIAF-04",
          "FLOAT_OR_AMBIGUOUS_MONETARY_AMOUNT",
          `AuthorizationClaim '${cid}' uses ambiguous 'amount' or IEEE-754 float instead of exact integer minor units.`
        );
      }
      if (authStatus !== "ACTIVE") {
        semanticOk = false;
        fail(
          "CIAF-12",
          "ALLOW_ON_INACTIVE_AUTHORITY",
          `AuthorizationClaim '${cid}' granted ALLOW while authority_status='${authStatus}'.`
        );
      }
      if (scopeSnap && typeof scopeSnap === "object") {
        if (!Array.isArray(scopeSnap.allowed_tools) || !scopeSnap.allowed_tools.includes(prop.tool_name)) {
          semanticOk = false;
          fail(
            "CIAF-04",
            "ALLOW_OUTSIDE_DELEGATED_TOOLS",
            `AuthorizationClaim '${cid}' granted ALLOW for tool '${prop.tool_name}' outside delegated_scope_snapshot.allowed_tools.`
          );
        }
        if (scopeSnap.revoked === true) {
          semanticOk = false;
          fail(
            "CIAF-12",
            "ALLOW_ON_REVOKED_SCOPE_SNAPSHOT",
            `AuthorizationClaim '${cid}' granted ALLOW while delegated_scope_snapshot.revoked=true.`
          );
        }
        if (scopeSnap.currency !== null && scopeSnap.currency !== undefined && params.currency !== scopeSnap.currency) {
          semanticOk = false;
          fail(
            "CIAF-04",
            "ALLOW_CURRENCY_MISMATCH",
            `AuthorizationClaim '${cid}' currency '${params.currency}' != delegated_scope_snapshot.currency '${scopeSnap.currency}'.`
          );
        }
        const autoMax = scopeSnap.max_auto_amount_minor_units;
        const escMax = scopeSnap.escalation_max_amount_minor_units;
        if (autoMax !== null || escMax !== null || "amount_minor_units" in params) {
          const amtMinor = params.amount_minor_units;
          const scaleVal = params.minor_unit_scale;
          if (
            !Number.isInteger(amtMinor) ||
            amtMinor <= 0 ||
            !Number.isInteger(scaleVal) ||
            scaleVal < 0 ||
            scaleVal > 18
          ) {
            semanticOk = false;
            fail(
              "CIAF-04",
              "INVALID_MONETARY_MINOR_UNITS",
              `AuthorizationClaim '${cid}' ALLOW requires positive integer amount_minor_units and integer minor_unit_scale (0..18).`
            );
          } else {
            if (typeof escMax === "number" && amtMinor > escMax) {
              semanticOk = false;
              fail(
                "CIAF-04",
                "ALLOW_EXCEEDS_DELEGATED_CEILING",
                `AuthorizationClaim '${cid}' granted ALLOW for ${amtMinor} minor units above delegated ceiling (${escMax}).`
              );
              fail(
                "CIAF-06",
                "ALLOW_EXCEEDS_DELEGATED_CEILING",
                `Gateway policy enforcement failed: ALLOW issued above absolute delegation ceiling (${amtMinor} > ${escMax}).`
              );
            }
            if (typeof autoMax === "number" && amtMinor > autoMax && esc.required !== true) {
              semanticOk = false;
              fail(
                "CIAF-06",
                "UNESCALATED_ALLOW_ABOVE_AUTONOMOUS_LIMIT",
                `AuthorizationClaim '${cid}' granted unescalated ALLOW for ${amtMinor} minor units above max_auto_amount_minor_units (${autoMax}).`
              );
              fail(
                "CIAF-07",
                "UNESCALATED_ALLOW_ABOVE_AUTONOMOUS_LIMIT",
                `Mandatory human escalation bypassed: ${amtMinor} minor units exceeds autonomous limit ${autoMax} without human review.`
              );
            }
          }
        }
      }
      if (esc.required) {
        if (esc.status !== "APPROVED" || !esc.reviewer_id || !esc.review_rationale || !esc.reviewed_at) {
          semanticOk = false;
          fail("CIAF-07", "ESCALATION_APPROVAL_INCOMPLETE", `AuthorizationClaim '${cid}' lacks human approval metadata.`);
        } else if (!esc.reviewer_signature || typeof esc.reviewer_signature !== "object") {
          signaturesOk = false;
          semanticOk = false;
          fail("CIAF-07", "FORGED_OR_UNSIGNED_HUMAN_APPROVAL", `AuthorizationClaim '${cid}' lacks independent HUMAN_REVIEWER signature.`);
        } else {
          const revSigner = trustedByKid.get(String(esc.reviewer_signature.key_id || ""));
          if (!revSigner || revSigner.role !== "HUMAN_REVIEWER" || revSigner.status !== "ACTIVE") {
            trustBoundaryOk = false;
            signaturesOk = false;
            fail("CIAF-07", "INVALID_HUMAN_REVIEWER_KEY_ROLE", `Escalation on '${cid}' not signed by active HUMAN_REVIEWER key.`);
          } else {
            const revPayload = {
              proposal_id: String(prop.proposal_id || ""),
              request_digest: String(prop.request_digest || ""),
              policy_digest: String(ac.authority_context?.policy_digest || ""),
              reviewer_id: String(esc.reviewer_id),
              approved: true,
              review_rationale: String(esc.review_rationale),
              reviewed_at: String(esc.reviewed_at),
            };
            const revCheck = await verifyJcsSignatureWebCrypto(revPayload, esc.reviewer_signature, revSigner);
            if (!revCheck.ok) {
              signaturesOk = false;
              fail("CIAF-07", "HUMAN_REVIEWER_SIGNATURE_INVALID", `Human reviewer signature invalid: ${revCheck.reason}`);
            }
          }
        }
      }
      if (!grant || typeof grant !== "object") {
        semanticOk = false;
        fail("CIAF-08", "MISSING_EXECUTION_GRANT_ON_ALLOW", `ALLOW claim '${cid}' lacks execution_grant.`);
      } else {
        const ttl = Number(grant.ttl_seconds || 0);
        const policyTtlCap = Number(policySnap.policy_document?.grant_max_ttl_seconds ?? 30);
        const issuedMs = Date.parse(grant.issued_at);
        const expiresMs = Date.parse(grant.expires_at);
        if (
          ttl < 1 ||
          policyTtlCap < 1 ||
          policyTtlCap > 300 ||
          ttl > policyTtlCap ||
          Math.round((expiresMs - issuedMs) / 1000) !== ttl
        ) {
          grantNonceTtlOk = false;
          fail("CIAF-08", "GRANT_TTL_POLICY_VIOLATION", `Grant '${grant.grant_id}' violates policy-bounded TTL (<=${policyTtlCap}s).`);
        }
        if (
          grant.bound_request_digest !== prop.request_digest ||
          grant.bound_policy_digest !== policySnap.policy_digest ||
          grant.bound_authorization_claim_id !== cid
        ) {
          grantNonceTtlOk = false;
          fail("CIAF-08", "GRANT_BINDING_MISMATCH", `Grant '${grant.grant_id}' digest binding mismatch.`);
        }
        const gSigner = trustedByKid.get(String(grant.gateway_grant_signature?.key_id || ""));
        if (!gSigner || gSigner.role !== "PRE_EXECUTION_GOVERNANCE_GATEWAY") {
          trustBoundaryOk = false;
          signaturesOk = false;
          fail("CIAF-08", "INVALID_GRANT_SIGNER_ROLE", `Grant '${grant.grant_id}' not signed by Gateway key.`);
        } else {
          const unsignedGrant = stripKeys(grant, ["gateway_grant_signature"]);
          const gVerify = await verifyJcsSignatureWebCrypto(
            unsignedGrant,
            grant.gateway_grant_signature,
            gSigner
          );
          if (!gVerify.ok) {
            signaturesOk = false;
            fail("CIAF-08", "GRANT_SIGNATURE_INVALID", `Grant '${grant.grant_id}' invalid sig: ${gVerify.reason}`);
          }
        }
      }
    } else if (grant !== null) {
      semanticOk = false;
      fail("CIAF-06", "GRANT_ISSUED_ON_NON_ALLOW", `Non-ALLOW claim '${cid}' must not carry execution_grant.`);
    }
  }

  // STEP 5: ExecutionClaims (Enveloped claim_digest -> Dual-Key Ed25519 sig -> Replay/TOCTOU/Semantics)
  const seenConsumedNonces = new Set<string>();
  let anyAuthorizedExecution = false;
  let anySecurityExceptionContained = false;

  for (const ec of execClaims) {
    const ecid = String(ec.claim_id || "unknown");

    // 5a. Recompute claim_digest over body + signature FIRST
    const ecWithSig = stripKeys(ec, ["claim_digest"]);
    if (ec.claim_digest !== (await jcsSha256(ecWithSig))) {
      digestsOk = false;
      fail(
        "CIAF-09",
        "EXEC_CLAIM_DIGEST_MISMATCH",
        `ExecutionClaim '${ecid}' claim_digest mismatch (receipt tampered after signing).`
      );
    }

    const act = ec.action_request || {};
    const expectedObsDig = await computeRequestDigest(
      String(act.tool_name || ""),
      String(act.operation || ""),
      act.parameters || {}
    );
    if (act.observed_request_digest !== expectedObsDig) {
      digestsOk = false;
      fail(
        "CIAF-08",
        "EXEC_OBSERVED_DIGEST_MISMATCH",
        `ExecutionClaim '${ecid}' observed_request_digest mismatch (parameters mutated).`
      );
    }

    const execBlock = ec.execution || {};
    if (execBlock.result_summary !== null && execBlock.result_summary !== undefined) {
      const expectedResDig = await jcsSha256(execBlock.result_summary);
      if (execBlock.result_digest !== expectedResDig) {
        digestsOk = false;
        fail("CIAF-09", "EXEC_RESULT_DIGEST_MISMATCH", `ExecutionClaim '${ecid}' result_digest mismatch.`);
      }
    }

    // 5b. Verify Ed25519 over unsigned body against role-pinned EXECUTION_SERVICE key
    const ekid = String(ec.signature?.key_id || "");
    const eSigner = trustedByKid.get(ekid);
    if (!eSigner) {
      trustBoundaryOk = false;
      signaturesOk = false;
      fail("CIAF-10", "UNTRUSTED_EXECUTOR_KEY", `ExecutionClaim '${ecid}' signed by untrusted key '${ekid}'.`);
    } else {
      if (eSigner.role !== "EXECUTION_SERVICE") {
        trustBoundaryOk = false;
        fail(
          "CIAF-08",
          "TRUST_BOUNDARY_KEY_ROLE_VIOLATION",
          `ExecutionClaim '${ecid}' signed with '${eSigner.role}' key ('${ekid}') instead of independent EXECUTION_SERVICE key.`
        );
      }
      const ecUnsigned = stripKeys(ec, ["signature", "claim_digest"]);
      const eVerify = await verifyJcsSignatureWebCrypto(ecUnsigned, ec.signature, eSigner);
      if (!eVerify.ok) {
        signaturesOk = false;
        fail(
          "CIAF-10",
          "EXEC_SIGNATURE_INVALID",
          `ExecutionClaim '${ecid}' Ed25519 verification failed: ${eVerify.reason}`
        );
      }
    }

    const binding = ec.authorization_binding || {};
    const secExc = ec.security_exception;
    const attempted = Boolean(execBlock.attempted);
    const executed = Boolean(execBlock.executed);

    if (attempted || executed || execBlock.status === "SUCCEEDED") {
      anyAuthorizedExecution = true;
      if (binding.grant_verification_status !== "VERIFIED" || secExc !== null) {
        semanticOk = false;
        fail("CIAF-08", "UNVERIFIED_EXECUTION_COMMITTED", `ExecutionClaim '${ecid}' executed without VERIFIED grant.`);
      }
      const refAuthz = authzById.get(String(binding.authorization_claim_id || ""));
      if (!refAuthz) {
        semanticOk = false;
        fail("CIAF-06", "MISSING_REFERENCED_AUTHZ_CLAIM", `ExecutionClaim '${ecid}' lacks matching AuthorizationClaim.`);
      } else {
        if (binding.authorization_claim_digest !== refAuthz.claim_digest) {
          semanticOk = false;
          fail("CIAF-08", "AUTHZ_CLAIM_DIGEST_LINK_BROKEN", `ExecutionClaim '${ecid}' authorization_claim_digest mismatch.`);
        }
        if (refAuthz.decision?.outcome !== "ALLOW") {
          semanticOk = false;
          fail("CIAF-06", "EXECUTION_DESPITE_NON_ALLOW", `ExecutionClaim '${ecid}' executed despite non-ALLOW decision.`);
        }
        const refGrant = refAuthz.execution_grant || {};
        const nonce = String(binding.consumed_nonce || "");
        if (!nonce || nonce !== refGrant.nonce) {
          grantNonceTtlOk = false;
          fail("CIAF-08", "GRANT_NONCE_MISMATCH", `ExecutionClaim '${ecid}' consumed_nonce != grant nonce.`);
        } else if (seenConsumedNonces.has(nonce)) {
          grantNonceTtlOk = false;
          fail(
            "CIAF-08",
            "DUPLICATE_CONSUMED_NONCE_IN_CAPSULE",
            `Replay violation: single-use nonce '${nonce}' consumed more than once!`
          );
        } else {
          seenConsumedNonces.add(nonce);
        }

        if (act.observed_request_digest !== refGrant.bound_request_digest) {
          grantNonceTtlOk = false;
          fail("CIAF-08", "UNBLOCKED_TOCTOU_MISMATCH", `ExecutionClaim '${ecid}' executed with mismatched payload digest.`);
        }

        const execMs = Date.parse(ec.timestamp);
        if (execMs < Date.parse(refGrant.issued_at) || execMs > Date.parse(refGrant.expires_at)) {
          grantNonceTtlOk = false;
          fail("CIAF-08", "EXECUTION_OUTSIDE_GRANT_TTL", `ExecutionClaim '${ecid}' timestamp outside grant TTL window.`);
        }
      }
    } else if (execBlock.status === "REJECTED_SECURITY_EXCEPTION") {
      anySecurityExceptionContained = true;
      if (attempted || executed || !secExc || secExc.detected !== true) {
        semanticOk = false;
        fail("CIAF-11", "INVALID_SECURITY_EXCEPTION_RECEIPT", `ExecutionClaim '${ecid}' invalid exception block.`);
      } else {
        info(secExc.control_id, secExc.exception_code, `Contained runtime attack verified: ${secExc.detail}`);
      }
    }
  }

  if (
    authzClaims.length > 0 &&
    authzClaims.some((ac) => ac.decision?.outcome === "ALLOW") &&
    execClaims.length === 0
  ) {
    semanticOk = false;
    fail("CIAF-09", "MISSING_EXECUTION_EVIDENCE_FOR_ALLOW", "ALLOW AuthorizationClaim present with zero ExecutionClaims.");
  }

  // STEP 6: Hash-Chain Continuity (CIAF-09)
  let chainOk = true;
  const allReceipts = [...authzClaims, ...execClaims];
  if (allReceipts.length === 0) {
    chainOk = false;
    fail("CIAF-09", "EMPTY_RECEIPT_CHAIN", "AuditCapsule contains zero receipts.");
  } else {
    const sorted = [...allReceipts].sort(
      (a, b) => Number(a.sequence_number ?? -1) - Number(b.sequence_number ?? -1)
    );
    for (let idx = 0; idx < sorted.length; idx++) {
      const r = sorted[idx];
      if (r.sequence_number !== idx) {
        chainOk = false;
        fail(
          "CIAF-09",
          "HASH_CHAIN_SEQUENCE_GAP_OR_REORDER",
          `Expected sequence_number ${idx}, got ${r.sequence_number} on '${r.claim_id}'.`
        );
      }
      if (idx === 0) {
        if (r.previous_receipt_digest !== null) {
          chainOk = false;
          fail("CIAF-09", "INVALID_GENESIS_PREVIOUS_DIGEST", "Genesis receipt must have previous_receipt_digest=null.");
        }
      } else if (r.previous_receipt_digest !== sorted[idx - 1].claim_digest) {
        chainOk = false;
        fail(
          "CIAF-09",
          "HASH_CHAIN_BROKEN_LINKAGE",
          `Receipt '${r.claim_id}' previous_receipt_digest does not match prior claim_digest.`
        );
      }
    }
    const hc = capsule.hash_chain || {};
    const orderedDigests = sorted.map((r) => String(r.claim_digest || ""));
    if (
      hc.receipt_count !== orderedDigests.length ||
      hc.genesis_receipt_digest !== orderedDigests[0] ||
      hc.tip_receipt_digest !== orderedDigests[orderedDigests.length - 1] ||
      JSON.stringify(hc.ordered_receipt_digests) !== JSON.stringify(orderedDigests)
    ) {
      chainOk = false;
      fail("CIAF-09", "HASH_CHAIN_HEADER_MISMATCH", "hash_chain header does not match ordered receipt digests.");
    }
  }

  const capsuleValid =
    schemaOk &&
    digestsOk &&
    trustBoundaryOk &&
    signaturesOk &&
    policyBindingOk &&
    grantNonceTtlOk &&
    chainOk &&
    semanticOk;

  let disposition: AssuranceClaim["assurance_disposition"] = "ASSURED_GOVERNANCE_BLOCK";
  if (!capsuleValid) {
    disposition = "ASSURANCE_FAILURE_TAMPER_OR_VIOLATION";
  } else if (anySecurityExceptionContained) {
    disposition = "ASSURED_SECURITY_EXCEPTION_CONTAINED";
  } else if (anyAuthorizedExecution) {
    disposition = "ASSURED_AUTHORIZED_EXECUTION";
  }

  if (capsuleValid && findings.length === 0) {
    info(
      "CIAF-10",
      "STATELESS_VERIFICATION_PASSED",
      `All Draft 2020-12 wire checks, RFC 8785 digests, delegated_scope_snapshot constraints, Dual-Key OKP JWK Ed25519 signatures, and hash-chain links verified (${disposition}).`
    );
  }

  const completenessNotice =
    "Local RFC 8785 SHA-256 hash-chaining verified (detects mid-chain tampering, deletion, or reordering). Grant TTL checks (<=30s) verify chronological consistency across issuer-asserted timestamps; defending against compromised-executor clock backdating and log-tail omission requires an external RFC 3161 TSA timestamp or IETF SCITT (RFC 9943 / RFC 9942 COSE Receipts) Transparency Service inclusion receipt.";

  const unsignedAssurance = {
    schema_version: "0.1.0" as const,
    claim_type: "ASSURANCE_CLAIM" as const,
    claim_id: `assure-webcrypto-${randomHex(6)}`,
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    verifier_id: "ciaf-webcrypto-verifier-01",
    capsule_id: String(capsule.capsule_id || "unknown-capsule"),
    capsule_digest: SHA256_RE.test(String(capsule.capsule_digest || ""))
      ? String(capsule.capsule_digest)
      : recomputedCapsuleDigest,
    capsule_valid: capsuleValid,
    assurance_disposition: disposition,
    checks: {
      schema_validation_passed: schemaOk,
      rfc8785_digests_valid: digestsOk,
      dual_key_trust_boundary_valid: trustBoundaryOk,
      ed25519_signatures_valid: signaturesOk,
      policy_digest_binding_valid: policyBindingOk,
      grant_nonce_and_ttl_valid: grantNonceTtlOk,
      hash_chain_continuity_valid: chainOk,
      semantic_consistency_valid: semanticOk,
      scitt_inclusion_verified: null,
    },
    failed_controls: Array.from(failedControls).sort(),
    findings,
    completeness_notice: completenessNotice,
    signature: null,
  };

  const claimDigest = await jcsSha256(unsignedAssurance);
  return { ...unsignedAssurance, claim_digest: claimDigest };
}

/**
 * Live Web Crypto Dual-Key Scenario Generator (`ALLOW`, `DENY`, `ESCALATE`, `REPLAY_CONTAINED`, `WRONG_KEY_FORGERY`, `UNBLOCKED_REPLAY_VIOLATION`, `ROGUE_GATEWAY_SCOPE_BYPASS`).
 */
export type SandboxScenarioMode =
  | "ALLOW"
  | "DENY"
  | "ESCALATE"
  | "REPLAY_CONTAINED"
  | "UNBLOCKED_REPLAY_VIOLATION"
  | "WRONG_KEY_FORGERY"
  | "ROGUE_GATEWAY_SCOPE_BYPASS";

export async function generateSandboxScenario(mode: SandboxScenarioMode): Promise<{
  capsule: AuditCapsule;
  trustedKeys: TrustedKeyEntry[];
}> {
  const rgKey = await generateRoleKeypair("webcrypto-rg-key-01", "REGISTRY_AUTHORITY");
  const gwKey = await generateRoleKeypair("webcrypto-gw-key-01", "PRE_EXECUTION_GOVERNANCE_GATEWAY");
  const exKey = await generateRoleKeypair("webcrypto-ex-key-01", "EXECUTION_SERVICE");
  const revKey = await generateRoleKeypair("webcrypto-reviewer-key-01", "HUMAN_REVIEWER");
  const trustedKeys: TrustedKeyEntry[] = [
    rgKey.manifestEntry,
    gwKey.manifestEntry,
    exKey.manifestEntry,
    revKey.manifestEntry,
  ];

  const policyDoc = {
    domain: "enterprise-accounts-payable",
    allowed_tools: ["payments.create"],
    autonomous_max_amount_minor_units: 500000,
    escalation_max_amount_minor_units: 2500000,
    allowed_currencies: ["USD"],
    minor_unit_scale: 2,
    grant_max_ttl_seconds: 30,
    require_single_use_nonce: true,
    authorized_human_reviewers: ["vp-finance@enterprise-example.org"],
  };
  const policyDigest = await jcsSha256(policyDoc);

  const delegatedScopeSnapshot = {
    accountable_owner: "controller@enterprise-example.org",
    allowed_tools: ["payments.create"],
    max_auto_amount_minor_units: 500000,
    escalation_max_amount_minor_units: 2500000,
    currency: "USD",
    revoked: false,
  };

  const t0 = new Date("2026-11-10T22:00:00Z");
  const t0Iso = "2026-11-10T22:00:00Z";
  const tExpIso = "2026-11-10T22:00:30Z";
  const tExecIso = "2026-11-10T22:00:04Z";
  const tReplayIso = "2026-11-10T22:00:07Z";

  const amountMinorUnits =
    mode === "DENY"
      ? 7500000
      : mode === "ESCALATE"
      ? 1250000
      : mode === "ROGUE_GATEWAY_SCOPE_BYPASS"
      ? 850000
      : 45000;
  const params = {
    amount_minor_units: amountMinorUnits,
    currency: "USD",
    minor_unit_scale: 2,
    beneficiary: mode === "ESCALATE" ? "vendor-globex-02" : "vendor-acme-01",
    invoice_id: `INV-WC-${mode.slice(0, 6)}`,
  };
  const reqDigest = await computeRequestDigest("payments.create", "CREATE_PAYMENT", params);
  const traceId = `trace-wc-${mode.toLowerCase()}`;

  const authzClaims: Record<string, any>[] = [];
  const execClaims: Record<string, any>[] = [];
  let seq = 0;
  let prevDigest: string | null = null;

  if (mode === "DENY") {
    const authzDeny = await signClaimEnvelopeWebCrypto(
      {
        schema_version: "0.1.0",
        claim_type: "AUTHORIZATION_CLAIM",
        claim_id: `authz-wc-${randomHex(6)}`,
        sequence_number: seq++,
        previous_receipt_digest: prevDigest,
        timestamp: t0Iso,
        gateway_id: "ciaf-gateway-webcrypto-01",
        subject: {
          agent_id: "agent-finance-01",
          use_case_id: "uc-ap-invoice-settlement-01",
          business_purpose: "Automated Accounts Payable verified vendor invoice settlement",
          accountable_owner: "controller@enterprise-example.org",
        },
        authority_context: {
          delegation_id: "del-fin-agent-01",
          authority_status: "ACTIVE",
          policy_id: "pol-ap-payments-2026",
          policy_version: "1.0.0",
          policy_digest: policyDigest,
          delegated_scope_snapshot: delegatedScopeSnapshot,
        },
        proposed_action: {
          proposal_id: "prop-wc-deny",
          tool_name: "payments.create",
          operation: "CREATE_PAYMENT",
          parameters: params,
          request_digest: reqDigest,
        },
        decision: {
          outcome: "DENY",
          reason_code: "AUTHORITY_SCOPE_EXCEEDED",
          rationale: "Proposed amount 7,500,000 minor units ($75,000.00 USD) exceeds maximum delegated & escalatable ceiling (2,500,000 minor units / $25,000.00 USD).",
          evaluated_controls: ["CIAF-01", "CIAF-02", "CIAF-03", "CIAF-04", "CIAF-05", "CIAF-06"],
        },
        human_escalation: {
          required: false,
          status: "NOT_REQUIRED",
          reviewer_id: null,
          review_rationale: null,
          reviewed_at: null,
          reviewer_signature: null,
        },
        execution_grant: null,
      },
      gwKey
    );
    authzClaims.push(authzDeny);
    prevDigest = authzDeny.claim_digest;
  } else {
    // Optional initial ESCALATE pending claim for ESCALATE workflow
    if (mode === "ESCALATE") {
      const authzEsc = await signClaimEnvelopeWebCrypto(
        {
          schema_version: "0.1.0",
          claim_type: "AUTHORIZATION_CLAIM",
          claim_id: `authz-wc-esc-${randomHex(6)}`,
          sequence_number: seq++,
          previous_receipt_digest: prevDigest,
          timestamp: t0Iso,
          gateway_id: "ciaf-gateway-webcrypto-01",
          subject: {
            agent_id: "agent-finance-01",
            use_case_id: "uc-ap-invoice-settlement-01",
            business_purpose: "Automated Accounts Payable verified vendor invoice settlement",
            accountable_owner: "controller@enterprise-example.org",
          },
          authority_context: {
            delegation_id: "del-fin-agent-01",
            authority_status: "ACTIVE",
            policy_id: "pol-ap-payments-2026",
            policy_version: "1.0.0",
            policy_digest: policyDigest,
            delegated_scope_snapshot: delegatedScopeSnapshot,
          },
          proposed_action: {
            proposal_id: "prop-wc-esc",
            tool_name: "payments.create",
            operation: "CREATE_PAYMENT",
            parameters: params,
            request_digest: reqDigest,
          },
          decision: {
            outcome: "ESCALATE",
            reason_code: "ESCALATION_REQUIRED_PENDING_REVIEW",
            rationale: "Proposed amount 1,250,000 minor units ($12,500.00 USD) exceeds 500,000 minor units ($5,000.00 USD) autonomous limit; human review required.",
            evaluated_controls: ["CIAF-01", "CIAF-02", "CIAF-03", "CIAF-04", "CIAF-05", "CIAF-06", "CIAF-07"],
          },
          human_escalation: {
            required: true,
            status: "PENDING",
            reviewer_id: null,
            review_rationale: null,
            reviewed_at: null,
            reviewer_signature: null,
          },
          execution_grant: null,
        },
        gwKey
      );
      authzClaims.push(authzEsc);
      prevDigest = authzEsc.claim_digest;
    }

    const allowClaimId = `authz-wc-allow-${randomHex(6)}`;
    const nonce = randomHex(16);
    const grantId = `grant-wc-${randomHex(6)}`;
    const unsignedGrant = {
      grant_id: grantId,
      nonce,
      issued_at: t0Iso,
      expires_at: tExpIso,
      ttl_seconds: 30,
      target_service: "payments-executor-01",
      bound_agent_id: "agent-finance-01",
      bound_tool_name: "payments.create",
      bound_request_digest: reqDigest,
      bound_policy_digest: policyDigest,
      bound_authorization_claim_id: allowClaimId,
    };
    const grantSig = await signJcsObjectWebCrypto(unsignedGrant, gwKey);

    const reviewedAtIso = "2026-11-10T22:00:02Z";
    const reviewerRationale = "Verified three-way PO match for Globex invoice.";
    const reviewerSig =
      mode === "ESCALATE"
        ? await signJcsObjectWebCrypto(
            {
              proposal_id: "prop-wc-esc",
              request_digest: reqDigest,
              policy_digest: policyDigest,
              reviewer_id: "vp-finance@enterprise-example.org",
              approved: true,
              review_rationale: reviewerRationale,
              reviewed_at: reviewedAtIso,
            },
            revKey
          )
        : null;

    const authzAllow = await signClaimEnvelopeWebCrypto(
      {
        schema_version: "0.1.0",
        claim_type: "AUTHORIZATION_CLAIM",
        claim_id: allowClaimId,
        sequence_number: seq++,
        previous_receipt_digest: prevDigest,
        timestamp: t0Iso,
        gateway_id: "ciaf-gateway-webcrypto-01",
        subject: {
          agent_id: "agent-finance-01",
          use_case_id: "uc-ap-invoice-settlement-01",
          business_purpose: "Automated Accounts Payable verified vendor invoice settlement",
          accountable_owner: "controller@enterprise-example.org",
        },
        authority_context: {
          delegation_id: "del-fin-agent-01",
          authority_status: "ACTIVE",
          policy_id: "pol-ap-payments-2026",
          policy_version: "1.0.0",
          policy_digest: policyDigest,
          delegated_scope_snapshot: delegatedScopeSnapshot,
        },
        proposed_action: {
          proposal_id: mode === "ESCALATE" ? "prop-wc-esc" : "prop-wc-allow",
          tool_name: "payments.create",
          operation: "CREATE_PAYMENT",
          parameters: params,
          request_digest: reqDigest,
        },
        decision: {
          outcome: "ALLOW",
          reason_code: mode === "ESCALATE" ? "ESCALATED_HUMAN_APPROVED" : "WITHIN_DELEGATED_AUTHORITY",
          rationale:
            mode === "ESCALATE"
              ? "Escalated proposal approved and signed by vp-finance@enterprise-example.org."
              : mode === "ROGUE_GATEWAY_SCOPE_BYPASS"
              ? "Buggy/rogue Gateway issued unescalated ALLOW for $8,500.00 (850,000 minor units) above $5,000.00 auto limit."
              : "Proposed action satisfies delegated scope and pinned policy.",
          evaluated_controls:
            mode === "ESCALATE"
              ? ["CIAF-01", "CIAF-02", "CIAF-03", "CIAF-04", "CIAF-05", "CIAF-06", "CIAF-07"]
              : ["CIAF-01", "CIAF-02", "CIAF-03", "CIAF-04", "CIAF-05", "CIAF-06"],
        },
        human_escalation:
          mode === "ESCALATE"
            ? {
                required: true,
                status: "APPROVED",
                reviewer_id: "vp-finance@enterprise-example.org",
                review_rationale: reviewerRationale,
                reviewed_at: reviewedAtIso,
                reviewer_signature: reviewerSig,
              }
            : {
                required: false,
                status: "NOT_REQUIRED",
                reviewer_id: null,
                review_rationale: null,
                reviewed_at: null,
                reviewer_signature: null,
              },
        execution_grant: {
          ...unsignedGrant,
          gateway_grant_signature: grantSig,
        },
      },
      gwKey
    );
    authzClaims.push(authzAllow);
    prevDigest = authzAllow.claim_digest;

    const resultSummary = {
      payment_id: `pay-${randomHex(5)}`,
      settled_amount_minor_units: amountMinorUnits,
      currency: "USD",
      minor_unit_scale: 2,
      beneficiary: params.beneficiary,
      settlement_status: "SETTLED",
    };
    const resultDigest = await jcsSha256(resultSummary);

    // Sign with WRONG key role (`gwKey` instead of `exKey`) if testing `WRONG_KEY_FORGERY`
    const execSigner = mode === "WRONG_KEY_FORGERY" ? gwKey : exKey;

    const execFirst = await signClaimEnvelopeWebCrypto(
      {
        schema_version: "0.1.0",
        claim_type: "EXECUTION_CLAIM",
        claim_id: `exec-wc-${randomHex(6)}`,
        sequence_number: seq++,
        previous_receipt_digest: prevDigest,
        timestamp: tExecIso,
        executor_id: "payments-executor-01",
        authorization_binding: {
          authorization_claim_id: authzAllow.claim_id,
          authorization_claim_digest: authzAllow.claim_digest,
          grant_id: grantId,
          consumed_nonce: nonce,
          policy_digest: policyDigest,
          grant_verification_status: "VERIFIED",
        },
        action_request: {
          proposal_id: mode === "ESCALATE" ? "prop-wc-esc" : "prop-wc-allow",
          agent_id: "agent-finance-01",
          tool_name: "payments.create",
          operation: "CREATE_PAYMENT",
          parameters: params,
          observed_request_digest: reqDigest,
        },
        execution: {
          attempted: true,
          executed: true,
          status: "SUCCEEDED",
          side_effects_committed: true,
          result_digest: resultDigest,
          result_summary: resultSummary,
        },
        security_exception: null,
      },
      execSigner
    );
    execClaims.push(execFirst);
    prevDigest = execFirst.claim_digest;

    if (mode === "REPLAY_CONTAINED") {
      const execReplayBlocked = await signClaimEnvelopeWebCrypto(
        {
          schema_version: "0.1.0",
          claim_type: "EXECUTION_CLAIM",
          claim_id: `exec-wc-replay-block-${randomHex(6)}`,
          sequence_number: seq++,
          previous_receipt_digest: prevDigest,
          timestamp: tReplayIso,
          executor_id: "payments-executor-01",
          authorization_binding: {
            authorization_claim_id: authzAllow.claim_id,
            authorization_claim_digest: authzAllow.claim_digest,
            grant_id: grantId,
            consumed_nonce: null,
            policy_digest: policyDigest,
            grant_verification_status: "NONCE_REPLAYED",
          },
          action_request: {
            proposal_id: "prop-wc-allow",
            agent_id: "agent-finance-01",
            tool_name: "payments.create",
            operation: "CREATE_PAYMENT",
            parameters: params,
            observed_request_digest: reqDigest,
          },
          execution: {
            attempted: false,
            executed: false,
            status: "REJECTED_SECURITY_EXCEPTION",
            side_effects_committed: false,
            result_digest: null,
            result_summary: null,
          },
          security_exception: {
            detected: true,
            control_id: "CIAF-08",
            exception_code: "GRANT_NONCE_REPLAY",
            severity: "CRITICAL",
            detail: `Single-use grant nonce '${nonce}' was already consumed; replay blocked pre-execution.`,
          },
        },
        exKey
      );
      execClaims.push(execReplayBlocked);
    } else if (mode === "UNBLOCKED_REPLAY_VIOLATION") {
      // Simulate a broken executor that allowed a second execution reusing the SAME single-use nonce!
      const execDuplicate = await signClaimEnvelopeWebCrypto(
        {
          schema_version: "0.1.0",
          claim_type: "EXECUTION_CLAIM",
          claim_id: `exec-wc-dup-nonce-${randomHex(6)}`,
          sequence_number: seq++,
          previous_receipt_digest: prevDigest,
          timestamp: tReplayIso,
          executor_id: "payments-executor-01",
          authorization_binding: {
            authorization_claim_id: authzAllow.claim_id,
            authorization_claim_digest: authzAllow.claim_digest,
            grant_id: grantId,
            consumed_nonce: nonce, // ILLEGAL REUSE OF CONSUMED NONCE!
            policy_digest: policyDigest,
            grant_verification_status: "VERIFIED",
          },
          action_request: {
            proposal_id: "prop-wc-allow",
            agent_id: "agent-finance-01",
            tool_name: "payments.create",
            operation: "CREATE_PAYMENT",
            parameters: params,
            observed_request_digest: reqDigest,
          },
          execution: {
            attempted: true,
            executed: true,
            status: "SUCCEEDED",
            side_effects_committed: true,
            result_digest: resultDigest,
            result_summary: resultSummary,
          },
          security_exception: null,
        },
        exKey
      );
      execClaims.push(execDuplicate);
    }
  }

  const allOrdered = [...authzClaims, ...execClaims].sort(
    (a, b) => a.sequence_number - b.sequence_number
  );
  const orderedDigests = allOrdered.map((r) => r.claim_digest);

  const unsignedAttestation = {
    registry_id: "ciaf-registry-webcrypto-01",
    attested_at: t0Iso,
    use_case: {
      use_case_id: "uc-ap-invoice-settlement-01",
      business_purpose: "Automated Accounts Payable verified vendor invoice settlement",
      accountable_owner: "controller@enterprise-example.org",
      risk_tier: "HIGH",
      status: "ACTIVE",
    },
    agent: {
      agent_id: "agent-finance-01",
      workload_id: "spiffe://enterprise-example.org/ns/finance/sa/agent-finance-01",
      model_profile: "vendor-neutral-reasoning-agent-v1",
      status: "ACTIVE",
    },
    delegation: {
      delegation_id: "del-fin-agent-01",
      policy_id: "pol-ap-payments-2026",
      allowed_tools: ["payments.create"],
      autonomous_max_amount: 500000,
      escalation_max_amount: 2500000,
      allowed_currencies: ["USD"],
      status: "ACTIVE",
    },
  };
  const attSig = await signJcsObjectWebCrypto(unsignedAttestation, rgKey);
  const attWithSig = { ...unsignedAttestation, signature: attSig };
  const authorityAttestation =
    mode === "ROGUE_GATEWAY_SCOPE_BYPASS"
      ? null
      : {
          ...attWithSig,
          attestation_digest: await jcsSha256(attWithSig),
        };

  const unsignedCapsule = {
    schema_version: "0.1.0",
    capsule_type: "CIAF_LCM_AUDIT_CAPSULE",
    capsule_id: `caps-wc-${randomHex(6)}`,
    materialized_at: new Date(t0.getTime() + 10000).toISOString().replace(/\.\d{3}Z$/, "Z"),
    workflow_trace_id: traceId,
    policy_snapshot: {
      policy_id: "pol-ap-payments-2026",
      policy_version: "1.0.0",
      policy_document: policyDoc,
      policy_digest: policyDigest,
    },
    authority_attestation: authorityAttestation,
    public_key_manifest: trustedKeys,
    hash_chain: {
      algorithm: "SHA-256",
      canonicalization: "RFC8785-JCS",
      genesis_receipt_digest: orderedDigests[0],
      tip_receipt_digest: orderedDigests[orderedDigests.length - 1],
      receipt_count: orderedDigests.length,
      ordered_receipt_digests: orderedDigests,
    },
    authorization_claims: authzClaims,
    execution_claims: execClaims,
    scitt_transparency: {
      status: "NOT_REGISTERED_LOCAL_CHAIN_ONLY",
      transparency_service_id: null,
      cose_sign1_statement_digest: null,
      inclusion_receipt_b64u: null,
      completeness_guarantee:
        "Local RFC 8785 SHA-256 hash-chaining detects mid-chain tampering; log-tail omission proofs and independent wall-clock anchoring require IETF SCITT (RFC 9943 / RFC 9942 COSE Receipts) or RFC 3161 TSA.",
    },
  };

  const capsuleDigest = await jcsSha256(unsignedCapsule);
  return {
    capsule: { ...unsignedCapsule, capsule_digest: capsuleDigest },
    trustedKeys,
  };
}

/**
 * Mutate a saved `AuditCapsule` in-place (simulating post-hoc JSON evidence tampering to $45,000.00 = 4,500,000 minor units).
 */
export function tamperCapsuleReceipt(capsule: AuditCapsule): AuditCapsule {
  const mutated: AuditCapsule = structuredClone(capsule);
  if (mutated.execution_claims && mutated.execution_claims.length > 0) {
    mutated.execution_claims[0].action_request.parameters.amount_minor_units = 4500000;
    if (mutated.execution_claims[0].execution.result_summary) {
      mutated.execution_claims[0].execution.result_summary.settled_amount_minor_units = 4500000;
    }
  } else if (mutated.authorization_claims && mutated.authorization_claims.length > 0) {
    mutated.authorization_claims[0].proposed_action.parameters.amount_minor_units = 4500000;
  }
  return mutated;
}

/**
 * Delete the genesis or intermediate receipt to simulate a Hash-Chain Deletion Attack (CIAF-09).
 */
export async function deleteChainReceiptAttack(capsule: AuditCapsule): Promise<AuditCapsule> {
  const mutated: AuditCapsule = structuredClone(capsule);
  if (mutated.authorization_claims && mutated.authorization_claims.length > 1) {
    // Remove intermediate approval receipt (index 1)
    mutated.authorization_claims.splice(1, 1);
  } else if (mutated.authorization_claims && mutated.authorization_claims.length === 1 && mutated.execution_claims?.length > 0) {
    // Remove genesis authorization receipt leaving orphaned execution receipt at seq 1!
    mutated.authorization_claims.splice(0, 1);
  }
  // Even if the attacker recomputes outer capsule_digest, inner sequence_number & previous_receipt_digest break!
  const stripped = stripKeys(mutated, ["capsule_digest"]);
  mutated.capsule_digest = await jcsSha256(stripped);
  return mutated;
}

/**
 * 2-Axis Per-Control Audit Readiness Scorecard (`CIAF-01` through `CIAF-12`) & Critical-Failure Override Engine.
 * Matches `docs/audit-readiness-methodology-v0.1.md` verbatim.
 */
export type AxisAControlId =
  | "CIAF-01"
  | "CIAF-02"
  | "CIAF-03"
  | "CIAF-04"
  | "CIAF-05"
  | "CIAF-06"
  | "CIAF-07"
  | "CIAF-08"
  | "CIAF-11"
  | "CIAF-12";

export type AxisBControlId = "CIAF-09" | "CIAF-10";

export type CiafControlId = AxisAControlId | AxisBControlId;

export const AXIS_A_CONTROLS: ReadonlyArray<{
  id: AxisAControlId;
  title: string;
  gateTag?: string;
}> = [
  { id: "CIAF-01", title: "Use Case Registration & Business Purpose" },
  { id: "CIAF-02", title: "Named Human Accountable Owner", gateTag: "GATE 3 (== 0)" },
  { id: "CIAF-03", title: "Cryptographic Workload / Agent Identity" },
  { id: "CIAF-04", title: "Scoped Delegation & Integer Minor Units" },
  { id: "CIAF-05", title: "RFC 8785 Policy Digest Pinning" },
  { id: "CIAF-06", title: "Mandatory Pre-Execution Governance Gate", gateTag: "GATE 1 (<= 1)" },
  { id: "CIAF-07", title: "Risk-Threshold Human Escalation Signature" },
  { id: "CIAF-08", title: "Dual-Key Executor, Nonce & <=30s TOCTOU Binding", gateTag: "GATE 1 (<= 1)" },
  { id: "CIAF-11", title: "Bypass & Security Exception Receipt Logging" },
  { id: "CIAF-12", title: "Immediate Authority Revocation Kill-Switch", gateTag: "GATE 3 (<= 1)" },
];

export const AXIS_B_CONTROLS: ReadonlyArray<{
  id: AxisBControlId;
  title: string;
  gateTag?: string;
}> = [
  { id: "CIAF-09", title: "Append-Only Hash-Chain & Lazy Capsule Provenance", gateTag: "GATE 2 (<= 1) / GATE 4" },
  { id: "CIAF-10", title: "Stateless Independent Cryptographic Verification", gateTag: "GATE 2 (<= 1)" },
];

export type ReadinessDisposition =
  | "NOT_AUDIT_READY"
  | "CONDITIONAL_REMEDIATION_REQUIRED"
  | "AUDIT_READY_LOCAL_PROVENANCE"
  | "AUDIT_READY_VERIFIABLE_COMPLETENESS";

export interface ReadinessScoresInput {
  controls: Record<CiafControlId, number>;
  scittRegistered: boolean;
  sharedSigningKeysDetected: boolean;
}

export interface ReadinessEvaluation {
  rawAxisAMean: number;
  axisAMin: number;
  effectiveAxisAMaturity: number;
  rawAxisBMean: number;
  axisBMin: number;
  effectiveAxisBConfidence: number;
  readinessDisposition: ReadinessDisposition;
  overrideTriggered: boolean;
  overrideReasons: string[];
}

export function createUniformControlScores(
  score: number,
  overrides: Partial<Record<CiafControlId, number>> = {}
): Record<CiafControlId, number> {
  return {
    "CIAF-01": score,
    "CIAF-02": score,
    "CIAF-03": score,
    "CIAF-04": score,
    "CIAF-05": score,
    "CIAF-06": score,
    "CIAF-07": score,
    "CIAF-08": score,
    "CIAF-09": score,
    "CIAF-10": score,
    "CIAF-11": score,
    "CIAF-12": score,
    ...overrides,
  };
}

export function evaluateTwoAxisReadiness(input: ReadinessScoresInput): ReadinessEvaluation {
  const axisAVals = AXIS_A_CONTROLS.map((c) => input.controls[c.id]);
  const axisBVals = AXIS_B_CONTROLS.map((c) => input.controls[c.id]);
  const allVals = [...axisAVals, ...axisBVals];

  const rawAxisAMean = Number((axisAVals.reduce((acc, v) => acc + v, 0) / 10).toFixed(2));
  const axisAMin = Math.min(...axisAVals);

  const rawAxisBMean = Number((axisBVals.reduce((acc, v) => acc + v, 0) / 2).toFixed(2));
  const axisBMin = Math.min(...axisBVals);

  let effectiveAxisAMaturity = rawAxisAMean;
  let effectiveAxisBConfidence = rawAxisBMean;
  const overrideReasons: string[] = [];

  const gate1Triggered = input.controls["CIAF-06"] <= 1 || input.controls["CIAF-08"] <= 1;
  const gate2Triggered =
    input.controls["CIAF-09"] <= 1 ||
    input.controls["CIAF-10"] <= 1 ||
    input.sharedSigningKeysDetected;
  const gate3Triggered = input.controls["CIAF-02"] === 0 || input.controls["CIAF-12"] <= 1;

  // Critical Gate 1: Runtime Pre-Execution Gate or Dual-Key Executor failure (CIAF-06 <= 1 OR CIAF-08 <= 1)
  if (gate1Triggered) {
    effectiveAxisAMaturity = Math.min(effectiveAxisAMaturity, 1.0);
    overrideReasons.push(
      `Critical Gate 1 (CIAF-06=${input.controls["CIAF-06"]}/4, CIAF-08=${input.controls["CIAF-08"]}/4): Runtime Pre-Execution Gate or Dual-Key Executor Enforcement is <= 1/4 (Note: CIAF-07 is evaluated separately). High policy scores CANNOT compensate for bypassable runtime enforcement — Disposition forced to NOT_AUDIT_READY (Axis A capped at 1.00/4).`
    );
  }

  // Critical Gate 2: Unverifiable / Mutable / Shared-Key Evidence (CIAF-09 <= 1 OR CIAF-10 <= 1 OR sharedSigningKeysDetected)
  if (gate2Triggered) {
    effectiveAxisBConfidence = Math.min(effectiveAxisBConfidence, 1.0);
    overrideReasons.push(
      `Critical Gate 2 (CIAF-09=${input.controls["CIAF-09"]}/4, CIAF-10=${input.controls["CIAF-10"]}/4, sharedKeys=${input.sharedSigningKeysDetected}): Unverifiable, mutable, or shared-key evidence detected — Disposition forced to NOT_AUDIT_READY (Axis B capped at 1.00/4).`
    );
  }

  // Critical Gate 3: Unowned Risk or Missing Revocation Kill-Switch (CIAF-02 == 0 OR CIAF-12 <= 1)
  if (gate3Triggered) {
    effectiveAxisAMaturity = Math.min(effectiveAxisAMaturity, 1.0);
    overrideReasons.push(
      `Critical Gate 3 (CIAF-02=${input.controls["CIAF-02"]}/4, CIAF-12=${input.controls["CIAF-12"]}/4): Production agent lacks a named human accountable_owner (CIAF-02 == 0) or immediate revocation kill-switch (CIAF-12 <= 1) — Disposition forced to NOT_AUDIT_READY (Axis A capped at 1.00/4).`
    );
  }

  // Critical Gate 4: Without SCITT RFC 9943 / RFC 9942 receipt + independent external timestamp, Axis B caps at 3.00/4
  if (!input.scittRegistered && effectiveAxisBConfidence > 3.0) {
    effectiveAxisBConfidence = 3.0;
    overrideReasons.push(
      "Critical Gate 4 (CIAF-09): Axis B (Evidence Provenance & Verification Confidence) capped at 3.00/4 because IETF SCITT (RFC 9943 / RFC 9942 COSE Receipts) registration + external trusted timestamping are not enabled (local hash-chaining proves mid-chain integrity, not tail non-omission)."
    );
  }

  let readinessDisposition: ReadinessDisposition;
  if (gate1Triggered || gate2Triggered || gate3Triggered) {
    readinessDisposition = "NOT_AUDIT_READY";
  } else if (
    Math.min(effectiveAxisAMaturity, effectiveAxisBConfidence) < 3.0 ||
    allVals.some((v) => v < 2)
  ) {
    readinessDisposition = "CONDITIONAL_REMEDIATION_REQUIRED";
  } else if (!input.scittRegistered) {
    readinessDisposition = "AUDIT_READY_LOCAL_PROVENANCE";
  } else {
    readinessDisposition = "AUDIT_READY_VERIFIABLE_COMPLETENESS";
  }

  return {
    rawAxisAMean,
    axisAMin,
    effectiveAxisAMaturity: Number(effectiveAxisAMaturity.toFixed(2)),
    rawAxisBMean,
    axisBMin,
    effectiveAxisBConfidence: Number(effectiveAxisBConfidence.toFixed(2)),
    readinessDisposition,
    overrideTriggered: overrideReasons.length > 0,
    overrideReasons,
  };
}

