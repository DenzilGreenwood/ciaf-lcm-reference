// Copyright 2026 CIAF-LCM Working Group Contributors
// SPDX-License-Identifier: Apache-2.0
/**
 * Cross-Language RFC 8785 + Web Crypto Ed25519 Parity Verifier (Node 20+ / 24+).
 * Proves that:
 * 1. The JS/TS JCS canonicalizer produces byte-for-byte identical output & SHA-256 digest
 *    to Python `ciaf_lcm.canonical` on astral-plane Unicode, `-0.0`, ES6 floats, and control chars.
 * 2. A capsule signed in Python `cryptography` verifies cleanly in `SubtleCrypto` using OKP JWK.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(__dirname, "../src/fixtures/python_cross_lang_fixture.json");
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf-8"));

const SHORT_ESCAPES = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

function compareUtf16CodeUnits(a, b) {
  const minLen = Math.min(a.length, b.length);
  for (let i = 0; i < minLen; i++) {
    const diff = a.charCodeAt(i) - b.charCodeAt(i);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

function serializeJcsString(value) {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code in SHORT_ESCAPES) out += SHORT_ESCAPES[code];
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else if (code >= 0xd800 && code <= 0xdbff) {
      out += value.slice(i, i + 2);
      i++;
    } else out += value[i];
  }
  return out + '"';
}

function canonicalizeJcsStr(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("NaN/Infinity forbidden");
    return value === 0 ? "0" : value.toString();
  }
  if (typeof value === "string") return serializeJcsString(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalizeJcsStr).join(",") + "]";
  const keys = Object.keys(value).sort(compareUtf16CodeUnits);
  return "{" + keys.map((k) => `${serializeJcsString(k)}:${canonicalizeJcsStr(value[k])}`).join(",") + "}";
}

async function jcsSha256(value) {
  const bytes = new TextEncoder().encode(canonicalizeJcsStr(value));
  const buf = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

function b64uDecode(encoded) {
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((encoded.length + 3) % 4);
  return Uint8Array.from(Buffer.from(padded, "base64"));
}

async function main() {
  // 1. Test JCS torture vector (including explicit JS -0.0 injection!)
  const liveVector = structuredClone(fixture.jcs_torture_vector.input);
  liveVector.numbers.neg_zero = -0.0;

  const tsCanonical = canonicalizeJcsStr(liveVector);
  const tsDigest = await jcsSha256(liveVector);

  if (tsCanonical !== fixture.jcs_torture_vector.expected_canonical_jcs) {
    throw new Error(
      `JCS canonical mismatch!\nTS: ${tsCanonical}\nPY: ${fixture.jcs_torture_vector.expected_canonical_jcs}`
    );
  }
  if (tsDigest !== fixture.jcs_torture_vector.expected_sha256) {
    throw new Error(`JCS SHA-256 mismatch: ${tsDigest} != ${fixture.jcs_torture_vector.expected_sha256}`);
  }

  // 2. Verify Python-signed AuditCapsule using Node Web Crypto SubtleCrypto + OKP JWK
  const capsule = fixture.python_signed_capsule;
  const keysById = new Map(fixture.trusted_key_manifest.map((k) => [k.key_id, k]));

  const capNoDigest = { ...capsule };
  delete capNoDigest.capsule_digest;
  if ((await jcsSha256(capNoDigest)) !== capsule.capsule_digest) {
    throw new Error("Capsule digest mismatch across Python -> JS JCS!");
  }

  if (capsule.authority_attestation) {
    const attWithSig = { ...capsule.authority_attestation };
    delete attWithSig.attestation_digest;
    if ((await jcsSha256(attWithSig)) !== capsule.authority_attestation.attestation_digest) {
      throw new Error("authority_attestation digest mismatch across Python -> JS JCS!");
    }
    const attUnsigned = { ...attWithSig };
    delete attUnsigned.signature;
    const rgEntry = keysById.get(capsule.authority_attestation.signature.key_id);
    const rgPub = await globalThis.crypto.subtle.importKey(
      "jwk",
      rgEntry.public_key_jwk,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    const rgOk = await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      rgPub,
      b64uDecode(capsule.authority_attestation.signature.sig_b64u),
      new TextEncoder().encode(canonicalizeJcsStr(attUnsigned))
    );
    if (!rgOk) {
      throw new Error("Web Crypto Ed25519 verification failed for Python-signed authority_attestation");
    }
  }

  for (const claim of [...capsule.authorization_claims, ...capsule.execution_claims]) {
    const withSig = { ...claim };
    delete withSig.claim_digest;
    if ((await jcsSha256(withSig)) !== claim.claim_digest) {
      throw new Error(`Claim digest mismatch on ${claim.claim_id}`);
    }

    const unsignedBody = { ...withSig };
    delete unsignedBody.signature;

    const entry = keysById.get(claim.signature.key_id);
    const pubKey = await globalThis.crypto.subtle.importKey(
      "jwk",
      entry.public_key_jwk,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    const ok = await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      pubKey,
      b64uDecode(claim.signature.sig_b64u),
      new TextEncoder().encode(canonicalizeJcsStr(unsignedBody))
    );
    if (!ok) {
      throw new Error(`Web Crypto Ed25519 verification failed for Python-signed ${claim.claim_id}`);
    }
  }

  console.log("PASS: Cross-language Python <-> Web Crypto JCS & Ed25519 OKP JWK parity verified byte-for-byte.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

