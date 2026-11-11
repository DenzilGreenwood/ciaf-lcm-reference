// Copyright 2026 CIAF-LCM Working Group Contributors
// SPDX-License-Identifier: Apache-2.0
/**
 * Strict RFC 8785 (JSON Canonicalization Scheme / JCS) implementation in TypeScript.
 *
 * Parity Guarantees with Python `ciaf_lcm.canonical`:
 * 1. Normalizes `-0` (`Object.is(n, -0)`) to `"0"` and rejects `NaN` / `Infinity`.
 * 2. Formats IEEE-754 numbers via ECMAScript `Number.prototype.toString()` (RFC 8785 §3.2.2.3).
 * 3. Escapes strings minimally per RFC 8785 §3.2.2.2 and rejects lone UTF-16 surrogates.
 * 4. Sorts object keys strictly by 16-bit UTF-16 code units (`charCodeAt`) per RFC 8785 §3.2.3.
 */

const SHORT_ESCAPES: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

export function compareUtf16CodeUnits(a: string, b: string): number {
  const minLen = Math.min(a.length, b.length);
  for (let i = 0; i < minLen; i++) {
    const diff = a.charCodeAt(i) - b.charCodeAt(i);
    if (diff !== 0) {
      return diff;
    }
  }
  return a.length - b.length;
}

function assertNoLoneSurrogates(str: string): void {
  for (let i = 0; i < str.length; i++) {
    const unit = str.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < str.length ? str.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        throw new Error("RFC 8785 forbids unpaired high UTF-16 surrogate in JSON string.");
      }
      i++; // valid surrogate pair consumed
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error("RFC 8785 forbids unpaired low UTF-16 surrogate in JSON string.");
    }
  }
}

function serializeJcsString(value: string): string {
  assertNoLoneSurrogates(value);
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code in SHORT_ESCAPES) {
      out += SHORT_ESCAPES[code];
    } else if (code < 0x20) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else if (code >= 0xd800 && code <= 0xdbff) {
      // Emit full astral character (high + low surrogate) literally as UTF-8
      out += value.slice(i, i + 2);
      i++;
    } else {
      out += value[i];
    }
  }
  out += '"';
  return out;
}

export function canonicalizeJcsStr(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (value === true) {
    return "true";
  }
  if (value === false) {
    return "false";
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("RFC 8785 forbids NaN and Infinity in JSON numbers.");
    }
    if (value === 0) {
      // Covers both +0 and -0
      return "0";
    }
    return value.toString();
  }
  if (typeof value === "string") {
    return serializeJcsString(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((elem) => canonicalizeJcsStr(elem)).join(",") + "]";
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort(compareUtf16CodeUnits);
    const members: string[] = [];
    for (const k of keys) {
      const v = record[k];
      if (v === undefined || typeof v === "function" || typeof v === "symbol") {
        throw new Error(`Unsupported property value for key '${k}' in RFC 8785 serialization.`);
      }
      members.push(`${serializeJcsString(k)}:${canonicalizeJcsStr(v)}`);
    }
    return "{" + members.join(",") + "}";
  }
  throw new Error(`Unsupported type for RFC 8785 canonicalization: ${typeof value}`);
}

export function canonicalizeJcsBytes(value: unknown): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(canonicalizeJcsStr(value));
  const buf = new ArrayBuffer(encoded.byteLength);
  const out = new Uint8Array(buf);
  out.set(encoded);
  return out;
}

export async function jcsSha256(value: unknown): Promise<string> {
  const bytes = canonicalizeJcsBytes(value);
  const hashBuf = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  const hashArray = Array.from(new Uint8Array(hashBuf));
  const hex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

export async function computeRequestDigest(
  toolName: string,
  operation: string,
  parameters: Record<string, unknown>
): Promise<string> {
  return jcsSha256({
    tool_name: toolName,
    operation,
    parameters,
  });
}

