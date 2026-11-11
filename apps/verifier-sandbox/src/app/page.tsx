"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import crossLangFixture from "@/fixtures/python_cross_lang_fixture.json";
import { canonicalizeJcsStr, jcsSha256 } from "@/lib/jcs";
import {
  AXIS_A_CONTROLS,
  AXIS_B_CONTROLS,
  type AssuranceClaim,
  type AuditCapsule,
  type CiafControlId,
  type ReadinessScoresInput,
  type SandboxScenarioMode,
  type TrustedKeyEntry,
  createUniformControlScores,
  deleteChainReceiptAttack,
  evaluateTwoAxisReadiness,
  generateSandboxScenario,
  tamperCapsuleReceipt,
  verifyCapsuleZeroTrust,
} from "@/lib/ciafWebCrypto";

type InspectorTab = "CLAIMS" | "CANONICAL_JCS" | "KEY_MANIFEST" | "ASSURANCE_JSON";
type IndustryProfile = "BANKING" | "HEALTHCARE" | "TRIBAL_GAMING";
type KeyCustodyMode = "PYTHON_DETERMINISTIC_FIXTURE" | "BROWSER_SANDBOX_KEYS";

const INDUSTRY_NOTES: Record<
  IndustryProfile,
  { title: string; subtitle: string; bullets: string[] }
> = {
  BANKING: {
    title: "Regional Banking & Treasury Operations",
    subtitle: "Post-SR 11-7 Supervisory Baseline (2026: SR 26-2 / OCC 2026-13 / FIL-15-2026)",
    bullets: [
      "Primary MRM Instruments (April 17, 2026): Federal Reserve SR 26-2, OCC Bulletin 2026-13, and FDIC FIL-15-2026 rescinded and superseded 2011 MRM guidance (SR 11-7 / OCC 2011-12 / FIL-22-2017) and 2021 BSA/AML MRM statements (SR 21-8 / OCC 2021-19 / FIL-27-2021). Generative and agentic AI are explicitly excluded from direct MRM scope as 'novel and rapidly evolving,' while requiring governance under broader safety-and-soundness risk programs.",
      "Forthcoming AI Guidance (RFI): In the April 17, 2026 issuance, the Fed, OCC, and FDIC signaled a forthcoming Request for Information (RFI) on banks' use of generative and agentic AI; exclusion from SR 26-2 does not create a supervisory safe harbor.",
      "Third-Party Risk Management (TPRM) Applies: External foundation models, hosted agent APIs, and third-party guardrails remain governed under the June 2023 Interagency Guidance on Third-Party Relationships (SR 23-4 / OCC 2023-17 / FIL-29-2023), which stays in force while the OCC/Fed/FDIC/NCUA proposed TPRM revision (91 FR 58536, Sept. 15, 2026; OCC Bulletin 2026-46 — pending finalization) awaits final agency action.",
      "Operational Controls (CIAF-04..08): Consequential treasury/payment agents (payments.create) require pinned delegated limits in ISO-4217 integer minor currency units (CIAF-04), segregation-of-duties human escalation signatures (CIAF-07), rolling velocity caps, and dual-key <=30s single-use grants (CIAF-08) to block TOCTOU mutations ($500.00 -> $50,000.00) prior to settlement.",
    ],
  },
  HEALTHCARE: {
    title: "Healthcare Systems (HIPAA Security & Privacy Safeguards)",
    subtitle: "45 CFR § 164.312 Technical Safeguards & Minimum Necessary ePHI",
    bullets: [
      "Scopes domain-neutral agent delegations (CIAF-04) to the minimum ePHI tool surface needed for the registered clinical or revenue-cycle business_purpose (CIAF-01).",
      "Enforces independent HUMAN_REVIEWER cryptographic adjudication (CIAF-07) before clinical order or prior-authorization mutations.",
      "Requires >=128-bit salted RFC 8785 SHA-256 or HMAC-SHA256 commitments before anchoring ePHI digests in external IETF SCITT (RFC 9943 / RFC 9942) logs to prevent low-entropy brute-force.",
    ],
  },
  TRIBAL_GAMING: {
    title: "Tribal Gaming Operations (NIGC MICS / TICS & Compacts)",
    subtitle: "25 CFR Part 543 (Class II) vs. Tribal-State Compact (Class III) Boundaries",
    bullets: [
      "Separates Class II MICS/TICS workflows from Class III compacted gaming systems inside digest-pinned policy_document scopes (CIAF-01, CIAF-05).",
      "Gates patron wallet transfers, promotional credit awards, and cage adjustments via CIAF-06 thresholds and pit/cage supervisor sign-off (CIAF-07).",
      "Delivers offline-verifiable AuditCapsules (CIAF-10) and CIAF-11 security exception alerts to Surveillance and independent TGRA revenue auditors.",
    ],
  },
};

export default function VerifierSandboxPage() {
  const [activeLabel, setActiveLabel] = useState<string>(
    "Python-Signed Interop Fixture (ALLOW $450.00 / 45,000 minor units)"
  );
  const [keyCustodyMode, setKeyCustodyMode] = useState<KeyCustodyMode>(
    "PYTHON_DETERMINISTIC_FIXTURE"
  );
  const [capsule, setCapsule] = useState<AuditCapsule>(
    () => structuredClone(crossLangFixture.python_signed_capsule) as AuditCapsule
  );
  const [trustedKeys, setTrustedKeys] = useState<TrustedKeyEntry[]>(
    () => structuredClone(crossLangFixture.trusted_key_manifest) as TrustedKeyEntry[]
  );
  const [assurance, setAssurance] = useState<AssuranceClaim | null>(null);
  const [jcsParityStatus, setJcsParityStatus] = useState<{
    checked: boolean;
    jcsMatch: boolean;
    digestMatch: boolean;
    ed25519Verified: boolean;
    digest: string;
    durationMs: number;
  }>({
    checked: false,
    jcsMatch: false,
    digestMatch: false,
    ed25519Verified: false,
    digest: "",
    durationMs: 0,
  });
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("CLAIMS");
  const [busy, setBusy] = useState<boolean>(false);
  const [copiedNotice, setCopiedNotice] = useState<boolean>(false);

  const repoBaseUrl =
    process.env.NEXT_PUBLIC_GITHUB_REPO_URL ||
    "https://github.com/DenzilGreenwood/ciaf-lcm-reference";

  // 2-Axis Per-Control Readiness Scorecard state (12 individual controls: CIAF-01..12)
  const [industry, setIndustry] = useState<IndustryProfile>("BANKING");
  const [scores, setScores] = useState<ReadinessScoresInput>(() => ({
    controls: createUniformControlScores(3, {
      "CIAF-01": 4,
      "CIAF-02": 4,
      "CIAF-05": 4,
    }),
    scittRegistered: false,
    sharedSigningKeysDetected: false,
  }));

  const readiness = useMemo(() => evaluateTwoAxisReadiness(scores), [scores]);

  const setControlScore = (id: CiafControlId, val: number) => {
    setScores((prev) => ({
      ...prev,
      controls: {
        ...prev.controls,
        [id]: val,
      },
    }));
  };

  const runVerification = useCallback(
    async (
      nextCapsule: AuditCapsule,
      nextKeys: TrustedKeyEntry[],
      label: string,
      custody: KeyCustodyMode
    ) => {
      setBusy(true);
      try {
        const result = await verifyCapsuleZeroTrust(nextCapsule, nextKeys);
        setCapsule(nextCapsule);
        setTrustedKeys(nextKeys);
        setAssurance(result);
        setActiveLabel(label);
        setKeyCustodyMode(custody);
      } finally {
        setBusy(false);
      }
    },
    []
  );

  // Live in-browser mount verification: executes real JCS + SubtleCrypto.digest('SHA-256') + SubtleCrypto.verify('Ed25519')
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const tStart = performance.now();
      const liveVector: Record<string, any> = structuredClone(
        crossLangFixture.jcs_torture_vector.input
      );
      liveVector.numbers.neg_zero = -0.0; // Explicit live JS -0.0 IEEE-754 edge test
      const tsStr = canonicalizeJcsStr(liveVector);
      const tsDigest = await jcsSha256(liveVector);
      const jcsMatch = tsStr === crossLangFixture.jcs_torture_vector.expected_canonical_jcs;
      const digestMatch = tsDigest === crossLangFixture.jcs_torture_vector.expected_sha256;

      const initCapsule = structuredClone(crossLangFixture.python_signed_capsule) as AuditCapsule;
      const initKeys = structuredClone(
        crossLangFixture.trusted_key_manifest
      ) as TrustedKeyEntry[];
      const verified = await verifyCapsuleZeroTrust(initCapsule, initKeys);
      const elapsedMs = Number((performance.now() - tStart).toFixed(2));

      if (!cancelled) {
        setJcsParityStatus({
          checked: true,
          jcsMatch,
          digestMatch,
          ed25519Verified: verified.capsule_valid && verified.checks.ed25519_signatures_valid,
          digest: tsDigest,
          durationMs: elapsedMs,
        });
        setAssurance(verified);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleLoadPythonFixture = async () => {
    await runVerification(
      structuredClone(crossLangFixture.python_signed_capsule) as AuditCapsule,
      structuredClone(crossLangFixture.trusted_key_manifest) as TrustedKeyEntry[],
      "Python-Signed Interop Fixture (ALLOW $450.00 / 45,000 minor units)",
      "PYTHON_DETERMINISTIC_FIXTURE"
    );
  };

  const handleSimulate = async (mode: SandboxScenarioMode, label: string) => {
    setBusy(true);
    try {
      const generated = await generateSandboxScenario(mode);
      await runVerification(
        generated.capsule,
        generated.trustedKeys,
        label,
        "BROWSER_SANDBOX_KEYS"
      );
    } finally {
      setBusy(false);
    }
  };

  const handleTamperReceipt = async () => {
    const tampered = tamperCapsuleReceipt(capsule);
    await runVerification(
      tampered,
      trustedKeys,
      `${activeLabel} -> [TAMPERED: amount_minor_units mutated to 4,500,000 ($45,000.00)]`,
      keyCustodyMode
    );
  };

  const handleDeleteChainLink = async () => {
    const chainBroken = await deleteChainReceiptAttack(capsule);
    await runVerification(
      chainBroken,
      trustedKeys,
      `${activeLabel} -> [ATTACK: Receipt Deleted from Hash-Chain]`,
      keyCustodyMode
    );
  };

  const handleExportCapsuleJson = () => {
    const jsonBytes = JSON.stringify(capsule, null, 2) + "\n";
    const blob = new Blob([jsonBytes], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${capsule.capsule_id || "ciaf-lcm"}.audit-capsule.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopyCapsuleJson = async () => {
    await navigator.clipboard.writeText(JSON.stringify(capsule, null, 2));
    setCopiedNotice(true);
    setTimeout(() => setCopiedNotice(false), 2000);
  };

  const canonicalPreview = useMemo(() => {
    try {
      return canonicalizeJcsStr(capsule);
    } catch (e) {
      return `Canonicalization error: ${String(e)}`;
    }
  }, [capsule]);

  const liveParityAllPassed =
    jcsParityStatus.checked &&
    jcsParityStatus.jcsMatch &&
    jcsParityStatus.digestMatch &&
    jcsParityStatus.ed25519Verified;

  const statusColor = !assurance
    ? "border-slate-700 bg-slate-900/70 text-slate-300"
    : assurance.capsule_valid
      ? assurance.assurance_disposition === "ASSURED_SECURITY_EXCEPTION_CONTAINED"
        ? "border-amber-500/50 bg-amber-950/30 text-amber-200"
        : "border-emerald-500/50 bg-emerald-950/30 text-emerald-200"
      : "border-rose-500/70 bg-rose-950/40 text-rose-200";

  return (
    <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      {/* Header */}
      <header className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-xl">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
              <span className="rounded bg-cyan-950/80 px-2.5 py-1 border border-cyan-800/60">
                CIAF-LCM v0.1.1 • Public Comment Draft (Open through February 10, 2027)
              </span>
              <span className="rounded bg-slate-800 px-2.5 py-1 text-slate-300">
                RFC 8785 (JCS) + Web Crypto Ed25519
              </span>
              <span className="rounded bg-slate-800 px-2.5 py-1 text-slate-300">
                Stateless Client-Side Verifier
              </span>
            </div>
            <h1 className="mt-3 text-2xl font-bold tracking-tight text-white sm:text-3xl">
              Receipt &amp; Audit Readiness Inspector
            </h1>
            <p className="mt-1 font-mono text-xs sm:text-sm text-slate-400">
              Capability != Authority != Authorization != Execution != Assurance
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-2 text-xs font-mono">
              <button
                onClick={handleExportCapsuleJson}
                className="rounded-lg border border-cyan-600/80 bg-cyan-950/70 px-3 py-1.5 font-semibold text-cyan-100 hover:bg-cyan-900/80 transition cursor-pointer"
              >
                Export AuditCapsule (.json)
              </button>
              <button
                onClick={handleCopyCapsuleJson}
                className="rounded-lg border border-slate-700 bg-slate-800/90 px-3 py-1.5 text-slate-200 hover:bg-slate-700 transition cursor-pointer"
              >
                {copiedNotice ? "Copied JSON!" : "Copy Capsule JSON"}
              </button>
              <a
                href={`${repoBaseUrl}/blob/main/controls/ciaf-control-catalog-v0.1.md`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-1.5 text-slate-300 hover:border-cyan-700 hover:text-cyan-200 transition"
              >
                Control Catalog (CIAF-01..12) ↗
              </a>
              <a
                href={`${repoBaseUrl}/tree/main/schemas`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-1.5 text-slate-300 hover:border-cyan-700 hover:text-cyan-200 transition"
              >
                JSON Schemas (2020-12) ↗
              </a>
              <a
                href={`${repoBaseUrl}/blob/main/standards-crosswalks/ietf-scitt-profile-v0.1.md`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-1.5 text-slate-300 hover:border-cyan-700 hover:text-cyan-200 transition"
              >
                IETF SCITT (RFC 9943 / 9942) ↗
              </a>
            </div>
          </div>

          {/* Live Computed Cross-Language Torture-Vector & SubtleCrypto Parity Panel */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/90 p-3.5 text-xs font-mono space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-block h-2.5 w-2.5 rounded-full ${
                  liveParityAllPassed ? "bg-emerald-400" : "bg-amber-400"
                }`}
              />
              <span className="font-semibold text-slate-200">
                Live SubtleCrypto Parity Check:
              </span>
              <span
                className={
                  liveParityAllPassed ? "text-emerald-400 font-bold" : "text-amber-400"
                }
              >
                {!jcsParityStatus.checked
                  ? "COMPUTING IN BROWSER..."
                  : `JCS=${String(jcsParityStatus.jcsMatch)} | SHA256=${String(
                      jcsParityStatus.digestMatch
                    )} | Ed25519=${String(jcsParityStatus.ed25519Verified)} (${
                      jcsParityStatus.durationMs
                    } ms)`}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 truncate max-w-lg">
              Live Digest (-0.0, U+1F600 &lt; U+E000): {jcsParityStatus.digest || "computing..."}
            </div>
          </div>
        </div>
      </header>

      {/* Scenario & Adversarial Controls */}
      <section className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-cyan-400">
            1. Simulate Governance Flows (`agent-finance-01` -&gt; `payments.create`)
          </h2>
          <p className="text-xs text-slate-400">
            Generate fresh in-browser Dual-Key Web Crypto Ed25519 receipts (`amount_minor_units`,
            `minor_unit_scale: 2`) or reload the deterministic Python-signed interop capsule.
          </p>
          <div className="flex flex-wrap gap-2 pt-1">
            <button
              disabled={busy}
              onClick={handleLoadPythonFixture}
              className="rounded-lg border border-cyan-700/70 bg-cyan-950/50 px-3 py-2 text-xs font-medium text-cyan-200 hover:bg-cyan-900/60 transition cursor-pointer disabled:opacity-50"
            >
              Python Interop Capsule ($450.00)
            </button>
            <button
              disabled={busy}
              onClick={() =>
                handleSimulate(
                  "ALLOW",
                  "WebCrypto ALLOW ($450.00 / 45,000 minor units)"
                )
              }
              className="rounded-lg border border-emerald-700/70 bg-emerald-950/50 px-3 py-2 text-xs font-medium text-emerald-200 hover:bg-emerald-900/60 transition cursor-pointer disabled:opacity-50"
            >
              Simulate ALLOW ($450.00)
            </button>
            <button
              disabled={busy}
              onClick={() =>
                handleSimulate(
                  "DENY",
                  "WebCrypto DENY ($75,000.00 AUTHORITY_SCOPE_EXCEEDED)"
                )
              }
              className="rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700 transition cursor-pointer disabled:opacity-50"
            >
              Simulate DENY ($75,000.00)
            </button>
            <button
              disabled={busy}
              onClick={() =>
                handleSimulate(
                  "ESCALATE",
                  "WebCrypto ESCALATE -> Signed Human Approval ($12,500.00)"
                )
              }
              className="rounded-lg border border-indigo-700/70 bg-indigo-950/50 px-3 py-2 text-xs font-medium text-indigo-200 hover:bg-indigo-900/60 transition cursor-pointer disabled:opacity-50"
            >
              Simulate ESCALATE ($12,500.00)
            </button>
          </div>
        </div>

        <div className="rounded-2xl border border-rose-900/50 bg-slate-900/60 p-5 space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-rose-400">
            2. Adversarial Fault &amp; Attack Injectors
          </h2>
          <p className="text-xs text-slate-400">
            Attack the active capsule or simulate replay, key-forgery, and rogue-gateway violations
            caught by the Stateless Verifier (`CIAF-10`).
          </p>
          <div className="flex flex-wrap gap-2 pt-1">
            <button
              disabled={busy}
              onClick={handleTamperReceipt}
              className="rounded-lg border border-rose-700/80 bg-rose-950/60 px-3 py-2 text-xs font-semibold text-rose-200 hover:bg-rose-900/70 transition cursor-pointer disabled:opacity-50"
            >
              Tamper Receipt ($45,000.00)
            </button>
            <button
              disabled={busy}
              onClick={() =>
                handleSimulate(
                  "REPLAY_CONTAINED",
                  "Replay Attack -> Blocked by Executor (CIAF-08 / CIAF-11)"
                )
              }
              className="rounded-lg border border-amber-700/80 bg-amber-950/60 px-3 py-2 text-xs font-semibold text-amber-200 hover:bg-amber-900/70 transition cursor-pointer disabled:opacity-50"
            >
              Simulate Replay (Contained)
            </button>
            <button
              disabled={busy}
              onClick={() =>
                handleSimulate(
                  "UNBLOCKED_REPLAY_VIOLATION",
                  "Unblocked Replay Violation (Duplicate Consumed Nonce)"
                )
              }
              className="rounded-lg border border-rose-700/80 bg-rose-950/60 px-3 py-2 text-xs font-semibold text-rose-200 hover:bg-rose-900/70 transition cursor-pointer disabled:opacity-50"
            >
              Inject Duplicate Nonce
            </button>
            <button
              disabled={busy}
              onClick={handleDeleteChainLink}
              className="rounded-lg border border-rose-700/80 bg-rose-950/60 px-3 py-2 text-xs font-semibold text-rose-200 hover:bg-rose-900/70 transition cursor-pointer disabled:opacity-50"
            >
              Delete Hash-Chain Receipt
            </button>
            <button
              disabled={busy}
              onClick={() =>
                handleSimulate(
                  "WRONG_KEY_FORGERY",
                  "Forged ExecutionClaim Signed with Gateway Key (CIAF-08)"
                )
              }
              className="rounded-lg border border-rose-700/80 bg-rose-950/60 px-3 py-2 text-xs font-semibold text-rose-200 hover:bg-rose-900/70 transition cursor-pointer disabled:opacity-50"
            >
              Forge with Gateway Key
            </button>
            <button
              disabled={busy}
              onClick={() =>
                handleSimulate(
                  "ROGUE_GATEWAY_SCOPE_BYPASS",
                  "Rogue Gateway Unescalated ALLOW ($8,500.00 > $5,000.00 Scope Snapshot)"
                )
              }
              className="rounded-lg border border-rose-700/80 bg-rose-950/60 px-3 py-2 text-xs font-semibold text-rose-200 hover:bg-rose-900/70 transition cursor-pointer disabled:opacity-50"
            >
              Rogue Gateway Scope Bypass ($8,500)
            </button>
          </div>
        </div>
      </section>

      {/* Independent Stateless Verification Banner & Check Matrix */}
      <section className={`rounded-2xl border p-6 space-y-5 ${statusColor}`}>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="text-xs font-mono uppercase opacity-80">
              Active Scenario: {activeLabel}
            </div>
            <h2 className="mt-1 text-xl font-bold tracking-tight">
              Stateless Verifier Disposition:{" "}
              <span className="font-mono">
                {assurance ? assurance.assurance_disposition : "VERIFYING..."}
              </span>
            </h2>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md border border-slate-600/80 bg-slate-900/90 px-2.5 py-1 text-xs font-mono font-semibold text-cyan-200">
              {keyCustodyMode === "BROWSER_SANDBOX_KEYS"
                ? "STATELESS VERIFIER (BROWSER SANDBOX KEYS)"
                : "STATELESS VERIFIER (PYTHON FIXTURE KEYS)"}
            </span>
            {assurance?.failed_controls.map((ctrl) => (
              <span
                key={ctrl}
                className="rounded-md bg-rose-600 px-2.5 py-1 text-xs font-mono font-bold text-white shadow"
              >
                FAILED: {ctrl}
              </span>
            ))}
            {assurance?.capsule_valid && (
              <span className="rounded-md bg-emerald-600 px-3 py-1 text-xs font-mono font-bold text-white shadow">
                CAPSULE VALID (STATELESS VERIFIER)
              </span>
            )}
          </div>
        </div>

        {/* 8-Check Grid */}
        {assurance && (
          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
            {[
              ["Wire Schema (2020-12)", assurance.checks.schema_validation_passed],
              ["RFC 8785 Digests", assurance.checks.rfc8785_digests_valid],
              ["Dual-Key Boundary", assurance.checks.dual_key_trust_boundary_valid],
              ["Ed25519 Signatures", assurance.checks.ed25519_signatures_valid],
              ["Policy Digest Pinning", assurance.checks.policy_digest_binding_valid],
              ["Grant Nonce & <=30s TTL", assurance.checks.grant_nonce_and_ttl_valid],
              ["Hash-Chain Continuity", assurance.checks.hash_chain_continuity_valid],
              ["Scope Snapshot & Semantics", assurance.checks.semantic_consistency_valid],
            ].map(([label, ok]) => (
              <div
                key={String(label)}
                className={`rounded-lg border px-3 py-2 text-xs font-mono flex items-center justify-between ${
                  ok
                    ? "border-emerald-500/30 bg-slate-950/60 text-emerald-300"
                    : "border-rose-500/60 bg-rose-950/70 text-rose-200 font-bold"
                }`}
              >
                <span>{String(label)}</span>
                <span>{ok ? "PASS" : "FAIL"}</span>
              </div>
            ))}
          </div>
        )}

        {/* Findings List */}
        {assurance && assurance.findings.length > 0 && (
          <div className="space-y-1.5 rounded-xl bg-slate-950/80 p-4 border border-slate-800">
            <div className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Verifier Findings &amp; Completeness Notice
            </div>
            {assurance.findings.map((f, idx) => (
              <div
                key={`${f.code}-${idx}`}
                className="flex flex-wrap items-baseline gap-2 text-xs font-mono"
              >
                <span
                  className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                    f.severity === "CRITICAL"
                      ? "bg-rose-600 text-white"
                      : "bg-cyan-900 text-cyan-200"
                  }`}
                >
                  {f.severity}
                </span>
                <span className="text-amber-300 font-semibold">[{f.control_id}]</span>
                <span className="text-slate-200 font-semibold">{f.code}:</span>
                <span className="text-slate-300">{f.message}</span>
              </div>
            ))}
            <div className="pt-2 text-[11px] font-mono text-slate-400 border-t border-slate-800/80">
              SCITT &amp; Clock Notice: {assurance.completeness_notice}
            </div>
          </div>
        )}

        {/* Explicit Sandbox Key Custody Disclosure (Deduplicated from SCITT & Clock Notice) */}
        <div className="rounded-xl border border-slate-700/80 bg-slate-950/85 p-3.5 text-xs text-slate-300 leading-relaxed">
          <span className="font-semibold text-cyan-300">Sandbox Key Custody Notice: </span>
          The Stateless Verifier (<code className="text-cyan-200">CIAF-10</code>) validates wire
          schemas (<code className="text-cyan-200">schema_version: &quot;0.1.0&quot;</code>), RFC
          8785 digests, <code className="text-cyan-200">delegated_scope_snapshot</code>{" "}
          constraints, and role-pinned Ed25519 signatures using <strong>only</strong> the{" "}
          <code className="text-cyan-200">AuditCapsule</code> and out-of-band{" "}
          <code className="text-cyan-200">trusted_keys</code> OKP JWK manifest (zero runtime
          database or private-key access). Interactive browser simulations generate ephemeral
          signing keys in memory for demonstration; production deployments require isolated
          KMS/HSM security domains per role.
        </div>
      </section>

      {/* Cryptographic & Canonical JSON Inspector */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">
              3. Cryptographic Capsule, Canonical JCS &amp; Signature Inspector
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              capsule_digest: {capsule.capsule_digest}
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {(
              [
                ["CLAIMS", "AuditCapsule & Dual-Signed Claims"],
                ["CANONICAL_JCS", "RFC 8785 Canonical Bytes (JCS)"],
                ["KEY_MANIFEST", "Trusted OKP JWK Manifest"],
                ["ASSURANCE_JSON", "Verifier AssuranceClaim"],
              ] as const
            ).map(([tabId, label]) => (
              <button
                key={tabId}
                onClick={() => setInspectorTab(tabId)}
                className={`rounded-lg px-3 py-1.5 text-xs font-mono transition cursor-pointer ${
                  inspectorTab === tabId
                    ? "bg-cyan-600 text-white font-semibold"
                    : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {inspectorTab === "CLAIMS" && (
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="space-y-2">
              <div className="text-xs font-mono font-semibold text-cyan-300">
                AuthorizationClaims ({capsule.authorization_claims?.length || 0}) — Gateway Key
              </div>
              <pre className="max-h-96 overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs font-mono text-slate-200">
                {JSON.stringify(capsule.authorization_claims, null, 2)}
              </pre>
            </div>
            <div className="space-y-2">
              <div className="text-xs font-mono font-semibold text-emerald-300">
                ExecutionClaims ({capsule.execution_claims?.length || 0}) — Executor Key
              </div>
              <pre className="max-h-96 overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs font-mono text-slate-200">
                {JSON.stringify(capsule.execution_claims, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {inspectorTab === "CANONICAL_JCS" && (
          <div className="space-y-2">
            <div className="text-xs font-mono text-slate-400">
              Deterministic UTF-16 Key-Sorted, Whitespace-Free RFC 8785 Serialization ({canonicalPreview.length} UTF-8 chars):
            </div>
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs font-mono text-cyan-200">
              {canonicalPreview}
            </pre>
          </div>
        )}

        {inspectorTab === "KEY_MANIFEST" && (
          <pre className="max-h-96 overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs font-mono text-amber-200">
            {JSON.stringify(trustedKeys, null, 2)}
          </pre>
        )}

        {inspectorTab === "ASSURANCE_JSON" && (
          <pre className="max-h-96 overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs font-mono text-emerald-200">
            {JSON.stringify(assurance, null, 2)}
          </pre>
        )}
      </section>

      {/* Interactive 2-Axis Per-Control Audit Readiness Scorecard */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 space-y-6">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">
              4. Interactive 2-Axis Per-Control Readiness Scorecard (`CIAF-01`..`CIAF-12`)
            </h2>
            <p className="text-xs text-slate-400">
              Partitions Axis A (`10` Design &amp; Runtime Controls) and Axis B (`2` Provenance &amp;
              Verification Controls) without single-score blending (`CIAF-LCM-AUDIT-v0.1.1`).
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() =>
                setScores({
                  controls: createUniformControlScores(4, {
                    "CIAF-08": 1,
                    "CIAF-09": 3,
                    "CIAF-10": 3,
                  }),
                  scittRegistered: false,
                  sharedSigningKeysDetected: false,
                })
              }
              className="rounded-lg border border-rose-700/70 bg-rose-950/50 px-3 py-1.5 text-xs font-medium text-rose-200 hover:bg-rose-900/60 cursor-pointer"
            >
              Preset: High Policy (4/4) + Broken Executor (CIAF-08=1/4)
            </button>
            <button
              onClick={() =>
                setScores({
                  controls: createUniformControlScores(4, {
                    "CIAF-12": 1,
                    "CIAF-09": 3,
                    "CIAF-10": 3,
                  }),
                  scittRegistered: false,
                  sharedSigningKeysDetected: false,
                })
              }
              className="rounded-lg border border-amber-700/70 bg-amber-950/50 px-3 py-1.5 text-xs font-medium text-amber-200 hover:bg-amber-900/60 cursor-pointer"
            >
              Preset: Missing Kill-Switch (CIAF-12=1/4 -&gt; Gate 3)
            </button>
            <button
              onClick={() =>
                setScores({
                  controls: createUniformControlScores(3),
                  scittRegistered: false,
                  sharedSigningKeysDetected: false,
                })
              }
              className="rounded-lg border border-cyan-700/70 bg-cyan-950/50 px-3 py-1.5 text-xs font-medium text-cyan-200 hover:bg-cyan-900/60 cursor-pointer"
            >
              Preset: Reference v0.1.1 (Local Provenance 3/4)
            </button>
            <button
              onClick={() =>
                setScores({
                  controls: createUniformControlScores(4),
                  scittRegistered: true,
                  sharedSigningKeysDetected: false,
                })
              }
              className="rounded-lg border border-emerald-700/70 bg-emerald-950/50 px-3 py-1.5 text-xs font-medium text-emerald-200 hover:bg-emerald-900/60 cursor-pointer"
            >
              Preset: Full SCITT RFC 9943/9942 Completeness (4/4)
            </button>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-12">
          {/* 12 Per-Control Sliders Partitioned into Axis A (10) & Axis B (2) */}
          <div className="lg:col-span-7 space-y-5 rounded-xl border border-slate-800 bg-slate-950/70 p-5">
            {/* Axis A Block */}
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <div className="text-xs font-mono font-bold uppercase text-cyan-300">
                  Axis A — Control Design &amp; Runtime Maturity (10 Controls: CIAF-01..08, 11..12)
                </div>
                <div className="text-xs font-mono text-slate-300">
                  Raw Mean (sum/10):{" "}
                  <span className="font-bold text-cyan-300">
                    {readiness.rawAxisAMean.toFixed(2)}
                  </span>{" "}
                  | Min: <span className="font-bold text-cyan-300">{readiness.axisAMin}/4</span>
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                {AXIS_A_CONTROLS.map((ctrl) => (
                  <div
                    key={ctrl.id}
                    className="rounded-lg border border-slate-800/90 bg-slate-900/60 p-2.5 space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono gap-2">
                      <span className="inline-flex flex-wrap items-center gap-1.5 text-slate-200 font-semibold">
                        <span>{ctrl.id}</span>
                        {ctrl.gateTag && (
                          <>
                            {" "}
                            <span className="rounded bg-rose-950/80 border border-rose-800/70 px-1.5 py-0.5 text-[9px] text-rose-300">
                              {ctrl.gateTag}
                            </span>
                          </>
                        )}
                      </span>
                      <span className="shrink-0 font-bold text-cyan-300">
                        {scores.controls[ctrl.id]} / 4
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate" title={ctrl.title}>
                      {ctrl.title}
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={4}
                      step={1}
                      value={scores.controls[ctrl.id]}
                      onChange={(e) => setControlScore(ctrl.id, Number(e.target.value))}
                      className="w-full accent-cyan-500 cursor-pointer"
                    />
                  </div>
                ))}
              </div>
            </div>

            {/* Axis B Block */}
            <div className="space-y-3 pt-2 border-t border-slate-800">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <div className="text-xs font-mono font-bold uppercase text-emerald-300">
                  Axis B — Evidence Provenance &amp; Verification Confidence (2 Controls: CIAF-09..10)
                </div>
                <div className="text-xs font-mono text-slate-300">
                  Raw Mean (sum/2):{" "}
                  <span className="font-bold text-emerald-300">
                    {readiness.rawAxisBMean.toFixed(2)}
                  </span>{" "}
                  | Min: <span className="font-bold text-emerald-300">{readiness.axisBMin}/4</span>
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                {AXIS_B_CONTROLS.map((ctrl) => (
                  <div
                    key={ctrl.id}
                    className="rounded-lg border border-slate-800/90 bg-slate-900/60 p-2.5 space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono gap-2">
                      <span className="inline-flex flex-wrap items-center gap-1.5 text-slate-200 font-semibold">
                        <span>{ctrl.id}</span>
                        {ctrl.gateTag && (
                          <>
                            {" "}
                            <span className="rounded bg-amber-950/80 border border-amber-800/70 px-1.5 py-0.5 text-[9px] text-amber-300">
                              {ctrl.gateTag}
                            </span>
                          </>
                        )}
                      </span>
                      <span className="shrink-0 font-bold text-emerald-300">
                        {scores.controls[ctrl.id]} / 4
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate" title={ctrl.title}>
                      {ctrl.title}
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={4}
                      step={1}
                      value={scores.controls[ctrl.id]}
                      onChange={(e) => setControlScore(ctrl.id, Number(e.target.value))}
                      className="w-full accent-emerald-500 cursor-pointer"
                    />
                  </div>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 pt-3 border-t border-slate-800 text-xs font-mono sm:grid-cols-2">
              <label className="flex items-center gap-2.5 rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-2.5 cursor-pointer text-slate-200 hover:border-emerald-700/60 transition">
                <input
                  type="checkbox"
                  checked={scores.scittRegistered}
                  onChange={(e) =>
                    setScores((prev) => ({ ...prev, scittRegistered: e.target.checked }))
                  }
                  className="accent-emerald-500 shrink-0"
                />
                <span>IETF SCITT (RFC 9943 / 9942) + External Timestamp Active</span>
              </label>
              <label className="flex items-center gap-2.5 rounded-lg border border-rose-900/50 bg-rose-950/20 px-3 py-2.5 cursor-pointer text-rose-300 hover:border-rose-700/70 transition">
                <input
                  type="checkbox"
                  checked={scores.sharedSigningKeysDetected}
                  onChange={(e) =>
                    setScores((prev) => ({
                      ...prev,
                      sharedSigningKeysDetected: e.target.checked,
                    }))
                  }
                  className="accent-rose-500 shrink-0"
                />
                <span>Fault: Shared Gateway/Executor Signing Keys (Gate 2)</span>
              </label>
            </div>
          </div>

          {/* 2-Axis Result Panel */}
          <div className="lg:col-span-5 flex flex-col justify-between rounded-xl border border-slate-800 bg-slate-950/90 p-5 space-y-4">
            <div className="space-y-3">
              <div className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Deterministic Two-Axis Disposition (No Axis Blending)
              </div>
              <div
                className={`rounded-xl border p-4 font-mono ${
                  readiness.readinessDisposition === "AUDIT_READY_VERIFIABLE_COMPLETENESS" ||
                  readiness.readinessDisposition === "AUDIT_READY_LOCAL_PROVENANCE"
                    ? "border-emerald-500/50 bg-emerald-950/30 text-emerald-200"
                    : readiness.readinessDisposition === "CONDITIONAL_REMEDIATION_REQUIRED"
                      ? "border-amber-500/50 bg-amber-950/30 text-amber-200"
                      : "border-rose-500/70 bg-rose-950/40 text-rose-200"
                }`}
              >
                <div className="text-xs uppercase opacity-80">Normative Readiness Disposition</div>
                <div className="mt-1 text-base sm:text-lg font-bold break-all">
                  {readiness.readinessDisposition}
                </div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
                  <div className="rounded bg-slate-950/70 p-2.5">
                    <div className="text-slate-400">Axis A (10 Controls)</div>
                    <div className="mt-0.5 text-base font-bold">
                      {readiness.effectiveAxisAMaturity.toFixed(2)} / 4
                    </div>
                    <div className="text-[11px] text-slate-400">
                      raw mean {readiness.rawAxisAMean.toFixed(2)} | min {readiness.axisAMin}/4
                    </div>
                  </div>
                  <div className="rounded bg-slate-950/70 p-2.5">
                    <div className="text-slate-400">Axis B (2 Controls)</div>
                    <div className="mt-0.5 text-base font-bold">
                      {readiness.effectiveAxisBConfidence.toFixed(2)} / 4
                    </div>
                    <div className="text-[11px] text-slate-400">
                      raw mean {readiness.rawAxisBMean.toFixed(2)} | min {readiness.axisBMin}/4
                    </div>
                  </div>
                </div>
              </div>

              {readiness.overrideTriggered ? (
                <div className="space-y-1.5 rounded-lg border border-rose-500/50 bg-rose-950/30 p-3 text-xs font-mono text-rose-200">
                  <div className="font-bold uppercase">Critical Gate / Cap Active:</div>
                  {readiness.overrideReasons.map((r, i) => (
                    <div key={i}>• {r}</div>
                  ))}
                </div>
              ) : (
                <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3 text-xs font-mono text-emerald-300">
                  No critical-failure gates triggered. Runtime enforcement and cryptographic
                  provenance support the normative disposition.
                </div>
              )}
            </div>

            {/* Regulated Industry Profile Selector */}
            <div className="space-y-2 pt-3 border-t border-slate-800">
              <div className="flex flex-wrap gap-1.5">
                {(
                  [
                    ["BANKING", "Regional Banking"],
                    ["HEALTHCARE", "Healthcare (HIPAA)"],
                    ["TRIBAL_GAMING", "Tribal Gaming (NIGC)"],
                  ] as const
                ).map(([id, label]) => (
                  <button
                    key={id}
                    onClick={() => setIndustry(id)}
                    className={`rounded px-2.5 py-1 text-xs font-mono cursor-pointer ${
                      industry === id
                        ? "bg-indigo-600 text-white font-semibold"
                        : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <div className="rounded-lg bg-slate-900 p-3 text-xs space-y-1 border border-slate-800">
                <div className="font-semibold text-indigo-300">
                  {INDUSTRY_NOTES[industry].title}
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  {INDUSTRY_NOTES[industry].subtitle}
                </div>
                <ul className="list-disc pl-4 space-y-1 text-slate-300 pt-1">
                  {INDUSTRY_NOTES[industry].bullets.map((b, i) => (
                    <li key={i}>{b}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
