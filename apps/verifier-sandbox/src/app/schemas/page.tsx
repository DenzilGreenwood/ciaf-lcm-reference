import React from "react";
import type { Metadata } from "next";
import { GITHUB_REPO_DEFAULT, getAllLoadedSchemas } from "@/lib/repoDocs";
import { SchemaExplorerClient } from "@/components/SchemaExplorerClient";

export const metadata: Metadata = {
  title: "Draft 2020-12 JSON Schemas — CIAF-LCM v0.1.1",
  description:
    "Apache-2.0 JSON Schema Draft 2020-12 wire contracts for AuthorizationClaim, ExecutionClaim, AuditCapsule, and AssuranceClaim.",
};

export default function SchemasPage() {
  const schemas = getAllLoadedSchemas();
  const repoUrl = process.env.NEXT_PUBLIC_GITHUB_REPO_URL || GITHUB_REPO_DEFAULT;

  return (
    <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-6">
      <header className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-xl space-y-3">
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
          <span className="rounded bg-cyan-950/80 px-2.5 py-1 border border-cyan-800/60">
            JSON Schema Draft 2020-12
          </span>
          <span className="rounded bg-slate-800 px-2.5 py-1 text-slate-300">
            Wire Version: &quot;0.1.0&quot; • License: Apache-2.0
          </span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
          CIAF-LCM Wire &amp; Envelope JSON Schemas
        </h1>
        <p className="max-w-4xl text-sm text-slate-300 leading-relaxed">
          Conformant runtimes, gateways, execution services, and verifiers validate complete wire
          envelopes against these Draft 2020-12 schemas <em>prior</em> to stripping{" "}
          <code className="text-cyan-200">signature</code> and{" "}
          <code className="text-cyan-200">claim_digest</code> for RFC 8785 canonicalization and
          Ed25519 signature verification.
        </p>
      </header>

      <SchemaExplorerClient schemas={schemas} repoBaseUrl={repoUrl} />
    </main>
  );
}

