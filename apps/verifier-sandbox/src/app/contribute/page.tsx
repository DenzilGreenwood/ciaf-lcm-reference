import React from "react";
import type { Metadata } from "next";
import { GITHUB_REPO_DEFAULT, readRepoFile } from "@/lib/repoDocs";
import { MarkdownRenderer } from "@/components/MarkdownRenderer";

export const metadata: Metadata = {
  title: "Contribute & Public Comment (RFC v0.1.1) — CIAF-LCM",
  description:
    "Submit public specification comments through February 10, 2027, contribute cleanroom runtime adapters, or report cryptographic verifier issues.",
};

export default function ContributePage() {
  const repoUrl = process.env.NEXT_PUBLIC_GITHUB_REPO_URL || GITHUB_REPO_DEFAULT;
  const contributingMd = readRepoFile("CONTRIBUTING.md");

  const channels = [
    {
      badge: "90-Day Public Comment",
      title: "1. Specification & Crosswalk Critique",
      description:
        "Propose normative refinements, control-catalog test procedures, regulatory citations, or NIST / ISO 42001 / IETF SCITT crosswalk updates (CC-BY-4.0).",
      cta: "Open RFC Comment Form ↗",
      href: `${repoUrl}/issues/new?template=01-public-comment-rfc.yml`,
      accent: "border-cyan-700/70 bg-cyan-950/30 text-cyan-200",
    },
    {
      badge: "Cleanroom Interop",
      title: "2. Independent Runtime Adapter",
      description:
        "Submit a zero-coupled producer or sidecar in Go, Rust, TypeScript, Java, Python, Envoy/OPA, or MCP proxy passing IndependentVerifier (Apache-2.0).",
      cta: "Submit Adapter Vector ↗",
      href: `${repoUrl}/issues/new?template=02-adapter-interoperability.yml`,
      accent: "border-emerald-700/70 bg-emerald-950/30 text-emerald-200",
    },
    {
      badge: "Cryptographic & Schema QA",
      title: "3. Verifier Bug or Security Advisory",
      description:
        "Report RFC 8785 edge cases, schema validation discrepancies, or responsible private security disclosures for key/boundary logic.",
      cta: "Report Bug / Security Issue ↗",
      href: `${repoUrl}/issues/new/choose`,
      accent: "border-amber-700/70 bg-amber-950/30 text-amber-200",
    },
  ];

  return (
    <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      <header className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-xl space-y-3">
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
          <span className="rounded bg-cyan-950/80 px-2.5 py-1 border border-cyan-800/60">
            Open Public Review • Through February 10, 2027
          </span>
          <span className="rounded bg-slate-800 px-2.5 py-1 text-slate-300">
            Specs: CC-BY-4.0 • Code &amp; Schemas: Apache-2.0
          </span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
          Contribute to CIAF-LCM v0.1.1 &amp; Submit Public Comments
        </h1>
        <p className="max-w-4xl text-sm text-slate-300 leading-relaxed">
          External auditors, risk officers, standards working-group members, and systems engineers
          can submit structured public comments, cleanroom interoperability adapters, and pull
          requests directly on GitHub. Every pull request automatically runs the 25-test Python
          adversarial suite, cross-language RFC 8785 / Web Crypto Ed25519 parity checks, and static
          verifier build.
        </p>
      </header>

      <section className="grid gap-4 md:grid-cols-3">
        {channels.map((ch) => (
          <div
            key={ch.title}
            className="flex flex-col justify-between rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4"
          >
            <div className="space-y-2">
              <span
                className={`inline-block rounded border px-2 py-0.5 text-[11px] font-mono ${ch.accent}`}
              >
                {ch.badge}
              </span>
              <h2 className="text-base font-semibold text-white">{ch.title}</h2>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">{ch.description}</p>
            </div>
            <a
              href={ch.href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono font-semibold text-cyan-200 hover:border-cyan-500 hover:text-white transition"
            >
              {ch.cta}
            </a>
          </div>
        ))}
      </section>

      <article className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 sm:p-8 shadow-xl">
        <MarkdownRenderer markdown={contributingMd} repoBaseUrl={repoUrl} />
      </article>
    </main>
  );
}

