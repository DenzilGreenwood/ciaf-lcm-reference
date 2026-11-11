import React from "react";
import Link from "next/link";
import type { Metadata } from "next";
import { GITHUB_REPO_DEFAULT, SPEC_DOCS } from "@/lib/repoDocs";

export const metadata: Metadata = {
  title: "Specifications, Control Catalog & Crosswalks — CIAF-LCM v0.1.1",
  description:
    "CC-BY-4.0 normative specifications, CIAF-01..12 control catalog, audit readiness methodology, and NIST AI RMF, ISO/IEC 42001, and IETF SCITT profiles.",
};

export default function SpecsDirectoryPage() {
  const repoUrl = process.env.NEXT_PUBLIC_GITHUB_REPO_URL || GITHUB_REPO_DEFAULT;
  const categories = [
    "Core Architecture & Methodology",
    "Control Catalog",
    "Standards Crosswalks",
  ] as const;

  return (
    <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      <header className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-xl space-y-3">
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
          <span className="rounded bg-cyan-950/80 px-2.5 py-1 border border-cyan-800/60">
            CC-BY-4.0 Normative Specifications
          </span>
          <span className="rounded bg-slate-800 px-2.5 py-1 text-slate-300">
            Public Comment Window: Open through February 10, 2027
          </span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
          CIAF-LCM v0.1.1 Specifications, Control Catalog &amp; Standards Crosswalks
        </h1>
        <p className="max-w-4xl text-sm text-slate-300 leading-relaxed">
          All specification documents below are rendered directly from the repository&apos;s
          normative Markdown sources and licensed under{" "}
          <code className="text-cyan-200">CC-BY-4.0</code>. Every document enforces the five-layer
          separation:{" "}
          <code className="text-cyan-200">
            Capability != Authority != Authorization != Execution != Assurance
          </code>
          .
        </p>
      </header>

      {categories.map((cat) => {
        const items = SPEC_DOCS.filter((d) => d.category === cat);
        return (
          <section key={cat} className="space-y-4">
            <h2 className="border-b border-slate-800 pb-2 text-sm font-mono font-bold uppercase tracking-wider text-cyan-300">
              {cat}
            </h2>
            <div className="grid gap-4 md:grid-cols-2">
              {items.map((doc) => (
                <div
                  key={doc.slug}
                  className="flex flex-col justify-between rounded-2xl border border-slate-800 bg-slate-900/60 p-5 hover:border-cyan-700/70 transition space-y-4"
                >
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-cyan-300">
                        {doc.docId}
                      </span>
                      <span className="text-slate-400">{doc.license}</span>
                    </div>
                    <h3 className="text-lg font-semibold text-white">
                      <Link href={`/specs/${doc.slug}/`} className="hover:text-cyan-300 transition">
                        {doc.title}
                      </Link>
                    </h3>
                    <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                      {doc.summary}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/80 pt-3 text-xs font-mono">
                    <Link
                      href={`/specs/${doc.slug}/`}
                      className="rounded-lg bg-cyan-600 px-3 py-1.5 font-semibold text-white hover:bg-cyan-500 transition"
                    >
                      Read Specification →
                    </Link>
                    <a
                      href={`${repoUrl}/blob/main/${doc.repoRelativePath}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-slate-400 hover:text-cyan-300"
                    >
                      Source ({doc.repoRelativePath}) ↗
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </section>
        );
      })}
    </main>
  );
}

