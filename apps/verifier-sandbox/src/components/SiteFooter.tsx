import React from "react";
import Link from "next/link";
import { GITHUB_REPO_DEFAULT } from "@/lib/repoDocs";

export function SiteFooter() {
  const repoUrl = process.env.NEXT_PUBLIC_GITHUB_REPO_URL || GITHUB_REPO_DEFAULT;

  return (
    <footer className="mt-12 border-t border-slate-800/90 bg-slate-950/80 py-8 text-xs text-slate-400">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 sm:px-6 lg:flex-row lg:items-center lg:justify-between lg:px-8">
        <div className="space-y-1">
          <div className="font-mono font-semibold text-slate-200">
            CIAF-LCM v0.1.1 — Cognitive Insight Audit Framework (Lazy Capsule Materialization)
          </div>
          <div className="font-mono text-[11px] text-slate-400">
            Invariant: Capability != Authority != Authorization != Execution != Assurance
          </div>
          <div className="text-[11px] text-slate-300">
            Specification Editor: <span className="font-semibold text-slate-200">Denzil James Greenwood, AIGP</span>{" "}
            • Independent open reference specification (not affiliated with or endorsed by NIST, ISO/IEC, or the IETF).
          </div>
          <div>
            Specifications &amp; Crosswalks licensed under{" "}
            <a
              href={`${repoUrl}/blob/main/LICENSE-SPEC`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-300 hover:underline"
            >
              CC-BY-4.0
            </a>{" "}
            • Schemas, Reference Code &amp; Stateless Verifier licensed under{" "}
            <a
              href={`${repoUrl}/blob/main/LICENSE-CODE`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-300 hover:underline"
            >
              Apache-2.0
            </a>
            .
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 font-mono">
          <Link href="/" className="hover:text-cyan-300">
            Verifier
          </Link>
          <span>•</span>
          <Link href="/specs/" className="hover:text-cyan-300">
            Specifications
          </Link>
          <span>•</span>
          <Link href="/schemas/" className="hover:text-cyan-300">
            JSON Schemas
          </Link>
          <span>•</span>
          <Link href="/contribute/" className="hover:text-cyan-300">
            Submit RFC Comment
          </Link>
          <span>•</span>
          <a
            href={`${repoUrl}/issues/new/choose`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-300 hover:underline"
          >
            GitHub Issues ↗
          </a>
        </div>
      </div>
    </footer>
  );
}

