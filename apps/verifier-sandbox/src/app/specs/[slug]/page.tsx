import React from "react";
import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { GITHUB_REPO_DEFAULT, SPEC_DOCS, getSpecDocBySlug } from "@/lib/repoDocs";
import { MarkdownRenderer, extractTocHeadings } from "@/components/MarkdownRenderer";

export function generateStaticParams() {
  return SPEC_DOCS.map((doc) => ({ slug: doc.slug }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const doc = SPEC_DOCS.find((d) => d.slug === slug);
  if (!doc) {
    return { title: "Specification Not Found — CIAF-LCM v0.1.1" };
  }
  return {
    title: `${doc.shortTitle} (${doc.docId}) — CIAF-LCM v0.1.1`,
    description: doc.summary,
  };
}

export default async function SpecDocumentPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const doc = getSpecDocBySlug(slug);
  if (!doc) notFound();

  const repoUrl = process.env.NEXT_PUBLIC_GITHUB_REPO_URL || GITHUB_REPO_DEFAULT;
  const toc = extractTocHeadings(doc.content);
  const rfcIssueUrl = `${repoUrl}/issues/new?template=01-public-comment-rfc.yml&title=${encodeURIComponent(
    `[RFC v0.1.1] ${doc.docId}: `
  )}`;

  return (
    <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-6">
      {/* Breadcrumb & Document Action Bar */}
      <div className="flex flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-900/80 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <Link href="/specs/" className="text-cyan-300 hover:underline">
            ← All Specifications
          </Link>
          <span className="text-slate-600">/</span>
          <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-200">{doc.docId}</span>
          <span className="rounded border border-slate-700 px-2 py-0.5 text-slate-400">
            {doc.license}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <a
            href={rfcIssueUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg border border-emerald-600/80 bg-emerald-950/60 px-3 py-1.5 font-semibold text-emerald-200 hover:bg-emerald-900/70 transition"
          >
            Submit Public Comment on {doc.docId} ↗
          </a>
          <a
            href={`${repoUrl}/blob/main/${doc.repoRelativePath}`}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-slate-300 hover:border-cyan-700 hover:text-cyan-200 transition"
          >
            View Markdown on GitHub ↗
          </a>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-12">
        {/* Sidebar: Sibling Docs + On-Page Table of Contents */}
        <aside className="lg:col-span-3 space-y-5">
          <div className="lg:sticky lg:top-20 space-y-5">
            {toc.length > 0 && (
              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 space-y-2.5">
                <div className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-300">
                  On This Page
                </div>
                <ul className="space-y-1.5 text-xs">
                  {toc.map((h) => (
                    <li key={h.id} className={h.level === 3 ? "pl-3" : ""}>
                      <a
                        href={`#${h.id}`}
                        className="block text-slate-300 hover:text-cyan-300 transition leading-snug"
                      >
                        {h.text}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 space-y-2.5">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                Specification Suite
              </div>
              <ul className="space-y-1 text-xs font-mono">
                {SPEC_DOCS.map((item) => (
                  <li key={item.slug}>
                    <Link
                      href={`/specs/${item.slug}/`}
                      className={`block rounded px-2 py-1.5 transition ${
                        item.slug === doc.slug
                          ? "bg-cyan-950/90 border border-cyan-700/70 text-cyan-200 font-semibold"
                          : "text-slate-300 hover:bg-slate-800/80"
                      }`}
                    >
                      {item.shortTitle}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </aside>

        {/* Rendered Normative Markdown Document */}
        <article className="lg:col-span-9 rounded-2xl border border-slate-800 bg-slate-900/50 p-6 sm:p-8 shadow-xl">
          <MarkdownRenderer markdown={doc.content} repoBaseUrl={repoUrl} />
        </article>
      </div>
    </main>
  );
}

