"use client";

import React, { useState } from "react";
import type { SchemaDocMeta } from "@/lib/repoDocs";

export function SchemaExplorerClient({
  schemas,
  repoBaseUrl,
}: {
  schemas: Array<SchemaDocMeta & { rawJson: string }>;
  repoBaseUrl: string;
}) {
  const [activeSlug, setActiveSlug] = useState<string>(schemas[0]?.slug || "authorization-claim");
  const [copied, setCopied] = useState<boolean>(false);

  const current = schemas.find((s) => s.slug === activeSlug) || schemas[0];

  const handleCopy = async () => {
    if (!current) return;
    await navigator.clipboard.writeText(current.rawJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!current) return;
    const blob = new Blob([current.rawJson], { type: "application/schema+json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = current.repoRelativePath.split("/").pop() || `${current.slug}.schema.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {schemas.map((s) => {
          const active = s.slug === current?.slug;
          return (
            <button
              key={s.slug}
              onClick={() => setActiveSlug(s.slug)}
              className={`rounded-xl border p-4 text-left transition cursor-pointer ${
                active
                  ? "border-cyan-500 bg-cyan-950/40 shadow-md"
                  : "border-slate-800 bg-slate-900/60 hover:border-slate-700"
              }`}
            >
              <div className="text-xs font-mono font-bold text-cyan-300">{s.title}</div>
              <p className="mt-1.5 text-xs text-slate-300 line-clamp-3 leading-relaxed">
                {s.summary}
              </p>
            </button>
          );
        })}
      </div>

      {current && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">{current.title}</h2>
              <div className="mt-0.5 text-xs font-mono text-slate-400">
                $id: <span className="text-cyan-300">{current.schemaId}</span> • License:{" "}
                {current.license}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <button
                onClick={handleCopy}
                className="rounded-lg border border-cyan-600/80 bg-cyan-950/70 px-3 py-1.5 font-semibold text-cyan-100 hover:bg-cyan-900/80 transition cursor-pointer"
              >
                {copied ? "Copied Schema!" : "Copy Schema JSON"}
              </button>
              <button
                onClick={handleDownload}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-slate-200 hover:bg-slate-700 transition cursor-pointer"
              >
                Download .schema.json
              </button>
              <a
                href={`${repoBaseUrl}/blob/main/${current.repoRelativePath}`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-slate-300 hover:border-cyan-700 hover:text-cyan-200 transition"
              >
                GitHub Source ↗
              </a>
            </div>
          </div>

          <pre className="max-h-[38rem] overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs font-mono leading-relaxed text-emerald-200">
            {current.rawJson}
          </pre>
        </div>
      )}
    </div>
  );
}

