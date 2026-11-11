"use client";

import React, { useEffect, useId, useRef, useState } from "react";

let mermaidInitialized = false;

export function MermaidDiagram({
  chart,
  title = "Architecture & Trust-Boundary Diagram",
}: {
  chart: string;
  title?: string;
}) {
  const reactId = useId();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [svgHtml, setSvgHtml] = useState<string>("");
  const [renderError, setRenderError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const cleanId = `ciaf-mmd-${reactId.replace(/[^a-zA-Z0-9]/g, "")}-${Date.now()}`;

    (async () => {
      try {
        const mermaidModule = await import("mermaid");
        const mermaid = mermaidModule.default;

        if (!mermaidInitialized) {
          mermaid.initialize({
            startOnLoad: false,
            securityLevel: "strict",
            theme: "dark",
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
            flowchart: {
              htmlLabels: false,
              useMaxWidth: true,
              curve: "basis",
              padding: 14,
            },
            sequence: {
              useMaxWidth: true,
              actorMargin: 40,
              messageMargin: 32,
            },
            themeVariables: {
              darkMode: true,
              background: "#020617",
              primaryColor: "#083344",
              primaryTextColor: "#e2e8f0",
              primaryBorderColor: "#06b6d4",
              lineColor: "#38bdf8",
              secondaryColor: "#0f172a",
              tertiaryColor: "#1e293b",
              clusterBkg: "#0f172a",
              clusterBorder: "#334155",
              actorBkg: "#083344",
              actorBorder: "#06b6d4",
              actorTextColor: "#f8fafc",
              signalColor: "#38bdf8",
              signalTextColor: "#e2e8f0",
            },
          });
          mermaidInitialized = true;
        }

        const normalizedChart = chart.replace(/<br\s*\/?>/gi, " ").trim();
        const { svg } = await mermaid.render(cleanId, normalizedChart);

        if (!cancelled) {
          setSvgHtml(svg);
          setRenderError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setRenderError(err instanceof Error ? err.message : String(err));
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [chart, reactId]);

  return (
    <div className="my-4 overflow-hidden rounded-xl border border-slate-800 bg-slate-950/95 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/90 bg-slate-900/80 px-4 py-2 text-xs font-mono">
        <span className="uppercase tracking-wider text-cyan-300 font-semibold">{title}</span>
        <span className="text-[11px] text-slate-400">Rendered Interactive SVG (Mermaid)</span>
      </div>

      <div
        ref={containerRef}
        className="overflow-x-auto p-4 sm:p-6 flex items-center justify-center min-h-[120px] [&_svg]:max-w-full [&_svg]:h-auto"
      >
        {renderError ? (
          <div className="w-full space-y-2">
            <div className="text-xs font-mono text-amber-300">
              Diagram fallback view ({renderError}):
            </div>
            <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 p-3 text-xs font-mono text-cyan-100">
              {chart}
            </pre>
          </div>
        ) : svgHtml ? (
          <div
            className="w-full flex justify-center"
            dangerouslySetInnerHTML={{ __html: svgHtml }}
          />
        ) : (
          <div className="text-xs font-mono text-slate-400 animate-pulse">
            Rendering architecture diagram...
          </div>
        )}
      </div>

      <details className="border-t border-slate-800/80 bg-slate-900/40 px-4 py-2 text-xs font-mono text-slate-400">
        <summary className="cursor-pointer hover:text-cyan-300 select-none">
          View Mermaid Diagram Source
        </summary>
        <pre className="mt-2 overflow-x-auto rounded-lg bg-slate-950 p-3 text-[11px] text-slate-300">
          {chart}
        </pre>
      </details>
    </div>
  );
}

