import React from "react";
import Link from "next/link";
import { MermaidDiagram } from "@/components/MermaidDiagram";

export interface TocHeading {
  level: 2 | 3;
  text: string;
  id: string;
}

export function slugifyHeading(raw: string): string {
  return raw
    .replace(/`/g, "")
    .replace(/\\\$/g, "")
    .replace(/[^\w\s-]/g, "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-");
}

export function extractTocHeadings(markdown: string): TocHeading[] {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const headings: TocHeading[] = [];
  let inFence = false;

  for (const line of lines) {
    if (line.trimStart().startsWith("```")) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const m2 = /^##\s+(.+)$/.exec(line);
    if (m2) {
      const clean = m2[1].replace(/`/g, "").replace(/\\\$/g, "$").trim();
      headings.push({ level: 2, text: clean, id: slugifyHeading(m2[1]) });
      continue;
    }
    const m3 = /^###\s+(.+)$/.exec(line);
    if (m3) {
      const clean = m3[1].replace(/`/g, "").replace(/\\\$/g, "$").trim();
      headings.push({ level: 3, text: clean, id: slugifyHeading(m3[1]) });
    }
  }
  return headings;
}

const INTERNAL_DOC_LINK_MAP: Record<string, string> = {
  "reference-architecture-v0.1.md": "/specs/reference-architecture/",
  "docs/reference-architecture-v0.1.md": "/specs/reference-architecture/",
  "vocabulary-v0.1.md": "/specs/vocabulary/",
  "docs/vocabulary-v0.1.md": "/specs/vocabulary/",
  "audit-readiness-methodology-v0.1.md": "/specs/audit-readiness-methodology/",
  "docs/audit-readiness-methodology-v0.1.md": "/specs/audit-readiness-methodology/",
  "ciaf-control-catalog-v0.1.md": "/specs/control-catalog/",
  "controls/ciaf-control-catalog-v0.1.md": "/specs/control-catalog/",
  "ietf-scitt-profile-v0.1.md": "/specs/ietf-scitt-profile/",
  "standards-crosswalks/ietf-scitt-profile-v0.1.md": "/specs/ietf-scitt-profile/",
  "nist-ai-rmf-crosswalk-v0.1.md": "/specs/nist-ai-rmf-crosswalk/",
  "standards-crosswalks/nist-ai-rmf-crosswalk-v0.1.md": "/specs/nist-ai-rmf-crosswalk/",
  "iso-42001-crosswalk-v0.1.md": "/specs/iso-42001-crosswalk/",
  "standards-crosswalks/iso-42001-crosswalk-v0.1.md": "/specs/iso-42001-crosswalk/",
  "../schemas/": "/schemas/",
  "schemas/": "/schemas/",
  "CONTRIBUTING.md": "/contribute/",
};

function resolveMarkdownHref(href: string, repoBaseUrl: string): { url: string; external: boolean } {
  if (href.startsWith("http://") || href.startsWith("https://")) {
    return { url: href, external: true };
  }
  const normalized = href.replace(/^\.\//, "");
  if (INTERNAL_DOC_LINK_MAP[normalized]) {
    return { url: INTERNAL_DOC_LINK_MAP[normalized], external: false };
  }
  const strippedParent = normalized.replace(/^\.\.\//, "");
  if (INTERNAL_DOC_LINK_MAP[strippedParent]) {
    return { url: INTERNAL_DOC_LINK_MAP[strippedParent], external: false };
  }
  return {
    url: `${repoBaseUrl}/blob/main/${strippedParent}`,
    external: true,
  };
}

function renderInlineSegment(
  rawText: string,
  repoBaseUrl: string,
  keyPrefix: string
): React.ReactNode[] {
  const parts = rawText.split(/(<br\s*\/?>)/gi);
  const out: React.ReactNode[] = [];

  parts.forEach((segment, segIdx) => {
    if (/^<br\s*\/?>$/i.test(segment)) {
      out.push(<br key={`${keyPrefix}-br-${segIdx}`} />);
      return;
    }

    const unescaped = segment.replace(/\\\$/g, "$");
    const tokenRegex =
      /(\[([^\]]+)\]\(([^)]+)\)|\*\*([^*]+)\*\*|`([^`]+)`|\*([^*]+)\*)/g;

    let lastIdx = 0;
    let match: RegExpExecArray | null;
    let tokIdx = 0;

    while ((match = tokenRegex.exec(unescaped)) !== null) {
      if (match.index > lastIdx) {
        out.push(unescaped.slice(lastIdx, match.index));
      }
      if (match[2] !== undefined && match[3] !== undefined) {
        const resolved = resolveMarkdownHref(match[3], repoBaseUrl);
        const labelNodes = renderInlineSegment(
          match[2],
          repoBaseUrl,
          `${keyPrefix}-${segIdx}-lnk-${tokIdx}`
        );
        if (resolved.external) {
          out.push(
            <a
              key={`${keyPrefix}-${segIdx}-a-${tokIdx}`}
              href={resolved.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-300 underline decoration-cyan-700/70 underline-offset-2 hover:text-cyan-200"
            >
              {labelNodes}
            </a>
          );
        } else {
          out.push(
            <Link
              key={`${keyPrefix}-${segIdx}-l-${tokIdx}`}
              href={resolved.url}
              className="text-cyan-300 underline decoration-cyan-700/70 underline-offset-2 hover:text-cyan-200"
            >
              {labelNodes}
            </Link>
          );
        }
      } else if (match[4] !== undefined) {
        out.push(
          <strong key={`${keyPrefix}-${segIdx}-b-${tokIdx}`} className="font-semibold text-white">
            {renderInlineSegment(
              match[4],
              repoBaseUrl,
              `${keyPrefix}-${segIdx}-bi-${tokIdx}`
            )}
          </strong>
        );
      } else if (match[5] !== undefined) {
        out.push(
          <code
            key={`${keyPrefix}-${segIdx}-c-${tokIdx}`}
            className="rounded bg-slate-800/90 px-1.5 py-0.5 font-mono text-[0.85em] text-cyan-200 border border-slate-700/70"
          >
            {match[5]}
          </code>
        );
      } else if (match[6] !== undefined) {
        out.push(
          <em key={`${keyPrefix}-${segIdx}-i-${tokIdx}`} className="italic text-slate-200">
            {match[6]}
          </em>
        );
      }
      lastIdx = match.index + match[0].length;
      tokIdx++;
    }

    if (lastIdx < unescaped.length) {
      out.push(unescaped.slice(lastIdx));
    }
  });

  return out;
}

function splitTableRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  return trimmed.split("|").map((c) => c.trim());
}

export function MarkdownRenderer({
  markdown,
  repoBaseUrl,
}: {
  markdown: string;
  repoBaseUrl: string;
}) {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const blocks: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed) {
      i++;
      continue;
    }

    // Fenced code block
    if (trimmed.startsWith("```")) {
      const lang = trimmed.slice(3).trim() || "text";
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++;
      if (lang === "mermaid") {
        blocks.push(<MermaidDiagram key={`mmd-${i}`} chart={codeLines.join("\n")} />);
      } else {
        blocks.push(
          <div
            key={`code-${i}`}
            className="my-4 overflow-hidden rounded-xl border border-slate-800 bg-slate-950"
          >
            <div className="flex items-center justify-between border-b border-slate-800/90 bg-slate-900/80 px-3.5 py-1.5 text-[11px] font-mono uppercase tracking-wider text-slate-400">
              <span>{lang}</span>
            </div>
            <pre className="overflow-x-auto p-4 text-xs font-mono leading-relaxed text-cyan-100">
              {codeLines.join("\n")}
            </pre>
          </div>
        );
      }
      continue;
    }

    // Horizontal rule
    if (/^---+$/.test(trimmed)) {
      blocks.push(<hr key={`hr-${i}`} className="my-6 border-slate-800" />);
      i++;
      continue;
    }

    // Headings
    const hMatch = /^(#{1,4})\s+(.+)$/.exec(line);
    if (hMatch) {
      const level = hMatch[1].length;
      const content = hMatch[2];
      const id = slugifyHeading(content);
      const inline = renderInlineSegment(content, repoBaseUrl, `h-${i}`);
      if (level === 1) {
        blocks.push(
          <h1
            key={`h1-${i}`}
            id={id}
            className="mt-2 mb-4 text-2xl sm:text-3xl font-bold tracking-tight text-white"
          >
            {inline}
          </h1>
        );
      } else if (level === 2) {
        blocks.push(
          <h2
            key={`h2-${i}`}
            id={id}
            className="mt-8 mb-3 scroll-mt-24 border-b border-slate-800 pb-2 text-xl font-bold text-cyan-200"
          >
            {inline}
          </h2>
        );
      } else if (level === 3) {
        blocks.push(
          <h3
            key={`h3-${i}`}
            id={id}
            className="mt-6 mb-2 scroll-mt-24 text-base sm:text-lg font-semibold text-white"
          >
            {inline}
          </h3>
        );
      } else {
        blocks.push(
          <h4
            key={`h4-${i}`}
            id={id}
            className="mt-4 mb-1.5 text-sm font-semibold uppercase tracking-wider text-slate-300"
          >
            {inline}
          </h4>
        );
      }
      i++;
      continue;
    }

    // Pipe Table
    if (
      trimmed.startsWith("|") &&
      i + 1 < lines.length &&
      /^\|\s*:?-{3,}/.test(lines[i + 1].trim())
    ) {
      const headers = splitTableRow(lines[i]);
      i += 2; // Skip header + separator row
      const rows: string[][] = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        rows.push(splitTableRow(lines[i]));
        i++;
      }
      blocks.push(
        <div
          key={`tbl-${i}`}
          className="my-5 overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/70"
        >
          <table className="min-w-full divide-y divide-slate-800 text-left text-xs sm:text-sm">
            <thead className="bg-slate-900/90 text-xs font-mono uppercase text-cyan-300">
              <tr>
                {headers.map((h, hIdx) => (
                  <th key={hIdx} className="px-3.5 py-2.5 font-semibold">
                    {renderInlineSegment(h, repoBaseUrl, `th-${i}-${hIdx}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300">
              {rows.map((row, rIdx) => (
                <tr key={rIdx} className="hover:bg-slate-900/40">
                  {row.map((cell, cIdx) => (
                    <td key={cIdx} className="px-3.5 py-2.5 align-top leading-relaxed">
                      {renderInlineSegment(cell, repoBaseUrl, `td-${i}-${rIdx}-${cIdx}`)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      continue;
    }

    // Blockquote
    if (trimmed.startsWith(">")) {
      const quoteLines: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ""));
        i++;
      }
      blocks.push(
        <blockquote
          key={`bq-${i}`}
          className="my-4 space-y-2 rounded-r-xl border-l-4 border-cyan-500 bg-cyan-950/20 px-4 py-3 text-sm text-slate-200 leading-relaxed"
        >
          {quoteLines.map((ql, qIdx) => (
            <p key={qIdx}>{renderInlineSegment(ql, repoBaseUrl, `bq-${i}-${qIdx}`)}</p>
          ))}
        </blockquote>
      );
      continue;
    }

    // Unordered or Ordered Lists
    if (/^(\s*)([-*]|\d+\.)\s+/.test(line)) {
      const isOrdered = /^\s*\d+\.\s+/.test(line);
      const items: Array<{ text: string; subItems: string[] }> = [];
      while (i < lines.length && /^(\s*)([-*]|\d+\.)\s+/.test(lines[i])) {
        const m = /^(\s*)([-*]|\d+\.)\s+(.+)$/.exec(lines[i]);
        if (!m) break;
        const indent = m[1].length;
        if (indent >= 2 && items.length > 0) {
          items[items.length - 1].subItems.push(m[3]);
        } else {
          items.push({ text: m[3], subItems: [] });
        }
        i++;
      }
      const ListTag = isOrdered ? "ol" : "ul";
      blocks.push(
        <ListTag
          key={`lst-${i}`}
          className={`my-3 space-y-1.5 pl-5 text-sm text-slate-300 leading-relaxed ${
            isOrdered ? "list-decimal" : "list-disc"
          }`}
        >
          {items.map((item, idx) => (
            <li key={idx}>
              {renderInlineSegment(item.text, repoBaseUrl, `li-${i}-${idx}`)}
              {item.subItems.length > 0 && (
                <ul className="mt-1.5 space-y-1 list-disc pl-5 text-slate-300">
                  {item.subItems.map((sub, sIdx) => (
                    <li key={sIdx}>
                      {renderInlineSegment(sub, repoBaseUrl, `sub-${i}-${idx}-${sIdx}`)}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ListTag>
      );
      continue;
    }

    // Paragraph
    const paraLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].trim().startsWith("```") &&
      !lines[i].trim().startsWith("#") &&
      !lines[i].trim().startsWith(">") &&
      !lines[i].trim().startsWith("|") &&
      !/^---+$/.test(lines[i].trim()) &&
      !/^(\s*)([-*]|\d+\.)\s+/.test(lines[i])
    ) {
      paraLines.push(lines[i].trim());
      i++;
    }
    blocks.push(
      <p key={`p-${i}`} className="my-3 text-sm sm:text-[15px] leading-relaxed text-slate-300">
        {renderInlineSegment(paraLines.join(" "), repoBaseUrl, `p-${i}`)}
      </p>
    );
  }

  return <div className="space-y-1">{blocks}</div>;
}

