"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Stateless Verifier" },
  { href: "/specs/", label: "Specifications & Crosswalks" },
  { href: "/specs/control-catalog/", label: "Control Catalog (CIAF-01..12)" },
  { href: "/schemas/", label: "JSON Schemas (2020-12)" },
  { href: "/contribute/", label: "Contribute & Public Comment" },
] as const;

export function SiteNav() {
  const pathname = usePathname() || "/";
  const repoBaseUrl =
    process.env.NEXT_PUBLIC_GITHUB_REPO_URL ||
    "https://github.com/DenzilGreenwood/ciaf-lcm-reference";

  const isActive = (href: string) => {
    const normPath = pathname.endsWith("/") ? pathname : `${pathname}/`;
    if (href === "/") return normPath === "/";
    if (href === "/specs/") {
      return normPath.startsWith("/specs/") && normPath !== "/specs/control-catalog/";
    }
    return normPath === href || normPath.startsWith(href);
  };

  return (
    <nav className="sticky top-0 z-40 border-b border-slate-800/90 bg-[#090d16]/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6 lg:px-8">
        <div className="flex items-center gap-3">
          <Link
            href="/"
            className="flex items-center gap-2 font-mono text-sm font-bold tracking-tight text-white hover:text-cyan-300 transition"
          >
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-cyan-400" />
            <span>CIAF-LCM v0.1.1</span>
          </Link>
          <span className="hidden xl:inline-block rounded border border-cyan-800/60 bg-cyan-950/60 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
            Public Comment Open through Feb 10, 2027
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
          {NAV_ITEMS.map((item) => {
            const active = isActive(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`rounded-lg px-2.5 py-1.5 transition ${
                  active
                    ? "bg-cyan-600 text-white font-semibold shadow-sm"
                    : "text-slate-300 hover:bg-slate-800/90 hover:text-white"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
          <a
            href={repoBaseUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-slate-200 hover:border-cyan-600 hover:text-cyan-200 transition"
          >
            GitHub ↗
          </a>
        </div>
      </div>
    </nav>
  );
}

