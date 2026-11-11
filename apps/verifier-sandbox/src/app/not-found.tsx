import React from "react";
import Link from "next/link";

export default function NotFoundPage() {
  return (
    <main className="mx-auto max-w-3xl px-4 py-20 text-center space-y-4">
      <div className="inline-block rounded border border-cyan-800/60 bg-cyan-950/60 px-3 py-1 font-mono text-xs text-cyan-300">
        404 • Route Not Found
      </div>
      <h1 className="text-2xl font-bold text-white">Page Not Found</h1>
      <p className="text-sm text-slate-400">
        The requested specification or schema route does not exist in this CIAF-LCM v0.1.1 portal.
      </p>
      <div className="pt-2">
        <Link
          href="/"
          className="inline-block rounded-lg bg-cyan-600 px-4 py-2 font-mono text-xs font-semibold text-white hover:bg-cyan-500 transition"
        >
          ← Return to Stateless Verifier
        </Link>
      </div>
    </main>
  );
}

