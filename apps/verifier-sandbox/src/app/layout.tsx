import type { Metadata } from "next";
import { SiteNav } from "@/components/SiteNav";
import { SiteFooter } from "@/components/SiteFooter";
import "./globals.css";

export const metadata: Metadata = {
  title: "CIAF-LCM v0.1.1 — Receipt & Readiness Inspector",
  description:
    "Stateless interactive cryptographic verifier, normative specifications, JSON Schemas, and 2-axis audit readiness inspector for CIAF-LCM v0.1.1 (RFC 8785 JCS + Web Crypto Ed25519).",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col antialiased selection:bg-cyan-500/30 selection:text-cyan-100">
        <SiteNav />
        <div className="flex-1">{children}</div>
        <SiteFooter />
      </body>
    </html>
  );
}

