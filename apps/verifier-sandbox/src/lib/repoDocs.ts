import fs from "node:fs";
import path from "node:path";

export interface SpecDocMeta {
  slug: string;
  title: string;
  shortTitle: string;
  category: "Core Architecture & Methodology" | "Control Catalog" | "Standards Crosswalks";
  docId: string;
  license: "CC-BY-4.0";
  repoRelativePath: string;
  summary: string;
  issueTemplateDocOption: string;
}

export interface SchemaDocMeta {
  slug: string;
  title: string;
  schemaId: string;
  license: "Apache-2.0";
  repoRelativePath: string;
  summary: string;
}

export const GITHUB_REPO_DEFAULT = "https://github.com/DenzilGreenwood/ciaf-lcm-reference";

export const SPEC_DOCS: ReadonlyArray<SpecDocMeta> = [
  {
    slug: "reference-architecture",
    title: "Normative Reference Architecture (v0.1.1)",
    shortTitle: "Reference Architecture",
    category: "Core Architecture & Methodology",
    docId: "CIAF-LCM-ARCH-v0.1.1",
    license: "CC-BY-4.0",
    repoRelativePath: "docs/reference-architecture-v0.1.md",
    summary:
      "Six-plane reference architecture, Dual-Key Ed25519 trust boundaries, lazy capsule materialization, 6-vector threat model, and normative reason/exception code registries.",
    issueTemplateDocOption: "Reference Architecture (docs/reference-architecture-v0.1.md)",
  },
  {
    slug: "vocabulary",
    title: "Normative Vocabulary & Five-Layer Separation (v0.1.1)",
    shortTitle: "Normative Vocabulary",
    category: "Core Architecture & Methodology",
    docId: "CIAF-LCM-VOCAB-v0.1.1",
    license: "CC-BY-4.0",
    repoRelativePath: "docs/vocabulary-v0.1.md",
    summary:
      "Formal RFC 2119 definitions for the 12 core terms and the non-conflation rule: Capability != Authority != Authorization != Execution != Assurance.",
    issueTemplateDocOption: "Normative Vocabulary (docs/vocabulary-v0.1.md)",
  },
  {
    slug: "control-catalog",
    title: "Normative Control Catalog: CIAF-01 through CIAF-12 (v0.1.1)",
    shortTitle: "Control Catalog (CIAF-01..12)",
    category: "Control Catalog",
    docId: "CIAF-LCM-CTRL-v0.1.1",
    license: "CC-BY-4.0",
    repoRelativePath: "controls/ciaf-control-catalog-v0.1.md",
    summary:
      "Twelve testable governance, pre-execution gating, dual-key enforcement, provenance, stateless verification, and kill-switch controls mapped 1-to-1 to JSON Schema paths.",
    issueTemplateDocOption: "Control Catalog CIAF-01..12 (controls/ciaf-control-catalog-v0.1.md)",
  },
  {
    slug: "audit-readiness-methodology",
    title: "Audit Readiness Methodology & Regulated Profiles (v0.1.1)",
    shortTitle: "Audit Readiness Methodology",
    category: "Core Architecture & Methodology",
    docId: "CIAF-LCM-AUDIT-v0.1.1",
    license: "CC-BY-4.0",
    repoRelativePath: "docs/audit-readiness-methodology-v0.1.md",
    summary:
      "Six-step audit lifecycle, disjoint 12-control 2-Axis scoring rubric, Critical Gates 1-4, and Healthcare (HIPAA), Regional Banking (SR 26-2 / TPRM), and Tribal Gaming (NIGC) profiles.",
    issueTemplateDocOption: "Audit Readiness Methodology (docs/audit-readiness-methodology-v0.1.md)",
  },
  {
    slug: "ietf-scitt-profile",
    title: "IETF SCITT (RFC 9943 / RFC 9942) Transparency Profile",
    shortTitle: "IETF SCITT Profile",
    category: "Standards Crosswalks",
    docId: "CIAF-LCM-PROFILE-SCITT-v0.1",
    license: "CC-BY-4.0",
    repoRelativePath: "standards-crosswalks/ietf-scitt-profile-v0.1.md",
    summary:
      "COSE_Sign1 Signed Statement protected headers, RFC 9597 CWT_Claims admission bindings, RFC 9942 COSE Merkle inclusion receipts, and salted commitments for regulated fields.",
    issueTemplateDocOption: "IETF SCITT Profile (standards-crosswalks/ietf-scitt-profile-v0.1.md)",
  },
  {
    slug: "nist-ai-rmf-crosswalk",
    title: "NIST AI Risk Management Framework (AI RMF 1.0) Crosswalk",
    shortTitle: "NIST AI RMF 1.0 Crosswalk",
    category: "Standards Crosswalks",
    docId: "CIAF-LCM-XWALK-NIST-v0.1",
    license: "CC-BY-4.0",
    repoRelativePath: "standards-crosswalks/nist-ai-rmf-crosswalk-v0.1.md",
    summary:
      "Versioned GOVERN, MAP, MEASURE, and MANAGE subcategory alignments with explicit Direct/Partial/Supportive classifications and active revision context.",
    issueTemplateDocOption: "NIST AI RMF 1.0 Crosswalk (standards-crosswalks/nist-ai-rmf-crosswalk-v0.1.md)",
  },
  {
    slug: "iso-42001-crosswalk",
    title: "ISO/IEC 42001:2023 AIMS Clauses & Annex A Crosswalk",
    shortTitle: "ISO/IEC 42001 Crosswalk",
    category: "Standards Crosswalks",
    docId: "CIAF-LCM-XWALK-ISO42001-v0.1",
    license: "CC-BY-4.0",
    repoRelativePath: "standards-crosswalks/iso-42001-crosswalk-v0.1.md",
    summary:
      "Supportive technical alignment across ISO/IEC 42001:2023 Clauses 4-10 and Annex A controls, explicitly delineating organizational management-system gaps.",
    issueTemplateDocOption: "ISO/IEC 42001:2023 Crosswalk (standards-crosswalks/iso-42001-crosswalk-v0.1.md)",
  },
];

export const SCHEMA_DOCS: ReadonlyArray<SchemaDocMeta> = [
  {
    slug: "authorization-claim",
    title: "AuthorizationClaim Schema (v0.1)",
    schemaId: "https://schemas.ciaf-lcm.org/v0.1/authorization-claim.v0.1.schema.json",
    license: "Apache-2.0",
    repoRelativePath: "schemas/authorization-claim.v0.1.schema.json",
    summary:
      "Pre-Execution Governance Gateway claim binding subject, delegated_scope_snapshot, integer minor-unit request_digest, human escalation signature, and <=30s ExecutionGrant.",
  },
  {
    slug: "execution-claim",
    title: "ExecutionClaim Schema (v0.1)",
    schemaId: "https://schemas.ciaf-lcm.org/v0.1/execution-claim.v0.1.schema.json",
    license: "Apache-2.0",
    repoRelativePath: "schemas/execution-claim.v0.1.schema.json",
    summary:
      "Downstream Execution Service receipt binding consumed single-use nonce, observed_request_digest, side-effect settlement outcome, or contained CIAF-11 security exception.",
  },
  {
    slug: "audit-capsule",
    title: "AuditCapsule Schema (v0.1)",
    schemaId: "https://schemas.ciaf-lcm.org/v0.1/audit-capsule.v0.1.schema.json",
    license: "Apache-2.0",
    repoRelativePath: "schemas/audit-capsule.v0.1.schema.json",
    summary:
      "Lazily materialized evidence bundle packaging policy_snapshot, optional REGISTRY_AUTHORITY attestation, OKP JWK manifest, hash_chain, ordered receipts, and SCITT status.",
  },
  {
    slug: "assurance-claim",
    title: "AssuranceClaim Schema (v0.1)",
    schemaId: "https://schemas.ciaf-lcm.org/v0.1/assurance-claim.v0.1.schema.json",
    license: "Apache-2.0",
    repoRelativePath: "schemas/assurance-claim.v0.1.schema.json",
    summary:
      "Stateless Independent Verifier (CIAF-10) output recording the 8 deterministic cryptographic/semantic checks, failed_controls, findings, and SCITT/clock notice.",
  },
];

export function resolveRepoRoot(): string {
  const candidates = [
    process.cwd(),
    path.resolve(process.cwd(), "..", ".."),
    path.resolve(process.cwd(), ".."),
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "schemas", "audit-capsule.v0.1.schema.json"))) {
      return dir;
    }
  }
  return path.resolve(process.cwd(), "..", "..");
}

export function readRepoFile(repoRelativePath: string): string {
  const fullPath = path.join(resolveRepoRoot(), repoRelativePath);
  return fs.readFileSync(fullPath, "utf-8");
}

export function getSpecDocBySlug(slug: string): (SpecDocMeta & { content: string }) | null {
  const meta = SPEC_DOCS.find((d) => d.slug === slug);
  if (!meta) return null;
  return {
    ...meta,
    content: readRepoFile(meta.repoRelativePath),
  };
}

export function getAllLoadedSchemas(): Array<SchemaDocMeta & { rawJson: string }> {
  return SCHEMA_DOCS.map((meta) => ({
    ...meta,
    rawJson: readRepoFile(meta.repoRelativePath),
  }));
}

