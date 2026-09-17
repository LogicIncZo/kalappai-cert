/**
 * Docs ↔ contract consistency.
 *
 * The README's endpoint table and request/response shapes are claims about the
 * service. This check compares them to the committed contract artifact, so a
 * documented route that does not exist (or a route that was never documented)
 * fails the gate instead of being discovered by a user.
 *
 * Usage: bun scripts/check-docs.ts
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import artifact from "../contract/cert-service.v1.json";

const ROOT = join(import.meta.dir, "..");
const README = readFileSync(join(ROOT, "README.md"), "utf8");

const problems: string[] = [];

/* ---- endpoints: README table rows `| METHOD | `path` | ... |` ---- */

const documented = new Set<string>();
for (const line of README.split("\n")) {
  const m = line.match(/^\|\s*(GET|POST|PUT|PATCH|DELETE)\s*\|\s*`([^`]+)`\s*\|/);
  if (m) documented.add(`${m[1]} ${m[2]}`);
}

const declared = new Set(
  artifact.routes
    /* probes hit parameterised routes with a placeholder, so compare on the declared shape */
    .map((r: { method: string; path: string }) => `${r.method} ${r.path}`),
);

for (const d of documented) {
  if (!declared.has(d)) problems.push(`README documents a route that is not in the contract: ${d}`);
}
for (const c of declared) {
  if (!documented.has(c)) problems.push(`contract declares a route the README does not document: ${c}`);
}

/* ---- request shape: `stats` fields the client must send ---- */

const statsRow = README.match(/Body:\s*`\{([^}]*stats:\s*\{([^}]*)\}[^}]*)\}`/);
if (!statsRow) {
  problems.push("README does not document the issuance request body in the expected shape");
} else {
  const bodyText = statsRow[1];
  const statsText = statsRow[2] ?? "";
  for (const field of artifact.issuance.requestRequired) {
    if (!new RegExp(`\\b${field}\\b`).test(bodyText)) {
      problems.push(`README request body does not mention required field \`${field}\``);
    }
  }
  for (const field of artifact.issuance.statsRequired) {
    if (!new RegExp(`\\b${field}\\b`).test(statsText)) {
      problems.push(`README \`stats\` block does not mention required field \`${field}\``);
    }
  }
}

/* ---- response shape: 201 keys ---- */

const responseRow = README.match(/→\s*`\{([^}]*)\}`/);
if (!responseRow) {
  problems.push("README does not document the 201 response shape");
} else {
  for (const field of artifact.issuance.responseFields) {
    if (!new RegExp(`\\b${field}\\b`).test(responseRow[1])) {
      problems.push(`README 201 response does not mention \`${field}\``);
    }
  }
}

/* ---- pass rules must be stated, and stated correctly ---- */

for (const [label, value] of [
  ["accuracy", artifact.passRules.accuracyPercent],
  ["elapsed", artifact.passRules.minElapsedMs / 1000],
  ["chars", artifact.passRules.minChars],
] as Array<[string, number]>) {
  if (!README.includes(String(value))) {
    problems.push(`README does not state the declared ${label} pass rule (${value})`);
  }
}

/* ---- report ---- */

if (problems.length === 0) {
  console.log(`✓ docs match the contract (${declared.size} routes, ${artifact.issuance.responseFields.length} response fields)`);
  process.exit(0);
}

console.log("✗ docs and contract disagree:");
for (const p of problems) console.log(`  · ${p}`);
console.log("\n  fix README.md, or the contract in src/contract.ts (then `bun run contract:emit`).");
process.exit(1);
