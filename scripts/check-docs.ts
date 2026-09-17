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

/* ---- the gate describes itself honestly ---- */

/* `scripts/verify.sh` labels its stages `step "N/M  …"`. If that count drifts from
   what the docs claim, or the numbering skips, a reader is being told something
   about the gate that is not true — the exact failure mode this file exists for. */

const verifySh = readFileSync(join(ROOT, "scripts", "verify.sh"), "utf8");
const stageLabels = [...verifySh.matchAll(/step "([0-9]+)\/([0-9]+)\s/g)].map((m) => ({
  n: Number(m[1]),
  of: Number(m[2]),
}));

const claimedTotal = stageLabels[0]?.of ?? 0;

if (stageLabels.length === 0) {
  problems.push("scripts/verify.sh labels no stages — the gate cannot be described");
} else {
  /* Compare as a set of numerators, not a sequence: mutually exclusive branches
     (the --fast / --full demo paths) legitimately label the same stage twice. */
  for (const s of stageLabels) {
    if (s.of !== claimedTotal) problems.push(`verify.sh stage ${s.n} claims /${s.of}, stage 1 claims /${claimedTotal}`);
    if (s.n < 1 || s.n > claimedTotal) problems.push(`verify.sh labels a stage ${s.n}/${s.of}, outside 1..${claimedTotal}`);
  }
  const seen = new Set(stageLabels.map((s) => s.n));
  for (let i = 1; i <= claimedTotal; i++) {
    if (!seen.has(i)) problems.push(`verify.sh never labels stage ${i} (it advertises ${claimedTotal} stages)`);
  }
}

/* Every document that states a stage count must state this one. */
for (const file of ["README.md", "AGENTS.md", "CHANGELOG.md"]) {
  let text: string;
  try {
    text = readFileSync(join(ROOT, file), "utf8");
  } catch {
    continue;
  }
  const WORDS: Record<string, number> = {
    six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12,
  };
  for (const m of text.matchAll(/(\d+|six|seven|eight|nine|ten|eleven|twelve)\s+stages/gi)) {
    const stated = WORDS[m[1].toLowerCase()] ?? Number(m[1]);
    if (stated !== claimedTotal) {
      problems.push(`${file} says ${m[1]} stages, verify.sh runs ${claimedTotal}`);
    }
  }
}

/* `bun run <script>` referenced in the docs must exist. */
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { scripts: Record<string, string> };
for (const file of ["README.md", "AGENTS.md", "CONTRIBUTING.md"]) {
  let text: string;
  try {
    text = readFileSync(join(ROOT, file), "utf8");
  } catch {
    continue;
  }
  for (const m of text.matchAll(/bun run ([a-z][\w:-]*)/g)) {
    if (!(m[1] in pkg.scripts)) {
      problems.push(`${file} tells a reader to run \`bun run ${m[1]}\`, which is not a script`);
    }
  }
}

/* ---- report ---- */

if (problems.length === 0) {
  console.log(
    `✓ docs match the contract (${declared.size} routes, ${artifact.issuance.responseFields.length} response fields, gate of ${claimedTotal} stages)`,
  );
  process.exit(0);
}

console.log("✗ docs and contract disagree:");
for (const p of problems) console.log(`  · ${p}`);
console.log("\n  fix README.md, or the contract in src/contract.ts (then `bun run contract:emit`).");
process.exit(1);
