/**
 * Emit (or verify) the machine-readable contract artifact.
 *
 *   bun scripts/emit-contract.ts           # write contract/cert-service.v1.json
 *   bun scripts/emit-contract.ts --check   # fail if the file on disk differs
 *
 * The artifact is what the PWA repo vendors and pins by SHA-256, so it is a
 * release object: it changes only when the surface changes, and the diff is the
 * review. `--check` runs in CI, which makes an un-emitted surface edit a build
 * failure rather than a surprise in the client.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import {
  CLAIMS,
  CONTRACT_VERSION,
  CREDENTIAL,
  ISSUANCE,
  PASS_RULES,
  RATE_LIMIT,
  REFUSALS,
  ROUTES,
  STAT_INVARIANTS,
  VERIFICATION,
} from "../src/contract";

const OUT = join(import.meta.dir, "..", "contract", "cert-service.v1.json");

/** Stable serialisation: fixed key order comes from this literal, not from the object. */
export function buildArtifact() {
  return {
    name: "kalappai-cert",
    contractVersion: CONTRACT_VERSION,
    declaredIn: "src/contract.ts",
    passRules: {
      ...PASS_RULES,
      enforcedOn: "server-parsed values; a required field cannot be omitted to skip a rule",
    },
    statInvariants: {
      ...STAT_INVARIANTS,
      onViolation: REFUSALS.implausibleStats,
    },
    rateLimit: { ...RATE_LIMIT },
    refusals: { ...REFUSALS },
    issuance: { ...ISSUANCE },
    verification: { ...VERIFICATION },
    credential: { ...CREDENTIAL },
    claims: { ...CLAIMS },
    routes: ROUTES.map((r) => ({ method: r.method, path: r.path, purpose: r.purpose })),
  };
}

export function serialise(): string {
  return JSON.stringify(buildArtifact(), null, 2) + "\n";
}

export function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

if (import.meta.main) {
  const check = process.argv.includes("--check");
  const body = serialise();
  const hash = sha256(body);

  if (check) {
    const onDisk = existsSync(OUT) ? readFileSync(OUT, "utf8") : null;
    if (onDisk === body) {
      console.log(`✓ contract artifact matches src/contract.ts`);
      console.log(`  ${OUT}`);
      console.log(`  sha256: ${hash}`);
      process.exit(0);
    }
    console.error("✗ contract drift — the artifact does not match src/contract.ts");
    console.error(`  expected sha256: ${hash}`);
    if (onDisk === null) {
      console.error(`  ${OUT} does not exist`);
    } else {
      console.error(`  on-disk sha256:  ${sha256(onDisk)}`);
      const a = onDisk.split("\n");
      const b = body.split("\n");
      for (let i = 0; i < Math.max(a.length, b.length); i++) {
        if (a[i] !== b[i]) {
          console.error(`  first difference at line ${i + 1}:`);
          console.error(`    on disk:  ${JSON.stringify(a[i] ?? null)}`);
          console.error(`    expected: ${JSON.stringify(b[i] ?? null)}`);
          break;
        }
      }
    }
    console.error("\n  run: bun run contract:emit  (then commit the artifact)");
    process.exit(1);
  }

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, body);
  console.log(`✓ wrote ${OUT}`);
  console.log(`  sha256: ${hash}`);
  console.log(`  pin this hash in the client repo (kalappai: contract/PINNED.sha256)`);
}
