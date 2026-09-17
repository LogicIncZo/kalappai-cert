/**
 * Live smoke — the end-to-end path a real learner takes, against a real process.
 *
 * Boots `bun src/index.ts` on a throwaway port and DB, then walks the whole
 * journey: issue → refusal of an unearned attempt → JSON verify → human verify
 * page → VC-JWT against the published JWKS → tamper detection.
 *
 * This is deliberately NOT a unit test. It proves the documented entrypoint
 * boots, serves the declared routes and produces a verifiable credential in one
 * process — the thing CI/CD actually ships.
 *
 * Usage:  bun scripts/smoke.ts [--base <url>]
 *         --base hits an already-running instance instead of spawning one
 *         (used by the post-deploy job against the live service).
 * Exit:   0 = all steps passed, 1 = first failing step printed
 */
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BOLD = "\x1b[1m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const DIM = "\x1b[2m";
const NC = "\x1b[0m";

const PASSAGE_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

const smokeState = { id: "", vcJwt: "", verifyUrl: "", dbFile: "" };

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function waitForReady(base: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${base}/`);
      if (r.status === 200) return;
      last = String(r.status);
    } catch (e) {
      last = (e as Error).message;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`service did not become ready within ${timeoutMs}ms (last: ${last})`);
}

type Step = { name: string; run: (base: string) => Promise<string> };

const steps: Step[] = [
  {
    name: "boots and serves the health banner",
    run: async (base) => {
      const r = await fetch(`${base}/`);
      if (r.status !== 200) throw new Error(`GET / -> ${r.status}`);
      const j = (await r.json()) as { service?: string };
      if (j.service !== "kalappai-cert") throw new Error(`unexpected banner: ${JSON.stringify(j)}`);
      return "200 · service banner";
    },
  },
  {
    name: "issues a certificate for a passing attempt",
    run: async (base) => {
      const r = await fetch(`${base}/api/certificates`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          alias: "Smoke Run",
          layoutId: "tamil99",
          passageId: "smoke-60s",
          targetHash: PASSAGE_HASH,
          stats: {
            grossWpm: 24.2,
            netWpm: 23.1,
            accuracy: 97.4,
            errors: 2,
            strokes: 205,
            kdph: 1290,
            elapsedMs: 60_000,
            chars: 141,
          },
        }),
      });
      if (r.status !== 201) throw new Error(`POST /api/certificates -> ${r.status} ${await r.text()}`);
      const j = (await r.json()) as { id: string; vcJwt: string; verifyUrl: string };
      if (!j.id || !j.vcJwt) throw new Error("201 without id/vcJwt");
      smokeState.id = j.id;
      smokeState.vcJwt = j.vcJwt;
      smokeState.verifyUrl = j.verifyUrl;
      return `201 · ${j.id}`;
    },
  },
  {
    name: "refuses an attempt that does not clear the pass rules",
    run: async (base) => {
      const r = await fetch(`${base}/api/certificates`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          alias: "Smoke Run",
          layoutId: "tamil99",
          passageId: "smoke-60s",
          targetHash: PASSAGE_HASH,
          stats: {
            grossWpm: 30,
            netWpm: 29,
            accuracy: 61,
            errors: 40,
            strokes: 100,
            kdph: 900,
            elapsedMs: 60_000,
            chars: 141,
          },
        }),
      });
      if (r.status !== 422) throw new Error(`expected 422, got ${r.status}`);
      return "422 · pass rules held";
    },
  },
  {
    name: "verifies the issued record over JSON",
    run: async (base) => {
      const r = await fetch(`${base}/api/certificates/${smokeState.id}`);
      if (r.status !== 200) throw new Error(`-> ${r.status}`);
      const j = (await r.json()) as { signatureValid: boolean; recordSelfConsistent: boolean };
      if (!j.signatureValid || !j.recordSelfConsistent) throw new Error("record did not self-verify");
      return "signatureValid · true";
    },
  },
  {
    name: "serves a human verify page with a QR back to itself",
    run: async (base) => {
      const r = await fetch(`${base}/certs/${smokeState.id}`);
      if (r.status !== 200) throw new Error(`-> ${r.status}`);
      const html = await r.text();
      if (!html.includes("<svg")) throw new Error("no QR svg on the verify page");
      if (!html.includes("window.print")) throw new Error("no print control on the verify page");
      if (!smokeState.verifyUrl.includes(`/certs/${smokeState.id}`)) {
        throw new Error("verifyUrl does not point at this certificate");
      }
      return "200 · QR + print present";
    },
  },
  {
    name: "VC-JWT verifies against the published JWKS",
    run: async (base) => {
      const [h64, p64, sig64] = smokeState.vcJwt.split(".");
      const jw = (await (await fetch(`${base}/.well-known/jwks.json`)).json()) as {
        keys: Array<Record<string, unknown>>;
      };
      const pub = createPublicKey({ key: jw.keys[0], format: "jwk" });
      const ok = cryptoVerify(
        null,
        Buffer.from(`${h64}.${p64}`),
        pub,
        Buffer.from(sig64.replace(/-/g, "+").replace(/_/g, "/"), "base64"),
      );
      if (!ok) throw new Error("Ed25519 proof did not verify");
      return "EdDSA · verified";
    },
  },
  {
    name: "detects a tampered record",
    run: async (base) => {
      const { Database } = await import("bun:sqlite");
      const db = new Database(smokeState.dbFile);
      db.query("UPDATE certs SET net_wpm = 99.9 WHERE id = ?").run(smokeState.id);
      db.close();
      const j = (await (await fetch(`${base}/api/certificates/${smokeState.id}`)).json()) as {
        signatureValid: boolean;
      };
      if (j.signatureValid) throw new Error("tampering went undetected");
      return "tamper detected · signatureValid false";
    },
  },
];

const providedBase = arg("--base");
let child: ReturnType<typeof Bun.spawn> | undefined;
let workDir = "";
let base: string;

if (providedBase) {
  /* Against an already-running instance there is no local DB to tamper with, so the
     tamper step is reported as skipped rather than silently passing. */
  base = providedBase.replace(/\/+$/, "");
  console.log(`${BOLD}Live smoke${NC} ${DIM}— against ${base}${NC}\n`);
} else {
  const port = 8500 + Math.floor(Math.random() * 400);
  workDir = mkdtempSync(join(tmpdir(), "kalappai-smoke-"));
  smokeState.dbFile = join(workDir, "certs.db");
  base = `http://127.0.0.1:${port}`;
  child = Bun.spawn(["bun", "src/index.ts"], {
    env: {
      ...process.env,
      PORT: String(port),
      KALAPPAI_CERT_DB: smokeState.dbFile,
      KALAPPAI_CERT_BASE: base,
      KALAPPAI_CERT_SECRET: "smoke-secret",
      KALAPPAI_CERT_ORIGIN: "https://logicinczo.github.io",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  await waitForReady(base);
  console.log(`${BOLD}Live smoke${NC} ${DIM}— spawned on ${base}, DB ${smokeState.dbFile}${NC}\n`);
}

let failures = 0;
for (const step of steps) {
  if (step.name.includes("tampered") && !smokeState.dbFile) {
    console.log(`  ${DIM}−${NC} ${step.name} ${DIM}(skipped: remote instance has no local DB)${NC}`);
    continue;
  }
  try {
    const note = await step.run(base);
    console.log(`  ${GREEN}✓${NC} ${step.name} ${DIM}(${note})${NC}`);
  } catch (e) {
    console.log(`  ${RED}✗${NC} ${step.name}`);
    console.log(`    ${RED}${(e as Error).message}${NC}`);
    failures++;
    break;
  }
}

if (child) child.kill();
if (workDir) rmSync(workDir, { recursive: true, force: true });

console.log("");
if (failures === 0) {
  console.log(`${GREEN}${BOLD}✓ Live smoke passed${NC}`);
  process.exit(0);
}
console.log(`${RED}${BOLD}✗ Live smoke failed${NC}`);
process.exit(1);
