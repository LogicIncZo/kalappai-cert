/**
 * Demo infrastructure — seed a certification service with a deterministic set of
 * practice certificates.
 *
 * Everything here reads `contract/cert-service.v1.json`, so the demo cannot drift
 * from the declared surface: if a field is renamed, the demo fails loudly instead
 * of quietly demonstrating an old shape.
 *
 * Modes:
 *
 *   bun demo/seed.ts                spawn a local instance, seed it, print the
 *                                   verify URLs and a scannable QR, hold open
 *                                   until Ctrl-C (the interactive demo)
 *   bun demo/seed.ts --url <base>   seed an instance that is already running
 *   bun demo/seed.ts --port <n>     spawn on a chosen port (predictable URLs)
 *   bun demo/seed.ts --check        seed a spawned instance and assert that every
 *                                   seeded certificate verifies (gate mode)
 *
 * The check mode is part of `bun run verify`, so the demo is exercised on every
 * loop iteration rather than rotting between releases.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import QRCode from "qrcode";
import artifact from "../contract/cert-service.v1.json";

const CHECK = process.argv.includes("--check");
const urlArgIndex = process.argv.indexOf("--url");
const EXTERNAL_BASE = urlArgIndex > -1 ? process.argv[urlArgIndex + 1] : undefined;
const portArgIndex = process.argv.indexOf("--port");
const FIXED_PORT = portArgIndex > -1 ? Number(process.argv[portArgIndex + 1]) : undefined;

const BOLD = "\u001b[1m";
const DIM = "\u001b[2m";
const GREEN = "\u001b[0;32m";
const RED = "\u001b[0;31m";
const YELLOW = "\u001b[0;33m";
const NC = "\u001b[0m";

type Seed = {
  alias: string;
  layoutId: string;
  passageId: string;
  /** the passage that was "typed" — hashed, never stored by the service */
  passage: string;
  stats: {
    grossWpm: number;
    netWpm: number;
    accuracy: number;
    errors: number;
    strokes: number;
    kdph: number;
    elapsedMs: number;
    chars: number;
  };
};

/**
 * Four representative attempts, one per layout. The last deliberately sits just
 * above the pass rules so the demo shows a near-miss score rather than only
 * comfortable passes.
 */
const SEEDS: Seed[] = [
  {
    alias: "Demo · Tamil99",
    layoutId: "tamil99",
    passageId: "exam-60s-v1",
    passage: "தமிழ் மொழி மிகவும் பழமையானது. அது இனிமையானது.",
    stats: { grossWpm: 24.6, netWpm: 23.1, accuracy: 96.8, errors: 4, strokes: 208, kdph: 1248, elapsedMs: 60_000, chars: 145 },
  },
  {
    alias: "Demo · InScript",
    layoutId: "inscript",
    passageId: "exam-60s-v1",
    passage: "கல்வி என்பது கண்ணுக்குத் தெரியாத செல்வம்.",
    stats: { grossWpm: 18.2, netWpm: 16.9, accuracy: 94.1, errors: 6, strokes: 176, kdph: 1056, elapsedMs: 60_000, chars: 132 },
  },
  {
    alias: "Demo · Typewriter",
    layoutId: "typewriter",
    passageId: "exam-60s-v1",
    passage: "நூல் பல கற்றும் தமக்குத் தெரியாது என்பது அறியாமை.",
    stats: { grossWpm: 15.4, netWpm: 15.4, accuracy: 98.9, errors: 2, strokes: 158, kdph: 948, elapsedMs: 60_000, chars: 128 },
  },
  {
    alias: "Demo · Near miss",
    layoutId: "tamil99",
    passageId: "exam-60s-v1",
    passage: "முயற்சி திருவினையாக்கும்.",
    stats: { grossWpm: 12.1, netWpm: 11.4, accuracy: 90.4, errors: 5, strokes: 141, kdph: 846, elapsedMs: 30_400, chars: 121 },
  },
];

const sha256 = (s: string) => new Bun.CryptoHasher("sha256").update(s).digest("hex");
const b64urlToBuf = (x: string) => Buffer.from(x.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const decodeJwtPart = (x: string) => JSON.parse(b64urlToBuf(x).toString("utf8"));

async function waitForReady(base: string, timeoutMs = 15_000): Promise<void> {
  const started = Date.now();
  for (;;) {
    try {
      const r = await fetch(`${base}/`);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    if (Date.now() - started > timeoutMs) throw new Error(`service did not become ready at ${base}`);
    await new Promise((r) => setTimeout(r, 120));
  }
}

type Issued = { id: string; alias: string; verifyUrl: string; vcJwt: string; layoutId: string };

async function issue(base: string, seed: Seed): Promise<Issued> {
  const r = await fetch(`${base}${artifact.issuance.path}`, {
    method: artifact.issuance.method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      alias: seed.alias,
      layoutId: seed.layoutId,
      passageId: seed.passageId,
      targetHash: sha256(seed.passage),
      stats: seed.stats,
    }),
  });
  if (r.status !== artifact.issuance.successStatus) {
    throw new Error(`issuing "${seed.alias}" failed: ${r.status} ${await r.text()}`);
  }
  const body = (await r.json()) as Record<string, unknown>;
  for (const field of artifact.issuance.responseFields) {
    if (!(field in body)) throw new Error(`response is missing declared field \`${field}\``);
  }
  return {
    id: body.id as string,
    alias: seed.alias,
    verifyUrl: body.verifyUrl as string,
    vcJwt: body.vcJwt as string,
    layoutId: seed.layoutId,
  };
}

/** Assert a seeded certificate is verifiable exactly as the contract claims. */
async function assertVerifiable(base: string, issued: Issued): Promise<string[]> {
  const notes: string[] = [];

  const json = await fetch(`${base}${artifact.verification.jsonPath.replace(":id", issued.id)}`);
  const record = (await json.json()) as { signatureValid: boolean };
  if (record.signatureValid !== true) throw new Error(`${issued.id}: signatureValid was not true`);

  const page = await fetch(`${base}${artifact.verification.humanPath.replace(":id", issued.id)}`);
  const html = await page.text();
  if (!html.includes("<svg")) throw new Error(`${issued.id}: verify page carries no QR`);
  if (!html.includes(issued.id)) throw new Error(`${issued.id}: verify page does not name the id`);
  notes.push("page + QR");

  const jwks = (await (await fetch(`${base}${artifact.credential.jwksPath}`)).json()) as {
    keys: Array<Record<string, unknown>>;
  };
  const [h, p, s] = issued.vcJwt.split(".");
  const pub = createPublicKey({ key: jwks.keys[0]!, format: "jwk" });
  const ok = cryptoVerify(null, Buffer.from(`${h}.${p}`), pub, b64urlToBuf(s!));
  if (!ok) throw new Error(`${issued.id}: VC-JWT does not verify against the published JWKS`);
  const payload = decodeJwtPart(p!) as { vc: { credentialSubject: { name: string } } };
  if (payload.vc.credentialSubject.name !== issued.alias) {
    throw new Error(`${issued.id}: credential subject is not the seeded alias`);
  }
  notes.push("VC-JWT ↔ JWKS");

  return notes;
}

async function main() {
  const owned = !EXTERNAL_BASE;
  let child: ReturnType<typeof Bun.spawn> | undefined;
  let dbDir = "";
  let base = (EXTERNAL_BASE ?? "").replace(/\/+$/, "");

  if (owned) {
    const port = FIXED_PORT ?? 8600 + Math.floor(Math.random() * 200);
    dbDir = mkdtempSync(join(tmpdir(), "kalappai-demo-"));
    base = `http://127.0.0.1:${port}`;
    child = Bun.spawn(["bun", "src/index.ts"], {
      env: {
        ...process.env,
        PORT: String(port),
        KALAPPAI_CERT_DB: join(dbDir, "certs.db"),
        KALAPPAI_CERT_SECRET: "demo-secret-not-for-production",
        KALAPPAI_CERT_BASE: base,
      },
      stdout: "ignore",
      stderr: "pipe",
    });
  }

  await waitForReady(base);

  console.log(`${BOLD}Kalappai certification demo${NC} ${DIM}— ${base}${NC}`);
  if (owned) console.log(`${DIM}spawned from src/index.ts · throwaway database in ${dbDir}${NC}`);
  console.log("");

  const issued: Issued[] = [];
  let failed = 0;

  for (const seed of SEEDS) {
    try {
      const cert = await issue(base, seed);
      const notes = CHECK ? await assertVerifiable(base, cert) : [];
      issued.push(cert);
      console.log(
        `  ${GREEN}✓${NC} ${cert.alias.padEnd(18)} ${DIM}${cert.layoutId.padEnd(11)} ` +
          `${seed.stats.netWpm.toFixed(1)} net wpm · ${seed.stats.accuracy.toFixed(1)}%${NC}` +
          (notes.length ? ` ${DIM}[${notes.join(", ")}]${NC}` : ""),
      );
    } catch (e) {
      failed++;
      console.log(`  ${RED}✗${NC} ${seed.alias} — ${(e as Error).message}`);
    }
  }

  console.log("");

  if (CHECK) {
    if (child) child.kill();
    if (failed > 0) {
      console.log(`${RED}${BOLD}✗ Demo seeding failed${NC} (${failed} of ${SEEDS.length})`);
      process.exit(1);
    }
    console.log(`${GREEN}${BOLD}✓ Demo seeded and verified${NC} ${DIM}(${issued.length} certificates, QR + VC-JWT checked)${NC}`);
    process.exit(0);
  }

  console.log(`${BOLD}Verify pages${NC}`);
  for (const cert of issued) console.log(`  ${cert.verifyUrl}`);
  console.log("");

  const first = issued[0];
  if (first) {
    console.log(`${BOLD}Scan this${NC} ${DIM}(the QR the certificate carries, pointing at itself)${NC}`);
    console.log(await QRCode.toString(first.verifyUrl, { type: "terminal", small: true }));
    console.log(`${DIM}Anything that scans it lands on the public verify page for ${first.id}.${NC}`);
    console.log("");
  }

  console.log(`${YELLOW}!${NC} Practice certificates: not TNDTE or TNPSC qualifications.`);
  console.log(`${DIM}Ctrl-C to stop${owned ? " and discard the throwaway database" : ""}.${NC}`);

  process.on("SIGINT", () => {
    if (child) child.kill();
    console.log("");
    process.exit(0);
  });

  if (!owned) process.exit(0);
  await new Promise(() => {});
}

main().catch((e) => {
  console.error(`${RED}${BOLD}✗ ${(e as Error).message}${NC}`);
  process.exit(1);
});
