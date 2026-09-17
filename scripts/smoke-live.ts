/**
 * Deployed-instance conformance ("deploy drift" detector).
 *
 * Where `scripts/smoke.ts` proves a freshly spawned build behaves, this proves the
 * build that is actually SERVING behaves — and that it is the same surface this
 * commit declares. It is the CD-side half of the gate.
 *
 * Deliberately NON-MUTATING: every write-shaped probe is one that must be refused
 * (missing field, failed pass rules, impossible stats), so running it against
 * production never mints a certificate.
 *
 * Usage:
 *   bun scripts/smoke-live.ts                       # uses the default live instance
 *   bun scripts/smoke-live.ts https://host.example  # or any other deployment
 */
import artifact from "../contract/cert-service.v1.json";

const DEFAULT_BASE = "https://kalappai-cert-cashlessconsumer.zocomputer.io";
const base = (process.argv[2] ?? process.env.KALAPPAI_CERT_PROBE_BASE ?? DEFAULT_BASE).replace(/\/+$/, "");

const bold = (s: string) => `\u001b[1m${s}\u001b[0m`;
const dim = (s: string) => `\u001b[2m${s}\u001b[0m`;
const green = (s: string) => `\u001b[32m${s}\u001b[0m`;
const red = (s: string) => `\u001b[31m${s}\u001b[0m`;

let failed = 0;

function pass(label: string, detail = "") {
  console.log(`  ${green("✓")} ${label}${detail ? ` ${dim(`(${detail})`)}` : ""}`);
}
function fail(label: string, detail = "") {
  failed++;
  console.log(`  ${red("✗")} ${label}${detail ? ` ${dim(`(${detail})`)}` : ""}`);
}

const validStats = {
  grossWpm: 21.4,
  netWpm: 19.8,
  accuracy: 96.2,
  errors: 3,
  strokes: 180,
  kdph: 1100,
  elapsedMs: 60_000,
  chars: 145,
};

function body(overrides: Record<string, unknown> = {}) {
  return {
    alias: "deploy-probe",
    layoutId: "tamil99",
    passageId: "exam-60s-v1",
    targetHash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    stats: { ...validStats, ...((overrides.stats as Record<string, unknown>) ?? {}) },
    ...Object.fromEntries(Object.entries(overrides).filter(([k]) => k !== "stats")),
  };
}

async function post(payload: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const r = await fetch(`${base}${artifact.issuance.path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": "deploy-probe" },
    body: JSON.stringify(payload),
  });
  let json: Record<string, unknown> = {};
  try {
    json = (await r.json()) as Record<string, unknown>;
  } catch {
    /* non-JSON body is itself a finding */
  }
  return { status: r.status, json };
}

console.log(`${bold("Deployed-instance conformance")} ${dim(`— ${base}`)}\n`);

/* ---- 1. the deployment answers at all ---- */

try {
  const r = await fetch(`${base}/`);
  const j = (await r.json()) as { service?: string; ok?: boolean };
  if (r.status === 200 && j.ok === true) pass("the deployment answers its health banner", `200 · ${j.service ?? "?"}`);
  else fail("the deployment answers its health banner", `${r.status}`);
} catch (e) {
  fail("the deployment answers its health banner", (e as Error).message);
  console.log(`\n${red(bold("✗ Deploy conformance could not run"))} — nothing reachable at ${base}\n`);
  process.exit(1);
}

/* ---- 2. every declared readable route is live and answering as declared ---- */

const staticRoutes = artifact.routes.filter((r) => !r.path.includes(":") && r.method === "GET");
for (const route of staticRoutes) {
  try {
    const r = await fetch(`${base}${route.path}`);
    if (r.status === 200) pass(`readable route ${route.path}`, `${r.status} · ${route.purpose}`);
    else fail(`readable route ${route.path}`, `${r.status}`);
  } catch (e) {
    fail(`readable route ${route.path}`, (e as Error).message);
  }
}

/* ---- 3. the deployed build enforces the contract's CURRENT rules ---- */

const invalid = await post(body({ stats: { chars: undefined } }));
if (invalid.status === artifact.refusals.invalidRequest.status) {
  pass("the deployed build requires every declared field", `chars omitted → ${invalid.status}`);
} else {
  fail(
    "the deployed build requires every declared field",
    `chars omitted → ${invalid.status} (want ${artifact.refusals.invalidRequest.status}) — deployed build predates the declared contract`,
  );
}

const belowRules = await post(body({ stats: { accuracy: artifact.passRules.accuracyPercent - 1 } }));
if (belowRules.status === artifact.refusals.failedPassRules.status) {
  pass("the deployed build holds the pass rules", `accuracy ${artifact.passRules.accuracyPercent - 1} → ${belowRules.status}`);
} else {
  fail("the deployed build holds the pass rules", `${belowRules.status}`);
}

const impossible = await post(body({ stats: { netWpm: 99, grossWpm: 10 } }));
if (impossible.status === artifact.refusals.implausibleStats.status) {
  pass("the deployed build refuses self-contradictory reports", `net > gross → ${impossible.status}`);
} else {
  fail("the deployed build refuses self-contradictory reports", `${impossible.status}`);
}

/* ---- 4. the deployed credential machinery matches the declared shape ---- */

try {
  const [issuer, jwks] = await Promise.all([
    fetch(`${base}${artifact.credential.issuerPath}`).then((r) => r.json()),
    fetch(`${base}${artifact.credential.jwksPath}`).then((r) => r.json()),
  ]);
  const key = (jwks as { keys: Array<Record<string, unknown>> }).keys[0];
  const okAlg = key?.alg === artifact.credential.alg;
  const okCrv = key?.crv === artifact.credential.crv;
  if (okAlg && okCrv) pass("the deployed JWKS publishes the declared key type", `${key.alg} · ${key.crv}`);
  else fail("the deployed JWKS publishes the declared key type", `${key?.alg ?? "?"} · ${key?.crv ?? "?"}`);

  const issuerId = (issuer as { id?: string }).id ?? "";
  if (issuerId.startsWith(base)) pass("the issuer identity is self-referential to this deployment", issuerId);
  else fail("the issuer identity is self-referential to this deployment", `${issuerId} does not start with ${base}`);
} catch (e) {
  fail("the deployed issuer/JWKS endpoints answer", (e as Error).message);
}

/* ---- report ---- */

if (failed === 0) {
  console.log(`\n${green(bold("✓ Deployment conforms to the committed contract"))}\n`);
  process.exit(0);
}
console.log(
  `\n${red(bold(`✗ Deployment does not conform (${failed} check${failed === 1 ? "" : "s"} failed)`))}` +
    `\n  the live instance is serving something other than this commit's contract — redeploy.\n`,
);
process.exit(1);
