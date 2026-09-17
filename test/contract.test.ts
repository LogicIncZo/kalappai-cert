/**
 * Contract conformance.
 *
 * Proves that the COMMITTED contract artifact (`contract/cert-service.v1.json`)
 * describes what this service actually does — nothing here reads `src/contract.ts`,
 * so the artifact cannot pass by agreeing with itself.
 *
 * The service is spawned as a real child process on a temp DB, so this also proves
 * the documented entrypoint boots.
 *
 * Every refusal, boundary and limit asserted below is read from the artifact: change
 * the contract without changing behaviour and this suite fails; change behaviour
 * without changing the contract and it fails too.
 */
import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { createPublicKey, verify } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import artifact from "../contract/cert-service.v1.json";

const ROOT = join(import.meta.dir, "..");
const PORT = 8500 + Math.floor(Math.random() * 400);
const BASE = `http://localhost:${PORT}`;
const DB_DIR = mkdtempSync(join(tmpdir(), "kalappai-contract-"));
const DB_FILE = join(DB_DIR, "certs.db");
const ORIGIN = "https://logicinczo.github.io";

const proc = Bun.spawn(["bun", "src/index.ts"], {
  cwd: ROOT,
  env: {
    ...process.env,
    PORT: String(PORT),
    KALAPPAI_CERT_DB: DB_FILE,
    KALAPPAI_CERT_SECRET: "contract-test-secret",
    KALAPPAI_CERT_BASE: BASE,
    KALAPPAI_CERT_ORIGIN: ORIGIN,
  },
  stdout: "pipe",
  stderr: "pipe",
});

async function waitForBoot(): Promise<void> {
  for (let i = 0; i < 80; i++) {
    try {
      const r = await fetch(`${BASE}/`);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await Bun.sleep(100);
  }
  const stderr = await new Response(proc.stderr).text();
  throw new Error(`service never became ready on ${BASE}\n${stderr}`);
}
await waitForBoot();

afterAll(() => proc.kill());

/* ---------------------------------------------------------------- helpers ---- */

/** Distinct client key per call so the declared rate limit never leaks between tests. */
let ipSeq = 0;
const nextIp = () => `10.0.${Math.floor(ipSeq / 250)}.${(ipSeq++ % 250) + 1}`;

type Stats = Record<string, number>;
const PASSAGE_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

function validBody(overrides: { stats?: Stats; [k: string]: unknown } = {}) {
  const { stats, ...rest } = overrides;
  return {
    alias: "Contract Probe",
    layoutId: "tamil99",
    passageId: "exam-60s-v1",
    targetHash: PASSAGE_HASH,
    stats: {
      grossWpm: 25,
      netWpm: 23,
      accuracy: 96,
      errors: 3,
      strokes: 210,
      kdph: 1300,
      elapsedMs: 60_000,
      chars: artifact.passRules.minChars + 5,
      ...stats,
    },
    ...rest,
  };
}

async function issue(body: unknown, ip = nextIp()) {
  const r = await fetch(`${BASE}${artifact.issuance.path}`, {
    method: artifact.issuance.method,
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}

/* ------------------------------------------------------- declared routes ---- */

describe("declared routes", () => {
  for (const route of artifact.routes) {
    const { method, path, probe } = route;
    test(`${method} ${path} — ${probe.expect.join("/")}`, async () => {
      const url = `${BASE}${path.replace(":id", "zzzzzzzzzz")}`;
      const r = await fetch(url, {
        method,
        headers: { "content-type": "application/json", "x-forwarded-for": nextIp() },
        ...(method === "POST" ? { body: "{}" } : {}),
      });
      expect(probe.expect).toContain(r.status);
      if (probe.json) {
        expect(r.headers.get("content-type") ?? "").toContain("json");
        const body = (await r.json()) as Record<string, unknown>;
        expect(typeof body).toBe("object");
      }
    });
  }
});

/* ------------------------------------------------------------- issuance ---- */

describe("issuance surface", () => {
  test("a passing attempt returns exactly the declared response fields", async () => {
    const { status, body } = await issue(validBody());
    expect(status).toBe(artifact.issuance.successStatus);
    expect(Object.keys(body).sort()).toEqual([...artifact.issuance.responseFields].sort());
  });

  test("omitting any declared required stat field is refused, not silently allowed", async () => {
    for (const field of artifact.issuance.statsRequired) {
      const body = validBody();
      delete (body.stats as Record<string, number>)[field];
      const { status, body: res } = await issue(body);
      expect({ field, status }).toEqual({ field, status: artifact.refusals.invalidRequest.status });
      expect(res.error).toBe(artifact.refusals.invalidRequest.error);
    }
  });

  test("omitting any declared required top-level field is refused", async () => {
    for (const field of artifact.issuance.requestRequired) {
      const body = validBody() as Record<string, unknown>;
      delete body[field];
      const { status } = await issue(body);
      expect({ field, status }).toEqual({ field, status: artifact.refusals.invalidRequest.status });
    }
  });

  test("a targetHash that is not the declared SHA-256 shape is refused", async () => {
    const { status, body } = await issue(validBody({ targetHash: "not-a-hash" }));
    expect(status).toBe(artifact.refusals.invalidRequest.status);
    expect(body.error).toBe(artifact.refusals.invalidRequest.error);
  });

  test("malformed JSON is refused with the declared message", async () => {
    const { status, body } = await issue("{not json");
    expect(status).toBe(artifact.refusals.invalidJson.status);
    expect(body.error).toBe(artifact.refusals.invalidJson.error);
  });
});

/* ------------------------------------------------------------- pass rules ---- */

describe("pass rules (boundaries taken from the artifact)", () => {
  const { accuracyPercent, minElapsedMs, minChars } = artifact.passRules;

  test(`accuracy just below ${accuracyPercent} is refused at 422`, async () => {
    const { status, body } = await issue(validBody({ stats: { accuracy: accuracyPercent - 0.01 } }));
    expect(status).toBe(artifact.refusals.failedPassRules.status);
    expect(body.error).toBe(artifact.refusals.failedPassRules.error);
  });

  test(`elapsed just below ${minElapsedMs} ms is refused at 422`, async () => {
    const { status } = await issue(validBody({ stats: { elapsedMs: minElapsedMs - 1 } }));
    expect(status).toBe(artifact.refusals.failedPassRules.status);
  });

  test(`chars just below ${minChars} is refused at 422`, async () => {
    const { status } = await issue(validBody({ stats: { chars: minChars - 1 } }));
    expect(status).toBe(artifact.refusals.failedPassRules.status);
  });

  test("exactly at every declared rule passes", async () => {
    const { status } = await issue(
      validBody({ stats: { accuracy: accuracyPercent, elapsedMs: minElapsedMs, chars: minChars } }),
    );
    expect(status).toBe(artifact.issuance.successStatus);
  });
});

/* -------------------------------------------------------- stat invariants ---- */

describe("declared stat invariants", () => {
  const violation = artifact.statInvariants.onViolation;

  test("net WPM above gross WPM is refused", async () => {
    const { status, body } = await issue(validBody({ stats: { grossWpm: 10, netWpm: 40 } }));
    expect(status).toBe(violation.status);
    expect(body.error).toBe(violation.error);
  });

  test("100% accuracy reported alongside errors is refused", async () => {
    const { status, body } = await issue(validBody({ stats: { accuracy: 100, errors: 4 } }));
    expect(status).toBe(violation.status);
    expect(body.error).toBe(violation.error);
  });

  test("more errors than strokes is refused", async () => {
    const { status, body } = await issue(validBody({ stats: { strokes: 5, errors: 9 } }));
    expect(status).toBe(violation.status);
    expect(body.error).toBe(violation.error);
  });
});

/* --------------------------------------------------------------- refusals ---- */

describe("rate limit (declared window and allowance)", () => {
  test(`${artifact.rateLimit.issues} issues allowed, the next is refused at 429`, async () => {
    const ip = nextIp();
    const statuses: number[] = [];
    for (let i = 0; i < artifact.rateLimit.issues + 1; i++) {
      const r = await fetch(`${BASE}${artifact.issuance.path}`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        body: JSON.stringify(validBody()),
      });
      statuses.push(r.status);
      if (r.status === artifact.refusals.rateLimited.status) {
        const body = (await r.json()) as { error: string };
        expect(body.error).toBe(artifact.refusals.rateLimited.error);
      }
    }
    const allowed = statuses.filter((s) => s === artifact.issuance.successStatus).length;
    expect(allowed).toBe(artifact.rateLimit.issues);
    expect(statuses[artifact.rateLimit.issues]).toBe(artifact.refusals.rateLimited.status);
  });
});

/* ---------------------------------------------------------- verification ---- */

describe("verification", () => {
  test("JSON verification reports a valid signature for an untouched record", async () => {
    const { body: issued } = await issue(validBody());
    const id = issued.id as string;
    const v = await fetch(`${BASE}${artifact.verification.jsonPath.replace(":id", id)}`);
    expect(v.status).toBe(200);
    const data = (await v.json()) as { signatureValid: boolean; certificate: { id: string } };
    expect(data.signatureValid).toBe(true);
    expect(data.certificate.id).toBe(id);
  });

  test(`the ?${artifact.verification.signatureProbeParam}= probe detects a wrong signature`, async () => {
    const { body: issued } = await issue(validBody());
    const id = issued.id as string;
    const param = artifact.verification.signatureProbeParam;
    const v = await fetch(`${BASE}${artifact.verification.jsonPath.replace(":id", id)}?${param}=deadbeef`);
    const data = (await v.json()) as { signatureValid: boolean };
    expect(data.signatureValid).toBe(false);
  });

  test("an unknown id is refused with the declared not-found", async () => {
    const r = await fetch(`${BASE}${artifact.verification.jsonPath.replace(":id", "nosuchcert")}`);
    expect(r.status).toBe(artifact.refusals.notFound.status);
    expect(((await r.json()) as { error: string }).error).toBe(artifact.refusals.notFound.error);
  });

  test("the human verify page carries a QR back to itself and the issued id", async () => {
    const { body: issued } = await issue(validBody());
    const id = issued.id as string;
    const page = await fetch(`${BASE}${artifact.verification.humanPath.replace(":id", id)}`);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("<svg"); // the QR
    expect(html).toContain(id);
    if (artifact.verification.qrTargetsSelf) expect(html).not.toContain("https://example.com");
  });
});

/* ------------------------------------------------------------ credential ---- */

describe("credential claims", () => {
  test("VC-JWT uses the declared proof, verifies against the declared JWKS", async () => {
    const { body: issued } = await issue(validBody());
    const vcJwt = issued.vcJwt as string;
    const [h64, p64, s64] = vcJwt.split(".");

    const dec = (x: string) => Buffer.from(x.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const header = JSON.parse(dec(h64)) as { alg: string; typ?: string };
    expect(header.alg).toBe(artifact.credential.alg);

    const payload = JSON.parse(dec(p64)) as {
      iss: string;
      vc: { type: string[]; credentialSubject: { name: string } };
    };
    expect(payload.iss).toContain(artifact.credential.issuerPath);
    for (const t of artifact.credential.types) expect(payload.vc.type).toContain(t);
    expect(payload.vc.credentialSubject.name).toBe("Contract Probe");

    const jwks = (await (await fetch(`${BASE}${artifact.credential.jwksPath}`)).json()) as {
      keys: Array<Record<string, unknown>>;
    };
    const jwk = jwks.keys[0];
    expect(jwk.crv).toBe(artifact.credential.crv);
    expect(jwk.kid).toBe(artifact.credential.kid);

    const pub = createPublicKey({ key: jwk as never, format: "jwk" });
    const ok = verify(
      null,
      Buffer.from(`${h64}.${p64}`),
      pub,
      Buffer.from(s64.replace(/-/g, "+").replace(/_/g, "/"), "base64"),
    );
    expect(ok).toBe(true);
  });

  test("issuer metadata is published at the declared path", async () => {
    const r = await fetch(`${BASE}${artifact.credential.issuerPath}`);
    expect(r.status).toBe(200);
    const meta = (await r.json()) as { id: string; publicKeyJwk?: unknown };
    expect(meta.publicKeyJwk).toBeTruthy();
  });
});
