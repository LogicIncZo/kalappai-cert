/**
 * Cognizance gate contract tests.
 *
 * Two layers:
 *   1. pure `assess()` / `irregularity()` — the tier ladder and every refusal;
 *   2. the live service — issue, verify, tamper, re-download fidelity.
 *
 * Run against a FRESH throwaway DB on a random port, like server.test.ts.
 * POSTs carry a distinct x-forwarded-for so the shared per-IP limiter is not
 * consumed by the certificate suite.
 */
import { afterAll, describe, expect, test } from "bun:test";
import { createHash, createPublicKey, verify } from "node:crypto";
import { GATES, assess, gateHash, irregularity, type CognizanceRequest, type Gate } from "../src/cognizance";

const PORT = 8399 + Math.floor(Math.random() * 100);
const BASE = `http://localhost:${PORT}`;
process.env.KALAPPAI_CERT_DB = "/tmp/kalappai-cognizance-test-" + Date.now() + ".db";
process.env.PORT = String(PORT);
process.env.KALAPPAI_CERT_SECRET = "test-secret";
process.env.KALAPPAI_CERT_ORIGIN = "https://logicinczo.github.io";

const { default: app, DB_FILE } = await import("../src/index.ts");
const server = Bun.serve({ port: PORT, fetch: app.fetch });
afterAll(() => server.stop(true));

const GATE = GATES[0]!;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** Irregular, human-paced intervals: median 162.5 ms, irregularity 0.5. */
const HUMAN = [140, 165, 210, 180, 155, 125, 190, 170, 160, 150];
/** Same, with one 1.8 s pause: a hesitation. */
const HUMAN_PAUSE = [...HUMAN, 1800];

function req(
  overrides: Record<string, Partial<CognizanceRequest["fields"][number]>> = {},
  gate: Gate = GATE,
): CognizanceRequest {
  return {
    gateId: gate.id,
    alias: "",
    fields: gate.fields.map((f) => ({
      fieldId: f.id,
      charsProduced: f.value.length,
      keydowns: f.value.length,
      insertedChars: 0,
      pasteAttempts: 0,
      backspaces: 0,
      repeats: 0,
      peeks: 0,
      firstKeystrokeMs: 800,
      durationMs: 5000,
      valueSha256: sha(f.value),
      samples: [...HUMAN_PAUSE],
      ...overrides[f.id],
    })),
  };
}

const allFields = (o: Record<string, unknown>) =>
  Object.fromEntries(GATE.fields.map((f) => [f.id, o])) as Record<string, Partial<CognizanceRequest["fields"][number]>>;

const recallField = GATE.fields.find((f) => f.mode === "recall")!;
const transcribeField = GATE.fields.find((f) => f.mode === "transcribe")!;

describe("cognizance assess (pure)", () => {
  test("gate catalogue hashes each definition", () => {
    expect(GATES.length).toBeGreaterThanOrEqual(3);
    for (const g of GATES) expect(gateHash(g)).toMatch(/^[0-9a-f]{64}$/);
  });

  test("T3 for deliberate, self-corrected, recall-clean entry", () => {
    const a = assess(GATE, req({ [transcribeField.id]: { backspaces: 1 } }));
    expect(a.accepted).toBe(true);
    expect(a.tier).toBe("T3");
    expect(a.tierWithheldBecause).toBeNull();
    expect(a.residue.produced).toBe(a.residue.governed);
    expect(a.flags).toContain("recalled-from-memory");
    expect(a.flags).toContain("self-corrected");
  });

  test("T2 when the hidden source was revealed", () => {
    const a = assess(GATE, req({ [recallField.id]: { peeks: 1 } }));
    expect(a.tier).toBe("T2");
    expect(a.tierWithheldBecause).toContain("revealed");
    expect(a.flags).toContain("source-revealed");
  });

  test("T1 when entry is human-paced but shows neither hesitation nor correction", () => {
    const a = assess(GATE, req(allFields({ samples: [...HUMAN] })));
    expect(a.tier).toBe("T1");
    expect(a.tierWithheldBecause).toContain("no hesitation and no self-correction");
  });

  test("T0 with a stated reason for machine-regular entry", () => {
    const a = assess(GATE, req(allFields({ samples: [200, 200, 200, 200] })));
    expect(a.accepted).toBe(true);
    expect(a.tier).toBe("T0");
    expect(a.tierWithheldBecause).toContain("machine-regular");
  });

  test("T0 when the first keystroke arrives before a human could read", () => {
    const a = assess(GATE, req(allFields({ firstKeystrokeMs: 50 })));
    expect(a.tier).toBe("T0");
    expect(a.tierWithheldBecause).toContain("first keystroke arrived faster");
  });

  test("T0 when held-key repetition dominates", () => {
    const a = assess(GATE, req({ [transcribeField.id]: { repeats: transcribeField.value.length } }));
    expect(a.tier).toBe("T0");
    expect(a.tierWithheldBecause).toContain("held-key repetition");
  });

  test("T0 with 'too few keystroke intervals' when timing cannot be judged", () => {
    const a = assess(GATE, req(allFields({ samples: [500] })));
    expect(a.accepted).toBe(true);
    expect(a.tier).toBe("T0");
    expect(a.tierWithheldBecause).toContain("too few keystroke intervals");
  });

  test("refuses text that arrived with no keystroke behind it", () => {
    const a = assess(GATE, req(allFields({ keydowns: 0 })));
    expect(a.accepted).toBe(false);
    expect(a.rejectedReason).toBe("characters arrived without keystrokes");
  });

  test("refuses a pasted value, with the reason on the record", () => {
    const a = assess(GATE, req({ [transcribeField.id]: { pasteAttempts: 1 } }));
    expect(a.accepted).toBe(false);
    expect(a.rejectedReason).toBe("paste is not accepted at this gate");
  });

  test("refuses inserted characters", () => {
    const a = assess(GATE, req({ [transcribeField.id]: { insertedChars: 4 } }));
    expect(a.accepted).toBe(false);
    expect(a.rejectedReason).toBe("characters were inserted, not typed");
  });

  test("refuses a shortfall in coverage", () => {
    const a = assess(GATE, req({ [transcribeField.id]: { charsProduced: 1 } }));
    expect(a.accepted).toBe(false);
    expect(a.rejectedReason).toBe("governed text was not fully produced by keystroke");
    expect(a.fields.find((f) => f.fieldId === transcribeField.id)!.coverage).toBeLessThan(1);
  });

  test("refuses a value that does not match the governed text", () => {
    const a = assess(GATE, req({ [transcribeField.id]: { valueSha256: sha("0000") } }));
    expect(a.accepted).toBe(false);
    expect(a.rejectedReason).toBe("produced value does not match the governed text");
  });

  test("refuses an implausible keystroke count", () => {
    const many = transcribeField.value.length * 5;
    const a = assess(GATE, req({ [transcribeField.id]: { charsProduced: many, keydowns: many } }));
    expect(a.accepted).toBe(false);
    expect(a.rejectedReason).toBe("implausible keystroke count for the governed text");
  });

  test("irregularity needs at least three intervals", () => {
    expect(irregularity([100, 100])).toBeNull();
    expect(irregularity([100, 100, 100, 100])).toBe(1);
    expect(irregularity(HUMAN)).toBeLessThanOrEqual(0.6);
  });
});

let xffN = 0;
/** Unique per-request ip so the shared per-IP limiters are never the thing under test. */
const H = () => ({ "content-type": "application/json", "x-forwarded-for": `cog-test-${++xffN}` });

async function session(gateId = GATE.id): Promise<string> {
  const r = await fetch(`${BASE}/api/cognizance/session`, {
    method: "POST",
    headers: H(),
    body: JSON.stringify({ gateId }),
  });
  const j = (await r.json()) as { sessionId?: string; error?: string };
  if (r.status !== 201 || !j.sessionId) throw new Error(`no session: ${r.status} ${j.error ?? ""}`);
  return j.sessionId;
}

const postRaw = (body: unknown) =>
  fetch(`${BASE}/api/cognizance`, { method: "POST", headers: H(), body: JSON.stringify(body) });

/**
 * Opens a gate session, spends `reveals` reveals on it, then submits. The recall
 * tier is decided by the reveal count the ISSUER recorded for that session.
 */
async function post(body: CognizanceRequest | Record<string, unknown>, reveals = 0) {
  const sessionId = await session();
  for (let i = 0; i < reveals; i++) {
    await fetch(`${BASE}/api/cognizance/session/${sessionId}/reveal`, { method: "POST", headers: H() });
  }
  return postRaw({ ...(body as Record<string, unknown>), sessionId });
}

describe("cognizance service", () => {
  test("gate catalogue is public and hashed", async () => {
    const r = await fetch(`${BASE}/cognizance/gates`);
    expect(r.status).toBe(200);
    const j = (await r.json()) as { gates: Array<{ id: string; sha256: string; fields: unknown[] }> };
    expect(j.gates.length).toBe(GATES.length);
    for (const g of j.gates) {
      expect(g.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(g.fields.length).toBeGreaterThan(0);
    }
  });

  test("issues a CognizanceReceipt VC-JWT that verifies against JWKS", async () => {
    const r = await post(req({ [transcribeField.id]: { backspaces: 1 } }));
    expect(r.status).toBe(201);
    const issued = (await r.json()) as {
      id: string; tier: string; tierLabel: string; verifyUrl: string; vcJwt: string;
      residue: { produced: number; governed: number; inserted: number };
      credential: {
        id: string;
        type: string[]; credentialSubject: { fields: Array<{ valueSha256: string }>; gate: { sha256: string } };
        termsOfUse: Array<{ id: string }>;
      };
    };
    expect(issued.tier).toBe("T3");
    expect(issued.tierLabel).toBe("Recalled");
    expect(issued.residue.inserted).toBe(0);
    expect(issued.credential.type).toContain("CognizanceReceipt");
    const [h64, p64, sig64] = issued.vcJwt.split(".");
    const dec = (x: string) => Buffer.from(x!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const issuerBase = String(JSON.parse(dec(p64!)).iss).replace(/\/api\/issuer$/, "");
    expect(issued.credential.termsOfUse[0]!.id).toBe(`${issuerBase}/cognizance/limits`);
    expect(issued.credential.id).toBe(`${issuerBase}/cognizance/r/${issued.id}`);
    expect(issued.credential.credentialSubject.gate.sha256).toBe(gateHash(GATE));
    expect(issued.credential.credentialSubject.fields[0]!.valueSha256).toBe(sha(GATE.fields[0]!.value));

    expect(JSON.parse(dec(h64!)).alg).toBe("EdDSA");
    expect(JSON.parse(dec(p64!)).vc.credentialSubject.tier).toBe("T3");

    const jw = (await (await fetch(`${BASE}/.well-known/jwks.json`)).json()) as { keys: Array<Record<string, unknown>> };
    const pub = createPublicKey({ key: jw.keys[0]!, format: "jwk" });
    const ok = verify(null, Buffer.from(`${h64}.${p64}`), pub, Buffer.from(sig64!.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
    expect(ok).toBe(true);
  });

  test("receipt page is two-sided: tier, residue, limits, QR, and a re-downloadable credential", async () => {
    const issued = (await (await post(req({ [transcribeField.id]: { backspaces: 1 } }))).json()) as {
      id: string; vcJwt: string;
    };
    const page = await fetch(`${BASE}/cognizance/r/${issued.id}`);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("Signature valid");
    expect(html).toContain("What this does not prove");
    expect(html).toContain("<svg");
    expect(html).toContain("window.print");
    expect(html).toContain("Source reveals");

    // The credential rebuilt for the page must be byte-identical to the one issued.
    const href = html.match(/data:text\/plain;charset=utf-8,([^"]+)"/)![1]!;
    expect(decodeURIComponent(href)).toBe(issued.vcJwt);
  });

  test("stored evidence is content-free: digests and counters, never values", async () => {
    const issued = (await (await post(req())).json()) as { id: string };
    const { Database } = await import("bun:sqlite");
    const db = new Database(DB_FILE);
    const row = db.query("SELECT * FROM cognizance WHERE id = ?").get(issued.id) as Record<string, unknown>;
    db.close();
    const flat = JSON.stringify(row);
    for (const f of GATE.fields) expect(flat).not.toContain(f.value);
    expect(flat).toContain(sha(GATE.fields[0]!.value));
  });

  test("detects DB tampering with the tier", async () => {
    const issued = (await (await post(req())).json()) as { id: string };
    const { Database } = await import("bun:sqlite");
    const db = new Database(DB_FILE);
    db.query("UPDATE cognizance SET median_iki_ms = 1 WHERE id = ?").run(issued.id);
    db.close();
    const v = (await (await fetch(`${BASE}/api/cognizance/${issued.id}`)).json()) as { signatureValid: boolean };
    expect(v.signatureValid).toBe(false);
  });

  test("refuses a pasted submission (422) and reports the reason", async () => {
    const r = await post(req({ [transcribeField.id]: { pasteAttempts: 1 } }));
    expect(r.status).toBe(422);
    const j = (await r.json()) as { reason: string };
    expect(j.reason).toBe("paste is not accepted at this gate");
  });

  test("a submission whose characters had no keystrokes is refused (422)", async () => {
    const r = await post(req(allFields({ keydowns: 0 })));
    expect(r.status).toBe(422);
    const j = (await r.json()) as { reason: string };
    expect(j.reason).toBe("characters arrived without keystrokes");
  });

  test("rejects malformed payloads, unknown gates and unknown receipts", async () => {
    expect((await post({ gateId: GATE.id })).status).toBe(400);
    expect((await post({ gateId: "nope", fields: [] })).status).toBe(404);
    expect((await fetch(`${BASE}/api/cognizance/nope`)).status).toBe(404);
    expect((await fetch(`${BASE}/cognizance/r/nope`)).status).toBe(404);
  });


  test("the served statement is redacted: recall secrets never reach the client", async () => {
    const demo = await (await fetch(`${BASE}/cognizance`)).text();
    expect(demo).toContain("\u25ae");
    const catalogue = (await (await fetch(`${BASE}/cognizance/gates`)).json()) as {
      gates: Array<{ id: string; statement: string; consequence: string }>;
    };
    for (const gate of GATES) {
      const secrets = gate.fields.filter((f) => f.mode === "recall").map((f) => f.hide ?? f.value);
      const served = catalogue.gates.find((g) => g.id === gate.id)!;
      for (const secret of secrets) {
        expect(demo).not.toContain(secret);
        expect(served.statement).not.toContain(secret);
        expect(served.consequence).not.toContain(secret);
      }
    }
  });

  test("a gate session reveals the full text, once asked, and the reveal is counted", async () => {
    const id = await session();
    const r = await fetch(`${BASE}/api/cognizance/session/${id}/reveal`, { method: "POST", headers: H() });
    expect(r.status).toBe(200);
    const j = (await r.json()) as { reveals: number; statement: string; note: string };
    expect(j.reveals).toBe(1);
    expect(j.statement).toContain(recallField.hide ?? recallField.value);
    expect(j.note).toContain("top tier");
  });

  test("reveals are counted by the issuer, so a silent client cannot buy the top tier", async () => {
    const clean = (await (await post(req({ [transcribeField.id]: { backspaces: 1 } }))).json()) as { tier: string };
    expect(clean.tier).toBe("T3");
    const revealed = (await (
      await post(req({ [transcribeField.id]: { backspaces: 1 } }), 1)
    ).json()) as { tier: string; tierWithheldBecause: string; reveals: number };
    expect(revealed.reveals).toBe(1);
    expect(revealed.tier).toBe("T2");
    expect(revealed.tierWithheldBecause).toContain("revealed");
  });

  test("a gate session is single-use", async () => {
    const id = await session();
    const body = JSON.stringify({ ...req(), sessionId: id });
    const first = await fetch(`${BASE}/api/cognizance`, { method: "POST", headers: H(), body });
    expect(first.status).toBe(201);
    const again = await fetch(`${BASE}/api/cognizance`, { method: "POST", headers: H(), body });
    expect(again.status).toBe(409);
  });

  test("missing, unknown and cross-gate sessions are refused", async () => {
    expect((await postRaw(req())).status).toBe(400);
    expect((await postRaw({ ...req(), sessionId: "nope" })).status).toBe(400);
    const id = await session(GATE.id);
    expect((await postRaw({ ...req({}, GATES[1]!), sessionId: id })).status).toBe(400);
    expect((await fetch(`${BASE}/api/cognizance/session/nope/reveal`, { method: "POST" })).status).toBe(404);
  });

  test("demo page and limits page render", async () => {
    const demo = await (await fetch(`${BASE}/cognizance`)).text();
    expect(demo).toContain('id="form"');
    expect(demo).toContain('id="autofill"');
    expect(demo).toContain("Type the consequence, not the corpus.");
    expect(demo).toContain("\u25ae");
    // No recall secret may reach the page — not the value, not the phrase it hides behind.
    for (const f of GATE.fields.filter((x) => x.mode === "recall")) {
      expect(demo).not.toContain(f.value);
      if (f.hide) expect(demo).not.toContain(f.hide);
    }
    const limits = await (await fetch(`${BASE}/cognizance/limits`)).text();
    expect(limits).toContain("not bot detection");
    expect(limits).toContain("Known false negatives");
  });
});
