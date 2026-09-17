/**
 * Kalappai cognizance gate (கவனிப்பு) — "was this produced, deliberately, by a human?"
 *
 * This is NOT bot detection. There is no adversary here: the only party who can
 * defeat the gate is the person whose attention it is meant to secure. What the
 * gate does is remove the zero-effort path to a submission (paste, autofill,
 * agent-fill) and leave a signed, two-sided receipt of what was produced.
 *
 * Honest framing — rendered on every receipt, and machine-readable in the
 * credential's termsOfUse:
 *   - it records that characters were PRODUCED, not that they were UNDERSTOOD;
 *   - telemetry is client-reported; the thresholds are chosen, not validated on
 *     a population; a determined user can fabricate every number in it;
 *   - it is a friction layer and an evidentiary receipt, not a security control
 *     and not legal proof of consent.
 *
 * Design rules that the code enforces:
 *   1. Type the consequence, not the corpus. Gates govern a handful of short,
 *      operative values, never the whole text.
 *   2. Recompute, never trust. The client sends raw inter-keystroke samples and
 *      counters; every derived figure is computed here.
 *   3. The receipt is content-free. Field values are compared by SHA-256
 *      against the relying party's gate definition and never stored.
 *   4. Tiers, not a badge. T0 produced → T1 deliberate → T2 attentive →
 *      T3 recalled. A withheld tier states why.
 *   5. A non-typing route must exist. Dictation, switch access and autofill are
 *      rejected by design, so any deployment must offer an alternate route with
 *      the same receipt type. See /cognizance/limits.
 */
import type { Hono } from "hono";
import { createHash } from "node:crypto";
import type { Database } from "bun:sqlite";
import QRCode from "qrcode";

/* ------------------------------------------------------------------ *
 * Gate catalogue
 *
 * In a real deployment the gate definitions live with the relying party
 * (the bank, the insurer, the portal) and this service only verifies.
 * These three demo gates are illustrative and use no real PII.
 * ------------------------------------------------------------------ */

export type GateFieldMode = "transcribe" | "recall";

export type GateField = {
  id: string;
  label: string;
  value: string;
  mode: GateFieldMode;
  hint?: string;
  /** Substring of the statement redacted while this recall value is typed. */
  hide?: string;
};

export type Gate = {
  id: string;
  title: string;
  context: string;
  statement: string;
  consequence: string;
  fields: GateField[];
};

export const GATES: Gate[] = [
  {
    id: "upi-autopay-mandate",
    title: "UPI Autopay mandate — Acme Broadband",
    context: "Example gate · recurring debit mandate",
    statement:
      "You are authorising Acme Broadband to debit Rs 4,999 on 5 October 2026 and every month after that, until you cancel. There is no cancellation charge and no notice period. You may cancel from the mandate screen of your UPI app at any time.",
    consequence: "Rs 4,999 every month, first debit October 2026",
    fields: [
      {
        id: "amount",
        label: "Amount you are authorising (digits only)",
        value: "4999",
        mode: "transcribe",
        hint: "Type the amount from the mandate above.",
      },
      {
        id: "first-debit",
        label: "Month of the first debit (YYYY-MM)",
        value: "2026-10",
        mode: "recall",
        hide: "October 2026",
        hint: "The date is hidden while you type this. Type the month you just read.",
      },
    ],
  },
  {
    id: "foreclosure-charges",
    title: "Foreclosure charge schedule",
    context: "Example gate · loan foreclosure",
    statement:
      "Foreclosure is permitted at any time after the twelfth EMI. The charge is 2 per cent of the outstanding principal, subject to a minimum of Rs 1,500. The exact charge must be shown to you before you are asked to pay it.",
    consequence: "2 per cent of outstanding, minimum Rs 1,500",
    fields: [
      {
        id: "after-emi",
        label: "EMIs that must be paid before foreclosure is allowed (digits only)",
        value: "12",
        mode: "transcribe",
        hint: "Type the number of EMIs from the schedule above.",
      },
      {
        id: "min-charge",
        label: "Minimum charge (Rs, digits only)",
        value: "1500",
        mode: "recall",
        hide: "Rs 1,500",
        hint: "The minimum is hidden while you type this.",
      },
    ],
  },
  {
    id: "kyc-data-sharing",
    title: "KYC profile sharing — insurer underwriting",
    context: "Example gate · data-sharing consent",
    statement:
      "The KYC profile held in your bank record may be shared with the insurer you name, for underwriting only. Sharing the same profile for marketing requires your separate consent, which you are free to refuse without losing access to the policy.",
    consequence: "Sharing limited to underwriting; marketing needs separate consent",
    fields: [
      {
        id: "purpose",
        label: "The single purpose this consent covers (one word)",
        value: "underwriting",
        mode: "transcribe",
        hint: "One word, from the consent text above.",
      },
      {
        id: "excluded",
        label: "What additionally needs your separate consent (one word)",
        value: "marketing",
        mode: "recall",
        hide: "marketing",
        hint: "That word is hidden while you type this.",
      },
    ],
  },
];

/** Field values are short by design: type the consequence, not the corpus. */
export const MAX_FIELD_VALUE_CHARS = 64;

/* ------------------------------------------------------------------ *
 * Thresholds — chosen, not validated. Every one is published on
 * /cognizance/limits so a deployment can argue with them in the open.
 * ------------------------------------------------------------------ */

export const RULES = {
  /** Median inter-keystroke interval below this looks machine-regular. */
  minMedianIkiMs: 90,
  /** Share of intervals within +/-10% of the median that disqualifies T1. */
  maxIrregularity: 0.6,
  /** Faster than this from focus to first character suggests pre-filled entry. */
  minFirstKeystrokeMs: 300,
  /** A pause longer than this counts as a hesitation worth reporting. */
  hesitationMs: 1500,
  /** Held-key fills produce repeats roughly 1:1 with characters. */
  maxRepeatRatio: 0.25,
  /** Fewer pooled keystroke intervals than this and timing cannot be judged. */
  minSamplesInPool: 3,
  maxSamplesPerField: 400,
};

export const TIER_LABELS: Record<Tier, string> = {
  T0: "Produced",
  T1: "Deliberate",
  T2: "Attentive",
  T3: "Recalled",
};

export const TIER_MEANING: Record<Tier, string> = {
  T0: "Every governed character was produced by keystroke; nothing was pasted, dropped or filled.",
  T1: "…and the typing rhythm is inconsistent with scripted, machine-regular entry.",
  T2: "…and the entry shows a hesitation or a self-correction — evidence of reading, not just of typing.",
  T3: "…and at least one consequential value was produced from memory, with the source text hidden and never re-revealed.",
};

export type Tier = "T0" | "T1" | "T2" | "T3";

/* ------------------------------------------------------------------ *
 * Assessment
 * ------------------------------------------------------------------ */

export type FieldTelemetry = {
  fieldId: string;
  charsProduced: number;
  /** Printable, non-repeat keydowns seen on the field. */
  keydowns: number;
  insertedChars: number;
  pasteAttempts: number;
  backspaces: number;
  repeats: number;
  peeks: number;
  firstKeystrokeMs: number | null;
  durationMs: number;
  valueSha256: string;
  samples: number[];
};

export type FieldAssessment = {
  fieldId: string;
  label: string;
  mode: GateFieldMode;
  governedChars: number;
  charsProduced: number;
  keydowns: number;
  insertedChars: number;
  pasteAttempts: number;
  backspaces: number;
  repeats: number;
  peeks: number;
  coverage: number;
  medianIkiMs: number;
  irregularity: number | null;
  hesitations: number;
  firstKeystrokeMs: number | null;
  durationMs: number;
  valueMatches: boolean;
  valueSha256: string;
  produced: boolean;
};

export type Assessment = {
  accepted: boolean;
  rejectedReason: string | null;
  tier: Tier;
  tierLabel: string;
  tierWithheldBecause: string | null;
  fields: FieldAssessment[];
  residue: { produced: number; governed: number; inserted: number };
  flags: string[];
  timing: { samples: number; medianIkiMs: number; irregularity: number | null; hesitations: number };
};

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export function gateHash(gate: Gate): string {
  return sha256(
    JSON.stringify({
      id: gate.id,
      statement: gate.statement,
      fields: gate.fields.map((f) => ({ id: f.id, value: f.value, mode: f.mode })),
    }),
  );
}

/** Blanks out every recall-mode secret (f.hide) found in a piece of displayed text. */
export function redact(text: string, gate: Gate): string {
  let s = text;
  for (const f of gate.fields) {
    if (f.mode !== "recall") continue;
    const secret = f.hide ?? f.value;
    if (secret && s.includes(secret)) s = s.split(secret).join("\u25ae".repeat(Math.min(secret.length, 16)));
  }
  return s;
}

/**
 * The gate as the client is served it: every recall-mode secret is blanked, in
 * the statement and in the consequence line. The full text is reachable only
 * through a reveal, and the issuer counts the reveals — not the client.
 */
export function servedGate(gate: Gate): {
  id: string; title: string; context: string; statement: string; consequence: string; sha256: string;
  fields: Array<{ id: string; label: string; mode: GateFieldMode; hint: string | null; chars: number }>;
} {
  return {
    id: gate.id,
    title: gate.title,
    context: gate.context,
    statement: redact(gate.statement, gate),
    consequence: redact(gate.consequence, gate),
    sha256: gateHash(gate),
    fields: gate.fields.map((f) => ({
      id: f.id, label: f.label, mode: f.mode, hint: f.hint ?? null, chars: f.value.length,
    })),
  };
}

const median = (xs: number[]): number => {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
};

/** Share of samples sitting within +/-10% of the median. 1 = perfectly regular. */
export function irregularity(samples: number[]): number | null {
  if (samples.length < 3) return null;
  const m = median(samples);
  if (m <= 0) return null;
  const near = samples.filter((s) => Math.abs(s - m) <= m * 0.1).length;
  return Math.round((near / samples.length) * 1000) / 1000;
}

export type CognizanceRequest = {
  gateId: string;
  alias?: string;
  fields: FieldTelemetry[];
};

const isSha256 = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);

const int = (v: unknown, lo: number, hi: number): number | null => {
  const n = Number(v);
  return Number.isInteger(n) && n >= lo && n <= hi ? n : null;
};

/** Validates and normalises the wire payload. Returns null when malformed. */
export function parseRequest(raw: unknown, gate: Gate): CognizanceRequest | null {
  if (!raw || typeof raw !== "object") return null;
  const b = raw as Record<string, unknown>;
  if (b.gateId !== gate.id) return null;
  if (!Array.isArray(b.fields)) return null;

  const out: FieldTelemetry[] = [];
  for (const f of b.fields) {
    if (!f || typeof f !== "object") return null;
    const r = f as Record<string, unknown>;
    const spec = gate.fields.find((g) => g.id === r.fieldId);
    if (!spec) return null;

    const samples: number[] = [];
    if (r.samples !== undefined) {
      if (!Array.isArray(r.samples) || r.samples.length > RULES.maxSamplesPerField) return null;
      for (const s of r.samples) {
        const n = int(s, 0, 60_000);
        if (n === null) return null;
        samples.push(n);
      }
    }

    const charsProduced = int(r.charsProduced, 0, 100_000);
    const keydowns = int(r.keydowns, 0, 100_000);
    const insertedChars = int(r.insertedChars, 0, 100_000);
    const pasteAttempts = int(r.pasteAttempts, 0, 1000);
    const backspaces = int(r.backspaces, 0, 100_000);
    const repeats = int(r.repeats, 0, 100_000);
    const peeks = int(r.peeks, 0, 1000);
    const durationMs = int(r.durationMs, 0, 6 * 3600 * 1000);
    const firstRaw = r.firstKeystrokeMs === null || r.firstKeystrokeMs === undefined ? 0 : int(r.firstKeystrokeMs, 0, 6 * 3600 * 1000);

    if (
      charsProduced === null || keydowns === null || insertedChars === null || pasteAttempts === null ||
      backspaces === null || repeats === null || peeks === null || durationMs === null ||
      firstRaw === null || !isSha256(r.valueSha256)
    ) return null;

    out.push({
      fieldId: spec.id,
      charsProduced,
      keydowns,
      insertedChars,
      pasteAttempts,
      backspaces,
      repeats,
      peeks,
      firstKeystrokeMs: r.firstKeystrokeMs === null || r.firstKeystrokeMs === undefined ? null : firstRaw,
      durationMs,
      valueSha256: r.valueSha256 as string,
      samples,
    });
  }
  if (out.length !== gate.fields.length) return null;
  return { gateId: gate.id, alias: typeof b.alias === "string" ? b.alias : "", fields: out };
}

/**
 * Recomputes the whole verdict from raw client telemetry. Nothing derived is
 * trusted: coverage, timing, regularity and tier are all decided here.
 */
export function assess(gate: Gate, req: CognizanceRequest, reveals = 0): Assessment {
  const pool: number[] = [];
  const fields: FieldAssessment[] = gate.fields.map((spec) => {
    const t = req.fields.find((f) => f.fieldId === spec.id)!;
    const governedChars = spec.value.length;
    const coverage = governedChars === 0 ? 1 : Math.min(1, t.charsProduced / governedChars);
    const valueMatches = t.valueSha256 === sha256(spec.value);
    // Reveals of the redacted source are counted by the issuer, not by the client:
    // the larger of the two counts wins, so a silent client cannot buy a tier.
    const peeks = spec.mode === "recall" ? Math.max(t.peeks, reveals) : t.peeks;
    pool.push(...t.samples);
    return {
      fieldId: spec.id,
      label: spec.label,
      mode: spec.mode,
      governedChars,
      charsProduced: t.charsProduced,
      keydowns: t.keydowns,
      insertedChars: t.insertedChars,
      pasteAttempts: t.pasteAttempts,
      backspaces: t.backspaces,
      repeats: t.repeats,
      peeks,
      coverage: Math.round(coverage * 1000) / 1000,
      medianIkiMs: Math.round(median(t.samples)),
      irregularity: irregularity(t.samples),
      hesitations: t.samples.filter((s) => s >= RULES.hesitationMs).length,
      firstKeystrokeMs: t.firstKeystrokeMs,
      durationMs: t.durationMs,
      valueMatches,
      valueSha256: t.valueSha256,
      produced: coverage >= 1 && t.insertedChars === 0 && t.pasteAttempts === 0 && valueMatches,
    };
  });

  const residue = {
    produced: fields.reduce((n, f) => n + f.charsProduced, 0),
    governed: fields.reduce((n, f) => n + f.governedChars, 0),
    inserted: fields.reduce((n, f) => n + f.insertedChars, 0),
  };

  const flags: string[] = [];
  if (fields.some((f) => f.peeks > 0)) flags.push("source-revealed");
  if (fields.some((f) => f.backspaces > 0)) flags.push("self-corrected");
  if (fields.some((f) => f.hesitations > 0)) flags.push("hesitated");
  if (fields.some((f) => f.mode === "recall" && f.peeks === 0 && f.coverage >= 1)) flags.push("recalled-from-memory");

  const pooledMedian = Math.round(median(pool));
  const pooledIrregularity = irregularity(pool);
  const timing = { samples: pool.length, medianIkiMs: pooledMedian, irregularity: pooledIrregularity, hesitations: pool.filter((s) => s >= RULES.hesitationMs).length };

  const base: Omit<Assessment, "accepted" | "rejectedReason" | "tier" | "tierLabel" | "tierWithheldBecause"> = {
    fields,
    residue,
    flags,
    timing,
  };

  const rejected = (reason: string): Assessment => ({
    ...base,
    accepted: false,
    rejectedReason: reason,
    tier: "T0",
    tierLabel: "Not issued",
    tierWithheldBecause: reason,
  });

  if (fields.some((f) => f.insertedChars > 0)) return rejected("characters were inserted, not typed");
  if (fields.some((f) => f.keydowns < f.charsProduced)) return rejected("characters arrived without keystrokes");
  if (fields.some((f) => f.pasteAttempts > 0)) return rejected("paste is not accepted at this gate");
  if (fields.some((f) => !f.valueMatches)) return rejected("produced value does not match the governed text");
  if (fields.some((f) => f.coverage < 1)) return rejected("governed text was not fully produced by keystroke");
  if (fields.some((f) => f.charsProduced > f.governedChars * 4)) return rejected("implausible keystroke count for the governed text");

  // T1 and above need enough keystrokes to judge rhythm at all.
  if (pool.length < RULES.minSamplesInPool) {
    return {
      ...base,
      accepted: true,
      rejectedReason: null,
      tier: "T0",
      tierLabel: TIER_LABELS.T0,
      tierWithheldBecause: `too few keystroke intervals (${pool.length}) to judge timing`,
    };
  }

  const rhythmOk =
    pooledMedian >= RULES.minMedianIkiMs &&
    pooledIrregularity !== null &&
    pooledIrregularity <= RULES.maxIrregularity;
  const pacingOk = fields.every(
    (f) => f.firstKeystrokeMs === null || f.firstKeystrokeMs >= RULES.minFirstKeystrokeMs,
  );
  const repeatRatio = residue.produced > 0 ? fields.reduce((n, f) => n + f.repeats, 0) / residue.produced : 1;
  const heldKeyOk = repeatRatio <= RULES.maxRepeatRatio;

  if (!(rhythmOk && pacingOk && heldKeyOk)) {
    const why = !rhythmOk
      ? `typing rhythm is machine-regular (median ${pooledMedian} ms, irregularity ${pooledIrregularity})`
      : !pacingOk
        ? `first keystroke arrived faster than ${RULES.minFirstKeystrokeMs} ms after focus`
        : "held-key repetition suggests the field was filled, not typed";
    return { ...base, accepted: true, rejectedReason: null, tier: "T0", tierLabel: TIER_LABELS.T0, tierWithheldBecause: why };
  }

  const attentive = timing.hesitations >= 1 || fields.some((f) => f.backspaces > 0);
  if (!attentive) {
    return {
      ...base,
      accepted: true,
      rejectedReason: null,
      tier: "T1",
      tierLabel: TIER_LABELS.T1,
      tierWithheldBecause: "no hesitation and no self-correction — nothing beyond smooth typing was observed",
    };
  }

  const recallFields = fields.filter((f) => f.mode === "recall");
  const recalledOk = recallFields.length > 0 && recallFields.every((f) => f.peeks === 0);
  if (!recalledOk) {
    return {
      ...base,
      accepted: true,
      rejectedReason: null,
      tier: "T2",
      tierLabel: TIER_LABELS.T2,
      tierWithheldBecause: recallFields.length === 0
        ? "this gate has no recall-mode field"
        : "the hidden source was revealed while typing a recalled value",
    };
  }

  return { ...base, accepted: true, rejectedReason: null, tier: "T3", tierLabel: TIER_LABELS.T3, tierWithheldBecause: null };
}

/* ------------------------------------------------------------------ *
 * Persistence + credential
 * ------------------------------------------------------------------ */

export type CognizanceRow = {
  id: string;
  issued_at: number;
  gate_id: string;
  gate_hash: string;
  tier: string;
  alias: string;
  produced_chars: number;
  governed_chars: number;
  inserted_chars: number;
  backspaces: number;
  median_iki_ms: number;
  duration_ms: number;
  evidence_json: string;
  reveals: number;
  signature: string;
};

const canonicalRow = (r: Omit<CognizanceRow, "signature">): string =>
  (Object.keys(r).sort() as (keyof Omit<CognizanceRow, "signature">)[])
    .map((k) => `${k}=${String(r[k])}`)
    .join("|");

const dollar = (r: Record<string, unknown>): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(r)) out[`$${k}`] = v;
  return out;
};

export const COGNIZANCE_SCHEMA = `
  CREATE TABLE IF NOT EXISTS cognizance (
    id TEXT PRIMARY KEY,
    issued_at INTEGER NOT NULL,
    gate_id TEXT NOT NULL,
    gate_hash TEXT NOT NULL,
    tier TEXT NOT NULL,
    alias TEXT NOT NULL,
    produced_chars INTEGER NOT NULL,
    governed_chars INTEGER NOT NULL,
    inserted_chars INTEGER NOT NULL,
    backspaces INTEGER NOT NULL,
    median_iki_ms REAL NOT NULL,
    duration_ms INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    reveals INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS cognizance_sessions (
    id TEXT PRIMARY KEY,
    gate_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    reveals INTEGER NOT NULL,
    submitted_at INTEGER
  );
`;

type SessionRow = { id: string; gate_id: string; created_at: number; reveals: number; submitted_at: number | null };

/** A gate session is short-lived: opening one is cheap, issuing a receipt is not. */
const SESSION_TTL_MS = 30 * 60 * 1000;

const sessionHits = new Map<string, number[]>();
function sessionLimited(ip: string): boolean {
  const now = Date.now();
  const arr = (sessionHits.get(ip) ?? []).filter((t) => now - t < 5 * 60 * 1000);
  arr.push(now);
  sessionHits.set(ip, arr);
  return arr.length > 60;
}

export type CognizanceDeps = {
  db: Database;
  base: string;
  issuerId: string;
  hmac: (payload: string, at: number) => string;
  vcJwt: (credential: Record<string, unknown>, verifyUrl: string, issuedAt: number) => string;
  newId: () => string;
  limited: (ip: string) => boolean;
  ttlDays: number;
};

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function receiptCredential(
  row: CognizanceRow,
  gate: Gate | null,
  assessment: Assessment,
  base: string,
  issuerId: string,
): Record<string, unknown> {
  const verifyUrl = `${base}/cognizance/r/${row.id}`;
  const validUntil = new Date(row.issued_at + 86_400_000 * TTL_DAYS).toISOString();
  // Receipts outlive catalogue revisions: fall back to what the row recorded.
  const gateInfo = gate
    ? { id: gate.id, title: gate.title, sha256: row.gate_hash }
    : { id: row.gate_id, title: row.gate_id, sha256: row.gate_hash, note: "gate definition no longer in this issuer's catalogue" };
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: verifyUrl,
    type: ["VerifiableCredential", "CognizanceReceipt"],
    issuer: issuerId,
    validFrom: new Date(row.issued_at).toISOString(),
    validUntil,
    credentialSubject: {
      id: `urn:kalappai:cognizance:${row.id}`,
      alias: row.alias || undefined,
      gate: gateInfo,
      tier: row.tier,
      tierLabel: assessment.tierLabel,
      tierWithheldBecause: assessment.tierWithheldBecause,
      fields: assessment.fields.map((f) => ({
        fieldId: f.fieldId,
        label: f.label,
        mode: f.mode,
        valueSha256: f.valueSha256,
        governedChars: f.governedChars,
        charsProduced: f.charsProduced,
        insertedChars: f.insertedChars,
        keydowns: f.keydowns,
        backspaces: f.backspaces,
        peeks: f.peeks,
        coverage: f.coverage,
        medianIkiMs: f.medianIkiMs,
        durationMs: f.durationMs,
        valueMatches: f.valueMatches,
      })),
    },
    evidence: [
      {
        type: ["CognizanceEvidence"],
        residue: assessment.residue,
        flags: assessment.flags,
        timing: assessment.timing,
        thresholds: RULES,
        issuerReveals: row.reveals,
      },
    ],
    termsOfUse: [{ type: "IssuerPolicy", id: `${base}/cognizance/limits` }],
  };
}

/** ttlDays is injected at mount time; kept module-local for the credential builder. */
let TTL_DAYS = 90;

/* ------------------------------------------------------------------ *
 * Router
 * ------------------------------------------------------------------ */

export function mountCognizance(app: Hono, deps: CognizanceDeps): void {
  const { db, base, issuerId, hmac, vcJwt, newId, limited } = deps;
  TTL_DAYS = Number.isFinite(deps.ttlDays) && deps.ttlDays > 0 ? Math.floor(deps.ttlDays) : 90;

  db.exec(COGNIZANCE_SCHEMA);

  // Additive migration: `reveals` arrived with server-counted reveals.
  const cols = db.query("PRAGMA table_info(cognizance)").all() as Array<{ name: string }>;
  if (cols.length && !cols.some((col) => col.name === "reveals")) {
    db.query("ALTER TABLE cognizance ADD COLUMN reveals INTEGER NOT NULL DEFAULT 0").run();
  }

  const gateById = (id: string) => GATES.find((g) => g.id === id);

  app.get("/cognizance/gates", (c) => c.json({ gates: GATES.map(servedGate) }));

  app.post("/api/cognizance/session", async (c) => {
    const ip = c.req.header("x-forwarded-for") ?? "local";
    if (sessionLimited(ip)) return c.json({ error: "rate limited" }, 429);

    let raw: unknown;
    try { raw = await c.req.json(); } catch { return c.json({ error: "invalid json" }, 400); }
    const gate = gateById(String((raw as { gateId?: unknown })?.gateId ?? ""));
    if (!gate) return c.json({ error: "unknown gate" }, 404);

    const id = newId();
    const createdAt = Date.now();
    db.query("INSERT INTO cognizance_sessions VALUES ($id, $gate_id, $created_at, $reveals, $submitted_at)").run({
      $id: id,
      $gate_id: gate.id,
      $created_at: createdAt,
      $reveals: 0,
      $submitted_at: null,
    } as unknown as Record<string, string | number>);

    return c.json(
      { sessionId: id, createdAt, expiresInMs: SESSION_TTL_MS, reveals: 0, gate: servedGate(gate) },
      201,
    );
  });

  /**
   * Reveal the redacted source. The issuer counts the reveal, not the client: a
   * reveal is recorded against the session and forfeits the top tier for every
   * recall value, however the client later reports its own counters.
   */
  app.post("/api/cognizance/session/:id/reveal", (c) => {
    const session = db.query("SELECT * FROM cognizance_sessions WHERE id = ?").get(c.req.param("id")) as SessionRow | null;
    if (!session) return c.json({ error: "unknown gate session" }, 404);
    if (session.submitted_at) return c.json({ error: "gate session already used" }, 409);
    if (Date.now() - session.created_at > SESSION_TTL_MS) return c.json({ error: "gate session expired" }, 410);
    const gate = gateById(session.gate_id);
    if (!gate) return c.json({ error: "unknown gate" }, 404);

    db.query("UPDATE cognizance_sessions SET reveals = reveals + 1 WHERE id = ?").run(session.id);
    return c.json({
      reveals: session.reveals + 1,
      statement: gate.statement,
      consequence: gate.consequence,
      note: "Reveal recorded by the issuer. A receipt can still be issued, but not at the top tier.",
    });
  });

  app.post("/api/cognizance", async (c) => {
    const ip = c.req.header("x-forwarded-for") ?? "local";
    if (limited(ip)) return c.json({ error: "rate limited" }, 429);

    let raw: unknown;
    try { raw = await c.req.json(); } catch { return c.json({ error: "invalid json" }, 400); }
    const gateId = String((raw as { gateId?: unknown })?.gateId ?? "");
    const gate = gateById(gateId);
    if (!gate) return c.json({ error: "unknown gate" }, 404);

    const req = parseRequest(raw, gate);
    if (!req) return c.json({ error: "invalid cognizance request" }, 400);

    const sessionId = String((raw as { sessionId?: unknown })?.sessionId ?? "");
    const session = sessionId
      ? (db.query("SELECT * FROM cognizance_sessions WHERE id = ?").get(sessionId) as SessionRow | null)
      : null;
    if (!session) return c.json({ error: "unknown or missing gate session" }, 400);
    if (session.gate_id !== gate.id) return c.json({ error: "gate session belongs to a different gate" }, 400);
    if (session.submitted_at) return c.json({ error: "gate session already used" }, 409);
    if (Date.now() - session.created_at > SESSION_TTL_MS) return c.json({ error: "gate session expired" }, 410);

    const assessment = assess(gate, req, session.reveals);
    if (!assessment.accepted) {
      return c.json({ error: "gate not satisfied", reason: assessment.rejectedReason, assessment }, 422);
    }

    const alias = String(req.alias ?? "").trim().slice(0, 40);
    const issuedAt = Date.now();
    const rowBase: Omit<CognizanceRow, "signature"> = {
      id: newId(),
      issued_at: issuedAt,
      gate_id: gate.id,
      gate_hash: gateHash(gate),
      tier: assessment.tier,
      alias,
      produced_chars: assessment.residue.produced,
      governed_chars: assessment.residue.governed,
      inserted_chars: assessment.residue.inserted,
      backspaces: assessment.fields.reduce((n, f) => n + f.backspaces, 0),
      median_iki_ms: assessment.timing.medianIkiMs,
      duration_ms: assessment.fields.reduce((n, f) => n + f.durationMs, 0),
      reveals: session.reveals,
      evidence_json: JSON.stringify({ fields: assessment.fields, flags: assessment.flags, timing: assessment.timing, tierWithheldBecause: assessment.tierWithheldBecause }),
    };
    const signature = hmac(canonicalRow(rowBase), issuedAt);
    const row: CognizanceRow = { ...rowBase, signature };
    db.query(
      `INSERT INTO cognizance VALUES ($id, $issued_at, $gate_id, $gate_hash, $tier, $alias, $produced_chars,
       $governed_chars, $inserted_chars, $backspaces, $median_iki_ms, $duration_ms, $evidence_json, $signature, $reveals)`,
    ).run(dollar(row) as Record<string, string | number>);
    db.query("UPDATE cognizance_sessions SET submitted_at = ? WHERE id = ?").run(issuedAt, session.id);

    const credential = receiptCredential(row, gate, assessment, base, issuerId);
    const verifyUrl = `${base}/cognizance/r/${row.id}`;
    return c.json(
      {
        id: row.id,
        issuedAt,
        tier: row.tier,
        tierLabel: assessment.tierLabel,
        tierWithheldBecause: assessment.tierWithheldBecause,
        residue: assessment.residue,
        reveals: session.reveals,
        signature,
        verifyPath: `/cognizance/r/${row.id}`,
        verifyUrl,
        credential,
        vcJwt: vcJwt(credential, verifyUrl, issuedAt),
      },
      201,
    );
  });

  app.get("/api/cognizance/:id", (c) => {
    const row = db.query("SELECT * FROM cognizance WHERE id = ?").get(c.req.param("id")) as CognizanceRow | null;
    if (!row) return c.json({ error: "not found" }, 404);
    const { signature: _stored, ...payload } = row;
    const recalc = hmac(canonicalRow(payload), row.issued_at);
    const a = Buffer.from(recalc);
    const b = Buffer.from(row.signature);
    const valid = a.length === b.length && a.toString("hex") === b.toString("hex");
    const expired = Date.now() > row.issued_at + 86_400_000 * TTL_DAYS;
    return c.json({ receipt: row, signatureValid: valid, expired, verifyUrl: `${base}/cognizance/r/${row.id}` });
  });

  app.get("/cognizance/limits", (c) => c.html(limitsPage(base)));

  app.get("/cognizance/r/:id", async (c) => {
    const id = c.req.param("id");
    const row = db.query("SELECT * FROM cognizance WHERE id = ?").get(id) as CognizanceRow | null;
    if (!row) return c.html("<!doctype html><title>Cognizance receipt</title><p>Receipt not found.</p>", 404);
    const { signature: _stored, ...payload } = row;
    const recalc = hmac(canonicalRow(payload), row.issued_at);
    const a = Buffer.from(recalc);
    const b = Buffer.from(row.signature);
    const valid = a.length === b.length && a.toString("hex") === b.toString("hex");
    const gate = gateById(row.gate_id);
    const evidence = JSON.parse(row.evidence_json) as {
      fields: FieldAssessment[];
      flags: string[];
      timing: { samples: number; medianIkiMs: number; irregularity: number | null; hesitations: number };
      tierWithheldBecause: string | null;
    };
    const verifyUrl = `${base}/cognizance/r/${id}`;
    const qrSvg = valid ? await QRCode.toString(verifyUrl, { type: "svg", margin: 0, width: 148 }) : "";
    const issuedAt = new Date(row.issued_at).toISOString().slice(0, 16).replace("T", " ");
    const validUntil = new Date(row.issued_at + 86_400_000 * TTL_DAYS).toISOString().slice(0, 10);
    const credential = receiptCredential(row, gate ?? null, assessmentFromRow(row, evidence), base, issuerId);
    const jwt = valid ? vcJwt(credential, verifyUrl, row.issued_at) : null;
    const jwtHref = jwt ? `data:text/plain;charset=utf-8,${encodeURIComponent(jwt)}` : "#";

    const fieldRows = evidence.fields
      .map(
        (f) => `<tr>
      <td>${esc(f.label)}<div class="sub">${f.mode === "recall" ? "typed from memory, source hidden" : "typed from the displayed text"}</div></td>
      <td>${f.charsProduced} / ${f.governedChars} typed from ${f.keydowns} keystrokes<br><span class="sub">${f.insertedChars} inserted · ${f.backspaces} corrected · ${f.peeks} reveal${f.peeks === 1 ? "" : "s"}</span></td>
      <td>${f.medianIkiMs} ms<br><span class="sub">median gap between keys</span></td>
    </tr>`,
      )
      .join("");

    return c.html(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kalappai cognizance receipt ${esc(id)}</title>
<style>
  body{font-family:system-ui,sans-serif;background:#12100c;color:#f2e8d5;margin:0;padding:2rem 1rem}
  main{max-width:640px;margin:0 auto;background:rgba(32,28,22,.72);border:1px solid rgba(232,163,61,.18);border-radius:14px;padding:1.6rem}
  h1{font-size:1.15rem;margin:0 0 .2rem;color:#e8a33d}
  h2{font-size:.9rem;margin:1.4rem 0 .4rem;color:#e8a33d;text-transform:uppercase;letter-spacing:.04em}
  table{width:100%;border-collapse:collapse;margin-top:.4rem}
  td{padding:.5rem 0;border-bottom:1px solid rgba(232,163,61,.12);font-size:.9rem;vertical-align:top}
  td:first-child{color:#cbbfa6;width:46%}
  .sub{color:#a09480;font-size:.75rem}
  .ok{color:#7fb069;font-weight:600}.bad{color:#e2705f;font-weight:600}
  .tier{display:inline-block;border:1px solid rgba(232,163,61,.5);border-radius:999px;padding:.15rem .7rem;color:#e8a33d;font-size:.85rem;margin-right:.4rem}
  .note{font-size:.78rem;color:#a09480;margin-top:1rem;line-height:1.5}
  .note a{color:#e8a33d}
  .qr{background:#fff;padding:.6rem;border-radius:8px;display:inline-block;margin-top:1rem}
  .actions{margin-top:1.1rem;display:flex;gap:.6rem;flex-wrap:wrap}
  .actions button,.actions a{font:inherit;font-size:.85rem;padding:.45rem .8rem;border-radius:8px;border:1px solid rgba(232,163,61,.4);color:#e8a33d;background:none;text-decoration:none}
  .actions button{cursor:pointer}
  @media print{body{background:#fff;color:#111;padding:0}main{max-width:none;border:1px solid #999;background:#fff;border-radius:0}
    .qr{border:1px solid #ccc}.noprint{display:none !important}h1,h2{color:#8a5a10}td,td:first-child{color:#111;border-bottom-color:#bbb}.sub,.note{color:#555}.tier{border-color:#999;color:#333}.ok{color:#1d5a12}.bad{color:#8f1f10}}
</style></head><body><main>
<h1>கவனிப்பு · Kalappai cognizance receipt</h1>
<div class="sub">id <code>${esc(id)}</code></div>
<p class="${valid ? "ok" : "bad"}">${valid ? "✔ Signature valid — this record has not been altered." : "✘ Signature INVALID — do not trust this record."}</p>
<p><span class="tier">${esc(row.tier)} · ${esc(TIER_LABELS[row.tier as Tier] ?? row.tier)}</span>
<span class="sub">${esc(TIER_MEANING[row.tier as Tier] ?? "")}</span></p>
${evidence.tierWithheldBecause ? `<p class="sub">Next tier withheld because ${esc(evidence.tierWithheldBecause)}.</p>` : ""}
<h2>What was governed</h2>
<table>
<tr><td>Gate</td><td>${esc(gate?.title ?? row.gate_id)}<div class="sub">gate definition sha256 ${esc(row.gate_hash.slice(0, 16))}…</div></td></tr>
<tr><td>Consequence</td><td>${esc(gate?.consequence ?? "")}</td></tr>
</table>
<h2>What was produced</h2>
<table>${fieldRows}
<tr><td>Total</td><td>${row.produced_chars} characters produced by keystroke for ${row.governed_chars} governed${row.produced_chars > row.governed_chars ? ` (${row.produced_chars - row.governed_chars} corrected and retyped)` : ""}<div class="sub">${row.inserted_chars} inserted · ${row.backspaces} corrections · rhythm ${evidence.timing.samples} intervals, median ${row.median_iki_ms} ms, irregularity ${evidence.timing.irregularity ?? "n/a"}</div></td></tr>
<tr><td>Observed</td><td>${evidence.flags.length ? evidence.flags.map((f) => esc(f)).join(" · ") : "no distinguishing behaviour"}</td></tr>
<tr><td>Source reveals</td><td>${row.reveals === 0 ? "none — the redacted source was never revealed for this attempt" : `${row.reveals} — the issuer recorded the redacted source being revealed`}</td></tr>
<tr><td>Issued</td><td>${esc(issuedAt)} UTC · expires ${esc(validUntil)}</td></tr>
</table>
<p class="note"><strong>What this does not prove.</strong> It records that these characters were produced at this device at this time, and that nothing was pasted, dropped or filled. It does not prove that the text was understood, that the typist is the account holder, or that the client was unmodified — a determined user can fabricate every figure above.
<a href="${esc(base)}/cognizance/limits">Full limits and thresholds →</a></p>
<p class="note">Receipt holder: ${esc(row.alias || "unnamed — no identity is required to obtain or verify this receipt")}. Nothing here is signed by, or represents, the relying party's system of record; the relying party must also keep its own transaction record.</p>
<div class="qr" title="Scan to verify">${qrSvg}</div>
<div class="actions noprint">
  <button onclick="window.print()">Print / keep a copy</button>
  <a href="${jwtHref}" download="kalappai-cognizance-${esc(id)}.vcjwt.txt">Download credential (VC-JWT)</a>
  <a href="${esc(base)}/cognizance">Try the gate</a>
</div>
</main></body></html>`);
  });

  app.get("/cognizance", (c) => {
    const gate = gateById(c.req.query("gate") ?? "") ?? GATES[0]!;
    return c.html(demoPage(gate, base));
  });

}

/**
 * Rebuilds the issue-time assessment from the stored evidence, so a credential
 * re-downloaded from the verify page is byte-identical to the one issued.
 */
function assessmentFromRow(
  row: CognizanceRow,
  evidence: {
    fields: FieldAssessment[];
    flags: string[];
    timing: { samples: number; medianIkiMs: number; irregularity: number | null; hesitations: number };
    tierWithheldBecause: string | null;
  },
): Assessment {
  const fields = Array.isArray(evidence.fields) ? evidence.fields : [];
  const sum = (pick: (f: FieldAssessment) => number): number =>
    fields.length ? fields.reduce((n, f) => n + pick(f), 0) : 0;
  return {
    accepted: true,
    rejectedReason: null,
    tier: row.tier as Tier,
    tierLabel: TIER_LABELS[row.tier as Tier] ?? row.tier,
    tierWithheldBecause: evidence.tierWithheldBecause ?? null,
    fields,
    residue: {
      produced: fields.length ? sum((f) => f.charsProduced) : row.produced_chars,
      governed: fields.length ? sum((f) => f.governedChars) : row.governed_chars,
      inserted: fields.length ? sum((f) => f.insertedChars) : row.inserted_chars,
    },
    flags: evidence.flags ?? [],
    timing: evidence.timing,
  };
}

/* ------------------------------------------------------------------ *
 * Pages
 * ------------------------------------------------------------------ */

function limitsPage(base: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kalappai cognizance gate — limits and thresholds</title>
<style>
  body{font-family:system-ui,sans-serif;background:#12100c;color:#f2e8d5;margin:0;padding:2rem 1rem;line-height:1.6}
  main{max-width:680px;margin:0 auto;background:rgba(32,28,22,.72);border:1px solid rgba(232,163,61,.18);border-radius:14px;padding:1.8rem}
  h1{font-size:1.2rem;color:#e8a33d;margin:0 0 .3rem}
  h2{font-size:.95rem;color:#e8a33d;margin:1.6rem 0 .4rem}
  code{background:rgba(232,163,61,.1);padding:.1rem .3rem;border-radius:4px;font-size:.85em}
  ul{padding-left:1.2rem}li{margin:.35rem 0;font-size:.92rem}
  .lede{color:#cbbfa6;font-size:.95rem}
  a{color:#e8a33d}
  table{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.88rem}
  td{padding:.35rem 0;border-bottom:1px solid rgba(232,163,61,.12)}
  td:first-child{color:#cbbfa6;width:52%}
</style></head><body><main>
<h1>What a cognizance receipt is, and what it is not</h1>
<p class="lede">This is a friction layer with a receipt. It is not bot detection, not authentication, and not legal
proof of consent. It exists so that the costly path to a submission is the attentive one, and so that the person
who typed has something of their own to keep.</p>

<h2>What a receipt does assert</h2>
<ul>
  <li>Every governed character was produced by keystroke on the client that submitted it.</li>
  <li>Each produced character had a keystroke behind it: text that arrives with no preceding keydown — dictation,
  an agent driving the browser, a remote-desktop paste — is counted as insertion and refused, whatever its
  <code>inputType</code> claims.</li>
  <li>No paste, drop, autofill or programmatic insertion event was reported for those fields.</li>
  <li>The produced value hashed to the same SHA-256 as the relying party's gate definition.</li>
  <li>Where a tier above <code>T0</code> is claimed: the pooled typing rhythm was not machine-regular, no field was pre-filled within ${RULES.minFirstKeystrokeMs} ms of focus, and held-key repetition stayed under ${Math.round(RULES.maxRepeatRatio * 100)}% of characters.</li>
</ul>

<h2>What it does not assert</h2>
<ul>
  <li><strong>Comprehension.</strong> Typing a value is not reading it. A user can produce every character while looking away.</li>
  <li><strong>Identity.</strong> It says a human-like typist, on this client, produced the text — not that the typist is the account holder.</li>
  <li><strong>Client integrity.</strong> Telemetry is reported by the browser. A determined user can fabricate all of it, including the raw inter-keystroke samples. Treat a receipt as one weighted signal, never as a sole basis for denying a dispute.</li>
  <li><strong>Completeness of the display.</strong> The gate asserts the governed values were produced; it cannot prove the rest of the statement was rendered legibly, in the user's language, or on screen at all.</li>
</ul>

<h2>Known false negatives</h2>
<ul>
  <li>Very fast typists can have a median inter-keystroke interval below ${RULES.minMedianIkiMs} ms and will be held at <code>T0</code>.</li>
  <li>Dictation, switch access, password managers and assistive autofill are <em>rejected by design</em>. A deployment that offers no alternate route to the same receipt type is excluding disabled users, and is doing so with a mechanism that SSC-style typing-test rules already provide exemptions for.</li>
  <li>Short governed values yield too few keystroke intervals to judge timing; the receipt says so rather than inventing a tier.</li>
  <li>Input that arrives with no keydown at all is refused even when it is legitimate: dictation, switch access,
  remote desktop, password managers and some composition/IME paths. Those users need the alternate route, and
  Tamil input methods that map keys directly (Tamil99, InScript) are unaffected. A composition event can also be
  synthesised, so a keystroke that arms one is weak evidence in itself.</li>
  <li>An autofill that fires no input event at all is caught by the coverage check (fewer characters produced than governed), not by insertion counting.</li>
</ul>

<h2>Obligations on the deployment</h2>
<ul>
  <li>Show the person the receipt <em>before</em> the submission is final, and let them keep it. A receipt generated silently for the vendor becomes surveillance, and one-sided evidence in a dispute becomes a compliance weapon.</li>
  <li>Publish the gate definition hash and the thresholds in force. They are chosen, not validated on a population; a deployment that will not publish them should not be trusted with the claim.</li>
  <li>Offer a non-typing route to the same receipt type, and say so in the interface.</li>
  <li>Never store the governed values. This service compares SHA-256 digests and stores no field content.</li>
</ul>

<h2>Thresholds in force at this issuer</h2>
<table>
<tr><td>Median inter-keystroke interval floor</td><td>${RULES.minMedianIkiMs} ms</td></tr>
<tr><td>Regularity ceiling (share of intervals within ±10% of the median)</td><td>${RULES.maxIrregularity}</td></tr>
<tr><td>Minimum focus-to-first-keystroke</td><td>${RULES.minFirstKeystrokeMs} ms</td></tr>
<tr><td>Hesitation threshold</td><td>${RULES.hesitationMs} ms</td></tr>
<tr><td>Held-key repeat ceiling</td><td>${Math.round(RULES.maxRepeatRatio * 100)}% of produced characters</td></tr>
<tr><td>Minimum pooled intervals before timing is judged</td><td>${RULES.minSamplesInPool}</td></tr>
</table>
<p class="lede" style="margin-top:1.4rem"><a href="${esc(base)}/cognizance">← Back to the gate</a></p>
</main></body></html>`;
}

function demoPage(gate: Gate, base: string): string {
  const gateOptions = GATES.map(
    (g) => `<option value="${esc(g.id)}"${g.id === gate.id ? " selected" : ""}>${esc(g.title)}</option>`,
  ).join("");

  const fields = gate.fields
    .map(
      (f) => `<div class="field" data-field="${esc(f.id)}" data-recall="${f.mode === "recall" ? "1" : "0"}">
  <label for="in-${esc(f.id)}">${esc(f.label)}</label>
  <input id="in-${esc(f.id)}" data-input="${esc(f.id)}" autocomplete="off" autocapitalize="off" spellcheck="false" inputmode="text" placeholder="${f.mode === "recall" ? "from memory" : "type it"}">
  <div class="hint">${esc(f.hint ?? "")}</div>
  <div class="tm" id="tm-${esc(f.id)}"></div>
</div>`,
    )
    .join("");

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kalappai cognizance gate — ${esc(gate.title)}</title>
<style>
  body{font-family:system-ui,sans-serif;background:#12100c;color:#f2e8d5;margin:0;padding:2rem 1rem;line-height:1.55}
  main{max-width:720px;margin:0 auto}
  h1{font-size:1.25rem;color:#e8a33d;margin:0 0 .2rem}
  .lede{color:#a09480;font-size:.85rem;margin:0 0 1.2rem}
  .card{background:rgba(32,28,22,.72);border:1px solid rgba(232,163,61,.18);border-radius:14px;padding:1.4rem;margin-bottom:1rem}
  select{font:inherit;font-size:.9rem;background:#1b1813;color:#f2e8d5;border:1px solid rgba(232,163,61,.3);border-radius:8px;padding:.4rem .5rem;width:100%}
  .ctx{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:#a09480;margin-top:1rem}
  .stmt{font-size:1.02rem;color:#f2e8d5}
  .stmt.masked{filter:blur(5px);user-select:none}
  .maskwarn{color:#e8a33d;font-size:.8rem;margin-top:.5rem}
  .consequence{margin-top:.9rem;padding:.7rem .9rem;border-left:2px solid #e8a33d;background:rgba(232,163,61,.07);font-size:.92rem}
  label{display:block;font-size:.85rem;color:#cbbfa6;margin-bottom:.35rem}
  input{width:100%;font:inherit;font-size:1rem;background:#1b1813;color:#f2e8d5;border:1px solid rgba(232,163,61,.3);border-radius:8px;padding:.55rem .7rem}
  input.bad{border-color:#e2705f}
  .hint{font-size:.74rem;color:#a09480;margin-top:.3rem}
  .tm{font-size:.74rem;color:#7fb069;margin-top:.3rem;font-variant-numeric:tabular-nums}
  .field{margin-bottom:1rem}
  button{font:inherit;font-size:.9rem;padding:.5rem .9rem;border-radius:8px;border:1px solid rgba(232,163,61,.4);background:none;color:#e8a33d;cursor:pointer}
  button.primary{background:#e8a33d;color:#1b1813;border-color:#e8a33d;font-weight:600}
  .row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
  h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:#a09480;margin:1.2rem 0 .5rem}
  pre{background:#1b1813;border:1px solid rgba(232,163,61,.15);border-radius:8px;padding:.8rem;font-size:.74rem;overflow:auto;color:#cbbfa6;max-height:260px}
  .res{font-size:.88rem;padding:.7rem .9rem;border-radius:8px;margin-top:.8rem}
  .res.ok{background:rgba(127,176,105,.12);border:1px solid rgba(127,176,105,.4);color:#bfe0a8}
  .res.bad{background:rgba(226,112,95,.1);border:1px solid rgba(226,112,95,.4);color:#f0b3a8}
  a{color:#e8a33d}
  .small{font-size:.78rem;color:#a09480}
  ul.notes{padding-left:1.1rem;margin:.4rem 0}
  ul.notes li{font-size:.8rem;color:#a09480;margin:.25rem 0}
</style></head><body><main>
<h1>கவனிப்பு · Cognizance gate</h1>
<p class="lede">Type the consequence, not the corpus. Nothing you type is stored — only a SHA-256 of the value,
compared here against the gate definition. <a href="${esc(base)}/cognizance/limits">What this proves and does not prove →</a></p>

<div class="card">
  <select id="gatesel" onchange="location.search='?gate='+this.value">${gateOptions}</select>
  <div class="ctx">${esc(gate.context)}</div>
  <div id="stmt" class="stmt">${esc(redact(gate.statement, gate))}</div>
  <div id="maskwarn" class="maskwarn" style="display:none">The consequential values above are redacted.
    <button id="peek" type="button">Reveal for 6 seconds</button>
    <div id="revealcount" class="sub"></div></div>
  <div class="consequence" id="consequence">Consequence: ${esc(redact(gate.consequence, gate))}</div>
</div>

<div class="card">
  <form id="form" autocomplete="off">
    ${fields}
    <div class="row">
      <button class="primary" type="submit">Submit and get my receipt</button>
      <button type="button" id="autofill">Simulate autofill / agent fill</button>
      <button type="button" id="trypaste">Simulate paste</button>
    </div>
  </form>
  <div id="result"></div>
</div>

<div class="card">
  <h2>What will be sent (no values, only digests and counters)</h2>
  <pre id="preview">{} </pre>
  <h2>How it behaves at the edges</h2>
  <ul class="notes">
    <li>Paste and drop are blocked and recorded as an attempt — the gate will not issue a receipt.</li>
    <li>Autofill and dictation arrive as inserted characters, not keystrokes: rejected.</li>
    <li>Typing has to be irregular enough to be human. Scripted, evenly-spaced entry is held at the lowest tier and the receipt says why.</li>
    <li>Values typed in recall mode with the source revealed cannot claim the top tier; the attempt is still receipted honestly.</li>
    <li>Type slowly. Deliberate input is the point; there is no speed score here.</li>
  </ul>
</div>
</main>
<script>
(function(){
  var GATE_ID = ${JSON.stringify(gate.id)};
  // Same-origin deployments (the real case) call relative paths; a page served
  // from anywhere else — local testing, a copy on another host — calls BASE.
  var API = (function(){ try { return new URL(${JSON.stringify(base)}).origin === location.origin ? '' : ${JSON.stringify(base)}; } catch (e) { return ''; } })();
  var FIELD_IDS = ${JSON.stringify(gate.fields.map((f) => f.id))};
  var FIELD_LEN = ${JSON.stringify(gate.fields.map((f) => f.value.length))};
  var S = {};
  var lastLen = {};
  var REDACTED = ${JSON.stringify(redact(gate.statement, gate))};
  var CONSEQ = ${JSON.stringify(redact(gate.consequence, gate))};
  var HAVE_RECALL = ${gate.fields.some((f) => f.mode === "recall") ? "true" : "false"};
  var sess = null, revealCount = 0;
  // Recall values are never rendered, so the autofill demo inserts blanks for them:
  // the point is that characters arrive without keystrokes, not which characters.
  var AUTOFILL = ${JSON.stringify(gate.fields.map((f) => (f.mode === "recall" ? "\u25ae\u25ae\u25ae\u25ae\u25ae\u25ae" : f.value)))};

  function st(id){
    if(!S[id]) S[id] = { produced:0, inserted:0, keydowns:0, armed:false, pastes:0, backspaces:0, repeats:0, peeks:0, samples:[], last:null, t0:null, first:null };
    return S[id];
  }
  function hex8(n){ return n.toString(16).padStart(2,'0'); }
  async function sha256(v){
    var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v));
    return Array.from(new Uint8Array(buf)).map(hex8).join('');
  }
  function el(id){ return document.getElementById('in-'+id); }

  function render(){
    FIELD_IDS.forEach(function(id, i){
      var s = st(id), box = document.getElementById('tm-'+id);
      if(!box) return;
      var cov = Math.min(1, s.produced / Math.max(1, FIELD_LEN[i]));
      box.textContent = 'produced ' + s.produced + '/' + FIELD_LEN[i] +
        ' · inserted ' + s.inserted + ' · corrected ' + s.backspaces +
        ' · keystrokes ' + s.keydowns + ' · reveals ' + s.peeks + ' · intervals ' + s.samples.length + (s.samples.length ? ' (median ' + med(s.samples) + ' ms)' : '');
      box.style.color = (cov >= 1 && s.inserted === 0 && s.pastes === 0) ? '#7fb069' : '#e8a33d';
    });
    preview();
  }
  function med(xs){ var s = xs.slice().sort(function(a,b){return a-b}); var m = Math.floor(s.length/2); return s.length % 2 ? s[m] : Math.round((s[m-1]+s[m])/2); }

  function payloadFor(){
    return { gateId: GATE_ID, fields: FIELD_IDS.map(function(id){
      var s = st(id);
      return { fieldId: id, charsProduced: s.produced, insertedChars: s.inserted, keydowns: s.keydowns, pasteAttempts: s.pastes,
        backspaces: s.backspaces, repeats: s.repeats, peeks: s.peeks,
        firstKeystrokeMs: (s.first !== null && s.t0 !== null) ? Math.round(s.first - s.t0) : null,
        durationMs: s.t0 !== null ? Math.round(performance.now() - s.t0) : 0,
        valueSha256: s.digest || '', samples: s.samples.slice(0, 60) };
    })};
  }
  async function preview(){
    var p = payloadFor();
    for (var i = 0; i < p.fields.length; i++){
      var v = el(p.fields[i].fieldId);
      p.fields[i].valueSha256 = v && v.value ? await sha256(v.value) : '(nothing typed)';
    }
    document.getElementById('preview').textContent = JSON.stringify(p, null, 1);
  }
  function show(kind, html){ var r = document.getElementById('result'); r.className = 'res ' + kind; r.innerHTML = html; }

  function setRevealNote(){
    if (revealCount === 0) return;
    document.getElementById('revealcount').textContent =
      'Source revealed ' + revealCount + ' time' + (revealCount === 1 ? '' : 's') +
      ' — counted by the issuer. The top tier is no longer available for this attempt.';
  }
  async function ensureSession(){
    if (sess) return sess;
    try {
      var r = await fetch(API + '/api/cognizance/session', { method:'POST', headers:{ 'content-type':'application/json', accept:'application/json' }, body: JSON.stringify({ gateId: GATE_ID }) });
      var j = await r.json();
      if (r.status === 201){ sess = j.sessionId; revealCount = j.reveals || 0; return sess; }
      show('bad', 'Could not open a gate session: ' + (j.error || r.status));
    } catch (err){ show('bad', 'Could not open a gate session: ' + err); }
    return null;
  }

  FIELD_IDS.forEach(function(id, i){
    var input = el(id), s = st(id), recall = input.closest('.field').dataset.recall === '1';

    input.addEventListener('focus', function(){
      s.t0 = performance.now(); s.last = null; s.first = null;
      ensureSession();
    });

    input.addEventListener('keydown', function(e){
      var now = performance.now();
      if (e.key === 'Backspace') s.backspaces++;
      if (e.repeat) s.repeats++;
      if (e.key && e.key.length === 1 && !e.repeat){
        if (s.first === null) s.first = now;
        s.keydowns++;
        s.armed = true;
        if (s.last !== null){ s.samples.push(Math.round(now - s.last)); if (s.samples.length > 200) s.samples.shift(); }
        s.last = now;
      }
      render();
    });

    input.addEventListener('input', function(e){
      var it = e.inputType || '';
      var grew = Math.max(0, input.value.length - (lastLen[id] === undefined ? 0 : lastLen[id]));
      var added = typeof e.data === 'string' && e.data.length ? e.data.length : grew;
      if (it === 'insertFromPaste' || it === 'insertFromDrop' || it === 'insertFromYank' || it === 'insertReplacementText' || it === 'insertFromPasteAsQuotation'){
        s.inserted += added;
      } else if (s.armed){
        s.produced += added;
        s.armed = false;
      } else {
        s.inserted += added;
      }
      lastLen[id] = input.value.length;
      render();
    });

    input.addEventListener('paste', function(e){
      e.preventDefault();
      s.pastes++;
      show('bad', 'Paste is blocked at this gate. Paste events are recorded, and a receipt will not be issued for a pasted value.');
      render();
    });
    input.addEventListener('drop', function(e){ e.preventDefault(); s.pastes++; render(); });

    if (recall){
      // The value is not in this page until a reveal is asked for, and the
      // issuer counts reveals. These are the client's own, weaker, observations.
      window.addEventListener('blur', function(){ if (document.activeElement === input){ s.peeks++; render(); } });
      document.addEventListener('visibilitychange', function(){ if (document.hidden && document.activeElement === input){ s.peeks++; render(); } });
    }
  });

  var peekBtn = document.getElementById('peek');
  if (peekBtn) peekBtn.addEventListener('click', async function(){
    if (!HAVE_RECALL) return;
    var id = await ensureSession();
    if (!id) return;
    try {
      var r = await fetch(API + '/api/cognizance/session/' + id + '/reveal', { method:'POST', headers:{ accept:'application/json' } });
      var j = await r.json();
      if (r.status !== 200){ show('bad', 'Could not reveal: ' + (j.error || r.status)); return; }
      revealCount = j.reveals;
      var stmt = document.getElementById('stmt');
      stmt.textContent = j.statement;
      document.getElementById('consequence').textContent = 'Consequence: ' + j.consequence;
      document.getElementById('maskwarn').style.display = 'block';
      setRevealNote();
      setTimeout(function(){
        stmt.textContent = REDACTED;
        document.getElementById('consequence').textContent = 'Consequence: ' + CONSEQ;
      }, 6000);
      render();
    } catch (err){ show('bad', 'Could not reveal: ' + err); }
  });

  document.getElementById('autofill').addEventListener('click', function(){
    FIELD_IDS.forEach(function(id, i){
      var input = el(id);
      if (input.value) return;
      input.value = AUTOFILL[i];
      input.dispatchEvent(new InputEvent('input', { inputType: 'insertText', data: null, bubbles: true }));
      input.classList.add('bad');
    });
    show('bad', 'Simulated agent fill: text arrived with no keystroke behind it (inputType insertText, which is what CDP, autofill and dictation produce). The keystroke check catches this and the gate refuses a receipt.');
    render();
  });

  document.getElementById('trypaste').addEventListener('click', function(){
    var input = el(FIELD_IDS[0]);
    input.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true }));
    render();
  });

  document.getElementById('form').addEventListener('submit', async function(e){
    e.preventDefault();
    var p = payloadFor();
    for (var i = 0; i < p.fields.length; i++){
      var v = el(p.fields[i].fieldId);
      p.fields[i].valueSha256 = await sha256(v ? v.value : '');
    }
    p.alias = '';
    p.sessionId = sess || await ensureSession();
    if (!p.sessionId){ show('bad', 'No gate session could be opened — try again.'); return; }
    show('ok', 'Submitting…');
    try {
      var r = await fetch(API + '/api/cognizance', { method:'POST', headers:{ 'content-type':'application/json', accept:'application/json' }, body: JSON.stringify(p) });
      var j = await r.json();
      if (r.status === 201){
        show('ok', '<strong>Receipt ' + j.id + ' · ' + j.tier + ' ' + j.tierLabel + '</strong><br>' +
          j.residue.produced + ' of ' + j.residue.governed + ' governed characters produced by keystroke.<br>' +
          (j.tierWithheldBecause ? 'Next tier withheld: ' + j.tierWithheldBecause + '.<br>' : '') +
          '<a href="' + j.verifyPath + '">Open, print and keep the receipt →</a>');
      } else {
        show('bad', '<strong>No receipt: ' + (j.reason || j.error) + '</strong>' +
          (j.assessment && j.assessment.fields ? '<br>produced ' + j.assessment.residue.produced + '/' + j.assessment.residue.governed + ' governed characters, ' + j.assessment.residue.inserted + ' inserted.' : ''));
      }
    } catch (err) {
      show('bad', 'Could not reach the issuer: ' + err);
    }
  });

  render();
})();
</script>
</body></html>`;
}
