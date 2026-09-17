/**
 * Declared service surface — the single source of truth.
 *
 * Everything a client can rely on lives here: routes, request fields, server-side
 * pass rules, refusal codes and their exact strings, and the credential shape.
 *
 * Two artifacts are derived from this file and checked in CI:
 *
 *   1. `contract/cert-service.v1.json` — emitted by `scripts/emit-contract.ts`
 *      (`--check` fails if it drifts from this file). The PWA repo vendors that
 *      artifact and pins its SHA-256, so an accidental surface change cannot
 *      land silently in either repo.
 *   2. `test/contract.test.ts` — drives the running server from the *emitted
 *      artifact*, so the document is proven against behaviour, not just declared.
 *
 * Rule for editing: change the constant here, then run `bun run contract:emit`.
 * A surface change is a deliberate act with a diff, never a side effect.
 */

export const CONTRACT_VERSION = 1;

/* ---------------------------------------------------------------- pass rules */

/**
 * Enforced server-side on values the server itself parsed. A client cannot skip
 * a rule by omitting a field — `chars` is required for exactly that reason. (It
 * used to be optional, which let a caller bypass the 120-character floor by
 * leaving it out; see docs/ANTI-GAMING.md.)
 */
export const PASS_RULES = {
  /** minimum accuracy percentage */
  accuracyPercent: 90,
  /** minimum elapsed wall-clock time for the attempt (ms) */
  minElapsedMs: 30_000,
  /** minimum characters typed in the passage */
  minChars: 120,
} as const;

/**
 * Structural invariants of an honest typing report. A violation means the
 * numbers could not have come from a real attempt, so it is refused as a
 * malformed report (400) rather than a failed attempt (422).
 *
 * These are cheap arithmetic identities derived from the scoring model in the
 * client (`net = max(typed - errors, 0) / 5 / minutes`), not heuristics — an
 * honest client of any version cannot trip them.
 */
export const STAT_INVARIANTS = {
  /** net WPM is gross WPM with errors subtracted, so it can never exceed it */
  netNotAboveGross: true,
  /** 100% accuracy means no key was mistyped */
  perfectAccuracyImpliesNoErrors: true,
  /** every error was a keystroke, so errors can never exceed total strokes */
  errorsNotAboveStrokes: true,
} as const;

/* ---------------------------------------------------------------- rate limit */

export const RATE_LIMIT = {
  /** issues allowed per window, per client key */
  issues: 12,
  windowMs: 5 * 60 * 1000,
  /** keyed on `x-forwarded-for`, falling back to the literal "local" */
  keyHeader: "x-forwarded-for",
  refusalMessage: "rate limited",
} as const;

/* ----------------------------------------------------------------- refusals */

/** Exact `error` strings clients must be able to match on. */
export const REFUSALS = {
  invalidJson: { status: 400, error: "invalid json" },
  invalidRequest: { status: 400, error: "invalid certificate request" },
  implausibleStats: { status: 400, error: "implausible typing report" },
  failedPassRules: { status: 422, error: "attempt does not meet pass rules" },
  rateLimited: { status: 429, error: "rate limited" },
  notFound: { status: 404, error: "not found" },
} as const;

/* ---------------------------------------------------------------- issuance */

export const ISSUANCE = {
  method: "POST",
  path: "/api/certificates",
  /** top-level body fields */
  requestRequired: ["alias", "layoutId", "passageId", "targetHash"] as const,
  /** fields read from `stats` — all are required */
  statsRequired: [
    "grossWpm",
    "netWpm",
    "accuracy",
    "errors",
    "strokes",
    "kdph",
    "elapsedMs",
    "chars",
  ] as const,
  /** keys present on a 201 response */
  responseFields: ["id", "issuedAt", "signature", "verifyPath", "verifyUrl", "credential", "vcJwt"] as const,
  successStatus: 201,
  /** `targetHash` must be the lowercase hex SHA-256 of the exact passage typed */
  targetHashPattern: "^[0-9a-f]{64}$",
} as const;

/* ------------------------------------------------------------- verification */

export const VERIFICATION = {
  /** machine-readable record + `signatureValid` */
  jsonPath: "/api/certificates/:id",
  /** human page: certificate, QR back to itself, print button, VC-JWT download */
  humanPath: "/certs/:id",
  /** `?sig=` probes the record against a given HMAC (tamper probe) */
  signatureProbeParam: "sig",
  /** QR in the page encodes this page's own absolute URL */
  qrTargetsSelf: true,
} as const;

/* -------------------------------------------------------------- credential */

export const CREDENTIAL = {
  spec: "W3C Verifiable Credentials 2.0",
  proofFormat: "JWT",
  alg: "EdDSA",
  crv: "Ed25519",
  kid: "kalappai-issuer-1",
  /** Open Badges 3.0 (1EdTech) — the achievement shape clients should expect */
  badgeProfile: "Open Badges 3.0",
  types: ["VerifiableCredential", "OpenBadgeCredential"] as const,
  issuerPath: "/api/issuer",
  jwksPath: "/.well-known/jwks.json",
  /** persisted next to the DB as issuer-key.json, so old credentials keep verifying */
  issuerKeyPersisted: true,
} as const;

/* -------------------------------------------------- what a certificate claims */

/**
 * Honest scope of a certificate. Recorded here so the verify page, the README
 * and the client UI cannot drift into overclaiming, and so the trust gap is a
 * documented property of the surface rather than an accident.
 *
 * The service attests: *these numbers were submitted for this passage and the
 * attempt met the pass rules.* It does not, on its own, attest that the numbers
 * are true — they are client-reported. See docs/ANTI-GAMING.md.
 */
export const CLAIMS = {
  attested: [
    "the attempt met the server-enforced pass rules",
    "the record has not been altered since issuance (HMAC, with a configured secret)",
    "the score is bound to one passage via its SHA-256",
  ],
  notAttested: [
    "that the reported speed and accuracy were produced by a human at the keyboard",
    "that the alias belongs to the person presenting the certificate",
    "any government or examining-body qualification",
  ],
  /** server-verifiable improvement path; see docs/ANTI-GAMING.md */
  strongerEvidence: "a keystroke-evidence block, re-derived server-side (the cognizance pattern)",
} as const;

/* ----------------------------------------------------------------- routes */

export type Route = {
  method: "GET" | "POST";
  path: string;
  purpose: string;
  /** what a request with no valid input returns, used by the conformance test */
  probe: { expect: number[]; json: boolean };
};

export const ROUTES: Route[] = [
  { method: "GET", path: "/", purpose: "health + service banner", probe: { expect: [200], json: true } },
  { method: "POST", path: "/api/certificates", purpose: "issue a certificate", probe: { expect: [400], json: true } },
  { method: "GET", path: "/api/certificates/:id", purpose: "JSON verification + signatureValid", probe: { expect: [404], json: true } },
  { method: "GET", path: "/certs/:id", purpose: "human verify page (QR, print, VC-JWT)", probe: { expect: [404], json: false } },
  { method: "GET", path: "/api/issuer", purpose: "issuer metadata + public key", probe: { expect: [200], json: true } },
  { method: "GET", path: "/.well-known/jwks.json", purpose: "public key set (Ed25519)", probe: { expect: [200], json: true } },
  { method: "POST", path: "/api/cognizance/session", purpose: "open a cognizance gate session", probe: { expect: [404], json: true } },
  { method: "POST", path: "/api/cognizance/session/:id/reveal", purpose: "reveal the redacted source (issuer-counted)", probe: { expect: [404], json: true } },
  { method: "POST", path: "/api/cognizance", purpose: "submit keystroke telemetry", probe: { expect: [400, 404, 422], json: true } },
  { method: "GET", path: "/api/cognizance/:id", purpose: "receipt verification + signatureValid", probe: { expect: [404], json: true } },
  { method: "GET", path: "/cognizance/gates", purpose: "gate catalogue, recall secrets redacted", probe: { expect: [200], json: true } },
  { method: "GET", path: "/cognizance", purpose: "the demo gate, try it in a browser", probe: { expect: [200], json: false } },
  { method: "GET", path: "/cognizance/r/:id", purpose: "human receipt page", probe: { expect: [404], json: false } },
  { method: "GET", path: "/cognizance/limits", purpose: "what a receipt asserts and does not", probe: { expect: [200], json: false } },
];
