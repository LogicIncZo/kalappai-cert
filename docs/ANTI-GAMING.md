# What a Kalappai certificate proves — and how it could be gamed

This service signs a claim. This document is about the gap between the claim a
reader thinks a certificate makes and the claim it actually makes, and what it
would cost to narrow that gap.

Written against the code as it stands (`src/index.ts`, `src/contract.ts`), not
against an intention. Every "closed" line below is enforced by the gate in
`scripts/verify.sh` or by `test/contract.test.ts`.

## 1. What is actually asserted

Issuing binds four things together:

- the **layout** (`layoutId`) and the **passage** (`passageId` + `targetHash`, the
  SHA-256 of the exact text typed),
- a set of **self-reported metrics** (`stats`),
- the **pass rules** the server re-evaluated itself,
- the **alias** the learner typed.

The signature makes the record tamper-evident *after* issuance and the Ed25519
VC makes it verifiable offline. Neither says anything about whether the metrics
were really produced by a person at a keyboard. The verification page says
"practice record, not a government qualification" for exactly this reason.

## 2. The gaming surface, enumerated

| # | Attack | Cost to attacker | Blocked today? |
| --- | --- | --- | --- |
| G1 | `curl` a perfect score with someone else's name | one HTTP request | **No** |
| G2 | Omit a field to skip a rule (e.g. no `chars` → skip the 120-char floor) | trivial | **Yes** — every declared field is required; rules run on server-parsed values |
| G3 | Self-contradictory report (`net > gross`, 100 % accuracy with errors>0, errors>strokes) | trivial | **Yes** — declared stat invariants, refused as a malformed report |
| G4 | Issue in bulk | trivial | **Partly** — `RATE_LIMIT` (12 issues / 5 min per `x-forwarded-for`) |
| G5 | Edit a row in the SQLite DB after issuance | filesystem access | **Yes** — HMAC over the canonical record; `recordSelfConsistent` goes false |
| G6 | Forge a VC | Ed25519 key theft | **Yes** — signature verifies only against the published JWKS |
| G7 | Replay someone else's certificate as your own | trivial | **No** — the alias is free text with no identity binding (by design: no accounts) |
| G8 | Automate the *client* (drive the browser/JS) | moderate | **No** |
| G9 | Synthesise a plausible keystroke stream | moderate | **No** — see §5 |

So today the certificate is an **honest self-report with tamper-evident
afterlife**. That is a real property, worth having, and much weaker than "we
verified a human typed this at this speed".

Attack G1 is the one that matters. Everything in §4 is about raising it from
"one curl" to "a script that also fabricates a timing stream", and about making
the difference *visible to a verifier* rather than pretending it does not exist.

## 3. Why the metrics cannot be trusted as sent

`stats` arrives from a browser the learner controls. The server bounds them
(`num(stats.grossWpm, 0, 200)` …) and cross-checks them against each other, which
catches sloppy fabrication — but a careful fabricator simply sends numbers that
satisfy every invariant and every pass rule.

Any real fix has to derive the metrics from evidence the server can recompute,
not from numbers the client asserts.

## 4. Attestation: deriving the numbers from keystrokes

The same machinery already exists in this codebase for a different purpose. The
**cognizance gate** (`src/cognizance.ts`) accepts raw inter-keystroke intervals
and counters, and decides *server-side*: coverage (every governed character came
from a keystroke), regularity (median interval and MAD), hesitation and
self-correction, with the issuer counting reveals. Nothing is trusted from the
client.

A certificate could be issued the same way: the client sends the keystroke
stream for the exam attempt, and the server derives `strokes`, `errors`,
`elapsedMs` and therefore `grossWpm`/`netWpm`/`accuracy`/`kdph` itself.

### What it costs — measured

Benchmarked on this machine (`/tmp` benchmark against a spawned instance of this
service; cognizance gate `upi-autopay-mandate`, 2 governed fields, 22 intervals):

| Cost | Measured |
| --- | --- |
| `assess()` — full server-side assessment of one receipt | **p50 7 µs, p95 23 µs** |
| Stream summary (sort + median + mean + MAD + p90), 240 intervals | p50 22 µs — **0.09 µs/keystroke** |
| Same, 500 intervals (≈ one 60 s exam) | p50 49 µs — **0.10 µs/keystroke** |
| Same, 2400 intervals (≈ a 5-minute passage) | p50 296 µs — **0.12 µs/keystroke** |
| `POST /api/cognizance` end to end, incl. SQLite write | **p50 1.74 ms, p95 2.07 ms** |
| Payload size | 692 B for 22 intervals → **≈ 31 B/interval** (500 ≈ 16 KB, 2400 ≈ 76 KB) |

**Conclusion: the server side is not the constraint.** Assessment is linear in
keystrokes at ~0.1 µs each — 500 keystrokes cost 49 µs of CPU, three orders of
magnitude below the 1.7 ms HTTP + SQLite round-trip it would ride along with. The
real costs are elsewhere:

- **Payload**: ~16 KB per attempt at exam scale. Fine on wifi, poor on a 2G
  connection — and Kalappai is aimed at learners who may not have either.
- **Storage**: one evidence blob per issued certificate instead of eight
  numbers. Still small (tens of KB), but it is now a growth rate, not a row.
- **Client capture**: a `keydown` handler appending to an array for the duration
  of the exam, then one JSON body. Negligible CPU, but it is real work on the
  main thread during typing, and it must not be allowed to interfere with the
  keystroke path the tutor depends on.
- **Honesty of the derived metrics**: the tutor already computes metrics from
  the same events, so the derivation has to be *the same function* on both
  sides or the certificate will disagree with what the learner saw.

### The limit of the idea

Attestation does not make forgery impossible, and pretending otherwise would be
the dishonest part. An attacker who can send a fabricated metric set can also
send a fabricated interval stream — plausible-looking human timing is easy to
synthesise, and the literature on keystroke-dynamics spoofing is not encouraging.

What attestation buys is **cost asymmetry and auditability**: fabricating a
score becomes *writing a keystroke simulator*, and the evidence record lets a
verifier (or an investigator, later) see the stream a certificate was based on
rather than take eight numbers on faith. Used as a *filter over a population*
rather than as a proof about an individual, that is genuinely useful.

## 5. Recommended posture

1. **Say it once, on the artifact.** The verify page and the VC's `termsOfUse`
   state the claim and its limits. Already done for cognizance; do the same for
   certificates.
2. **Close the cheap holes now.** G2 and G3 are closed. Keep them closed: the
   contract test refuses regression.
3. **Label the trust level.** A certificate should carry how its metrics were
   obtained — `self-reported` today, `keystroke-attested` once a stream is
   supplied and recomputed — and the verify page should render that label
   prominently. This is the highest-value next step: it costs one field and it
   stops the service from implying more than it knows.
4. **Then, if it earns its keep**, accept an optional stream and derive the
   metrics. Add `docs/CONTRACT.md` for the stream shape first; the field names
   must be frozen by the same artifact discipline as everything else.
5. **Do not** build identity binding to chase G7. The absence of accounts is a
   feature of the tutor and a certificate for a self-chosen alias is honest as
   long as it is described that way.
6. **Do not** claim bot detection. The cognizance gate's own limits page makes
   this point; the certificate path should not contradict it.

## 6. What would need to change for these to be *qualifications*

Nothing in this document gets Kalappai certificates to the status of a TNDTE or
TNPSC typing qualification. That would require an examining body, a proctored
environment, and a candidate identity — none of which this service has or should
pretend to have. The honest claim is narrower and more useful: *this is what
this learner's browser measured, the record has not been altered since, and you
can verify that yourself offline.*
