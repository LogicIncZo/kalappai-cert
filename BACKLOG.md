# Backlog

The loop's queue. Each entry states what "done" means, because a loop that cannot
tell when it is finished does not stop — it wanders.

Conventions:

- **Ready** entries are specified enough to start without asking anything.
- **Blocked** entries name the blocker.
- **Landed** entries move to `CHANGELOG.md` and are deleted from here.
- One loop iteration takes one entry. If an entry turns out to be three things,
  split it rather than half-finishing it.
- Anything that changes the declared surface is a two-repo change
  (see `CONTRIBUTING.md` → "Changing the contract").

---

## Ready

### 1. Attestation tier on certificates (`self-reported` vs `keystroke-attested`)

**Why.** Today every number in a certificate is self-reported by the client. The
server enforces plausibility (`docs/ANTI-GAMING.md`), which catches sloppy
fabrication and nothing else. A verifier reading a certificate currently cannot
tell an honest 25 WPM from a `curl` loop.

**Done when.**

- `POST /api/certificates` accepts an optional `attestation` block carrying raw
  inter-keystroke samples, the same shape the cognizance gate already consumes.
- When the attestation is present *and* passes the server-side checks, the issued
  certificate carries `trustLevel: "keystroke-attested"`; otherwise
  `trustLevel: "self-reported"`.
- The tier is inside the signed record and inside the VC, so it cannot be added
  later by hand.
- The verify page states the tier in plain language, and says what it does not mean.
- Omission never fails: an un-attested attempt still issues, marked honestly.
- `src/contract.ts` declares the field; the README documents it; the conformance
  test proves both tiers are obtainable and that a fabricated attestation is
  refused rather than silently downgraded.

**Evidence to gather first.** The cognizance gate's assessment path is already
measured at ~1.5 ms for a two-field receipt (~190 HTTP requests/s measured on a
small CI-class container, `docs/ANTI-GAMING.md`) — so reusing it is affordable at
exam volumes. Confirm with a benchmark before wiring it in.

**Note.** This is a *reduction* in attack surface, not a solution. A determined
forger will synthesise a plausible keystroke stream. The value is that the cheap
forgery stops working and honest attempts become distinguishable.

### 2. Cross-field plausibility, second pass

**Why.** The three invariants in `src/contract.ts` are the ones that are provably
safe for an honest client. There are more that are *probably* safe and need
evidence before being enforced on real users.

**Done when.** For each candidate rule (accuracy consistent with `errors`/`chars`;
`kdph` consistent with `strokes`/`elapsedMs`; `grossWpm` consistent with
`chars`/`elapsedMs`), there is a recorded measurement of the worst-case honest
deviation — from the engine's own golden corpus and from real seeded attempts — and
the rule is enforced only with a margin wider than that deviation. Rules that
cannot be validated stay out of the contract.

### 3. Non-typing route for the cognizance gate

**Why.** The gate refuses dictation, autofill and switch access *by design*
(`/cognizance/limits` says so). A deployment that only offers the typing route is
excluding the users who most need an accessible route to the same receipt.

**Done when.** A second, documented route to a receipt exists — voice with a
per-utterance timing profile, or a witnessed/relying-party-attested route — issuing
a receipt whose `termsOfUse` states which route produced it. The limits page
describes both routes and neither is presented as equivalent to the other.

### 4. `KALAPPAI_CERT_ORIGIN` fails closed in production

**Why.** `KALAPPAI_CERT_ORIGIN` defaults to `*`. That is convenient locally and
wrong in production: it lets any page on the web drive issuance from a visitor's
browser.

**Done when.** When `NODE_ENV=production` and the origin is unset, the process
refuses to start with an explicit message, or starts with a loud warning and a
documented `KALAPPAI_CERT_ALLOW_ANY_ORIGIN` opt-in. Tests cover both paths, and the
Docker/compose defaults are coherent with the new behaviour.

### 5. Deployment conformance is armed

**Why.** `scripts/smoke-live.ts` exists and is proven, but CI skips it unless the
`KALAPPAI_CERT_LIVE_URL` repository variable is set. A deployment that silently
drifts from the committed contract is the exact failure this repo was built to
prevent.

**Done when.** The variable is set on the repository, the `conformance` job runs on
`main`, and a deliberately stale deployment is shown to fail it.

---

## Blocked

### 6. CI cannot restart the Zo service on merge

**Why.** Deploy is currently manual: merge, then restart the `kalappai-cert` Zo
user service, then `bun run smoke:live`. The gate proves the commit; nothing proves
the deployment happened.

**Blocker.** Automation needs a credential that can restart a Zo user service, and
that credential does not exist yet. Do not put a Zo identity token in a public
repository's secrets until its scope is understood.

**Done when.** Either a narrowly-scoped deploy credential exists and a `deploy` job
restarts the service then runs `smoke:live`, or the manual step is written down
where the next person will find it (it is, in `README.md` and `AGENTS.md`).

---

## Landed

- Loop gate with contract, docs, typecheck, lint, tests, live smoke and hygiene
  stages — `c2801e5`, extended with the demo stage.
- Declared surface as a single source of truth, with a conformance suite that reads
  the *artifact* rather than the declaration — `3278748`, `f83d868`, `06e8a95`.
- Closed the `chars`-omission pass-rule bypass and the self-contradictory-report
  hole — `f1ba5e9`.
- `?sig=` tamper probe now reports record self-consistency and caller-signature
  match separately, so a `false` is never ambiguous — `f1ba5e9`.
