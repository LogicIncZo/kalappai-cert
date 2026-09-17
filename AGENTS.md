# kalappai-cert — agent operating manual

Certification service for the [Kalappai](https://github.com/LogicIncZo/kalappai) typing
tutor. One Bun process, one SQLite file, no external services, no accounts.

**This file is the contract between the repo and whoever (or whatever) is changing it.**
Read it before your first edit; follow the loop; do not weaken a gate to make a change pass.

## The loop

Each iteration is one unit of work, and ends in a commit that a stranger could verify:

1. **Pick** the top unstarted task from [BACKLOG.md](BACKLOG.md) — or the task you were given.
2. **Read the surface you are about to touch.** The API surface is *declared*, not inferred:
   `src/contract.ts` is the single source of truth for routes, request/response fields, pass
   rules, rate limits, refusal messages and credential claims. If you change behaviour without
   changing the contract, the gate fails — deliberately.
3. **Change code and tests together.** Contract-affecting changes also need `contract:emit`.
4. **Run the gate**: `bun run verify`. Seven stages, no skipping. It must exit 0.
5. **Commit** — conventional-commit subject, imperative, explaining *why* when it is not obvious.
   Never commit `data/` (issuer key, database).
6. **Deploy** by restarting the Zo service (below) when the change affects the served surface.
7. **Confirm the deployment**: `bun run smoke:live` — it tests the *deployed* instance against
   the *committed* contract, and fails when the two disagree.
8. **Record** what changed: tick the task in `BACKLOG.md`, add a `CHANGELOG.md` entry.

If a step cannot be completed, say so in the commit message and in `BACKLOG.md` rather than
leaving the repo in a state where the gate passes but the deployment is untested.

## Verification gates

`bun run verify` → `scripts/verify.sh`. Every stage is a real gate: it fails the build.

| # | Stage | What it protects |
| --- | --- | --- |
| 1 | `contract:check` | The committed artifact `contract/cert-service.v1.json` matches `src/contract.ts`. Clients pin its SHA-256 — silent drift breaks them. |
| 2 | `check-docs` | README documents **exactly** the contract: no undocumented routes, no documented routes that do not exist, correct request/response fields, pass rules stated. |
| 3 | `typecheck` | `tsc --noEmit` over `src/`, `test/`, `scripts/` — the verification code is code, and must itself be verified. |
| 4 | `lint` | Biome (`--error-on-warnings`). Formatting is deliberately off; this is a bug gate, not a style gate. |
| 5 | `test` | Contract conformance + server + cognizance suites. `test/contract.test.ts` reads only the **artifact** and drives a spawned instance — it cannot pass by agreeing with the source it is meant to check. |
| 6 | `smoke` | Spawns the documented entrypoint on a temp DB and drives issue → verify → tamper → VC-JWT-against-JWKS end to end. Proves the real entrypoint boots, not just that `app.fetch` works. |
| 7 | `hygiene` | No committed database or issuer key, no secret-shaped literals in tracked source, no stray artifacts. |

Deployment-side gates (run by CI, and by you after a deploy):

- `bun run smoke:live` — the deployed instance conforms to the committed contract.
- CI `conformance` job — same check, against the live URL, on every push to `main`.
- CI `image` job — builds the Dockerfile and publishes to GHCR with provenance + SBOM attestations.

## Invariants — do not break these

1. **The server decides.** Every rule is evaluated on values the server parsed itself.
   A client cannot skip a rule by omitting a field (this is why `stats.chars` is required).
2. **Recompute, never trust.** Anything a client asserts about itself is a *claim*; anything the
   server derives is *evidence*. New features must not add trusted client assertions.
3. **Refusals are declared.** Status codes and messages come from `REFUSALS`; never inline a new one.
4. **Certificates are practice records, not qualifications.** That sentence stays on the verify
   page and in every credential's `termsOfUse`.
5. **No PII beyond what is printed on the certificate** (the learner-typed alias). No telemetry,
   no IP retention, no fingerprinting. Cognizance receipts are content-free by design.
6. **The issuer key is durable.** Lose `data/issuer-key.json` and every credential ever issued
   stops verifying. Back it up; never commit it.
7. **Honest labelling beats a stronger claim.** If a mechanism is a cost barrier rather than a
   proof, say so in the docs. See [docs/ANTI-GAMING.md](docs/ANTI-GAMING.md).

## Anti-gaming

The certificate is a claim about a stranger's typing ability, so the person with the most to gain
from gaming it is the learner themselves. Read `docs/ANTI-GAMING.md` before adding or describing
any trust mechanism. The short version:

- Server-side pass rules, cross-field invariants and rate limits raise the cost of a *sloppy*
  forgery. They do not detect a careful one.
- The structural fix is keystroke attestation: accept the keystroke stream, derive the score
  server-side, and stamp the resulting trust level on the credential so a verifier can tell an
  attested record from a self-reported one. The machinery already exists in `src/cognizance.ts`.
  It is on the backlog, not yet implemented for certificates.

## Deployment

Live instance (Zo user service `kalappai-cert`, http mode, port 8123):

<https://kalappai-cert-cashlessconsumer.zocomputer.io>

```sh
# after changing the served surface
# restart the service (Zo: update_user_service on svc_1AFtzXsc1ww), then:
bun run smoke:live
```

Self-hosting: `Dockerfile` + `deploy/docker-compose.yml` (durable `/data` volume is mandatory —
that volume holds the issuer key). `KALAPPAI_CERT_BASE` must be the public URL clients will
reach, because it is baked into QR codes, credential ids and `verifyUrl`.

Env vars: `PORT`, `KALAPPAI_CERT_SECRET`, `KALAPPAI_CERT_DB`, `KALAPPAI_CERT_BASE`,
`KALAPPAI_CERT_ORIGIN`, `KALAPPAI_COGNIZANCE_TTL_DAYS`.

## Layout

| Path | What lives there |
| --- | --- |
| `src/index.ts` | HTTP surface: issue, verify, QR/print page, JWKS, issuer metadata |
| `src/contract.ts` | **The declared surface.** Routes, fields, pass rules, refusals, claims |
| `src/cognizance.ts` | Keystroke-attested cognizance gate (sessions, reveals, tiers, receipts) |
| `contract/cert-service.v1.json` | Emitted artifact; clients pin its SHA-256 |
| `scripts/verify.sh` | The gate. `scripts/emit-contract.ts`, `check-docs.ts`, `smoke.ts`, `smoke-live.ts` |
| `test/` | `contract.test.ts` (artifact-driven conformance), `server.test.ts`, `cognizance.test.ts` |
| `demo/` | Runnable end-to-end demo + seeded certificate set |
| `deploy/`, `Dockerfile` | Self-hosting |
| `docs/ANTI-GAMING.md` | Threat model, what the gates buy, what they do not |
| `data/` | **Not in version control.** Issuer key + database |
