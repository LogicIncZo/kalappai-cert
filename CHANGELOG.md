# Changelog

Notable changes to the certification service. The contract version is the
compatibility surface clients pin; it only moves when the declared shape moves.

## [Unreleased]

### Added

- **Declared contract** (`src/contract.ts` → `contract/cert-service.v1.json`,
  contract version 1): routes, request/response shapes with `chars`, pass rules,
  rate limit, refusals, credential claims and read-only probes.
- **Verification gate** (`bun run verify`, 9 stages): contract artifact, docs,
  typecheck, lint, tests, live smoke, demo, deployability, hygiene.
- **Deployability stage** (`bun run image:check`): the `Dockerfile` and
  `deploy/docker-compose.yml` are checked against the service they package — the
  CMD entry file exists, EXPOSE matches the default PORT, the healthcheck probes a
  declared route, `KALAPPAI_CERT_DB` is pinned and its directory is a declared
  `VOLUME` that compose mounts, and the compose image matches what CI publishes.
  This protects a release path that otherwise only runs on a `v*` tag.
- **Deployed-instance conformance** (`bun run smoke:live`): compares a running
  deployment against the committed contract, so "is production actually running
  this commit?" is a command rather than an assumption.
- **CI** — the gate on every push and PR; deployment conformance on `main`;
  GHCR image with build provenance and SBOM on `v*` tags.
- **Demo infrastructure** (`demo/`): `bun run demo:seed` spawns an instance,
  seeds deterministic certificates and prints verify URLs plus a scannable QR;
  `demo/run.sh` holds a public demo open on a known port.
- **Container + deployment** (`Dockerfile`, `deploy/docker-compose.yml`) with a
  durable volume for the issuer key, healthcheck included.
- **`docs/ANTI-GAMING.md`** — what this service can and cannot attest to, the
  measured cost of keystroke attestation, and the trust tier proposal.
- **`AGENTS.md`** — the operating manual for a loop working in this repository.

### Changed

- **`chars` is now a required field**, read from `stats.chars`. It previously
  defaulted to *absent*, which skipped the 120-character pass rule entirely —
  a client could clear the rule by omitting the field.
- **Cross-field invariants are enforced** (net WPM ≤ gross WPM, 100% accuracy
  implies zero errors, errors ≤ strokes). A self-contradictory report is refused
  as `400 implausible typing report`, not `422`.
- **`GET /api/certificates/:id` separates its two answers**:
  `recordSelfConsistent` (the stored row survived) and `signatureMatchesProvided`
  (the `?sig=` copy the caller holds matches). A wrong `?sig=` no longer reports
  `signatureValid: true`.
- **Refusal statuses and messages come from the contract**, so a documented
  refusal and a served refusal cannot drift.

### Fixed

- **README documented `GET /api/cognizance/gates`, which 404s.** The real path is
  `GET /cognizance/gates`. This was found by the new docs stage and is the reason
  the docs stage exists.
- README documented `chars` as a top-level body field, omitted `verifyPath` and
  `credential` from the 201 response, and documented `?sig=` as a separate route.
- `sha256` helper was unused in `src/index.ts`; `import type` used for the
  type-only `Hono` import in `src/cognizance.ts`.
- **The gate miscounted its own stages.** The hygiene stage ran inline and was
  never added to the tally, so a nine-stage pass reported eight. It now counts
  what it ran, and the summary says nine.

[Unreleased]: https://github.com/LogicIncZo/kalappai-cert/commits/main
