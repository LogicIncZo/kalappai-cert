# Contributing

This repository is set up to be developed by a **loop**: an agent or a person
picks one item from [BACKLOG.md](BACKLOG.md), makes the smallest honest change,
runs the gate, and commits. The gate — `bun run verify` — is the contract
between a change and a commit. Everything else here follows from that.

## The loop

```sh
bun install
bun run verify --fast     # tight inner loop: contract, docs, types, tests
bun run verify            # the real gate, before you commit
```

1. **Pick one item.** One backlog entry, one intent. If you find something else
   broken, write it in BACKLOG.md rather than fixing it in the same commit.
2. **Write the failing check first** where a check can be written. A pass rule,
   a refusal, a route, a field: if it is a claim about behaviour, it belongs in
   `test/contract.test.ts` or `test/server.test.ts`. A gate that can only be
   satisfied by a human remembering something is not a gate.
3. **Make the change.**
4. **Run the gate.** Fix the cause, never the check.
5. **Commit** with one intent per commit, then push.

## Definition of done

A change is done when all of these are true:

- `bun run verify` passes locally, on the working tree, with nothing skipped.
- Any new or changed claim about the HTTP surface is in `src/contract.ts` and
  the artifact is re-emitted (`bun run contract:emit`).
- `README.md` still documents exactly the surface — the docs stage fails on both
  "documented but absent" and "present but undocumented".
- New behaviour has a test that fails without the change.
- `docs/ANTI-GAMING.md` still describes what the service actually enforces.

## Never do this

- **Never weaken a gate to make a change pass.** Not the pass rules, not the
  invariants, not a probe, not a threshold. If a gate is wrong, correct it in
  its own commit with the reason in the message — that is a claim change, and it
  should be visible in the diff and in `CHANGELOG.md`.
- **Never commit `data/`.** The issuer key lives there; losing it silently
  invalidates every credential the service ever issued. The hygiene stage
  enforces this, but do not rely on it being the thing that stops you.
- **Never trust a client-supplied decision.** Coverage, tiers, timings,
  pass rules and reveals are recomputed server-side. A field the client can
  send is a field the client can lie about.
- **Never add a runtime dependency** without a note in `NOTICE.md`. The whole
  point of this service is that it is one process and one file.

## Changing the contract

The contract is the declared surface, and clients pin it by hash. To change it:

1. Edit `src/contract.ts` (not the artifact — the artifact is generated).
2. `bun run contract:emit` and commit the regenerated artifact.
3. Update `README.md` and, if the change is behavioural, the pass rules or
   invariants in the tests.
4. Add the new hash to the client repo's `contract/PINNED.sha256` — the client
   gate will not move until you do, by design.
5. Note the break in `CHANGELOG.md` if the change is not backward compatible.

## Commit messages

`type(scope): what changed and why it matters`. Types: `feat`, `fix`, `test`,
`docs`, `ci`, `refactor`, `chore`, `gate` (the change is to a verification gate).
