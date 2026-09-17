## What this changes

<!-- One intent. If you found something else broken, it goes in BACKLOG.md. -->

## Which claim moves

<!-- Pick one and delete the rest. -->

- [ ] No claim moves — internal change, behaviour is identical.
- [ ] A claim in `src/contract.ts` moves (contract re-emitted, artifact diff included).
- [ ] A claim in `docs/ANTI-GAMING.md` moves (what the service attests to changed).
- [ ] A gate moves — and this PR says why, in the description.

## Evidence

- [ ] `bun run verify` passes locally with nothing skipped.
- [ ] New behaviour has a test that fails without the change.
- [ ] `README.md` still documents exactly the contract (docs stage green).
- [ ] `CHANGELOG.md` updated when a claim, pass rule or invariant moved.

## If a gate changed

<!-- Delete if not applicable. The rule is: correct a wrong gate in its own
     commit, with the reason in the message — never weaken one to pass. -->

Gate:
Reason it was wrong:
What it now asserts:
