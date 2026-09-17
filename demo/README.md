# Demo infrastructure

Enough of a service to show, screenshot and regression-test the whole issuance
path without typing an exam by hand each time.

Everything here reads `contract/cert-service.v1.json`, so the demo cannot drift
from the declared surface: rename a field and the demo fails loudly instead of
quietly demonstrating an old shape. The demo runs in the gate (`bun run verify`,
stage 7), which is why it does not rot.

## Run it

```sh
bun run demo:seed                    # spawn, seed, print URLs + a QR, hold open
bash demo/run.sh                     # same, on a fixed port (8799) for screenshots
bash demo/run.sh --check             # assert the whole path, exit 0/1 (no hold)
bun run demo:seed --url https://…    # seed an instance that is already running
```

`demo/run.sh` is the entry point used by `bun run verify --full`.

## What it seeds

Four certificates across the layouts, chosen so the verify page can be shown
with realistic variety and one near-miss:

| Alias | Layout | Why it is there |
| --- | --- | --- |
| Demo · Tamil99 | tamil99 | the default layout, a comfortable pass |
| Demo · InScript | inscript | a second layout, different mechanism |
| Demo · Typewriter | typewriter | reordering layout, high accuracy |
| Demo · Near miss | tamil99 | just clears the accuracy rule — shows a marginal pass |

Each seed is checked end to end: the certificate verifies over JSON, the human
page carries a QR back to itself, and the VC-JWT verifies against the published
JWKS. A seed that cannot be demonstrated is a failed seed.

## Screenshots

With `bash demo/run.sh` holding the service open, the URLs it prints can be
screenshotted directly. For the cognizance gate the committed screenshots in
`docs/` are the reference; they were taken the same way.
