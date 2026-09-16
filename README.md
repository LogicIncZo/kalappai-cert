# kalappai-cert (சான்றிதழ்) — certification service for Kalappai

Standalone backend for the [Kalappai (கலப்பை)](https://github.com/LogicIncZo/kalappai)
Tamil typing tutor. Any client session that has completed an exam can POST its
score here and receive a signed, publicly verifiable certificate.

**Zero vendor lock-in, zero external services**: Hono + SQLite (bun:sqlite) +
`qrcode`. One Bun process, one DB file.

## What issuance produces

Each passed attempt is stored twice-protected:

1. **HMAC-protected SQLite record** — tamper-evident; `GET /api/certificates/:id`
   recomputes the HMAC and reports `signatureValid`.
2. **W3C Verifiable Credential** — VC 2.0 with a JWT proof (EdDSA / Ed25519),
   carrying an **Open Badges 3.0**-shaped achievement (1EdTech shape) with the
   learner-entered alias. The VC-JWT is downloadable from the verify page and
   verifiable offline against the public key in `/.well-known/jwks.json`.

The public verify page at `/certs/:id` renders the certificate, a **QR code
pointing back at itself** (scan → anyone can verify), a print button
(print-ready layout), and the raw VC-JWT.

A certificate from Kalappai is a **practice record, not a government
qualification** — the verify page says so explicitly.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/certificates` | Issue. Body: `{ alias, layoutId, passageId, targetHash, chars, stats: { grossWpm, netWpm, accuracy, errors, strokes, kdph, elapsedMs } }` → `{ id, issuedAt, signature, verifyUrl, vcJwt }` |
| GET | `/api/certificates/:id` | JSON verification: full record + `signatureValid` |
| GET | `/api/certificates/:id?sig=<sig>` | Verifies that the record matches the given signature (tamper probe) |
| GET | `/certs/:id` | Human verify page: certificate, QR, print, VC-JWT download |
| GET | `/api/issuer` | Issuer metadata (`id`, name, publicKeyJwk) |
| GET | `/.well-known/jwks.json` | Public key (JWKS, Ed25519) |

**Pass rules are enforced server-side** (accuracy ≥ 90%, ≥ 30 s, ≥ 120 chars) —
a client cannot talk its way to a certificate.

`targetHash` is the SHA-256 of the exact passage typed, binding the credential
to the exercise rather than to a claim.

## Configuration

| Env var | Meaning |
| --- | --- |
| `PORT` | Listen port (default 8123) |
| `KALAPPAI_CERT_SECRET` | HMAC secret. If unset, an ephemeral per-day secret is used and HMACs do not survive restarts (warned at boot). Set it in production. |
| `KALAPPAI_CERT_DB` | SQLite path (default `./data/certs.db`). The Ed25519 issuer key is persisted next to it as `issuer-key.json` (created on first boot). |
| `KALAPPAI_CERT_BASE` | Public base URL — appears in QR codes, credential ids and `verifyUrl` |
| `KALAPPAI_CERT_ORIGIN` | CORS allow-origin (default `*`) |

The VC signature (Ed25519) always survives restarts — the keypair is persisted
— but the database HMAC needs `KALAPPAI_CERT_SECRET` to do so.

## Run

```sh
bun install
KALAPPAI_CERT_SECRET=$(openssl rand -hex 32) \
KALAPPAI_CERT_BASE=https://cert.example.com \
bun src/index.ts
```

Tests (self-contained, spawns its own instance on a random port, covers issue →
verify round-trip, VC-JWT Ed25519 verification against the JWKS, DB-tampering
detection, pass-rule rejection, CORS):

```sh
bun test ./test/
```

## Deployment (Zo Computer)

Runs as a Zo user service `kalappai-cert` (http mode, port 8123):
`cd /path/to/kalappai-cert && bun src/index.ts`, with `KALAPPAI_CERT_DB`,
`KALAPPAI_CERT_BASE`, `KALAPPAI_CERT_ORIGIN` set as service env vars.

Live instance: <https://kalappai-cert-cashlessconsumer.zocomputer.io>

The PWA client (kalappai repo) keeps the server URL user-configurable — the app
is fully functional offline; certification is opt-in.

## License

GPL-3.0-or-later. Runtime dep: `qrcode` (MIT) — see NOTICE.md.
