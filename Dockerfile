# syntax=docker/dockerfile:1
#
# kalappai-cert — one Bun process, one SQLite file, no external services.
#
# The certificate signing key lives in /data/issuer-key.json and is generated on
# first boot. Keep /data on a durable volume: lose it and previously issued
# credentials can no longer be verified against the published JWKS.

FROM oven/bun:1-alpine AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

FROM oven/bun:1-alpine

ENV NODE_ENV=production \
    PORT=8123 \
    KALAPPAI_CERT_DB=/data/certs.db

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json bun.lock tsconfig.json ./
COPY src ./src

RUN mkdir -p /data && chown -R bun:bun /app /data
USER bun

EXPOSE 8123
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/" >/dev/null 2>&1 || exit 1

CMD ["bun", "src/index.ts"]
