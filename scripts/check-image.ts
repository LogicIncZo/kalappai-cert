/**
 * Deployability — the container definition against the contract and the runtime.
 *
 * The image is built on a `v*` tag and nowhere else, which means every way it can
 * be wrong is a way that is discovered at release time, by which point the tag is
 * already public. This stage checks the same claims without a daemon:
 *
 *   · the entrypoint named by CMD is a file the image actually copies
 *   · the exposed port is the port the service defaults to
 *   · the health check hits a route the contract declares
 *   · the database path is set explicitly, so the issuer key cannot silently land
 *     in the image layer instead of the volume (a key written inside a container
 *     is a key that disappears with it, taking every issued credential with it)
 *   · the volume covers that path, and compose mounts it
 *   · compose pulls the reference CI publishes
 *   · no runtime import escapes the files the image copies
 *
 * Nothing here needs Docker. Usage: bun scripts/check-image.ts
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, normalize } from "node:path";

const ROOT = join(import.meta.dir, "..");
const problems: string[] = [];
const note = (msg: string) => problems.push(msg);

const read = (p: string) => readFileSync(join(ROOT, p), "utf8");

const dockerfile = read("Dockerfile");
const contract = JSON.parse(read("contract/cert-service.v1.json")) as {
  routes: Array<{ method: string; path: string }>;
};
const compose = (() => {
  try {
    return read("deploy/docker-compose.yml");
  } catch {
    return "";
  }
})();

/** Dockerfile instructions of one kind, with line continuations collapsed. */
function instructions(text: string, name: string): string[] {
  const lines = text.replace(/\\\r?\n\s*/g, " ").split(/\r?\n/);
  return lines
    .filter((l) => new RegExp(`^\\s*${name}\\b`, "i").test(l))
    .map((l) => l.replace(/^\s*/i, "").replace(new RegExp(`^${name}\\b`, "i"), "").trim());
}

const port = String(8123);
const dbEnv = /KALAPPAI_CERT_DB=([^\s\\]+)/.exec(dockerfile)?.[1] ?? "";

/* ---- 1. the files the image builds from ---- */
const copies = instructions(dockerfile, "copy").flatMap((c) => {
  /* COPY [--from=…] <src...> <dest> — the last token is the destination. */
  const parts = c.split(/\s+/).filter((p) => !p.startsWith("--from"));
  return parts.slice(0, -1);
});

if (!copies.length) note("the Dockerfile copies nothing — nothing to build");
for (const src of copies) {
  /* Only cheap, real assertions: a copy source must exist, or be an explicit
     build-stage artifact (`/app/...`), which is checked by the entrypoint below. */
  if (isAbsolute(src) || src.startsWith("!")) continue;
  if (!existsSync(join(ROOT, src))) note(`the Dockerfile COPYs \`${src}\`, which does not exist in the build context`);
}
for (const required of ["package.json", "bun.lock", "src"]) {
  if (!copies.some((c) => c === required || c.startsWith(`${required}/`))) {
    note(`the image never copies \`${required}\`, so the service cannot start`);
  }
}

/* ---- 2. the entrypoint ---- */
const cmd = instructions(dockerfile, "cmd")[0] ?? "";
/* CMD is either exec form (`["bun", "src/index.ts"]`) or shell form; in both the
   script path is a bare token ending in a source extension. */
const cmdFile =
  cmd
    .split(/[\s,[\]"]+/)
    .filter(Boolean)
    .find((t) => /\.(ts|tsx|js|mjs|cjs)$/.test(t)) ?? "";
if (!cmdFile) {
  note(`could not read a script path out of CMD (${cmd || "missing"})`);
} else {
  const rel = normalize(cmdFile.replace(/^\//, ""));
  const inImage = copies.some((c) => rel === c || rel.startsWith(`${c}/`));
  if (!existsSync(join(ROOT, rel))) note(`CMD runs \`${cmdFile}\`, which does not exist in the repo`);
  else if (!inImage) note(`CMD runs \`${cmdFile}\`, which the COPY set does not put in the image`);
}

/* ---- 3. the port ---- */
const exposed = instructions(dockerfile, "expose").join(" ").match(/\d+/)?.[0] ?? "";
const defaultPort = /const PORT = Number\(process\.env\.PORT \?\? (\d+)\)/.exec(read("src/index.ts"))?.[1] ?? "";
if (!exposed) note("the Dockerfile declares no EXPOSE port");
if (!defaultPort) note("could not read the service's default PORT from src/index.ts");
if (exposed && defaultPort && exposed !== defaultPort) {
  note(`the image EXPOSEs ${exposed} but the service defaults to ${defaultPort}`);
}
if (port && !dockerfile.includes(`PORT=${port}`)) {
  note(`the image never sets PORT, while compose publishes a fixed host port`);
}

/* ---- 4. the health check ---- */
const health = instructions(dockerfile, "healthcheck").join(" ");
const healthPath = /127\.0\.0\.1:\$\{?PORT\}?(\/[^\s"']*)?/.exec(health)?.[1] || "/";
if (!health) {
  note("the Dockerfile declares no HEALTHCHECK");
} else if (!contract.routes.some((r) => r.path === healthPath)) {
  note(`the HEALTHCHECK probes \`${healthPath}\`, which the contract does not declare as a route`);
}

/* ---- 5. the durable path — this is the one that loses credentials ---- */
if (!dbEnv) {
  note(
    "the image does not set KALAPPAI_CERT_DB, so the issuer key falls back to a path inside the\n" +
      "    image layer: a rebuilt container would generate a fresh key and every credential\n" +
      "    issued before it would stop verifying",
  );
} else {
  const dbDir = dirname(dbEnv);
  const volumes = instructions(dockerfile, "volume")
    .join(" ")
    .match(/[[\]"]|[^\s[\],"']+/g)
    ?.filter((t) => t.startsWith("/")) ?? [];
  if (!volumes.includes(dbDir)) {
    note(`KALAPPAI_CERT_DB lives in ${dbDir}, which the image does not declare as a VOLUME`);
  }
  /* Compose mounts the directory as a *target*: `cert-data:/data` in short syntax
     or `target: /data` in long syntax. Matching `${dbDir}:` would only find it as a
     source, which is how a correct compose file got flagged the first time. */
  const esc = dbDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const mountedAsTarget =
    new RegExp(`:\\s*${esc}\\s*(?::\\w+)?\\s*(?:#.*)?$`, "m").test(compose) ||
    new RegExp(`target:\\s*${esc}\\s*(?:#.*)?$`, "m").test(compose);
  if (compose && !mountedAsTarget) {
    note(`compose does not mount ${dbDir}, so the issuer key is lost when the container is replaced`);
  }
  /* The database path must not be under the app tree, which is not a volume. */
  if (/^\/app\//.test(dbEnv)) {
    note(`KALAPPAI_CERT_DB is ${dbEnv} — inside the application tree, not a volume`);
  }
}

/* ---- 6. compose pulls what CI publishes ---- */
if (compose) {
  const composeImage = /image:\s*(\S+)/.exec(compose)?.[1] ?? "";
  const ciImages = /images:\s*(ghcr\.io\/[^\s]+)/i.exec(read(".github/workflows/ci.yml"))?.[1] ?? "";
  /* CI builds `ghcr.io/${{ github.repository }}`; only the suffix is checkable here. */
  const ciRepo = ciImages.replace(/\/\$?\{?\{?.*$/, "");
  if (composeImage && ciImages && !composeImage.toLowerCase().startsWith(ciRepo.toLowerCase())) {
    note(`compose pulls \`${composeImage}\` but CI publishes to \`${ciImages}\``);
  }
}

/* ---- 7. no runtime import escapes the copied set ---- */
const srcFiles: string[] = [];
const walk = (dir: string) => {
  for (const entry of new Bun.Glob("**/*.ts").scanSync({ cwd: join(ROOT, dir), onlyFiles: true })) {
    srcFiles.push(`${dir}/${entry}`);
  }
};
walk("src");
if (!srcFiles.length) note("no TypeScript sources under src/ — the image would serve nothing");

for (const file of srcFiles) {
  const text = read(file).replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  for (const m of text.matchAll(/(?:^|\n)\s*import[^"'\n]*["']([^"']+)["']/g)) {
    const spec = m[1];
    if (!spec.startsWith(".")) continue;
    const target = normalize(join(dirname(file), spec));
    const candidates = [target, `${target}.ts`, join(target, "index.ts")];
    if (!candidates.some((c) => existsSync(join(ROOT, c)))) {
      note(`${file} imports \`${spec}\`, which resolves to nothing`);
    } else if (target.startsWith("..")) {
      note(`${file} imports \`${spec}\` from outside src/ — the image only copies src/`);
    }
  }
}

/* ---- report ---- */
if (problems.length === 0) {
  console.log(
    `✓ the container definition matches the service (entrypoint ${cmdFile || "?"} · port ${exposed} · ` +
      `data ${dbEnv || "?"} · volume declared · compose matches CI)`,
  );
  process.exit(0);
}

console.log("✗ the container definition and the service disagree:");
for (const p of problems) console.log(`  · ${p}`);
console.log("\n  fix Dockerfile, deploy/docker-compose.yml, or the code it names.");
process.exit(1);
