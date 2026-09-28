#!/usr/bin/env node
// @ts-check
/**
 * check-dts-consumers.mjs
 *
 * Compiles small consumer files against the built declarations, the way a
 * project that installed hppx sees them, with this project's TypeScript:
 *
 *   - `index.cts`: a CommonJS TypeScript file using every import form
 *     (default import, named imports, type imports, `import x = require()`);
 *   - `require.cjs`: a CommonJS JavaScript file checked with `checkJs`, using
 *     the `require()` forms from the README;
 *   - `index.mts`: an ESM TypeScript file.
 *
 * Each file also carries `@ts-expect-error` lines for misuse the types must
 * reject, so the check fails if the declarations become too loose.
 * `skipLibCheck` is off, so an illegal declaration (for example TS2309,
 * `export =` next to other exports) is reported as well.
 *
 * Everything runs in memory: the fixtures and a virtual `node_modules/hppx`
 * (this repository's package.json and dist/*.d.*) live under a directory that
 * never exists on disk; every other file (TypeScript's lib files, @types) is
 * read from disk. The fixture folder has its own package.json, so the
 * package's self-reference never applies, and the script asserts which
 * declaration file each fixture resolved.
 *
 * Syntactic, global and option diagnostics are reported for every file;
 * semantic diagnostics only for the fixtures and hppx's declaration files, so
 * a release of an unrelated @types package cannot fail this check.
 *
 * Exit codes:
 *   0: every consumer compiles
 *   1: a diagnostic was reported, a fixture resolved the wrong file, or dist/ is missing
 */

import ts from "typescript";
import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const toPosix = (/** @type {string} */ p) => p.split(path.sep).join("/");
const root = toPosix(path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."));
const virtualRoot = `${root}/.consumer-check`;
const appDir = `${virtualRoot}/app`;
const pkgDir = `${virtualRoot}/node_modules/hppx`;

const CJS_TS = `import hppx from "hppx";
import { sanitize, DANGEROUS_KEYS, DEFAULT_SOURCES, DEFAULT_STRATEGY } from "hppx";
import type { HppxOptions, SanitizeOptions, RequestSource, MergeStrategy, SanitizedResult } from "hppx";
import hppxRequired = require("hppx");
import type { Request } from "express";

const options: HppxOptions = { whitelist: ["tags"], strict: true, mergeStrategy: "keepFirst" };
const sanitizeOptions: SanitizeOptions = { trimValues: true };
const middleware = hppx(options);
const fromRequire = hppxRequired({ sources: ["query"] });
const viaDefault = hppx.default({});
const viaRequireDefault = hppxRequired.default({});
const cleaned: { a: string } = sanitize({ a: "1" }, sanitizeOptions);
const cleanedViaRequire: { b: number } = hppxRequired.sanitize({ b: 1 });
const keys: ReadonlySet<string> = DANGEROUS_KEYS;
const keysViaRequire: ReadonlySet<string> = hppxRequired.DANGEROUS_KEYS;
const sources: RequestSource[] = DEFAULT_SOURCES;
const strategy: MergeStrategy = DEFAULT_STRATEGY;
type Result = SanitizedResult<{ a: string }>;
declare const req: Request;
const polluted: Record<string, unknown> | undefined = req.queryPolluted;

// @ts-expect-error strict must be a boolean
hppx({ strict: "yes" });
// @ts-expect-error sources only accepts query, body and params
hppx({ sources: ["cookies"] });
// @ts-expect-error DANGEROUS_KEYS is a ReadonlySet
DANGEROUS_KEYS.add("isAdmin");

export { middleware, fromRequire, viaDefault, viaRequireDefault, cleaned, cleanedViaRequire };
export { keys, keysViaRequire, sources, strategy, polluted };
export type { Result };
`;

const CJS_JS = `const hppx = require("hppx");
const { sanitize, DANGEROUS_KEYS, DEFAULT_SOURCES, DEFAULT_STRATEGY } = require("hppx");

/** @type {import("hppx").HppxOptions} */
const options = { whitelist: ["tags"], logPollution: false };
const middleware = hppx(options);
const viaDefault = hppx.default({ strict: true });
/** @type {{ a: string }} */
const cleaned = sanitize({ a: "1" });
/** @type {ReadonlySet<string>} */
const keys = DANGEROUS_KEYS;

// @ts-expect-error strict must be a boolean
hppx({ strict: "yes" });

module.exports = { middleware, viaDefault, cleaned, keys, DEFAULT_SOURCES, DEFAULT_STRATEGY };
`;

const ESM_TS = `import hppx, { sanitize, DANGEROUS_KEYS, DEFAULT_SOURCES, DEFAULT_STRATEGY } from "hppx";
import type { HppxOptions, SanitizeOptions, RequestSource, MergeStrategy, SanitizedResult } from "hppx";
import type { Request } from "express";

const options: HppxOptions = { whitelist: ["tags"], strict: true };
const sanitizeOptions: SanitizeOptions = { maxDepth: 5 };
const middleware = hppx(options);
const cleaned: { a: string } = sanitize({ a: "1" }, sanitizeOptions);
const keys: ReadonlySet<string> = DANGEROUS_KEYS;
const sources: RequestSource[] = DEFAULT_SOURCES;
const strategy: MergeStrategy = DEFAULT_STRATEGY;
type Result = SanitizedResult<{ a: string }>;
declare const req: Request;
const polluted: Record<string, unknown> | undefined = req.bodyPolluted;

// @ts-expect-error the ESM entry exports the factory itself, without a default property
hppx.default({});
// @ts-expect-error DANGEROUS_KEYS is a ReadonlySet
DANGEROUS_KEYS.delete("__proto__");

export { middleware, cleaned, keys, sources, strategy, polluted };
export type { Result };
`;

/** @type {{ file: string, mode: ts.ResolutionMode, expected: string }[]} */
const fixtures = [
  {
    file: `${appDir}/index.cts`,
    mode: ts.ModuleKind.CommonJS,
    expected: `${pkgDir}/dist/index.d.cts`,
  },
  {
    file: `${appDir}/require.cjs`,
    mode: ts.ModuleKind.CommonJS,
    expected: `${pkgDir}/dist/index.d.cts`,
  },
  {
    file: `${appDir}/index.mts`,
    mode: ts.ModuleKind.ESNext,
    expected: `${pkgDir}/dist/index.d.ts`,
  },
];

function readRepoFile(/** @type {string} */ relative) {
  const full = `${root}/${relative}`;
  if (!existsSync(full)) {
    console.error(
      `[check-dts-consumers] Missing ${relative}. Did you run \`npm run build\` first?`,
    );
    process.exit(1);
  }
  return readFileSync(full, "utf8");
}

/** @type {Map<string, string>} */
const virtualFiles = new Map([
  [`${appDir}/package.json`, JSON.stringify({ name: "hppx-consumer-check", private: true })],
  [`${appDir}/index.cts`, CJS_TS],
  [`${appDir}/require.cjs`, CJS_JS],
  [`${appDir}/index.mts`, ESM_TS],
  [`${pkgDir}/package.json`, readRepoFile("package.json")],
  [`${pkgDir}/dist/index.d.ts`, readRepoFile("dist/index.d.ts")],
  [`${pkgDir}/dist/index.d.cts`, readRepoFile("dist/index.d.cts")],
]);

const isVirtual = (/** @type {string} */ p) => p === virtualRoot || p.startsWith(`${virtualRoot}/`);

/** @type {ts.CompilerOptions} */
const options = {
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  target: ts.ScriptTarget.ES2022,
  strict: true,
  skipLibCheck: false,
  allowJs: true,
  checkJs: true,
  noEmit: true,
  types: [],
};

const base = ts.createCompilerHost(options);
/** @type {ts.CompilerHost} */
const host = {
  ...base,
  getCurrentDirectory: () => root,
  fileExists: (f) => (isVirtual(f) ? virtualFiles.has(f) : base.fileExists(f)),
  readFile: (f) => (isVirtual(f) ? virtualFiles.get(f) : base.readFile(f)),
  directoryExists: (d) =>
    isVirtual(d)
      ? [...virtualFiles.keys()].some((f) => f.startsWith(`${d}/`))
      : existsSync(d) && statSync(d).isDirectory(),
  getDirectories: (d) => (isVirtual(d) ? [] : (base.getDirectories?.(d) ?? [])),
  realpath: (p) => (isVirtual(p) ? p : (base.realpath?.(p) ?? p)),
  getSourceFile: (fileName, languageVersionOrOptions, onError, shouldCreate) => {
    if (!isVirtual(fileName)) {
      return base.getSourceFile(fileName, languageVersionOrOptions, onError, shouldCreate);
    }
    const text = virtualFiles.get(fileName);
    return text === undefined
      ? undefined
      : ts.createSourceFile(fileName, text, languageVersionOrOptions, true);
  },
};

const failures = [];

for (const { file, mode, expected } of fixtures) {
  const resolved = ts.resolveModuleName("hppx", file, options, host, undefined, undefined, mode)
    .resolvedModule?.resolvedFileName;
  if (resolved !== expected) {
    failures.push(
      `${path.posix.basename(file)} resolved "hppx" to ${resolved ?? "nothing"}, expected ${expected}`,
    );
  }
}

const program = ts.createProgram(
  fixtures.map((f) => f.file),
  options,
  host,
);
const checked = program
  .getSourceFiles()
  .filter(
    (sf) => fixtures.some((f) => f.file === sf.fileName) || sf.fileName.startsWith(`${pkgDir}/`),
  );
const diagnostics = [
  ...program.getOptionsDiagnostics(),
  ...program.getGlobalDiagnostics(),
  ...program.getSyntacticDiagnostics(),
  ...checked.flatMap((sf) => program.getSemanticDiagnostics(sf)),
];
for (const d of diagnostics) {
  const where = d.file
    ? `${path.posix.relative(virtualRoot, d.file.fileName)}:${d.file.getLineAndCharacterOfPosition(d.start ?? 0).line + 1}`
    : "(options)";
  failures.push(`${where} TS${d.code} ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`);
}

if (failures.length > 0) {
  console.error(`[check-dts-consumers] FAIL (TypeScript ${ts.version}):`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(
  `[check-dts-consumers] OK: ${fixtures.length} consumer files compile against dist/index.d.cts and dist/index.d.ts (TypeScript ${ts.version}, ${checked.length} files checked semantically).`,
);
