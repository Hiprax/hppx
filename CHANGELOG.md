# Changelog

## v0.2.4 — Repo hardening + badges + provenance trust signal (2026-05-12)

Documentation and repo-hardening release. No source/API changes; the
package surface and runtime behavior are unchanged. The published
tarball changes only because the README ships with the new badge set.

### Added

- **README badges aligned to the required project set:**
  CI, CodeQL, codecov, Dependencies, npm provenance — plus npm version,
  license, Node.js. Replaces the prior "Zero Dependencies" wording with
  a plain `dependencies-0` badge. Adds an `npm provenance` static badge
  linking to the package page where npm renders the Sigstore-attested
  provenance for each released version.

### Hardened (GitHub-side, no repo file changes)

The following best-practice settings were enabled directly on the
GitHub repository (`Hiprax/hppx`) via the GitHub API. These are
repository configuration, not source code, so they do not appear in
the diff — but they protect every future commit and release.

- **Dependabot alerts** enabled — surfaces transitive vulnerabilities
  in dev dependencies (zero runtime deps means runtime is always 0
  vulnerabilities by construction).
- **Dependabot security updates** enabled — auto-opens PRs for
  vulnerability fixes when an advisory affects the lockfile.
- **Private vulnerability reporting** enabled — researchers can report
  security issues via GitHub's confidential channel instead of public
  issues.
- **Secret scanning** + **push protection** enabled (was already on).
- **Tag protection ruleset** (`release tags`, id 16297738) targeting
  `refs/tags/v[0-9]*` with `deletion`, `non_fast_forward`, and
  `update` rules — published version tags can no longer be moved or
  removed once created, even by the owner. Combined with the
  immutability of npm version IDs, every `vX.Y.Z` published from this
  repo is now a permanent reference point.
- **Branch protection ruleset on `main`** (id 16288916, unchanged
  from v0.2.3): blocks deletion, non-fast-forward, requires 5 status
  checks (Test on Node 18/20/22/24, Analyze javascript-typescript),
  required linear history, no bypass.
- **Merge settings tightened:** merge commits disabled, squash merge
  enabled (PR title + body), rebase merge allowed, auto-merge enabled,
  head branches auto-deleted on PR merge. Squash merge keeps `main`'s
  history linear and clean.

### Verified

- `npm run typecheck` — clean.
- `npm run lint` — clean.
- `npm run format:check` — clean.
- `npm test` — 185/185 passing.
- `npm run build` — both ESM/CJS bundles emit.
- `npm run check-dts` — `dist/index.d.ts` and `dist/index.d.cts` expose
  the same 11 symbols.
- `npm run check-types-pack` — attw No problems found.
- `npm audit` — 0 vulnerabilities.
- `npm pack --dry-run` — tarball shape unchanged.

## v0.2.3 — Dependency upgrades + CI/release automation (2026-05-12)

Dev-dependency refresh plus a one-time GitHub/CI hardening pass. No
runtime/API changes; the package still ships zero runtime dependencies and
the public surface is unchanged. Two visible changes: a headline ESLint
bump to v10 and a full release-automation pipeline on tag push.

### Added — CI / release infrastructure

- **`.github/workflows/ci.yml`.** Build, dts-parity (`check-dts`), types-pack
  (`check-types-pack` via [`@arethetypeswrong/cli`][attw]), `typecheck`,
  `lint`, `format:check`, and `test --coverage` across Node 18 / 20 / 22 / 24. Coverage is uploaded to Codecov on the Node 22 leg.
- **`.github/workflows/release.yml`.** Triggered on `v*.*.*` tag push (and
  `workflow_dispatch`). Re-runs every quality gate, refuses to publish
  unless `package.json` `version` matches the tag, runs
  `npm publish --provenance --access public` via OIDC, then creates a
  GitHub Release with the matching CHANGELOG section as the body.
- **`.github/workflows/codeql.yml`.** GitHub Advanced Security CodeQL
  analysis (`security-and-quality` query suite) on push, pull request, and
  weekly schedule.
- **`.github/PULL_REQUEST_TEMPLATE.md`** and `.github/ISSUE_TEMPLATE/*` (bug
  report, feature request, plus `blank_issues_enabled: false`).
- **`scripts/_lib.mjs`, `scripts/verify.mjs`, `scripts/new-branch.mjs`,
  `scripts/sync-main.mjs`, `scripts/release-prepare.mjs`,
  `scripts/release-tag.mjs`.** Zero-dependency, cross-platform Node scripts
  that mirror the CI gates locally and drive the release flow.
- **New npm scripts:** `verify`, `check-types-pack`, `format:check`,
  `branch`, `sync`, `release:prepare`, `release:tag`.
- **`@arethetypeswrong/cli` ^0.18.2** added as a devDependency for the new
  `check-types-pack` gate. Complements the existing
  `scripts/check-dts-parity.mjs` (parity catches "the two `.d.ts` files
  disagree on what's exported"; attw catches "the exports map shape lies to
  consumers about ESM/CJS").
- **README badges** updated: npm, license, CI, CodeQL, Codecov, Node, zero
  dependencies. Ordering aligned with the CI workflow names.

[attw]: https://arethetypeswrong.github.io/

### Changed — dependencies

- **ESLint 9.39.4 → 10.3.0** (major). The flat config (`eslint.config.mjs`)
  the project already uses required no edits to migrate. The published
  package's `engines.node` stays `>=18` because hppx itself remains
  Node-18-compatible at runtime; ESLint 10 only affects local development,
  where contributors now need Node `^20.19.0 || ^22.13.0 || >=24` (matching
  ESLint 10's own requirement). All `eslint:recommended` defaults that became
  active in v10 (`no-unassigned-vars`, `no-useless-assignment`,
  `preserve-caught-error`, stricter `no-shadow-restricted-names`) pass clean
  against the current source.
- **`@eslint/js` added as an explicit devDependency at `^10.0.1`.** It was
  previously hoisted from `eslint`'s tree; making it explicit matches how it's
  imported in `eslint.config.mjs` and keeps it pinned alongside `eslint` for
  predictable resolution.
- **`@typescript-eslint/*` 8.59.1 → 8.59.3** (`eslint-plugin`, `parser`, and
  the meta `typescript-eslint` package). 8.59.x already declares ESLint 10 in
  its peer range (`^8.57.0 || ^9.0.0 || ^10.0.0`), so no migration was
  required.
- **`@types/node` 25.6.0 → 25.7.0**, **`jest` 30.3.0 → 30.4.2** (patch/minor).

### Verified

- `npm run typecheck` — clean.
- `npm run lint` — clean under ESLint 10.
- `npm test` — 185/185 passing, coverage stmts 99.72%, branches 95.01%, funcs
  100%, lines 100%.
- `npm run build` — both ESM/CJS bundles emit; DTS rollup succeeds.
- `npm run check-dts` — `dist/index.d.ts` and `dist/index.d.cts` expose the
  same 11 symbols.
- `npm run check-types-pack` — attw reports no issues on the packed tarball.
- `npm audit` — 0 vulnerabilities.
- `npm run format:check` — clean.

## v0.2.2 — Dependency upgrades (2026-05-04)

Dev-dependency refresh. No runtime/API changes; the package still ships zero
runtime dependencies and the public surface is unchanged. Two minimal source
changes were required for TypeScript 6.0 compatibility (see below).

### Changed

- **TypeScript 5.9 → 6.0.3.** Largest bump in this batch. TypeScript 6.0
  changes the default `types` value to `[]` and deprecates `baseUrl`. Adjusted
  `tsconfig.json` to keep behavior intact:
  - Added `"types": ["node", "jest"]` so Jest globals (`describe`, `test`,
    `expect`, …) resolve in the test typecheck under the new default. The
    repo's runtime types (`@types/node`) are listed alongside.
  - Added `"ignoreDeprecations": "6.0"` to silence the `baseUrl` deprecation
    that tsup's DTS rollup raises against its internal compiler options. This
    is the workaround tracked upstream in `egoist/tsup#1389`; it is a no-op
    until TypeScript 7.
- **`@types/node` 24.10 → 25.6** (devDep only; package `engines` stays
  `>=18`).
- **`@types/supertest` 6.0 → 7.2** (transitive `@types/superagent` realigned).
- **`@types/express` 5.0.5 → 5.0.6**, **`express` 5.1 → 5.2.1**, **`jest`
  30.2 → 30.3**, **`prettier` 3.6.2 → 3.8.3**, **`rimraf` 6.1.0 → 6.1.3**,
  **`supertest` 7.1.4 → 7.2.2**, **`ts-jest` 29.4.5 → 29.4.9**, **`tsup`
  8.5.0 → 8.5.1**, **`@typescript-eslint/*` 8.46 → 8.59.1**, **`eslint`
  9.39.1 → 9.39.4** (patch/minor).
- **Pinned to ESLint 9.x deliberately.** ESLint 10 requires Node
  `^20.19.0 || ^22.13.0 || >=24`, which conflicts with the package's
  `engines.node: >=18`. Staying on the latest 9.x.
- **`src/index.ts`** — added `import type {} from "express-serve-static-core";`
  immediately above the existing `declare module "express-serve-static-core"`
  augmentation. TypeScript 6.0's stricter DTS rollup no longer resolves
  augmentation targets through transitive `@types` packages alone; the
  type-only side-effect import pulls the module into scope without affecting
  the JS bundles (CJS/ESM byte sizes unchanged). The augmentation block still
  appears verbatim in both `dist/index.d.ts` and `dist/index.d.cts`.

### Verified

- `npm run typecheck` — clean.
- `npm run lint` — clean.
- `npm test` — 185/185 passing, coverage stmts/funcs/lines at 100%, branches
  95.01%.
- `npm run build` — both ESM/CJS bundles emit; DTS rollup succeeds.
- `npm run check-dts` — `dist/index.d.ts` and `dist/index.d.cts` expose the
  same 11 symbols.
- `npm audit` — 0 vulnerabilities.
- `npx prettier --check .` — clean.
- `npm pack --dry-run` — 9 files, 49.5 kB tarball / 178.7 kB unpacked,
  unchanged tarball shape.

## v0.2.1 — Bulletproofing Iteration 2 (2026-05-04)

A small post-v0.2.0 audit pass. One real correctness fix, one build-pipeline
cleanup, and tooling hygiene. Backward compatible.

### Fixed

- **`pollutedKeys` deduplication for nested arrays.** When the input contained
  a nested array (an array whose elements are themselves arrays, e.g.
  `{ a: [[1, 2], [3, 4]] }`), `processNode` recorded pollution under the same
  path once for each level it visited, producing duplicate entries in
  `pollutedKeys` and successive `setIn` writes that overwrote each other in
  `pollutedTree`. `processNode` now tracks an `inArray` flag and only records
  pollution at the outermost array site, so each distinct leaf path appears
  exactly once. The polluted tree value (the outer array) is unchanged. Covers
  both `keepLast` and `combine` strategies (`src/index.ts`,
  `tests/hppx.coverage.test.ts`).

### Changed / Cleanup

- **Removed dead hand-authored `src/index.d.cts`.** The hand-authored file was
  silently overwritten by the tsup-auto-generated `.d.cts` during the DTS
  build step, making it unreachable for consumers despite being shipped in
  the tarball. Deleted the file, dropped the `onSuccess` copy hook from
  `tsup.config.ts`, removed the `src` entry from `package.json` `files`, and
  updated `CLAUDE.md`'s Dual-Format Build section. tsup now auto-generates
  both `.d.ts` and `.d.cts`, kept in symbol-parity by
  `scripts/check-dts-parity.mjs`. The shipped tarball is unchanged in shape;
  it just no longer carries an inert `src/index.d.cts` (`tsup.config.ts`,
  `package.json`, `CLAUDE.md`, `scripts/check-dts-parity.mjs`).
- **Added `endOfLine: "auto"` to `.prettierrc.json`** so prettier validates
  content but accepts whatever line ending each file uses on disk. Stops
  CRLF/LF noise from drowning out real formatting drift on Windows checkouts
  (`.prettierrc.json`).
- **Repo-wide prettier formatting normalization.** Re-ran `prettier --write`
  across `README.md`, `CHANGELOG.md`, `FIX.md`, `tests/*.ts`, and
  `scripts/check-dts-parity.mjs` to clear the small formatting drift that had
  accumulated. `npx prettier --check .` is now clean.

## v0.2.0 — Bulletproofing Iteration 1 (2026-05-04)

A comprehensive hardening pass covering security, correctness, build/tooling, API
ergonomics, tests, and documentation. Backward compatible.

### Security

- **Fixed:** Prototype-pollution bypass via the `__hppxProcessed_*` skip flag.
  The flag is now read with `Object.prototype.hasOwnProperty.call` (no
  prototype-chain traversal) and written via `Object.defineProperty` with
  `writable: false, configurable: false, enumerable: false` so it cannot be
  tampered with by upstream code or leaked through response serializers
  (`src/index.ts`).
- **Fixed:** Express 5 lazy `req.query` getter no longer causes silent
  fail-open. `setReqPropertySafe` now uses `Object.defineProperty` to shadow
  the prototype-level getter on first write, falls back to direct assignment
  when the descriptor is non-configurable but writable, and surfaces a clear
  warning via the configured `logger` (or `console.warn`) when the descriptor
  is non-configurable AND non-writable rather than skipping silently
  (`src/index.ts`).
- **Fixed:** Shared (acyclic) subtree data loss in `safeDeepClone` and
  `expandObjectPaths`. Switched from a walk-wide `WeakSet` to path-stack
  cycle detection (add on entry, remove on exit via `try/finally`) so shared
  references are cloned correctly at every site while genuine cycles are
  still broken (`src/index.ts`).
- **Hardened:** `sanitizeKey` now rejects ASCII C0/C1 control characters
  (U+0000..U+001F, U+007F..U+009F), Unicode bidirectional override characters
  (U+200E/F, U+202A..U+202E, U+2066..U+2069), and U+FEFF in addition to NUL.
  Pre-compiled at module load, ReDoS-safe (character class only)
  (`src/index.ts`).
- **Hardened:** `req.path` access in the middleware is wrapped in a
  defensive `try/catch`. A throwing path getter no longer propagates as a
  500 — exclusion lookup is best-effort and the request continues to be
  sanitized (`src/index.ts`).
- **Hardened:** `process.env.NODE_ENV` access removed from the logger-failure
  fallback path so the package no longer crashes on edge runtimes
  (Cloudflare Workers, Vercel Edge, Deno without Node-compat) where
  `process` may be undefined or `process.env` may be a throwing Proxy
  (`src/index.ts`).
- **Hardened:** `combine` merge strategy now records pollution into the
  polluted tree, `pollutedKeys`, and fires `onPollutionDetected`. The
  combined output is still returned as the cleaned value, but the security
  signal is no longer silently bypassed (`src/index.ts`).
- **Hardened:** Cache-poisoning resistance — both `pathSegmentCache` and the
  per-instance whitelist `pathCache` use a clear-on-full eviction policy so a
  flood of unique keys cannot permanently disable caching for legitimate
  traffic (`src/index.ts`).

### Build / Tooling

- **Fixed:** `npm run lint` is now functional. Migrated from the legacy
  `.eslintrc.cjs` (rejected by ESLint v9) to the flat-config format in
  `eslint.config.mjs`. Migrated all rules (`@typescript-eslint/no-explicit-any: off`,
  `@typescript-eslint/consistent-type-definitions: ["error", "interface"]`,
  Prettier compatibility), and added a global `dist/**` ignore. Removed
  `.eslintrc.cjs`.
- **Changed:** `engines.node` bumped from `>=16` (EOL since 2023-09) to
  `>=18` (`package.json`). README badge updated.
- **Fixed:** Resolved `npm audit` advisories in dev dependencies (Handlebars
  prototype-pollution chain, ReDoS in minimatch / path-to-regexp / picomatch,
  qs DoS, rollup path traversal, js-yaml prototype-pollution, yaml stack
  overflow). Updated `package-lock.json`. No runtime dependencies are
  affected.
- **Added:** Hand-maintained `.d.ts` vs `.d.cts` symbol-parity check in
  `scripts/check-dts-parity.mjs`, wired into `npm run prepare` so a missing
  or extraneous symbol fails the publish pipeline.

### API / Correctness

- **Changed:** Express request-type augmentation moved from a separate
  `src/express-augment.d.ts` file into a `declare module
"express-serve-static-core"` block at the top of `src/index.ts`. tsup now
  emits the augmentation into both `dist/index.d.ts` and `dist/index.d.cts`
  automatically; consumers no longer need to add `/// <reference>` paths.
  Deleted `src/express-augment.d.ts`.
- **Changed:** `mergeValues` exhaustiveness check now throws on an
  unrecognized strategy instead of silently falling back to `keepLast`.
  Validation rejects invalid strategies at construction time, so this only
  fires on a programmer error introducing a new union member without
  updating the switch (`src/index.ts`).
- **Refactored:** `detectAndReduce` now performs a single upfront
  `safeDeepClone` and walks the cloned tree without re-cloning subtrees per
  polluted-array site. Documented detachment invariant: polluted-tree
  entries reference nodes inside the detached cloned tree, never the
  caller-owned input. This eliminates the previous double-clone /
  fresh-WeakSet aliasing concern raised by Finding 24
  (`src/index.ts`).
- **Added:** Validation for the boolean options `strict`, `trimValues`,
  `preserveNull`, `logPollution`. Each throws `TypeError("<name> must be a
boolean")` on misuse. Aligns with the README "fail loudly on bad config"
  contract (`src/index.ts`).
- **Added:** Validation for `whitelist` (must be string or string[] of
  strings); element-type validation for `whitelist`, `excludePaths`, and
  `sources`; rejection of empty `sources: []`
  (`src/index.ts`).

### Tests

- **Added:** New test suites and tests covering all the above
  changes (180 tests passing across 8 suites including the new
  `tests/hppx.express5.test.ts` and `tests/hppx.edgeruntime.test.ts`):
  - Express 5 integration with the lazy `req.query` getter
    (`tests/hppx.express5.test.ts`).
  - Prototype-poisoned `__hppxProcessed_*` flag bypass; verified the
    flag is non-enumerable on `req`
    (`tests/hppx.security.test.ts`).
  - Path-stack cycle detection: shared object/array subtrees, diamond
    graphs, self-cycles, cycles through arrays
    (`tests/hppx.security.test.ts`).
  - Control-character / bidirectional-override key rejection
    (`tests/hppx.security.test.ts`).
  - `req.path` getter throws (defensive read), with logger and
    no-logger paths (`tests/hppx.coverage.test.ts`).
  - Boolean-option validation; `whitelist` / `excludePaths` /
    `sources` element-type validation; empty `sources: []` rejection
    (`tests/hppx.security.test.ts`).
  - Cache-eviction tests for `pathSegmentCache` and whitelist
    `pathCache` (`tests/hppx.performance.test.ts`).
  - `combine`-strategy pollution-signal test
    (`tests/hppx.test.ts`).
  - Edge-runtime `process` undefined fallback
    (`tests/hppx.edgeruntime.test.ts`).
  - `setReqPropertySafe` writable + non-configurable branch; logger
    fallback to `console.warn` when configured logger throws;
    `__hppxProcessed_*` defineProperty-failure assignment fallback;
    `safeDeepClone` inner-clone WeakSet invariant
    (`tests/hppx.coverage.test.ts`).
  - Type-only smoke test asserting the augmentation is visible at
    consumer sites (`tests/types/express-augment.test-d.ts`).
- **Fixed:** Removed `setTimeout(0)`-based race in
  `tests/hppx.coverage.test.ts` for `Object.defineProperty` patch
  restoration. Patch is now installed in `beforeEach` and restored
  synchronously in `afterEach`.
- **Improved:** Logger-failure tests use `jest.spyOn(console, ...)` with
  `restoreMocks: true` (`jest.config.ts`) so no `[hppx] Logger failed`
  lines leak to stderr.
- **Strengthened:** Frozen-`req.query` test now asserts the polluted tree
  is captured AND a warning is surfaced via the configured logger
  instead of merely "no crash" (`tests/hppx.coverage.test.ts`).
- **Improved:** Coverage tightened to 99.72% statements / 95.30%
  branches / 100% functions / 100% lines. Each remaining
  `/* istanbul ignore */` annotation is documented with a comment
  explaining why the branch is unreachable from outside.

### Documentation

- **Added:** README "Multi-Middleware Stacking" section now documents
  which options (`whitelist`) are honored on subsequent middleware
  invocations vs. which are silently ignored (`mergeStrategy`,
  `strict`, `maxDepth`, etc.). Added a "Known Behaviors" subsection.
- **Added:** README mentions `req.params` augmentation appears as
  `req.paramsPolluted`. The `sanitize()` named-export note clarifies
  that only `SanitizeOptions` keys are honored — middleware-only keys
  (`sources`, `excludePaths`, `strict`, etc.) are silently ignored if
  passed.
- **Added:** README Security table updated to mention rejection of
  control characters and bidirectional override characters in keys.
- **Added:** Inline JSDoc on `parsePathSegments` documenting the lenient
  bracket/dot parse, with a security argument for why strict grammar
  enforcement is unnecessary given the upstream `sanitizeKey` checks
  (`src/index.ts`).

## v0.1.10 (Test Coverage Improvements)

- **Improved:** Test coverage now meets 95%+ on all metrics (100% statements, 95.09% branches, 100% functions, 100% lines)
- **Added:** 10 new meaningful test cases targeting previously uncovered code paths:
  - `safeDeepClone` array depth limiting and dangerous key filtering in nested arrays
  - `safeDeepClone` circular reference handling for arrays and objects inside arrays
  - `setIn` dangerous last-key protection (`__proto__`, `constructor` as final path segments)
  - `processNode` undefined value handling
  - Middleware error wrapping for non-Error thrown values
  - Body content-type absence handling
  - Whitelist path cache hit across multiple request sources
- **Fixed:** Replaced `require()` calls with proper ESM imports in `hppx.more.test.ts`
- **Added:** `/* istanbul ignore */` comments on 7 verified-unreachable defensive code branches with justification
- **Testing:** 111 total tests passing across 6 test suites

## v0.1.9 (Security & Bug Fix Audit)

- **Fixed:** `preserveNull: false` was a complete no-op — both ternary branches returned the same value (`src/index.ts:321`)
- **Fixed:** `expandObjectPaths` had no recursion depth limit, allowing stack overflow before `maxDepth` check
- **Fixed:** `safeDeepClone` had no recursion depth limit, same stack overflow risk
- **Fixed:** No circular reference protection in `expandObjectPaths` or `safeDeepClone` — added `WeakSet`-based cycle detection
- **Fixed:** `sanitize()` standalone function now validates options (same as `hppx()` middleware)
- **Fixed:** `validateOptions` now checks `logger` and `onPollutionDetected` are functions when provided
- **Refactored:** Extracted `validateSanitizeOptions()` for shared validation between `sanitize()` and `hppx()`
- **Testing:** Added 20 new tests covering all fixes (101 total tests passing)

## v0.1.8 (CommonJS IntelliSense - Exports Map Fix)

- **Fixed:** TypeScript now correctly uses `index.d.cts` for CommonJS via proper exports map
- **Changed:** Updated `package.json` exports to specify separate type paths for ESM and CommonJS
- **Note:** Full IntelliSense now works for `require("hppx")` without `.default`

## v0.1.7 (CommonJS IntelliSense - Namespace Pattern)

- **Added:** Function + namespace declaration pattern in `index.d.cts`
- **Note:** Required exports map fix in v0.1.8 to activate

## v0.1.6 (CommonJS IntelliSense Attempt)

- **Attempted:** TypeScript IntelliSense fix (incomplete)
- **Added:** Initial custom `index.d.cts` type definitions

## v0.1.5 (CommonJS Default Export Fix)

- **Fixed:** CommonJS default export now works correctly without requiring `.default`
- **Enhanced:** Added esbuild footer to properly merge default and named exports in CommonJS
- **Note:** Users can now use `require("hppx")()` directly instead of `require("hppx").default()`

## v0.1.4 (CommonJS Support & Pollution Logging)

- **Added:** Basic CommonJS support with `cjsInterop: true`
- **Added:** Automatic logging when pollution is detected (default: enabled)
- **Added:** `logPollution` option to control pollution logging (default: true)
- **Enhanced:** Logger now handles both errors and pollution warnings
- **Documentation:** Added CommonJS examples throughout README
- **Documentation:** Added custom logging examples

## v0.1.3 (Build Configuration Fix)

- **Fixed:** Build configuration to generate correct file extensions (.mjs for ESM, .cjs for CJS)
- **Fixed:** Module resolution errors when importing the package
- **Changed:** Updated tsup config to use `outExtension` for proper file naming
- **Testing:** All 81 tests passing with 97.09% statement coverage

## v0.1.2 (Changelog Added)

- **Added:** CHANGELOG.md to keep track of changes

## v0.1.1 (Security & Performance Update)

- **Security Enhancements:**
  - Added `maxArrayLength` to prevent memory exhaustion attacks
  - Added `maxKeyLength` to prevent long key DoS attacks
  - Enhanced prototype pollution protection in nested operations
  - Fixed validation of malformed keys (null bytes, bracket/dot-only keys)
  - Added comprehensive options validation with helpful error messages
- **Bug Fixes:**
  - Fixed `onPollutionDetected` callback receiving correct source information
  - Improved error handling with proper error propagation
- **Performance:**
  - Added path caching for faster whitelist checks
  - Added path segment caching to reduce parsing overhead
  - Optimized repeated sanitization operations
- **Developer Experience:**
  - Improved TypeScript types and removed unnecessary `any` types
  - Enhanced error messages and logging
  - Added comprehensive test suite for security features
