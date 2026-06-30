# hppx

**Superior HTTP Parameter Pollution protection middleware** for Node.js/Express, written in TypeScript. It sanitizes `req.query`, `req.body`, and `req.params`, blocks prototype-pollution keys, supports nested whitelists, multiple merge strategies, and plays nicely with stacked middlewares.

[![npm version](https://img.shields.io/npm/v/hppx)](https://www.npmjs.com/package/hppx)
[![CI](https://github.com/Hiprax/hppx/actions/workflows/ci.yml/badge.svg)](https://github.com/Hiprax/hppx/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Hiprax/hppx/actions/workflows/codeql.yml/badge.svg)](https://github.com/Hiprax/hppx/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/Hiprax/hppx/branch/main/graph/badge.svg)](https://codecov.io/gh/Hiprax/hppx)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/Hiprax/hppx/blob/main/package.json)
[![npm provenance](https://img.shields.io/badge/npm-provenance-success?logo=npm&logoColor=white)](https://www.npmjs.com/package/hppx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A518-green.svg)](https://nodejs.org/)

---

## Features

- **Zero runtime dependencies** — minimal attack surface and bundle size
- **Multiple merge strategies** — `keepFirst`, `keepLast` (default), `combine`
- **Enhanced security:**
  - Blocks dangerous keys: `__proto__`, `prototype`, `constructor`
  - Prevents null-byte injection in keys
  - Rejects malformed keys (dot/bracket-only patterns)
  - Validates key lengths to prevent DoS attacks
  - Limits array sizes to prevent memory exhaustion
- **Flexible whitelisting** — nested whitelist with dot-notation, leaf, and prefix/subtree matching
- **Pollution tracking** — records polluted parameters on the request (`queryPolluted`, `bodyPolluted`, `paramsPolluted`)
- **Multi-middleware support** — works with multiple middlewares on different routes (whitelists applied incrementally)
- **DoS protection** — `maxDepth`, `maxKeys`, `maxArrayLength`, `maxKeyLength`
- **Performance optimized** — path caching and Set-based lookups for fast whitelist checks
- **Fully typed API** — TypeScript-first with comprehensive type definitions for both ESM and CommonJS

---

## Installation

```bash
npm install hppx
```

---

## Quick Start

### ESM (ES Modules)

```typescript
import express from "express";
import hppx from "hppx";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  hppx({
    whitelist: ["tags", "user.roles", "ids"],
    mergeStrategy: "keepLast",
    sources: ["query", "body"],
  }),
);

app.get("/search", (req, res) => {
  res.json({
    query: req.query,
    queryPolluted: req.queryPolluted ?? {},
    body: req.body ?? {},
    bodyPolluted: req.bodyPolluted ?? {},
    params: req.params,
    paramsPolluted: req.paramsPolluted ?? {},
  });
});
```

### CommonJS

```javascript
const express = require("express");
const hppx = require("hppx");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  hppx({
    whitelist: ["tags", "user.roles", "ids"],
    mergeStrategy: "keepLast",
    sources: ["query", "body"],
  }),
);

app.get("/search", (req, res) => {
  res.json({
    query: req.query,
    queryPolluted: req.queryPolluted ?? {},
    body: req.body ?? {},
    bodyPolluted: req.bodyPolluted ?? {},
    params: req.params,
    paramsPolluted: req.paramsPolluted ?? {},
  });
});
```

### Polluted Parameter Tree

For each enabled source, hppx attaches a parallel `*Polluted` object to the
request that records the original (pre-reduction) array values for any keys
that were detected as polluted:

| Source   | Cleaned data on `req` | Polluted tree on `req` |
| -------- | --------------------- | ---------------------- |
| `query`  | `req.query`           | `req.queryPolluted`    |
| `body`   | `req.body`            | `req.bodyPolluted`     |
| `params` | `req.params`          | `req.paramsPolluted`   |

These properties are typed via a TypeScript module augmentation included in
the published types — no extra import is needed.

---

## API

### Default Export: `hppx(options?: HppxOptions)`

Creates an Express-compatible middleware. Applies sanitization to each selected source and exposes `*.Polluted` objects on the request.

> **Note:** Invalid options throw a `TypeError` at middleware creation time, not at request time. This ensures misconfiguration is caught early.

#### Options

**Whitelist & Strategy:**

| Option          | Type                                     | Default      | Description                                                                                                                                                                                                                        |
| --------------- | ---------------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `whitelist`     | `string[] \| string`                     | `[]`         | Keys allowed to remain as arrays. Supports exact dot-notation (`"user.tags"`), leaf matching (`"tags"` matches any path ending in `tags`), and prefix/subtree matching (`"user"` whitelists every key under the `user.*` subtree). |
| `mergeStrategy` | `'keepFirst' \| 'keepLast' \| 'combine'` | `'keepLast'` | How to reduce duplicate/array parameters when not whitelisted. `keepFirst` takes the first value, `keepLast` takes the last, `combine` flattens all values into a single array.                                                    |

**Source Selection:**

| Option                 | Type                                   | Default                       | Description                                                                                                                                           |
| ---------------------- | -------------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sources`              | `Array<'query' \| 'body' \| 'params'>` | `['query', 'body', 'params']` | Which request parts to sanitize.                                                                                                                      |
| `checkBodyContentType` | `'urlencoded' \| 'any' \| 'none'`      | `'urlencoded'`                | When to process `req.body`. `urlencoded` only processes URL-encoded bodies, `any` processes all content types, `none` skips body processing entirely. |
| `excludePaths`         | `string[]`                             | `[]`                          | Paths to exclude from sanitization. Supports `*` wildcard suffix (e.g., `"/assets*"`).                                                                |

**Security Limits (DoS Protection):**

| Option           | Type     | Default | Range    | Description                                                                           |
| ---------------- | -------- | ------- | -------- | ------------------------------------------------------------------------------------- |
| `maxDepth`       | `number` | `20`    | 1 - 100  | Maximum object nesting depth. Exceeding this throws an error passed to `next()`.      |
| `maxKeys`        | `number` | `5000`  | >= 1     | Maximum number of keys to process. Exceeding this throws an error passed to `next()`. |
| `maxArrayLength` | `number` | `1000`  | >= 1     | Maximum array length. Arrays are truncated before processing.                         |
| `maxKeyLength`   | `number` | `200`   | 1 - 1000 | Maximum key string length. Longer keys are silently dropped.                          |

> **Note — in-order, in-place commit model:** Sources are processed in the order specified by the `sources` array and each source's sanitized result is committed in-place to `req` before the next source begins. When `maxDepth` or `maxKeys` is exceeded, the error is forwarded to `next()` immediately — but **any earlier sources that already completed are already sanitized on `req`** while the throwing source stays raw. Error handlers should not assume an atomic all-or-nothing transform across sources.

**Behavior & Callbacks:**

| Option                | Type                              | Default | Description                                                                                                                                                                                              |
| --------------------- | --------------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `trimValues`          | `boolean`                         | `false` | Trim whitespace from string values.                                                                                                                                                                      |
| `preserveNull`        | `boolean`                         | `true`  | Preserve `null` values in the output.                                                                                                                                                                    |
| `strict`              | `boolean`                         | `false` | Immediately respond with HTTP 400 when pollution is detected. Response includes `error`, `message`, `pollutedParameters`, and `code` (`"HPP_DETECTED"`) fields.                                          |
| `onPollutionDetected` | `(req, info) => void`             | —       | Callback fired on pollution detection. Called **once per polluted source** (e.g., fires twice if both query and body are polluted). `info` contains `{ source: RequestSource, pollutedKeys: string[] }`. |
| `logger`              | `(err: Error \| unknown) => void` | —       | Custom logger for errors and pollution warnings. Receives `string` for pollution warnings and `Error` for caught errors. Falls back to `console.warn`/`console.error` if the logger throws.              |
| `logPollution`        | `boolean`                         | `true`  | Enable automatic logging when pollution is detected.                                                                                                                                                     |

---

### Named Export: `sanitize(input, options?)`

```typescript
function sanitize<T extends Record<string, unknown>>(input: T, options?: SanitizeOptions): T;
```

Sanitize a plain object using the same rules as the middleware.

**Return shape:** `sanitize()` returns **only** the cleaned object — the
same shape as `input`, with arrays reduced according to the chosen merge
strategy. It does **not** return the internal `SanitizedResult`
(`{ cleaned, pollutedTree, pollutedKeys }`); polluted-tree data is
deliberately discarded. If you need access to the polluted tree or polluted
keys, use the middleware factory `hppx()` and read `req.queryPolluted` /
`req.bodyPolluted` / `req.paramsPolluted` instead.

**Options:** `sanitize()` accepts only `SanitizeOptions` —
`whitelist`, `mergeStrategy`, `maxDepth`, `maxKeys`, `maxArrayLength`,
`maxKeyLength`, `trimValues`, and `preserveNull`. Middleware-only options
(`sources`, `excludePaths`, `strict`, `onPollutionDetected`, `logger`,
`logPollution`, `checkBodyContentType`) are silently ignored when passed
to `sanitize()` — use `hppx()` if you need any of those features.

**ESM:**

```typescript
import { sanitize } from "hppx";

const clean = sanitize(payload, {
  whitelist: ["user.tags"],
  mergeStrategy: "keepFirst",
});
```

**CommonJS:**

```javascript
const { sanitize } = require("hppx");

const clean = sanitize(payload, {
  whitelist: ["user.tags"],
  mergeStrategy: "keepFirst",
});
```

---

### Exported Types

All types are available for both ESM and CommonJS consumers:

```typescript
import type {
  RequestSource, // "query" | "body" | "params"
  MergeStrategy, // "keepFirst" | "keepLast" | "combine"
  SanitizeOptions, // Options for sanitize()
  HppxOptions, // Full middleware options (extends SanitizeOptions)
  SanitizedResult, // { cleaned, pollutedTree, pollutedKeys }
} from "hppx";
```

### Exported Constants

```typescript
import { DANGEROUS_KEYS, DEFAULT_SOURCES, DEFAULT_STRATEGY } from "hppx";

DANGEROUS_KEYS; // Set<string> — {"__proto__", "prototype", "constructor"}
DEFAULT_SOURCES; // ["query", "body", "params"]
DEFAULT_STRATEGY; // "keepLast"
```

---

## Advanced Usage

### Strict Mode (Respond 400 on Pollution)

```typescript
app.use(hppx({ strict: true }));

// Polluted requests receive:
// {
//   "error": "Bad Request",
//   "message": "HTTP Parameter Pollution detected",
//   "pollutedParameters": ["query.x"],
//   "code": "HPP_DETECTED"
// }
```

### Process JSON Bodies Too

```typescript
app.use(express.json());
app.use(hppx({ checkBodyContentType: "any" }));
```

### Exclude Specific Paths

```typescript
app.use(hppx({ excludePaths: ["/public", "/assets*"] }));
```

### Custom Logging

```typescript
// Use your application's logger
app.use(
  hppx({
    logger: (msg) => {
      if (typeof msg === "string") {
        myLogger.warn(msg); // Pollution warnings
      } else {
        myLogger.error(msg); // Errors
      }
    },
  }),
);

// Disable automatic pollution logging
app.use(hppx({ logPollution: false }));
```

### Multi-Middleware Stacking

hppx supports incremental whitelisting across multiple middleware instances. Each subsequent middleware applies its own whitelist to the already-collected polluted data:

```typescript
// Global middleware — whitelist "a"
app.use(hppx({ whitelist: ["a"] }));

// Route-level middleware — additionally whitelist "b" and "c"
const router = express.Router();
router.use(hppx({ whitelist: ["b", "c"] }));

// On this route, "a", "b", and "c" are all allowed as arrays
router.get("/data", (req, res) => {
  res.json({ query: req.query });
});

app.use("/api", router);
```

#### Option Precedence Across Stacked Middleware

When the same source (`query` / `body` / `params`) has already been processed by an
earlier `hppx()` instance on the same request, a subsequent `hppx()` only applies its
own **`whitelist`** — used to restore additional whitelisted entries from the
polluted tree the first middleware already collected. Every other option on the
later instance is **silently ignored for that source** because the source is no
longer available in its original (un-reduced) form.

The options ignored on subsequent middleware (per-source) are:

- `mergeStrategy`
- `maxDepth`, `maxKeys`, `maxArrayLength`, `maxKeyLength`
- `trimValues`, `preserveNull`
- `strict` (will **not** trigger HTTP 400 if the earlier middleware already cleaned the source)
- `onPollutionDetected`, `logger`, `logPollution`
- `excludePaths` is checked per-instance (independent of the processed flag), but
  if the source was already processed, only whitelist restoration runs.

**Footgun example:**

```typescript
// Global middleware — keepLast strategy, no strict mode
app.use(hppx({ mergeStrategy: "keepLast" }));

// Route-level middleware — strict mode, but it's TOO LATE
app.use(
  "/api/admin",
  hppx({ strict: true }), // SILENTLY IGNORED — the source was already
  // cleaned by the global middleware, so strict
  // mode here will NOT cause a 400 response.
);
```

If you need strict mode on a specific route, configure `strict: true` on the
**first** `hppx()` instance that processes the relevant source — typically the
global middleware. Equivalent options (`maxDepth`, `mergeStrategy`, callbacks,
loggers) must likewise be set on the first instance. Subsequent instances are
useful only for **expanding** the whitelist to recover additional fields from
`req.queryPolluted`/`req.bodyPolluted`/`req.paramsPolluted` on a per-route basis.

A subsequent middleware can only ever _expand_ the whitelist (by restoring more
fields back from the polluted tree). It cannot restrict an already-whitelisted
field, because the previous middleware has already moved that field back into
the source.

### Pollution Detection Callback

```typescript
app.use(
  hppx({
    onPollutionDetected: (req, info) => {
      // Called once per polluted source (query, body, params)
      securityLogger.warn("HPP detected", {
        source: info.source,
        pollutedKeys: info.pollutedKeys,
      });
    },
  }),
);
```

---

## Security

### What hppx Protects Against

| Threat                       | Protection                                                                                                                                                                                 |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Parameter pollution**      | Duplicate parameters are reduced to a single value via the chosen merge strategy                                                                                                           |
| **Prototype pollution**      | `__proto__`, `constructor`, `prototype` keys are blocked at every processing level                                                                                                         |
| **DoS via deep nesting**     | `maxDepth` limit throws error on excessive nesting                                                                                                                                         |
| **DoS via key flooding**     | `maxKeys` limit throws error when key count is exceeded                                                                                                                                    |
| **DoS via large arrays**     | `maxArrayLength` truncates arrays before processing                                                                                                                                        |
| **DoS via long keys**        | `maxKeyLength` silently drops excessively long keys                                                                                                                                        |
| **Null-byte injection**      | Keys containing `\u0000` are silently dropped                                                                                                                                              |
| **Control / bidi key chars** | Keys containing ASCII / C1 control characters (`\x00`-`\x1F`, `\x7F`-`\x9F`) or Unicode bidirectional override characters (LRM/RLM, LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI, BOM) are dropped |
| **Malformed keys**           | Keys consisting only of dots/brackets (e.g., `"..."`, `"[["`) are dropped                                                                                                                  |

### Production Configuration

```typescript
app.use(
  hppx({
    maxDepth: 10,
    maxKeys: 1000,
    maxArrayLength: 100,
    maxKeyLength: 100,
    strict: true,
    onPollutionDetected: (req, info) => {
      securityLogger.warn("HPP detected", {
        ip: req.ip,
        path: req.path,
        source: info.source,
        pollutedKeys: info.pollutedKeys,
      });
    },
  }),
);
```

### Express 5 Note

In Express 5, `req.query` is exposed as a lazy getter on the prototype chain rather than
an own property. hppx handles this transparently: it uses `Object.defineProperty` to
install the sanitized value as a writable own property that shadows the proto-level
getter. After the middleware runs, `req.query` reflects the cleaned value (e.g.
`req.query.x === "2"` after `?x=1&x=2` with `mergeStrategy: "keepLast"`).

If a downstream layer makes `req.query` non-configurable AND non-writable before hppx
runs (uncommon), hppx will not silently leave the polluted value in place — it will
emit a warning via the configured `logger` (or `console.warn` if none is provided) so
the misconfiguration is visible. The warning is de-duplicated per request and per
source.

### What hppx Does NOT Protect Against

hppx is not a complete security solution. You still need:

- **SQL injection protection** — use parameterized queries
- **XSS protection** — sanitize output, use CSP headers
- **CSRF protection** — use CSRF tokens
- **Authentication/Authorization** — validate user permissions
- **Rate limiting** — prevent brute-force attacks
- **Input validation** — use schema validation libraries (Joi, Yup, Zod) alongside hppx

---

## FAQ / Known Behaviors

A short reference for behaviors that surprise people most often.

**1. The `combine` strategy still records pollution.**
Earlier versions silently dropped pollution events when `mergeStrategy: "combine"`
was in effect, because the array was preserved as-is. This was a footgun for
security logging. Today, `combine` records polluted keys into `req.queryPolluted`
(etc.) and fires `onPollutionDetected` and `logPollution` exactly like the other
strategies — the cleaned data simply contains the flattened array rather than a
reduced single value.

**2. Multi-middleware: subsequent passes only honor `whitelist`.**
When two `hppx()` instances run on the same request (e.g. global + router), the
second one only applies its own `whitelist` — to restore additional fields out
of the polluted tree the first instance already collected. All other options
(`mergeStrategy`, `strict`, `onPollutionDetected`, limits, etc.) on the second
instance are silently ignored for any source the first instance already
processed. See **Multi-Middleware Stacking → Option Precedence** above for the
full list. Configure `strict: true`, callbacks, and limits on the **first**
`hppx()` that processes the source — typically the global middleware.

**3. Express 5 frozen `req.query` fallback.**
Express 5 exposes `req.query` as a lazy getter on the prototype chain. hppx
shadows it with a writable own property carrying the cleaned value. If an
unusual downstream layer makes `req.query` non-configurable AND non-writable
before hppx runs, hppx will emit a warning via the configured `logger` (or
`console.warn`) instead of silently leaving the polluted array in place.

**4. Control / bidirectional override characters in keys are rejected.**
Keys containing ASCII / C1 control characters (`\x00`-`\x1F`, `\x7F`-`\x9F`),
Unicode bidirectional override characters (LRM/RLM, LRE/RLE/PDF/LRO/RLO,
LRI/RLI/FSI/PDI), or BOM (`﻿`) are silently dropped. This prevents
log-injection / DB-corruption tricks that use invisible control characters
to disguise key names.

**5. `sanitize()` returns only the cleaned object.**
The standalone `sanitize()` function returns the same shape as its input, with
arrays reduced. It does **not** return `{cleaned, pollutedTree, pollutedKeys}`
— if you need the polluted tree, use the middleware factory `hppx()` and read
`req.queryPolluted` / `req.bodyPolluted` / `req.paramsPolluted`. Middleware-only
options (`sources`, `excludePaths`, `strict`, callbacks, etc.) are silently
ignored when passed to `sanitize()`.

**6. `whitelist` is a data-preservation control; `strict` / `logPollution` are wire-level detection signals.**

These two concerns are deliberately independent:

- **`whitelist`** controls what happens _after_ reduction. Whitelisted keys have their raw
  arrays moved back from the polluted tree into `req.query` (etc.) and are pruned from
  `req.queryPolluted`. The route handler sees the original multi-value array for whitelisted
  keys — they are not further reduced.
- **`strict`** and **`logPollution`** are driven by pre-restoration data — the `pollutedKeys`
  set returned by `detectAndReduce` captures every parameter that arrived duplicated on the
  wire, regardless of whitelist configuration. Because `anyPollutionDetected` is set from
  that pre-restoration snapshot, a whitelisted key that arrives duplicated on the wire still
  causes `strict: true` to return HTTP 400 and `logPollution: true` to emit a warning.

If you need certain keys to carry multiple values without triggering strict mode, do not use
`strict: true` in combination with `whitelist` for those keys — or handle those keys in a
separate, non-strict middleware.

**7. `onPollutionDetected` and `req.*Polluted` reflect the post-restoration state.**

After `detectAndReduce` collects all duplicated keys, `moveWhitelistedFromPolluted` restores
whitelisted entries back into `req.query` (etc.) and prunes them from `req.queryPolluted`.
Two consequences:

- `req.queryPolluted` (and `req.bodyPolluted`, `req.paramsPolluted`) never contains whitelisted
  keys — they have already been moved back to the main request object.
- `onPollutionDetected` is invoked only when `req.queryPolluted` is **non-empty** after
  restoration. If _all_ polluted keys are whitelisted, the polluted tree is `{}` after
  restoration and the callback is **not** called (even though `logPollution` still fires for
  the wire-level signal). If _some_ (but not all) keys are whitelisted, the callback fires for
  that source — and its `info.pollutedKeys` array contains **all** pre-restoration polluted
  keys (both whitelisted and non-whitelisted ones).

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Links

- [NPM Package](https://www.npmjs.com/package/hppx)
- [GitHub Repository](https://github.com/Hiprax/hppx)
- [Issue Tracker](https://github.com/Hiprax/hppx/issues)
- [Changelog](CHANGELOG.md)
