# hppx

🔐 **Superior HTTP Parameter Pollution protection middleware** for Node.js/Express, written in TypeScript. It sanitizes `req.query`, `req.body`, and `req.params`, blocks prototype-pollution keys, supports nested whitelists, multiple merge strategies, and plays nicely with stacked middlewares.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)

## Features

- Array merging strategies: `keepFirst`, `keepLast` (default), `combine`
- Safe-by-default: blocks `__proto__`, `prototype`, `constructor`
- Nested whitelist with dot-notation and leaf matching
- Records polluted parameters on the request (`queryPolluted`, `bodyPolluted`, `paramsPolluted`)
- Works with multiple middlewares on different routes (whitelists applied incrementally)
- DoS-guards: `maxDepth`, `maxKeys`
- Fully typed API and helpers (`sanitize`)

## 📦 Installation

```bash
npm install hppx
```

## Usage

```ts
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
  })
);

app.get("/search", (req, res) => {
  res.json({
    query: req.query,
    queryPolluted: req.queryPolluted ?? {},
    body: req.body ?? {},
    bodyPolluted: req.bodyPolluted ?? {},
  });
});
```

## API

### default export: `hppx(options?: HppxOptions)`

Creates an Express-compatible middleware. Applies sanitization to each selected source and exposes `*.Polluted` objects.

Key options:

- `whitelist?: string[]` — keys allowed as arrays; supports dot-notation; leaf matches too
- `mergeStrategy?: 'keepFirst'|'keepLast'|'combine'` — how to reduce arrays when not whitelisted
- `sources?: Array<'query'|'body'|'params'>` — which request parts to sanitize
- `checkBodyContentType?: 'urlencoded'|'any'|'none'` — when to process `req.body` (default: `urlencoded`)
- `excludePaths?: string[]` — exclude specific paths (supports `*` suffix)
- `maxDepth?: number` and `maxKeys?: number` — DoS protections
- `strict?: boolean` — if pollution detected, immediately respond 400
- `onPollutionDetected?: (req, info) => void` — callback on detection

### named export: `sanitize(input, options)`

Sanitize an arbitrary object using the same rules as the middleware. Useful for manual usage.

## Advanced usage

- Strict mode (respond 400 on pollution):

```ts
app.use(hppx({ strict: true }));
```

- Process JSON bodies too:

```ts
app.use(express.json());
app.use(hppx({ checkBodyContentType: 'any' }));
```

- Exclude specific paths (supports `*` suffix):

```ts
app.use(hppx({ excludePaths: ['/public', '/assets*'] }));
```

- Use the sanitizer directly:

```ts
import { sanitize } from 'hppx';

const clean = sanitize(payload, {
  whitelist: ['user.tags'],
  mergeStrategy: 'keepFirst',
});
```

## Notes

- Arrays are reduced by default; whitelisted paths are preserved as arrays.
- Dangerous keys like `__proto__`, `prototype`, `constructor` are removed.
- DoS protections are available via `maxDepth` and `maxKeys`.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- [NPM Package](https://www.npmjs.com/package/@hiprax/hppx)
- [GitHub Repository](https://github.com/Hiprax/hppx)
- [Issue Tracker](https://github.com/Hiprax/hppx/issues)

---

### **Made with ❤️ for secure applications**
