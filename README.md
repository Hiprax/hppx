# hppx

🔐 **Superior HTTP Parameter Pollution protection middleware** for Node.js/Express, written in TypeScript. It sanitizes `req.query`, `req.body`, and `req.params`, blocks prototype-pollution keys, supports nested whitelists, multiple merge strategies, and plays nicely with stacked middlewares.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-16+-green.svg)](https://nodejs.org/)

## Features

- **Multiple merge strategies**: `keepFirst`, `keepLast` (default), `combine`
- **Enhanced security**:
  - Blocks dangerous keys: `__proto__`, `prototype`, `constructor`
  - Prevents null-byte injection in keys
  - Validates key lengths to prevent DoS attacks
  - Limits array sizes to prevent memory exhaustion
- **Flexible whitelisting**: Nested whitelist with dot-notation and leaf matching
- **Pollution tracking**: Records polluted parameters on the request (`queryPolluted`, `bodyPolluted`, `paramsPolluted`)
- **Multi-middleware support**: Works with multiple middlewares on different routes (whitelists applied incrementally)
- **DoS protection**: `maxDepth`, `maxKeys`, `maxArrayLength`, `maxKeyLength`
- **Performance optimized**: Path caching for improved performance
- **Fully typed API**: TypeScript-first with comprehensive type definitions and helper functions (`sanitize`)

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
  }),
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

#### Key Options

**Whitelist & Strategy:**

- `whitelist?: string[]` — keys allowed as arrays; supports dot-notation; leaf matches too
- `mergeStrategy?: 'keepFirst'|'keepLast'|'combine'` — how to reduce arrays when not whitelisted

**Source Selection:**

- `sources?: Array<'query'|'body'|'params'>` — which request parts to sanitize (default: all)
- `checkBodyContentType?: 'urlencoded'|'any'|'none'` — when to process `req.body` (default: `urlencoded`)
- `excludePaths?: string[]` — exclude specific paths (supports `*` wildcard suffix)

**Security Limits (DoS Protection):**

- `maxDepth?: number` — maximum object nesting depth (default: 20, max: 100)
- `maxKeys?: number` — maximum number of keys to process (default: 5000)
- `maxArrayLength?: number` — maximum array length (default: 1000)
- `maxKeyLength?: number` — maximum key string length (default: 200, max: 1000)

**Additional Options:**

- `trimValues?: boolean` — trim string values (default: false)
- `preserveNull?: boolean` — preserve null values (default: true)
- `strict?: boolean` — if pollution detected, immediately respond with 400 error
- `onPollutionDetected?: (req, info) => void` — callback on pollution detection
- `logger?: (err: Error) => void` — custom error logger

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
app.use(hppx({ checkBodyContentType: "any" }));
```

- Exclude specific paths (supports `*` suffix):

```ts
app.use(hppx({ excludePaths: ["/public", "/assets*"] }));
```

- Use the sanitizer directly:

```ts
import { sanitize } from "hppx";

const clean = sanitize(payload, {
  whitelist: ["user.tags"],
  mergeStrategy: "keepFirst",
});
```

## Security Best Practices

### Input Validation

Always combine HPP protection with additional input validation:

- Use schema validation libraries (e.g., Joi, Yup, Zod)
- Validate data types and ranges after sanitization
- Never trust user input, even after sanitization

### Configuration Recommendations

For production environments, consider these settings:

```ts
app.use(
  hppx({
    maxDepth: 10, // Lower depth for typical use cases
    maxKeys: 1000, // Reasonable limit for most requests
    maxArrayLength: 100, // Prevent large array attacks
    maxKeyLength: 100, // Shorter keys for most applications
    strict: true, // Return 400 on pollution attempts
    onPollutionDetected: (req, info) => {
      // Log security events for monitoring
      securityLogger.warn("HPP detected", {
        ip: req.ip,
        path: req.path,
        pollutedKeys: info.pollutedKeys,
      });
    },
  }),
);
```

### What HPP Protects Against

- **Parameter pollution**: Duplicate parameters causing unexpected behavior
- **Prototype pollution**: Attacks via `__proto__`, `constructor`, `prototype`
- **DoS attacks**: Excessive nesting, too many keys, huge arrays
- **Null-byte injection**: Keys containing null characters (`\u0000`)

### What HPP Does NOT Protect Against

HPP is not a complete security solution. You still need:

- **SQL injection protection**: Use parameterized queries
- **XSS protection**: Sanitize output, use CSP headers
- **CSRF protection**: Use CSRF tokens
- **Authentication/Authorization**: Validate user permissions
- **Rate limiting**: Prevent brute-force attacks

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- [NPM Package](https://www.npmjs.com/package/hppx)
- [GitHub Repository](https://github.com/Hiprax/hppx)
- [Issue Tracker](https://github.com/Hiprax/hppx/issues)

---

### **Made with ❤️ for secure applications**
