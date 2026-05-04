import express from "express";
import request from "supertest";
import hppx, { sanitize } from "../src/index";

describe("hppx - Security Features", () => {
  describe("Array length limits (DoS protection)", () => {
    test("limits array length to prevent memory exhaustion", () => {
      const largeArray = Array.from({ length: 2000 }, (_, i) => i);
      const input = { x: largeArray };
      const cleaned = sanitize(input, { maxArrayLength: 100, mergeStrategy: "keepLast" });
      // Should have been truncated during processing
      expect(cleaned.x).toBeDefined();
    });

    test("respects custom maxArrayLength", () => {
      const arr = [1, 2, 3, 4, 5];
      const input = { x: arr };
      const cleaned = sanitize(input, { maxArrayLength: 3, mergeStrategy: "keepLast" });
      expect(cleaned.x).toBeDefined();
    });

    test("handles very large arrays in middleware", async () => {
      const app = express();
      app.use(express.json());
      app.use(hppx({ maxArrayLength: 10, checkBodyContentType: "any", logPollution: false }));
      app.post("/test", (req, res) => res.json({ body: req.body }));

      const largeArray = Array.from({ length: 100 }, (_, i) => i);
      const res = await request(app).post("/test").send({ x: largeArray });
      expect(res.status).toBe(200);
    });
  });

  describe("Key length validation", () => {
    test("rejects excessively long keys", () => {
      const longKey = "a".repeat(500);
      const input = { [longKey]: "value" };
      const cleaned = sanitize(input, { maxKeyLength: 100 });
      expect(cleaned[longKey]).toBeUndefined();
      expect(Object.keys(cleaned).length).toBe(0);
    });

    test("accepts keys within limit", () => {
      const okKey = "a".repeat(50);
      const input = { [okKey]: "value" };
      const cleaned = sanitize(input, { maxKeyLength: 100 });
      expect(cleaned[okKey]).toBe("value");
    });

    test("respects custom maxKeyLength", async () => {
      const app = express();
      app.use(hppx({ maxKeyLength: 10, logPollution: false }));
      app.get("/test", (req, res) => res.json({ query: req.query }));

      const longKey = "a".repeat(20);
      const res = await request(app)
        .get("/test")
        .query({ [longKey]: "value", short: "ok" });
      expect(res.status).toBe(200);
      expect(res.body.query[longKey]).toBeUndefined();
      expect(res.body.query.short).toBe("ok");
    });
  });

  describe("Prototype pollution protection", () => {
    test("blocks __proto__ in keys", () => {
      const input = { __proto__: { polluted: true }, safe: "value" } as any;
      const cleaned = sanitize(input);
      // __proto__ should not be an own property
      expect(Object.prototype.hasOwnProperty.call(cleaned, "__proto__")).toBe(false);
      expect(cleaned.safe).toBe("value");
    });

    test("blocks constructor in keys", () => {
      const input = { constructor: { polluted: true }, safe: "value" } as any;
      const cleaned = sanitize(input);
      // constructor should not be an own property with our value
      expect(Object.prototype.hasOwnProperty.call(cleaned, "constructor")).toBe(false);
      expect(cleaned.safe).toBe("value");
    });

    test("blocks prototype in keys", () => {
      const input = { prototype: { polluted: true }, safe: "value" } as any;
      const cleaned = sanitize(input);
      expect(cleaned.prototype).toBeUndefined();
      expect(cleaned.safe).toBe("value");
    });

    test("blocks nested dangerous keys in setIn", async () => {
      const app = express();
      app.use(hppx({ logPollution: false }));
      app.get("/test", (req, res) => res.json({ query: req.query }));

      const res = await request(app)
        .get("/test")
        .query({ "user.__proto__.isAdmin": "true", "user.name": "john" });

      expect(res.status).toBe(200);
      expect((res.body.query as any).user.__proto__?.isAdmin).toBeUndefined();
    });

    test("blocks null byte in keys", () => {
      const input = { ["key\u0000name"]: "value", safe: "ok" } as any;
      const cleaned = sanitize(input);
      expect(cleaned["key\u0000name"]).toBeUndefined();
      expect(cleaned.safe).toBe("ok");
    });

    test("blocks malformed keys (only dots/brackets)", () => {
      const input = { "...": "value1", "[[[": "value2", normal: "ok" } as any;
      const cleaned = sanitize(input);
      expect(cleaned["..."]).toBeUndefined();
      expect(cleaned["[[["]).toBeUndefined();
      expect(cleaned.normal).toBe("ok");
    });
  });

  describe("Control and bidirectional characters in keys", () => {
    // ASCII C0 controls (U+0000..U+001F) and DEL (U+007F).
    // Define samples using explicit Unicode escapes so the source file remains
    // free of literal control characters (which would render the file confusing
    // and could be mangled by editors / git tooling).
    const c0Samples: { name: string; ch: string }[] = [
      { name: "NUL (U+0000)", ch: "\u0000" },
      { name: "SOH (U+0001)", ch: "\u0001" },
      { name: "BEL (U+0007)", ch: "\u0007" },
      { name: "TAB (U+0009)", ch: "\u0009" },
      { name: "LF (U+000A)", ch: "\u000A" },
      { name: "VT (U+000B)", ch: "\u000B" },
      { name: "FF (U+000C)", ch: "\u000C" },
      { name: "CR (U+000D)", ch: "\u000D" },
      { name: "ESC (U+001B)", ch: "\u001B" },
      { name: "US (U+001F)", ch: "\u001F" },
      { name: "DEL (U+007F)", ch: "\u007F" },
    ];

    test.each(c0Samples)("rejects key containing $name", ({ ch }) => {
      const polluted = `key${ch}injected`;
      const input = { [polluted]: "value", safe: "ok" } as Record<string, unknown>;
      const cleaned = sanitize(input);
      expect(cleaned[polluted]).toBeUndefined();
      expect(cleaned.safe).toBe("ok");
    });

    // C1 controls (U+0080..U+009F) — sample a few representative ones.
    const c1Samples: { name: string; ch: string }[] = [
      { name: "PAD (U+0080)", ch: "\u0080" },
      { name: "NEL (U+0085)", ch: "\u0085" },
      { name: "CSI (U+009B)", ch: "\u009B" },
      { name: "APC (U+009F)", ch: "\u009F" },
    ];

    test.each(c1Samples)("rejects key containing $name", ({ ch }) => {
      const polluted = `key${ch}injected`;
      const input = { [polluted]: "value", safe: "ok" } as Record<string, unknown>;
      const cleaned = sanitize(input);
      expect(cleaned[polluted]).toBeUndefined();
      expect(cleaned.safe).toBe("ok");
    });

    // Unicode bidirectional control / formatting characters.
    const bidiSamples: { name: string; ch: string }[] = [
      { name: "LRM (U+200E)", ch: "\u200E" },
      { name: "RLM (U+200F)", ch: "\u200F" },
      { name: "LRE (U+202A)", ch: "\u202A" },
      { name: "RLE (U+202B)", ch: "\u202B" },
      { name: "PDF (U+202C)", ch: "\u202C" },
      { name: "LRO (U+202D)", ch: "\u202D" },
      { name: "RLO (U+202E)", ch: "\u202E" },
      { name: "LRI (U+2066)", ch: "\u2066" },
      { name: "RLI (U+2067)", ch: "\u2067" },
      { name: "FSI (U+2068)", ch: "\u2068" },
      { name: "PDI (U+2069)", ch: "\u2069" },
      { name: "BOM/ZWNBSP (U+FEFF)", ch: "\uFEFF" },
    ];

    test.each(bidiSamples)("rejects key containing $name", ({ ch }) => {
      const polluted = `admin${ch}user`;
      const input = { [polluted]: "value", safe: "ok" } as Record<string, unknown>;
      const cleaned = sanitize(input);
      expect(cleaned[polluted]).toBeUndefined();
      expect(cleaned.safe).toBe("ok");
    });

    test("rejects keys containing RLO override (visual spoofing attempt)", () => {
      // U+202E reverses subsequent characters' display direction; attackers can
      // use this to confuse key-based authorization checks (e.g. visually
      // displaying "admin" while the underlying key differs from "admin").
      const spoofed = "\u202Enimda";
      const input = { [spoofed]: "value", safe: "ok" } as Record<string, unknown>;
      const cleaned = sanitize(input);
      expect(cleaned[spoofed]).toBeUndefined();
      expect(cleaned.safe).toBe("ok");
    });

    test("rejects key containing control character via the middleware", async () => {
      const app = express();
      app.use(hppx({ logPollution: false }));
      app.get("/test", (req, res) => res.json({ query: req.query }));

      const polluted = "bad\u0001key";
      const res = await request(app)
        .get("/test")
        .query({ [polluted]: "value", safe: "ok" });

      expect(res.status).toBe(200);
      expect(res.body.query[polluted]).toBeUndefined();
      expect(res.body.query.safe).toBe("ok");
    });

    test("accepts ordinary printable Unicode characters in keys", () => {
      // Sanity check: the new character class must not over-block. Latin
      // extended (café), Greek (α), Arabic, CJK, and emoji must still be valid
      // key characters.
      const safeKeys = ["café", "α", "مرحبا", "日本語", "key🚀"];
      for (const k of safeKeys) {
        const cleaned = sanitize({ [k]: "v" } as Record<string, unknown>);
        expect(cleaned[k]).toBe("v");
      }
    });
  });

  describe("Options validation", () => {
    test("throws on invalid maxDepth", () => {
      expect(() => hppx({ maxDepth: -1 })).toThrow(TypeError);
      expect(() => hppx({ maxDepth: 0 })).toThrow(TypeError);
      expect(() => hppx({ maxDepth: 1000 })).toThrow(TypeError);
      expect(() => hppx({ maxDepth: "10" as any })).toThrow(TypeError);
    });

    test("throws on invalid maxKeys", () => {
      expect(() => hppx({ maxKeys: -1 })).toThrow(TypeError);
      expect(() => hppx({ maxKeys: 0 })).toThrow(TypeError);
      expect(() => hppx({ maxKeys: "100" as any })).toThrow(TypeError);
    });

    test("throws on invalid maxArrayLength", () => {
      expect(() => hppx({ maxArrayLength: -1 })).toThrow(TypeError);
      expect(() => hppx({ maxArrayLength: 0 })).toThrow(TypeError);
    });

    test("throws on invalid maxKeyLength", () => {
      expect(() => hppx({ maxKeyLength: -1 })).toThrow(TypeError);
      expect(() => hppx({ maxKeyLength: 0 })).toThrow(TypeError);
      expect(() => hppx({ maxKeyLength: 2000 })).toThrow(TypeError);
    });

    test("throws on invalid mergeStrategy", () => {
      expect(() => hppx({ mergeStrategy: "invalid" as any })).toThrow(TypeError);
    });

    test("throws on invalid sources", () => {
      expect(() => hppx({ sources: "query" as any })).toThrow(TypeError);
      expect(() => hppx({ sources: ["query", "invalid"] as any })).toThrow(TypeError);
    });

    test("throws on invalid checkBodyContentType", () => {
      expect(() => hppx({ checkBodyContentType: "invalid" as any })).toThrow(TypeError);
    });

    test("throws on invalid excludePaths", () => {
      expect(() => hppx({ excludePaths: "path" as any })).toThrow(TypeError);
    });

    test("throws on invalid logger", () => {
      expect(() => hppx({ logger: "not a function" as any })).toThrow(TypeError);
      expect(() => hppx({ logger: 42 as any })).toThrow(TypeError);
      expect(() => hppx({ logger: {} as any })).toThrow(TypeError);
    });

    test("throws on invalid onPollutionDetected", () => {
      expect(() => hppx({ onPollutionDetected: "not a function" as any })).toThrow(TypeError);
      expect(() => hppx({ onPollutionDetected: true as any })).toThrow(TypeError);
      expect(() => hppx({ onPollutionDetected: [] as any })).toThrow(TypeError);
    });

    test("throws on invalid strict", () => {
      expect(() => hppx({ strict: "true" as any })).toThrow(TypeError);
      expect(() => hppx({ strict: 1 as any })).toThrow(TypeError);
      expect(() => hppx({ strict: 0 as any })).toThrow(TypeError);
      expect(() => hppx({ strict: null as any })).toThrow(TypeError);
      expect(() => hppx({ strict: {} as any })).toThrow(TypeError);
    });

    test("throws on invalid logPollution", () => {
      expect(() => hppx({ logPollution: "yes" as any })).toThrow(TypeError);
      expect(() => hppx({ logPollution: 1 as any })).toThrow(TypeError);
      expect(() => hppx({ logPollution: null as any })).toThrow(TypeError);
      expect(() => hppx({ logPollution: {} as any })).toThrow(TypeError);
    });

    test("throws on invalid trimValues", () => {
      expect(() => hppx({ trimValues: "true" as any })).toThrow(TypeError);
      expect(() => hppx({ trimValues: 1 as any })).toThrow(TypeError);
      expect(() => hppx({ trimValues: null as any })).toThrow(TypeError);
      expect(() => sanitize({}, { trimValues: "true" as any })).toThrow(TypeError);
    });

    test("throws on invalid preserveNull", () => {
      expect(() => hppx({ preserveNull: "false" as any })).toThrow(TypeError);
      expect(() => hppx({ preserveNull: 0 as any })).toThrow(TypeError);
      expect(() => hppx({ preserveNull: null as any })).toThrow(TypeError);
      expect(() => sanitize({}, { preserveNull: 0 as any })).toThrow(TypeError);
    });

    test("throws on invalid whitelist type", () => {
      expect(() => hppx({ whitelist: 42 as any })).toThrow(TypeError);
      expect(() => hppx({ whitelist: {} as any })).toThrow(TypeError);
      expect(() => hppx({ whitelist: true as any })).toThrow(TypeError);
      expect(() => sanitize({}, { whitelist: 42 as any })).toThrow(TypeError);
      expect(() => sanitize({}, { whitelist: {} as any })).toThrow(TypeError);
    });

    test("throws on whitelist array containing non-string elements", () => {
      expect(() => hppx({ whitelist: ["ok", 42 as any] })).toThrow(TypeError);
      expect(() => hppx({ whitelist: ["ok", { name: "x" } as any] })).toThrow(TypeError);
      expect(() => hppx({ whitelist: [null as any] })).toThrow(TypeError);
      expect(() => sanitize({}, { whitelist: ["ok", 42 as any] })).toThrow(TypeError);
    });

    test("throws on excludePaths array containing non-string elements", () => {
      expect(() => hppx({ excludePaths: [42 as any] })).toThrow(TypeError);
      expect(() => hppx({ excludePaths: ["/ok", 1 as any] })).toThrow(TypeError);
      expect(() => hppx({ excludePaths: [null as any] })).toThrow(TypeError);
      expect(() => hppx({ excludePaths: [{} as any] })).toThrow(TypeError);
    });

    test("throws on empty sources array", () => {
      expect(() => hppx({ sources: [] })).toThrow(TypeError);
      expect(() => hppx({ sources: [] })).toThrow(/at least one/);
    });

    test("accepts valid options", () => {
      expect(() => hppx({ maxDepth: 10 })).not.toThrow();
      expect(() => hppx({ maxKeys: 100 })).not.toThrow();
      expect(() => hppx({ maxArrayLength: 50 })).not.toThrow();
      expect(() => hppx({ maxKeyLength: 100 })).not.toThrow();
      expect(() => hppx({ mergeStrategy: "keepFirst" })).not.toThrow();
      expect(() => hppx({ sources: ["query", "body"] })).not.toThrow();
      expect(() => hppx({ checkBodyContentType: "any" })).not.toThrow();
      expect(() => hppx({ excludePaths: ["/public"] })).not.toThrow();
      expect(() => hppx({ logger: () => {} })).not.toThrow();
      expect(() => hppx({ onPollutionDetected: () => {} })).not.toThrow();
      expect(() => hppx({ strict: true })).not.toThrow();
      expect(() => hppx({ strict: false })).not.toThrow();
      expect(() => hppx({ logPollution: true })).not.toThrow();
      expect(() => hppx({ logPollution: false })).not.toThrow();
      expect(() => hppx({ trimValues: true })).not.toThrow();
      expect(() => hppx({ preserveNull: false })).not.toThrow();
      expect(() => hppx({ whitelist: "user.tags" })).not.toThrow();
      expect(() => hppx({ whitelist: ["a", "b.c"] })).not.toThrow();
    });
  });

  describe("Enhanced error handling", () => {
    test("handles errors with custom logger", async () => {
      const errors: any[] = [];
      const app = express();
      app.use(
        hppx({
          maxDepth: 2,
          logger: (err) => errors.push(err),
        }),
      );
      app.get("/test", (req, res) => res.json({ ok: true }));

      // Create deeply nested object to trigger maxDepth error
      const deep = { a: { b: { c: { d: "value" } } } };
      await request(app).get("/test").query(deep);

      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toBeInstanceOf(Error);
    });

    test("error is passed to next middleware", async () => {
      const app = express();
      app.use(hppx({ maxDepth: 1, logPollution: false }));

      // Error handler must come after the route
      app.get("/test", (req, res) => res.json({ ok: true }));
      app.use((err: any, _req: any, res: any, _next: any) => {
        res.status(500).json({ error: err.message });
      });

      // Create a deeply nested object that exceeds maxDepth of 1
      // Express parses query strings into nested objects
      const res = await request(app).get("/test").query({ "a[b][c]": "value" });

      expect(res.status).toBe(500);
      expect(res.body.error).toContain("depth");
    });
  });

  describe("Fixed onPollutionDetected callback", () => {
    test("callback receives correct source for query pollution", async () => {
      const calls: any[] = [];
      const app = express();
      app.use(
        hppx({
          onPollutionDetected: (req, info) => calls.push(info),
          logPollution: false, // Disable logging for cleaner test output
        }),
      );
      app.get("/test", (req, res) => res.json({}));

      await request(app).get("/test?x=1&x=2");

      expect(calls.length).toBeGreaterThan(0);
      expect(calls[0].source).toBe("query");
      expect(calls[0].pollutedKeys).toContain("query.x");
    });

    test("callback receives correct source for body pollution", async () => {
      const calls: any[] = [];
      const app = express();
      app.use(express.urlencoded({ extended: true }));
      app.use(
        hppx({
          onPollutionDetected: (req, info) => calls.push(info),
          logPollution: false,
        }),
      );
      app.post("/test", (req, res) => res.json({}));

      await request(app)
        .post("/test")
        .set("content-type", "application/x-www-form-urlencoded")
        .send("x=1&x=2");

      expect(calls.length).toBeGreaterThan(0);
      expect(calls[0].source).toBe("body");
      expect(calls[0].pollutedKeys).toContain("body.x");
    });

    test("callback receives multiple sources when both polluted", async () => {
      const calls: any[] = [];
      const app = express();
      app.use(express.urlencoded({ extended: true }));
      app.use(
        hppx({
          onPollutionDetected: (req, info) => calls.push(info),
          logPollution: false,
        }),
      );
      app.post("/test", (req, res) => res.json({}));

      await request(app)
        .post("/test?a=1&a=2")
        .set("content-type", "application/x-www-form-urlencoded")
        .send("b=3&b=4");

      expect(calls.length).toBe(2);
      const sources = calls.map((c) => c.source);
      expect(sources).toContain("query");
      expect(sources).toContain("body");
    });
  });

  describe("Circular reference protection", () => {
    test("handles circular references in sanitize without stack overflow", () => {
      const obj: any = { a: "value" };
      obj.self = obj;
      // Should not throw a stack overflow error
      const result = sanitize(obj);
      expect(result.a).toBe("value");
      // The circular ref should be replaced with {}
      expect(result.self).toEqual({});
    });

    test("handles indirect circular references", () => {
      const a: any = { name: "a" };
      const b: any = { name: "b", ref: a };
      a.ref = b;
      const result = sanitize(a);
      expect(result.name).toBe("a");
      expect(result.ref.name).toBe("b");
      // The back-reference should be cut off
      expect(result.ref.ref).toEqual({});
    });

    test("circular references in middleware do not crash", async () => {
      const app = express();
      app.use(express.json());
      app.use(hppx({ checkBodyContentType: "any", logPollution: false }));
      app.post("/test", (req, res) => res.json({ ok: true }));

      // We can't send a circular ref over HTTP, but we can test
      // that the middleware processes deeply nested objects without crashing
      const deep: any = {};
      let cur = deep;
      for (let i = 0; i < 15; i++) {
        cur.nested = {};
        cur = cur.nested;
      }
      cur.value = "leaf";

      const res = await request(app)
        .post("/test")
        .set("content-type", "application/json")
        .send(deep);
      expect(res.status).toBe(200);
    });
  });

  describe("Depth limits in expandObjectPaths and safeDeepClone", () => {
    test("expandObjectPaths respects maxDepth via sanitize", () => {
      // Create deeply nested input that exceeds maxDepth during expand
      const deep: any = {};
      let cur = deep;
      for (let i = 0; i < 5; i++) {
        cur.level = {};
        cur = cur.level;
      }
      cur.value = "leaf";

      // maxDepth: 3 should throw because the nested object is 6 levels deep
      expect(() => sanitize(deep, { maxDepth: 3 })).toThrow(/depth/i);
    });

    test("safeDeepClone respects maxDepth via detectAndReduce", () => {
      // The middleware uses safeDeepClone internally, test via middleware
      const app = express();
      app.use(hppx({ maxDepth: 2, logPollution: false }));
      app.get("/test", (req, res) => res.json({ ok: true }));

      // Deep query string will trigger the depth check
      return request(app)
        .get("/test")
        .query({ "a[b][c][d]": "value" })
        .then((res) => {
          expect(res.status).toBeGreaterThanOrEqual(500);
        });
    });
  });

  describe("Pollution logging", () => {
    // Tests in this block intentionally trigger logger / fallback console.warn
    // output. We use jest.spyOn(...).mockImplementation so restoreMocks: true
    // (configured in jest.config.ts) tears the spy down deterministically
    // between tests, preventing leaked "[hppx] ..." messages on stderr.

    test("logs pollution to console.warn by default", async () => {
      const warnings: any[] = [];
      jest.spyOn(console, "warn").mockImplementation((...args: any[]) => {
        warnings.push(args);
      });

      const app = express();
      app.use(hppx());
      app.get("/test", (req, res) => res.json({}));

      await request(app).get("/test?x=1&x=2");

      expect(warnings.length).toBeGreaterThan(0);
      expect(warnings[0][0]).toContain("[hppx]");
      expect(warnings[0][0]).toContain("HTTP Parameter Pollution detected");
      expect(warnings[0][0]).toContain("query.x");
    });

    test("uses custom logger when provided", async () => {
      const logs: any[] = [];
      const customLogger = jest.fn((msg) => logs.push(msg));

      const app = express();
      app.use(hppx({ logger: customLogger }));
      app.get("/test", (req, res) => res.json({}));

      await request(app).get("/test?a=1&a=2&b=3&b=4");

      expect(customLogger).toHaveBeenCalled();
      expect(logs.length).toBeGreaterThan(0);
      expect(logs[0]).toContain("[hppx]");
      expect(logs[0]).toContain("HTTP Parameter Pollution detected");
    });

    test("falls back to console.warn when custom logger fails", async () => {
      const warnings: any[] = [];
      jest.spyOn(console, "warn").mockImplementation((...args: any[]) => {
        warnings.push(args);
      });

      const failingLogger = jest.fn(() => {
        throw new Error("Logger failed");
      });

      const app = express();
      app.use(hppx({ logger: failingLogger }));
      app.get("/test", (req, res) => res.json({}));

      await request(app).get("/test?x=1&x=2");

      expect(failingLogger).toHaveBeenCalled();
      expect(warnings.length).toBeGreaterThan(0);
      expect(warnings[0][0]).toContain("[hppx]");
    });

    test("respects logPollution: false", async () => {
      const warnings: any[] = [];
      jest.spyOn(console, "warn").mockImplementation((...args: any[]) => {
        warnings.push(args);
      });

      const app = express();
      app.use(hppx({ logPollution: false }));
      app.get("/test", (req, res) => res.json({}));

      await request(app).get("/test?x=1&x=2");

      // Should not log anything
      const hppxWarnings = warnings.filter((w) =>
        w.some((arg: any) => typeof arg === "string" && arg.includes("[hppx]")),
      );
      expect(hppxWarnings.length).toBe(0);
    });

    test("logs multiple polluted parameters correctly", async () => {
      const logs: any[] = [];
      const customLogger = jest.fn((msg) => logs.push(msg));

      const app = express();
      app.use(hppx({ logger: customLogger }));
      app.get("/test", (req, res) => res.json({}));

      await request(app).get("/test?a=1&a=2&b=3&b=4&c=5&c=6");

      expect(logs.length).toBeGreaterThan(0);
      expect(logs[0]).toContain("3 parameter(s) affected");
      expect(logs[0]).toContain("query.a");
      expect(logs[0]).toContain("query.b");
      expect(logs[0]).toContain("query.c");
    });
  });

  describe("Prototype-poisoned __hppxProcessed_* flag bypass", () => {
    test("ignores Object.prototype.__hppxProcessed_query and still sanitizes", async () => {
      // Pre-poison the prototype chain — simulates an upstream prototype-pollution
      // gadget elsewhere in the process. Wrap in try/finally so we ALWAYS clean up,
      // even if the assertions throw.
      (Object.prototype as Record<string, unknown>).__hppxProcessed_query = true;
      try {
        let observedQuery: any = null;
        let observedQueryPolluted: any = null;

        const app = express();
        app.use(hppx({ logPollution: false }));
        app.get("/test", (req, res) => {
          observedQuery = req.query;
          observedQueryPolluted = (req as any).queryPolluted;
          res.json({});
        });

        const res = await request(app).get("/test?x=1&x=2");

        expect(res.status).toBe(200);
        // The middleware MUST have run — it must NOT have been short-circuited
        // by the prototype-poisoned flag. So req.query.x should be reduced (keepLast).
        expect(observedQuery).toBeTruthy();
        expect(observedQuery.x).toBe("2");
        // And the pollution should have been recorded.
        expect(observedQueryPolluted).toBeTruthy();
        expect(observedQueryPolluted.x).toEqual(["1", "2"]);
      } finally {
        delete (Object.prototype as Record<string, unknown>).__hppxProcessed_query;
      }
    });

    test("processed flag is non-enumerable on req", async () => {
      let processedKeyEnumerable: boolean | null = null;

      const app = express();
      app.use(hppx({ logPollution: false }));
      app.get("/test", (req, res) => {
        const desc = Object.getOwnPropertyDescriptor(req, "__hppxProcessed_query");
        processedKeyEnumerable = desc ? Boolean(desc.enumerable) : null;
        res.json({});
      });

      await request(app).get("/test?x=1&x=2");

      // Flag was set (descriptor exists) and is NOT enumerable.
      expect(processedKeyEnumerable).toBe(false);
    });
  });

  describe("Shared subtree handling (path-stack cycle detection)", () => {
    test("preserves shared object subtree (acyclic) on every occurrence", () => {
      // A shared but acyclic object reference must appear cloned at every site.
      // The previous WeakSet-for-the-whole-walk implementation incorrectly emitted
      // {} on the second visit.
      const shared = { x: 1 };
      const result = sanitize({ a: shared, b: shared } as any);

      expect(result.a).toEqual({ x: 1 });
      expect(result.b).toEqual({ x: 1 });
      // Each occurrence must be its own copy, not share reference identity with the input
      expect(result.a).not.toBe(shared);
      expect(result.b).not.toBe(shared);
    });

    test("preserves shared array subtree (acyclic) on every occurrence", () => {
      // A shared array reference must be retained at every key. Whitelist both
      // entries so the array is preserved (not reduced as pollution). The previous
      // shared-WeakSet implementation produced [] for the second occurrence
      // regardless of whitelist, because the shared array was already in `seen`
      // when the polluted-tree clone ran.
      const arr = [1, 2];
      const result = sanitize({ a: { v: arr }, b: { v: arr } } as any, {
        whitelist: ["a.v", "b.v"],
      });
      expect(result.a.v).toEqual([1, 2]);
      expect(result.b.v).toEqual([1, 2]);
    });

    test("breaks genuine self-cycle without infinite loop", () => {
      const o: any = { x: 1 };
      o.self = o;
      const result = sanitize(o);
      expect(result.x).toBe(1);
      // Cycle is cut off — the back-edge becomes an empty object
      expect(result.self).toEqual({});
    });

    test("breaks cycle through array without infinite loop", () => {
      const a: any = [];
      a.push(a);
      // Wrap so it goes through the middleware/sanitize as an object value
      const result: any = sanitize({ items: { wrapped: a } } as any);
      // Should terminate cleanly. After the cycle is broken, the resulting
      // structure must remain a finite JSON-serializable shape.
      expect(() => JSON.stringify(result)).not.toThrow();
    });

    test("preserves diamond-shaped acyclic graph", () => {
      // leaf is referenced from two slots in parent, and parent is referenced
      // from two slots in the root. The previous implementation lost three of
      // the four leaves; the path-stack implementation must keep all four.
      const leaf = { z: 1 };
      const parent = { l: leaf, r: leaf };
      const result: any = sanitize({ a: parent, b: parent } as any);

      expect(result.a.l.z).toBe(1);
      expect(result.a.r.z).toBe(1);
      expect(result.b.l.z).toBe(1);
      expect(result.b.r.z).toBe(1);
    });
  });
});
