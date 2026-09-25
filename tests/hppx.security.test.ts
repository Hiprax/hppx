import express from "express";
import request from "supertest";
import hppx, {
  sanitize,
  DANGEROUS_KEYS,
  DEFAULT_SOURCES,
  type HppxOptions,
  type RequestSource,
} from "../src/index";

describe("hppx - Security Features", () => {
  describe("Array length limits (DoS protection)", () => {
    test("limits array length to prevent memory exhaustion", () => {
      // Distinct elements 0..1999; safeDeepClone slices to 100 (indices 0..99).
      // keepLast selects values[99] = 99. Pins truncation depth (safeDeepClone's
      // maxArrayLength slice) and the mergeValues keepLast path — current intended behavior.
      const largeArray = Array.from({ length: 2000 }, (_, i) => i);
      const input = { x: largeArray };
      const cleaned = sanitize(input, { maxArrayLength: 100, mergeStrategy: "keepLast" });
      expect(cleaned.x).toBe(99);
    });

    test("respects custom maxArrayLength", () => {
      // Distinct elements; slice(0,3) -> [10,20,30]; keepLast selects 30 — pins behavior.
      const arr = [10, 20, 30, 40, 50];
      const input = { x: arr };
      const cleaned = sanitize(input, { maxArrayLength: 3, mergeStrategy: "keepLast" });
      expect(cleaned.x).toBe(30);
    });

    test("maxArrayLength with combine strategy truncates then flattens — pins current behavior", () => {
      // Distinct elements 0..1999; safeDeepClone slices to 100 (indices 0..99).
      // combine pushes each scalar into one array -> length 100, last element 99.
      // Pins truncation (safeDeepClone's maxArrayLength slice) and the mergeValues combine path.
      const largeArray = Array.from({ length: 2000 }, (_, i) => i);
      const input = { x: largeArray };
      const cleaned = sanitize(input, { maxArrayLength: 100, mergeStrategy: "combine" });
      expect(Array.isArray(cleaned.x)).toBe(true);
      expect((cleaned.x as unknown[]).length).toBe(100);
      expect((cleaned.x as unknown[])[99]).toBe(99);
    });

    test("handles very large arrays in middleware", async () => {
      const app = express();
      app.use(express.json());
      app.use(
        hppx({
          maxArrayLength: 10,
          mergeStrategy: "combine",
          checkBodyContentType: "any",
          logPollution: false,
        }),
      );
      app.post("/test", (req, res) => res.json({ body: req.body }));

      // 100-element input; safeDeepClone slices to 10; combine collects 10 scalars.
      const largeArray = Array.from({ length: 100 }, (_, i) => i);
      const res = await request(app).post("/test").send({ x: largeArray });
      expect(res.status).toBe(200);
      // Pins truncation to maxArrayLength (10) via combine — current intended behavior.
      expect(res.body.body.x).toHaveLength(10);
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

    // Calls `construct`, requires the exact documented TypeError, and requires that nothing was
    // produced: no middleware function from hppx(), no cleaned object from sanitize().
    function expectRejected(construct: () => unknown, message: string): void {
      let produced: unknown;
      let thrown: unknown;
      try {
        produced = construct();
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(TypeError);
      expect((thrown as Error).message).toBe(message);
      // Reports a returned value (instead of only "no throw") if construction ever stops failing.
      expect(produced).toBeUndefined();
    }

    const DEPTH_MESSAGE = "maxDepth must be a number between 1 and 100";
    const KEYS_MESSAGE = "maxKeys must be a positive number";
    const ARRAY_MESSAGE = "maxArrayLength must be a positive number";
    const KEY_LENGTH_MESSAGE = "maxKeyLength must be a number between 1 and 1000";

    const nanCases: { option: string; options: HppxOptions; message: string }[] = [
      { option: "maxDepth", options: { maxDepth: NaN }, message: DEPTH_MESSAGE },
      { option: "maxKeys", options: { maxKeys: NaN }, message: KEYS_MESSAGE },
      { option: "maxArrayLength", options: { maxArrayLength: NaN }, message: ARRAY_MESSAGE },
      { option: "maxKeyLength", options: { maxKeyLength: NaN }, message: KEY_LENGTH_MESSAGE },
    ];

    test.each(nanCases)(
      "hppx() rejects NaN for $option at construction with the documented TypeError",
      ({ options, message }) => {
        expectRejected(() => hppx(options), message);
      },
    );

    test.each(nanCases)(
      "sanitize() rejects NaN for $option with the documented TypeError before processing input",
      ({ options, message }) => {
        expectRejected(() => sanitize({ a: ["1", "2"] }, options), message);
      },
    );

    test("rejects NaN produced by numeric parsing of an unset or empty setting (maxArrayLength)", () => {
      expectRejected(() => hppx({ maxArrayLength: Number(undefined) }), ARRAY_MESSAGE);
      expectRejected(() => hppx({ maxArrayLength: Number.parseInt("", 10) }), ARRAY_MESSAGE);
      expectRejected(
        () => sanitize({ x: ["a"] }, { maxArrayLength: Number(undefined) }),
        ARRAY_MESSAGE,
      );
    });

    // `levels` nested single-key objects around a string leaf: nest(2) = { k: { k: "leaf" } }.
    function nest(levels: number): Record<string, unknown> {
      let node: unknown = "leaf";
      for (let i = 0; i < levels; i++) node = { k: node };
      return node as Record<string, unknown>;
    }

    function manyKeys(count: number): Record<string, string> {
      return Object.fromEntries(Array.from({ length: count }, (_, i) => [`k${i}`, "v"]));
    }

    test("maxDepth accepts the documented bounds 1 and 100, and each bound is the one enforced", () => {
      expect(typeof hppx({ maxDepth: 1 })).toBe("function");
      expect(typeof hppx({ maxDepth: 100 })).toBe("function");

      expect(sanitize(nest(1), { maxDepth: 1 })).toEqual({ k: "leaf" });
      expect(() => sanitize(nest(3), { maxDepth: 1 })).toThrow(
        new Error("Maximum object depth (1) exceeded"),
      );
      // Depth 50 is beyond the default (20) yet within 100: accepted only because 100 applies.
      expect(sanitize(nest(50), { maxDepth: 100 })).toEqual(nest(50));
      expect(() => sanitize(nest(50))).toThrow(new Error("Maximum object depth (20) exceeded"));
      expect(() => sanitize(nest(150), { maxDepth: 100 })).toThrow(
        new Error("Maximum object depth (100) exceeded"),
      );
    });

    test("maxDepth rejects 0, 101, Infinity and -Infinity with the documented TypeError", () => {
      for (const value of [0, 101, Infinity, -Infinity]) {
        expectRejected(() => hppx({ maxDepth: value }), DEPTH_MESSAGE);
        expectRejected(() => sanitize({ a: "1" }, { maxDepth: value }), DEPTH_MESSAGE);
      }
    });

    test("maxKeyLength accepts the documented bounds 1 and 1000, and each bound is the one enforced", () => {
      expect(typeof hppx({ maxKeyLength: 1 })).toBe("function");
      expect(typeof hppx({ maxKeyLength: 1000 })).toBe("function");

      expect(sanitize({ a: "1", ab: "2" }, { maxKeyLength: 1 })).toEqual({ a: "1" });
      const atLimit = "k".repeat(1000);
      const overLimit = "j".repeat(1001);
      const cleaned = sanitize({ [atLimit]: "1", [overLimit]: "2" }, { maxKeyLength: 1000 });
      expect(cleaned).toEqual({ [atLimit]: "1" });
      expect(Object.prototype.hasOwnProperty.call(cleaned, overLimit)).toBe(false);
    });

    test("maxKeyLength rejects 0, 1001, Infinity and -Infinity with the documented TypeError", () => {
      for (const value of [0, 1001, Infinity, -Infinity]) {
        expectRejected(() => hppx({ maxKeyLength: value }), KEY_LENGTH_MESSAGE);
        expectRejected(() => sanitize({ a: "1" }, { maxKeyLength: value }), KEY_LENGTH_MESSAGE);
      }
    });

    test("maxKeys accepts 1 and Infinity (documented range >= 1), and the accepted value is enforced", () => {
      expect(typeof hppx({ maxKeys: 1 })).toBe("function");
      expect(typeof hppx({ maxKeys: Infinity })).toBe("function");

      expect(sanitize({ a: "1" }, { maxKeys: 1 })).toEqual({ a: "1" });
      expect(() => sanitize({ a: "1", b: "2" }, { maxKeys: 1 })).toThrow(
        new Error("Maximum key count (1) exceeded"),
      );
      // 6000 keys exceed the default 5000, so this passes only because Infinity is in effect.
      expect(Object.keys(sanitize(manyKeys(6000), { maxKeys: Infinity }))).toHaveLength(6000);
      expect(() => sanitize(manyKeys(6000))).toThrow(
        new Error("Maximum key count (5000) exceeded"),
      );
    });

    test("maxKeys rejects 0 and -Infinity with the documented TypeError", () => {
      for (const value of [0, -Infinity]) {
        expectRejected(() => hppx({ maxKeys: value }), KEYS_MESSAGE);
        expectRejected(() => sanitize({ a: "1" }, { maxKeys: value }), KEYS_MESSAGE);
      }
    });

    test("maxArrayLength accepts 1 and Infinity (documented range >= 1), and the accepted value is enforced", () => {
      expect(typeof hppx({ maxArrayLength: 1 })).toBe("function");
      expect(typeof hppx({ maxArrayLength: Infinity })).toBe("function");

      expect(sanitize({ x: ["a", "b"] }, { maxArrayLength: 1, mergeStrategy: "combine" })).toEqual({
        x: ["a"],
      });
      const large = Array.from({ length: 1500 }, (_, i) => i);
      // The default (1000) would truncate; Infinity keeps every element.
      const cleaned = sanitize(
        { x: large },
        { maxArrayLength: Infinity, mergeStrategy: "combine" },
      );
      expect(cleaned.x).toEqual(large);
      expect(sanitize({ x: large }, { mergeStrategy: "combine" }).x).toHaveLength(1000);
    });

    test("maxArrayLength rejects 0 and -Infinity with the documented TypeError", () => {
      for (const value of [0, -Infinity]) {
        expectRejected(() => hppx({ maxArrayLength: value }), ARRAY_MESSAGE);
        expectRejected(() => sanitize({ a: "1" }, { maxArrayLength: value }), ARRAY_MESSAGE);
      }
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

  describe("onPollutionDetected callback throw is swallowed", () => {
    // These tests exercise the try/catch at src/index.ts:1102-1121 that silently
    // discards user-callback errors so they cannot disrupt request processing.

    test("non-strict: throwing callback contained; next() called without error; req.queryPolluted populated", () => {
      const mw = hppx({
        onPollutionDetected: () => {
          throw new Error("boom");
        },
        logPollution: false,
      });
      const req: any = { query: { x: ["1", "2"] }, headers: {} };
      const res: any = {};
      const next = jest.fn();

      mw(req, res, next);

      // The callback's throw is contained inside the catch block; next() must be
      // called exactly once with no argument.
      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      // req.queryPolluted is still populated even though the callback threw.
      expect(req.queryPolluted).toEqual({ x: ["1", "2"] });
    });

    test("strict + throwing callback: throw contained; 400 HPP_DETECTED still returned; next not called", () => {
      // The onPollutionDetected try/catch (src/index.ts:1102-1121) runs BEFORE the
      // strict block (src/index.ts:1123-1130), so a contained throw cannot suppress
      // the strict 400 response.
      const mw = hppx({
        strict: true,
        onPollutionDetected: () => {
          throw new Error("boom");
        },
        logPollution: false,
      });
      const req: any = { query: { x: ["1", "2"] }, headers: {} };
      const jsonMock = jest.fn();
      const res: any = { status: jest.fn().mockReturnValue({ json: jsonMock }) };
      const next = jest.fn();

      mw(req, res, next);

      // Strict block fired after the catch: 400 with HPP_DETECTED code.
      expect(res.status).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith(expect.objectContaining({ code: "HPP_DETECTED" }));
      // next() must not be called when strict mode sends the 400 response.
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("strict mode degrades gracefully when res.status is not a function", () => {
    // Exercises the third operand of the compound condition at src/index.ts:1123:
    // `strict && res && typeof res.status === "function"`. When res.status is
    // absent (non-Express harness), the condition short-circuits to false and
    // the middleware falls through to next() rather than throwing a TypeError.

    test("strict: next() called without error when res has no status method", () => {
      const mw = hppx({ strict: true, logPollution: false });
      const req: any = { query: { x: ["1", "2"] }, headers: {} };
      const res: any = {}; // no status method — typeof res.status === "undefined"
      const next = jest.fn();

      mw(req, res, next);

      // The strict guard silently skips the 400 response; next() is called normally.
      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      // Sanitization still ran: keepLast reduces the array.
      expect(req.query).toEqual({ x: "2" });
      expect(req.queryPolluted).toEqual({ x: ["1", "2"] });
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

  describe("Configuration is fixed when hppx() returns", () => {
    // `sources` and `excludePaths` are validated when hppx() is called. The
    // middleware must act on that validated configuration only: later changes
    // to the caller's arrays, or to the exported DEFAULT_SOURCES, must neither
    // bypass validation nor change a middleware that already exists.
    function run(mw: ReturnType<typeof hppx>, req: Record<string, unknown>) {
      const next = jest.fn();
      mw(req, {}, next);
      return next;
    }

    test("an entry added to sources after creation never touches that part of req", () => {
      const sources: RequestSource[] = ["query"];
      const mw = hppx({ sources, logPollution: false });
      // Validation rejects "cookies" up front; appending it later must not bypass that.
      (sources as string[]).push("cookies");
      const req: any = { headers: {}, query: { a: ["1", "2"] }, cookies: { sid: ["x", "y"] } };

      const next = run(mw, req);

      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      expect(req.query).toEqual({ a: "2" });
      expect(req.queryPolluted).toEqual({ a: ["1", "2"] });
      expect(req.cookies).toEqual({ sid: ["x", "y"] });
      expect(Object.prototype.hasOwnProperty.call(req, "cookiesPolluted")).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(req, "__hppxProcessed_cookies")).toBe(false);
    });

    test("a __proto__ entry added to sources after creation never defines req.__proto__", () => {
      const sources: RequestSource[] = ["query"];
      const mw = hppx({ sources, logPollution: false });
      (sources as string[]).push("__proto__");
      const req: any = { headers: {}, query: { a: ["1", "2"] } };

      const next = run(mw, req);

      expect(next).toHaveBeenCalledWith();
      expect(req.query).toEqual({ a: "2" });
      expect(Object.getPrototypeOf(req)).toBe(Object.prototype);
      expect(Object.getOwnPropertyNames(req)).not.toContain("__proto__");
      expect(Object.getOwnPropertyNames(req)).not.toContain("__proto__Polluted");
    });

    test("sources are processed in the configured order", () => {
      const seen: string[] = [];
      const messages: unknown[] = [];
      const mw = hppx({
        sources: ["body", "query"],
        checkBodyContentType: "any",
        logger: (message) => messages.push(message),
        onPollutionDetected: (_req, info) => seen.push(info.source),
      });
      const req: any = { headers: {}, query: { q: ["1", "2"] }, body: { b: ["3", "4"] } };

      const next = run(mw, req);

      expect(next).toHaveBeenCalledWith();
      expect(seen).toEqual(["body", "query"]);
      expect(messages).toEqual([
        "[hppx] HTTP Parameter Pollution detected - 2 parameter(s) affected: body.b, query.q",
      ]);
    });

    test("excludePaths changed after creation neither exempts a path nor breaks requests", () => {
      const excludePaths = ["/health"];
      const mw = hppx({ excludePaths, logPollution: false });
      (excludePaths as unknown[]).push(42, "/api/*");
      const api: any = { headers: {}, path: "/api/items", query: { a: ["1", "2"] } };
      const health: any = { headers: {}, path: "/health", query: { a: ["1", "2"] } };

      const apiNext = run(mw, api);
      const healthNext = run(mw, health);

      expect(apiNext).toHaveBeenCalledTimes(1);
      expect(apiNext).toHaveBeenCalledWith();
      expect(api.query).toEqual({ a: "2" });
      expect(api.queryPolluted).toEqual({ a: ["1", "2"] });
      // The exclusion configured at creation still applies.
      expect(healthNext).toHaveBeenCalledWith();
      expect(health.query).toEqual({ a: ["1", "2"] });
      expect(Object.prototype.hasOwnProperty.call(health, "queryPolluted")).toBe(false);
    });

    test("whitelist changed after creation neither adds nor removes a whitelisted key", () => {
      const whitelist = ["keep"];
      const mw = hppx({ whitelist, logPollution: false });
      whitelist.splice(0, 1, "drop");
      const req: any = { headers: {}, query: { keep: ["1", "2"], drop: ["3", "4"] } };

      const next = run(mw, req);

      expect(next).toHaveBeenCalledWith();
      expect(req.query).toEqual({ keep: ["1", "2"], drop: "4" });
      expect(req.queryPolluted).toEqual({ drop: ["3", "4"] });
    });

    describe("exported DEFAULT_SOURCES", () => {
      const original = [...DEFAULT_SOURCES];
      afterEach(() => {
        DEFAULT_SOURCES.splice(0, DEFAULT_SOURCES.length, ...original);
      });

      test("an invalid entry added before creation fails closed with the sources TypeError", () => {
        (DEFAULT_SOURCES as string[]).push("cookies");
        const create = () => hppx({ logPollution: false });

        expect(create).toThrow(TypeError);
        expect(create).toThrow("sources must only contain 'query', 'body', or 'params'");
      });

      test("a change made after creation does not affect an existing middleware", () => {
        const mw = hppx({ logPollution: false });
        (DEFAULT_SOURCES as string[]).push("cookies");
        DEFAULT_SOURCES.splice(DEFAULT_SOURCES.indexOf("params"), 1);
        const req: any = { headers: {}, params: { id: ["1", "2"] }, cookies: { sid: ["x", "y"] } };

        const next = run(mw, req);

        expect(next).toHaveBeenCalledWith();
        expect(req.params).toEqual({ id: "2" });
        expect(req.paramsPolluted).toEqual({ id: ["1", "2"] });
        expect(req.cookies).toEqual({ sid: ["x", "y"] });
        expect(Object.prototype.hasOwnProperty.call(req, "cookiesPolluted")).toBe(false);
      });
    });
  });

  describe("DANGEROUS_KEYS is read-only and cannot weaken the guards", () => {
    const original = ["__proto__", "prototype", "constructor"];
    afterEach(() => {
      // Restore the exact contents through Set.prototype (bypassing any
      // read-only facade), even when an assertion failed.
      for (const key of [...DANGEROUS_KEYS]) {
        if (!original.includes(key)) Set.prototype.delete.call(DANGEROUS_KEYS, key);
      }
      for (const key of original) Set.prototype.add.call(DANGEROUS_KEYS, key);
    });

    test("add, delete and clear throw a TypeError and leave the keys unchanged", () => {
      const keys = DANGEROUS_KEYS as Set<string>;

      expect(() => keys.add("isAdmin")).toThrow(TypeError);
      expect(() => keys.delete("__proto__")).toThrow(TypeError);
      expect(() => keys.clear()).toThrow(TypeError);
      expect(() => keys.delete("__proto__")).toThrow("DANGEROUS_KEYS is read-only");
      expect([...DANGEROUS_KEYS]).toEqual(["__proto__", "prototype", "constructor"]);
      expect(DANGEROUS_KEYS.has("isAdmin")).toBe(false);
      // Still a plain Set for existing readers, including deep equality.
      expect(DANGEROUS_KEYS).toBeInstanceOf(Set);
      expect(Object.getPrototypeOf(DANGEROUS_KEYS)).toBe(Set.prototype);
      expect(DANGEROUS_KEYS).toEqual(new Set(["__proto__", "prototype", "constructor"]));
      expect(DANGEROUS_KEYS.size).toBe(3);
    });

    test("removing a key through Set.prototype still leaves hppx blocking it", () => {
      Set.prototype.delete.call(DANGEROUS_KEYS, "constructor");
      expect(DANGEROUS_KEYS.has("constructor")).toBe(false);

      const result = sanitize({ constructor: "x", "a.constructor": "y", keep: "1" } as any);

      expect(result).toEqual({ a: {}, keep: "1" });
      expect(Object.prototype.hasOwnProperty.call(result, "constructor")).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(result.a, "constructor")).toBe(false);
    });
  });

  describe("writes into hppx-built objects define own properties", () => {
    // `Object.freeze(Object.prototype)` (a common prototype-pollution
    // mitigation) makes every inherited method name read-only, so a plain
    // assignment such as `out.toString = value` throws in strict mode (the
    // "override mistake") and a request like `?toString=1` became a 500. The
    // Jest process cannot freeze its own Object.prototype, so these tests make
    // one inherited name read-only, and install one inherited setter, which is
    // the same mechanism for that name.
    let trapped: unknown[];
    beforeEach(() => {
      trapped = [];
      Object.defineProperty(Object.prototype, "hppxReadOnly", {
        value: "inherited",
        writable: false,
        enumerable: false,
        configurable: true,
      });
      Object.defineProperty(Object.prototype, "hppxTrap", {
        get: () => undefined,
        set: (value: unknown) => {
          trapped.push(value);
        },
        enumerable: false,
        configurable: true,
      });
    });
    afterEach(() => {
      delete (Object.prototype as Record<string, unknown>).hppxReadOnly;
      delete (Object.prototype as Record<string, unknown>).hppxTrap;
    });

    function run(mw: ReturnType<typeof hppx>, req: Record<string, unknown>) {
      const next = jest.fn();
      mw(req, {}, next);
      return next;
    }

    test("a key named like a read-only inherited property is kept, flat and dotted", () => {
      const flat = sanitize({ hppxReadOnly: "1" } as any);
      const dotted = sanitize({ "hppxReadOnly.x": "2" } as any);

      expect(flat).toEqual({ hppxReadOnly: "1" });
      expect(Object.prototype.hasOwnProperty.call(flat, "hppxReadOnly")).toBe(true);
      expect(dotted).toEqual({ hppxReadOnly: { x: "2" } });
      expect(Object.prototype.hasOwnProperty.call(dotted, "hppxReadOnly")).toBe(true);
    });

    test("duplicates of such a key are reduced and recorded instead of failing the request", () => {
      const mw = hppx({ logPollution: false });
      const flat: any = { headers: {}, query: { hppxReadOnly: ["1", "2"] } };
      const nested: any = { headers: {}, query: { hppxReadOnly: { x: ["3", "4"] } } };

      const flatNext = run(mw, flat);
      const nestedNext = run(mw, nested);

      expect(flatNext).toHaveBeenCalledTimes(1);
      expect(flatNext).toHaveBeenCalledWith();
      expect(flat.query).toEqual({ hppxReadOnly: "2" });
      expect(flat.queryPolluted).toEqual({ hppxReadOnly: ["1", "2"] });
      expect(nestedNext).toHaveBeenCalledWith();
      expect(nested.query).toEqual({ hppxReadOnly: { x: "4" } });
      expect(nested.queryPolluted).toEqual({ hppxReadOnly: { x: ["3", "4"] } });
    });

    test("whitelist restoration into a missing subtree defines it as an own property", () => {
      const first = hppx({ logPollution: false });
      const second = hppx({ logPollution: false, whitelist: ["hppxReadOnly.x"] });
      const req: any = { headers: {}, query: { hppxReadOnly: { x: ["1", "2"] } } };

      const firstNext = run(first, req);
      delete req.query.hppxReadOnly;
      const secondNext = run(second, req);

      expect(firstNext).toHaveBeenCalledWith();
      expect(secondNext).toHaveBeenCalledWith();
      expect(Object.prototype.hasOwnProperty.call(req.query, "hppxReadOnly")).toBe(true);
      expect(req.query.hppxReadOnly).toEqual({ x: ["1", "2"] });
    });

    test("an inherited setter never receives request data", () => {
      const flat = sanitize({ hppxTrap: "secret" } as any);
      const dotted = sanitize({ "hppxTrap.x": "nested" } as any);

      expect(flat).toEqual({ hppxTrap: "secret" });
      expect(dotted).toEqual({ hppxTrap: { x: "nested" } });
      expect(trapped).toEqual([]);
    });
  });

  describe("Non-enumerable *Polluted properties", () => {
    function invokeDirectly(mw: ReturnType<typeof hppx>, reqOverrides: Record<string, unknown>) {
      const req: any = { headers: {}, ...reqOverrides };
      const res: any = {};
      const next = jest.fn();
      mw(req, res, next);
      return { req, next };
    }

    test("queryPolluted descriptor has enumerable: false after processing", () => {
      const mw = hppx({ logPollution: false });
      const { req } = invokeDirectly(mw, { query: { x: ["1", "2"] } });

      const desc = Object.getOwnPropertyDescriptor(req, "queryPolluted");
      expect(desc).toBeDefined();
      expect(desc!.enumerable).toBe(false);
    });

    test("queryPolluted is readable by name and holds the raw duplicate tree", () => {
      const mw = hppx({ logPollution: false });
      const { req } = invokeDirectly(mw, { query: { x: ["1", "2"] } });

      expect(req.queryPolluted).toEqual({ x: ["1", "2"] });
    });

    test("bodyPolluted descriptor has enumerable: false after processing", () => {
      const mw = hppx({ logPollution: false, checkBodyContentType: "any" });
      const { req } = invokeDirectly(mw, { body: { x: ["1", "2"] } });

      const desc = Object.getOwnPropertyDescriptor(req, "bodyPolluted");
      expect(desc).toBeDefined();
      expect(desc!.enumerable).toBe(false);
    });

    test("paramsPolluted descriptor has enumerable: false after processing", () => {
      const mw = hppx({ logPollution: false });
      const { req } = invokeDirectly(mw, { params: { id: ["a", "b"] } });

      const desc = Object.getOwnPropertyDescriptor(req, "paramsPolluted");
      expect(desc).toBeDefined();
      expect(desc!.enumerable).toBe(false);
    });

    test("queryPolluted absent from JSON.stringify(req) and Object.keys(req)", () => {
      const mw = hppx({ logPollution: false });
      const { req } = invokeDirectly(mw, { query: { x: ["1", "2"] } });

      const serialized = JSON.stringify(req);
      // Non-enumerable own properties are excluded from JSON serialization
      expect(serialized).not.toContain("queryPolluted");
      // Object.keys only returns own enumerable keys
      expect(Object.keys(req)).not.toContain("queryPolluted");
      // The reduced-away raw values should also not be serialized
      expect(serialized).not.toContain('"1","2"');
    });

    test("cleaned query source remains enumerable and present in JSON.stringify(req)", () => {
      const mw = hppx({ logPollution: false });
      const { req } = invokeDirectly(mw, { query: { x: ["1", "2"] } });

      const desc = Object.getOwnPropertyDescriptor(req, "query");
      expect(desc).toBeDefined();
      expect(desc!.enumerable).toBe(true);
      expect(Object.keys(req)).toContain("query");
      expect(JSON.stringify(req)).toContain('"query"');
    });

    test("multi-middleware: second instance whitelist restoration works; queryPolluted stays non-enumerable", () => {
      // First middleware: no whitelist — reduces both x and y
      const mw1 = hppx({ logPollution: false });
      // Second middleware: whitelist x — restores x from polluted tree
      const mw2 = hppx({ logPollution: false, whitelist: ["x"] });

      const req: any = {
        headers: {},
        query: { x: ["1", "2"], y: ["3", "4"] },
      };
      const res: any = {};

      mw1(req, res, jest.fn());

      // After first pass: both reduced, queryPolluted is non-enumerable
      expect(req.query.x).toBe("2");
      expect(req.query.y).toBe("4");
      expect(Object.getOwnPropertyDescriptor(req, "queryPolluted")!.enumerable).toBe(false);

      mw2(req, res, jest.fn());

      // After second pass (whitelist restoration only): x is restored as raw array
      expect(req.query.x).toEqual(["1", "2"]);
      // y is still the reduced scalar (not whitelisted)
      expect(req.query.y).toBe("4");
      // queryPolluted is still non-enumerable after in-place mutation by mw2
      expect(Object.getOwnPropertyDescriptor(req, "queryPolluted")!.enumerable).toBe(false);
      // And still absent from serialization
      expect(Object.keys(req)).not.toContain("queryPolluted");
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
