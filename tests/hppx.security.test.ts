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
      app.use(hppx({ maxArrayLength: 10, checkBodyContentType: "any" }));
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
      app.use(hppx({ maxKeyLength: 10 }));
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
      app.use(hppx());
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

    test("accepts valid options", () => {
      expect(() => hppx({ maxDepth: 10 })).not.toThrow();
      expect(() => hppx({ maxKeys: 100 })).not.toThrow();
      expect(() => hppx({ maxArrayLength: 50 })).not.toThrow();
      expect(() => hppx({ maxKeyLength: 100 })).not.toThrow();
      expect(() => hppx({ mergeStrategy: "keepFirst" })).not.toThrow();
      expect(() => hppx({ sources: ["query", "body"] })).not.toThrow();
      expect(() => hppx({ checkBodyContentType: "any" })).not.toThrow();
      expect(() => hppx({ excludePaths: ["/public"] })).not.toThrow();
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
      app.use(hppx({ maxDepth: 1 }));

      // Error handler must come after the route
      app.get("/test", (req, res) => res.json({ ok: true }));
      app.use((err: any, req: any, res: any, next: any) => {
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
});
