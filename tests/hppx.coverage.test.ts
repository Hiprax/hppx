import express from "express";
import request from "supertest";
import hppx, { sanitize } from "../src/index";

describe("hppx - Coverage for Edge Cases", () => {
  describe("setReqPropertySafe edge cases", () => {
    test("handles non-configurable and non-writable properties", async () => {
      const app = express();

      // Create a request-like object with a frozen property
      app.use((req: any, _res, next) => {
        // Make a property non-configurable and non-writable
        Object.defineProperty(req, "testProp", {
          value: "original",
          writable: false,
          configurable: false,
        });
        next();
      });

      app.use(hppx({ logPollution: false }));

      app.get("/test", (req: any, res) => {
        // The property should remain unchanged
        res.json({ testProp: req.testProp });
      });

      const res = await request(app).get("/test");
      expect(res.status).toBe(200);
      expect(res.body.testProp).toBe("original");
    });

    test("handles assignment fallback when defineProperty fails", async () => {
      const app = express();

      // Create a scenario where defineProperty might fail but assignment works
      app.use((req: any, _res, next) => {
        // Make Object.defineProperty potentially problematic for a specific property
        const originalDefineProperty = Object.defineProperty;
        let callCount = 0;

        Object.defineProperty = function <T>(
          obj: T,
          prop: PropertyKey,
          descriptor: PropertyDescriptor & ThisType<any>,
        ): T {
          // Fail the first few defineProperty calls to force fallback to direct assignment
          if (
            obj === req &&
            (prop === "queryPolluted" || prop === "bodyPolluted") &&
            callCount < 2
          ) {
            callCount++;
            throw new Error("defineProperty blocked");
          }
          return originalDefineProperty.call(Object, obj, prop, descriptor) as T;
        };

        next();

        // Restore after middleware runs
        setTimeout(() => {
          Object.defineProperty = originalDefineProperty;
        }, 0);
      });

      app.use(hppx({ logPollution: false }));

      app.get("/test", (req, res) => {
        // queryPolluted should be set via fallback assignment (lines 136-137)
        res.json({
          hasQueryPolluted: typeof req.queryPolluted !== "undefined",
          query: req.query,
        });
      });

      const res = await request(app).get("/test?a=1&a=2");
      expect(res.status).toBe(200);
      expect(res.body.hasQueryPolluted).toBe(true);
    });
  });

  describe("mergeValues default case", () => {
    test("sanitize rejects unrecognized mergeStrategy", () => {
      // sanitize now validates options, so invalid strategies throw
      const input = { x: [1, 2, 3] };
      expect(() => sanitize(input, { mergeStrategy: "invalid" as any })).toThrow(TypeError);
    });

    test("keepLast explicitly uses its case branch", () => {
      const input = { x: [1, 2, 3] };
      const result = sanitize(input, { mergeStrategy: "keepLast" });
      expect(result.x).toBe(3);
    });
  });

  describe("Whitelist leaf matching", () => {
    test("matches leaf node in nested path", async () => {
      const app = express();
      app.use(hppx({ whitelist: ["tags"], logPollution: false })); // Leaf name only

      app.get("/test", (req, res) => {
        res.json({ query: req.query });
      });

      // "tags" appears as a leaf in "user.tags"
      const res = await request(app).get("/test?user.tags=a&user.tags=b&user.name=John");

      expect(res.status).toBe(200);
      // Should preserve array for "tags" because it matches the leaf
      expect(res.body.query.user.tags).toEqual(["a", "b"]);
      expect(res.body.query.user.name).toBe("John");
    });

    test("leaf matching with multiple nested levels", async () => {
      const app = express();
      app.use(hppx({ whitelist: ["id"], logPollution: false })); // Matches any leaf named "id"

      app.get("/test", (req, res) => {
        res.json({ query: req.query });
      });

      const res = await request(app).get(
        "/test?user.profile.id=1&user.profile.id=2&product.id=3&product.id=4",
      );

      expect(res.status).toBe(200);
      // Both "id" fields should be preserved as arrays (leaf matching)
      expect(res.body.query.user.profile.id).toEqual(["1", "2"]);
      expect(res.body.query.product.id).toEqual(["3", "4"]);
    });
  });

  describe("Logger error handling in development", () => {
    const originalEnv = process.env.NODE_ENV;
    const originalConsoleError = console.error;

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
      console.error = originalConsoleError;
    });

    test("falls back to console.error when logger fails in development", async () => {
      process.env.NODE_ENV = "development";

      const consoleErrors: any[] = [];
      console.error = jest.fn((...args) => consoleErrors.push(args));

      const failingLogger = () => {
        throw new Error("Logger failed!");
      };

      const app = express();
      app.use(
        hppx({
          maxDepth: 1,
          logger: failingLogger,
        }),
      );

      app.get("/test", (req, res) => res.json({ ok: true }));

      // Create deeply nested object to trigger error
      await request(app).get("/test").query({ "a[b][c]": "value" });

      // Console.error should have been called as fallback
      expect(consoleErrors.length).toBeGreaterThan(0);
      expect(
        consoleErrors.some((args) =>
          args.some((arg: any) => typeof arg === "string" && arg.includes("[hppx]")),
        ),
      ).toBe(true);
    });

    test("does not use console.error fallback in production", async () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";

      const consoleErrors: any[] = [];
      const mockConsoleError = jest.fn((...args) => consoleErrors.push(args));
      console.error = mockConsoleError;

      const failingLogger = () => {
        throw new Error("Logger failed!");
      };

      const app = express();
      app.use(
        hppx({
          maxDepth: 1,
          logger: failingLogger,
        }),
      );

      app.get("/test", (req, res) => res.json({ ok: true }));

      // Create deeply nested object to trigger error
      await request(app).get("/test").query({ "a[b][c]": "value" });

      // Reset NODE_ENV before assertions
      process.env.NODE_ENV = originalNodeEnv;

      // Console.error should NOT have been called in production (filter out hppx logs)
      const hppxErrors = consoleErrors.filter((args) =>
        args.some((arg: any) => typeof arg === "string" && arg.includes("[hppx]")),
      );
      expect(hppxErrors.length).toBe(0);
    });

    test("handles logger that throws during error processing", async () => {
      // Temporarily suppress console.error for this test
      const originalConsoleError = console.error;
      console.error = jest.fn();

      const errors: any[] = [];
      const throwingLogger = (err: any) => {
        errors.push(err);
        throw new Error("Logger exploded!");
      };

      const app = express();
      app.use(
        hppx({
          maxDepth: 1,
          logger: throwingLogger,
        }),
      );

      app.get("/test", (req, res) => res.json({ ok: true }));

      // Should handle logger error gracefully
      const res = await request(app).get("/test").query({ "a[b][c]": "value" });

      // Restore console.error
      console.error = originalConsoleError;

      // Request should still complete (error passed to Express)
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe("Additional edge cases", () => {
    test("handles empty pathParts array in whitelist check", () => {
      const input = { a: [1, 2] };
      const result = sanitize(input, {
        whitelist: [],
        mergeStrategy: "keepLast",
      });

      // With no whitelist, arrays should be reduced
      expect(result.a).toBe(2);
    });

    test("combines nested arrays correctly", () => {
      const input = {
        x: [
          [1, 2],
          [3, 4],
        ],
        y: [[[5]], [[6]]],
      };

      const result = sanitize(input, { mergeStrategy: "combine" });

      // Combine recursively flattens arrays at each level
      // x: [[1,2], [3,4]] -> combines to [1,2,3,4]
      // y: [[[5]], [[6]]] -> combines to [[5], [6]] -> combines to [5, 6]
      expect(result.x).toEqual([1, 2, 3, 4]);
      expect(result.y).toEqual([5, 6]);
    });

    test("handles truly frozen request properties", async () => {
      const app = express();

      // Attempt to create a truly frozen property that can't be modified
      app.use((req: any, _res, next) => {
        // Create a sealed object that will resist modification
        const frozenObj = Object.freeze({ frozen: true });
        try {
          Object.defineProperty(req, "query", {
            value: frozenObj,
            writable: false,
            configurable: false,
          });
        } catch (e) {
          // If we can't freeze it, just continue
        }
        next();
      });

      app.use(hppx({ logPollution: false }));

      app.get("/test", (req, res) => {
        res.json({ query: req.query });
      });

      const res = await request(app).get("/test?a=1");
      expect(res.status).toBe(200);
    });

    test("handles objects with null prototype", () => {
      const nullProtoObj = Object.create(null);
      nullProtoObj.a = [1, 2];
      nullProtoObj.b = "test";

      // Should handle objects with null prototype safely
      const result = sanitize(nullProtoObj, { mergeStrategy: "keepLast" });

      expect(result.a).toBe(2);
      expect(result.b).toBe("test");
    });
  });

  describe("safeDeepClone depth and key filtering", () => {
    test("throws on deeply nested arrays exceeding maxDepth", () => {
      // Arrays count toward depth in safeDeepClone but not in processNode,
      // so deeply nested arrays specifically trigger safeDeepClone's depth check
      const input = { a: [[[["deep"]]]] };
      expect(() => sanitize(input, { maxDepth: 3 })).toThrow(/depth/i);
    });

    test("filters dangerous keys from objects nested inside arrays", () => {
      // Objects inside arrays bypass expandObjectPaths (which only expands plain objects),
      // so safeDeepClone's own key filtering is the safety net
      const inner = Object.create(null);
      inner["__proto__"] = "malicious";
      inner["constructor"] = "bad";
      inner.safe = "ok";

      const result = sanitize({ items: [inner] }, { mergeStrategy: "combine" });

      expect(result.items).toEqual([{ safe: "ok" }]);
      // Dangerous keys must not appear as own properties
      expect(Object.prototype.hasOwnProperty.call(result.items[0], "__proto__")).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(result.items[0], "constructor")).toBe(false);
    });

    test("handles circular array references inside objects", () => {
      // Circular arrays bypass expandObjectPaths (which only processes objects),
      // so safeDeepClone's WeakSet-based circular detection is the safety net
      const arr: any[] = [];
      arr.push(arr); // arr[0] === arr (circular)

      const result = sanitize({ items: arr }, { mergeStrategy: "combine" });

      // Should not stack overflow; circular ref is replaced with empty array
      expect(result.items).toBeDefined();
      expect(Array.isArray(result.items)).toBe(true);
    });

    test("handles circular object references inside arrays", () => {
      // Objects inside arrays survive expandObjectPaths without circular ref detection,
      // so safeDeepClone's WeakSet catches circular object refs during cloning
      const obj: any = { name: "test" };
      obj.self = obj; // circular: obj.self === obj

      const result = sanitize({ items: [obj] }, { mergeStrategy: "combine" });

      // Should not stack overflow; first occurrence is cloned, circular ref → {}
      expect(result.items).toBeDefined();
      expect(result.items[0].name).toBe("test");
      expect(result.items[0].self).toEqual({});
    });
  });

  describe("setIn dangerous last key protection", () => {
    test("blocks dangerous keys in last path segment", () => {
      // "a.__proto__" passes sanitizeKey (not in DANGEROUS_KEYS itself),
      // but when expanded to path ["a", "__proto__"], the last segment is blocked
      const result = sanitize({ "a.__proto__": "malicious", "a.safe": "ok" } as any);

      expect(result.a).toBeDefined();
      expect(result.a.safe).toBe("ok");
      // __proto__ must not be set as a property
      expect(Object.prototype.hasOwnProperty.call(result.a, "__proto__")).toBe(false);
    });

    test("blocks constructor as last path segment", () => {
      const result = sanitize({ "a.constructor": "malicious", "a.name": "ok" } as any);

      expect(result.a).toBeDefined();
      expect(result.a.name).toBe("ok");
      expect(Object.prototype.hasOwnProperty.call(result.a, "constructor")).toBe(false);
    });
  });

  describe("processNode edge cases", () => {
    test("handles undefined values in input objects", () => {
      const result = sanitize({ a: undefined, b: "ok", c: null } as any);

      expect(result.a).toBeUndefined();
      expect(result.b).toBe("ok");
      expect(result.c).toBeNull();
    });
  });

  describe("Middleware error handling for non-Error throws", () => {
    test("wraps non-Error thrown values into Error objects", async () => {
      const app = express();

      // Define req.body as a getter that throws a string (not an Error instance)
      // This exercises the catch block's non-Error wrapping at line 668
      app.use((req: any, _res, next) => {
        Object.defineProperty(req, "body", {
          get() {
            throw "string error thrown";
          },
          configurable: true,
        });
        next();
      });

      app.use(hppx({ sources: ["body"], checkBodyContentType: "any", logPollution: false }));
      app.post("/test", (_req, res) => res.json({ ok: true }));
      app.use((err: any, _req: any, res: any, _next: any) => {
        res.status(500).json({ error: err.message });
      });

      const res = await request(app).post("/test");
      expect(res.status).toBe(500);
      expect(res.body.error).toBe("string error thrown");
    });
  });

  describe("Body content-type handling edge cases", () => {
    test("skips body processing when content-type header is absent", async () => {
      const app = express();

      // Manually set body to simulate parsed body without content-type
      app.use((req: any, _res, next) => {
        req.body = { x: [1, 2] };
        next();
      });

      app.use(hppx({ logPollution: false }));
      app.post("/test", (req, res) =>
        res.json({
          body: req.body,
          bodyPolluted: (req as any).bodyPolluted || {},
        }),
      );

      // Post without setting content-type header
      const res = await request(app).post("/test").set("content-type", "");
      expect(res.status).toBe(200);
      // Body should not be processed since default checkBodyContentType is "urlencoded"
      // and there's no urlencoded content-type
      expect(res.body.body.x).toEqual([1, 2]);
    });
  });

  describe("Whitelist path cache effectiveness", () => {
    test("cache hit on repeated path lookups across multiple sources", async () => {
      const app = express();
      app.use(express.urlencoded({ extended: true }));

      // Single middleware with whitelist that processes both query and body
      app.use(hppx({ whitelist: ["x"], logPollution: false }));
      app.post("/test", (req, res) =>
        res.json({
          query: req.query,
          queryPolluted: (req as any).queryPolluted || {},
          body: req.body,
          bodyPolluted: (req as any).bodyPolluted || {},
        }),
      );

      // Both query and body have the same whitelisted key "x"
      const res = await request(app)
        .post("/test?x=1&x=2")
        .set("content-type", "application/x-www-form-urlencoded")
        .send("x=3&x=4");

      expect(res.status).toBe(200);
      // Both should preserve arrays due to whitelist
      expect(res.body.query.x).toEqual(["1", "2"]);
      expect(res.body.body.x).toEqual(["3", "4"]);
      // Pollution should be empty since x is whitelisted
      expect(res.body.queryPolluted).toEqual({});
      expect(res.body.bodyPolluted).toEqual({});
    });
  });
});
